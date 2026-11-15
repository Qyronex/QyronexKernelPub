// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Safe `#![forbid(unsafe_code)]` read/write `ext4` filesystem over [`CachedBlockDevice`].

pub mod crc32c;
pub mod dir;
pub mod extent;
pub mod format;

use alloc::vec;
use alloc::vec::Vec;
use kernal_linux_abi::Errno;

use crate::block_cache::{BlockDevice, CachedBlockDevice, DEFAULT_CACHE_BLOCKS};

use self::crc32c::bitmap_csum;
use self::dir::{
    DirEntryItem, add_entry, find_entry, init_dot_dotdot_block, is_dir_empty, list_entries,
    remove_entry, replace_entry_target, update_dotdot,
};
use self::extent::{BlockAllocIo, map_logical_block, map_or_alloc_logical_block, truncate_extents};
use self::format::{
    DiskInode, EXT4_BG_BLOCK_UNINIT, EXT4_BG_INODE_UNINIT, EXT4_FT_DIR, EXT4_FT_REG_FILE,
    EXT4_FT_SYMLINK, EXT4_ROOT_INO, GroupDesc, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, SuperblockMeta,
    mode_to_filetype, read_u16,
};

pub const EXT4_MAX_SYMLINK_FAST_BYTES: usize = 60;
pub const EXT4_DEFAULT_TIME_SECS: u32 = 1_784_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4CreateAttr {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub now: u32,
}

impl Ext4CreateAttr {
    pub const fn new(mode: u16, uid: u32, gid: u32, now: u32) -> Self {
        Self {
            mode,
            uid,
            gid,
            now,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4InodeStat {
    pub ino: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u16,
    pub size: u64,
    pub blksize: u32,
    pub blocks_512: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub flags: u32,
}

impl Ext4InodeStat {
    fn from_disk(inode: &DiskInode, block_size: usize) -> Self {
        Self {
            ino: inode.ino,
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            nlink: inode.links_count,
            size: inode.size,
            blksize: block_size as u32,
            blocks_512: u64::from(inode.blocks_lo),
            atime: i64::from(inode.atime),
            mtime: i64::from(inode.mtime),
            ctime: i64::from(inode.ctime),
            flags: inode.flags,
        }
    }

    pub const fn is_dir(self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }

    pub const fn is_reg(self) -> bool {
        (self.mode & S_IFMT) == S_IFREG
    }

    pub const fn is_symlink(self) -> bool {
        (self.mode & S_IFMT) == S_IFLNK
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4StatFsInfo {
    pub bsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub namelen: u64,
}

#[derive(Clone, Debug)]
pub struct Ext4DirEntry {
    pub ino: u32,
    pub file_type: u8,
    pub name: Vec<u8>,
}

/// Mounted `ext4` filesystem volume backed by a [`CachedBlockDevice`] slice of a [`BlockDevice`].
pub struct Ext4Volume {
    cache: CachedBlockDevice,
    sb: SuperblockMeta,
    groups: Vec<GroupDesc>,
    read_only: bool,
    sb_dirty: bool,
    dirty_groups: Vec<bool>,
}

struct VolumeIo<'a> {
    vol: &'a mut Ext4Volume,
    dev: &'a mut dyn BlockDevice,
}

impl BlockAllocIo for VolumeIo<'_> {
    fn read_fs_block(&mut self, pblock: u64, out: &mut [u8]) -> Result<(), Errno> {
        self.vol.read_fs_block(self.dev, pblock, out)
    }

    fn write_fs_block(&mut self, pblock: u64, data: &[u8]) -> Result<(), Errno> {
        self.vol.write_fs_block(self.dev, pblock, data)
    }

    fn alloc_fs_block(&mut self, goal_group: u32) -> Result<u64, Errno> {
        self.vol.alloc_fs_block(self.dev, goal_group)
    }

    fn free_fs_block(&mut self, pblock: u64) -> Result<(), Errno> {
        self.vol.free_fs_block(self.dev, pblock)
    }

    fn fs_seed(&self) -> u32 {
        self.vol.sb.csum_seed
    }

    fn block_size(&self) -> usize {
        self.vol.sb.block_size
    }

    fn metadata_csum(&self) -> bool {
        self.vol.sb.has_metadata_csum()
    }
}

fn is_power_of(mut n: u32, base: u32) -> bool {
    if n < 1 {
        return false;
    }
    while n > 1 {
        if !n.is_multiple_of(base) {
            return false;
        }
        n /= base;
    }
    true
}

fn group_has_super(sb: &SuperblockMeta, group: u32) -> bool {
    if group == 0 {
        return true;
    }
    if (sb.feature_ro_compat & super::ext4::format::EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER) == 0 {
        return true;
    }
    group == 1 || is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7)
}

impl Ext4Volume {
    /// Mounts an `ext4` filesystem residing within sectors `[start_sector .. start_sector + sector_count)`.
    pub fn mount(
        dev: &mut dyn BlockDevice,
        start_sector: u64,
        sector_count: u64,
        request_ro: bool,
    ) -> Result<Self, Errno> {
        let hw_ro = dev.read_only();
        let mut cache = CachedBlockDevice::new(
            start_sector,
            sector_count,
            hw_ro || request_ro,
            DEFAULT_CACHE_BLOCKS,
        );
        let mut sb_raw = [0u8; 1024];
        cache.read_bytes(dev, 1024, &mut sb_raw)?;
        let sb = SuperblockMeta::parse(sb_raw)?;

        let read_only = hw_ro || request_ro || sb.force_ro;
        cache.set_read_only(read_only);

        let total_groups = sb.group_count as usize;
        if total_groups > 65536 {
            return Err(Errno::EINVAL);
        }
        let gdt_byte_offset = sb.gdt_start_block() * (sb.block_size as u64);
        let gdt_total_bytes = total_groups
            .checked_mul(sb.desc_size)
            .ok_or(Errno::EINVAL)?;
        let mut gdt_raw = vec![0u8; gdt_total_bytes];
        cache.read_bytes(dev, gdt_byte_offset, &mut gdt_raw)?;

        let is_64 = sb.is_64bit();
        let mut groups = Vec::with_capacity(total_groups);
        for g in 0..total_groups {
            let start = g * sb.desc_size;
            groups.push(GroupDesc::parse(
                &gdt_raw[start..start + sb.desc_size],
                is_64,
            ));
        }

        let dirty_groups = vec![false; total_groups];
        Ok(Self {
            cache,
            sb,
            groups,
            read_only,
            sb_dirty: false,
            dirty_groups,
        })
    }

    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn set_read_only(&mut self, dev: &mut dyn BlockDevice, ro: bool) -> Result<(), Errno> {
        if ro {
            if !self.read_only {
                self.sync(dev)?;
            }
            self.read_only = true;
            self.cache.set_read_only(true);
            return Ok(());
        }
        if dev.read_only() || self.sb.force_ro {
            return Err(Errno::EROFS);
        }
        self.read_only = false;
        self.cache.set_read_only(false);
        Ok(())
    }

    fn ensure_writable(&self) -> Result<(), Errno> {
        if self.read_only {
            Err(Errno::EROFS)
        } else {
            Ok(())
        }
    }

    pub const fn root_ino(&self) -> u32 {
        EXT4_ROOT_INO
    }

    pub const fn block_size(&self) -> usize {
        self.sb.block_size
    }

    fn read_fs_block(
        &mut self,
        dev: &mut dyn BlockDevice,
        pblock: u64,
        out: &mut [u8],
    ) -> Result<(), Errno> {
        if out.len() != self.sb.block_size || pblock >= self.sb.blocks_count {
            return Err(Errno::EIO);
        }
        let off = pblock * (self.sb.block_size as u64);
        self.cache.read_bytes(dev, off, out)
    }

    fn write_fs_block(
        &mut self,
        dev: &mut dyn BlockDevice,
        pblock: u64,
        data: &[u8],
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        if data.len() != self.sb.block_size || pblock >= self.sb.blocks_count {
            return Err(Errno::EIO);
        }
        let off = pblock * (self.sb.block_size as u64);
        self.cache.write_bytes(dev, off, data)
    }

    fn group_of_inode(&self, ino: u32) -> Result<(u32, u32), Errno> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Errno::ENOENT);
        }
        let idx0 = ino - 1;
        let group = idx0 / self.sb.inodes_per_group;
        let index = idx0 % self.sb.inodes_per_group;
        if usize::try_from(group)
            .ok()
            .is_none_or(|g| g >= self.groups.len())
        {
            return Err(Errno::EIO);
        }
        Ok((group, index))
    }

    fn group_of_block(&self, pblock: u64) -> Result<(u32, u32), Errno> {
        if pblock < u64::from(self.sb.first_data_block) || pblock >= self.sb.blocks_count {
            return Err(Errno::EINVAL);
        }
        let rel = pblock - u64::from(self.sb.first_data_block);
        let bpg = u64::from(self.sb.blocks_per_group);
        let group = u32::try_from(rel / bpg).map_err(|_| Errno::EINVAL)?;
        let bit = (rel % bpg) as u32;
        if (group as usize) >= self.groups.len() {
            return Err(Errno::EINVAL);
        }
        Ok((group, bit))
    }

    fn inode_byte_offset(&self, ino: u32) -> Result<u64, Errno> {
        let (group, index) = self.group_of_inode(ino)?;
        let gd = &self.groups[group as usize];
        let base = gd.inode_table * (self.sb.block_size as u64);
        let off = u64::from(index) * (self.sb.inode_size as u64);
        base.checked_add(off).ok_or(Errno::EIO)
    }

    fn load_inode(&mut self, dev: &mut dyn BlockDevice, ino: u32) -> Result<DiskInode, Errno> {
        let off = self.inode_byte_offset(ino)?;
        let mut raw = vec![0u8; self.sb.inode_size];
        self.cache.read_bytes(dev, off, &mut raw)?;
        DiskInode::parse(ino, &raw)
    }

    fn store_inode(
        &mut self,
        dev: &mut dyn BlockDevice,
        inode: &mut DiskInode,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        inode.sync_raw(&self.sb);
        let off = self.inode_byte_offset(inode.ino)?;
        self.cache
            .write_bytes(dev, off, &inode.raw[..self.sb.inode_size])
    }

    fn mark_group_dirty(&mut self, group: u32) {
        if let Some(flag) = self.dirty_groups.get_mut(group as usize) {
            *flag = true;
        }
        self.sb_dirty = true;
    }

    fn flush_metadata_headers(&mut self, dev: &mut dyn BlockDevice) -> Result<(), Errno> {
        if self.read_only {
            return Ok(());
        }
        let gdt_base = self.sb.gdt_start_block() * (self.sb.block_size as u64);
        let desc_size = self.sb.desc_size;
        for (g_idx, dirty) in self.dirty_groups.iter_mut().enumerate() {
            if *dirty {
                let sb_copy = self.sb;
                self.groups[g_idx].sync_raw(&sb_copy, g_idx as u32);
                let raw_desc = self.groups[g_idx].raw;
                let off = gdt_base + (g_idx as u64) * (desc_size as u64);
                self.cache.write_bytes(dev, off, &raw_desc[..desc_size])?;
                *dirty = false;
            }
        }
        if self.sb_dirty {
            self.sb.sync_raw(EXT4_DEFAULT_TIME_SECS);
            let sb_raw = self.sb.raw;
            self.cache.write_bytes(dev, 1024, &sb_raw)?;
            self.sb_dirty = false;
        }
        Ok(())
    }

    /// Ensures block bitmap for `group` is initialized if `EXT4_BG_BLOCK_UNINIT` was set.
    fn load_block_bitmap(
        &mut self,
        dev: &mut dyn BlockDevice,
        group: u32,
    ) -> Result<Vec<u8>, Errno> {
        let bs = self.sb.block_size;
        let gd = self.groups[group as usize];
        let mut bmap = vec![0u8; bs];
        if (gd.flags & EXT4_BG_BLOCK_UNINIT) == 0 {
            self.read_fs_block(dev, gd.block_bitmap, &mut bmap)?;
            return Ok(bmap);
        }

        // Initialize uninitialized block bitmap safely.
        let group_start = u64::from(self.sb.first_data_block)
            + u64::from(group) * u64::from(self.sb.blocks_per_group);
        let blocks_in_group = self.sb.blocks_in_group(group);
        let group_end = group_start + u64::from(blocks_in_group);

        let mark_if_in_group = |bmap: &mut [u8], pblk: u64| {
            if pblk >= group_start && pblk < group_end {
                let bit = (pblk - group_start) as usize;
                bmap[bit / 8] |= 1u8 << (bit % 8);
            }
        };

        if group_has_super(&self.sb, group) {
            let gdt_blocks = u64::from(self.sb.group_count)
                .saturating_mul(self.sb.desc_size as u64)
                .div_ceil(bs as u64);
            let resv_gdt = u64::from(read_u16(&self.sb.raw, 0xce));
            for blk in group_start..group_start + 1 + gdt_blocks + resv_gdt {
                mark_if_in_group(&mut bmap, blk);
            }
        }
        mark_if_in_group(&mut bmap, gd.block_bitmap);
        mark_if_in_group(&mut bmap, gd.inode_bitmap);
        let itable_blocks = u64::from(self.sb.inodes_per_group)
            .saturating_mul(self.sb.inode_size as u64)
            .div_ceil(bs as u64);
        for blk in gd.inode_table..gd.inode_table + itable_blocks {
            mark_if_in_group(&mut bmap, blk);
        }
        for bit in (blocks_in_group as usize)..(bs * 8) {
            bmap[bit / 8] |= 1u8 << (bit % 8);
        }

        self.write_fs_block(dev, gd.block_bitmap, &bmap)?;
        let gd_mut = &mut self.groups[group as usize];
        gd_mut.flags &= !EXT4_BG_BLOCK_UNINIT;
        if self.sb.has_metadata_csum() {
            gd_mut.block_bitmap_csum =
                bitmap_csum(self.sb.csum_seed, &bmap, self.sb.blocks_per_group);
        }
        self.mark_group_dirty(group);
        Ok(bmap)
    }

    fn load_inode_bitmap(
        &mut self,
        dev: &mut dyn BlockDevice,
        group: u32,
    ) -> Result<Vec<u8>, Errno> {
        let bs = self.sb.block_size;
        let gd = self.groups[group as usize];
        let mut bmap = vec![0u8; bs];
        if (gd.flags & EXT4_BG_INODE_UNINIT) == 0 {
            self.read_fs_block(dev, gd.inode_bitmap, &mut bmap)?;
            return Ok(bmap);
        }
        for bit in (self.sb.inodes_per_group as usize)..(bs * 8) {
            bmap[bit / 8] |= 1u8 << (bit % 8);
        }
        self.write_fs_block(dev, gd.inode_bitmap, &bmap)?;
        let gd_mut = &mut self.groups[group as usize];
        gd_mut.flags &= !EXT4_BG_INODE_UNINIT;
        if self.sb.has_metadata_csum() {
            gd_mut.inode_bitmap_csum =
                bitmap_csum(self.sb.csum_seed, &bmap, self.sb.inodes_per_group);
        }
        self.mark_group_dirty(group);
        Ok(bmap)
    }

    fn alloc_fs_block(&mut self, dev: &mut dyn BlockDevice, goal_group: u32) -> Result<u64, Errno> {
        self.ensure_writable()?;
        if self.sb.free_blocks_count == 0 {
            return Err(Errno::ENOSPC);
        }
        let n_groups = self.groups.len() as u32;
        let start_g = goal_group % n_groups;
        for step in 0..n_groups {
            let group = (start_g + step) % n_groups;
            if self.groups[group as usize].free_blocks_count == 0 {
                continue;
            }
            let mut bmap = self.load_block_bitmap(dev, group)?;
            let valid_bits = self.sb.blocks_in_group(group) as usize;
            let mut found: Option<usize> = None;
            'scan: for (byte_idx, &byte) in bmap.iter().enumerate() {
                if byte == 0xff {
                    continue;
                }
                for bit in 0..8usize {
                    let abs_bit = byte_idx * 8 + bit;
                    if abs_bit >= valid_bits {
                        break 'scan;
                    }
                    if (byte & (1u8 << bit)) == 0 {
                        found = Some(abs_bit);
                        break 'scan;
                    }
                }
            }
            let Some(bit_idx) = found else {
                continue;
            };
            bmap[bit_idx / 8] |= 1u8 << (bit_idx % 8);
            let bb_blk = self.groups[group as usize].block_bitmap;
            self.write_fs_block(dev, bb_blk, &bmap)?;

            if self.sb.has_metadata_csum() {
                self.groups[group as usize].block_bitmap_csum =
                    bitmap_csum(self.sb.csum_seed, &bmap, self.sb.blocks_per_group);
            }
            self.groups[group as usize].free_blocks_count = self.groups[group as usize]
                .free_blocks_count
                .saturating_sub(1);
            self.sb.free_blocks_count = self.sb.free_blocks_count.saturating_sub(1);
            self.mark_group_dirty(group);

            let pblock = u64::from(self.sb.first_data_block)
                + u64::from(group) * u64::from(self.sb.blocks_per_group)
                + (bit_idx as u64);
            return Ok(pblock);
        }
        Err(Errno::ENOSPC)
    }

    fn free_fs_block(&mut self, dev: &mut dyn BlockDevice, pblock: u64) -> Result<(), Errno> {
        self.ensure_writable()?;
        let (group, bit) = self.group_of_block(pblock)?;
        let bit_idx = bit as usize;
        let mut bmap = self.load_block_bitmap(dev, group)?;
        if (bmap[bit_idx / 8] & (1u8 << (bit_idx % 8))) == 0 {
            return Ok(());
        }
        bmap[bit_idx / 8] &= !(1u8 << (bit_idx % 8));
        let bb_blk = self.groups[group as usize].block_bitmap;
        self.write_fs_block(dev, bb_blk, &bmap)?;

        if self.sb.has_metadata_csum() {
            self.groups[group as usize].block_bitmap_csum =
                bitmap_csum(self.sb.csum_seed, &bmap, self.sb.blocks_per_group);
        }
        self.groups[group as usize].free_blocks_count += 1;
        self.sb.free_blocks_count += 1;
        self.mark_group_dirty(group);
        Ok(())
    }

    fn alloc_inode(
        &mut self,
        dev: &mut dyn BlockDevice,
        goal_group: u32,
        is_dir: bool,
    ) -> Result<u32, Errno> {
        self.ensure_writable()?;
        if self.sb.free_inodes_count == 0 {
            return Err(Errno::ENOSPC);
        }
        let n_groups = self.groups.len() as u32;
        let start_g = goal_group % n_groups;
        let first_user_ino = self.sb.first_ino;
        for step in 0..n_groups {
            let group = (start_g + step) % n_groups;
            if self.groups[group as usize].free_inodes_count == 0 {
                continue;
            }
            let mut bmap = self.load_inode_bitmap(dev, group)?;
            let valid_bits = self.sb.inodes_per_group as usize;
            let mut found: Option<usize> = None;
            'scan: for (byte_idx, &byte) in bmap.iter().enumerate() {
                if byte == 0xff {
                    continue;
                }
                for bit in 0..8usize {
                    let abs_bit = byte_idx * 8 + bit;
                    if abs_bit >= valid_bits {
                        break 'scan;
                    }
                    let candidate_ino = group * self.sb.inodes_per_group + (abs_bit as u32) + 1;
                    if candidate_ino < first_user_ino {
                        continue;
                    }
                    if (byte & (1u8 << bit)) == 0 {
                        found = Some(abs_bit);
                        break 'scan;
                    }
                }
            }
            let Some(bit_idx) = found else {
                continue;
            };
            bmap[bit_idx / 8] |= 1u8 << (bit_idx % 8);
            let ib_blk = self.groups[group as usize].inode_bitmap;
            self.write_fs_block(dev, ib_blk, &bmap)?;

            let gd = &mut self.groups[group as usize];
            if self.sb.has_metadata_csum() {
                gd.inode_bitmap_csum =
                    bitmap_csum(self.sb.csum_seed, &bmap, self.sb.inodes_per_group);
            }
            gd.free_inodes_count = gd.free_inodes_count.saturating_sub(1);
            if is_dir {
                gd.used_dirs_count += 1;
            }
            let min_unused = self
                .sb
                .inodes_per_group
                .saturating_sub((bit_idx as u32) + 1);
            gd.itable_unused = gd.itable_unused.min(min_unused);
            self.sb.free_inodes_count = self.sb.free_inodes_count.saturating_sub(1);
            self.mark_group_dirty(group);

            return Ok(group * self.sb.inodes_per_group + (bit_idx as u32) + 1);
        }
        Err(Errno::ENOSPC)
    }

    fn free_inode(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: u32,
        was_dir: bool,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        let (group, index) = self.group_of_inode(ino)?;
        let idx_usize = index as usize;
        let mut bmap = self.load_inode_bitmap(dev, group)?;
        if (bmap[idx_usize / 8] & (1u8 << (idx_usize % 8))) != 0 {
            bmap[idx_usize / 8] &= !(1u8 << (idx_usize % 8));
            let ib_blk = self.groups[group as usize].inode_bitmap;
            self.write_fs_block(dev, ib_blk, &bmap)?;

            let gd = &mut self.groups[group as usize];
            if self.sb.has_metadata_csum() {
                gd.inode_bitmap_csum =
                    bitmap_csum(self.sb.csum_seed, &bmap, self.sb.inodes_per_group);
            }
            gd.free_inodes_count += 1;
            if was_dir {
                gd.used_dirs_count = gd.used_dirs_count.saturating_sub(1);
            }
            self.sb.free_inodes_count += 1;
            self.mark_group_dirty(group);
        }
        Ok(())
    }

    fn release_inode_and_blocks(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: u32,
        now: u32,
    ) -> Result<(), Errno> {
        let mut inode = self.load_inode(dev, ino)?;
        let was_dir = inode.is_dir();
        if inode.uses_extents() {
            let mut io = VolumeIo { vol: self, dev };
            truncate_extents(&mut io, &mut inode, 0)?;
        }
        inode.dtime = now.max(1);
        inode.ctime = now;
        inode.size = 0;
        inode.links_count = 0;
        self.store_inode(dev, &mut inode)?;
        self.free_inode(dev, ino, was_dir)?;
        self.flush_metadata_headers(dev)
    }

    pub fn stat_inode(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: u32,
    ) -> Result<Ext4InodeStat, Errno> {
        let inode = self.load_inode(dev, ino)?;
        Ok(Ext4InodeStat::from_disk(&inode, self.sb.block_size))
    }

    pub fn lookup_child(
        &mut self,
        dev: &mut dyn BlockDevice,
        dir_ino: u32,
        name: &[u8],
    ) -> Result<Ext4InodeStat, Errno> {
        let dir_inode = self.load_inode(dev, dir_ino)?;
        if !dir_inode.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let has_ft = self.sb.has_filetype();
        let entry = {
            let mut io = VolumeIo { vol: self, dev };
            find_entry(&mut io, &dir_inode, name, has_ft)?
        };
        let Some(item) = entry else {
            return Err(Errno::ENOENT);
        };
        self.stat_inode(dev, item.inode)
    }

    pub fn readdir(
        &mut self,
        dev: &mut dyn BlockDevice,
        dir_ino: u32,
    ) -> Result<Vec<Ext4DirEntry>, Errno> {
        let dir_inode = self.load_inode(dev, dir_ino)?;
        if !dir_inode.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let has_ft = self.sb.has_filetype();
        let items: Vec<DirEntryItem> = {
            let mut io = VolumeIo { vol: self, dev };
            list_entries(&mut io, &dir_inode, has_ft)?
        };
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let mut ft = item.file_type;
            if ft == 0
                && let Ok(child) = self.load_inode(dev, item.inode)
            {
                ft = mode_to_filetype(child.mode);
            }
            out.push(Ext4DirEntry {
                ino: item.inode,
                file_type: ft,
                name: item.name,
            });
        }
        Ok(out)
    }

    pub fn read_symlink(&mut self, dev: &mut dyn BlockDevice, ino: u32) -> Result<Vec<u8>, Errno> {
        let inode = self.load_inode(dev, ino)?;
        if !inode.is_symlink() {
            return Err(Errno::EINVAL);
        }
        let size = usize::try_from(inode.size).map_err(|_| Errno::ENAMETOOLONG)?;
        if size > 4096 {
            return Err(Errno::ENAMETOOLONG);
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        // Fast inline symlink stored inside `i_block` (blocks_lo == 0 and size <= 60).
        if inode.blocks_lo == 0 && size <= EXT4_MAX_SYMLINK_FAST_BYTES {
            return Ok(inode.i_block[..size].to_vec());
        }
        let mut out = vec![0u8; size];
        let mut io = VolumeIo { vol: self, dev };
        let Some(pblock) = map_logical_block(&mut io, &inode, 0)? else {
            return Err(Errno::EIO);
        };
        let bs = io.block_size();
        let mut blk = vec![0u8; bs];
        io.read_fs_block(pblock, &mut blk)?;
        let take = size.min(bs);
        out[..take].copy_from_slice(&blk[..take]);
        Ok(out)
    }

    pub fn read_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: u32,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        let inode = self.load_inode(dev, ino)?;
        if inode.is_dir() {
            return Err(Errno::EISDIR);
        }
        if offset >= inode.size || out.is_empty() {
            return Ok(0);
        }
        let avail = inode.size - offset;
        let to_read = (out.len() as u64).min(avail) as usize;
        let bs = self.sb.block_size;
        let mut blk_buf = vec![0u8; bs];
        let mut done = 0usize;

        while done < to_read {
            let pos = offset + (done as u64);
            let lblock = u32::try_from(pos / (bs as u64)).map_err(|_| Errno::E2BIG)?;
            let inner = (pos % (bs as u64)) as usize;
            let take = (bs - inner).min(to_read - done);
            let pblock = {
                let mut io = VolumeIo { vol: self, dev };
                map_logical_block(&mut io, &inode, lblock)?
            };
            if let Some(pb) = pblock {
                self.read_fs_block(dev, pb, &mut blk_buf)?;
                out[done..done + take].copy_from_slice(&blk_buf[inner..inner + take]);
            } else {
                out[done..done + take].fill(0);
            }
            done += take;
        }
        Ok(done)
    }

    pub fn write_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: u32,
        offset: u64,
        data: &[u8],
        now: u32,
    ) -> Result<usize, Errno> {
        self.ensure_writable()?;
        let mut inode = self.load_inode(dev, ino)?;
        if inode.is_dir() {
            return Err(Errno::EISDIR);
        }
        if !inode.uses_extents() {
            return Err(Errno::EOPNOTSUPP);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let end_off = offset.checked_add(data.len() as u64).ok_or(Errno::E2BIG)?;
        let (goal_group, _) = self.group_of_inode(ino)?;
        let bs = self.sb.block_size;
        let mut blk_buf = vec![0u8; bs];
        let mut done = 0usize;

        while done < data.len() {
            let pos = offset + (done as u64);
            let lblock = u32::try_from(pos / (bs as u64)).map_err(|_| Errno::E2BIG)?;
            let inner = (pos % (bs as u64)) as usize;
            let take = (bs - inner).min(data.len() - done);

            let (pblock, newly_alloc) = {
                let mut io = VolumeIo { vol: self, dev };
                map_or_alloc_logical_block(&mut io, &mut inode, lblock, goal_group)?
            };
            if take < bs {
                if newly_alloc {
                    blk_buf.fill(0);
                } else {
                    self.read_fs_block(dev, pblock, &mut blk_buf)?;
                }
            }
            blk_buf[inner..inner + take].copy_from_slice(&data[done..done + take]);
            self.write_fs_block(dev, pblock, &blk_buf)?;
            done += take;
        }

        if end_off > inode.size {
            inode.size = end_off;
        }
        inode.mtime = now;
        inode.ctime = now;
        self.store_inode(dev, &mut inode)?;
        self.flush_metadata_headers(dev)?;
        Ok(done)
    }

    pub fn truncate_inode(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: u32,
        new_size: u64,
        now: u32,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        let mut inode = self.load_inode(dev, ino)?;
        if inode.is_dir() {
            return Err(Errno::EISDIR);
        }
        if !inode.is_reg() {
            return Err(Errno::EINVAL);
        }
        let bs = self.sb.block_size;
        if new_size < inode.size {
            let keep_blocks =
                u32::try_from(new_size.div_ceil(bs as u64)).map_err(|_| Errno::E2BIG)?;
            {
                let mut io = VolumeIo { vol: self, dev };
                truncate_extents(&mut io, &mut inode, keep_blocks)?;
            }
            let tail_rem = (new_size % (bs as u64)) as usize;
            if tail_rem > 0 {
                let last_lblock = (new_size / (bs as u64)) as u32;
                let maybe_pb = {
                    let mut io = VolumeIo { vol: self, dev };
                    map_logical_block(&mut io, &inode, last_lblock)?
                };
                if let Some(pb) = maybe_pb {
                    let mut blk = vec![0u8; bs];
                    self.read_fs_block(dev, pb, &mut blk)?;
                    blk[tail_rem..].fill(0);
                    self.write_fs_block(dev, pb, &blk)?;
                }
            }
        }
        inode.size = new_size;
        inode.mtime = now;
        inode.ctime = now;
        self.store_inode(dev, &mut inode)?;
        self.flush_metadata_headers(dev)
    }

    pub fn create_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        parent_ino: u32,
        name: &[u8],
        attr: Ext4CreateAttr,
    ) -> Result<Ext4InodeStat, Errno> {
        self.ensure_writable()?;
        let mut parent = self.load_inode(dev, parent_ino)?;
        if !parent.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let has_ft = self.sb.has_filetype();
        {
            let mut io = VolumeIo { vol: self, dev };
            if find_entry(&mut io, &parent, name, has_ft)?.is_some() {
                return Err(Errno::EEXIST);
            }
        }
        let (goal_group, _) = self.group_of_inode(parent_ino)?;
        let new_ino = self.alloc_inode(dev, goal_group, false)?;
        let full_mode = S_IFREG | (attr.mode & 0o7777);
        let mut new_inode =
            DiskInode::new_empty(&self.sb, new_ino, full_mode, attr.uid, attr.gid, attr.now);
        self.store_inode(dev, &mut new_inode)?;

        let add_res = {
            let mut io = VolumeIo { vol: self, dev };
            add_entry(
                &mut io,
                &mut parent,
                name,
                new_ino,
                EXT4_FT_REG_FILE,
                has_ft,
                goal_group,
            )
        };
        if let Err(err) = add_res {
            let _ = self.free_inode(dev, new_ino, false);
            return Err(err);
        }
        parent.mtime = attr.now;
        parent.ctime = attr.now;
        self.store_inode(dev, &mut parent)?;
        self.flush_metadata_headers(dev)?;
        Ok(Ext4InodeStat::from_disk(&new_inode, self.sb.block_size))
    }

    pub fn mkdir(
        &mut self,
        dev: &mut dyn BlockDevice,
        parent_ino: u32,
        name: &[u8],
        attr: Ext4CreateAttr,
    ) -> Result<Ext4InodeStat, Errno> {
        self.ensure_writable()?;
        let mut parent = self.load_inode(dev, parent_ino)?;
        if !parent.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let has_ft = self.sb.has_filetype();
        {
            let mut io = VolumeIo { vol: self, dev };
            if find_entry(&mut io, &parent, name, has_ft)?.is_some() {
                return Err(Errno::EEXIST);
            }
        }
        let (goal_group, _) = self.group_of_inode(parent_ino)?;
        let new_ino = self.alloc_inode(dev, goal_group, true)?;
        let full_mode = S_IFDIR | (attr.mode & 0o7777);
        let mut dir_inode =
            DiskInode::new_empty(&self.sb, new_ino, full_mode, attr.uid, attr.gid, attr.now);

        let init_res = {
            let mut io = VolumeIo { vol: self, dev };
            init_dot_dotdot_block(&mut io, &mut dir_inode, parent_ino, goal_group)
        };
        if let Err(err) = init_res {
            let _ = self.free_inode(dev, new_ino, true);
            return Err(err);
        }
        self.store_inode(dev, &mut dir_inode)?;

        let add_res = {
            let mut io = VolumeIo { vol: self, dev };
            add_entry(
                &mut io,
                &mut parent,
                name,
                new_ino,
                EXT4_FT_DIR,
                has_ft,
                goal_group,
            )
        };
        if let Err(err) = add_res {
            let mut io = VolumeIo { vol: self, dev };
            let _ = truncate_extents(&mut io, &mut dir_inode, 0);
            let _ = self.free_inode(dev, new_ino, true);
            return Err(err);
        }
        parent.links_count = parent.links_count.saturating_add(1);
        parent.mtime = attr.now;
        parent.ctime = attr.now;
        self.store_inode(dev, &mut parent)?;
        self.flush_metadata_headers(dev)?;
        Ok(Ext4InodeStat::from_disk(&dir_inode, self.sb.block_size))
    }

    pub fn symlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        parent_ino: u32,
        name: &[u8],
        target: &[u8],
        attr: Ext4CreateAttr,
    ) -> Result<Ext4InodeStat, Errno> {
        self.ensure_writable()?;
        if target.is_empty() || target.len() > 4096 {
            return Err(Errno::EINVAL);
        }
        let bs = self.sb.block_size;
        if target.len() > bs {
            return Err(Errno::ENAMETOOLONG);
        }
        let mut parent = self.load_inode(dev, parent_ino)?;
        if !parent.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let has_ft = self.sb.has_filetype();
        {
            let mut io = VolumeIo { vol: self, dev };
            if find_entry(&mut io, &parent, name, has_ft)?.is_some() {
                return Err(Errno::EEXIST);
            }
        }
        let (goal_group, _) = self.group_of_inode(parent_ino)?;
        let new_ino = self.alloc_inode(dev, goal_group, false)?;
        let full_mode = S_IFLNK | 0o777;
        let mut sym_inode =
            DiskInode::new_empty(&self.sb, new_ino, full_mode, attr.uid, attr.gid, attr.now);
        sym_inode.size = target.len() as u64;

        if target.len() <= EXT4_MAX_SYMLINK_FAST_BYTES {
            sym_inode.i_block[..target.len()].copy_from_slice(target);
        } else {
            sym_inode.flags |= super::ext4::format::EXT4_EXTENTS_FL;
            super::ext4::format::write_u16(
                &mut sym_inode.i_block,
                0,
                super::ext4::format::EXT4_EXTENT_MAGIC,
            );
            super::ext4::format::write_u16(&mut sym_inode.i_block, 2, 0);
            super::ext4::format::write_u16(&mut sym_inode.i_block, 4, 4);
            super::ext4::format::write_u16(&mut sym_inode.i_block, 6, 0);
            let pb = {
                let mut io = VolumeIo { vol: self, dev };
                map_or_alloc_logical_block(&mut io, &mut sym_inode, 0, goal_group)?.0
            };
            let mut blk = vec![0u8; bs];
            blk[..target.len()].copy_from_slice(target);
            self.write_fs_block(dev, pb, &blk)?;
        }
        self.store_inode(dev, &mut sym_inode)?;

        let add_res = {
            let mut io = VolumeIo { vol: self, dev };
            add_entry(
                &mut io,
                &mut parent,
                name,
                new_ino,
                EXT4_FT_SYMLINK,
                has_ft,
                goal_group,
            )
        };
        if let Err(err) = add_res {
            let mut io = VolumeIo { vol: self, dev };
            if target.len() > EXT4_MAX_SYMLINK_FAST_BYTES {
                let _ = truncate_extents(&mut io, &mut sym_inode, 0);
            }
            let _ = self.free_inode(dev, new_ino, false);
            return Err(err);
        }
        parent.mtime = attr.now;
        parent.ctime = attr.now;
        self.store_inode(dev, &mut parent)?;
        self.flush_metadata_headers(dev)?;
        Ok(Ext4InodeStat::from_disk(&sym_inode, self.sb.block_size))
    }

    pub fn link(
        &mut self,
        dev: &mut dyn BlockDevice,
        target_ino: u32,
        parent_ino: u32,
        name: &[u8],
        now: u32,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        let mut target = self.load_inode(dev, target_ino)?;
        if target.is_dir() {
            return Err(Errno::EPERM);
        }
        let mut parent = self.load_inode(dev, parent_ino)?;
        if !parent.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let has_ft = self.sb.has_filetype();
        let ft = mode_to_filetype(target.mode);
        let (goal_group, _) = self.group_of_inode(parent_ino)?;
        {
            let mut io = VolumeIo { vol: self, dev };
            add_entry(
                &mut io,
                &mut parent,
                name,
                target_ino,
                ft,
                has_ft,
                goal_group,
            )?;
        }
        target.links_count = target.links_count.saturating_add(1);
        target.ctime = now;
        self.store_inode(dev, &mut target)?;
        parent.mtime = now;
        parent.ctime = now;
        self.store_inode(dev, &mut parent)?;
        self.flush_metadata_headers(dev)
    }

    pub fn unlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        parent_ino: u32,
        name: &[u8],
        now: u32,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        let mut parent = self.load_inode(dev, parent_ino)?;
        if !parent.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let has_ft = self.sb.has_filetype();
        let entry = {
            let mut io = VolumeIo { vol: self, dev };
            find_entry(&mut io, &parent, name, has_ft)?
        };
        let Some(item) = entry else {
            return Err(Errno::ENOENT);
        };
        let mut target = self.load_inode(dev, item.inode)?;
        if target.is_dir() {
            return Err(Errno::EISDIR);
        }
        {
            let mut io = VolumeIo { vol: self, dev };
            let _ = remove_entry(&mut io, &mut parent, name)?;
        }
        parent.mtime = now;
        parent.ctime = now;
        self.store_inode(dev, &mut parent)?;

        target.links_count = target.links_count.saturating_sub(1);
        target.ctime = now;
        self.store_inode(dev, &mut target)?;
        if target.links_count == 0 {
            self.release_inode_and_blocks(dev, item.inode, now)?;
        } else {
            self.flush_metadata_headers(dev)?;
        }
        Ok(())
    }

    pub fn rmdir(
        &mut self,
        dev: &mut dyn BlockDevice,
        parent_ino: u32,
        name: &[u8],
        now: u32,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        if name == b"." || name == b".." {
            return Err(Errno::EINVAL);
        }
        let mut parent = self.load_inode(dev, parent_ino)?;
        if !parent.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let has_ft = self.sb.has_filetype();
        let entry = {
            let mut io = VolumeIo { vol: self, dev };
            find_entry(&mut io, &parent, name, has_ft)?
        };
        let Some(item) = entry else {
            return Err(Errno::ENOENT);
        };
        if item.inode == EXT4_ROOT_INO {
            return Err(Errno::EBUSY);
        }
        let child = self.load_inode(dev, item.inode)?;
        if !child.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let empty = {
            let mut io = VolumeIo { vol: self, dev };
            is_dir_empty(&mut io, &child)?
        };
        if !empty {
            return Err(Errno::ENOTEMPTY);
        }
        {
            let mut io = VolumeIo { vol: self, dev };
            let _ = remove_entry(&mut io, &mut parent, name)?;
        }
        parent.links_count = parent.links_count.saturating_sub(1);
        parent.mtime = now;
        parent.ctime = now;
        self.store_inode(dev, &mut parent)?;
        self.release_inode_and_blocks(dev, item.inode, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rename(
        &mut self,
        dev: &mut dyn BlockDevice,
        old_dir_ino: u32,
        old_name: &[u8],
        new_dir_ino: u32,
        new_name: &[u8],
        noreplace: bool,
        now: u32,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        if old_name == b"." || old_name == b".." || new_name == b"." || new_name == b".." {
            return Err(Errno::EINVAL);
        }
        let old_dir = self.load_inode(dev, old_dir_ino)?;
        let new_dir = self.load_inode(dev, new_dir_ino)?;
        if !old_dir.is_dir() || !new_dir.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let has_ft = self.sb.has_filetype();
        let src_item = {
            let mut io = VolumeIo { vol: self, dev };
            find_entry(&mut io, &old_dir, old_name, has_ft)?
        }
        .ok_or(Errno::ENOENT)?;

        if old_dir_ino == new_dir_ino && old_name == new_name {
            return Ok(());
        }

        let src_inode = self.load_inode(dev, src_item.inode)?;
        let src_is_dir = src_inode.is_dir();
        let src_ft = mode_to_filetype(src_inode.mode);

        let existing_dst = {
            let mut io = VolumeIo { vol: self, dev };
            find_entry(&mut io, &new_dir, new_name, has_ft)?
        };
        if let Some(dst_item) = existing_dst {
            if noreplace {
                return Err(Errno::EEXIST);
            }
            if dst_item.inode == src_item.inode {
                // Same inode -> just remove old entry unless same dir & name.
                let mut od = self.load_inode(dev, old_dir_ino)?;
                {
                    let mut io = VolumeIo { vol: self, dev };
                    let _ = remove_entry(&mut io, &mut od, old_name)?;
                }
                self.store_inode(dev, &mut od)?;
                return self.flush_metadata_headers(dev);
            }
            let mut dst_inode = self.load_inode(dev, dst_item.inode)?;
            if src_is_dir {
                if !dst_inode.is_dir() {
                    return Err(Errno::ENOTDIR);
                }
                let empty = {
                    let mut io = VolumeIo { vol: self, dev };
                    is_dir_empty(&mut io, &dst_inode)?
                };
                if !empty {
                    return Err(Errno::ENOTEMPTY);
                }
            } else if dst_inode.is_dir() {
                return Err(Errno::EISDIR);
            }

            let mut nd = self.load_inode(dev, new_dir_ino)?;
            {
                let mut io = VolumeIo { vol: self, dev };
                replace_entry_target(&mut io, &mut nd, new_name, src_item.inode, src_ft, has_ft)?;
            }
            nd.mtime = now;
            nd.ctime = now;
            self.store_inode(dev, &mut nd)?;

            let mut od = self.load_inode(dev, old_dir_ino)?;
            {
                let mut io = VolumeIo { vol: self, dev };
                let _ = remove_entry(&mut io, &mut od, old_name)?;
            }
            if src_is_dir && old_dir_ino != new_dir_ino {
                od.links_count = od.links_count.saturating_sub(1);
            }
            od.mtime = now;
            od.ctime = now;
            self.store_inode(dev, &mut od)?;

            if src_is_dir && old_dir_ino != new_dir_ino {
                let mut moved = self.load_inode(dev, src_item.inode)?;
                {
                    let mut io = VolumeIo { vol: self, dev };
                    update_dotdot(&mut io, &mut moved, new_dir_ino)?;
                }
                self.store_inode(dev, &mut moved)?;
            }

            if dst_inode.is_dir() {
                self.release_inode_and_blocks(dev, dst_item.inode, now)?;
            } else {
                dst_inode.links_count = dst_inode.links_count.saturating_sub(1);
                dst_inode.ctime = now;
                self.store_inode(dev, &mut dst_inode)?;
                if dst_inode.links_count == 0 {
                    self.release_inode_and_blocks(dev, dst_item.inode, now)?;
                } else {
                    self.flush_metadata_headers(dev)?;
                }
            }
            return Ok(());
        }

        // Destination does not exist yet.
        let (goal_group, _) = self.group_of_inode(new_dir_ino)?;
        let mut nd = self.load_inode(dev, new_dir_ino)?;
        {
            let mut io = VolumeIo { vol: self, dev };
            add_entry(
                &mut io,
                &mut nd,
                new_name,
                src_item.inode,
                src_ft,
                has_ft,
                goal_group,
            )?;
        }
        if src_is_dir && old_dir_ino != new_dir_ino {
            nd.links_count = nd.links_count.saturating_add(1);
        }
        nd.mtime = now;
        nd.ctime = now;
        self.store_inode(dev, &mut nd)?;

        let mut od = self.load_inode(dev, old_dir_ino)?;
        {
            let mut io = VolumeIo { vol: self, dev };
            let _ = remove_entry(&mut io, &mut od, old_name)?;
        }
        if src_is_dir && old_dir_ino != new_dir_ino {
            od.links_count = od.links_count.saturating_sub(1);
        }
        od.mtime = now;
        od.ctime = now;
        self.store_inode(dev, &mut od)?;

        if src_is_dir && old_dir_ino != new_dir_ino {
            let mut moved = self.load_inode(dev, src_item.inode)?;
            {
                let mut io = VolumeIo { vol: self, dev };
                update_dotdot(&mut io, &mut moved, new_dir_ino)?;
            }
            self.store_inode(dev, &mut moved)?;
        }
        self.flush_metadata_headers(dev)
    }

    pub fn chmod(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: u32,
        mode_bits: u16,
        now: u32,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        let mut inode = self.load_inode(dev, ino)?;
        inode.mode = (inode.mode & S_IFMT) | (mode_bits & 0o7777);
        inode.ctime = now;
        self.store_inode(dev, &mut inode)?;
        self.flush_metadata_headers(dev)
    }

    pub fn chown(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: u32,
        uid: Option<u32>,
        gid: Option<u32>,
        now: u32,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        let mut inode = self.load_inode(dev, ino)?;
        if let Some(u) = uid {
            inode.uid = u;
        }
        if let Some(g) = gid {
            inode.gid = g;
        }
        inode.ctime = now;
        self.store_inode(dev, &mut inode)?;
        self.flush_metadata_headers(dev)
    }

    pub fn utimens(
        &mut self,
        dev: &mut dyn BlockDevice,
        ino: u32,
        atime: Option<u32>,
        mtime: Option<u32>,
        now: u32,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        let mut inode = self.load_inode(dev, ino)?;
        if let Some(a) = atime {
            inode.atime = a;
        }
        if let Some(m) = mtime {
            inode.mtime = m;
        }
        inode.ctime = now;
        self.store_inode(dev, &mut inode)?;
        self.flush_metadata_headers(dev)
    }

    pub fn statfs(&self) -> Ext4StatFsInfo {
        Ext4StatFsInfo {
            bsize: self.sb.block_size as u64,
            blocks: self.sb.blocks_count,
            bfree: self.sb.free_blocks_count,
            bavail: self.sb.free_blocks_count,
            files: u64::from(self.sb.inodes_count),
            ffree: u64::from(self.sb.free_inodes_count),
            namelen: 255,
        }
    }

    pub fn sync(&mut self, dev: &mut dyn BlockDevice) -> Result<(), Errno> {
        self.flush_metadata_headers(dev)?;
        self.cache.sync(dev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_cache::BLOCK_SECTOR_SIZE;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::process::Command;

    struct VecBlockDev {
        data: Vec<u8>,
        ro: bool,
    }

    impl VecBlockDev {
        fn new(bytes: usize) -> Self {
            Self {
                data: vec![0u8; bytes],
                ro: false,
            }
        }
    }

    impl BlockDevice for VecBlockDev {
        fn total_sectors(&self) -> u64 {
            (self.data.len() / BLOCK_SECTOR_SIZE) as u64
        }

        fn read_only(&self) -> bool {
            self.ro
        }

        fn read_sectors(&mut self, start_sector: u64, out: &mut [u8]) -> Result<(), Errno> {
            let off = (start_sector as usize) * BLOCK_SECTOR_SIZE;
            out.copy_from_slice(&self.data[off..off + out.len()]);
            Ok(())
        }

        fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> Result<(), Errno> {
            let off = (start_sector as usize) * BLOCK_SECTOR_SIZE;
            self.data[off..off + data.len()].copy_from_slice(data);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Errno> {
            Ok(())
        }
    }

    #[test]
    fn real_mkfs_ext4_rw_and_e2fsck_clean() {
        if !std::path::Path::new("/usr/sbin/mkfs.ext4").exists()
            || !std::path::Path::new("/usr/sbin/e2fsck").exists()
        {
            return;
        }
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let img_path = std::env::temp_dir().join(format!("kernal_ext4_unit_{id}.img"));
        let _ = std::fs::remove_file(&img_path);

        let total_bytes = 32 * 1024 * 1024usize;
        {
            let f = std::fs::File::create(&img_path).unwrap();
            f.set_len(total_bytes as u64).unwrap();
        }
        let mkfs_ok = Command::new("/usr/sbin/mkfs.ext4")
            .args(["-F", "-b", "4096", img_path.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(mkfs_ok.success());

        let mut dev = VecBlockDev::new(total_bytes);
        dev.data = std::fs::read(&img_path).unwrap();

        let total_secs = dev.total_sectors();
        let mut vol = Ext4Volume::mount(&mut dev, 0, total_secs, false).unwrap();

        let root_ino = vol.root_ino();
        let dir_attr = Ext4CreateAttr::new(0o755, 0, 0, EXT4_DEFAULT_TIME_SECS);
        let file_attr = Ext4CreateAttr::new(0o644, 0, 0, EXT4_DEFAULT_TIME_SECS);
        let dir_stat = vol.mkdir(&mut dev, root_ino, b"root", dir_attr).unwrap();
        let f_stat = vol
            .create_file(&mut dev, dir_stat.ino, b"testfile", file_attr)
            .unwrap();

        // Write across 6 blocks (>4 blocks) + sparse holes (forcing depth-1 extent tree!).
        let payload: Vec<u8> = (0..24_576u32).map(|i| (i % 251) as u8).collect();
        vol.write_file(&mut dev, f_stat.ino, 0, &payload, EXT4_DEFAULT_TIME_SECS)
            .unwrap();
        for hole_idx in 1..=8u64 {
            vol.write_file(
                &mut dev,
                f_stat.ino,
                hole_idx * 32_768,
                b"EXT_DEPTH1",
                EXT4_DEFAULT_TIME_SECS,
            )
            .unwrap();
        }

        let sym1 = vol
            .symlink(
                &mut dev,
                dir_stat.ino,
                b"fast_sym",
                b"/root/testfile",
                file_attr,
            )
            .unwrap();
        let long_target = vec![b'a'; 120];
        let sym2 = vol
            .symlink(&mut dev, dir_stat.ino, b"long_sym", &long_target, file_attr)
            .unwrap();

        // Add many files to trigger multi-block dir.
        let sub_stat = vol.mkdir(&mut dev, root_ino, b"many", dir_attr).unwrap();
        for i in 0..80u32 {
            let name = alloc::format!("entry_long_name_{i:03}");
            let st = vol
                .create_file(&mut dev, sub_stat.ino, name.as_bytes(), file_attr)
                .unwrap();
            vol.write_file(&mut dev, st.ino, 0, b"ok", EXT4_DEFAULT_TIME_SECS)
                .unwrap();
        }
        vol.rename(
            &mut dev,
            sub_stat.ino,
            b"entry_long_name_001",
            dir_stat.ino,
            b"renamed_entry",
            true,
            EXT4_DEFAULT_TIME_SECS,
        )
        .unwrap();
        vol.unlink(
            &mut dev,
            dir_stat.ino,
            b"renamed_entry",
            EXT4_DEFAULT_TIME_SECS,
        )
        .unwrap();
        vol.truncate_inode(&mut dev, f_stat.ino, 24_576, EXT4_DEFAULT_TIME_SECS)
            .unwrap();

        // Write a second sparse file with >4 disjoint extents that remains kept on disk.
        let sparse_f = vol
            .create_file(&mut dev, dir_stat.ino, b"deep_extent", file_attr)
            .unwrap();
        for hole_idx in 0..10u64 {
            vol.write_file(
                &mut dev,
                sparse_f.ino,
                hole_idx * 16_384,
                b"FRAGMENTED",
                EXT4_DEFAULT_TIME_SECS,
            )
            .unwrap();
        }
        vol.sync(&mut dev).unwrap();

        // Remount cleanly and verify readback.
        let mut vol2 = Ext4Volume::mount(&mut dev, 0, total_secs, false).unwrap();
        let mut read_back = vec![0u8; payload.len()];
        let n = vol2
            .read_file(&mut dev, f_stat.ino, 0, &mut read_back)
            .unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(read_back, payload);
        for hole_idx in 0..10u64 {
            let mut m = [0u8; 10];
            assert_eq!(
                vol2.read_file(&mut dev, sparse_f.ino, hole_idx * 16_384, &mut m)
                    .unwrap(),
                10
            );
            assert_eq!(&m, b"FRAGMENTED");
        }
        assert_eq!(
            vol2.read_symlink(&mut dev, sym1.ino).unwrap(),
            b"/root/testfile"
        );
        assert_eq!(vol2.read_symlink(&mut dev, sym2.ino).unwrap(), long_target);
        assert!(vol2.readdir(&mut dev, sub_stat.ino).unwrap().len() >= 81); // ., .., 79 files

        std::fs::write(&img_path, &dev.data).unwrap();
        let fsck = Command::new("/usr/sbin/e2fsck")
            .args(["-fn", img_path.to_str().unwrap()])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&img_path);
        assert!(
            fsck.status.success(),
            "e2fsck failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&fsck.stdout),
            String::from_utf8_lossy(&fsck.stderr)
        );
    }
}
