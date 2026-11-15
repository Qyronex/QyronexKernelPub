// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! On-disk `ext4` structures and safe little-endian encoders/decoders.

use kernal_linux_abi::Errno;

use super::crc32c::{group_desc_csum, inode_csum, superblock_csum, uuid_csum_seed};

pub const EXT4_SUPER_MAGIC: u16 = 0xef53;
pub const EXT4_EXTENT_MAGIC: u16 = 0xf30a;
pub const EXT4_ROOT_INO: u32 = 2;

pub const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;
pub const EXT4_FEATURE_COMPAT_EXT_ATTR: u32 = 0x0008;
pub const EXT4_FEATURE_COMPAT_DIR_INDEX: u32 = 0x0020;

pub const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
pub const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
pub const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
pub const EXT4_FEATURE_INCOMPAT_LARGE_DIR: u32 = 0x4000;
pub const EXT4_FEATURE_INCOMPAT_CSUM_SEED: u32 = 0x2000;
pub const EXT4_FEATURE_INCOMPAT_SUPPORTED: u32 = EXT4_FEATURE_INCOMPAT_FILETYPE
    | EXT4_FEATURE_INCOMPAT_RECOVER
    | EXT4_FEATURE_INCOMPAT_EXTENTS
    | EXT4_FEATURE_INCOMPAT_64BIT
    | EXT4_FEATURE_INCOMPAT_FLEX_BG
    | EXT4_FEATURE_INCOMPAT_CSUM_SEED
    | EXT4_FEATURE_INCOMPAT_LARGE_DIR;

pub const EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
pub const EXT4_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;
pub const EXT4_FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x0008;
pub const EXT4_FEATURE_RO_COMPAT_GDT_CSUM: u32 = 0x0010;
pub const EXT4_FEATURE_RO_COMPAT_DIR_NLINK: u32 = 0x0020;
pub const EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
pub const EXT4_FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
pub const EXT4_FEATURE_RO_COMPAT_SUPPORTED_RW: u32 = EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER
    | EXT4_FEATURE_RO_COMPAT_LARGE_FILE
    | EXT4_FEATURE_RO_COMPAT_HUGE_FILE
    | EXT4_FEATURE_RO_COMPAT_GDT_CSUM
    | EXT4_FEATURE_RO_COMPAT_DIR_NLINK
    | EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE
    | EXT4_FEATURE_RO_COMPAT_METADATA_CSUM;

pub const EXT4_INODE_SIZE_BASE: usize = 128;
pub const EXT4_INDEX_FL: u32 = 0x0000_1000;
pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
pub const EXT4_HUGE_FILE_FL: u32 = 0x0004_0000;

pub const EXT4_BG_INODE_UNINIT: u16 = 0x0001;
pub const EXT4_BG_BLOCK_UNINIT: u16 = 0x0002;
pub const EXT4_BG_INODE_ZEROED: u16 = 0x0004;

pub const EXT4_FT_UNKNOWN: u8 = 0;
pub const EXT4_FT_REG_FILE: u8 = 1;
pub const EXT4_FT_DIR: u8 = 2;
pub const EXT4_FT_SYMLINK: u8 = 7;
pub const EXT4_FT_CSUM: u8 = 0xde;

pub const S_IFMT: u16 = 0o170_000;
pub const S_IFDIR: u16 = 0o040_000;
pub const S_IFREG: u16 = 0o100_000;
pub const S_IFLNK: u16 = 0o120_000;

#[inline]
pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
pub fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub fn combine_u48(lo: u32, hi: u16) -> u64 {
    u64::from(lo) | (u64::from(hi) << 32)
}

#[inline]
pub fn split_u48(v: u64) -> (u32, u16) {
    ((v & 0xffff_ffff) as u32, ((v >> 32) & 0xffff) as u16)
}

#[inline]
pub fn combine_u64(lo: u32, hi: u32) -> u64 {
    u64::from(lo) | (u64::from(hi) << 32)
}

#[inline]
pub fn mode_to_filetype(mode: u16) -> u8 {
    match mode & S_IFMT {
        S_IFREG => EXT4_FT_REG_FILE,
        S_IFDIR => EXT4_FT_DIR,
        S_IFLNK => EXT4_FT_SYMLINK,
        _ => EXT4_FT_UNKNOWN,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SuperblockMeta {
    pub raw: [u8; 1024],
    pub block_size: usize,
    pub blocks_count: u64,
    pub free_blocks_count: u64,
    pub inodes_count: u32,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: usize,
    pub first_ino: u32,
    pub desc_size: usize,
    pub group_count: u32,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub csum_seed: u32,
    pub force_ro: bool,
    pub want_extra_isize: u16,
}

impl SuperblockMeta {
    pub fn parse(raw: [u8; 1024]) -> Result<Self, Errno> {
        let magic = read_u16(&raw, 0x38);
        if magic != EXT4_SUPER_MAGIC {
            return Err(Errno::EINVAL);
        }
        let log_block_size = read_u32(&raw, 0x18);
        if log_block_size > 2 {
            return Err(Errno::EINVAL);
        }
        let block_size = 1024usize << log_block_size;

        let feature_compat = read_u32(&raw, 0x5c);
        let feature_incompat = read_u32(&raw, 0x60);
        let feature_ro_compat = read_u32(&raw, 0x64);

        if (feature_incompat & !EXT4_FEATURE_INCOMPAT_SUPPORTED) != 0 {
            return Err(Errno::EINVAL);
        }

        let is_64bit = (feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0;
        let has_metadata_csum = (feature_ro_compat & EXT4_FEATURE_RO_COMPAT_METADATA_CSUM) != 0;
        let has_gdt_csum = (feature_ro_compat & EXT4_FEATURE_RO_COMPAT_GDT_CSUM) != 0;

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&raw[0x68..0x78]);
        let csum_seed = if (feature_incompat & EXT4_FEATURE_INCOMPAT_CSUM_SEED) != 0 {
            read_u32(&raw, 0x1b0)
        } else {
            uuid_csum_seed(&uuid)
        };

        if has_metadata_csum {
            let stored = read_u32(&raw, 0x3fc);
            let calc = superblock_csum(&raw);
            if stored != calc {
                return Err(Errno::EIO);
            }
        }

        let inodes_count = read_u32(&raw, 0x00);
        let blocks_lo = read_u32(&raw, 0x04);
        let blocks_hi = if is_64bit { read_u32(&raw, 0x150) } else { 0 };
        let blocks_count = combine_u64(blocks_lo, blocks_hi);

        let free_lo = read_u32(&raw, 0x0c);
        let free_hi = if is_64bit { read_u32(&raw, 0x158) } else { 0 };
        let free_blocks_count = combine_u64(free_lo, free_hi);

        let free_inodes_count = read_u32(&raw, 0x10);
        let first_data_block = read_u32(&raw, 0x14);
        let blocks_per_group = read_u32(&raw, 0x20);
        let inodes_per_group = read_u32(&raw, 0x28);

        if blocks_count == 0 || blocks_per_group == 0 || inodes_per_group == 0 {
            return Err(Errno::EINVAL);
        }

        let rev_level = read_u32(&raw, 0x4c);
        let first_ino = if rev_level == 0 {
            11
        } else {
            read_u32(&raw, 0x54)
        };
        let inode_size = if rev_level == 0 {
            EXT4_INODE_SIZE_BASE
        } else {
            usize::from(read_u16(&raw, 0x58))
        };
        if inode_size < EXT4_INODE_SIZE_BASE
            || !inode_size.is_power_of_two()
            || inode_size > block_size
        {
            return Err(Errno::EINVAL);
        }

        let raw_desc_size = read_u16(&raw, 0xfe);
        let desc_size = if is_64bit {
            let ds = usize::from(raw_desc_size);
            if ds < 64 { 64 } else { ds }
        } else {
            32
        };
        if desc_size != 32 && desc_size != 64 {
            return Err(Errno::EINVAL);
        }

        let group_count_u64 =
            (blocks_count - u64::from(first_data_block)).div_ceil(u64::from(blocks_per_group));
        let group_count = u32::try_from(group_count_u64.max(1)).map_err(|_| Errno::EINVAL)?;

        // Force read-only if image contains unknown RO_COMPAT flags or un-replayed recovery flag.
        // We can also update `GDT_CSUM` or `METADATA_CSUM` safely.
        let force_ro = (feature_ro_compat & !EXT4_FEATURE_RO_COMPAT_SUPPORTED_RW) != 0
            || (feature_incompat & EXT4_FEATURE_INCOMPAT_RECOVER) != 0
            || (has_gdt_csum && !has_metadata_csum);
        let want_extra_isize = read_u16(&raw, 0x15c);

        Ok(Self {
            raw,
            block_size,
            blocks_count,
            free_blocks_count,
            inodes_count,
            free_inodes_count,
            first_data_block,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            first_ino: first_ino.max(11),
            desc_size,
            group_count,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            csum_seed,
            force_ro,
            want_extra_isize,
        })
    }

    pub const fn is_64bit(&self) -> bool {
        (self.feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0
    }

    pub const fn has_metadata_csum(&self) -> bool {
        (self.feature_ro_compat & EXT4_FEATURE_RO_COMPAT_METADATA_CSUM) != 0
    }

    pub const fn has_filetype(&self) -> bool {
        (self.feature_incompat & EXT4_FEATURE_INCOMPAT_FILETYPE) != 0
    }

    pub const fn gdt_start_block(&self) -> u64 {
        (self.first_data_block as u64) + 1
    }

    pub fn blocks_in_group(&self, group: u32) -> u32 {
        let start =
            u64::from(self.first_data_block) + u64::from(group) * u64::from(self.blocks_per_group);
        let rem = self.blocks_count.saturating_sub(start);
        rem.min(u64::from(self.blocks_per_group)) as u32
    }

    pub fn sync_raw(&mut self, write_time: u32) {
        write_u32(
            &mut self.raw,
            0x0c,
            (self.free_blocks_count & 0xffff_ffff) as u32,
        );
        if self.is_64bit() {
            write_u32(&mut self.raw, 0x158, (self.free_blocks_count >> 32) as u32);
        }
        write_u32(&mut self.raw, 0x10, self.free_inodes_count);
        if write_time != 0 {
            write_u32(&mut self.raw, 0x30, write_time);
        }
        if self.has_metadata_csum() {
            let csum = superblock_csum(&self.raw);
            write_u32(&mut self.raw, 0x3fc, csum);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GroupDesc {
    pub raw: [u8; 64],
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub used_dirs_count: u32,
    pub flags: u16,
    pub block_bitmap_csum: u32,
    pub inode_bitmap_csum: u32,
    pub itable_unused: u32,
    pub checksum: u16,
}

impl GroupDesc {
    pub fn parse(slice: &[u8], is_64bit: bool) -> Self {
        let mut raw = [0u8; 64];
        let copy_len = slice.len().min(64);
        raw[..copy_len].copy_from_slice(&slice[..copy_len]);

        let bb_lo = read_u32(&raw, 0x00);
        let ib_lo = read_u32(&raw, 0x04);
        let it_lo = read_u32(&raw, 0x08);
        let fb_lo = u32::from(read_u16(&raw, 0x0c));
        let fi_lo = u32::from(read_u16(&raw, 0x0e));
        let ud_lo = u32::from(read_u16(&raw, 0x10));
        let flags = read_u16(&raw, 0x12);
        let bbc_lo = u32::from(read_u16(&raw, 0x18));
        let ibc_lo = u32::from(read_u16(&raw, 0x1a));
        let iu_lo = u32::from(read_u16(&raw, 0x1c));
        let checksum = read_u16(&raw, 0x1e);

        if is_64bit && slice.len() >= 64 {
            Self {
                raw,
                block_bitmap: combine_u64(bb_lo, read_u32(&raw, 0x20)),
                inode_bitmap: combine_u64(ib_lo, read_u32(&raw, 0x24)),
                inode_table: combine_u64(it_lo, read_u32(&raw, 0x28)),
                free_blocks_count: fb_lo | (u32::from(read_u16(&raw, 0x2c)) << 16),
                free_inodes_count: fi_lo | (u32::from(read_u16(&raw, 0x2e)) << 16),
                used_dirs_count: ud_lo | (u32::from(read_u16(&raw, 0x30)) << 16),
                flags,
                block_bitmap_csum: bbc_lo | (u32::from(read_u16(&raw, 0x38)) << 16),
                inode_bitmap_csum: ibc_lo | (u32::from(read_u16(&raw, 0x3a)) << 16),
                itable_unused: iu_lo | (u32::from(read_u16(&raw, 0x32)) << 16),
                checksum,
            }
        } else {
            Self {
                raw,
                block_bitmap: u64::from(bb_lo),
                inode_bitmap: u64::from(ib_lo),
                inode_table: u64::from(it_lo),
                free_blocks_count: fb_lo,
                free_inodes_count: fi_lo,
                used_dirs_count: ud_lo,
                flags,
                block_bitmap_csum: bbc_lo,
                inode_bitmap_csum: ibc_lo,
                itable_unused: iu_lo,
                checksum,
            }
        }
    }

    pub fn sync_raw(&mut self, sb: &SuperblockMeta, group: u32) {
        write_u32(
            &mut self.raw,
            0x00,
            (self.block_bitmap & 0xffff_ffff) as u32,
        );
        write_u32(
            &mut self.raw,
            0x04,
            (self.inode_bitmap & 0xffff_ffff) as u32,
        );
        write_u32(&mut self.raw, 0x08, (self.inode_table & 0xffff_ffff) as u32);
        write_u16(
            &mut self.raw,
            0x0c,
            (self.free_blocks_count & 0xffff) as u16,
        );
        write_u16(
            &mut self.raw,
            0x0e,
            (self.free_inodes_count & 0xffff) as u16,
        );
        write_u16(&mut self.raw, 0x10, (self.used_dirs_count & 0xffff) as u16);
        write_u16(&mut self.raw, 0x12, self.flags);
        write_u16(
            &mut self.raw,
            0x18,
            (self.block_bitmap_csum & 0xffff) as u16,
        );
        write_u16(
            &mut self.raw,
            0x1a,
            (self.inode_bitmap_csum & 0xffff) as u16,
        );
        write_u16(&mut self.raw, 0x1c, (self.itable_unused & 0xffff) as u16);

        if sb.is_64bit() {
            write_u32(&mut self.raw, 0x20, (self.block_bitmap >> 32) as u32);
            write_u32(&mut self.raw, 0x24, (self.inode_bitmap >> 32) as u32);
            write_u32(&mut self.raw, 0x28, (self.inode_table >> 32) as u32);
            write_u16(&mut self.raw, 0x2c, (self.free_blocks_count >> 16) as u16);
            write_u16(&mut self.raw, 0x2e, (self.free_inodes_count >> 16) as u16);
            write_u16(&mut self.raw, 0x30, (self.used_dirs_count >> 16) as u16);
            write_u16(&mut self.raw, 0x32, (self.itable_unused >> 16) as u16);
            write_u16(&mut self.raw, 0x38, (self.block_bitmap_csum >> 16) as u16);
            write_u16(&mut self.raw, 0x3a, (self.inode_bitmap_csum >> 16) as u16);
        }

        if sb.has_metadata_csum() {
            self.checksum = group_desc_csum(sb.csum_seed, group, &self.raw[..sb.desc_size]);
            write_u16(&mut self.raw, 0x1e, self.checksum);
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiskInode {
    pub raw: alloc::vec::Vec<u8>,
    pub ino: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub links_count: u16,
    pub blocks_lo: u32,
    pub flags: u32,
    pub generation: u32,
    pub i_block: [u8; 60],
}

impl DiskInode {
    pub fn parse(ino: u32, bytes: &[u8]) -> Result<Self, Errno> {
        if bytes.len() < EXT4_INODE_SIZE_BASE {
            return Err(Errno::EINVAL);
        }
        let mode = read_u16(bytes, 0x00);
        let uid_lo = u32::from(read_u16(bytes, 0x02));
        let size_lo = read_u32(bytes, 0x04);
        let atime = read_u32(bytes, 0x08);
        let ctime = read_u32(bytes, 0x0c);
        let mtime = read_u32(bytes, 0x10);
        let dtime = read_u32(bytes, 0x14);
        let gid_lo = u32::from(read_u16(bytes, 0x18));
        let links_count = read_u16(bytes, 0x1a);
        let blocks_lo = read_u32(bytes, 0x1c);
        let flags = read_u32(bytes, 0x20);
        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&bytes[0x28..0x64]);
        let generation = read_u32(bytes, 0x64);
        let size_hi = read_u32(bytes, 0x6c);
        let uid_hi = u32::from(read_u16(bytes, 0x78));
        let gid_hi = u32::from(read_u16(bytes, 0x7a));

        let size = if (mode & S_IFMT) == S_IFDIR {
            u64::from(size_lo)
        } else {
            combine_u64(size_lo, size_hi)
        };

        Ok(Self {
            raw: bytes.to_vec(),
            ino,
            mode,
            uid: uid_lo | (uid_hi << 16),
            gid: gid_lo | (gid_hi << 16),
            size,
            atime,
            ctime,
            mtime,
            dtime,
            links_count,
            blocks_lo,
            flags,
            generation,
            i_block,
        })
    }

    pub fn new_empty(
        sb: &SuperblockMeta,
        ino: u32,
        mode: u16,
        uid: u32,
        gid: u32,
        now: u32,
    ) -> Self {
        let mut raw = alloc::vec![0u8; sb.inode_size];
        let extra = sb.want_extra_isize.max(32);
        if sb.inode_size > EXT4_INODE_SIZE_BASE && usize::from(extra) + 128 <= sb.inode_size {
            write_u16(&mut raw, 0x80, extra);
            if sb.inode_size >= 0x94 {
                write_u32(&mut raw, 0x90, now); // i_crtime
            }
        }
        let is_dir = (mode & S_IFMT) == S_IFDIR;
        let is_reg = (mode & S_IFMT) == S_IFREG;
        let mut i_block = [0u8; 60];
        let mut flags = 0u32;
        if is_dir || is_reg {
            flags |= EXT4_EXTENTS_FL;
            // Empty depth-0 extent header: magic=0xf30a, entries=0, max=4, depth=0
            write_u16(&mut i_block, 0, EXT4_EXTENT_MAGIC);
            write_u16(&mut i_block, 2, 0);
            write_u16(&mut i_block, 4, 4);
            write_u16(&mut i_block, 6, 0);
        }
        Self {
            raw,
            ino,
            mode,
            uid,
            gid,
            size: 0,
            atime: now,
            ctime: now,
            mtime: now,
            dtime: 0,
            links_count: if is_dir { 2 } else { 1 },
            blocks_lo: 0,
            flags,
            generation: 1,
            i_block,
        }
    }

    pub fn sync_raw(&mut self, sb: &SuperblockMeta) {
        if self.raw.len() < sb.inode_size {
            self.raw.resize(sb.inode_size, 0);
        }
        write_u16(&mut self.raw, 0x00, self.mode);
        write_u16(&mut self.raw, 0x02, (self.uid & 0xffff) as u16);
        write_u32(&mut self.raw, 0x04, (self.size & 0xffff_ffff) as u32);
        write_u32(&mut self.raw, 0x08, self.atime);
        write_u32(&mut self.raw, 0x0c, self.ctime);
        write_u32(&mut self.raw, 0x10, self.mtime);
        write_u32(&mut self.raw, 0x14, self.dtime);
        write_u16(&mut self.raw, 0x18, (self.gid & 0xffff) as u16);
        write_u16(&mut self.raw, 0x1a, self.links_count);
        write_u32(&mut self.raw, 0x1c, self.blocks_lo);
        write_u32(&mut self.raw, 0x20, self.flags);
        self.raw[0x28..0x64].copy_from_slice(&self.i_block);
        write_u32(&mut self.raw, 0x64, self.generation);
        let size_hi = if (self.mode & S_IFMT) == S_IFDIR {
            0
        } else {
            (self.size >> 32) as u32
        };
        write_u32(&mut self.raw, 0x6c, size_hi);
        write_u16(&mut self.raw, 0x78, (self.uid >> 16) as u16);
        write_u16(&mut self.raw, 0x7a, (self.gid >> 16) as u16);

        if sb.has_metadata_csum() {
            let csum = inode_csum(
                sb.csum_seed,
                self.ino,
                self.generation,
                &self.raw[..sb.inode_size],
            );
            write_u16(&mut self.raw, 0x7c, (csum & 0xffff) as u16);
            if sb.inode_size > 0x84 {
                write_u16(&mut self.raw, 0x82, (csum >> 16) as u16);
            }
        }
    }

    pub const fn uses_extents(&self) -> bool {
        (self.flags & EXT4_EXTENTS_FL) != 0
    }

    pub const fn is_dir(&self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }

    pub const fn is_reg(&self) -> bool {
        (self.mode & S_IFMT) == S_IFREG
    }

    pub const fn is_symlink(&self) -> bool {
        (self.mode & S_IFMT) == S_IFLNK
    }

    pub fn add_disk_blocks_512(&mut self, delta_blocks_fs: i64, block_size: usize) {
        let delta_512 = delta_blocks_fs * ((block_size / 512) as i64);
        if delta_512 >= 0 {
            self.blocks_lo = self.blocks_lo.saturating_add(delta_512 as u32);
        } else {
            self.blocks_lo = self.blocks_lo.saturating_sub((-delta_512) as u32);
        }
    }
}
