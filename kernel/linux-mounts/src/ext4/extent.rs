// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! `ext4` extent tree lookup, allocation/splitting, and truncation.

use alloc::vec;
use alloc::vec::Vec;
use kernal_linux_abi::Errno;

use super::crc32c::stamp_extent_block_tail;
use super::format::{
    DiskInode, EXT4_EXTENT_MAGIC, combine_u48, read_u16, read_u32, split_u48, write_u16, write_u32,
};

pub const EXTENT_HEADER_BYTES: usize = 12;
pub const EXTENT_ENTRY_BYTES: usize = 12;
pub const EXTENT_ROOT_MAX_ENTRIES: u16 = 4;
pub const EXTENT_MAX_LEN: u16 = 32768;

pub trait BlockAllocIo {
    fn read_fs_block(&mut self, pblock: u64, out: &mut [u8]) -> Result<(), Errno>;
    fn write_fs_block(&mut self, pblock: u64, data: &[u8]) -> Result<(), Errno>;
    fn alloc_fs_block(&mut self, goal_group: u32) -> Result<u64, Errno>;
    fn free_fs_block(&mut self, pblock: u64) -> Result<(), Errno>;
    fn fs_seed(&self) -> u32;
    fn block_size(&self) -> usize;
    fn metadata_csum(&self) -> bool;
}

#[derive(Clone, Copy, Debug)]
struct ExtentHeader {
    entries: u16,
    max: u16,
    depth: u16,
    generation: u32,
}

impl ExtentHeader {
    fn parse(buf: &[u8]) -> Result<Self, Errno> {
        if buf.len() < EXTENT_HEADER_BYTES {
            return Err(Errno::EIO);
        }
        let magic = read_u16(buf, 0);
        if magic != EXT4_EXTENT_MAGIC {
            return Err(Errno::EIO);
        }
        let entries = read_u16(buf, 2);
        let max = read_u16(buf, 4);
        let depth = read_u16(buf, 6);
        let generation = read_u32(buf, 8);
        if depth > 5 || entries > max {
            return Err(Errno::EIO);
        }
        let needed = EXTENT_HEADER_BYTES + usize::from(max) * EXTENT_ENTRY_BYTES;
        if needed > buf.len() {
            return Err(Errno::EIO);
        }
        Ok(Self {
            entries,
            max,
            depth,
            generation,
        })
    }

    fn write(&self, buf: &mut [u8]) {
        write_u16(buf, 0, EXT4_EXTENT_MAGIC);
        write_u16(buf, 2, self.entries);
        write_u16(buf, 4, self.max);
        write_u16(buf, 6, self.depth);
        write_u32(buf, 8, self.generation);
    }
}

#[derive(Clone, Copy, Debug)]
struct ExtentIdx {
    block: u32,
    leaf: u64,
}

impl ExtentIdx {
    fn parse(buf: &[u8], idx: u16) -> Self {
        let off = EXTENT_HEADER_BYTES + usize::from(idx) * EXTENT_ENTRY_BYTES;
        let block = read_u32(buf, off);
        let lo = read_u32(buf, off + 4);
        let hi = read_u16(buf, off + 8);
        Self {
            block,
            leaf: combine_u48(lo, hi),
        }
    }

    fn write(self, buf: &mut [u8], idx: u16) {
        let off = EXTENT_HEADER_BYTES + usize::from(idx) * EXTENT_ENTRY_BYTES;
        let (lo, hi) = split_u48(self.leaf);
        write_u32(buf, off, self.block);
        write_u32(buf, off + 4, lo);
        write_u16(buf, off + 8, hi);
        write_u16(buf, off + 10, 0);
    }
}

#[derive(Clone, Copy, Debug)]
struct ExtentLeaf {
    block: u32,
    raw_len: u16,
    start: u64,
}

impl ExtentLeaf {
    fn parse(buf: &[u8], idx: u16) -> Self {
        let off = EXTENT_HEADER_BYTES + usize::from(idx) * EXTENT_ENTRY_BYTES;
        let block = read_u32(buf, off);
        let raw_len = read_u16(buf, off + 4);
        let hi = read_u16(buf, off + 6);
        let lo = read_u32(buf, off + 8);
        Self {
            block,
            raw_len,
            start: combine_u48(lo, hi),
        }
    }

    fn write(self, buf: &mut [u8], idx: u16) {
        let off = EXTENT_HEADER_BYTES + usize::from(idx) * EXTENT_ENTRY_BYTES;
        let (lo, hi) = split_u48(self.start);
        write_u32(buf, off, self.block);
        write_u16(buf, off + 4, self.raw_len);
        write_u16(buf, off + 6, hi);
        write_u32(buf, off + 8, lo);
    }

    const fn is_unwritten(self) -> bool {
        self.raw_len > EXTENT_MAX_LEN
    }

    const fn block_len(self) -> u32 {
        if self.raw_len > EXTENT_MAX_LEN {
            (self.raw_len - EXTENT_MAX_LEN) as u32
        } else {
            self.raw_len as u32
        }
    }
}

fn external_max_entries(io: &dyn BlockAllocIo) -> u16 {
    let tail = if io.metadata_csum() { 4 } else { 0 };
    let usable = io.block_size().saturating_sub(EXTENT_HEADER_BYTES + tail);
    u16::try_from(usable / EXTENT_ENTRY_BYTES).unwrap_or(1)
}

fn save_node(
    io: &mut dyn BlockAllocIo,
    inode: &mut DiskInode,
    pblock: Option<u64>,
    buf: &mut [u8],
) -> Result<(), Errno> {
    match pblock {
        None => {
            inode.i_block.copy_from_slice(&buf[..60]);
            Ok(())
        }
        Some(pb) => {
            stamp_extent_block_tail(
                io.fs_seed(),
                inode.ino,
                inode.generation,
                buf,
                io.metadata_csum(),
            );
            io.write_fs_block(pb, buf)
        }
    }
}

fn read_node(
    io: &mut dyn BlockAllocIo,
    inode: &DiskInode,
    pblock: Option<u64>,
) -> Result<Vec<u8>, Errno> {
    match pblock {
        None => Ok(inode.i_block.to_vec()),
        Some(pb) => {
            let mut blk = vec![0u8; io.block_size()];
            io.read_fs_block(pb, &mut blk)?;
            Ok(blk)
        }
    }
}

/// Maps logical file block `lblock` to a physical block on disk, or `None` for sparse/unwritten holes.
pub fn map_logical_block(
    io: &mut dyn BlockAllocIo,
    inode: &DiskInode,
    lblock: u32,
) -> Result<Option<u64>, Errno> {
    if !inode.uses_extents() {
        return map_legacy_block(io, inode, lblock);
    }

    let mut cur_buf = inode.i_block.to_vec();
    for _step in 0..=5 {
        let hdr = ExtentHeader::parse(&cur_buf)?;
        if hdr.entries == 0 {
            return Ok(None);
        }
        if hdr.depth == 0 {
            for i in 0..hdr.entries {
                let leaf = ExtentLeaf::parse(&cur_buf, i);
                if lblock >= leaf.block && lblock < leaf.block.saturating_add(leaf.block_len()) {
                    if leaf.is_unwritten() {
                        return Ok(None);
                    }
                    let delta = u64::from(lblock - leaf.block);
                    return Ok(Some(leaf.start + delta));
                }
                if leaf.block > lblock {
                    return Ok(None);
                }
            }
            return Ok(None);
        }
        let mut chosen: Option<u64> = None;
        for i in 0..hdr.entries {
            let idx_entry = ExtentIdx::parse(&cur_buf, i);
            if idx_entry.block <= lblock {
                chosen = Some(idx_entry.leaf);
            } else {
                break;
            }
        }
        let Some(next_blk) = chosen else {
            return Ok(None);
        };
        let mut next_buf = vec![0u8; io.block_size()];
        io.read_fs_block(next_blk, &mut next_buf)?;
        cur_buf = next_buf;
    }
    Err(Errno::EIO)
}

fn map_legacy_block(
    io: &mut dyn BlockAllocIo,
    inode: &DiskInode,
    lblock: u32,
) -> Result<Option<u64>, Errno> {
    let ptrs_per_blk = (io.block_size() / 4) as u32;
    if lblock < 12 {
        let blk = read_u32(&inode.i_block, (lblock as usize) * 4);
        return Ok((blk != 0).then_some(u64::from(blk)));
    }
    let idx1 = lblock - 12;
    if idx1 < ptrs_per_blk {
        let ind = read_u32(&inode.i_block, 12 * 4);
        if ind == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u8; io.block_size()];
        io.read_fs_block(u64::from(ind), &mut buf)?;
        let blk = read_u32(&buf, (idx1 as usize) * 4);
        return Ok((blk != 0).then_some(u64::from(blk)));
    }
    let idx2 = idx1 - ptrs_per_blk;
    if idx2 < ptrs_per_blk * ptrs_per_blk {
        let dind = read_u32(&inode.i_block, 13 * 4);
        if dind == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u8; io.block_size()];
        io.read_fs_block(u64::from(dind), &mut buf)?;
        let ind = read_u32(&buf, ((idx2 / ptrs_per_blk) as usize) * 4);
        if ind == 0 {
            return Ok(None);
        }
        io.read_fs_block(u64::from(ind), &mut buf)?;
        let blk = read_u32(&buf, ((idx2 % ptrs_per_blk) as usize) * 4);
        return Ok((blk != 0).then_some(u64::from(blk)));
    }
    Err(Errno::E2BIG)
}

#[derive(Clone, Copy)]
enum LeafInsertOutcome {
    Done,
    NeedSplit,
}

fn try_insert_leaf_in_node(
    buf: &mut [u8],
    lblock: u32,
    pblock: u64,
    allow_merge: bool,
) -> Result<LeafInsertOutcome, Errno> {
    let mut hdr = ExtentHeader::parse(buf)?;
    if hdr.depth != 0 {
        return Err(Errno::EIO);
    }

    let mut leaves = Vec::with_capacity(usize::from(hdr.entries));
    for i in 0..hdr.entries {
        leaves.push(ExtentLeaf::parse(buf, i));
    }

    // Check existing or contiguous extend.
    let mut insert_pos = leaves.len();
    for (idx, leaf) in leaves.iter().enumerate() {
        if lblock < leaf.block {
            insert_pos = idx;
            break;
        }
        if lblock < leaf.block.saturating_add(leaf.block_len()) {
            return Err(Errno::EEXIST);
        }
    }

    if allow_merge && insert_pos > 0 {
        let prev = &mut leaves[insert_pos - 1];
        if !prev.is_unwritten()
            && prev.raw_len < EXTENT_MAX_LEN
            && prev.block + prev.block_len() == lblock
            && prev.start + u64::from(prev.block_len()) == pblock
        {
            prev.raw_len += 1;
            prev.write(buf, (insert_pos - 1) as u16);
            return Ok(LeafInsertOutcome::Done);
        }
    }

    if allow_merge && insert_pos < leaves.len() {
        let next = &mut leaves[insert_pos];
        if !next.is_unwritten()
            && next.raw_len < EXTENT_MAX_LEN
            && lblock + 1 == next.block
            && pblock + 1 == next.start
        {
            next.block = lblock;
            next.start = pblock;
            next.raw_len += 1;
            next.write(buf, insert_pos as u16);
            return Ok(LeafInsertOutcome::Done);
        }
    }

    if hdr.entries >= hdr.max {
        return Ok(LeafInsertOutcome::NeedSplit);
    }

    let new_leaf = ExtentLeaf {
        block: lblock,
        raw_len: 1,
        start: pblock,
    };
    leaves.insert(insert_pos, new_leaf);
    hdr.entries = leaves.len() as u16;
    hdr.write(buf);
    for (i, item) in leaves.iter().enumerate() {
        item.write(buf, i as u16);
    }
    Ok(LeafInsertOutcome::Done)
}

fn grow_root_depth(
    io: &mut dyn BlockAllocIo,
    inode: &mut DiskInode,
    goal_group: u32,
) -> Result<(), Errno> {
    let hdr = ExtentHeader::parse(&inode.i_block)?;
    let new_blk = io.alloc_fs_block(goal_group)?;
    let mut child_buf = vec![0u8; io.block_size()];
    let child_hdr = ExtentHeader {
        entries: hdr.entries,
        max: external_max_entries(io),
        depth: hdr.depth,
        generation: hdr.generation,
    };
    child_hdr.write(&mut child_buf);
    let copy_bytes = usize::from(hdr.entries) * EXTENT_ENTRY_BYTES;
    child_buf[EXTENT_HEADER_BYTES..EXTENT_HEADER_BYTES + copy_bytes]
        .copy_from_slice(&inode.i_block[EXTENT_HEADER_BYTES..EXTENT_HEADER_BYTES + copy_bytes]);

    let first_logical = if hdr.entries == 0 {
        0
    } else if hdr.depth == 0 {
        ExtentLeaf::parse(&inode.i_block, 0).block
    } else {
        ExtentIdx::parse(&inode.i_block, 0).block
    };

    stamp_extent_block_tail(
        io.fs_seed(),
        inode.ino,
        inode.generation,
        &mut child_buf,
        io.metadata_csum(),
    );
    if let Err(err) = io.write_fs_block(new_blk, &child_buf) {
        let _ = io.free_fs_block(new_blk);
        return Err(err);
    }

    inode.i_block = [0u8; 60];
    let root_hdr = ExtentHeader {
        entries: 1,
        max: EXTENT_ROOT_MAX_ENTRIES,
        depth: hdr.depth + 1,
        generation: hdr.generation,
    };
    root_hdr.write(&mut inode.i_block);
    ExtentIdx {
        block: first_logical,
        leaf: new_blk,
    }
    .write(&mut inode.i_block, 0);
    inode.add_disk_blocks_512(1, io.block_size());
    Ok(())
}

/// Inserts an index entry `(split_block, right_child)` into a parent node, or splits the parent.
enum InsertResult {
    Done,
    Split { key: u32, right_blk: u64 },
}

fn insert_in_subtree(
    io: &mut dyn BlockAllocIo,
    inode: &mut DiskInode,
    node_blk: Option<u64>,
    lblock: u32,
    pblock: u64,
    goal_group: u32,
) -> Result<InsertResult, Errno> {
    let mut buf = read_node(io, inode, node_blk)?;
    let mut hdr = ExtentHeader::parse(&buf)?;
    if hdr.depth == 0 {
        match try_insert_leaf_in_node(&mut buf, lblock, pblock, true)? {
            LeafInsertOutcome::Done => {
                save_node(io, inode, node_blk, &mut buf)?;
                return Ok(InsertResult::Done);
            }
            LeafInsertOutcome::NeedSplit => {
                // Split leaf node cleanly into two blocks.
                let mut leaves = Vec::with_capacity(usize::from(hdr.entries) + 1);
                for i in 0..hdr.entries {
                    leaves.push(ExtentLeaf::parse(&buf, i));
                }
                let pos = leaves.partition_point(|e| e.block < lblock);
                leaves.insert(
                    pos,
                    ExtentLeaf {
                        block: lblock,
                        raw_len: 1,
                        start: pblock,
                    },
                );
                let mid = leaves.len() / 2;
                let right_blk = io.alloc_fs_block(goal_group)?;
                let mut right_buf = vec![0u8; io.block_size()];
                let right_hdr = ExtentHeader {
                    entries: (leaves.len() - mid) as u16,
                    max: external_max_entries(io),
                    depth: 0,
                    generation: hdr.generation,
                };
                right_hdr.write(&mut right_buf);
                for (i, item) in leaves[mid..].iter().enumerate() {
                    item.write(&mut right_buf, i as u16);
                }
                stamp_extent_block_tail(
                    io.fs_seed(),
                    inode.ino,
                    inode.generation,
                    &mut right_buf,
                    io.metadata_csum(),
                );
                io.write_fs_block(right_blk, &right_buf)?;

                buf.fill(0);
                hdr.entries = mid as u16;
                hdr.write(&mut buf);
                for (i, item) in leaves[..mid].iter().enumerate() {
                    item.write(&mut buf, i as u16);
                }
                save_node(io, inode, node_blk, &mut buf)?;
                inode.add_disk_blocks_512(1, io.block_size());
                return Ok(InsertResult::Split {
                    key: leaves[mid].block,
                    right_blk,
                });
            }
        }
    }

    // Internal node (depth > 0).
    let mut child_idx = 0u16;
    for i in 0..hdr.entries {
        let e = ExtentIdx::parse(&buf, i);
        if e.block <= lblock {
            child_idx = i;
        } else {
            break;
        }
    }
    let chosen_entry = ExtentIdx::parse(&buf, child_idx);
    // Keep ei_block of child 0 consistent if inserting before existing minimum.
    if lblock < chosen_entry.block && child_idx == 0 {
        let mut updated = chosen_entry;
        updated.block = lblock;
        updated.write(&mut buf, 0);
        save_node(io, inode, node_blk, &mut buf)?;
    }

    match insert_in_subtree(
        io,
        inode,
        Some(chosen_entry.leaf),
        lblock,
        pblock,
        goal_group,
    )? {
        InsertResult::Done => Ok(InsertResult::Done),
        InsertResult::Split { key, right_blk } => {
            let mut entries = Vec::with_capacity(usize::from(hdr.entries) + 1);
            for i in 0..hdr.entries {
                entries.push(ExtentIdx::parse(&buf, i));
            }
            let pos = entries.partition_point(|e| e.block < key);
            entries.insert(
                pos,
                ExtentIdx {
                    block: key,
                    leaf: right_blk,
                },
            );
            if entries.len() <= usize::from(hdr.max) {
                hdr.entries = entries.len() as u16;
                hdr.write(&mut buf);
                for (i, item) in entries.iter().enumerate() {
                    item.write(&mut buf, i as u16);
                }
                save_node(io, inode, node_blk, &mut buf)?;
                Ok(InsertResult::Done)
            } else {
                let mid = entries.len() / 2;
                let new_right = io.alloc_fs_block(goal_group)?;
                let mut right_buf = vec![0u8; io.block_size()];
                let right_hdr = ExtentHeader {
                    entries: (entries.len() - mid) as u16,
                    max: external_max_entries(io),
                    depth: hdr.depth,
                    generation: hdr.generation,
                };
                right_hdr.write(&mut right_buf);
                for (i, item) in entries[mid..].iter().enumerate() {
                    item.write(&mut right_buf, i as u16);
                }
                stamp_extent_block_tail(
                    io.fs_seed(),
                    inode.ino,
                    inode.generation,
                    &mut right_buf,
                    io.metadata_csum(),
                );
                io.write_fs_block(new_right, &right_buf)?;

                buf.fill(0);
                hdr.entries = mid as u16;
                hdr.write(&mut buf);
                for (i, item) in entries[..mid].iter().enumerate() {
                    item.write(&mut buf, i as u16);
                }
                save_node(io, inode, node_blk, &mut buf)?;
                inode.add_disk_blocks_512(1, io.block_size());
                Ok(InsertResult::Split {
                    key: entries[mid].block,
                    right_blk: new_right,
                })
            }
        }
    }
}

/// Ensures logical block `lblock` maps to a physical block, allocating one if sparse/unmapped.
/// Returns `(physical_block, newly_allocated)`.
pub fn map_or_alloc_logical_block(
    io: &mut dyn BlockAllocIo,
    inode: &mut DiskInode,
    lblock: u32,
    goal_group: u32,
) -> Result<(u64, bool), Errno> {
    if !inode.uses_extents() {
        return Err(Errno::EOPNOTSUPP);
    }
    if let Some(existing) = map_logical_block(io, inode, lblock)? {
        return Ok((existing, false));
    }

    let pblock = io.alloc_fs_block(goal_group)?;
    let root_hdr = ExtentHeader::parse(&inode.i_block)?;
    if root_hdr.depth == 0 {
        let mut root_buf = inode.i_block.to_vec();
        match try_insert_leaf_in_node(&mut root_buf, lblock, pblock, true)? {
            LeafInsertOutcome::Done => {
                inode.i_block.copy_from_slice(&root_buf[..60]);
                inode.add_disk_blocks_512(1, io.block_size());
                return Ok((pblock, true));
            }
            LeafInsertOutcome::NeedSplit => {
                if let Err(err) = grow_root_depth(io, inode, goal_group) {
                    let _ = io.free_fs_block(pblock);
                    return Err(err);
                }
            }
        }
    }

    // Root now has depth >= 1 (or previously had depth >= 1).
    let res = match insert_in_subtree(io, inode, None, lblock, pblock, goal_group) {
        Ok(r) => r,
        Err(err) => {
            let _ = io.free_fs_block(pblock);
            return Err(err);
        }
    };
    if let InsertResult::Split { key, right_blk } = res {
        grow_root_depth(io, inode, goal_group)?;
        let mut root_hdr = ExtentHeader::parse(&inode.i_block)?;
        let mut idx0 = ExtentIdx::parse(&inode.i_block, 0);
        idx0.block = idx0.block.min(key);
        idx0.write(&mut inode.i_block, 0);
        ExtentIdx {
            block: key,
            leaf: right_blk,
        }
        .write(&mut inode.i_block, 1);
        root_hdr.entries = 2;
        root_hdr.write(&mut inode.i_block);
    }
    inode.add_disk_blocks_512(1, io.block_size());
    Ok((pblock, true))
}

fn truncate_subtree(
    io: &mut dyn BlockAllocIo,
    inode: &mut DiskInode,
    node_blk: Option<u64>,
    keep_blocks: u32,
) -> Result<bool, Errno> {
    let mut buf = read_node(io, inode, node_blk)?;
    let mut hdr = ExtentHeader::parse(&buf)?;
    if hdr.depth == 0 {
        let mut kept = Vec::new();
        for i in 0..hdr.entries {
            let mut leaf = ExtentLeaf::parse(&buf, i);
            let len = leaf.block_len();
            let end = leaf.block.saturating_add(len);
            if leaf.block >= keep_blocks {
                if !leaf.is_unwritten() {
                    for off in 0..u64::from(len) {
                        io.free_fs_block(leaf.start + off)?;
                        inode.add_disk_blocks_512(-1, io.block_size());
                    }
                }
            } else if end > keep_blocks {
                let keep_len = keep_blocks - leaf.block;
                if !leaf.is_unwritten() {
                    for off in u64::from(keep_len)..u64::from(len) {
                        io.free_fs_block(leaf.start + off)?;
                        inode.add_disk_blocks_512(-1, io.block_size());
                    }
                }
                leaf.raw_len = if leaf.is_unwritten() {
                    EXTENT_MAX_LEN + (keep_len as u16)
                } else {
                    keep_len as u16
                };
                kept.push(leaf);
            } else {
                kept.push(leaf);
            }
        }
        if kept.is_empty() && node_blk.is_some() {
            return Ok(true);
        }
        let header_copy = ExtentHeader {
            entries: kept.len() as u16,
            max: hdr.max,
            depth: 0,
            generation: hdr.generation,
        };
        let keep_slice_end = EXTENT_HEADER_BYTES + kept.len() * EXTENT_ENTRY_BYTES;
        buf[..keep_slice_end].fill(0);
        header_copy.write(&mut buf);
        for (i, item) in kept.iter().enumerate() {
            item.write(&mut buf, i as u16);
        }
        save_node(io, inode, node_blk, &mut buf)?;
        return Ok(false);
    }

    let mut kept_idx = Vec::new();
    for i in 0..hdr.entries {
        let idx_entry = ExtentIdx::parse(&buf, i);
        let child_empty = truncate_subtree(io, inode, Some(idx_entry.leaf), keep_blocks)?;
        if child_empty {
            io.free_fs_block(idx_entry.leaf)?;
            inode.add_disk_blocks_512(-1, io.block_size());
        } else {
            kept_idx.push(idx_entry);
        }
    }
    if kept_idx.is_empty() && node_blk.is_some() {
        return Ok(true);
    }
    if kept_idx.is_empty() && node_blk.is_none() {
        inode.i_block = [0u8; 60];
        ExtentHeader {
            entries: 0,
            max: EXTENT_ROOT_MAX_ENTRIES,
            depth: 0,
            generation: hdr.generation,
        }
        .write(&mut inode.i_block);
        return Ok(false);
    }
    hdr.entries = kept_idx.len() as u16;
    hdr.write(&mut buf);
    for (i, item) in kept_idx.iter().enumerate() {
        item.write(&mut buf, i as u16);
    }
    save_node(io, inode, node_blk, &mut buf)?;
    Ok(false)
}

/// Frees all data and external extent blocks starting at `keep_blocks` (`keep_blocks = 0` frees all).
pub fn truncate_extents(
    io: &mut dyn BlockAllocIo,
    inode: &mut DiskInode,
    keep_blocks: u32,
) -> Result<(), Errno> {
    if !inode.uses_extents() {
        return Err(Errno::EOPNOTSUPP);
    }
    let _ = truncate_subtree(io, inode, None, keep_blocks)?;
    Ok(())
}
