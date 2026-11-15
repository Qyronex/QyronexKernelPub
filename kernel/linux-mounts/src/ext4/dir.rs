// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Linear & HTree-compatible `ext4` directory lookup, iteration, and mutation.

use alloc::vec;
use alloc::vec::Vec;
use kernal_linux_abi::Errno;

use super::crc32c::stamp_dir_block_tail;
use super::extent::{BlockAllocIo, map_logical_block, map_or_alloc_logical_block};
use super::format::{
    DiskInode, EXT4_FT_CSUM, EXT4_FT_DIR, EXT4_FT_UNKNOWN, EXT4_INDEX_FL, read_u16, read_u32,
    write_u16, write_u32,
};

#[derive(Clone, Debug)]
pub struct DirEntryItem {
    pub inode: u32,
    pub file_type: u8,
    pub name: Vec<u8>,
}

#[inline]
const fn aligned_entry_len(name_len: usize) -> usize {
    (8 + name_len + 3) & !3
}

#[inline]
fn usable_block_end(io: &dyn BlockAllocIo) -> usize {
    if io.metadata_csum() {
        io.block_size() - 12
    } else {
        io.block_size()
    }
}

#[inline]
fn is_checksum_tail(buf: &[u8], off: usize) -> bool {
    off + 8 <= buf.len() && buf[off + 7] == EXT4_FT_CSUM && read_u32(buf, off) == 0
}

#[inline]
fn is_dx_internal_block(buf: &[u8], block_size: usize) -> bool {
    buf.len() >= 12
        && read_u32(buf, 0) == 0
        && usize::from(read_u16(buf, 4)) == block_size
        && buf[6] == 0
        && buf[7] == 0
}

fn format_empty_dir_block(io: &dyn BlockAllocIo, dir_ino: u32, dir_gen: u32, buf: &mut [u8]) {
    buf.fill(0);
    let end = usable_block_end(io);
    write_u32(buf, 0, 0);
    write_u16(buf, 4, end as u16);
    stamp_dir_block_tail(io.fs_seed(), dir_ino, dir_gen, buf, io.metadata_csum());
}

/// Initializes a freshly created directory's block 0 containing `.` and `..` plus tail checksum.
pub fn init_dot_dotdot_block(
    io: &mut dyn BlockAllocIo,
    dir_inode: &mut DiskInode,
    parent_ino: u32,
    goal_group: u32,
) -> Result<(), Errno> {
    let bs = io.block_size();
    let end = usable_block_end(io);
    if end < 24 {
        return Err(Errno::EIO);
    }
    let (pblock, _) = map_or_alloc_logical_block(io, dir_inode, 0, goal_group)?;
    let mut blk = vec![0u8; bs];

    // `.` entry (12 bytes)
    write_u32(&mut blk, 0, dir_inode.ino);
    write_u16(&mut blk, 4, 12);
    blk[6] = 1;
    blk[7] = EXT4_FT_DIR;
    blk[8] = b'.';

    // `..` entry spanning remaining usable space
    write_u32(&mut blk, 12, parent_ino);
    write_u16(&mut blk, 16, (end - 12) as u16);
    blk[18] = 2;
    blk[19] = EXT4_FT_DIR;
    blk[20] = b'.';
    blk[21] = b'.';

    stamp_dir_block_tail(
        io.fs_seed(),
        dir_inode.ino,
        dir_inode.generation,
        &mut blk,
        io.metadata_csum(),
    );
    io.write_fs_block(pblock, &blk)?;
    dir_inode.size = bs as u64;
    Ok(())
}

/// Converts an HTree (`EXT4_INDEX_FL`) directory to standard linear directory blocks before write.
fn ensure_linear_dir(io: &mut dyn BlockAllocIo, dir_inode: &mut DiskInode) -> Result<(), Errno> {
    if (dir_inode.flags & EXT4_INDEX_FL) == 0 {
        return Ok(());
    }
    let bs = io.block_size();
    let end = usable_block_end(io);
    let num_blocks = (dir_inode.size as usize).div_ceil(bs) as u32;

    if num_blocks > 0
        && let Some(pb0) = map_logical_block(io, dir_inode, 0)?
    {
        let mut blk = vec![0u8; bs];
        io.read_fs_block(pb0, &mut blk)?;
        let parent_ino = if blk.len() >= 24 {
            read_u32(&blk, 12)
        } else {
            dir_inode.ino
        };
        blk.fill(0);
        write_u32(&mut blk, 0, dir_inode.ino);
        write_u16(&mut blk, 4, 12);
        blk[6] = 1;
        blk[7] = EXT4_FT_DIR;
        blk[8] = b'.';

        write_u32(&mut blk, 12, parent_ino);
        write_u16(&mut blk, 16, (end - 12) as u16);
        blk[18] = 2;
        blk[19] = EXT4_FT_DIR;
        blk[20] = b'.';
        blk[21] = b'.';
        stamp_dir_block_tail(
            io.fs_seed(),
            dir_inode.ino,
            dir_inode.generation,
            &mut blk,
            io.metadata_csum(),
        );
        io.write_fs_block(pb0, &blk)?;
    }

    for lblock in 1..num_blocks {
        let Some(pb) = map_logical_block(io, dir_inode, lblock)? else {
            continue;
        };
        let mut blk = vec![0u8; bs];
        io.read_fs_block(pb, &mut blk)?;
        if is_dx_internal_block(&blk, bs) {
            format_empty_dir_block(io, dir_inode.ino, dir_inode.generation, &mut blk);
            io.write_fs_block(pb, &blk)?;
        }
    }

    dir_inode.flags &= !EXT4_INDEX_FL;
    Ok(())
}

/// Lists all valid entries inside `dir_inode`.
pub fn list_entries(
    io: &mut dyn BlockAllocIo,
    dir_inode: &DiskInode,
    has_filetype: bool,
) -> Result<Vec<DirEntryItem>, Errno> {
    let bs = io.block_size();
    let num_blocks = (dir_inode.size as usize).div_ceil(bs) as u32;
    let mut blk = vec![0u8; bs];
    let mut entries = Vec::new();

    for lblock in 0..num_blocks {
        let Some(pb) = map_logical_block(io, dir_inode, lblock)? else {
            continue;
        };
        io.read_fs_block(pb, &mut blk)?;
        let mut off = 0usize;
        while off + 8 <= bs {
            if is_checksum_tail(&blk, off) {
                break;
            }
            let rec_len = usize::from(read_u16(&blk, off + 4));
            if rec_len < 8 || (rec_len & 3) != 0 || off + rec_len > bs {
                break;
            }
            let ino = read_u32(&blk, off);
            let name_len = usize::from(blk[off + 6]);
            let file_type = if has_filetype {
                blk[off + 7]
            } else {
                EXT4_FT_UNKNOWN
            };
            if ino != 0 && name_len > 0 && off + 8 + name_len <= off + rec_len {
                entries.push(DirEntryItem {
                    inode: ino,
                    file_type,
                    name: blk[off + 8..off + 8 + name_len].to_vec(),
                });
            }
            off += rec_len;
        }
    }
    Ok(entries)
}

/// Finds a single entry by exact name inside `dir_inode`.
pub fn find_entry(
    io: &mut dyn BlockAllocIo,
    dir_inode: &DiskInode,
    target_name: &[u8],
    has_filetype: bool,
) -> Result<Option<DirEntryItem>, Errno> {
    if target_name.is_empty() || target_name.len() > 255 {
        return Err(Errno::EINVAL);
    }
    let bs = io.block_size();
    let num_blocks = (dir_inode.size as usize).div_ceil(bs) as u32;
    let mut blk = vec![0u8; bs];

    for lblock in 0..num_blocks {
        let Some(pb) = map_logical_block(io, dir_inode, lblock)? else {
            continue;
        };
        io.read_fs_block(pb, &mut blk)?;
        let mut off = 0usize;
        while off + 8 <= bs {
            if is_checksum_tail(&blk, off) {
                break;
            }
            let rec_len = usize::from(read_u16(&blk, off + 4));
            if rec_len < 8 || (rec_len & 3) != 0 || off + rec_len > bs {
                break;
            }
            let ino = read_u32(&blk, off);
            let name_len = usize::from(blk[off + 6]);
            if ino != 0
                && name_len == target_name.len()
                && off + 8 + name_len <= off + rec_len
                && &blk[off + 8..off + 8 + name_len] == target_name
            {
                return Ok(Some(DirEntryItem {
                    inode: ino,
                    file_type: if has_filetype {
                        blk[off + 7]
                    } else {
                        EXT4_FT_UNKNOWN
                    },
                    name: target_name.to_vec(),
                }));
            }
            off += rec_len;
        }
    }
    Ok(None)
}

pub fn is_dir_empty(io: &mut dyn BlockAllocIo, dir_inode: &DiskInode) -> Result<bool, Errno> {
    let entries = list_entries(io, dir_inode, true)?;
    Ok(entries
        .iter()
        .all(|e| e.name.as_slice() == b"." || e.name.as_slice() == b".."))
}

/// Adds `(child_ino, file_type, name)` to `dir_inode`, reusing slack or appending a dir block.
pub fn add_entry(
    io: &mut dyn BlockAllocIo,
    dir_inode: &mut DiskInode,
    name: &[u8],
    child_ino: u32,
    file_type: u8,
    has_filetype: bool,
    goal_group: u32,
) -> Result<(), Errno> {
    if name.is_empty() || name.len() > 255 || name == b"." || name == b".." || name.contains(&b'/')
    {
        return Err(Errno::EINVAL);
    }
    if find_entry(io, dir_inode, name, has_filetype)?.is_some() {
        return Err(Errno::EEXIST);
    }

    ensure_linear_dir(io, dir_inode)?;

    let bs = io.block_size();
    let usable_end = usable_block_end(io);
    let need_len = aligned_entry_len(name.len());
    let num_blocks = (dir_inode.size as usize).div_ceil(bs) as u32;
    let mut blk = vec![0u8; bs];
    let stored_ft = if has_filetype { file_type } else { 0 };

    for lblock in 0..num_blocks {
        let Some(pb) = map_logical_block(io, dir_inode, lblock)? else {
            continue;
        };
        io.read_fs_block(pb, &mut blk)?;
        let mut off = 0usize;
        while off + 8 <= usable_end {
            if is_checksum_tail(&blk, off) {
                break;
            }
            let rec_len = usize::from(read_u16(&blk, off + 4));
            if rec_len < 8 || (rec_len & 3) != 0 || off + rec_len > usable_end {
                break;
            }
            let cur_ino = read_u32(&blk, off);
            if cur_ino == 0 && rec_len >= need_len {
                write_u32(&mut blk, off, child_ino);
                write_u16(&mut blk, off + 4, rec_len as u16);
                blk[off + 6] = name.len() as u8;
                blk[off + 7] = stored_ft;
                blk[off + 8..off + 8 + name.len()].copy_from_slice(name);
                blk[off + 8 + name.len()..off + rec_len].fill(0);
                stamp_dir_block_tail(
                    io.fs_seed(),
                    dir_inode.ino,
                    dir_inode.generation,
                    &mut blk,
                    io.metadata_csum(),
                );
                io.write_fs_block(pb, &blk)?;
                return Ok(());
            }
            let cur_actual = if cur_ino == 0 {
                0
            } else {
                aligned_entry_len(usize::from(blk[off + 6]))
            };
            if rec_len >= cur_actual + need_len {
                let new_off = off + cur_actual;
                let rem_len = rec_len - cur_actual;
                write_u16(&mut blk, off + 4, cur_actual as u16);
                blk[new_off..new_off + rem_len].fill(0);
                write_u32(&mut blk, new_off, child_ino);
                write_u16(&mut blk, new_off + 4, rem_len as u16);
                blk[new_off + 6] = name.len() as u8;
                blk[new_off + 7] = stored_ft;
                blk[new_off + 8..new_off + 8 + name.len()].copy_from_slice(name);
                stamp_dir_block_tail(
                    io.fs_seed(),
                    dir_inode.ino,
                    dir_inode.generation,
                    &mut blk,
                    io.metadata_csum(),
                );
                io.write_fs_block(pb, &blk)?;
                return Ok(());
            }
            off += rec_len;
        }
    }

    // No space in existing directory blocks; allocate and format a new block.
    let new_lblock = num_blocks;
    let (new_pb, _) = map_or_alloc_logical_block(io, dir_inode, new_lblock, goal_group)?;
    blk.fill(0);
    write_u32(&mut blk, 0, child_ino);
    write_u16(&mut blk, 4, usable_end as u16);
    blk[6] = name.len() as u8;
    blk[7] = stored_ft;
    blk[8..8 + name.len()].copy_from_slice(name);
    stamp_dir_block_tail(
        io.fs_seed(),
        dir_inode.ino,
        dir_inode.generation,
        &mut blk,
        io.metadata_csum(),
    );
    io.write_fs_block(new_pb, &blk)?;
    dir_inode.size = u64::from(new_lblock + 1) * (bs as u64);
    Ok(())
}

/// Removes entry `name` from `dir_inode` and returns its inode number and file_type.
pub fn remove_entry(
    io: &mut dyn BlockAllocIo,
    dir_inode: &mut DiskInode,
    name: &[u8],
) -> Result<(u32, u8), Errno> {
    if name.is_empty() || name.len() > 255 || name == b"." || name == b".." {
        return Err(Errno::EINVAL);
    }
    ensure_linear_dir(io, dir_inode)?;

    let bs = io.block_size();
    let usable_end = usable_block_end(io);
    let num_blocks = (dir_inode.size as usize).div_ceil(bs) as u32;
    let mut blk = vec![0u8; bs];

    for lblock in 0..num_blocks {
        let Some(pb) = map_logical_block(io, dir_inode, lblock)? else {
            continue;
        };
        io.read_fs_block(pb, &mut blk)?;
        let mut off = 0usize;
        let mut prev_off: Option<usize> = None;
        while off + 8 <= usable_end {
            if is_checksum_tail(&blk, off) {
                break;
            }
            let rec_len = usize::from(read_u16(&blk, off + 4));
            if rec_len < 8 || (rec_len & 3) != 0 || off + rec_len > usable_end {
                break;
            }
            let ino = read_u32(&blk, off);
            let name_len = usize::from(blk[off + 6]);
            if ino != 0
                && name_len == name.len()
                && off + 8 + name_len <= off + rec_len
                && &blk[off + 8..off + 8 + name_len] == name
            {
                let ft = blk[off + 7];
                if let Some(poff) = prev_off {
                    let prev_len = usize::from(read_u16(&blk, poff + 4));
                    write_u16(&mut blk, poff + 4, (prev_len + rec_len) as u16);
                    blk[off..off + rec_len].fill(0);
                } else {
                    write_u32(&mut blk, off, 0);
                    blk[off + 6] = 0;
                    blk[off + 7] = 0;
                    blk[off + 8..off + rec_len].fill(0);
                }
                stamp_dir_block_tail(
                    io.fs_seed(),
                    dir_inode.ino,
                    dir_inode.generation,
                    &mut blk,
                    io.metadata_csum(),
                );
                io.write_fs_block(pb, &blk)?;
                return Ok((ino, ft));
            }
            prev_off = Some(off);
            off += rec_len;
        }
    }
    Err(Errno::ENOENT)
}

/// Updates the `..` parent inode pointer inside `dir_inode` when moving a directory across parents.
pub fn update_dotdot(
    io: &mut dyn BlockAllocIo,
    dir_inode: &mut DiskInode,
    new_parent_ino: u32,
) -> Result<(), Errno> {
    ensure_linear_dir(io, dir_inode)?;
    let bs = io.block_size();
    let Some(pb0) = map_logical_block(io, dir_inode, 0)? else {
        return Err(Errno::EIO);
    };
    let mut blk = vec![0u8; bs];
    io.read_fs_block(pb0, &mut blk)?;
    let mut off = 0usize;
    while off + 8 <= bs {
        let rec_len = usize::from(read_u16(&blk, off + 4));
        if rec_len < 8 || off + rec_len > bs {
            break;
        }
        let name_len = usize::from(blk[off + 6]);
        if name_len == 2 && off + 10 <= off + rec_len && &blk[off + 8..off + 10] == b".." {
            write_u32(&mut blk, off, new_parent_ino);
            stamp_dir_block_tail(
                io.fs_seed(),
                dir_inode.ino,
                dir_inode.generation,
                &mut blk,
                io.metadata_csum(),
            );
            io.write_fs_block(pb0, &blk)?;
            return Ok(());
        }
        off += rec_len;
    }
    Err(Errno::EIO)
}

/// Replaces `name`'s target inode in place during `rename` over an existing entry.
pub fn replace_entry_target(
    io: &mut dyn BlockAllocIo,
    dir_inode: &mut DiskInode,
    name: &[u8],
    new_ino: u32,
    new_ft: u8,
    has_filetype: bool,
) -> Result<u32, Errno> {
    ensure_linear_dir(io, dir_inode)?;
    let bs = io.block_size();
    let num_blocks = (dir_inode.size as usize).div_ceil(bs) as u32;
    let mut blk = vec![0u8; bs];
    for lblock in 0..num_blocks {
        let Some(pb) = map_logical_block(io, dir_inode, lblock)? else {
            continue;
        };
        io.read_fs_block(pb, &mut blk)?;
        let mut off = 0usize;
        while off + 8 <= bs {
            if is_checksum_tail(&blk, off) {
                break;
            }
            let rec_len = usize::from(read_u16(&blk, off + 4));
            if rec_len < 8 || (rec_len & 3) != 0 || off + rec_len > bs {
                break;
            }
            let ino = read_u32(&blk, off);
            let name_len = usize::from(blk[off + 6]);
            if ino != 0
                && name_len == name.len()
                && off + 8 + name_len <= off + rec_len
                && &blk[off + 8..off + 8 + name_len] == name
            {
                write_u32(&mut blk, off, new_ino);
                blk[off + 7] = if has_filetype { new_ft } else { 0 };
                stamp_dir_block_tail(
                    io.fs_seed(),
                    dir_inode.ino,
                    dir_inode.generation,
                    &mut blk,
                    io.metadata_csum(),
                );
                io.write_fs_block(pb, &blk)?;
                return Ok(ino);
            }
            off += rec_len;
        }
    }
    Err(Errno::ENOENT)
}
