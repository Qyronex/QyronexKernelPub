// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Castagnoli CRC32C helpers matching Linux `ext4` `metadata_csum`.

const CRC32C_POLY_REFLECTED: u32 = 0x82f6_3b78;

const fn build_crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ CRC32C_POLY_REFLECTED;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const CRC32C_TABLE: [u32; 256] = build_crc32c_table();

/// Raw Castagnoli CRC32C update matching Linux kernel `ext4_chksum()` (no final XOR).
#[inline]
pub fn crc32c_raw(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xff) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[idx];
    }
    crc
}

/// Computes `crc32c(~0, s_uuid)` used as the seed for all `metadata_csum` objects.
pub fn uuid_csum_seed(uuid: &[u8; 16]) -> u32 {
    crc32c_raw(u32::MAX, uuid)
}

/// Extends `fs_seed` with `(ino, i_generation)` used by inodes, dir blocks, and extent blocks.
pub fn inode_csum_seed(fs_seed: u32, ino: u32, generation: u32) -> u32 {
    let mut hdr = [0u8; 8];
    hdr[0..4].copy_from_slice(&ino.to_le_bytes());
    hdr[4..8].copy_from_slice(&generation.to_le_bytes());
    crc32c_raw(fs_seed, &hdr)
}

/// Superblock checksum covers bytes `0..0x3fc` starting from `~0`.
pub fn superblock_csum(sb_bytes: &[u8; 1024]) -> u32 {
    crc32c_raw(u32::MAX, &sb_bytes[..0x3fc])
}

/// Group descriptor checksum (`crc32c(seed, group_idx || desc_with_bg_checksum_zeroed) & 0xffff`).
pub fn group_desc_csum(fs_seed: u32, group: u32, desc: &[u8]) -> u16 {
    let mut crc = crc32c_raw(fs_seed, &group.to_le_bytes());
    let zero_at = 0x1eusize.min(desc.len());
    crc = crc32c_raw(crc, &desc[..zero_at]);
    if desc.len() > 0x1e {
        crc = crc32c_raw(crc, &[0u8; 2]);
        if desc.len() > 0x20 {
            crc = crc32c_raw(crc, &desc[0x20..]);
        }
    }
    (crc & 0xffff) as u16
}

/// Computes `ext4` bitmap checksum (`crc32c(fs_seed, bitmap[..valid_bytes])`).
pub fn bitmap_csum(fs_seed: u32, bitmap: &[u8], bits_in_group: u32) -> u32 {
    let byte_len = (usize::try_from(bits_in_group).unwrap_or(0))
        .div_ceil(8)
        .min(bitmap.len());
    crc32c_raw(fs_seed, &bitmap[..byte_len])
}

/// Computes 32-bit inode checksum (`i_checksum_lo` | (`i_checksum_hi << 16`)).
pub fn inode_csum(fs_seed: u32, ino: u32, generation: u32, raw_inode: &[u8]) -> u32 {
    let seed = inode_csum_seed(fs_seed, ino, generation);
    let mut crc = seed;
    let first_end = 0x7cusize.min(raw_inode.len());
    crc = crc32c_raw(crc, &raw_inode[..first_end]);
    if raw_inode.len() >= 0x7e {
        crc = crc32c_raw(crc, &[0u8; 2]);
    }
    if raw_inode.len() > 0x84 {
        crc = crc32c_raw(crc, &raw_inode[0x7e..0x82]);
        crc = crc32c_raw(crc, &[0u8; 2]);
        crc = crc32c_raw(crc, &raw_inode[0x84..]);
    } else if raw_inode.len() > 0x7e {
        crc = crc32c_raw(crc, &raw_inode[0x7e..]);
    }
    crc
}

/// Writes the 12-byte `ext4_dir_entry_tail` checksum at the end of a linear directory block.
pub fn stamp_dir_block_tail(
    fs_seed: u32,
    ino: u32,
    generation: u32,
    block: &mut [u8],
    metadata_csum: bool,
) {
    if !metadata_csum || block.len() < 12 {
        return;
    }
    let tail_off = block.len() - 12;
    block[tail_off..tail_off + 4].copy_from_slice(&0u32.to_le_bytes());
    block[tail_off + 4..tail_off + 6].copy_from_slice(&12u16.to_le_bytes());
    block[tail_off + 6] = 0;
    block[tail_off + 7] = 0xde;
    let seed = inode_csum_seed(fs_seed, ino, generation);
    let csum = crc32c_raw(seed, &block[..tail_off]);
    block[tail_off + 8..tail_off + 12].copy_from_slice(&csum.to_le_bytes());
}

/// Writes the 4-byte `ext4_extent_tail` checksum at the end of an external extent tree block.
pub fn stamp_extent_block_tail(
    fs_seed: u32,
    ino: u32,
    generation: u32,
    block: &mut [u8],
    metadata_csum: bool,
) {
    if !metadata_csum || block.len() < 4 {
        return;
    }
    let tail_off = block.len() - 4;
    let seed = inode_csum_seed(fs_seed, ino, generation);
    let csum = crc32c_raw(seed, &block[..tail_off]);
    block[tail_off..tail_off + 4].copy_from_slice(&csum.to_le_bytes());
}
