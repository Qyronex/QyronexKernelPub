// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Memory-safe (`#![forbid(unsafe_code)]`) Android 15 / GrapheneOS storage & integrity
//! kernel subsystems:
//! - FIPS 180-4 SHA-256
//! - `dm-verity` SHA-256 Merkle-tree block verification & Device-Mapper (`/dev/mapper/control`)
//! - `EROFS` (`0xE0F5E1E2`) on-disk superblock, inode, directory & file reader
//! - `F2FS` (`0xF2F52010`) superblock & encryption/verity/casefold validator
//! - Android `super.img` Dynamic Partitions (`LP_METADATA` `0x616c4467` / `0x414C5030`) parser
//! - Linux/Android `FUSE` (`/dev/fuse`) protocol handshake (`FUSE_INIT` v7.39) & request queue.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;

// ============================================================================
// 1. Pure Rust FIPS 180-4 SHA-256 (`#![forbid(unsafe_code)]`)
// ============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_chunks(chunks: &[&[u8]]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut buf = [0u8; 64];
    let mut buf_len = 0usize;
    let mut total_bits = 0u64;

    let compress = |state: &mut [u32; 8], block: &[u8; 64]| {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(hh);
    };

    for chunk in chunks {
        total_bits = total_bits.wrapping_add((chunk.len() as u64) * 8);
        let mut off = 0usize;
        while off < chunk.len() {
            let take = (64 - buf_len).min(chunk.len() - off);
            buf[buf_len..buf_len + take].copy_from_slice(&chunk[off..off + take]);
            buf_len += take;
            off += take;
            if buf_len == 64 {
                compress(&mut h, &buf);
                buf_len = 0;
            }
        }
    }

    buf[buf_len] = 0x80;
    buf_len += 1;
    if buf_len > 56 {
        buf[buf_len..64].fill(0);
        compress(&mut h, &buf);
        buf_len = 0;
    }
    buf[buf_len..56].fill(0);
    buf[56..64].copy_from_slice(&total_bits.to_be_bytes());
    compress(&mut h, &buf);

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_chunks(&[data])
}

// ============================================================================
// 2. `dm-verity` Merkle-Tree Verifier & Device-Mapper (`/dev/mapper/control`)
// ============================================================================

pub const DM_VERITY_MAGIC: [u8; 8] = *b"verity\0\0";

// Linux Device-Mapper ioctl numbers (`_IOWR(0xfd, cmd, struct dm_ioctl)`)
pub const DM_VERSION_CMD: u32 = 0;
pub const DM_DEV_CREATE_CMD: u32 = 3;
pub const DM_DEV_STATUS_CMD: u32 = 7;
pub const DM_TABLE_LOAD_CMD: u32 = 9;
// Qyronex direct verity block verification ioctl on `/dev/mapper/control`
pub const QYRONEX_DM_VERITY_VERIFY_BLOCK: u64 = 0xc040_fd80;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmVeritySuperblock {
    pub version: u32,
    pub hash_type: u32,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub salt: Vec<u8>,
}

impl DmVeritySuperblock {
    /// Parses a canonical Linux `dm-verity` v1 superblock (512 bytes).
    pub fn parse(raw: &[u8]) -> Result<Self, Errno> {
        if raw.len() < 512 || raw[0..8] != DM_VERITY_MAGIC {
            return Err(Errno::EINVAL);
        }
        let version = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let hash_type = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        let data_block_size = u32::from_le_bytes([raw[64], raw[65], raw[66], raw[67]]);
        let hash_block_size = u32::from_le_bytes([raw[68], raw[69], raw[70], raw[71]]);
        let data_blocks = u64::from_le_bytes([
            raw[72], raw[73], raw[74], raw[75], raw[76], raw[77], raw[78], raw[79],
        ]);
        let salt_size = u16::from_le_bytes([raw[82], raw[83]]) as usize;
        if version != 1
            || hash_type != 1
            || data_block_size == 0
            || !data_block_size.is_power_of_two()
            || hash_block_size == 0
            || !hash_block_size.is_power_of_two()
            || salt_size > 256
        {
            return Err(Errno::EINVAL);
        }
        let salt = raw[88..88 + salt_size].to_vec();
        Ok(Self {
            version,
            hash_type,
            data_block_size,
            hash_block_size,
            data_blocks,
            salt,
        })
    }
}

/// Verified `dm-verity` mapped device instance (single-level or Merkle root verification).
#[derive(Clone, Debug)]
pub struct DmVerityDevice {
    pub name: String,
    pub data_block_size: u32,
    pub salt: Vec<u8>,
    pub root_digest: [u8; 32],
    pub leaf_hashes: Vec<[u8; 32]>,
    pub restart_on_corruption: bool,
}

impl DmVerityDevice {
    /// Builds a verified `dm-verity` Merkle table over the provided data blocks.
    pub fn build_from_blocks(
        name: &str,
        data_block_size: u32,
        salt: &[u8],
        blocks: &[&[u8]],
    ) -> Result<Self, Errno> {
        if blocks.is_empty() || data_block_size == 0 || !data_block_size.is_power_of_two() {
            return Err(Errno::EINVAL);
        }
        let mut leaf_hashes = Vec::with_capacity(blocks.len());
        let mut tree_level_bytes = Vec::with_capacity(blocks.len() * 32);
        for blk in blocks {
            let d = sha256_chunks(&[salt, blk]);
            leaf_hashes.push(d);
            tree_level_bytes.extend_from_slice(&d);
        }
        let root_digest = sha256_chunks(&[salt, &tree_level_bytes]);
        Ok(Self {
            name: String::from(name),
            data_block_size,
            salt: salt.to_vec(),
            root_digest,
            leaf_hashes,
            restart_on_corruption: true,
        })
    }

    /// Verifies `block_index` against its leaf hash AND verifies the Merkle tree root digest.
    /// Fails closed with `Errno::EIO` on any single-bit tampering.
    pub fn verify_block(&self, block_index: usize, data: &[u8]) -> Result<(), Errno> {
        let expected_leaf = self.leaf_hashes.get(block_index).ok_or(Errno::EINVAL)?;
        let actual_leaf = sha256_chunks(&[&self.salt, data]);
        if actual_leaf != *expected_leaf {
            return Err(Errno::EIO);
        }
        // Re-verify Merkle root over leaf level
        let mut level = Vec::with_capacity(self.leaf_hashes.len() * 32);
        for h in &self.leaf_hashes {
            level.extend_from_slice(h);
        }
        let computed_root = sha256_chunks(&[&self.salt, &level]);
        if computed_root != self.root_digest {
            return Err(Errno::EIO);
        }
        Ok(())
    }
}

pub struct DmControlState {
    pub devices: Vec<DmVerityDevice>,
    pub verified_blocks: u64,
    pub corruption_blocks: u64,
}

impl DmControlState {
    pub fn new_with_android_root() -> Self {
        // Pre-seed verified `system-verity` root device covering Qyronex Android 15 system metadata
        let blk0 = b"QYRONEX_ANDROID_15_VERITY_SYSTEM_BLOCK_0";
        let blk1 = b"GRAPHENEOS_AVB2_LOCKED_VERIFIED_BOOT_GREEN";
        let dev = DmVerityDevice::build_from_blocks(
            "system-verity",
            4096,
            b"qyronex-avb2-salt",
            &[blk0.as_slice(), blk1.as_slice()],
        )
        .expect("static dm-verity table valid");
        Self {
            devices: vec![dev],
            verified_blocks: 0,
            corruption_blocks: 0,
        }
    }

    pub fn register_device(&mut self, cap: Capability, dev: DmVerityDevice) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EPERM);
        }
        if let Some(existing) = self.devices.iter_mut().find(|d| d.name == dev.name) {
            *existing = dev;
        } else {
            self.devices.push(dev);
        }
        Ok(())
    }

    pub fn verify_device_block(
        &mut self,
        name: &str,
        block_index: usize,
        data: &[u8],
    ) -> Result<(), Errno> {
        let dev = self
            .devices
            .iter()
            .find(|d| d.name == name)
            .ok_or(Errno::ENOENT)?;
        match dev.verify_block(block_index, data) {
            Ok(()) => {
                self.verified_blocks += 1;
                Ok(())
            }
            Err(e) => {
                if e == Errno::EIO {
                    self.corruption_blocks += 1;
                }
                Err(e)
            }
        }
    }
}

// ============================================================================
// 3. `EROFS` (Enhanced Read-Only File System — Android 14/15 system/APEX)
// ============================================================================

pub const EROFS_SUPER_OFFSET: usize = 1024;
pub const EROFS_SUPER_MAGIC_V1: u32 = 0xE0F5_E1E2;
const EROFS_ISLOTBITS: usize = 5; // 32-byte inode slot unit
const EROFS_INODE_LAYOUT_COMPACT: u16 = 0;
const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;
const EROFS_INODE_FLAT_PLAIN: u16 = 0;
const EROFS_INODE_FLAT_INLINE: u16 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErofsSuperblock {
    pub block_size: usize,
    pub root_nid: u16,
    pub inos: u64,
    pub blocks: u32,
    pub meta_blkaddr: u32,
    pub volume_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErofsInode {
    pub nid: u64,
    pub mode: u16,
    pub size: u64,
    pub raw_blkaddr: u32,
    pub layout_mode: u16,
    pub inode_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErofsDirent {
    pub nid: u64,
    pub file_type: u8,
    pub name: String,
}

impl ErofsSuperblock {
    pub fn parse(image: &[u8]) -> Result<Self, Errno> {
        if image.len() < EROFS_SUPER_OFFSET + 128 {
            return Err(Errno::EINVAL);
        }
        let sb = &image[EROFS_SUPER_OFFSET..];
        let magic = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
        if magic != EROFS_SUPER_MAGIC_V1 {
            return Err(Errno::EINVAL);
        }
        let blkszbits = sb[12];
        if !(9..=16).contains(&blkszbits) {
            return Err(Errno::EINVAL);
        }
        let root_nid = u16::from_le_bytes([sb[14], sb[15]]);
        let inos = u64::from_le_bytes([
            sb[16], sb[17], sb[18], sb[19], sb[20], sb[21], sb[22], sb[23],
        ]);
        let blocks = u32::from_le_bytes([sb[36], sb[37], sb[38], sb[39]]);
        let meta_blkaddr = u32::from_le_bytes([sb[40], sb[41], sb[42], sb[43]]);
        let vol_raw = &sb[64..80];
        let vol_end = vol_raw
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(vol_raw.len());
        let volume_name = String::from_utf8_lossy(&vol_raw[..vol_end]).into_owned();
        Ok(Self {
            block_size: 1usize << blkszbits,
            root_nid,
            inos,
            blocks,
            meta_blkaddr,
            volume_name,
        })
    }

    fn nid_offset(&self, nid: u64) -> Option<usize> {
        let meta_base = (self.meta_blkaddr as usize).checked_mul(self.block_size)?;
        let slot = (nid as usize).checked_shl(EROFS_ISLOTBITS as u32)?;
        meta_base.checked_add(slot)
    }

    pub fn read_inode(&self, image: &[u8], nid: u64) -> Result<ErofsInode, Errno> {
        let off = self.nid_offset(nid).ok_or(Errno::EINVAL)?;
        if off + 32 > image.len() {
            return Err(Errno::EINVAL);
        }
        let raw = &image[off..];
        let format = u16::from_le_bytes([raw[0], raw[1]]);
        let version = format & 0x1;
        let layout_mode = (format >> 1) & 0x7;
        if version == EROFS_INODE_LAYOUT_COMPACT {
            let mode = u16::from_le_bytes([raw[4], raw[5]]);
            let size = u64::from(u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]));
            let raw_blkaddr = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
            Ok(ErofsInode {
                nid,
                mode,
                size,
                raw_blkaddr,
                layout_mode,
                inode_bytes: 32,
            })
        } else if version == EROFS_INODE_LAYOUT_EXTENDED {
            if off + 64 > image.len() {
                return Err(Errno::EINVAL);
            }
            let mode = u16::from_le_bytes([raw[4], raw[5]]);
            let size = u64::from_le_bytes([
                raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
            ]);
            let raw_blkaddr = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
            Ok(ErofsInode {
                nid,
                mode,
                size,
                raw_blkaddr,
                layout_mode,
                inode_bytes: 64,
            })
        } else {
            Err(Errno::EINVAL)
        }
    }

    pub fn read_file_data(&self, image: &[u8], inode: &ErofsInode) -> Result<Vec<u8>, Errno> {
        let size = inode.size as usize;
        if size == 0 {
            return Ok(Vec::new());
        }
        match inode.layout_mode {
            EROFS_INODE_FLAT_PLAIN => {
                let start = (inode.raw_blkaddr as usize)
                    .checked_mul(self.block_size)
                    .ok_or(Errno::EINVAL)?;
                let end = start.checked_add(size).ok_or(Errno::EINVAL)?;
                if end > image.len() {
                    return Err(Errno::EIO);
                }
                Ok(image[start..end].to_vec())
            }
            EROFS_INODE_FLAT_INLINE => {
                let full_blocks = size / self.block_size;
                let tail_bytes = size % self.block_size;
                let mut out = Vec::with_capacity(size);
                if full_blocks > 0 {
                    let start = (inode.raw_blkaddr as usize)
                        .checked_mul(self.block_size)
                        .ok_or(Errno::EINVAL)?;
                    let len = full_blocks * self.block_size;
                    if start + len > image.len() {
                        return Err(Errno::EIO);
                    }
                    out.extend_from_slice(&image[start..start + len]);
                }
                if tail_bytes > 0 {
                    let tail_off = self
                        .nid_offset(inode.nid)
                        .and_then(|o| o.checked_add(inode.inode_bytes))
                        .ok_or(Errno::EINVAL)?;
                    if tail_off + tail_bytes > image.len() {
                        return Err(Errno::EIO);
                    }
                    out.extend_from_slice(&image[tail_off..tail_off + tail_bytes]);
                }
                Ok(out)
            }
            _ => Err(Errno::ENOSYS),
        }
    }

    pub fn read_dir(&self, image: &[u8], dir_nid: u64) -> Result<Vec<ErofsDirent>, Errno> {
        let inode = self.read_inode(image, dir_nid)?;
        let data = self.read_file_data(image, &inode)?;
        let mut out = Vec::new();
        let mut blk_off = 0usize;
        while blk_off < data.len() {
            let blk_end = (blk_off + self.block_size).min(data.len());
            let blk = &data[blk_off..blk_end];
            if blk.len() < 12 {
                break;
            }
            let first_nameoff = u16::from_le_bytes([blk[8], blk[9]]) as usize;
            if first_nameoff < 12 || first_nameoff > blk.len() || !first_nameoff.is_multiple_of(12)
            {
                return Err(Errno::EINVAL);
            }
            let count = first_nameoff / 12;
            for i in 0..count {
                let ent = &blk[i * 12..(i + 1) * 12];
                let nid = u64::from_le_bytes([
                    ent[0], ent[1], ent[2], ent[3], ent[4], ent[5], ent[6], ent[7],
                ]);
                let nameoff = u16::from_le_bytes([ent[8], ent[9]]) as usize;
                let file_type = ent[10];
                let next_nameoff = if i + 1 < count {
                    let next_ent = &blk[(i + 1) * 12..(i + 2) * 12];
                    u16::from_le_bytes([next_ent[8], next_ent[9]]) as usize
                } else {
                    blk.len()
                };
                if nameoff > next_nameoff || next_nameoff > blk.len() {
                    return Err(Errno::EINVAL);
                }
                let raw_name = &blk[nameoff..next_nameoff];
                let end = raw_name
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(raw_name.len());
                let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
                out.push(ErofsDirent {
                    nid,
                    file_type,
                    name,
                });
            }
            blk_off += self.block_size;
        }
        Ok(out)
    }

    pub fn lookup_file(&self, image: &[u8], filename: &str) -> Result<Vec<u8>, Errno> {
        let entries = self.read_dir(image, u64::from(self.root_nid))?;
        let ent = entries
            .iter()
            .find(|e| e.name == filename)
            .ok_or(Errno::ENOENT)?;
        let inode = self.read_inode(image, ent.nid)?;
        self.read_file_data(image, &inode)
    }
}

// ============================================================================
// 4. `F2FS` (Flash-Friendly File System — Android `/data`) Superblock Parser
// ============================================================================

pub const F2FS_SUPER_OFFSET: usize = 1024;
pub const F2FS_SUPER_MAGIC: u32 = 0xF2F5_2010;
pub const F2FS_FEATURE_ENCRYPT: u32 = 0x0001;
pub const F2FS_FEATURE_VERITY: u32 = 0x0400;
pub const F2FS_FEATURE_CASEFOLD: u32 = 0x1000;
pub const F2FS_FEATURE_COMPRESSION: u32 = 0x2000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct F2fsSuperblock {
    pub major_ver: u16,
    pub minor_ver: u16,
    pub block_size: u32,
    pub segment_count: u32,
    pub block_count: u64,
    pub root_ino: u32,
    pub feature: u32,
}

impl F2fsSuperblock {
    pub fn parse(image: &[u8]) -> Result<Self, Errno> {
        if image.len() < F2FS_SUPER_OFFSET + 140 {
            return Err(Errno::EINVAL);
        }
        let sb = &image[F2FS_SUPER_OFFSET..];
        let magic = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
        if magic != F2FS_SUPER_MAGIC {
            return Err(Errno::EINVAL);
        }
        let major_ver = u16::from_le_bytes([sb[4], sb[5]]);
        let minor_ver = u16::from_le_bytes([sb[6], sb[7]]);
        let log_blocksize = u32::from_le_bytes([sb[12], sb[13], sb[14], sb[15]]);
        if log_blocksize != 12 {
            return Err(Errno::EINVAL);
        }
        let block_count = u64::from_le_bytes([
            sb[32], sb[33], sb[34], sb[35], sb[36], sb[37], sb[38], sb[39],
        ]);
        let segment_count = u32::from_le_bytes([sb[48], sb[49], sb[50], sb[51]]);
        let root_ino = u32::from_le_bytes([sb[88], sb[89], sb[90], sb[91]]);
        let feature = u32::from_le_bytes([sb[124], sb[125], sb[126], sb[127]]);
        Ok(Self {
            major_ver,
            minor_ver,
            block_size: 1u32 << log_blocksize,
            segment_count,
            block_count,
            root_ino,
            feature,
        })
    }
}

// ============================================================================
// 5. Android `super.img` Dynamic Partitions (`LP_METADATA`) Parser
// ============================================================================

pub const LP_METADATA_GEOMETRY_MAGIC: u32 = 0x616c_4467;
pub const LP_METADATA_HEADER_MAGIC: u32 = 0x414C_5030;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LpDynamicPartition {
    pub name: String,
    pub attributes: u32,
    pub first_extent_index: u32,
    pub num_extents: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuperPartitionTable {
    pub metadata_max_size: u32,
    pub metadata_slot_count: u32,
    pub logical_block_size: u32,
    pub partitions: Vec<LpDynamicPartition>,
}

impl SuperPartitionTable {
    /// Parses canonical AOSP `super.img` geometry (at offset 4096) + metadata header (at offset 12288).
    pub fn parse(image: &[u8]) -> Result<Self, Errno> {
        if image.len() < 12288 + 256 {
            return Err(Errno::EINVAL);
        }
        let geom = &image[4096..];
        let gmagic = u32::from_le_bytes([geom[0], geom[1], geom[2], geom[3]]);
        if gmagic != LP_METADATA_GEOMETRY_MAGIC {
            return Err(Errno::EINVAL);
        }
        let metadata_max_size = u32::from_le_bytes([geom[40], geom[41], geom[42], geom[43]]);
        let metadata_slot_count = u32::from_le_bytes([geom[44], geom[45], geom[46], geom[47]]);
        let logical_block_size = u32::from_le_bytes([geom[48], geom[49], geom[50], geom[51]]);

        let hdr = &image[12288..];
        let hmagic = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        if hmagic != LP_METADATA_HEADER_MAGIC {
            return Err(Errno::EINVAL);
        }
        let header_size = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
        // Partition table descriptor at offset 80 in LpMetadataHeader: (offset: u32, num_entries: u32, entry_size: u32)
        let part_off = u32::from_le_bytes([hdr[80], hdr[81], hdr[82], hdr[83]]) as usize;
        let part_num = u32::from_le_bytes([hdr[84], hdr[85], hdr[86], hdr[87]]) as usize;
        let part_sz = u32::from_le_bytes([hdr[88], hdr[89], hdr[90], hdr[91]]) as usize;
        if part_sz < 52 || part_num > 64 {
            return Err(Errno::EINVAL);
        }
        let table_base = 12288usize
            .checked_add(header_size)
            .and_then(|v| v.checked_add(part_off))
            .ok_or(Errno::EINVAL)?;
        let mut partitions = Vec::with_capacity(part_num);
        for i in 0..part_num {
            let off = table_base + i * part_sz;
            if off + 52 > image.len() {
                return Err(Errno::EINVAL);
            }
            let e = &image[off..off + 52];
            let name_raw = &e[0..36];
            let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(36);
            let name = String::from_utf8_lossy(&name_raw[..name_end]).into_owned();
            let attributes = u32::from_le_bytes([e[36], e[37], e[38], e[39]]);
            let first_extent_index = u32::from_le_bytes([e[40], e[41], e[42], e[43]]);
            let num_extents = u32::from_le_bytes([e[44], e[45], e[46], e[47]]);
            partitions.push(LpDynamicPartition {
                name,
                attributes,
                first_extent_index,
                num_extents,
            });
        }
        Ok(Self {
            metadata_max_size,
            metadata_slot_count,
            logical_block_size,
            partitions,
        })
    }
}

// ============================================================================
// 6. Real Linux / Android `FUSE` Protocol Session (`/dev/fuse`, MediaProvider)
// ============================================================================

pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 39;
pub const FUSE_INIT_OPCODE: u32 = 26;

#[derive(Clone, Debug)]
pub struct FuseSessionState {
    pub initialized: bool,
    pub proto_major: u32,
    pub proto_minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub requests_served: u64,
    pub pending_init_sent: bool,
}

impl FuseSessionState {
    pub const fn new() -> Self {
        Self {
            initialized: false,
            proto_major: FUSE_KERNEL_VERSION,
            proto_minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: 131_072,
            flags: 0,
            requests_served: 0,
            pending_init_sent: false,
        }
    }

    /// Generates the canonical 56-byte `fuse_in_header (40B) + fuse_init_in (16B)` request
    /// read by a userspace FUSE daemon (`MediaProvider`) from `/dev/fuse`.
    pub fn build_init_request(&mut self) -> [u8; 56] {
        let mut msg = [0u8; 56];
        msg[0..4].copy_from_slice(&56u32.to_le_bytes()); // len
        msg[4..8].copy_from_slice(&FUSE_INIT_OPCODE.to_le_bytes()); // opcode = FUSE_INIT
        msg[8..16].copy_from_slice(&1u64.to_le_bytes()); // unique = 1
        msg[16..24].copy_from_slice(&1u64.to_le_bytes()); // nodeid = 1
        // fuse_init_in at offset 40: major, minor, max_readahead, flags
        msg[40..44].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
        msg[44..48].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
        msg[48..52].copy_from_slice(&self.max_readahead.to_le_bytes());
        msg[52..56].copy_from_slice(&0x0000_0001u32.to_le_bytes());
        self.pending_init_sent = true;
        msg
    }

    /// Processes a userspace FUSE daemon reply written to `/dev/fuse` (`fuse_out_header` 16B + payload).
    pub fn handle_daemon_reply(&mut self, reply: &[u8]) -> Result<(), Errno> {
        if reply.len() < 16 {
            return Err(Errno::EINVAL);
        }
        let len = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]) as usize;
        let error = i32::from_le_bytes([reply[4], reply[5], reply[6], reply[7]]);
        let unique = u64::from_le_bytes([
            reply[8], reply[9], reply[10], reply[11], reply[12], reply[13], reply[14], reply[15],
        ]);
        if len < 16 || len > reply.len() || error != 0 {
            return Err(Errno::EINVAL);
        }
        if unique == 1 && reply.len() >= 32 {
            self.proto_major = u32::from_le_bytes([reply[16], reply[17], reply[18], reply[19]]);
            self.proto_minor = u32::from_le_bytes([reply[20], reply[21], reply[22], reply[23]]);
            self.flags = u32::from_le_bytes([reply[28], reply[29], reply[30], reply[31]]);
            self.initialized = true;
        }
        self.requests_served += 1;
        Ok(())
    }
}

impl Default for FuseSessionState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_nist_abc_vector() {
        let digest = sha256(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn dm_verity_passes_clean_block_and_fails_closed_on_1bit_tamper() {
        let mut dm = DmControlState::new_with_android_root();
        let clean = b"QYRONEX_ANDROID_15_VERITY_SYSTEM_BLOCK_0";
        dm.verify_device_block("system-verity", 0, clean).unwrap();
        assert_eq!(dm.verified_blocks, 1);
        assert_eq!(dm.corruption_blocks, 0);

        let mut tampered = *clean;
        tampered[5] ^= 0x01; // Flip a single bit!
        assert_eq!(
            dm.verify_device_block("system-verity", 0, &tampered),
            Err(Errno::EIO)
        );
        assert_eq!(dm.corruption_blocks, 1);
    }

    #[test]
    fn erofs_and_f2fs_and_super_lp_and_fuse_roundtrip() {
        // 1. Minimal valid EROFS image with root dir -> "hello.txt" = "QYRONEX_EROFS_OK"
        let mut erofs = vec![0u8; 4096 * 3];
        erofs[1024..1028].copy_from_slice(&EROFS_SUPER_MAGIC_V1.to_le_bytes());
        erofs[1024 + 12] = 12; // 4096-byte blocks
        erofs[1024 + 14..1024 + 16].copy_from_slice(&0u16.to_le_bytes()); // root_nid = 0
        erofs[1024 + 16..1024 + 24].copy_from_slice(&2u64.to_le_bytes()); // inos = 2
        erofs[1024 + 36..1024 + 40].copy_from_slice(&3u32.to_le_bytes()); // blocks = 3
        erofs[1024 + 40..1024 + 44].copy_from_slice(&1u32.to_le_bytes()); // meta_blkaddr = 1
        erofs[1024 + 64..1024 + 71].copy_from_slice(b"qyronex");

        // Root dir inode at block 1, slot 0 (offset 4096): compact + FLAT_PLAIN at block 2
        let root_off = 4096;
        erofs[root_off..root_off + 2].copy_from_slice(&0u16.to_le_bytes()); // compact + FLAT_PLAIN
        erofs[root_off + 4..root_off + 6].copy_from_slice(&0o040755u16.to_le_bytes());
        erofs[root_off + 8..root_off + 12].copy_from_slice(&24u32.to_le_bytes());
        erofs[root_off + 16..root_off + 20].copy_from_slice(&2u32.to_le_bytes());

        // File inode at block 1, slot 1 (nid = 1, offset 4096 + 32): compact + FLAT_INLINE!
        let f_off = 4096 + 32;
        let payload = b"QYRONEX_EROFS_OK";
        erofs[f_off..f_off + 2].copy_from_slice(&(EROFS_INODE_FLAT_INLINE << 1).to_le_bytes());
        erofs[f_off + 4..f_off + 6].copy_from_slice(&0o100644u16.to_le_bytes());
        erofs[f_off + 8..f_off + 12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        erofs[f_off + 32..f_off + 32 + payload.len()].copy_from_slice(payload);

        // Root dir block at block 2 (offset 8192): 1 dirent -> nid 1, nameoff 12, "hello.txt"
        let d_off = 8192;
        erofs[d_off..d_off + 8].copy_from_slice(&1u64.to_le_bytes());
        erofs[d_off + 8..d_off + 10].copy_from_slice(&12u16.to_le_bytes());
        erofs[d_off + 10] = 1; // regular file
        erofs[d_off + 12..d_off + 21].copy_from_slice(b"hello.txt");

        let sb = ErofsSuperblock::parse(&erofs).unwrap();
        assert_eq!(sb.volume_name, "qyronex");
        assert_eq!(sb.lookup_file(&erofs, "hello.txt").unwrap(), payload);

        // 2. F2FS superblock
        let mut f2fs = vec![0u8; 4096];
        f2fs[1024..1028].copy_from_slice(&F2FS_SUPER_MAGIC.to_le_bytes());
        f2fs[1024 + 4..1024 + 6].copy_from_slice(&1u16.to_le_bytes());
        f2fs[1024 + 6..1024 + 8].copy_from_slice(&16u16.to_le_bytes());
        f2fs[1024 + 12..1024 + 16].copy_from_slice(&12u32.to_le_bytes());
        f2fs[1024 + 32..1024 + 40].copy_from_slice(&65536u64.to_le_bytes());
        f2fs[1024 + 48..1024 + 52].copy_from_slice(&128u32.to_le_bytes());
        f2fs[1024 + 88..1024 + 92].copy_from_slice(&3u32.to_le_bytes());
        f2fs[1024 + 124..1024 + 128]
            .copy_from_slice(&(F2FS_FEATURE_ENCRYPT | F2FS_FEATURE_VERITY).to_le_bytes());
        let fsb = F2fsSuperblock::parse(&f2fs).unwrap();
        assert_eq!(fsb.block_size, 4096);
        assert_eq!(fsb.feature & F2FS_FEATURE_VERITY, F2FS_FEATURE_VERITY);

        // 3. Android super.img LP_METADATA
        let mut super_img = vec![0u8; 16384];
        super_img[4096..4100].copy_from_slice(&LP_METADATA_GEOMETRY_MAGIC.to_le_bytes());
        super_img[4096 + 40..4096 + 44].copy_from_slice(&65536u32.to_le_bytes());
        super_img[4096 + 44..4096 + 48].copy_from_slice(&2u32.to_le_bytes());
        super_img[4096 + 48..4096 + 52].copy_from_slice(&4096u32.to_le_bytes());
        super_img[12288..12292].copy_from_slice(&LP_METADATA_HEADER_MAGIC.to_le_bytes());
        super_img[12288 + 8..12288 + 12].copy_from_slice(&256u32.to_le_bytes());
        super_img[12288 + 80..12288 + 84].copy_from_slice(&0u32.to_le_bytes());
        super_img[12288 + 84..12288 + 88].copy_from_slice(&2u32.to_le_bytes());
        super_img[12288 + 88..12288 + 92].copy_from_slice(&52u32.to_le_bytes());
        let p0 = 12288 + 256;
        super_img[p0..p0 + 8].copy_from_slice(b"system_a");
        let p1 = p0 + 52;
        super_img[p1..p1 + 8].copy_from_slice(b"vendor_a");
        let lp = SuperPartitionTable::parse(&super_img).unwrap();
        assert_eq!(lp.partitions.len(), 2);
        assert_eq!(lp.partitions[0].name, "system_a");
        assert_eq!(lp.partitions[1].name, "vendor_a");

        // 4. FUSE handshake
        let mut fuse = FuseSessionState::new();
        let req = fuse.build_init_request();
        assert_eq!(
            u32::from_le_bytes([req[4], req[5], req[6], req[7]]),
            FUSE_INIT_OPCODE
        );
        let mut reply = [0u8; 32];
        reply[0..4].copy_from_slice(&32u32.to_le_bytes());
        reply[8..16].copy_from_slice(&1u64.to_le_bytes());
        reply[16..20].copy_from_slice(&7u32.to_le_bytes());
        reply[20..24].copy_from_slice(&39u32.to_le_bytes());
        fuse.handle_daemon_reply(&reply).unwrap();
        assert!(fuse.initialized);
        assert_eq!(fuse.proto_minor, 39);
    }
}
