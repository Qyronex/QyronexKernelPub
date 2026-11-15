// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

use crate::queue::{DmaBufferGrant, SplitVirtqueue, VirtqDesc, validate_descriptor_chain};
use crate::{VIRTIO_F_VERSION_1, VirtioError};
use kernal_capability::{CapRights, Capability};

pub const SECTOR_SIZE: usize = 512;

pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;

pub const SUPPORTED_BLK_FEATURES: u64 = VIRTIO_F_VERSION_1
    | VIRTIO_BLK_F_SIZE_MAX
    | VIRTIO_BLK_F_SEG_MAX
    | VIRTIO_BLK_F_BLK_SIZE
    | VIRTIO_BLK_F_FLUSH
    | VIRTIO_BLK_F_RO;

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioBlkOp {
    Read,
    Write,
    Flush,
}

impl VirtioBlkOp {
    pub const fn request_type(self) -> u32 {
        match self {
            Self::Read => VIRTIO_BLK_T_IN,
            Self::Write => VIRTIO_BLK_T_OUT,
            Self::Flush => VIRTIO_BLK_T_FLUSH,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

/// Validates a VirtIO-Blk request descriptor chain and policy before device execution.
pub fn validate_blk_request(
    queue_size: usize,
    features: u64,
    op: VirtioBlkOp,
    descriptors: &[VirtqDesc],
    head: u16,
    grant: &DmaBufferGrant,
) -> Result<usize, VirtioError> {
    if (features & VIRTIO_F_VERSION_1) == 0 {
        return Err(VirtioError::MissingVersion1Feature);
    }
    if (features & !SUPPORTED_BLK_FEATURES) != 0 {
        return Err(VirtioError::UnsupportedFeature);
    }
    if op == VirtioBlkOp::Write && (features & VIRTIO_BLK_F_RO) != 0 {
        return Err(VirtioError::ReadOnlyDevice);
    }
    if op == VirtioBlkOp::Flush && (features & VIRTIO_BLK_F_FLUSH) == 0 {
        return Err(VirtioError::UnsupportedOp);
    }
    validate_descriptor_chain(queue_size, descriptors, head, Some(grant))
}

/// Capability-mediated VirtIO-Blk device backed by bounded 512-byte sectors (e.g. disposable
/// overlay buffer in unit/MMIO tests or real MMIO transport proxy).
#[derive(Clone, Debug)]
pub struct VirtioBlkDevice<const SECTORS: usize, const Q: usize> {
    queue: SplitVirtqueue<Q>,
    features: u64,
    sector_count: usize,
    sectors: [[u8; SECTOR_SIZE]; SECTORS],
    flush_generation: u64,
    revoked: bool,
}

impl<const SECTORS: usize, const Q: usize> VirtioBlkDevice<SECTORS, Q> {
    pub fn new(features: u64) -> Result<Self, VirtioError> {
        if (features & VIRTIO_F_VERSION_1) == 0 {
            return Err(VirtioError::MissingVersion1Feature);
        }
        if (features & !SUPPORTED_BLK_FEATURES) != 0 {
            return Err(VirtioError::UnsupportedFeature);
        }
        Ok(Self {
            queue: SplitVirtqueue::new(),
            features,
            sector_count: SECTORS,
            sectors: [[0u8; SECTOR_SIZE]; SECTORS],
            flush_generation: 0,
            revoked: false,
        })
    }

    pub const fn features(&self) -> u64 {
        self.features
    }

    pub const fn read_only(&self) -> bool {
        (self.features & VIRTIO_BLK_F_RO) != 0
    }

    pub const fn sector_count(&self) -> usize {
        self.sector_count
    }

    pub const fn flush_generation(&self) -> u64 {
        self.flush_generation
    }

    pub const fn generation(&self) -> u32 {
        self.queue.generation()
    }

    pub fn revoke_and_reset(&mut self) {
        self.queue.reset_and_revoke();
        self.revoked = false;
    }

    fn check_sector_range(
        &self,
        start_sector: u64,
        sector_len: usize,
    ) -> Result<usize, VirtioError> {
        let start = usize::try_from(start_sector).map_err(|_| VirtioError::OutOfRange)?;
        let end = start
            .checked_add(sector_len)
            .ok_or(VirtioError::OutOfRange)?;
        if end > self.sector_count {
            return Err(VirtioError::OutOfRange);
        }
        Ok(start)
    }

    /// Executes one sector read over validated Split Virtqueue descriptor & DMA grants.
    pub fn read_sectors(
        &mut self,
        cap: Capability,
        grant: &DmaBufferGrant,
        start_sector: u64,
        out_buf: &mut [u8],
    ) -> Result<(), VirtioError> {
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        if !cap.rights.contains(CapRights::READ) {
            return Err(VirtioError::RevokedAuthority);
        }
        if out_buf.is_empty() || !out_buf.len().is_multiple_of(SECTOR_SIZE) {
            return Err(VirtioError::InvalidPacket);
        }
        let nsectors = out_buf.len() / SECTOR_SIZE;
        let start = self.check_sector_range(start_sector, nsectors)?;

        let mut writable_grant = *grant;
        writable_grant.writable = true;
        let chain = [
            (grant.base_addr, 16, false),
            (
                grant
                    .base_addr
                    .checked_add(16)
                    .ok_or(VirtioError::DescriptorLengthOverflow)?,
                out_buf.len() as u32,
                true,
            ),
            (
                grant
                    .base_addr
                    .checked_add(16 + out_buf.len() as u64)
                    .ok_or(VirtioError::DescriptorLengthOverflow)?,
                1,
                true,
            ),
        ];
        let (head, generation) = self.queue.submit_chain(&chain, &writable_grant)?;
        for i in 0..nsectors {
            let offset = i * SECTOR_SIZE;
            out_buf[offset..offset + SECTOR_SIZE].copy_from_slice(&self.sectors[start + i]);
        }
        self.queue
            .complete_used(head, (out_buf.len() + 1) as u32, generation)?;
        let _ = self.queue.pop_used(generation)?;
        Ok(())
    }

    /// Executes one sector write to writable backing storage via validated DMA & queue descriptors.
    pub fn write_sectors(
        &mut self,
        cap: Capability,
        grant: &DmaBufferGrant,
        start_sector: u64,
        in_buf: &[u8],
    ) -> Result<(), VirtioError> {
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(VirtioError::RevokedAuthority);
        }
        if self.read_only() {
            return Err(VirtioError::ReadOnlyDevice);
        }
        if in_buf.is_empty() || !in_buf.len().is_multiple_of(SECTOR_SIZE) {
            return Err(VirtioError::InvalidPacket);
        }
        let nsectors = in_buf.len() / SECTOR_SIZE;
        let start = self.check_sector_range(start_sector, nsectors)?;

        let mut status_grant = *grant;
        status_grant.writable = true;
        let chain = [
            (grant.base_addr, 16, false),
            (
                grant
                    .base_addr
                    .checked_add(16)
                    .ok_or(VirtioError::DescriptorLengthOverflow)?,
                in_buf.len() as u32,
                false,
            ),
            (
                grant
                    .base_addr
                    .checked_add(16 + in_buf.len() as u64)
                    .ok_or(VirtioError::DescriptorLengthOverflow)?,
                1,
                true,
            ),
        ];
        let (head, generation) = self.queue.submit_chain(&chain, &status_grant)?;
        for i in 0..nsectors {
            let offset = i * SECTOR_SIZE;
            self.sectors[start + i].copy_from_slice(&in_buf[offset..offset + SECTOR_SIZE]);
        }
        self.queue.complete_used(head, 1, generation)?;
        let _ = self.queue.pop_used(generation)?;
        Ok(())
    }

    /// Executes an explicit `VIRTIO_BLK_T_FLUSH` write barrier when `BLK_F_FLUSH` was negotiated.
    pub fn flush(&mut self, cap: Capability, grant: &DmaBufferGrant) -> Result<(), VirtioError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(VirtioError::RevokedAuthority);
        }
        if (self.features & VIRTIO_BLK_F_FLUSH) == 0 {
            return Err(VirtioError::UnsupportedOp);
        }
        let mut status_grant = *grant;
        status_grant.writable = true;
        let chain = [
            (grant.base_addr, 16, false),
            (
                grant
                    .base_addr
                    .checked_add(16)
                    .ok_or(VirtioError::DescriptorLengthOverflow)?,
                1,
                true,
            ),
        ];
        let (head, generation) = self.queue.submit_chain(&chain, &status_grant)?;
        self.flush_generation = self.flush_generation.saturating_add(1);
        self.queue.complete_used(head, 1, generation)?;
        let _ = self.queue.pop_used(generation)?;
        Ok(())
    }
}
