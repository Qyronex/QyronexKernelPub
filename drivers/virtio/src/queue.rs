// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

use crate::VirtioError;

pub const MAX_VIRTQ_SIZE: usize = 32768;

pub const VRING_DESC_F_NEXT: u16 = 1 << 0;
pub const VRING_DESC_F_WRITE: u16 = 1 << 1;
pub const VRING_DESC_F_INDIRECT: u16 = 1 << 2;

/// VirtIO Split Virtqueue descriptor (`struct virtq_desc`, 16 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// VirtIO Split Virtqueue used-ring element (`struct virtq_used_elem`, 8 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// Explicit IOMMU/capability DMA grant binding allowed guest/device buffer addresses and lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaBufferGrant {
    pub base_addr: u64,
    pub len: u64,
    pub writable: bool,
    pub dma_assigned: bool,
    pub buffer_generation: u32,
    pub expected_generation: u32,
    pub revoked: bool,
}

impl DmaBufferGrant {
    pub const fn validate_authority(&self) -> Result<(), VirtioError> {
        if !self.dma_assigned {
            return Err(VirtioError::DmaUnassigned);
        }
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        if self.buffer_generation != self.expected_generation {
            return Err(VirtioError::StaleGeneration);
        }
        Ok(())
    }

    pub fn covers_descriptor(&self, desc: VirtqDesc) -> Result<(), VirtioError> {
        self.validate_authority()?;
        if desc.len == 0 {
            return Err(VirtioError::DescriptorLengthOverflow);
        }
        if (desc.flags & VRING_DESC_F_WRITE) != 0 && !self.writable {
            return Err(VirtioError::RevokedAuthority);
        }
        let grant_end = self
            .base_addr
            .checked_add(self.len)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let desc_end = desc
            .addr
            .checked_add(u64::from(desc.len))
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        if desc.addr < self.base_addr || desc_end > grant_end {
            return Err(VirtioError::DescriptorOutOfBounds);
        }
        Ok(())
    }
}

/// Validates a split-virtqueue descriptor chain for cycles, out-of-bounds indices, length overflow,
/// device-readable-before-device-writable ordering, and explicit DMA grant containment.
pub fn validate_descriptor_chain(
    queue_size: usize,
    descriptors: &[VirtqDesc],
    head: u16,
    grant: Option<&DmaBufferGrant>,
) -> Result<usize, VirtioError> {
    if queue_size == 0 || !queue_size.is_power_of_two() || queue_size > MAX_VIRTQ_SIZE {
        return Err(VirtioError::InvalidQueueSize);
    }
    if descriptors.is_empty() || descriptors.len() > queue_size {
        return Err(VirtioError::DescriptorOutOfBounds);
    }
    if let Some(dma) = grant {
        dma.validate_authority()?;
    }

    let mut visited = [false; 64];
    let use_bitset = descriptors.len() <= visited.len();
    let mut index = head;
    let mut chain_len = 0usize;
    let mut seen_device_write = false;

    for _ in 0..descriptors.len() {
        let idx = usize::from(index);
        if idx >= descriptors.len() {
            return Err(VirtioError::DescriptorOutOfBounds);
        }
        if use_bitset {
            if visited[idx] {
                return Err(VirtioError::DescriptorCycle);
            }
            visited[idx] = true;
        }
        let desc = descriptors[idx];
        let is_write = (desc.flags & VRING_DESC_F_WRITE) != 0;
        if seen_device_write && !is_write {
            return Err(VirtioError::DescriptorOrderingInvalid);
        }
        if is_write {
            seen_device_write = true;
        }
        if let Some(dma) = grant {
            dma.covers_descriptor(desc)?;
        }
        chain_len += 1;
        if (desc.flags & VRING_DESC_F_NEXT) == 0 {
            return Ok(chain_len);
        }
        index = desc.next;
    }

    Err(VirtioError::DescriptorCycle)
}

/// Pure in-kernel Split Virtqueue ring state (`desc`, `avail`, `used`) with generation revocation.
#[derive(Clone, Debug)]
pub struct SplitVirtqueue<const Q: usize> {
    desc: [VirtqDesc; Q],
    free_head: u16,
    num_free: usize,
    avail_idx: u16,
    avail_ring: [u16; Q],
    last_used_idx: u16,
    used_idx: u16,
    used_ring: [VirtqUsedElem; Q],
    generation: u32,
    revoked: bool,
}

impl<const Q: usize> Default for SplitVirtqueue<Q> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const Q: usize> SplitVirtqueue<Q> {
    pub fn new() -> Self {
        assert!(Q > 0 && Q.is_power_of_two() && Q <= MAX_VIRTQ_SIZE);
        let mut desc = [VirtqDesc::default(); Q];
        for (i, d) in desc.iter_mut().enumerate() {
            d.next = if i + 1 < Q { (i + 1) as u16 } else { 0 };
        }
        Self {
            desc,
            free_head: 0,
            num_free: Q,
            avail_idx: 0,
            avail_ring: [0; Q],
            last_used_idx: 0,
            used_idx: 0,
            used_ring: [VirtqUsedElem::default(); Q],
            generation: 1,
            revoked: false,
        }
    }

    pub const fn queue_size(&self) -> usize {
        Q
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Enqueues a contiguous validated chain into the available ring and returns `(head_idx, generation)`.
    pub fn submit_chain(
        &mut self,
        chain: &[(u64, u32, bool)],
        grant: &DmaBufferGrant,
    ) -> Result<(u16, u32), VirtioError> {
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        if chain.is_empty() || chain.len() > self.num_free {
            return Err(VirtioError::QueueFull);
        }
        grant.validate_authority()?;

        let head = self.free_head;
        let mut cursor = head;
        for (pos, &(addr, len, device_write)) in chain.iter().enumerate() {
            let next_free = self.desc[usize::from(cursor)].next;
            let flags = if pos + 1 < chain.len() {
                VRING_DESC_F_NEXT
            } else {
                0
            } | if device_write { VRING_DESC_F_WRITE } else { 0 };
            let next = if pos + 1 < chain.len() { next_free } else { 0 };
            let candidate = VirtqDesc {
                addr,
                len,
                flags,
                next,
            };
            grant.covers_descriptor(candidate)?;
            self.desc[usize::from(cursor)] = candidate;
            cursor = next_free;
        }

        // Validate final assembled descriptors explicitly before exposing head on avail ring.
        validate_descriptor_chain(Q, &self.desc, head, Some(grant))?;

        self.free_head = cursor;
        self.num_free -= chain.len();
        let slot = usize::from(self.avail_idx) & (Q - 1);
        self.avail_ring[slot] = head;
        self.avail_idx = self.avail_idx.wrapping_add(1);
        Ok((head, self.generation))
    }

    /// Completes one request onto the used ring (used by device/MMIO completion loop).
    pub fn complete_used(
        &mut self,
        head: u16,
        written_bytes: u32,
        expected_gen: u32,
    ) -> Result<(), VirtioError> {
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        if expected_gen != self.generation {
            return Err(VirtioError::StaleGeneration);
        }
        if usize::from(head) >= Q {
            return Err(VirtioError::DescriptorOutOfBounds);
        }
        let slot = usize::from(self.used_idx) & (Q - 1);
        self.used_ring[slot] = VirtqUsedElem {
            id: u32::from(head),
            len: written_bytes,
        };
        self.used_idx = self.used_idx.wrapping_add(1);
        Ok(())
    }

    /// Reclaims one completed descriptor chain and returns its used length.
    pub fn pop_used(&mut self, expected_gen: u32) -> Result<VirtqUsedElem, VirtioError> {
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        if expected_gen != self.generation {
            return Err(VirtioError::StaleGeneration);
        }
        if self.last_used_idx == self.used_idx {
            return Err(VirtioError::QueueEmpty);
        }
        let slot = usize::from(self.last_used_idx) & (Q - 1);
        let elem = self.used_ring[slot];
        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // Return chain descriptors back to the free list cleanly.
        let mut idx = u16::try_from(elem.id).map_err(|_| VirtioError::DescriptorOutOfBounds)?;
        for _ in 0..Q {
            let entry = self.desc[usize::from(idx)];
            let has_next = (entry.flags & VRING_DESC_F_NEXT) != 0;
            let next_idx = entry.next;
            self.desc[usize::from(idx)] = VirtqDesc {
                next: self.free_head,
                ..VirtqDesc::default()
            };
            self.free_head = idx;
            self.num_free += 1;
            if !has_next {
                return Ok(elem);
            }
            idx = next_idx;
        }
        Err(VirtioError::DescriptorCycle)
    }

    /// Revokes all active queue descriptors/rings on device reset/teardown and increments generation.
    pub fn reset_and_revoke(&mut self) {
        self.revoked = false;
        self.generation = self.generation.wrapping_add(1).max(1);
        self.avail_idx = 0;
        self.last_used_idx = 0;
        self.used_idx = 0;
        self.free_head = 0;
        self.num_free = Q;
        for (i, d) in self.desc.iter_mut().enumerate() {
            *d = VirtqDesc {
                next: if i + 1 < Q { (i + 1) as u16 } else { 0 },
                ..VirtqDesc::default()
            };
        }
    }
}
