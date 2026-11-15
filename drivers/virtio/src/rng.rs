// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

use crate::queue::{DmaBufferGrant, SplitVirtqueue};
use crate::{VIRTIO_F_VERSION_1, VirtioError};
use kernal_capability::{CapRights, Capability};

/// Capability- and DMA-mediated VirtIO-RNG entropy device.
#[derive(Clone, Debug)]
pub struct VirtioRngDevice<const Q: usize> {
    queue: SplitVirtqueue<Q>,
    features: u64,
    mixer_state: u64,
    reseeds: u64,
}

impl<const Q: usize> VirtioRngDevice<Q> {
    pub fn new(features: u64, initial_seed: u64) -> Result<Self, VirtioError> {
        if (features & VIRTIO_F_VERSION_1) == 0 {
            return Err(VirtioError::MissingVersion1Feature);
        }
        if initial_seed == 0 {
            return Err(VirtioError::DeviceFault);
        }
        Ok(Self {
            queue: SplitVirtqueue::new(),
            features,
            mixer_state: initial_seed,
            reseeds: 1,
        })
    }

    pub const fn features(&self) -> u64 {
        self.features
    }

    pub const fn reseeds(&self) -> u64 {
        self.reseeds
    }

    pub fn harvest_entropy(
        &mut self,
        cap: Capability,
        grant: &DmaBufferGrant,
        out: &mut [u8],
    ) -> Result<(), VirtioError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(VirtioError::RevokedAuthority);
        }
        if out.is_empty() {
            return Err(VirtioError::InvalidPacket);
        }
        let mut rx_grant = *grant;
        rx_grant.writable = true;
        let (head, generation) = self
            .queue
            .submit_chain(&[(grant.base_addr, out.len() as u32, true)], &rx_grant)?;

        for chunk in out.chunks_mut(8) {
            self.mixer_state = self.mixer_state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.mixer_state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        self.queue
            .complete_used(head, out.len() as u32, generation)?;
        let _ = self.queue.pop_used(generation)?;
        Ok(())
    }
}
