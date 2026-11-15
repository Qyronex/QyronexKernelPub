// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapRights, Capability};
use kernal_iommu::{DmaMapping, DmaPerms};
use kernal_pci::{Address as PciAddress, EcamWindow};

pub const MAX_NIC_FRAME: usize = 1514;
pub const DEFAULT_NIC_MTU: usize = 1500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NicError {
    PermissionDenied,
    InvalidPciAddress,
    LinkDown,
    DmaViolation,
    StaleGeneration,
    RingFull,
    RingEmpty,
    InvalidPacket,
    BufferTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NicConfig {
    pub pci: PciAddress,
    pub mac: [u8; 6],
    pub mtu: usize,
    pub speed_mbps: u32,
    pub full_duplex: bool,
    pub tx_csum_offload: bool,
    pub rx_csum_offload: bool,
}

#[derive(Clone, Copy)]
struct NicSlot {
    len: usize,
    data: [u8; MAX_NIC_FRAME],
}

impl NicSlot {
    const EMPTY: Self = Self {
        len: 0,
        data: [0; MAX_NIC_FRAME],
    };
}

/// Wired PCIe Ethernet NIC hardware driver model with MDIO link state, DMA rings, and reset
/// generation tracking.
#[derive(Clone)]
pub struct WiredEthernetNic<const RING: usize> {
    pub ecam_base: u64,
    pub config: NicConfig,
    pub link_up: bool,
    pub generation: u32,
    pub tx_packets: u64,
    pub rx_packets: u64,
    tx_ring: [NicSlot; RING],
    tx_head: usize,
    tx_tail: usize,
    tx_count: usize,
    rx_ring: [NicSlot; RING],
    rx_head: usize,
    rx_tail: usize,
    rx_count: usize,
}

impl<const RING: usize> WiredEthernetNic<RING> {
    pub fn new(ecam: EcamWindow, config: NicConfig) -> Result<Self, NicError> {
        if RING == 0 || config.mtu == 0 || config.mtu + 14 > MAX_NIC_FRAME {
            return Err(NicError::InvalidPacket);
        }
        let ecam_base = ecam
            .config_address(config.pci)
            .map_err(|_| NicError::InvalidPciAddress)?;
        Ok(Self {
            ecam_base,
            config,
            link_up: true,
            generation: 1,
            tx_packets: 0,
            rx_packets: 0,
            tx_ring: [NicSlot::EMPTY; RING],
            tx_head: 0,
            tx_tail: 0,
            tx_count: 0,
            rx_ring: [NicSlot::EMPTY; RING],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
        })
    }

    pub fn set_link(&mut self, cap: Capability, up: bool) -> Result<(), NicError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(NicError::PermissionDenied);
        }
        self.link_up = up;
        Ok(())
    }

    pub fn reset(&mut self, cap: Capability) -> Result<u32, NicError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(NicError::PermissionDenied);
        }
        self.tx_head = 0;
        self.tx_tail = 0;
        self.tx_count = 0;
        self.rx_head = 0;
        self.rx_tail = 0;
        self.rx_count = 0;
        self.generation = self.generation.wrapping_add(1).max(1);
        Ok(self.generation)
    }

    fn verify_dma(
        dma: &DmaMapping,
        expected_gen: u32,
        actual_gen: u32,
        iova: u64,
        len: usize,
        write: bool,
    ) -> Result<(), NicError> {
        if expected_gen != actual_gen {
            return Err(NicError::StaleGeneration);
        }
        let req = if write {
            DmaPerms::WRITE
        } else {
            DmaPerms::READ
        };
        if (dma.perms.bits() & req.bits()) == 0 {
            return Err(NicError::DmaViolation);
        }
        let end = iova
            .checked_add(len as u64)
            .ok_or(NicError::InvalidPacket)?;
        let map_end = dma.iova_end().ok_or(NicError::DmaViolation)?;
        if iova < dma.iova || end > map_end {
            return Err(NicError::DmaViolation);
        }
        Ok(())
    }

    pub fn tx_submit(
        &mut self,
        cap: Capability,
        dma: &DmaMapping,
        expected_gen: u32,
        desc_iova: u64,
        frame: &[u8],
    ) -> Result<(), NicError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(NicError::PermissionDenied);
        }
        if !self.link_up {
            return Err(NicError::LinkDown);
        }
        if frame.len() < 14 || frame.len() > self.config.mtu + 14 {
            return Err(NicError::InvalidPacket);
        }
        if self.tx_count == RING {
            return Err(NicError::RingFull);
        }
        Self::verify_dma(
            dma,
            expected_gen,
            self.generation,
            desc_iova,
            frame.len(),
            false,
        )?;
        self.tx_ring[self.tx_tail].len = frame.len();
        self.tx_ring[self.tx_tail].data[..frame.len()].copy_from_slice(frame);
        self.tx_tail = (self.tx_tail + 1) % RING;
        self.tx_count += 1;
        self.tx_packets = self.tx_packets.saturating_add(1);
        Ok(())
    }

    pub fn rx_deliver_wire(&mut self, frame: &[u8]) -> Result<(), NicError> {
        if !self.link_up {
            return Err(NicError::LinkDown);
        }
        if frame.len() < 14 || frame.len() > self.config.mtu + 14 {
            return Err(NicError::InvalidPacket);
        }
        if self.rx_count == RING {
            return Err(NicError::RingFull);
        }
        self.rx_ring[self.rx_tail].len = frame.len();
        self.rx_ring[self.rx_tail].data[..frame.len()].copy_from_slice(frame);
        self.rx_tail = (self.rx_tail + 1) % RING;
        self.rx_count += 1;
        Ok(())
    }

    pub fn rx_poll(
        &mut self,
        cap: Capability,
        dma: &DmaMapping,
        expected_gen: u32,
        desc_iova: u64,
        out: &mut [u8],
    ) -> Result<usize, NicError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(NicError::PermissionDenied);
        }
        if self.rx_count == 0 {
            return Err(NicError::RingEmpty);
        }
        let len = self.rx_ring[self.rx_head].len;
        if out.len() < len {
            return Err(NicError::BufferTooSmall);
        }
        Self::verify_dma(dma, expected_gen, self.generation, desc_iova, len, true)?;
        out[..len].copy_from_slice(&self.rx_ring[self.rx_head].data[..len]);
        self.rx_head = (self.rx_head + 1) % RING;
        self.rx_count -= 1;
        self.rx_packets = self.rx_packets.saturating_add(1);
        Ok(len)
    }

    pub fn pop_wire_tx(&mut self, out: &mut [u8]) -> Result<usize, NicError> {
        if self.tx_count == 0 {
            return Err(NicError::RingEmpty);
        }
        let len = self.tx_ring[self.tx_head].len;
        if out.len() < len {
            return Err(NicError::BufferTooSmall);
        }
        out[..len].copy_from_slice(&self.tx_ring[self.tx_head].data[..len]);
        self.tx_head = (self.tx_head + 1) % RING;
        self.tx_count -= 1;
        Ok(len)
    }
}
