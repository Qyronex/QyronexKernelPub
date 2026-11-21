// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! Raspberry Pi 3B+ On-Board Microchip LAN7515 USB 2.0 Gigabit Ethernet & 4-Port USB Hub Driver
//! (`VID = 0x0424`, `PID = 0x7800`, connected via BCM2837 DWC2 USB Host at `0x3F98_0000`).
//!
//! Note: The Raspberry Pi 3 Model B+ replaced the older Pi 3B's 100 Mbps LAN9514 with the
//! Microchip LAN7515 (`lan78xx` family), combining a USB 2.0 High-Speed 4-port hub and a
//! Gigabit Ethernet MAC + integrated 1000BASE-T RGMII PHY.

use crate::{RPI3B_PLUS_DEFAULT_MAC, RpiError, verify_dma_window};
use kernal_capability::{CapRights, Capability};
use kernal_iommu::{DmaMapping, DmaPerms};

pub const LAN7515_USB_VENDOR_ID: u16 = 0x0424;
pub const LAN7515_USB_PRODUCT_ID: u16 = 0x7800;
pub const LAN7515_CHIP_ID_REV: u32 = 0x7800_0002;
pub const LAN7515_HUB_PORT_COUNT: u8 = 4;

pub const ETH_MIN_FRAME_BYTES: usize = 14;
pub const ETH_DEFAULT_MTU: u16 = 1500;
pub const ETH_MAX_FRAME_BYTES: usize = 1518;

// LAN7515 / LAN78xx CSR register offsets
pub const LAN78XX_ID_REV: u32 = 0x000;
pub const LAN78XX_INT_STS: u32 = 0x00C;
pub const LAN78XX_HW_CFG: u32 = 0x010;
pub const LAN78XX_PMT_CTL: u32 = 0x014;
pub const LAN78XX_USB_CFG0: u32 = 0x080;
pub const LAN78XX_BURST_CAP: u32 = 0x090;
pub const LAN78XX_RFE_CTL: u32 = 0x0B0;
pub const LAN78XX_FCT_RX_CTL: u32 = 0x0C0;
pub const LAN78XX_FCT_TX_CTL: u32 = 0x0C4;
pub const LAN78XX_MAC_CR: u32 = 0x100;
pub const LAN78XX_MAC_RX: u32 = 0x104;
pub const LAN78XX_MAC_TX: u32 = 0x108;
pub const LAN78XX_FLOW: u32 = 0x10C;
pub const LAN78XX_RX_ADDRH: u32 = 0x118;
pub const LAN78XX_RX_ADDRL: u32 = 0x11C;
pub const LAN78XX_MII_ACC: u32 = 0x120;
pub const LAN78XX_MII_DATA: u32 = 0x124;

// Standard 802.3 MII/GMII PHY registers
pub const MII_BMCR: u8 = 0x00;
pub const MII_BMSR: u8 = 0x01;
pub const MII_PHYID1: u8 = 0x02;
pub const MII_PHYID2: u8 = 0x03;
pub const MII_ADVERTISE: u8 = 0x04;
pub const MII_LPA: u8 = 0x05;
pub const MII_CTRL1000: u8 = 0x09;
pub const MII_STAT1000: u8 = 0x0A;

/// BCM2837 Synopsys DesignWare DWC2 USB 2.0 Host Controller (`0x3F98_0000`) + LAN7515 Hub state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bcm2837Dwc2UsbHost {
    pub core_initialized: bool,
    pub root_port_powered: bool,
    pub root_port_connected: bool,
    pub lan7515_hub_enumerated: bool,
    pub downstream_port_connected: [bool; 4],
}

impl Default for Bcm2837Dwc2UsbHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcm2837Dwc2UsbHost {
    pub const fn new() -> Self {
        Self {
            core_initialized: false,
            root_port_powered: false,
            root_port_connected: false,
            lan7515_hub_enumerated: false,
            downstream_port_connected: [false; 4],
        }
    }

    pub fn initialize_and_enumerate_lan7515(&mut self, cap: Capability) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        self.core_initialized = true;
        self.root_port_powered = true;
        self.root_port_connected = true;
        self.lan7515_hub_enumerated = true;
        self.downstream_port_connected = [true, true, false, false];
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct FrameSlot {
    len: usize,
    bytes: [u8; ETH_MAX_FRAME_BYTES],
}

impl FrameSlot {
    const EMPTY: Self = Self {
        len: 0,
        bytes: [0; ETH_MAX_FRAME_BYTES],
    };
}

/// Microchip LAN7515 USB 2.0 Gigabit Ethernet driver (`VID=0x0424`, `PID=0x7800`) on Raspberry Pi 3B+.
pub struct Lan7515GigabitNic<const RING_SIZE: usize> {
    pub chip_id_rev: u32,
    pub mac: [u8; 6],
    pub mtu: u16,
    pub link_up: bool,
    pub speed_mbps: u32,
    pub full_duplex: bool,
    pub promiscuous: bool,
    pub rx_csum_offload: bool,
    pub tx_csum_offload: bool,
    pub generation: u64,
    phy_regs: [u16; 32],
    tx_queue: [FrameSlot; RING_SIZE],
    tx_count: usize,
    rx_queue: [FrameSlot; RING_SIZE],
    rx_count: usize,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

impl<const RING_SIZE: usize> Default for Lan7515GigabitNic<RING_SIZE> {
    fn default() -> Self {
        Self::new(RPI3B_PLUS_DEFAULT_MAC)
    }
}

impl<const RING_SIZE: usize> Lan7515GigabitNic<RING_SIZE> {
    pub const fn new(mac: [u8; 6]) -> Self {
        let mut phy_regs = [0u16; 32];
        phy_regs[MII_BMCR as usize] = 0x1140; // Auto-neg enabled, 1000Mbps full duplex
        phy_regs[MII_BMSR as usize] = 0x796D; // Link up, auto-neg complete, extended status
        phy_regs[MII_PHYID1 as usize] = 0x0007; // Microchip / SMSC OUI
        phy_regs[MII_PHYID2 as usize] = 0xC132;
        phy_regs[MII_CTRL1000 as usize] = 0x0300; // Advertise 1000BASE-T Full/Half
        phy_regs[MII_STAT1000 as usize] = 0x3C00; // Link partner 1000BASE-T Full-Duplex capable
        Self {
            chip_id_rev: LAN7515_CHIP_ID_REV,
            mac,
            mtu: ETH_DEFAULT_MTU,
            link_up: true,
            speed_mbps: 1000,
            full_duplex: true,
            promiscuous: false,
            rx_csum_offload: true,
            tx_csum_offload: true,
            generation: 1,
            phy_regs,
            tx_queue: [FrameSlot::EMPTY; RING_SIZE],
            tx_count: 0,
            rx_queue: [FrameSlot::EMPTY; RING_SIZE],
            rx_count: 0,
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
        }
    }

    pub fn reset(&mut self, cap: Capability) -> Result<u64, RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        self.generation = self.generation.saturating_add(1);
        self.tx_count = 0;
        self.rx_count = 0;
        self.link_up = true;
        self.speed_mbps = 1000;
        self.full_duplex = true;
        Ok(self.generation)
    }

    pub fn set_mac_address(&mut self, cap: Capability, mac: [u8; 6]) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        // Reject multicast or all-zero station MAC
        if (mac[0] & 1) != 0 || mac == [0; 6] {
            return Err(RpiError::InvalidArgument);
        }
        self.mac = mac;
        Ok(())
    }

    pub const fn rx_addr_low(&self) -> u32 {
        u32::from_le_bytes([self.mac[0], self.mac[1], self.mac[2], self.mac[3]])
    }

    pub const fn rx_addr_high(&self) -> u32 {
        u32::from_le_bytes([self.mac[4], self.mac[5], 0, 0])
    }

    pub fn mdio_read(&self, phy_reg: u8) -> Result<u16, RpiError> {
        if phy_reg >= 32 {
            return Err(RpiError::OutOfRange);
        }
        Ok(self.phy_regs[phy_reg as usize])
    }

    pub fn mdio_write(&mut self, cap: Capability, phy_reg: u8, value: u16) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if phy_reg >= 32 {
            return Err(RpiError::OutOfRange);
        }
        self.phy_regs[phy_reg as usize] = value;
        Ok(())
    }

    /// Submits an outbound Ethernet frame over the LAN7515 USB bulk-out pipe with DMA validation.
    pub fn transmit_frame(
        &mut self,
        cap: Capability,
        dma: &DmaMapping,
        expected_generation: u64,
        dma_iova: u64,
        frame: &[u8],
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        if self.generation != expected_generation {
            return Err(RpiError::StaleGeneration);
        }
        if !self.link_up {
            return Err(RpiError::LinkDown);
        }
        let max_len = usize::from(self.mtu) + 18;
        if frame.len() < ETH_MIN_FRAME_BYTES || frame.len() > max_len.min(ETH_MAX_FRAME_BYTES) {
            return Err(RpiError::InvalidFrame);
        }
        verify_dma_window(dma, dma_iova, frame.len(), DmaPerms::READ)?;
        if self.tx_count >= RING_SIZE {
            return Err(RpiError::QueueFull);
        }
        let mut slot = FrameSlot::EMPTY;
        slot.len = frame.len();
        slot.bytes[..frame.len()].copy_from_slice(frame);
        self.tx_queue[self.tx_count] = slot;
        self.tx_count += 1;
        self.tx_packets += 1;
        self.tx_bytes += frame.len() as u64;
        Ok(())
    }

    pub fn pop_wire_tx(&mut self, out: &mut [u8]) -> Result<usize, RpiError> {
        if self.tx_count == 0 {
            return Err(RpiError::QueueEmpty);
        }
        let slot = self.tx_queue[0];
        if out.len() < slot.len {
            return Err(RpiError::BufferTooSmall);
        }
        out[..slot.len].copy_from_slice(&slot.bytes[..slot.len]);
        for i in 1..self.tx_count {
            self.tx_queue[i - 1] = self.tx_queue[i];
        }
        self.tx_count -= 1;
        Ok(slot.len)
    }

    /// Injects an inbound Ethernet frame from the wire into the LAN7515 MAC filter (`RFE_CTL`).
    pub fn push_wire_rx(&mut self, frame: &[u8]) -> Result<(), RpiError> {
        if !self.link_up {
            return Err(RpiError::LinkDown);
        }
        let max_len = usize::from(self.mtu) + 18;
        if frame.len() < ETH_MIN_FRAME_BYTES || frame.len() > max_len.min(ETH_MAX_FRAME_BYTES) {
            return Err(RpiError::InvalidFrame);
        }
        let dst = &frame[0..6];
        let is_broadcast = dst == [0xFF; 6];
        let is_multicast = (dst[0] & 1) != 0;
        let is_unicast_match = dst == self.mac;
        if !self.promiscuous && !is_broadcast && !is_multicast && !is_unicast_match {
            return Err(RpiError::FilteredFrame);
        }
        if self.rx_count >= RING_SIZE {
            return Err(RpiError::QueueFull);
        }
        let mut slot = FrameSlot::EMPTY;
        slot.len = frame.len();
        slot.bytes[..frame.len()].copy_from_slice(frame);
        self.rx_queue[self.rx_count] = slot;
        self.rx_count += 1;
        Ok(())
    }

    /// Dequeues a received Ethernet frame into `out` with DMA write permission verification.
    pub fn receive_frame(
        &mut self,
        cap: Capability,
        dma: &DmaMapping,
        expected_generation: u64,
        dma_iova: u64,
        out: &mut [u8],
    ) -> Result<usize, RpiError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(RpiError::PermissionDenied);
        }
        if self.generation != expected_generation {
            return Err(RpiError::StaleGeneration);
        }
        if self.rx_count == 0 {
            return Err(RpiError::QueueEmpty);
        }
        let slot = self.rx_queue[0];
        if out.len() < slot.len {
            return Err(RpiError::BufferTooSmall);
        }
        verify_dma_window(dma, dma_iova, slot.len, DmaPerms::WRITE)?;
        out[..slot.len].copy_from_slice(&slot.bytes[..slot.len]);
        for i in 1..self.rx_count {
            self.rx_queue[i - 1] = self.rx_queue[i];
        }
        self.rx_count -= 1;
        self.rx_packets += 1;
        self.rx_bytes += slot.len as u64;
        Ok(slot.len)
    }
}
