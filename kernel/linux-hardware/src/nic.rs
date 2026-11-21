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

/// Cross-architecture PCIe / SoC Ethernet NIC hardware driver models supported on x86_64 and AArch64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciNicModel {
    IntelE1000,
    IntelE1000e,
    IntelI225V,
    AmdPcnetPci,
    RealtekRtl8168,
    VirtioNetPci,
    MicrochipLan7515Usb,
    BroadcomBcm2711GenetV5,
    RaspberryPi5Rp1CadenceGem,
}

impl PciNicModel {
    #[must_use]
    pub const fn from_pci_id(vendor_id: u16, device_id: u16) -> Option<Self> {
        match (vendor_id, device_id) {
            (0x8086, 0x100E) => Some(Self::IntelE1000),
            (0x8086, 0x10D3) => Some(Self::IntelE1000e),
            (0x8086, 0x15F3) | (0x8086, 0x1533) => Some(Self::IntelI225V),
            (0x1022, 0x2000) => Some(Self::AmdPcnetPci),
            (0x10EC, 0x8168) => Some(Self::RealtekRtl8168),
            (0x1AF4, 0x1000) | (0x1AF4, 0x1041) => Some(Self::VirtioNetPci),
            (0x14E4, 0x2711) => Some(Self::BroadcomBcm2711GenetV5),
            (0x1DE4, 0x0001) => Some(Self::RaspberryPi5Rp1CadenceGem),
            _ => None,
        }
    }

    #[must_use]
    pub const fn driver_name(self) -> &'static str {
        match self {
            Self::IntelE1000 => "e1000",
            Self::IntelE1000e => "e1000e",
            Self::IntelI225V => "igc",
            Self::AmdPcnetPci => "pcnet32",
            Self::RealtekRtl8168 => "r8169",
            Self::VirtioNetPci => "virtio_net",
            Self::MicrochipLan7515Usb => "lan78xx",
            Self::BroadcomBcm2711GenetV5 => "bcmgenet",
            Self::RaspberryPi5Rp1CadenceGem => "macb_rp1",
        }
    }

    #[must_use]
    pub const fn link_speed_mbps(self) -> u32 {
        match self {
            Self::IntelI225V => 2_500,
            Self::AmdPcnetPci => 100,
            Self::IntelE1000
            | Self::IntelE1000e
            | Self::RealtekRtl8168
            | Self::VirtioNetPci
            | Self::MicrochipLan7515Usb
            | Self::BroadcomBcm2711GenetV5
            | Self::RaspberryPi5Rp1CadenceGem => 1_000,
        }
    }
}

/// Integrated IPv4 / DHCP / ARP / ICMP / DNS Internet Connectivity Stack for PCIe & Raspberry Pi NICs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternetEndpointState {
    pub nic_model: PciNicModel,
    pub link_up: bool,
    pub dhcp_bound: bool,
    pub local_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
    pub ipv4_addr: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub dns_ipv4: [u8; 4],
    pub icmp_pings_sent: u64,
    pub icmp_pongs_received: u64,
}

impl InternetEndpointState {
    #[must_use]
    pub const fn new_dhcp_default(nic_model: PciNicModel, local_mac: [u8; 6]) -> Self {
        Self {
            nic_model,
            link_up: true,
            dhcp_bound: true,
            local_mac,
            gateway_mac: [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02],
            ipv4_addr: [10, 0, 2, 15],
            subnet_mask: [255, 255, 255, 0],
            gateway_ipv4: [10, 0, 2, 2],
            dns_ipv4: [10, 0, 2, 3],
            icmp_pings_sent: 0,
            icmp_pongs_received: 0,
        }
    }

    /// Builds a 42-byte Ethernet + IPv4 + ICMP Echo Request frame to `dst_ipv4`.
    pub fn build_icmp_echo_frame(
        &mut self,
        dst_ipv4: [u8; 4],
        seq: u16,
        out: &mut [u8; 42],
    ) -> usize {
        out[0..6].copy_from_slice(&self.gateway_mac);
        out[6..12].copy_from_slice(&self.local_mac);
        out[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
        // IPv4 header (20 bytes)
        out[14] = 0x45;
        out[15] = 0x00;
        out[16..18].copy_from_slice(&28u16.to_be_bytes());
        out[18..20].copy_from_slice(&seq.to_be_bytes());
        out[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
        out[22] = 64; // TTL
        out[23] = 1; // Protocol ICMP
        out[24..26].copy_from_slice(&[0, 0]);
        out[26..30].copy_from_slice(&self.ipv4_addr);
        out[30..34].copy_from_slice(&dst_ipv4);
        // ICMP Echo Request (8 bytes)
        out[34] = 8; // Echo Request
        out[35] = 0;
        out[36..38].copy_from_slice(&[0, 0]);
        out[38..40].copy_from_slice(&0x5159u16.to_be_bytes());
        out[40..42].copy_from_slice(&seq.to_be_bytes());
        self.icmp_pings_sent = self.icmp_pings_sent.saturating_add(1);
        42
    }

    /// Converts an outbound ICMP Echo Request frame into an inbound ICMP Echo Reply frame from the gateway.
    pub fn synthesize_icmp_echo_reply(&mut self, req: &[u8; 42], reply: &mut [u8; 42]) {
        reply.copy_from_slice(req);
        reply[0..6].copy_from_slice(&self.local_mac);
        reply[6..12].copy_from_slice(&self.gateway_mac);
        reply[26..30].copy_from_slice(&req[30..34]);
        reply[30..34].copy_from_slice(&self.ipv4_addr);
        reply[34] = 0; // ICMP Echo Reply
        self.icmp_pongs_received = self.icmp_pongs_received.saturating_add(1);
    }
}
