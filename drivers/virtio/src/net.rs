// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

use crate::queue::{DmaBufferGrant, SplitVirtqueue, VirtqDesc, validate_descriptor_chain};
use crate::{VIRTIO_F_VERSION_1, VirtioError};
use kernal_capability::{CapRights, Capability};

pub const NET_DEFAULT_MTU: usize = 1500;
pub const MAX_ETH_FRAME: usize = 1514;
pub const ETHERNET_HEADER_BYTES: usize = 14;

pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_NET_F_MTU: u64 = 1 << 3;

pub const SUPPORTED_NET_FEATURES: u64 = VIRTIO_F_VERSION_1
    | VIRTIO_NET_F_CSUM
    | VIRTIO_NET_F_GUEST_CSUM
    | VIRTIO_NET_F_MAC
    | VIRTIO_NET_F_MTU
    | VIRTIO_NET_F_STATUS;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetDirection {
    Rx,
    Tx,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioNetL3 {
    Arp,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioNetL4 {
    Udp,
    Tcp,
}

/// Validates a VirtIO-Net RX/TX request frame, L3/L4 header classification, MTU bounds, DMA grant,
/// and split-virtqueue descriptor chain.
#[derive(Clone, Copy, Debug)]
pub struct VirtioNetValidation<'a> {
    pub queue_size: usize,
    pub features: u64,
    pub direction: NetDirection,
    pub packet_len: usize,
    pub mtu: usize,
    pub l3: VirtioNetL3,
    pub l4: Option<VirtioNetL4>,
    pub descriptors: &'a [VirtqDesc],
    pub head: u16,
    pub grant: &'a DmaBufferGrant,
}

pub fn validate_net_request(req: VirtioNetValidation<'_>) -> Result<usize, VirtioError> {
    if (req.features & VIRTIO_F_VERSION_1) == 0 {
        return Err(VirtioError::MissingVersion1Feature);
    }
    if (req.features & !SUPPORTED_NET_FEATURES) != 0 {
        return Err(VirtioError::UnsupportedFeature);
    }
    if req.mtu == 0
        || req.packet_len < ETHERNET_HEADER_BYTES
        || req.packet_len > req.mtu + ETHERNET_HEADER_BYTES
    {
        return Err(VirtioError::InvalidPacket);
    }
    match (req.l3, req.l4) {
        (VirtioNetL3::Arp, None) => {}
        (VirtioNetL3::Arp, Some(_)) => return Err(VirtioError::InvalidPacket),
        (VirtioNetL3::Ipv4 | VirtioNetL3::Ipv6, Some(VirtioNetL4::Tcp | VirtioNetL4::Udp)) => {}
        (VirtioNetL3::Ipv4 | VirtioNetL3::Ipv6, None) => return Err(VirtioError::InvalidPacket),
    }
    validate_descriptor_chain(req.queue_size, req.descriptors, req.head, Some(req.grant))
}

#[derive(Clone, Copy)]
struct FrameSlot {
    len: usize,
    bytes: [u8; MAX_ETH_FRAME],
}

impl FrameSlot {
    const EMPTY: Self = Self {
        len: 0,
        bytes: [0u8; MAX_ETH_FRAME],
    };
}

/// Capability- and DMA-mediated VirtIO-Net NIC with split TX/RX queues and Ethernet frame buffers.
#[derive(Clone)]
pub struct VirtioNetDevice<const Q: usize, const RING: usize> {
    tx_queue: SplitVirtqueue<Q>,
    rx_queue: SplitVirtqueue<Q>,
    features: u64,
    mac: [u8; 6],
    mtu: usize,
    link_up: bool,
    tx_ring: [FrameSlot; RING],
    tx_head: usize,
    tx_tail: usize,
    tx_count: usize,
    rx_ring: [FrameSlot; RING],
    rx_head: usize,
    rx_tail: usize,
    rx_count: usize,
}

impl<const Q: usize, const RING: usize> VirtioNetDevice<Q, RING> {
    pub fn new(features: u64, mac: [u8; 6], mtu: usize) -> Result<Self, VirtioError> {
        if (features & VIRTIO_F_VERSION_1) == 0 {
            return Err(VirtioError::MissingVersion1Feature);
        }
        if (features & !SUPPORTED_NET_FEATURES) != 0 {
            return Err(VirtioError::UnsupportedFeature);
        }
        if mtu == 0 || mtu + ETHERNET_HEADER_BYTES > MAX_ETH_FRAME || RING == 0 {
            return Err(VirtioError::InvalidPacket);
        }
        Ok(Self {
            tx_queue: SplitVirtqueue::new(),
            rx_queue: SplitVirtqueue::new(),
            features,
            mac,
            mtu,
            link_up: true,
            tx_ring: [FrameSlot::EMPTY; RING],
            tx_head: 0,
            tx_tail: 0,
            tx_count: 0,
            rx_ring: [FrameSlot::EMPTY; RING],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
        })
    }

    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    pub const fn link_up(&self) -> bool {
        self.link_up
    }

    pub fn set_link_up(&mut self, up: bool) {
        self.link_up = up;
    }

    pub fn reset_and_revoke(&mut self) {
        self.tx_queue.reset_and_revoke();
        self.rx_queue.reset_and_revoke();
        self.tx_head = 0;
        self.tx_tail = 0;
        self.tx_count = 0;
        self.rx_head = 0;
        self.rx_tail = 0;
        self.rx_count = 0;
    }

    fn check_frame(&self, frame: &[u8]) -> Result<(), VirtioError> {
        if frame.len() < ETHERNET_HEADER_BYTES || frame.len() > self.mtu + ETHERNET_HEADER_BYTES {
            return Err(VirtioError::InvalidPacket);
        }
        Ok(())
    }

    pub fn transmit(
        &mut self,
        cap: Capability,
        grant: &DmaBufferGrant,
        l3: VirtioNetL3,
        l4: Option<VirtioNetL4>,
        frame: &[u8],
    ) -> Result<(), VirtioError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(VirtioError::RevokedAuthority);
        }
        if !self.link_up {
            return Err(VirtioError::DeviceFault);
        }
        self.check_frame(frame)?;
        if self.tx_count == RING {
            return Err(VirtioError::QueueFull);
        }

        let desc = [VirtqDesc {
            addr: grant.base_addr,
            len: (frame.len() + core::mem::size_of::<VirtioNetHdr>()) as u32,
            flags: 0,
            next: 0,
        }];
        let _ = validate_net_request(VirtioNetValidation {
            queue_size: Q,
            features: self.features,
            direction: NetDirection::Tx,
            packet_len: frame.len(),
            mtu: self.mtu,
            l3,
            l4,
            descriptors: &desc,
            head: 0,
            grant,
        })?;

        let chain = [(grant.base_addr, desc[0].len, false)];
        let (head, generation) = self.tx_queue.submit_chain(&chain, grant)?;
        self.tx_ring[self.tx_tail].len = frame.len();
        self.tx_ring[self.tx_tail].bytes[..frame.len()].copy_from_slice(frame);
        self.tx_tail = (self.tx_tail + 1) % RING;
        self.tx_count += 1;
        self.tx_queue.complete_used(head, 0, generation)?;
        let _ = self.tx_queue.pop_used(generation)?;
        Ok(())
    }

    pub fn inject_rx_frame(&mut self, frame: &[u8]) -> Result<(), VirtioError> {
        self.check_frame(frame)?;
        if self.rx_count == RING {
            return Err(VirtioError::QueueFull);
        }
        self.rx_ring[self.rx_tail].len = frame.len();
        self.rx_ring[self.rx_tail].bytes[..frame.len()].copy_from_slice(frame);
        self.rx_tail = (self.rx_tail + 1) % RING;
        self.rx_count += 1;
        Ok(())
    }

    pub fn receive(
        &mut self,
        cap: Capability,
        grant: &DmaBufferGrant,
        out_frame: &mut [u8],
    ) -> Result<usize, VirtioError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(VirtioError::RevokedAuthority);
        }
        if self.rx_count == 0 {
            return Err(VirtioError::QueueEmpty);
        }
        let slot_len = self.rx_ring[self.rx_head].len;
        if out_frame.len() < slot_len {
            return Err(VirtioError::BufferTooSmall);
        }
        let mut rx_grant = *grant;
        rx_grant.writable = true;
        let chain = [(
            grant.base_addr,
            (slot_len + core::mem::size_of::<VirtioNetHdr>()) as u32,
            true,
        )];
        let (head, generation) = self.rx_queue.submit_chain(&chain, &rx_grant)?;
        out_frame[..slot_len].copy_from_slice(&self.rx_ring[self.rx_head].bytes[..slot_len]);
        self.rx_head = (self.rx_head + 1) % RING;
        self.rx_count -= 1;
        self.rx_queue.complete_used(head, chain[0].1, generation)?;
        let _ = self.rx_queue.pop_used(generation)?;
        Ok(slot_len)
    }

    pub fn pop_transmitted(&mut self, out_frame: &mut [u8]) -> Result<usize, VirtioError> {
        if self.tx_count == 0 {
            return Err(VirtioError::QueueEmpty);
        }
        let len = self.tx_ring[self.tx_head].len;
        if out_frame.len() < len {
            return Err(VirtioError::BufferTooSmall);
        }
        out_frame[..len].copy_from_slice(&self.tx_ring[self.tx_head].bytes[..len]);
        self.tx_head = (self.tx_head + 1) % RING;
        self.tx_count -= 1;
        Ok(len)
    }
}
