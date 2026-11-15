// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Hardware split-virtqueue VirtIO-MMIO network device driver (`virtio-net`).
//!
//! Operates over any [`MmioBus`] (including [`crate::VolatileMmioBus`] mapped into TTBR1 Device
//! memory on AArch64 and mock buses in host tests) with an explicit static DMA memory block
//! (`VirtioNetDmaBlock`) validated by [`DmaBufferGrant`]. Supports both VirtIO 1.x (`version >= 2`,
//! 12-byte [`VirtioNetHdr`]) and legacy v1 (`version == 1`, 10-byte legacy header).

use core::mem::{offset_of, size_of};
use core::ptr::{NonNull, copy_nonoverlapping, read_volatile, write_bytes, write_volatile};

use kernal_fdt_aarch64::VirtioMmioInfo;

use crate::VirtioError;
use crate::blk_mmio::{VRING_AVAIL_F_NO_INTERRUPT, VirtqAvailPage, VirtqUsedPage, dma_fence};
use crate::mmio::{
    MmioBus, REG_CONFIG_BASE, REG_CONFIG_GENERATION, VIRTIO_F_VERSION_1, VirtioDeviceId,
    VirtioMmioTransport,
};
use crate::net::{
    ETHERNET_HEADER_BYTES, MAX_ETH_FRAME, NET_DEFAULT_MTU, VIRTIO_NET_F_MAC, VIRTIO_NET_F_MTU,
    VIRTIO_NET_F_STATUS, VirtioNetHdr,
};
use crate::queue::{
    DmaBufferGrant, MAX_VIRTQ_SIZE, VRING_DESC_F_WRITE, VirtqDesc, VirtqUsedElem,
    validate_descriptor_chain,
};

pub const DEFAULT_NET_MMIO_QUEUE_SIZE: usize = 32;
pub const DEFAULT_NET_MMIO_BUF_BYTES: usize = 2048;

pub const HARDWARE_NET_FEATURES: u64 =
    VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_NET_F_MTU;

const PAGE_BYTES: usize = 4096;
const VIRTIO_NET_S_LINK_UP: u16 = 1;
const DEFAULT_FALLBACK_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// Page-aligned split-virtqueue + RX/TX slot DMA memory block for one `virtio-net` controller.
#[repr(C, align(4096))]
pub struct VirtioNetDmaBlock<
    const Q: usize = DEFAULT_NET_MMIO_QUEUE_SIZE,
    const BUF: usize = DEFAULT_NET_MMIO_BUF_BYTES,
> {
    pub rx_avail: VirtqAvailPage<Q>,
    pub rx_used: VirtqUsedPage<Q>,
    pub tx_avail: VirtqAvailPage<Q>,
    pub tx_used: VirtqUsedPage<Q>,
    pub rx_slots: [[u8; BUF]; Q],
    pub tx_slots: [[u8; BUF]; Q],
}

impl<const Q: usize, const BUF: usize> VirtioNetDmaBlock<Q, BUF> {
    pub const fn zeroed() -> Self {
        const EMPTY_DESC: VirtqDesc = VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        };
        const EMPTY_USED: VirtqUsedElem = VirtqUsedElem { id: 0, len: 0 };
        Self {
            rx_avail: VirtqAvailPage {
                desc: [EMPTY_DESC; Q],
                avail_flags: 0,
                avail_idx: 0,
                avail_ring: [0; Q],
                avail_used_event: 0,
            },
            rx_used: VirtqUsedPage {
                used_flags: 0,
                used_idx: 0,
                used_ring: [EMPTY_USED; Q],
                used_avail_event: 0,
            },
            tx_avail: VirtqAvailPage {
                desc: [EMPTY_DESC; Q],
                avail_flags: 0,
                avail_idx: 0,
                avail_ring: [0; Q],
                avail_used_event: 0,
            },
            tx_used: VirtqUsedPage {
                used_flags: 0,
                used_idx: 0,
                used_ring: [EMPTY_USED; Q],
                used_avail_event: 0,
            },
            rx_slots: [[0; BUF]; Q],
            tx_slots: [[0; BUF]; Q],
        }
    }
}

pub struct VirtioNetMmio<
    B,
    const Q: usize = DEFAULT_NET_MMIO_QUEUE_SIZE,
    const BUF: usize = DEFAULT_NET_MMIO_BUF_BYTES,
> {
    bus: B,
    transport: VirtioMmioTransport,
    mac: [u8; 6],
    mtu: u16,
    link_up: bool,
    hdr_bytes: usize,
    dma_virt: NonNull<VirtioNetDmaBlock<Q, BUF>>,
    dma_phys_base: u64,
    grant: DmaBufferGrant,
    rx_avail_idx: u16,
    rx_last_used_idx: u16,
    tx_avail_idx: u16,
    tx_last_used_idx: u16,
    tx_in_flight: [bool; Q],
    tx_cursor: usize,
    revoked: bool,
}

// SAFETY: `VirtioNetMmio` exclusively owns its MMIO bus and `dma_virt` DMA region, so moving it
// behind a kernel synchronization wrapper across PEs is sound.
unsafe impl<B: Send, const Q: usize, const BUF: usize> Send for VirtioNetMmio<B, Q, BUF> {}

impl<B: MmioBus, const Q: usize, const BUF: usize> VirtioNetMmio<B, Q, BUF> {
    /// Initializes a VirtIO-MMIO network device on `bus` backed by `dma_virt` (`dma_phys_base`).
    ///
    /// # Safety
    /// - `dma_virt` must point to a valid, exclusively owned, 4 KiB-aligned `VirtioNetDmaBlock`
    ///   that remains live and unmoved for the lifetime of the returned driver.
    /// - `dma_phys_base` must be the exact physical address backing `dma_virt` for at least
    ///   `size_of::<VirtioNetDmaBlock<Q, BUF>>()` contiguous physical bytes, covered by `grant`.
    pub unsafe fn initialize(
        info: VirtioMmioInfo,
        mut bus: B,
        dma_virt: NonNull<VirtioNetDmaBlock<Q, BUF>>,
        dma_phys_base: u64,
        grant: DmaBufferGrant,
    ) -> Result<Self, VirtioError> {
        if !(4..=MAX_VIRTQ_SIZE).contains(&Q) || !Q.is_power_of_two() || Q > 128 {
            return Err(VirtioError::InvalidQueueSize);
        }
        if BUF < size_of::<VirtioNetHdr>() + MAX_ETH_FRAME {
            return Err(VirtioError::BufferTooSmall);
        }
        if offset_of!(VirtioNetDmaBlock<Q, BUF>, rx_used) != PAGE_BYTES
            || offset_of!(VirtioNetDmaBlock<Q, BUF>, tx_avail) != PAGE_BYTES * 2
            || offset_of!(VirtioNetDmaBlock<Q, BUF>, tx_used) != PAGE_BYTES * 3
        {
            return Err(VirtioError::InvalidQueueSize);
        }
        if !dma_phys_base.is_multiple_of(PAGE_BYTES as u64)
            || !(dma_virt.as_ptr() as usize).is_multiple_of(PAGE_BYTES)
        {
            return Err(VirtioError::DescriptorOutOfBounds);
        }

        let dma_bytes = u64::try_from(size_of::<VirtioNetDmaBlock<Q, BUF>>())
            .map_err(|_| VirtioError::OutOfRange)?;
        grant.validate_authority()?;
        if !grant.writable {
            return Err(VirtioError::RevokedAuthority);
        }
        let grant_end = grant
            .base_addr
            .checked_add(grant.len)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let dma_end = dma_phys_base
            .checked_add(dma_bytes)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        if dma_phys_base < grant.base_addr || dma_end > grant_end {
            return Err(VirtioError::DescriptorOutOfBounds);
        }

        let probe = VirtioMmioTransport::probe(info, &bus)?;
        if probe.device_id != VirtioDeviceId::Net {
            return Err(VirtioError::UnsupportedDeviceId);
        }

        let supported = if probe.version >= 2 {
            HARDWARE_NET_FEATURES
        } else {
            HARDWARE_NET_FEATURES & !VIRTIO_F_VERSION_1
        };
        let mut transport = VirtioMmioTransport::initialize(info, &mut bus, supported)?;
        let hdr_bytes = if (transport.negotiated_features & VIRTIO_F_VERSION_1) != 0 {
            size_of::<VirtioNetHdr>()
        } else {
            10
        };

        // SAFETY: `dma_virt` is exclusively owned, writable, aligned, and covers `VirtioNetDmaBlock`.
        unsafe {
            write_bytes(dma_virt.as_ptr(), 0, 1);
            write_volatile(
                &raw mut (*dma_virt.as_ptr()).rx_avail.avail_flags,
                VRING_AVAIL_F_NO_INTERRUPT,
            );
            write_volatile(
                &raw mut (*dma_virt.as_ptr()).tx_avail.avail_flags,
                VRING_AVAIL_F_NO_INTERRUPT,
            );
        }
        dma_fence();

        let rx_desc_phys = dma_phys_base;
        let rx_avail_phys = dma_phys_base
            .checked_add(offset_of!(VirtqAvailPage<Q>, avail_flags) as u64)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let rx_used_phys = dma_phys_base
            .checked_add(offset_of!(VirtioNetDmaBlock<Q, BUF>, rx_used) as u64)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;

        let tx_base = offset_of!(VirtioNetDmaBlock<Q, BUF>, tx_avail) as u64;
        let tx_desc_phys = dma_phys_base
            .checked_add(tx_base)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let tx_avail_phys = dma_phys_base
            .checked_add(tx_base + offset_of!(VirtqAvailPage<Q>, avail_flags) as u64)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let tx_used_phys = dma_phys_base
            .checked_add(offset_of!(VirtioNetDmaBlock<Q, BUF>, tx_used) as u64)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;

        transport.setup_queue(
            &mut bus,
            0,
            Q as u16,
            rx_desc_phys,
            rx_avail_phys,
            rx_used_phys,
        )?;
        transport.setup_queue(
            &mut bus,
            1,
            Q as u16,
            tx_desc_phys,
            tx_avail_phys,
            tx_used_phys,
        )?;
        transport.mark_driver_ok(&mut bus)?;

        let (mac, mtu, link_up) = Self::read_net_config(&bus, &transport)?;

        let mut dev = Self {
            bus,
            transport,
            mac,
            mtu,
            link_up,
            hdr_bytes,
            dma_virt,
            dma_phys_base,
            grant,
            rx_avail_idx: 0,
            rx_last_used_idx: 0,
            tx_avail_idx: 0,
            tx_last_used_idx: 0,
            tx_in_flight: [false; Q],
            tx_cursor: 0,
            revoked: false,
        };
        dev.post_all_rx_descriptors()?;
        Ok(dev)
    }

    fn read_net_config(
        bus: &B,
        transport: &VirtioMmioTransport,
    ) -> Result<([u8; 6], u16, bool), VirtioError> {
        for _ in 0..8 {
            let gen_before = if transport.version >= 2 {
                bus.read32(REG_CONFIG_GENERATION)?
            } else {
                0
            };

            let mac = if (transport.negotiated_features & VIRTIO_NET_F_MAC) != 0 {
                let mut m = [0u8; 6];
                for (i, byte) in m.iter_mut().enumerate() {
                    *byte = bus.read8(REG_CONFIG_BASE + i)?;
                }
                m
            } else {
                DEFAULT_FALLBACK_MAC
            };

            let link_up = if (transport.negotiated_features & VIRTIO_NET_F_STATUS) != 0 {
                let lo = bus.read8(REG_CONFIG_BASE + 6)?;
                let hi = bus.read8(REG_CONFIG_BASE + 7)?;
                (u16::from_le_bytes([lo, hi]) & VIRTIO_NET_S_LINK_UP) != 0
            } else {
                true
            };

            let mtu = if (transport.negotiated_features & VIRTIO_NET_F_MTU) != 0 {
                let lo = bus.read8(REG_CONFIG_BASE + 10)?;
                let hi = bus.read8(REG_CONFIG_BASE + 11)?;
                let raw = u16::from_le_bytes([lo, hi]);
                if raw == 0 {
                    NET_DEFAULT_MTU as u16
                } else {
                    raw
                }
            } else {
                NET_DEFAULT_MTU as u16
            };

            let gen_after = if transport.version >= 2 {
                bus.read32(REG_CONFIG_GENERATION)?
            } else {
                0
            };
            if gen_before == gen_after {
                return Ok((mac, mtu, link_up));
            }
        }
        Err(VirtioError::DeviceFault)
    }

    fn post_rx_descriptor(&mut self, slot: usize, notify: bool) -> Result<(), VirtioError> {
        let rx_base = offset_of!(VirtioNetDmaBlock<Q, BUF>, rx_slots) as u64;
        let slot_phys = self
            .dma_phys_base
            .checked_add(rx_base + (slot * BUF) as u64)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let desc = VirtqDesc {
            addr: slot_phys,
            len: u32::try_from(BUF).map_err(|_| VirtioError::DescriptorLengthOverflow)?,
            flags: VRING_DESC_F_WRITE,
            next: 0,
        };
        validate_descriptor_chain(Q, core::slice::from_ref(&desc), 0, Some(&self.grant))?;

        let avail_slot = usize::from(self.rx_avail_idx) & (Q - 1);
        let next_avail = self.rx_avail_idx.wrapping_add(1);
        let dma_ptr = self.dma_virt.as_ptr();
        // SAFETY: `dma_ptr` points to exclusively owned aligned DMA memory covered by `self.grant`.
        unsafe {
            write_volatile(&raw mut (*dma_ptr).rx_avail.desc[slot], desc);
            write_volatile(
                &raw mut (*dma_ptr).rx_avail.avail_ring[avail_slot],
                slot as u16,
            );
        }
        dma_fence();
        // SAFETY: descriptor and avail ring entry are published before `avail_idx`.
        unsafe {
            write_volatile(&raw mut (*dma_ptr).rx_avail.avail_idx, next_avail);
        }
        dma_fence();
        self.rx_avail_idx = next_avail;
        if notify {
            self.transport.notify_queue(&mut self.bus, 0)?;
        }
        Ok(())
    }

    fn post_all_rx_descriptors(&mut self) -> Result<(), VirtioError> {
        for slot in 0..Q {
            self.post_rx_descriptor(slot, false)?;
        }
        self.transport.notify_queue(&mut self.bus, 0)
    }

    fn reclaim_tx(&mut self) -> Result<(), VirtioError> {
        let dma_ptr = self.dma_virt.as_ptr();
        dma_fence();
        // SAFETY: volatile read of device-updated `used_idx`.
        let used_idx = unsafe { read_volatile(&raw const (*dma_ptr).tx_used.used_idx) };
        while self.tx_last_used_idx != used_idx {
            let ring_idx = usize::from(self.tx_last_used_idx) & (Q - 1);
            // SAFETY: `ring_idx` is bounded by `Q` and written by device prior to `used_idx`.
            let elem = unsafe { read_volatile(&raw const (*dma_ptr).tx_used.used_ring[ring_idx]) };
            if let Ok(desc_idx) = usize::try_from(elem.id)
                && desc_idx < Q
            {
                self.tx_in_flight[desc_idx] = false;
            }
            self.tx_last_used_idx = self.tx_last_used_idx.wrapping_add(1);
        }
        Ok(())
    }

    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    pub const fn link_up(&self) -> bool {
        self.link_up
    }

    pub const fn hdr_bytes(&self) -> usize {
        self.hdr_bytes
    }

    pub const fn transport(&self) -> &VirtioMmioTransport {
        &self.transport
    }

    /// Transmits a raw Ethernet frame over VirtIO-Net queue 1 (TX).
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), VirtioError> {
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        self.grant.validate_authority()?;
        if !self.link_up {
            return Err(VirtioError::DeviceDisabled);
        }
        if frame.len() < ETHERNET_HEADER_BYTES || frame.len() > MAX_ETH_FRAME {
            return Err(VirtioError::InvalidPacket);
        }
        let total_len = self
            .hdr_bytes
            .checked_add(frame.len())
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        if total_len > BUF {
            return Err(VirtioError::BufferTooSmall);
        }

        self.reclaim_tx()?;
        let mut chosen = None;
        for step in 0..Q {
            let idx = (self.tx_cursor + step) & (Q - 1);
            if !self.tx_in_flight[idx] {
                chosen = Some(idx);
                self.tx_cursor = (idx + 1) & (Q - 1);
                break;
            }
        }
        let Some(slot) = chosen else {
            return Err(VirtioError::QueueFull);
        };

        let tx_base = offset_of!(VirtioNetDmaBlock<Q, BUF>, tx_slots) as u64;
        let slot_phys = self
            .dma_phys_base
            .checked_add(tx_base + (slot * BUF) as u64)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let desc = VirtqDesc {
            addr: slot_phys,
            len: u32::try_from(total_len).map_err(|_| VirtioError::DescriptorLengthOverflow)?,
            flags: 0,
            next: 0,
        };
        validate_descriptor_chain(Q, core::slice::from_ref(&desc), 0, Some(&self.grant))?;

        let avail_slot = usize::from(self.tx_avail_idx) & (Q - 1);
        let next_avail = self.tx_avail_idx.wrapping_add(1);
        let dma_ptr = self.dma_virt.as_ptr();

        // SAFETY: `dma_ptr` points to exclusively owned aligned DMA memory covered by `self.grant`,
        // `slot` is not in flight (`!tx_in_flight[slot]`), and `total_len <= BUF`.
        unsafe {
            let dst_ptr = (&raw mut (*dma_ptr).tx_slots[slot]).cast::<u8>();
            write_bytes(dst_ptr, 0, self.hdr_bytes);
            copy_nonoverlapping(frame.as_ptr(), dst_ptr.add(self.hdr_bytes), frame.len());
            write_volatile(&raw mut (*dma_ptr).tx_avail.desc[slot], desc);
            write_volatile(
                &raw mut (*dma_ptr).tx_avail.avail_ring[avail_slot],
                slot as u16,
            );
        }
        dma_fence();
        // SAFETY: descriptor and payload are visible before `avail_idx` increments.
        unsafe {
            write_volatile(&raw mut (*dma_ptr).tx_avail.avail_idx, next_avail);
        }
        dma_fence();
        self.tx_avail_idx = next_avail;
        self.tx_in_flight[slot] = true;

        self.transport.notify_queue(&mut self.bus, 1)?;
        let _ = self.transport.ack_interrupt(&mut self.bus);
        Ok(())
    }

    /// Receives the next completed Ethernet frame from VirtIO-Net queue 0 (RX), if available,
    /// immediately replenishing the descriptor back onto the RX available ring.
    pub fn recv_frame(&mut self, out: &mut [u8]) -> Result<Option<usize>, VirtioError> {
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        self.grant.validate_authority()?;

        let dma_ptr = self.dma_virt.as_ptr();
        dma_fence();
        // SAFETY: volatile read of device-updated `used_idx`.
        let used_idx = unsafe { read_volatile(&raw const (*dma_ptr).rx_used.used_idx) };
        if self.rx_last_used_idx == used_idx {
            let _ = self.transport.ack_interrupt(&mut self.bus);
            return Ok(None);
        }

        let ring_idx = usize::from(self.rx_last_used_idx) & (Q - 1);
        // SAFETY: device published `used_idx != rx_last_used_idx` before this read.
        let elem = unsafe { read_volatile(&raw const (*dma_ptr).rx_used.used_ring[ring_idx]) };
        self.rx_last_used_idx = self.rx_last_used_idx.wrapping_add(1);

        let Ok(desc_idx) = usize::try_from(elem.id) else {
            return Err(VirtioError::DeviceFault);
        };
        if desc_idx >= Q {
            return Err(VirtioError::DeviceFault);
        }
        let used_len = (elem.len as usize).min(BUF);
        let frame_len = used_len.saturating_sub(self.hdr_bytes);
        let copied = if frame_len >= ETHERNET_HEADER_BYTES && frame_len <= out.len() {
            // SAFETY: `self.hdr_bytes + frame_len <= BUF` and `frame_len <= out.len()`.
            unsafe {
                let src_ptr = (&raw const (*dma_ptr).rx_slots[desc_idx]).cast::<u8>();
                copy_nonoverlapping(src_ptr.add(self.hdr_bytes), out.as_mut_ptr(), frame_len);
            }
            Some(frame_len)
        } else {
            None
        };

        self.post_rx_descriptor(desc_idx, true)?;
        let _ = self.transport.ack_interrupt(&mut self.bus);
        Ok(copied)
    }

    pub fn revoke_and_reset(&mut self) -> Result<(), VirtioError> {
        self.revoked = true;
        self.grant.revoked = true;
        self.transport.reset_and_revoke(&mut self.bus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmio::*;
    use kernal_fdt_aarch64::MmioRegion;

    struct MockNetMmioBus {
        version: u32,
        device_features: u64,
        driver_features: u64,
        features_sel: u32,
        driver_features_sel: u32,
        queue_sel: u32,
        queue_ready: [u32; 2],
        queue_desc: [u64; 2],
        queue_avail: [u64; 2],
        queue_used: [u64; 2],
        status: u32,
        interrupt_status: u32,
        mac: [u8; 6],
        rx_notifies: usize,
        tx_notifies: usize,
        dma_ptr: Option<NonNull<VirtioNetDmaBlock<8, 2048>>>,
    }

    impl MockNetMmioBus {
        fn new(mac: [u8; 6], dma: NonNull<VirtioNetDmaBlock<8, 2048>>) -> Self {
            Self {
                version: 2,
                device_features: HARDWARE_NET_FEATURES,
                driver_features: 0,
                features_sel: 0,
                driver_features_sel: 0,
                queue_sel: 0,
                queue_ready: [0; 2],
                queue_desc: [0; 2],
                queue_avail: [0; 2],
                queue_used: [0; 2],
                status: 0,
                interrupt_status: 0,
                mac,
                rx_notifies: 0,
                tx_notifies: 0,
                dma_ptr: Some(dma),
            }
        }
    }

    impl MmioBus for MockNetMmioBus {
        fn region_size(&self) -> u64 {
            0x200
        }

        fn read32(&self, offset: usize) -> Result<u32, VirtioError> {
            match offset {
                REG_MAGIC_VALUE => Ok(VIRTIO_MMIO_MAGIC),
                REG_VERSION => Ok(self.version),
                REG_DEVICE_ID => Ok(VirtioDeviceId::Net as u32),
                REG_VENDOR_ID => Ok(0x554d_4551),
                REG_DEVICE_FEATURES => Ok(if self.features_sel == 0 {
                    self.device_features as u32
                } else {
                    (self.device_features >> 32) as u32
                }),
                0x018 => Ok((self.device_features >> 32) as u32),
                REG_QUEUE_NUM_MAX => Ok(32),
                REG_QUEUE_READY => Ok(self
                    .queue_ready
                    .get(self.queue_sel as usize)
                    .copied()
                    .unwrap_or(0)),
                REG_INTERRUPT_STATUS => Ok(self.interrupt_status),
                REG_STATUS => Ok(self.status),
                REG_CONFIG_GENERATION => Ok(1),
                _ => Err(VirtioError::MmioOutOfBounds),
            }
        }

        fn write32(&mut self, offset: usize, value: u32) -> Result<(), VirtioError> {
            let q = self.queue_sel as usize;
            match offset {
                REG_DEVICE_FEATURES_SEL => self.features_sel = value,
                REG_DRIVER_FEATURES_SEL => self.driver_features_sel = value,
                REG_DRIVER_FEATURES => {
                    if self.driver_features_sel == 0 {
                        self.driver_features =
                            (self.driver_features & !0xffff_ffff) | u64::from(value);
                    } else {
                        self.driver_features =
                            (self.driver_features & 0xffff_ffff) | (u64::from(value) << 32);
                    }
                }
                REG_QUEUE_SEL => self.queue_sel = value,
                REG_QUEUE_NUM => {}
                REG_QUEUE_READY => {
                    if q < 2 {
                        self.queue_ready[q] = value;
                    }
                }
                REG_QUEUE_DESC_LOW => {
                    if q < 2 {
                        self.queue_desc[q] = (self.queue_desc[q] & !0xffff_ffff) | u64::from(value);
                    }
                }
                REG_QUEUE_DESC_HIGH => {
                    if q < 2 {
                        self.queue_desc[q] =
                            (self.queue_desc[q] & 0xffff_ffff) | (u64::from(value) << 32);
                    }
                }
                REG_QUEUE_AVAIL_LOW => {
                    if q < 2 {
                        self.queue_avail[q] =
                            (self.queue_avail[q] & !0xffff_ffff) | u64::from(value);
                    }
                }
                REG_QUEUE_AVAIL_HIGH => {
                    if q < 2 {
                        self.queue_avail[q] =
                            (self.queue_avail[q] & 0xffff_ffff) | (u64::from(value) << 32);
                    }
                }
                REG_QUEUE_USED_LOW => {
                    if q < 2 {
                        self.queue_used[q] = (self.queue_used[q] & !0xffff_ffff) | u64::from(value);
                    }
                }
                REG_QUEUE_USED_HIGH => {
                    if q < 2 {
                        self.queue_used[q] =
                            (self.queue_used[q] & 0xffff_ffff) | (u64::from(value) << 32);
                    }
                }
                REG_QUEUE_NOTIFY => {
                    if value == 0 {
                        self.rx_notifies += 1;
                    } else if value == 1 {
                        self.tx_notifies += 1;
                        if let Some(dma) = self.dma_ptr {
                            // Complete the latest TX descriptor synchronously in mock.
                            unsafe {
                                let avail_idx = (*dma.as_ptr()).tx_avail.avail_idx;
                                let used_idx = (*dma.as_ptr()).tx_used.used_idx;
                                let slot = usize::from(avail_idx.wrapping_sub(1)) & 7;
                                let desc_id = (*dma.as_ptr()).tx_avail.avail_ring[slot];
                                let len = (*dma.as_ptr()).tx_avail.desc[usize::from(desc_id)].len;
                                let u_slot = usize::from(used_idx) & 7;
                                (*dma.as_ptr()).tx_used.used_ring[u_slot] = VirtqUsedElem {
                                    id: u32::from(desc_id),
                                    len,
                                };
                                (*dma.as_ptr()).tx_used.used_idx = used_idx.wrapping_add(1);
                            }
                        }
                    }
                }
                REG_INTERRUPT_ACK => self.interrupt_status &= !value,
                REG_STATUS => self.status = value,
                _ => {}
            }
            Ok(())
        }

        fn read8(&self, offset: usize) -> Result<u8, VirtioError> {
            match offset {
                o if (REG_CONFIG_BASE..REG_CONFIG_BASE + 6).contains(&o) => {
                    Ok(self.mac[o - REG_CONFIG_BASE])
                }
                o if o == REG_CONFIG_BASE + 6 => Ok(VIRTIO_NET_S_LINK_UP as u8),
                o if o == REG_CONFIG_BASE + 7 => Ok(0),
                o if o == REG_CONFIG_BASE + 10 => Ok((NET_DEFAULT_MTU & 0xff) as u8),
                o if o == REG_CONFIG_BASE + 11 => Ok((NET_DEFAULT_MTU >> 8) as u8),
                _ => Err(VirtioError::MmioOutOfBounds),
            }
        }
    }

    #[test]
    fn virtio_net_mmio_init_tx_and_rx_replenish() {
        let mut dma = VirtioNetDmaBlock::<8, 2048>::zeroed();
        let dma_ptr = NonNull::from(&mut dma);
        let base_phys = dma_ptr.as_ptr() as u64;
        let grant = DmaBufferGrant {
            base_addr: base_phys,
            len: size_of::<VirtioNetDmaBlock<8, 2048>>() as u64,
            writable: true,
            dma_assigned: true,
            buffer_generation: 1,
            expected_generation: 1,
            revoked: false,
        };
        let mac = [0x52, 0x54, 0x00, 0xab, 0xcd, 0xef];
        let bus = MockNetMmioBus::new(mac, dma_ptr);
        let info = VirtioMmioInfo {
            region: MmioRegion {
                base: 0x0a00_0000,
                size: 0x200,
            },
            irq: 48,
            enabled: true,
        };

        let mut dev = unsafe { VirtioNetMmio::initialize(info, bus, dma_ptr, base_phys, grant) }
            .expect("virtio-net init");
        assert_eq!(dev.mac(), mac);
        assert_eq!(dev.mtu(), 1500);
        assert!(dev.link_up());
        assert_eq!(dev.hdr_bytes(), 12);

        let mut tx_frame = [0u8; 42];
        tx_frame[0..6].copy_from_slice(&[0xff; 6]);
        tx_frame[6..12].copy_from_slice(&mac);
        tx_frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        dev.send_frame(&tx_frame).expect("send ARP frame");

        // Inject one RX frame into slot 0 and mark used_idx = 1.
        unsafe {
            let rx_slot = &mut (*dma_ptr.as_ptr()).rx_slots[0];
            rx_slot[..12].fill(0);
            rx_slot[12..12 + 42].copy_from_slice(&tx_frame);
            (*dma_ptr.as_ptr()).rx_used.used_ring[0] = VirtqUsedElem {
                id: 0,
                len: (12 + 42) as u32,
            };
            (*dma_ptr.as_ptr()).rx_used.used_idx = 1;
        }
        let mut rx_out = [0u8; 64];
        let n = dev.recv_frame(&mut rx_out).expect("rx").expect("one frame");
        assert_eq!(n, 42);
        assert_eq!(&rx_out[..n], &tx_frame);
        // Descriptor 0 was immediately replenished into avail_idx 8 -> 9.
        assert_eq!(dev.rx_avail_idx, 9);
    }
}
