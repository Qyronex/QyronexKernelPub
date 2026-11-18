// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Hardware split-virtqueue VirtIO-MMIO Input driver (`virtio-input`).

use core::mem::{offset_of, size_of};
use core::ptr::{NonNull, read_volatile, write_bytes, write_volatile};

use kernal_fdt_aarch64::VirtioMmioInfo;

use crate::VirtioError;
use crate::blk_mmio::{VirtqAvailPage, VirtqUsedPage, dma_fence};
use crate::input::{
    ABS_X, ABS_Y, VIRTIO_INPUT_CFG_ABS_INFO, VIRTIO_INPUT_CFG_EV_BITS, VIRTIO_INPUT_CFG_ID_DEVIDS,
    VIRTIO_INPUT_CFG_ID_NAME, VIRTIO_INPUT_CFG_PROP_BITS, VIRTIO_INPUT_CFG_UNSET,
    VIRTIO_INPUT_EV_ABS, VIRTIO_INPUT_EV_KEY, VIRTIO_INPUT_EV_REL, VIRTIO_INPUT_EV_REP,
    VIRTIO_INPUT_EV_SYN, VIRTIO_INPUT_MAX_CFG_DATA, VirtioInputCaps, VirtioInputEvent,
    VirtioInputKind, decode_abs_info, decode_devids,
};
use crate::mmio::{
    MmioBus, REG_CONFIG_BASE, VIRTIO_F_VERSION_1, VirtioDeviceId, VirtioMmioTransport,
};
use crate::queue::{
    DmaBufferGrant, MAX_VIRTQ_SIZE, VRING_DESC_F_WRITE, VirtqDesc, VirtqUsedElem,
    validate_descriptor_chain,
};

pub const DEFAULT_INPUT_MMIO_QUEUE_SIZE: usize = 32;

const PAGE_BYTES: usize = 4096;

#[repr(C, align(4096))]
pub struct VirtioInputSlotsPage<const Q: usize> {
    pub events: [VirtioInputEvent; Q],
}

/// Page-aligned split-virtqueue + event buffer DMA block for one `virtio-input` device.
#[repr(C, align(4096))]
pub struct VirtioInputDmaBlock<const Q: usize = DEFAULT_INPUT_MMIO_QUEUE_SIZE> {
    pub event_avail: VirtqAvailPage<Q>,
    pub event_used: VirtqUsedPage<Q>,
    pub status_avail: VirtqAvailPage<Q>,
    pub status_used: VirtqUsedPage<Q>,
    pub event_slots: VirtioInputSlotsPage<Q>,
}

impl<const Q: usize> VirtioInputDmaBlock<Q> {
    pub const fn zeroed() -> Self {
        const EMPTY_DESC: VirtqDesc = VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        };
        const EMPTY_USED: VirtqUsedElem = VirtqUsedElem { id: 0, len: 0 };
        const EMPTY_EV: VirtioInputEvent = VirtioInputEvent {
            event_type: 0,
            code: 0,
            value: 0,
        };
        Self {
            event_avail: VirtqAvailPage {
                desc: [EMPTY_DESC; Q],
                avail_flags: 0,
                avail_idx: 0,
                avail_ring: [0; Q],
                avail_used_event: 0,
            },
            event_used: VirtqUsedPage {
                used_flags: 0,
                used_idx: 0,
                used_ring: [EMPTY_USED; Q],
                used_avail_event: 0,
            },
            status_avail: VirtqAvailPage {
                desc: [EMPTY_DESC; Q],
                avail_flags: 0,
                avail_idx: 0,
                avail_ring: [0; Q],
                avail_used_event: 0,
            },
            status_used: VirtqUsedPage {
                used_flags: 0,
                used_idx: 0,
                used_ring: [EMPTY_USED; Q],
                used_avail_event: 0,
            },
            event_slots: VirtioInputSlotsPage {
                events: [EMPTY_EV; Q],
            },
        }
    }
}

pub struct VirtioInputMmio<B, const Q: usize = DEFAULT_INPUT_MMIO_QUEUE_SIZE> {
    transport: VirtioMmioTransport,
    bus: B,
    dma_virt: NonNull<VirtioInputDmaBlock<Q>>,
    dma_grant: DmaBufferGrant,
    avail_idx: u16,
    last_used_idx: u16,
    caps: VirtioInputCaps,
    kind: VirtioInputKind,
}

// SAFETY: Access is serialized by callers under kernel locking.
unsafe impl<B: Send, const Q: usize> Send for VirtioInputMmio<B, Q> {}

impl<B: MmioBus, const Q: usize> VirtioInputMmio<B, Q> {
    /// Initializes a `virtio-input` MMIO device, queries its capability bitmaps, and pre-populates
    /// all `eventq` receive buffers.
    ///
    /// # Safety
    /// `dma_virt` must point to a valid, exclusively owned, 4 KiB-aligned
    /// [`VirtioInputDmaBlock<Q>`] mapped at `dma_phys` and covered by `dma_grant`.
    pub unsafe fn initialize(
        info: VirtioMmioInfo,
        mut bus: B,
        dma_virt: NonNull<VirtioInputDmaBlock<Q>>,
        dma_phys: u64,
        dma_grant: DmaBufferGrant,
    ) -> Result<Self, VirtioError> {
        if Q < 4
            || !Q.is_power_of_two()
            || Q > MAX_VIRTQ_SIZE
            || size_of::<VirtqAvailPage<Q>>() > PAGE_BYTES
            || size_of::<VirtqUsedPage<Q>>() > PAGE_BYTES
            || size_of::<VirtioInputSlotsPage<Q>>() > PAGE_BYTES
            || offset_of!(VirtioInputDmaBlock<Q>, event_used) != PAGE_BYTES
        {
            return Err(VirtioError::InvalidQueueSize);
        }
        dma_grant.validate_authority()?;
        let dma_size = u64::try_from(size_of::<VirtioInputDmaBlock<Q>>())
            .map_err(|_| VirtioError::DescriptorLengthOverflow)?;
        let grant_end = dma_grant
            .base_addr
            .checked_add(dma_grant.len)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let dma_end = dma_phys
            .checked_add(dma_size)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        if !dma_grant.writable || dma_phys < dma_grant.base_addr || dma_end > grant_end {
            return Err(VirtioError::DescriptorOutOfBounds);
        }

        let mut transport = VirtioMmioTransport::initialize(info, &mut bus, VIRTIO_F_VERSION_1)?;
        if transport.device_id != VirtioDeviceId::Input {
            return Err(VirtioError::UnsupportedDeviceId);
        }

        let caps = Self::probe_caps(&mut bus)?;
        let kind = caps.classify();

        // SAFETY: `dma_virt` is exclusively owned; initialize zeroed ring state.
        unsafe {
            write_bytes(dma_virt.as_ptr(), 0, 1);
        }
        dma_fence();

        let ev_desc_phys = dma_phys + offset_of!(VirtioInputDmaBlock<Q>, event_avail) as u64;
        let ev_avail_phys = ev_desc_phys + offset_of!(VirtqAvailPage<Q>, avail_flags) as u64;
        let ev_used_phys = dma_phys + offset_of!(VirtioInputDmaBlock<Q>, event_used) as u64;
        transport.setup_queue(
            &mut bus,
            0,
            Q as u16,
            ev_desc_phys,
            ev_avail_phys,
            ev_used_phys,
        )?;

        let st_desc_phys = dma_phys + offset_of!(VirtioInputDmaBlock<Q>, status_avail) as u64;
        let st_avail_phys = st_desc_phys + offset_of!(VirtqAvailPage<Q>, avail_flags) as u64;
        let st_used_phys = dma_phys + offset_of!(VirtioInputDmaBlock<Q>, status_used) as u64;
        let _ = transport.setup_queue(
            &mut bus,
            1,
            Q as u16,
            st_desc_phys,
            st_avail_phys,
            st_used_phys,
        );

        let slots_base = dma_phys + offset_of!(VirtioInputDmaBlock<Q>, event_slots) as u64;
        // Pre-post all `Q` 8-byte receive event descriptors into `eventq`.
        for idx in 0..Q {
            let slot_phys = slots_base + ((idx * size_of::<VirtioInputEvent>()) as u64);
            let desc = VirtqDesc {
                addr: slot_phys,
                len: size_of::<VirtioInputEvent>() as u32,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            };
            validate_descriptor_chain(1, &[desc], 0, Some(&dma_grant))?;
            // SAFETY: `idx < Q`, exclusive `dma_virt`.
            unsafe {
                let avail_ptr = &raw mut (*dma_virt.as_ptr()).event_avail;
                write_volatile(&raw mut (*avail_ptr).desc[idx], desc);
                write_volatile(&raw mut (*avail_ptr).avail_ring[idx], idx as u16);
            }
        }
        dma_fence();
        // SAFETY: `dma_virt` is exclusively owned.
        unsafe {
            write_volatile(
                &raw mut (*dma_virt.as_ptr()).event_avail.avail_idx,
                Q as u16,
            );
        }
        dma_fence();

        transport.mark_driver_ok(&mut bus)?;
        transport.notify_queue(&mut bus, 0)?;

        Ok(Self {
            transport,
            bus,
            dma_virt,
            dma_grant,
            avail_idx: Q as u16,
            last_used_idx: 0,
            caps,
            kind,
        })
    }

    fn query_config(
        bus: &mut B,
        select: u8,
        subsel: u8,
        out: &mut [u8],
    ) -> Result<usize, VirtioError> {
        let cmd = u32::from(select) | (u32::from(subsel) << 8);
        bus.write32(REG_CONFIG_BASE, cmd)?;
        dma_fence();
        let size = usize::from(bus.read8(REG_CONFIG_BASE + 2)?).min(VIRTIO_INPUT_MAX_CFG_DATA);
        let take = size.min(out.len());
        for (i, dst) in out[..take].iter_mut().enumerate() {
            *dst = bus.read8(REG_CONFIG_BASE + 8 + i)?;
        }
        let _ = bus.write32(REG_CONFIG_BASE, u32::from(VIRTIO_INPUT_CFG_UNSET));
        Ok(take)
    }

    fn probe_caps(bus: &mut B) -> Result<VirtioInputCaps, VirtioError> {
        let mut caps = VirtioInputCaps::empty();
        let mut buf = [0u8; 128];

        let n = Self::query_config(bus, VIRTIO_INPUT_CFG_ID_NAME, 0, &mut buf)?;
        let name_copy = n.min(caps.name.len());
        caps.name[..name_copy].copy_from_slice(&buf[..name_copy]);
        caps.name_len = name_copy;

        let n = Self::query_config(bus, VIRTIO_INPUT_CFG_ID_DEVIDS, 0, &mut buf)?;
        if let Ok(ids) = decode_devids(&buf[..n]) {
            caps.devids = ids;
        }

        let n = Self::query_config(bus, VIRTIO_INPUT_CFG_PROP_BITS, 0, &mut caps.prop_bits)?;
        if n == 0 {
            caps.prop_bits.fill(0);
        }

        // Probe EV_KEY / EV_REL / EV_ABS / EV_REP bitmasks.
        caps.ev_bits = 1 << VIRTIO_INPUT_EV_SYN;
        if Self::query_config(
            bus,
            VIRTIO_INPUT_CFG_EV_BITS,
            VIRTIO_INPUT_EV_KEY as u8,
            &mut caps.key_bits,
        )? > 0
        {
            caps.ev_bits |= 1 << VIRTIO_INPUT_EV_KEY;
        }
        if Self::query_config(
            bus,
            VIRTIO_INPUT_CFG_EV_BITS,
            VIRTIO_INPUT_EV_REL as u8,
            &mut caps.rel_bits,
        )? > 0
        {
            caps.ev_bits |= 1 << VIRTIO_INPUT_EV_REL;
        }
        if Self::query_config(
            bus,
            VIRTIO_INPUT_CFG_EV_BITS,
            VIRTIO_INPUT_EV_ABS as u8,
            &mut caps.abs_bits,
        )? > 0
        {
            caps.ev_bits |= 1 << VIRTIO_INPUT_EV_ABS;
            let n = Self::query_config(bus, VIRTIO_INPUT_CFG_ABS_INFO, ABS_X as u8, &mut buf)?;
            if let Ok(info) = decode_abs_info(&buf[..n]) {
                caps.abs_x = info;
            }
            let n = Self::query_config(bus, VIRTIO_INPUT_CFG_ABS_INFO, ABS_Y as u8, &mut buf)?;
            if let Ok(info) = decode_abs_info(&buf[..n]) {
                caps.abs_y = info;
            }
        }
        if Self::query_config(
            bus,
            VIRTIO_INPUT_CFG_EV_BITS,
            VIRTIO_INPUT_EV_REP as u8,
            &mut buf,
        )? > 0
        {
            caps.ev_bits |= 1 << VIRTIO_INPUT_EV_REP;
        }

        Ok(caps)
    }

    pub const fn caps(&self) -> &VirtioInputCaps {
        &self.caps
    }

    pub const fn kind(&self) -> VirtioInputKind {
        self.kind
    }

    pub const fn irq(&self) -> u32 {
        self.transport.irq
    }

    pub fn ack_interrupt(&mut self) -> Result<u32, VirtioError> {
        self.transport.ack_interrupt(&mut self.bus)
    }

    /// Returns the next completed input event from `eventq` and replenishes its descriptor.
    pub fn poll_event(&mut self) -> Result<Option<VirtioInputEvent>, VirtioError> {
        self.dma_grant.validate_authority()?;
        if !self.transport.driver_ok {
            return Err(VirtioError::DeviceFault);
        }
        dma_fence();
        // SAFETY: Volatile read of device-updated `used_idx`.
        let used_idx =
            unsafe { read_volatile(&raw const (*self.dma_virt.as_ptr()).event_used.used_idx) };
        if used_idx == self.last_used_idx {
            return Ok(None);
        }
        let ring_slot = (self.last_used_idx as usize) % Q;
        // SAFETY: `ring_slot < Q`; device has already written this used entry.
        let used_elem = unsafe {
            read_volatile(&raw const (*self.dma_virt.as_ptr()).event_used.used_ring[ring_slot])
        };
        let desc_id =
            usize::try_from(used_elem.id).map_err(|_| VirtioError::DescriptorOutOfBounds)?;
        if desc_id >= Q {
            return Err(VirtioError::DescriptorOutOfBounds);
        }
        // SAFETY: Device returned `desc_id` in used ring; read event then immediately repost.
        let ev = unsafe {
            let ev =
                read_volatile(&raw const (*self.dma_virt.as_ptr()).event_slots.events[desc_id]);
            let avail_ptr = &raw mut (*self.dma_virt.as_ptr()).event_avail;
            let avail_slot = (self.avail_idx as usize) % Q;
            write_volatile(&raw mut (*avail_ptr).avail_ring[avail_slot], desc_id as u16);
            dma_fence();
            self.avail_idx = self.avail_idx.wrapping_add(1);
            write_volatile(&raw mut (*avail_ptr).avail_idx, self.avail_idx);
            ev
        };
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        dma_fence();
        self.transport.notify_queue(&mut self.bus, 0)?;
        Ok(Some(ev))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{KEY_ENTER, VIRTIO_INPUT_EV_KEY};
    use crate::mmio::*;
    use core::cell::RefCell;
    use kernal_fdt_aarch64::MmioRegion;

    struct MockInputBus {
        regs: [u32; 128],
        cfg_bytes: [u8; 256],
        dma: *mut VirtioInputDmaBlock<32>,
    }

    impl MockInputBus {
        fn new_keyboard(dma: *mut VirtioInputDmaBlock<32>) -> RefCell<Self> {
            let mut regs = [0u32; 128];
            regs[REG_MAGIC_VALUE / 4] = VIRTIO_MMIO_MAGIC;
            regs[REG_VERSION / 4] = 2;
            regs[REG_DEVICE_ID / 4] = 18;
            regs[REG_VENDOR_ID / 4] = 0x554d_4551;
            regs[REG_QUEUE_NUM_MAX / 4] = 32;
            RefCell::new(Self {
                regs,
                cfg_bytes: [0; 256],
                dma,
            })
        }

        fn update_config_page(&mut self, select: u8, subsel: u8) {
            self.cfg_bytes.fill(0);
            self.cfg_bytes[0] = select;
            self.cfg_bytes[1] = subsel;
            match (select, subsel) {
                (VIRTIO_INPUT_CFG_ID_NAME, _) => {
                    let name = b"QEMU Virtio Keyboard";
                    self.cfg_bytes[2] = name.len() as u8;
                    self.cfg_bytes[8..8 + name.len()].copy_from_slice(name);
                }
                (VIRTIO_INPUT_CFG_ID_DEVIDS, _) => {
                    self.cfg_bytes[2] = 8;
                    self.cfg_bytes[8..10].copy_from_slice(&0x0006u16.to_le_bytes());
                    self.cfg_bytes[10..12].copy_from_slice(&0x0627u16.to_le_bytes());
                }
                (VIRTIO_INPUT_CFG_EV_BITS, t) if t == VIRTIO_INPUT_EV_KEY as u8 => {
                    self.cfg_bytes[2] = 32;
                    self.cfg_bytes[8 + (KEY_ENTER as usize) / 8] = 1 << ((KEY_ENTER as usize) % 8);
                }
                _ => {
                    self.cfg_bytes[2] = 0;
                }
            }
        }

        fn push_device_event(&mut self, ev: VirtioInputEvent) {
            // SAFETY: single-threaded unit test accesses `dma`.
            unsafe {
                let d = &mut *self.dma;
                let idx = (d.event_used.used_idx as usize) % 32;
                let desc_id = d.event_avail.avail_ring[idx] as usize;
                d.event_slots.events[desc_id] = ev;
                d.event_used.used_ring[idx] = VirtqUsedElem {
                    id: desc_id as u32,
                    len: 8,
                };
                d.event_used.used_idx = d.event_used.used_idx.wrapping_add(1);
            }
        }
    }

    struct SharedInputBus<'a>(&'a RefCell<MockInputBus>);

    impl MmioBus for SharedInputBus<'_> {
        fn region_size(&self) -> u64 {
            512
        }
        fn read32(&self, offset: usize) -> Result<u32, VirtioError> {
            let b = self.0.borrow();
            if offset == REG_DEVICE_FEATURES {
                let sel = b.regs[REG_DEVICE_FEATURES_SEL / 4];
                return Ok(if sel == 0 { 0 } else { 1 });
            }
            b.regs
                .get(offset / 4)
                .copied()
                .ok_or(VirtioError::MmioOutOfBounds)
        }
        fn write32(&mut self, offset: usize, value: u32) -> Result<(), VirtioError> {
            let mut b = self.0.borrow_mut();
            if offset == REG_CONFIG_BASE {
                let select = (value & 0xff) as u8;
                let subsel = ((value >> 8) & 0xff) as u8;
                b.update_config_page(select, subsel);
                return Ok(());
            }
            let slot = b
                .regs
                .get_mut(offset / 4)
                .ok_or(VirtioError::MmioOutOfBounds)?;
            *slot = value;
            if offset == REG_INTERRUPT_ACK {
                b.regs[REG_INTERRUPT_STATUS / 4] &= !value;
            }
            Ok(())
        }
        fn read8(&self, offset: usize) -> Result<u8, VirtioError> {
            let b = self.0.borrow();
            if offset >= REG_CONFIG_BASE && offset - REG_CONFIG_BASE < b.cfg_bytes.len() {
                return Ok(b.cfg_bytes[offset - REG_CONFIG_BASE]);
            }
            Err(VirtioError::MmioOutOfBounds)
        }
    }

    #[test]
    fn virtio_input_mmio_probes_caps_and_receives_events() {
        extern crate alloc;
        let mut dma = alloc::boxed::Box::new(VirtioInputDmaBlock::<32>::zeroed());
        let dma_ptr = &raw mut *dma;
        let dma_phys = dma_ptr as u64;
        let grant = DmaBufferGrant {
            base_addr: dma_phys,
            len: size_of::<VirtioInputDmaBlock<32>>() as u64,
            writable: true,
            dma_assigned: true,
            buffer_generation: 1,
            expected_generation: 1,
            revoked: false,
        };
        let bus_cell = MockInputBus::new_keyboard(dma_ptr);
        let info = VirtioMmioInfo {
            region: MmioRegion {
                base: 0x0a00_3c00,
                size: 0x200,
            },
            irq: 78,
            enabled: true,
        };
        let mut dev = unsafe {
            VirtioInputMmio::initialize(
                info,
                SharedInputBus(&bus_cell),
                NonNull::new(dma_ptr).unwrap(),
                dma_phys,
                grant,
            )
        }
        .unwrap();

        assert_eq!(dev.kind(), VirtioInputKind::Keyboard);
        assert_eq!(
            &dev.caps().name[..dev.caps().name_len],
            b"QEMU Virtio Keyboard"
        );
        assert_eq!(dev.poll_event().unwrap(), None);

        bus_cell.borrow_mut().push_device_event(VirtioInputEvent {
            event_type: VIRTIO_INPUT_EV_KEY,
            code: KEY_ENTER,
            value: 1,
        });
        assert_eq!(
            dev.poll_event().unwrap(),
            Some(VirtioInputEvent {
                event_type: VIRTIO_INPUT_EV_KEY,
                code: KEY_ENTER,
                value: 1,
            })
        );
        assert_eq!(dev.poll_event().unwrap(), None);
    }
}
