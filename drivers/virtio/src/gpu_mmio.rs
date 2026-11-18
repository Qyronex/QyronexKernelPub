// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Hardware split-virtqueue VirtIO-MMIO GPU 2D driver (`virtio-gpu`).

use core::hint::spin_loop;
use core::mem::{offset_of, size_of};
use core::ptr::{NonNull, copy_nonoverlapping, read_volatile, write_bytes, write_volatile};

use kernal_fdt_aarch64::VirtioMmioInfo;

use crate::VirtioError;
use crate::blk_mmio::{VRING_AVAIL_F_NO_INTERRUPT, VirtqAvailPage, VirtqUsedPage, dma_fence};
use crate::gpu::{
    VIRTIO_GPU_CMD_GET_DISPLAY_INFO, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
    VIRTIO_GPU_CMD_RESOURCE_FLUSH, VIRTIO_GPU_CMD_RESOURCE_UNREF, VIRTIO_GPU_CMD_SET_SCANOUT,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, VIRTIO_GPU_MAX_SCANOUTS, VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
    VIRTIO_GPU_RESP_OK_NODATA, VirtioGpuConfig, VirtioGpuCtrlHdr, VirtioGpuMemEntry, VirtioGpuRect,
    VirtioGpuResourceAttachBacking, VirtioGpuResourceCreate2d, VirtioGpuResourceDetachBacking,
    VirtioGpuResourceFlush, VirtioGpuResourceUnref, VirtioGpuRespDisplayInfo, VirtioGpuSetScanout,
    VirtioGpuTransferToHost2d, gpu_response_to_error, validate_create_2d, validate_mem_entries,
};
use crate::mmio::{
    MmioBus, REG_CONFIG_BASE, REG_CONFIG_GENERATION, VIRTIO_F_VERSION_1, VirtioDeviceId,
    VirtioMmioTransport,
};
use crate::queue::{
    DmaBufferGrant, MAX_VIRTQ_SIZE, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, VirtqDesc,
    VirtqUsedElem, validate_descriptor_chain,
};

pub const DEFAULT_GPU_MMIO_QUEUE_SIZE: usize = 16;
pub const DEFAULT_GPU_MMIO_REQ_BYTES: usize = 36864;

const PAGE_BYTES: usize = 4096;
const MAX_POLL_ITERS: u32 = 100_000_000;

/// Page-aligned split-virtqueue + command/response DMA memory block for one `virtio-gpu` device.
#[repr(C, align(4096))]
pub struct VirtioGpuDmaBlock<
    const Q: usize = DEFAULT_GPU_MMIO_QUEUE_SIZE,
    const REQ: usize = DEFAULT_GPU_MMIO_REQ_BYTES,
> {
    pub control_avail: VirtqAvailPage<Q>,
    pub control_used: VirtqUsedPage<Q>,
    pub cursor_avail: VirtqAvailPage<Q>,
    pub cursor_used: VirtqUsedPage<Q>,
    pub req_buf: [u8; REQ],
    pub resp_buf: [u8; PAGE_BYTES],
}

impl<const Q: usize, const REQ: usize> VirtioGpuDmaBlock<Q, REQ> {
    pub const fn zeroed() -> Self {
        const EMPTY_DESC: VirtqDesc = VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        };
        const EMPTY_USED: VirtqUsedElem = VirtqUsedElem { id: 0, len: 0 };
        Self {
            control_avail: VirtqAvailPage {
                desc: [EMPTY_DESC; Q],
                avail_flags: 0,
                avail_idx: 0,
                avail_ring: [0; Q],
                avail_used_event: 0,
            },
            control_used: VirtqUsedPage {
                used_flags: 0,
                used_idx: 0,
                used_ring: [EMPTY_USED; Q],
                used_avail_event: 0,
            },
            cursor_avail: VirtqAvailPage {
                desc: [EMPTY_DESC; Q],
                avail_flags: 0,
                avail_idx: 0,
                avail_ring: [0; Q],
                avail_used_event: 0,
            },
            cursor_used: VirtqUsedPage {
                used_flags: 0,
                used_idx: 0,
                used_ring: [EMPTY_USED; Q],
                used_avail_event: 0,
            },
            req_buf: [0; REQ],
            resp_buf: [0; PAGE_BYTES],
        }
    }
}

pub struct VirtioGpuMmio<
    B,
    const Q: usize = DEFAULT_GPU_MMIO_QUEUE_SIZE,
    const REQ: usize = DEFAULT_GPU_MMIO_REQ_BYTES,
> {
    transport: VirtioMmioTransport,
    bus: B,
    dma_virt: NonNull<VirtioGpuDmaBlock<Q, REQ>>,
    dma_phys: u64,
    dma_grant: DmaBufferGrant,
    avail_idx: u16,
    last_used_idx: u16,
    config: VirtioGpuConfig,
}

// SAFETY: Access is serialized by callers under kernel locking.
unsafe impl<B: Send, const Q: usize, const REQ: usize> Send for VirtioGpuMmio<B, Q, REQ> {}

impl<B: MmioBus, const Q: usize, const REQ: usize> VirtioGpuMmio<B, Q, REQ> {
    /// Initializes a `virtio-gpu` MMIO controller on `bus` using caller-owned DMA memory.
    ///
    /// # Safety
    /// `dma_virt` must point to a valid, exclusively owned, 4 KiB-aligned
    /// [`VirtioGpuDmaBlock<Q, REQ>`] mapped at `dma_phys` and covered by `dma_grant`.
    pub unsafe fn initialize(
        info: VirtioMmioInfo,
        mut bus: B,
        dma_virt: NonNull<VirtioGpuDmaBlock<Q, REQ>>,
        dma_phys: u64,
        dma_grant: DmaBufferGrant,
    ) -> Result<Self, VirtioError> {
        if Q < 4
            || !Q.is_power_of_two()
            || Q > MAX_VIRTQ_SIZE
            || size_of::<VirtqAvailPage<Q>>() > PAGE_BYTES
            || size_of::<VirtqUsedPage<Q>>() > PAGE_BYTES
            || offset_of!(VirtioGpuDmaBlock<Q, REQ>, control_used) != PAGE_BYTES
            || REQ < size_of::<VirtioGpuTransferToHost2d>()
        {
            return Err(VirtioError::InvalidQueueSize);
        }
        dma_grant.validate_authority()?;
        let dma_size = u64::try_from(size_of::<VirtioGpuDmaBlock<Q, REQ>>())
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
        if transport.device_id != VirtioDeviceId::Gpu {
            return Err(VirtioError::UnsupportedDeviceId);
        }

        // SAFETY: `dma_virt` is exclusively owned and valid for `size_of::<VirtioGpuDmaBlock>()`.
        unsafe {
            write_bytes(dma_virt.as_ptr(), 0, 1);
            (&raw mut (*dma_virt.as_ptr()).control_avail.avail_flags)
                .write_volatile(VRING_AVAIL_F_NO_INTERRUPT);
            (&raw mut (*dma_virt.as_ptr()).cursor_avail.avail_flags)
                .write_volatile(VRING_AVAIL_F_NO_INTERRUPT);
        }
        dma_fence();

        let ctrl_desc_phys = dma_phys + offset_of!(VirtioGpuDmaBlock<Q, REQ>, control_avail) as u64;
        let ctrl_avail_phys = ctrl_desc_phys + offset_of!(VirtqAvailPage<Q>, avail_flags) as u64;
        let ctrl_used_phys = dma_phys + offset_of!(VirtioGpuDmaBlock<Q, REQ>, control_used) as u64;
        transport.setup_queue(
            &mut bus,
            0,
            Q as u16,
            ctrl_desc_phys,
            ctrl_avail_phys,
            ctrl_used_phys,
        )?;

        let cur_desc_phys = dma_phys + offset_of!(VirtioGpuDmaBlock<Q, REQ>, cursor_avail) as u64;
        let cur_avail_phys = cur_desc_phys + offset_of!(VirtqAvailPage<Q>, avail_flags) as u64;
        let cur_used_phys = dma_phys + offset_of!(VirtioGpuDmaBlock<Q, REQ>, cursor_used) as u64;
        let _ = transport.setup_queue(
            &mut bus,
            1,
            Q as u16,
            cur_desc_phys,
            cur_avail_phys,
            cur_used_phys,
        );

        let config = Self::read_config_from(&bus)?;
        transport.mark_driver_ok(&mut bus)?;

        Ok(Self {
            transport,
            bus,
            dma_virt,
            dma_phys,
            dma_grant,
            avail_idx: 0,
            last_used_idx: 0,
            config,
        })
    }

    fn read_config_from(bus: &B) -> Result<VirtioGpuConfig, VirtioError> {
        for _ in 0..8 {
            let gen_before = bus.read32(REG_CONFIG_GENERATION)?;
            let events_read = bus.read32(REG_CONFIG_BASE)?;
            let events_clear = bus.read32(REG_CONFIG_BASE + 0x04)?;
            let num_scanouts = bus.read32(REG_CONFIG_BASE + 0x08)?;
            let num_capsets = bus.read32(REG_CONFIG_BASE + 0x0c)?;
            let gen_after = bus.read32(REG_CONFIG_GENERATION)?;
            if gen_before == gen_after {
                return Ok(VirtioGpuConfig {
                    events_read,
                    events_clear,
                    num_scanouts,
                    num_capsets,
                });
            }
        }
        Err(VirtioError::DeviceFault)
    }

    pub const fn config(&self) -> VirtioGpuConfig {
        self.config
    }

    pub fn ack_interrupt(&mut self) -> Result<u32, VirtioError> {
        self.transport.ack_interrupt(&mut self.bus)
    }

    pub fn get_display_info(&mut self) -> Result<VirtioGpuRespDisplayInfo, VirtioError> {
        let req = VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
        // SAFETY: `VirtioGpuCtrlHdr` is a `#[repr(C)]` plain struct with no padding invariants.
        let req_bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const req).cast::<u8>(),
                size_of::<VirtioGpuCtrlHdr>(),
            )
        };
        let resp_bytes = self.execute_cmd(
            req_bytes,
            size_of::<VirtioGpuRespDisplayInfo>(),
            VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
        )?;
        let mut resp = VirtioGpuRespDisplayInfo {
            hdr: VirtioGpuCtrlHdr::default(),
            pmodes: [Default::default(); VIRTIO_GPU_MAX_SCANOUTS],
        };
        // SAFETY: `resp_bytes.len() == size_of::<VirtioGpuRespDisplayInfo>()`, reading into
        // unaliased stack struct.
        unsafe {
            copy_nonoverlapping(
                resp_bytes.as_ptr(),
                (&raw mut resp).cast::<u8>(),
                size_of::<VirtioGpuRespDisplayInfo>(),
            );
        }
        Ok(resp)
    }

    pub fn create_resource_2d(
        &mut self,
        resource_id: u32,
        format: u32,
        width: u32,
        height: u32,
    ) -> Result<(), VirtioError> {
        validate_create_2d(resource_id, format, width, height)?;
        let req = VirtioGpuResourceCreate2d {
            hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_RESOURCE_CREATE_2D),
            resource_id,
            format,
            width,
            height,
        };
        self.execute_nodata_struct(&req)
    }

    pub fn attach_backing(
        &mut self,
        resource_id: u32,
        entries: &[VirtioGpuMemEntry],
    ) -> Result<(), VirtioError> {
        if resource_id == 0 {
            return Err(VirtioError::OutOfRange);
        }
        validate_mem_entries(entries)?;
        let hdr = VirtioGpuResourceAttachBacking {
            hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING),
            resource_id,
            nr_entries: u32::try_from(entries.len())
                .map_err(|_| VirtioError::DescriptorLengthOverflow)?,
        };
        let hdr_len = size_of::<VirtioGpuResourceAttachBacking>();
        let entries_len = entries
            .len()
            .checked_mul(size_of::<VirtioGpuMemEntry>())
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let total_len = hdr_len
            .checked_add(entries_len)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        if total_len > REQ {
            return Err(VirtioError::BufferTooSmall);
        }

        // Write header + entries contiguously into `req_buf`.
        // SAFETY: `total_len <= REQ` checked above; `self` owns `dma_virt` exclusively.
        unsafe {
            let dst = (&raw mut (*self.dma_virt.as_ptr()).req_buf).cast::<u8>();
            copy_nonoverlapping((&raw const hdr).cast::<u8>(), dst, hdr_len);
            copy_nonoverlapping(entries.as_ptr().cast::<u8>(), dst.add(hdr_len), entries_len);
        }
        self.submit_prepared_cmd(
            total_len,
            size_of::<VirtioGpuCtrlHdr>(),
            VIRTIO_GPU_RESP_OK_NODATA,
        )?;
        Ok(())
    }

    pub fn detach_backing(&mut self, resource_id: u32) -> Result<(), VirtioError> {
        if resource_id == 0 {
            return Err(VirtioError::OutOfRange);
        }
        let req = VirtioGpuResourceDetachBacking {
            hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING),
            resource_id,
            padding: 0,
        };
        self.execute_nodata_struct(&req)
    }

    pub fn set_scanout(
        &mut self,
        scanout_id: u32,
        resource_id: u32,
        rect: VirtioGpuRect,
    ) -> Result<(), VirtioError> {
        if scanout_id as usize >= VIRTIO_GPU_MAX_SCANOUTS {
            return Err(VirtioError::OutOfRange);
        }
        let req = VirtioGpuSetScanout {
            hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_SET_SCANOUT),
            r: rect,
            scanout_id,
            resource_id,
        };
        self.execute_nodata_struct(&req)
    }

    pub fn transfer_to_host_2d(
        &mut self,
        resource_id: u32,
        rect: VirtioGpuRect,
        offset: u64,
    ) -> Result<(), VirtioError> {
        if resource_id == 0 || rect.width == 0 || rect.height == 0 {
            return Err(VirtioError::OutOfRange);
        }
        let req = VirtioGpuTransferToHost2d {
            hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D),
            r: rect,
            offset,
            resource_id,
            padding: 0,
        };
        self.execute_nodata_struct(&req)
    }

    pub fn resource_flush(
        &mut self,
        resource_id: u32,
        rect: VirtioGpuRect,
    ) -> Result<(), VirtioError> {
        if resource_id == 0 || rect.width == 0 || rect.height == 0 {
            return Err(VirtioError::OutOfRange);
        }
        let req = VirtioGpuResourceFlush {
            hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_RESOURCE_FLUSH),
            r: rect,
            resource_id,
            padding: 0,
        };
        self.execute_nodata_struct(&req)
    }

    pub fn unref_resource(&mut self, resource_id: u32) -> Result<(), VirtioError> {
        if resource_id == 0 {
            return Err(VirtioError::OutOfRange);
        }
        let req = VirtioGpuResourceUnref {
            hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_RESOURCE_UNREF),
            resource_id,
            padding: 0,
        };
        self.execute_nodata_struct(&req)
    }

    fn execute_nodata_struct<T: Copy>(&mut self, req: &T) -> Result<(), VirtioError> {
        // SAFETY: Callers only pass `#[repr(C)]` POD command structs without padding UB.
        let bytes =
            unsafe { core::slice::from_raw_parts((req as *const T).cast::<u8>(), size_of::<T>()) };
        let _ = self.execute_cmd(
            bytes,
            size_of::<VirtioGpuCtrlHdr>(),
            VIRTIO_GPU_RESP_OK_NODATA,
        )?;
        Ok(())
    }

    fn execute_cmd(
        &mut self,
        req_bytes: &[u8],
        resp_len: usize,
        expected_resp: u32,
    ) -> Result<&[u8], VirtioError> {
        if req_bytes.is_empty() || req_bytes.len() > REQ {
            return Err(VirtioError::BufferTooSmall);
        }
        // SAFETY: `req_bytes.len() <= REQ`; exclusive access via `&mut self`.
        unsafe {
            let dst = (&raw mut (*self.dma_virt.as_ptr()).req_buf).cast::<u8>();
            copy_nonoverlapping(req_bytes.as_ptr(), dst, req_bytes.len());
        }
        self.submit_prepared_cmd(req_bytes.len(), resp_len, expected_resp)
    }

    fn submit_prepared_cmd(
        &mut self,
        req_len: usize,
        resp_len: usize,
        expected_resp: u32,
    ) -> Result<&[u8], VirtioError> {
        self.dma_grant.validate_authority()?;
        if !self.transport.driver_ok {
            return Err(VirtioError::DeviceFault);
        }
        if req_len == 0
            || req_len > REQ
            || resp_len < size_of::<VirtioGpuCtrlHdr>()
            || resp_len > PAGE_BYTES
        {
            return Err(VirtioError::BufferTooSmall);
        }

        let req_phys = self.dma_phys + offset_of!(VirtioGpuDmaBlock<Q, REQ>, req_buf) as u64;
        let resp_phys = self.dma_phys + offset_of!(VirtioGpuDmaBlock<Q, REQ>, resp_buf) as u64;

        let descs = [
            VirtqDesc {
                addr: req_phys,
                len: req_len as u32,
                flags: VRING_DESC_F_NEXT,
                next: 1,
            },
            VirtqDesc {
                addr: resp_phys,
                len: resp_len as u32,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            },
        ];

        validate_descriptor_chain(Q, &descs, 0, Some(&self.dma_grant))?;

        // SAFETY: Exclusive access to `dma_virt`; `resp_len <= PAGE_BYTES`.
        unsafe {
            let resp_mut = (&raw mut (*self.dma_virt.as_ptr()).resp_buf).cast::<u8>();
            write_bytes(resp_mut, 0, resp_len);
            let avail_ptr = &raw mut (*self.dma_virt.as_ptr()).control_avail;
            write_volatile(&raw mut (*avail_ptr).desc[0], descs[0]);
            write_volatile(&raw mut (*avail_ptr).desc[1], descs[1]);
            let slot = (self.avail_idx as usize) % Q;
            write_volatile(&raw mut (*avail_ptr).avail_ring[slot], 0);
            dma_fence();
            self.avail_idx = self.avail_idx.wrapping_add(1);
            write_volatile(&raw mut (*avail_ptr).avail_idx, self.avail_idx);
        }
        dma_fence();
        self.transport.notify_queue(&mut self.bus, 0)?;

        for _ in 0..MAX_POLL_ITERS {
            dma_fence();
            // SAFETY: Volatile read of device-written used index.
            let used_idx = unsafe {
                read_volatile(&raw const (*self.dma_virt.as_ptr()).control_used.used_idx)
            };
            if used_idx != self.last_used_idx {
                self.last_used_idx = used_idx;
                let _ = self.ack_interrupt();
                let mut hdr = VirtioGpuCtrlHdr::default();
                // SAFETY: Device completed command; read header and return slice of `resp_buf`.
                unsafe {
                    let resp_ptr = (&raw const (*self.dma_virt.as_ptr()).resp_buf).cast::<u8>();
                    copy_nonoverlapping(
                        resp_ptr,
                        (&raw mut hdr).cast::<u8>(),
                        size_of::<VirtioGpuCtrlHdr>(),
                    );
                    gpu_response_to_error(hdr.cmd_type, expected_resp)?;
                    return Ok(core::slice::from_raw_parts(resp_ptr, resp_len));
                }
            }
            spin_loop();
        }
        Err(VirtioError::DeviceFault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::{VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM, VirtioGpuDisplayOne};
    use crate::mmio::*;
    use core::cell::RefCell;
    use kernal_fdt_aarch64::MmioRegion;

    struct MockGpuBus {
        regs: [u32; 128],
        dma: *mut VirtioGpuDmaBlock<16, 36864>,
        last_cmd: u32,
        last_resource_id: u32,
        last_nr_entries: u32,
        last_flush_rect: VirtioGpuRect,
        display_w: u32,
        display_h: u32,
    }

    impl MockGpuBus {
        fn new(dma: *mut VirtioGpuDmaBlock<16, 36864>, w: u32, h: u32) -> RefCell<Self> {
            let mut regs = [0u32; 128];
            regs[REG_MAGIC_VALUE / 4] = VIRTIO_MMIO_MAGIC;
            regs[REG_VERSION / 4] = 2;
            regs[REG_DEVICE_ID / 4] = 16;
            regs[REG_VENDOR_ID / 4] = 0x554d_4551;
            regs[REG_QUEUE_NUM_MAX / 4] = 16;
            regs[REG_CONFIG_BASE / 4 + 2] = 1; // num_scanouts = 1
            RefCell::new(Self {
                regs,
                dma,
                last_cmd: 0,
                last_resource_id: 0,
                last_nr_entries: 0,
                last_flush_rect: VirtioGpuRect::default(),
                display_w: w,
                display_h: h,
            })
        }

        fn process_controlq(&mut self) {
            // SAFETY: Single-threaded host unit test owns `dma` uniquely.
            unsafe {
                let d = &mut *self.dma;
                let cmd = u32::from_le_bytes(d.req_buf[0..4].try_into().unwrap());
                self.last_cmd = cmd;
                let mut hdr = VirtioGpuCtrlHdr::new(VIRTIO_GPU_RESP_OK_NODATA);
                match cmd {
                    VIRTIO_GPU_CMD_GET_DISPLAY_INFO => {
                        hdr.cmd_type = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;
                        let mut info = VirtioGpuRespDisplayInfo {
                            hdr,
                            pmodes: [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS],
                        };
                        info.pmodes[0] = VirtioGpuDisplayOne {
                            r: VirtioGpuRect::new(0, 0, self.display_w, self.display_h),
                            enabled: 1,
                            flags: 0,
                        };
                        copy_nonoverlapping(
                            (&raw const info).cast::<u8>(),
                            d.resp_buf.as_mut_ptr(),
                            size_of::<VirtioGpuRespDisplayInfo>(),
                        );
                    }
                    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D => {
                        let req = *(d.req_buf.as_ptr().cast::<VirtioGpuResourceCreate2d>());
                        self.last_resource_id = req.resource_id;
                        copy_nonoverlapping(
                            (&raw const hdr).cast::<u8>(),
                            d.resp_buf.as_mut_ptr(),
                            size_of::<VirtioGpuCtrlHdr>(),
                        );
                    }
                    VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING => {
                        let req = *(d.req_buf.as_ptr().cast::<VirtioGpuResourceAttachBacking>());
                        self.last_resource_id = req.resource_id;
                        self.last_nr_entries = req.nr_entries;
                        copy_nonoverlapping(
                            (&raw const hdr).cast::<u8>(),
                            d.resp_buf.as_mut_ptr(),
                            size_of::<VirtioGpuCtrlHdr>(),
                        );
                    }
                    VIRTIO_GPU_CMD_RESOURCE_FLUSH => {
                        let req = *(d.req_buf.as_ptr().cast::<VirtioGpuResourceFlush>());
                        self.last_flush_rect = req.r;
                        copy_nonoverlapping(
                            (&raw const hdr).cast::<u8>(),
                            d.resp_buf.as_mut_ptr(),
                            size_of::<VirtioGpuCtrlHdr>(),
                        );
                    }
                    _ => {
                        copy_nonoverlapping(
                            (&raw const hdr).cast::<u8>(),
                            d.resp_buf.as_mut_ptr(),
                            size_of::<VirtioGpuCtrlHdr>(),
                        );
                    }
                }
                let u_idx = d.control_used.used_idx;
                d.control_used.used_ring[(u_idx as usize) % 16] = VirtqUsedElem { id: 0, len: 24 };
                d.control_used.used_idx = u_idx.wrapping_add(1);
                self.regs[REG_INTERRUPT_STATUS / 4] |= 1;
            }
        }
    }

    struct SharedGpuBus<'a>(&'a RefCell<MockGpuBus>);

    impl MmioBus for SharedGpuBus<'_> {
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
            let slot = b
                .regs
                .get_mut(offset / 4)
                .ok_or(VirtioError::MmioOutOfBounds)?;
            *slot = value;
            if offset == REG_INTERRUPT_ACK {
                b.regs[REG_INTERRUPT_STATUS / 4] &= !value;
            }
            if offset == REG_QUEUE_NOTIFY && value == 0 {
                b.process_controlq();
            }
            Ok(())
        }
        fn read8(&self, offset: usize) -> Result<u8, VirtioError> {
            let w = self.read32(offset & !3)?;
            Ok(((w >> ((offset & 3) * 8)) & 0xff) as u8)
        }
    }

    #[test]
    fn virtio_gpu_mmio_2d_scanout_lifecycle_succeeds() {
        extern crate alloc;
        let mut dma = alloc::boxed::Box::new(VirtioGpuDmaBlock::<16, 36864>::zeroed());
        let dma_ptr = (&raw mut *dma);
        let dma_phys = dma_ptr as u64;
        let grant = DmaBufferGrant {
            base_addr: dma_phys,
            len: size_of::<VirtioGpuDmaBlock<16, 36864>>() as u64,
            writable: true,
            dma_assigned: true,
            buffer_generation: 1,
            expected_generation: 1,
            revoked: false,
        };
        let bus_cell = MockGpuBus::new(dma_ptr, 1280, 800);
        let info = VirtioMmioInfo {
            region: MmioRegion {
                base: 0x0a00_3e00,
                size: 0x200,
            },
            irq: 79,
            enabled: true,
        };
        let mut gpu = unsafe {
            VirtioGpuMmio::initialize(
                info,
                SharedGpuBus(&bus_cell),
                NonNull::new(dma_ptr).unwrap(),
                dma_phys,
                grant,
            )
        }
        .unwrap();
        assert_eq!(gpu.config().num_scanouts, 1);

        let dpy = gpu.get_display_info().unwrap();
        assert_eq!(dpy.pmodes[0].enabled, 1);
        assert_eq!(dpy.pmodes[0].r, VirtioGpuRect::new(0, 0, 1280, 800));

        gpu.create_resource_2d(1, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM, 1280, 800)
            .unwrap();
        let backing = [
            VirtioGpuMemEntry {
                addr: 0x4100_0000,
                length: 4096,
                padding: 0,
            },
            VirtioGpuMemEntry {
                addr: 0x4100_1000,
                length: 4096,
                padding: 0,
            },
        ];
        gpu.attach_backing(1, &backing).unwrap();
        assert_eq!(bus_cell.borrow().last_nr_entries, 2);

        let full = VirtioGpuRect::new(0, 0, 1280, 800);
        gpu.set_scanout(0, 1, full).unwrap();
        gpu.transfer_to_host_2d(1, full, 0).unwrap();
        gpu.resource_flush(1, VirtioGpuRect::new(10, 20, 300, 200))
            .unwrap();
        assert_eq!(
            bus_cell.borrow().last_flush_rect,
            VirtioGpuRect::new(10, 20, 300, 200)
        );
        gpu.detach_backing(1).unwrap();
        gpu.unref_resource(1).unwrap();
    }
}
