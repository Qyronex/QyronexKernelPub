// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Hardware split-virtqueue VirtIO-MMIO block device driver (`virtio-blk`).
//!
//! Works over any [`MmioBus`] (including [`crate::VolatileMmioBus`] mapped into TTBR1 Device
//! memory on AArch64 and mock buses in host tests) with an explicit caller-owned static DMA block
//! (`VirtioBlkDmaBlock`) validated by [`DmaBufferGrant`] and [`validate_blk_request`] on every
//! request. Both VirtIO 1.x (`version == 2`) and legacy (`version == 1`) MMIO transports are
//! supported because `queue_front` (descriptors + avail) and `queue_used` occupy adjacent 4 KiB
//! pages.

use core::hint::spin_loop;
use core::mem::{offset_of, size_of};
use core::ptr::{NonNull, copy_nonoverlapping, read_volatile, write_bytes, write_volatile};

use kernal_fdt_aarch64::VirtioMmioInfo;

use crate::VirtioError;
use crate::blk::{
    SECTOR_SIZE, SUPPORTED_BLK_FEATURES, VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_FLUSH,
    VIRTIO_BLK_F_RO, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP, VirtioBlkOp,
    VirtioBlkReqHeader, validate_blk_request,
};
use crate::mmio::{
    MmioBus, REG_CONFIG_BASE, REG_CONFIG_GENERATION, VIRTIO_F_VERSION_1, VirtioDeviceId,
    VirtioMmioTransport,
};
use crate::queue::{
    DmaBufferGrant, MAX_VIRTQ_SIZE, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, VirtqDesc, VirtqUsedElem,
};

pub const DEFAULT_BLK_MMIO_QUEUE_SIZE: usize = 16;
pub const DEFAULT_BLK_MMIO_DMA_BYTES: usize = 65536;

const PAGE_BYTES: usize = 4096;
const MAX_POLL_ITERS: u32 = 100_000_000;
const STATUS_SENTINEL: u8 = 0xff;
pub(crate) const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;

#[inline(always)]
pub(crate) fn dma_fence() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: DSB SY ensures descriptors, avail ring, and DMA data reach device-observable coherent
    // memory prior to doorbell writes, and used-ring/payload reads follow device completion writes.
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

#[repr(C, align(4096))]
pub struct VirtqAvailPage<const Q: usize> {
    pub desc: [VirtqDesc; Q],
    pub avail_flags: u16,
    pub avail_idx: u16,
    pub avail_ring: [u16; Q],
    pub avail_used_event: u16,
}

#[repr(C, align(4096))]
pub struct VirtqUsedPage<const Q: usize> {
    pub used_flags: u16,
    pub used_idx: u16,
    pub used_ring: [VirtqUsedElem; Q],
    pub used_avail_event: u16,
}

#[repr(C, align(4096))]
pub struct VirtioBlkReqPage {
    pub header: VirtioBlkReqHeader,
    pub status: u8,
}

/// Page-aligned split-virtqueue + request/bounce DMA memory block for one `virtio-blk` controller.
///
/// Layout invariants verified at runtime during initialization:
/// - Offset `0`: descriptor table (`Q * 16` bytes) immediately followed by avail ring (fits in page 0).
/// - Offset `4096`: used ring (`VirtqUsedPage<Q>`), matching VirtIO-MMIO v1 (`REG_QUEUE_ALIGN=4096`)
///   and v2 (`REG_QUEUE_USED_*`) simultaneously.
/// - Offset `8192`: 16-byte `VirtioBlkReqHeader` + 1-byte status trailer.
/// - Offset `12288`: contiguous `BUF`-byte DMA bounce buffer.
#[repr(C, align(4096))]
pub struct VirtioBlkDmaBlock<
    const Q: usize = DEFAULT_BLK_MMIO_QUEUE_SIZE,
    const BUF: usize = DEFAULT_BLK_MMIO_DMA_BYTES,
> {
    pub queue_front: VirtqAvailPage<Q>,
    pub queue_used: VirtqUsedPage<Q>,
    pub req: VirtioBlkReqPage,
    pub data: [u8; BUF],
}

impl<const Q: usize, const BUF: usize> VirtioBlkDmaBlock<Q, BUF> {
    pub const fn zeroed() -> Self {
        Self {
            queue_front: VirtqAvailPage {
                desc: [VirtqDesc {
                    addr: 0,
                    len: 0,
                    flags: 0,
                    next: 0,
                }; Q],
                avail_flags: 0,
                avail_idx: 0,
                avail_ring: [0; Q],
                avail_used_event: 0,
            },
            queue_used: VirtqUsedPage {
                used_flags: 0,
                used_idx: 0,
                used_ring: [VirtqUsedElem { id: 0, len: 0 }; Q],
                used_avail_event: 0,
            },
            req: VirtioBlkReqPage {
                header: VirtioBlkReqHeader {
                    req_type: 0,
                    reserved: 0,
                    sector: 0,
                },
                status: 0,
            },
            data: [0; BUF],
        }
    }
}

pub struct VirtioBlkMmio<
    B,
    const Q: usize = DEFAULT_BLK_MMIO_QUEUE_SIZE,
    const BUF: usize = DEFAULT_BLK_MMIO_DMA_BYTES,
> {
    bus: B,
    transport: VirtioMmioTransport,
    capacity_sectors: u64,
    blk_size: u32,
    dma_virt: NonNull<VirtioBlkDmaBlock<Q, BUF>>,
    dma_phys_base: u64,
    grant: DmaBufferGrant,
    avail_idx: u16,
    last_used_idx: u16,
    revoked: bool,
}

// SAFETY: `VirtioBlkMmio` exclusively owns its MMIO bus and `dma_virt` DMA region, so moving it
// behind a kernel synchronization wrapper across PEs is sound.
unsafe impl<B: Send, const Q: usize, const BUF: usize> Send for VirtioBlkMmio<B, Q, BUF> {}

impl<B: MmioBus, const Q: usize, const BUF: usize> VirtioBlkMmio<B, Q, BUF> {
    /// Initializes a VirtIO-MMIO block device on `bus` backed by `dma_virt` (`dma_phys_base`).
    ///
    /// # Safety
    /// - `dma_virt` must point to a valid, exclusively owned, 4 KiB-aligned `VirtioBlkDmaBlock`
    ///   that remains live and unmoved for the lifetime of the returned driver.
    /// - `dma_phys_base` must be the exact physical address backing `dma_virt` for at least
    ///   `size_of::<VirtioBlkDmaBlock<Q, BUF>>()` contiguous physical bytes, covered by `grant`.
    pub unsafe fn initialize(
        info: VirtioMmioInfo,
        mut bus: B,
        dma_virt: NonNull<VirtioBlkDmaBlock<Q, BUF>>,
        dma_phys_base: u64,
        grant: DmaBufferGrant,
    ) -> Result<Self, VirtioError> {
        if !(4..=MAX_VIRTQ_SIZE).contains(&Q) || !Q.is_power_of_two() || Q > 128 {
            return Err(VirtioError::InvalidQueueSize);
        }
        if BUF < SECTOR_SIZE || !BUF.is_multiple_of(SECTOR_SIZE) {
            return Err(VirtioError::BufferTooSmall);
        }
        if offset_of!(VirtioBlkDmaBlock<Q, BUF>, queue_used) != PAGE_BYTES
            || offset_of!(VirtioBlkDmaBlock<Q, BUF>, req) != PAGE_BYTES * 2
        {
            return Err(VirtioError::InvalidQueueSize);
        }
        if !dma_phys_base.is_multiple_of(PAGE_BYTES as u64)
            || !(dma_virt.as_ptr() as usize).is_multiple_of(PAGE_BYTES)
        {
            return Err(VirtioError::DescriptorOutOfBounds);
        }

        let dma_bytes = u64::try_from(size_of::<VirtioBlkDmaBlock<Q, BUF>>())
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
        if probe.device_id != VirtioDeviceId::Blk {
            return Err(VirtioError::UnsupportedDeviceId);
        }

        let supported = if probe.version >= 2 {
            SUPPORTED_BLK_FEATURES
        } else {
            SUPPORTED_BLK_FEATURES & !VIRTIO_F_VERSION_1
        };
        let mut transport = VirtioMmioTransport::initialize(info, &mut bus, supported)?;

        // SAFETY: `dma_virt` is exclusively owned, writable, aligned, and covers `VirtioBlkDmaBlock`.
        unsafe {
            write_bytes(dma_virt.as_ptr(), 0, 1);
            write_volatile(
                &raw mut (*dma_virt.as_ptr()).queue_front.avail_flags,
                VRING_AVAIL_F_NO_INTERRUPT,
            );
        }
        dma_fence();

        let desc_phys = dma_phys_base;
        let avail_phys = dma_phys_base
            .checked_add(offset_of!(VirtqAvailPage<Q>, avail_flags) as u64)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let used_phys = dma_phys_base
            .checked_add(offset_of!(VirtioBlkDmaBlock<Q, BUF>, queue_used) as u64)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;

        transport.setup_queue(&mut bus, 0, Q as u16, desc_phys, avail_phys, used_phys)?;
        transport.mark_driver_ok(&mut bus)?;

        let (capacity_sectors, blk_size) = Self::read_blk_config(&bus, &transport)?;
        if capacity_sectors == 0 {
            return Err(VirtioError::DeviceFault);
        }

        Ok(Self {
            bus,
            transport,
            capacity_sectors,
            blk_size,
            dma_virt,
            dma_phys_base,
            grant,
            avail_idx: 0,
            last_used_idx: 0,
            revoked: false,
        })
    }

    fn read_blk_config(
        bus: &B,
        transport: &VirtioMmioTransport,
    ) -> Result<(u64, u32), VirtioError> {
        for _ in 0..8 {
            let gen_before = if transport.version >= 2 {
                bus.read32(REG_CONFIG_GENERATION)?
            } else {
                0
            };
            let cap_low = u64::from(bus.read32(REG_CONFIG_BASE)?);
            let cap_high = u64::from(bus.read32(REG_CONFIG_BASE + 4)?);
            let capacity = cap_low | (cap_high << 32);
            let blk_size = if (transport.negotiated_features & VIRTIO_BLK_F_BLK_SIZE) != 0 {
                let raw = bus.read32(REG_CONFIG_BASE + 0x14)?;
                if raw == 0 { SECTOR_SIZE as u32 } else { raw }
            } else {
                SECTOR_SIZE as u32
            };
            let gen_after = if transport.version >= 2 {
                bus.read32(REG_CONFIG_GENERATION)?
            } else {
                0
            };
            if gen_before == gen_after {
                return Ok((capacity, blk_size));
            }
        }
        Err(VirtioError::DeviceFault)
    }

    pub const fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors.saturating_mul(SECTOR_SIZE as u64)
    }

    pub const fn blk_size(&self) -> u32 {
        self.blk_size
    }

    pub const fn read_only(&self) -> bool {
        (self.transport.negotiated_features & VIRTIO_BLK_F_RO) != 0
    }

    pub const fn features(&self) -> u64 {
        self.transport.negotiated_features
    }

    pub const fn transport(&self) -> &VirtioMmioTransport {
        &self.transport
    }

    pub fn read_sectors(&mut self, start_sector: u64, out: &mut [u8]) -> Result<(), VirtioError> {
        if out.is_empty() {
            return Ok(());
        }
        if !out.len().is_multiple_of(SECTOR_SIZE) {
            return Err(VirtioError::InvalidPacket);
        }
        let total_sectors =
            u64::try_from(out.len() / SECTOR_SIZE).map_err(|_| VirtioError::OutOfRange)?;
        let end_sector = start_sector
            .checked_add(total_sectors)
            .ok_or(VirtioError::OutOfRange)?;
        if end_sector > self.capacity_sectors {
            return Err(VirtioError::OutOfRange);
        }

        let mut sector_cursor = start_sector;
        let mut offset = 0usize;
        while offset < out.len() {
            let chunk_len = (out.len() - offset).min(BUF);
            let chunk_sectors =
                u64::try_from(chunk_len / SECTOR_SIZE).map_err(|_| VirtioError::OutOfRange)?;
            self.execute_one(VirtioBlkOp::Read, sector_cursor, chunk_len, None)?;
            // SAFETY: `execute_one` fenced after completion and validated `chunk_len <= BUF`.
            unsafe {
                copy_nonoverlapping(
                    (&raw const (*self.dma_virt.as_ptr()).data).cast::<u8>(),
                    out[offset..offset + chunk_len].as_mut_ptr(),
                    chunk_len,
                );
            }
            sector_cursor += chunk_sectors;
            offset += chunk_len;
        }
        Ok(())
    }

    pub fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> Result<(), VirtioError> {
        if self.read_only() {
            return Err(VirtioError::ReadOnlyDevice);
        }
        if data.is_empty() {
            return Ok(());
        }
        if !data.len().is_multiple_of(SECTOR_SIZE) {
            return Err(VirtioError::InvalidPacket);
        }
        let total_sectors =
            u64::try_from(data.len() / SECTOR_SIZE).map_err(|_| VirtioError::OutOfRange)?;
        let end_sector = start_sector
            .checked_add(total_sectors)
            .ok_or(VirtioError::OutOfRange)?;
        if end_sector > self.capacity_sectors {
            return Err(VirtioError::OutOfRange);
        }

        let mut sector_cursor = start_sector;
        let mut offset = 0usize;
        while offset < data.len() {
            let chunk_len = (data.len() - offset).min(BUF);
            let chunk_sectors =
                u64::try_from(chunk_len / SECTOR_SIZE).map_err(|_| VirtioError::OutOfRange)?;
            self.execute_one(
                VirtioBlkOp::Write,
                sector_cursor,
                chunk_len,
                Some(&data[offset..offset + chunk_len]),
            )?;
            sector_cursor += chunk_sectors;
            offset += chunk_len;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), VirtioError> {
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        if (self.transport.negotiated_features & VIRTIO_BLK_F_FLUSH) == 0 {
            return Ok(());
        }
        self.execute_one(VirtioBlkOp::Flush, 0, 0, None)
    }

    pub fn revoke_and_reset(&mut self) -> Result<(), VirtioError> {
        self.revoked = true;
        self.grant.revoked = true;
        self.transport.reset_and_revoke(&mut self.bus)
    }

    fn execute_one(
        &mut self,
        op: VirtioBlkOp,
        sector: u64,
        data_len: usize,
        write_payload: Option<&[u8]>,
    ) -> Result<(), VirtioError> {
        if self.revoked {
            return Err(VirtioError::RevokedAuthority);
        }
        self.grant.validate_authority()?;
        if op != VirtioBlkOp::Flush && (data_len == 0 || data_len > BUF) {
            return Err(VirtioError::BufferTooSmall);
        }

        let dma_ptr = self.dma_virt.as_ptr();
        let req_offset = offset_of!(VirtioBlkDmaBlock<Q, BUF>, req) as u64;
        let status_offset = req_offset + offset_of!(VirtioBlkReqPage, status) as u64;
        let data_offset = offset_of!(VirtioBlkDmaBlock<Q, BUF>, data) as u64;

        let header_phys = self
            .dma_phys_base
            .checked_add(req_offset)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let status_phys = self
            .dma_phys_base
            .checked_add(status_offset)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        let data_phys = self
            .dma_phys_base
            .checked_add(data_offset)
            .ok_or(VirtioError::DescriptorLengthOverflow)?;

        let mut descs = [VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }; Q];

        if op == VirtioBlkOp::Flush {
            descs[0] = VirtqDesc {
                addr: header_phys,
                len: size_of::<VirtioBlkReqHeader>() as u32,
                flags: VRING_DESC_F_NEXT,
                next: 1,
            };
            descs[1] = VirtqDesc {
                addr: status_phys,
                len: 1,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            };
        } else {
            let data_u32 =
                u32::try_from(data_len).map_err(|_| VirtioError::DescriptorLengthOverflow)?;
            descs[0] = VirtqDesc {
                addr: header_phys,
                len: size_of::<VirtioBlkReqHeader>() as u32,
                flags: VRING_DESC_F_NEXT,
                next: 1,
            };
            descs[1] = VirtqDesc {
                addr: data_phys,
                len: data_u32,
                flags: VRING_DESC_F_NEXT
                    | if op == VirtioBlkOp::Read {
                        VRING_DESC_F_WRITE
                    } else {
                        0
                    },
                next: 2,
            };
            descs[2] = VirtqDesc {
                addr: status_phys,
                len: 1,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            };
        }

        let policy_features = self.transport.negotiated_features | VIRTIO_F_VERSION_1;
        validate_blk_request(Q, policy_features, op, &descs, 0, &self.grant)?;

        let header = VirtioBlkReqHeader {
            req_type: op.request_type(),
            reserved: 0,
            sector,
        };
        let avail_slot = usize::from(self.avail_idx) & (Q - 1);
        let next_avail = self.avail_idx.wrapping_add(1);

        // SAFETY: `dma_ptr` points to exclusively owned, aligned DMA memory covered by `self.grant`.
        unsafe {
            write_volatile(&raw mut (*dma_ptr).req.header, header);
            write_volatile(&raw mut (*dma_ptr).req.status, STATUS_SENTINEL);
            if let Some(src) = write_payload {
                copy_nonoverlapping(
                    src.as_ptr(),
                    (&raw mut (*dma_ptr).data).cast::<u8>(),
                    src.len(),
                );
            }
            for (idx, desc) in descs.iter().copied().enumerate().take(3) {
                write_volatile(&raw mut (*dma_ptr).queue_front.desc[idx], desc);
            }
            write_volatile(&raw mut (*dma_ptr).queue_front.avail_ring[avail_slot], 0);
        }
        dma_fence();

        // SAFETY: descriptors and payload are published; advance `avail_idx` before doorbell notify.
        unsafe {
            write_volatile(&raw mut (*dma_ptr).queue_front.avail_idx, next_avail);
        }
        dma_fence();
        self.avail_idx = next_avail;

        self.transport.notify_queue(&mut self.bus, 0)?;

        let expected_used = self.last_used_idx.wrapping_add(1);
        let mut spins = 0u32;
        loop {
            // SAFETY: volatile poll of device-owned `used_idx`.
            let observed = unsafe { read_volatile(&raw const (*dma_ptr).queue_used.used_idx) };
            if observed == expected_used {
                break;
            }
            if observed != self.last_used_idx {
                return Err(VirtioError::DeviceFault);
            }
            spins += 1;
            if spins >= MAX_POLL_ITERS {
                return Err(VirtioError::DeviceFault);
            }
            spin_loop();
        }
        dma_fence();

        let used_slot = usize::from(self.last_used_idx) & (Q - 1);
        // SAFETY: device signaled `used_idx == expected_used` before the `dma_fence()` above.
        let elem = unsafe { read_volatile(&raw const (*dma_ptr).queue_used.used_ring[used_slot]) };
        self.last_used_idx = expected_used;
        let _ = self.transport.ack_interrupt(&mut self.bus);

        if elem.id != 0 {
            return Err(VirtioError::DeviceFault);
        }

        // SAFETY: status byte was initialized to `STATUS_SENTINEL` and written by device before `used_idx`.
        let status = unsafe { read_volatile(&raw const (*dma_ptr).req.status) };
        match status {
            VIRTIO_BLK_S_OK => Ok(()),
            VIRTIO_BLK_S_UNSUPP => Err(VirtioError::UnsupportedOp),
            VIRTIO_BLK_S_IOERR => Err(VirtioError::DeviceFault),
            _ => Err(VirtioError::DeviceFault),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmio::*;
    use kernal_fdt_aarch64::MmioRegion;

    struct MockBlkMmioBus {
        regs: [u32; 128],
        disk: [u8; 8 * SECTOR_SIZE],
        dma: *mut VirtioBlkDmaBlock<16, 4096>,
        features: u64,
        version: u32,
        flush_count: u32,
    }

    impl MockBlkMmioBus {
        fn new(version: u32, features: u64, dma: *mut VirtioBlkDmaBlock<16, 4096>) -> Self {
            let mut regs = [0u32; 128];
            regs[REG_MAGIC_VALUE / 4] = VIRTIO_MMIO_MAGIC;
            regs[REG_VERSION / 4] = version;
            regs[REG_DEVICE_ID / 4] = VirtioDeviceId::Blk as u32;
            regs[REG_VENDOR_ID / 4] = 0x554d_4551;
            regs[REG_QUEUE_NUM_MAX / 4] = 16;
            regs[REG_CONFIG_BASE / 4] = 8; // 8 sectors
            regs[(REG_CONFIG_BASE + 0x14) / 4] = 512;
            Self {
                regs,
                disk: [0u8; 8 * SECTOR_SIZE],
                dma,
                features,
                version,
                flush_count: 0,
            }
        }

        fn process_queue(&mut self) {
            // SAFETY: single-threaded unit test owns `self.dma` cleanly for synchronous notify.
            unsafe {
                let dma = &mut *self.dma;
                let head = dma.queue_front.avail_ring[usize::from(dma.queue_used.used_idx) & 15];
                let d0 = dma.queue_front.desc[usize::from(head)];
                let header = *(d0.addr as *const VirtioBlkReqHeader);
                let d1 = dma.queue_front.desc[usize::from(d0.next)];
                let status_ptr = if header.req_type == crate::blk::VIRTIO_BLK_T_FLUSH {
                    self.flush_count += 1;
                    d1.addr as *mut u8
                } else {
                    let d2 = dma.queue_front.desc[usize::from(d1.next)];
                    let byte_off = usize::try_from(header.sector).unwrap() * SECTOR_SIZE;
                    let len = usize::try_from(d1.len).unwrap();
                    let buf = core::slice::from_raw_parts_mut(d1.addr as *mut u8, len);
                    if header.req_type == crate::blk::VIRTIO_BLK_T_IN {
                        buf.copy_from_slice(&self.disk[byte_off..byte_off + len]);
                    } else {
                        self.disk[byte_off..byte_off + len].copy_from_slice(buf);
                    }
                    d2.addr as *mut u8
                };
                let ok = if (self.features & VIRTIO_BLK_F_RO) != 0
                    && header.req_type == crate::blk::VIRTIO_BLK_T_OUT
                {
                    VIRTIO_BLK_S_IOERR
                } else {
                    VIRTIO_BLK_S_OK
                };
                *status_ptr = ok;
                let slot = usize::from(dma.queue_used.used_idx) & 15;
                dma.queue_used.used_ring[slot] = VirtqUsedElem {
                    id: u32::from(head),
                    len: if header.req_type == crate::blk::VIRTIO_BLK_T_IN {
                        d1.len + 1
                    } else {
                        1
                    },
                };
                dma.queue_used.used_idx = dma.queue_used.used_idx.wrapping_add(1);
                self.regs[REG_INTERRUPT_STATUS / 4] = 1;
            }
        }
    }

    impl MmioBus for MockBlkMmioBus {
        fn region_size(&self) -> u64 {
            0x200
        }

        fn read32(&self, offset: usize) -> Result<u32, VirtioError> {
            if offset == REG_DEVICE_FEATURES {
                let sel = self.regs[REG_DEVICE_FEATURES_SEL / 4];
                return Ok(if sel == 0 {
                    self.features as u32
                } else {
                    (self.features >> 32) as u32
                });
            }
            if offset == REG_STATUS && self.version >= 2 {
                return Ok(self.regs[offset / 4]);
            }
            Ok(self.regs[offset / 4])
        }

        fn write32(&mut self, offset: usize, value: u32) -> Result<(), VirtioError> {
            self.regs[offset / 4] = value;
            if offset == REG_QUEUE_NOTIFY && value == 0 {
                self.process_queue();
            }
            if offset == REG_INTERRUPT_ACK {
                self.regs[REG_INTERRUPT_STATUS / 4] &= !value;
            }
            Ok(())
        }

        fn read8(&self, _offset: usize) -> Result<u8, VirtioError> {
            Ok(0)
        }
    }

    fn info() -> VirtioMmioInfo {
        VirtioMmioInfo {
            region: MmioRegion {
                base: 0x0a00_0000,
                size: 0x200,
            },
            irq: 16,
            enabled: true,
        }
    }

    #[test]
    fn initializes_and_roundtrips_multi_sector_rw_and_flush_on_v2() {
        let mut dma = Box::new(VirtioBlkDmaBlock::<16, 4096>::zeroed());
        let dma_ptr = &raw mut *dma;
        let dma_addr = dma_ptr as u64;
        let grant = DmaBufferGrant {
            base_addr: dma_addr,
            len: size_of::<VirtioBlkDmaBlock<16, 4096>>() as u64,
            writable: true,
            dma_assigned: true,
            buffer_generation: 1,
            expected_generation: 1,
            revoked: false,
        };
        let bus = MockBlkMmioBus::new(2, VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH, dma_ptr);
        let mut blk = unsafe {
            VirtioBlkMmio::initialize(info(), bus, NonNull::new(dma_ptr).unwrap(), dma_addr, grant)
        }
        .expect("v2 virtio-blk initialize should succeed");

        assert_eq!(blk.capacity_sectors(), 8);
        assert_eq!(blk.capacity_bytes(), 4096);
        assert!(!blk.read_only());

        // Write 3 sectors (1536 bytes), testing multi-sector bounce + offset advance.
        let mut write_buf = [0u8; 3 * SECTOR_SIZE];
        for (i, b) in write_buf.iter_mut().enumerate() {
            *b = ((i * 7 + 3) & 0xff) as u8;
        }
        blk.write_sectors(2, &write_buf).expect("write_sectors");
        blk.flush().expect("flush");
        assert_eq!(blk.bus.flush_count, 1);

        let mut read_buf = [0u8; 3 * SECTOR_SIZE];
        blk.read_sectors(2, &mut read_buf).expect("read_sectors");
        assert_eq!(read_buf, write_buf);

        // Out-of-range check must fail closed.
        assert_eq!(
            blk.read_sectors(6, &mut read_buf),
            Err(VirtioError::OutOfRange)
        );
    }

    #[test]
    fn initializes_and_reads_on_legacy_v1_and_enforces_ro() {
        let mut dma = Box::new(VirtioBlkDmaBlock::<16, 4096>::zeroed());
        let dma_ptr = &raw mut *dma;
        let dma_addr = dma_ptr as u64;
        let grant = DmaBufferGrant {
            base_addr: dma_addr,
            len: size_of::<VirtioBlkDmaBlock<16, 4096>>() as u64,
            writable: true,
            dma_assigned: true,
            buffer_generation: 1,
            expected_generation: 1,
            revoked: false,
        };
        let mut bus = MockBlkMmioBus::new(1, VIRTIO_BLK_F_RO, dma_ptr);
        bus.disk[..4].copy_from_slice(b"EXT4");
        let mut blk = unsafe {
            VirtioBlkMmio::initialize(info(), bus, NonNull::new(dma_ptr).unwrap(), dma_addr, grant)
        }
        .expect("v1 read-only init should succeed");

        assert!(blk.read_only());
        assert_eq!(
            blk.write_sectors(0, &[0u8; 512]),
            Err(VirtioError::ReadOnlyDevice)
        );

        let mut sector = [0u8; SECTOR_SIZE];
        blk.read_sectors(0, &mut sector).expect("read_sectors");
        assert_eq!(&sector[..4], b"EXT4");
    }
}
