// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::VirtioError;
use core::ptr::{read_volatile, write_volatile};
use kernal_fdt_aarch64::{MmioRegion, VirtioMmioInfo};

/// Little-endian `"virt"` magic value exposed at VirtIO-MMIO offset `0x000`.
pub const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

pub const REG_MAGIC_VALUE: usize = 0x000;
pub const REG_VERSION: usize = 0x004;
pub const REG_DEVICE_ID: usize = 0x008;
pub const REG_VENDOR_ID: usize = 0x00c;
pub const REG_DEVICE_FEATURES: usize = 0x010;
pub const REG_DEVICE_FEATURES_SEL: usize = 0x014;
pub const REG_DRIVER_FEATURES: usize = 0x020;
pub const REG_DRIVER_FEATURES_SEL: usize = 0x024;
pub const REG_GUEST_PAGE_SIZE: usize = 0x028;
pub const REG_QUEUE_SEL: usize = 0x030;
pub const REG_QUEUE_NUM_MAX: usize = 0x034;
pub const REG_QUEUE_NUM: usize = 0x038;
pub const REG_QUEUE_ALIGN: usize = 0x03c;
pub const REG_QUEUE_PFN: usize = 0x040;
pub const REG_QUEUE_READY: usize = 0x044;
pub const REG_QUEUE_NOTIFY: usize = 0x050;
pub const REG_INTERRUPT_STATUS: usize = 0x060;
pub const REG_INTERRUPT_ACK: usize = 0x064;
pub const REG_STATUS: usize = 0x070;
pub const REG_QUEUE_DESC_LOW: usize = 0x080;
pub const REG_QUEUE_DESC_HIGH: usize = 0x084;
pub const REG_QUEUE_AVAIL_LOW: usize = 0x090;
pub const REG_QUEUE_AVAIL_HIGH: usize = 0x094;
pub const REG_QUEUE_USED_LOW: usize = 0x0a0;
pub const REG_QUEUE_USED_HIGH: usize = 0x0a4;
pub const REG_CONFIG_GENERATION: usize = 0x0fc;
pub const REG_CONFIG_BASE: usize = 0x100;

pub const STATUS_ACKNOWLEDGE: u32 = 1 << 0;
pub const STATUS_DRIVER: u32 = 1 << 1;
pub const STATUS_DRIVER_OK: u32 = 1 << 2;
pub const STATUS_FEATURES_OK: u32 = 1 << 3;
pub const STATUS_NEEDS_RESET: u32 = 1 << 6;
pub const STATUS_FAILED: u32 = 1 << 7;

/// VirtIO 1.x specification version bit (bit 32).
pub const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;

/// Recognized VirtIO MMIO device types from QEMU/VirtIO 1.2 Table 5.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VirtioDeviceId {
    Net = 1,
    Blk = 2,
    Console = 3,
    Rng = 4,
    Gpu = 16,
    Input = 18,
}

impl VirtioDeviceId {
    pub const fn from_raw(raw: u32) -> Result<Self, VirtioError> {
        match raw {
            1 => Ok(Self::Net),
            2 => Ok(Self::Blk),
            3 => Ok(Self::Console),
            4 => Ok(Self::Rng),
            16 => Ok(Self::Gpu),
            18 => Ok(Self::Input),
            _ => Err(VirtioError::UnsupportedDeviceId),
        }
    }
}

/// Abstract register access trait allowing safe mock testing and bounded hardware volatile MMIO.
pub trait MmioBus {
    fn region_size(&self) -> u64;
    fn read32(&self, offset: usize) -> Result<u32, VirtioError>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), VirtioError>;
    fn read8(&self, offset: usize) -> Result<u8, VirtioError>;
}

/// Bounds-checked AArch64/physical volatile MMIO aperture mapped into kernel address space.
#[derive(Clone, Copy, Debug)]
pub struct VolatileMmioBus {
    base: usize,
    size: u64,
}

impl VolatileMmioBus {
    /// Creates a bounded MMIO bus handle for one FDT-discovered region.
    ///
    /// # Safety
    /// `region.base` must be mapped as device/MMIO memory for at least `region.size` bytes inside
    /// the active kernel translation regime and exclusively accessed via this handle.
    pub unsafe fn new(region: MmioRegion) -> Result<Self, VirtioError> {
        if region.size < 0x200 {
            return Err(VirtioError::MmioOutOfBounds);
        }
        let base = usize::try_from(region.base).map_err(|_| VirtioError::MmioOutOfBounds)?;
        let _ = region
            .base
            .checked_add(region.size)
            .ok_or(VirtioError::MmioOutOfBounds)?;
        Ok(Self {
            base,
            size: region.size,
        })
    }

    fn check_offset(&self, offset: usize, width: usize) -> Result<usize, VirtioError> {
        if !offset.is_multiple_of(width) {
            return Err(VirtioError::MmioOutOfBounds);
        }
        let end = offset
            .checked_add(width)
            .ok_or(VirtioError::MmioOutOfBounds)?;
        if (end as u64) > self.size {
            return Err(VirtioError::MmioOutOfBounds);
        }
        self.base
            .checked_add(offset)
            .ok_or(VirtioError::MmioOutOfBounds)
    }
}

impl MmioBus for VolatileMmioBus {
    fn region_size(&self) -> u64 {
        self.size
    }

    fn read32(&self, offset: usize) -> Result<u32, VirtioError> {
        let addr = self.check_offset(offset, 4)?;
        // SAFETY: `check_offset` verified alignment and FDT aperture bounds for a 32-bit register.
        Ok(unsafe { read_volatile(addr as *const u32) })
    }

    fn write32(&mut self, offset: usize, value: u32) -> Result<(), VirtioError> {
        let addr = self.check_offset(offset, 4)?;
        // SAFETY: `check_offset` verified alignment and FDT aperture bounds for a 32-bit register.
        unsafe { write_volatile(addr as *mut u32, value) };
        Ok(())
    }

    fn read8(&self, offset: usize) -> Result<u8, VirtioError> {
        let addr = self.check_offset(offset, 1)?;
        // SAFETY: `check_offset` verified FDT aperture bounds for an 8-bit config register.
        Ok(unsafe { read_volatile(addr as *const u8) })
    }
}

/// Probe metadata captured during FDT-guided VirtIO-MMIO discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioMmioProbe {
    pub info: VirtioMmioInfo,
    pub version: u32,
    pub device_id: VirtioDeviceId,
    pub vendor_id: u32,
    pub device_features: u64,
}

/// Stateful VirtIO-MMIO v2/v1 transport controller with generation-tracked teardown.
#[derive(Clone, Copy, Debug)]
pub struct VirtioMmioTransport {
    pub irq: u32,
    pub version: u32,
    pub device_id: VirtioDeviceId,
    pub vendor_id: u32,
    pub negotiated_features: u64,
    pub generation: u32,
    pub driver_ok: bool,
}

impl VirtioMmioTransport {
    /// Probes an FDT `virtio,mmio` node without modifying device ownership until valid.
    pub fn probe<B: MmioBus>(
        info: VirtioMmioInfo,
        bus: &B,
    ) -> Result<VirtioMmioProbe, VirtioError> {
        if !info.enabled {
            return Err(VirtioError::DeviceDisabled);
        }
        if bus.read32(REG_MAGIC_VALUE)? != VIRTIO_MMIO_MAGIC {
            return Err(VirtioError::BadMagic);
        }
        let version = bus.read32(REG_VERSION)?;
        if version != 1 && version != 2 {
            return Err(VirtioError::UnsupportedVersion);
        }
        let raw_device_id = bus.read32(REG_DEVICE_ID)?;
        if raw_device_id == 0 {
            return Err(VirtioError::UnsupportedDeviceId);
        }
        let device_id = VirtioDeviceId::from_raw(raw_device_id)?;
        let vendor_id = bus.read32(REG_VENDOR_ID)?;

        let mut features = bus.read32(REG_DEVICE_FEATURES)? as u64;
        if version == 2 {
            features |= (bus.read32(REG_DEVICE_FEATURES_SEL + 4)? as u64) << 32;
        }

        Ok(VirtioMmioProbe {
            info,
            version,
            device_id,
            vendor_id,
            device_features: features,
        })
    }

    /// Reads the complete 64-bit device feature register pair by writing `DEVICE_FEATURES_SEL`.
    pub fn read_device_features<B: MmioBus>(bus: &mut B, version: u32) -> Result<u64, VirtioError> {
        bus.write32(REG_DEVICE_FEATURES_SEL, 0)?;
        let low = bus.read32(REG_DEVICE_FEATURES)? as u64;
        let high = if version >= 2 {
            bus.write32(REG_DEVICE_FEATURES_SEL, 1)?;
            bus.read32(REG_DEVICE_FEATURES)? as u64
        } else {
            0
        };
        Ok(low | (high << 32))
    }

    /// Performs VirtIO 1.2 section 3.1.1 initialization through feature negotiation.
    pub fn initialize<B: MmioBus>(
        info: VirtioMmioInfo,
        bus: &mut B,
        supported_driver_features: u64,
    ) -> Result<Self, VirtioError> {
        let probe = Self::probe(info, bus)?;
        // 1. Reset the device.
        bus.write32(REG_STATUS, 0)?;
        // 2-3. Set ACKNOWLEDGE and DRIVER status bits.
        bus.write32(REG_STATUS, STATUS_ACKNOWLEDGE)?;
        bus.write32(REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER)?;

        let dev_features = Self::read_device_features(bus, probe.version)?;
        let requested = dev_features & supported_driver_features;
        if probe.version == 2 && (requested & VIRTIO_F_VERSION_1) == 0 {
            bus.write32(REG_STATUS, STATUS_FAILED)?;
            return Err(VirtioError::MissingVersion1Feature);
        }

        bus.write32(REG_DRIVER_FEATURES_SEL, 0)?;
        bus.write32(REG_DRIVER_FEATURES, requested as u32)?;
        if probe.version >= 2 {
            bus.write32(REG_DRIVER_FEATURES_SEL, 1)?;
            bus.write32(REG_DRIVER_FEATURES, (requested >> 32) as u32)?;
            bus.write32(
                REG_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
            )?;
            let confirm = bus.read32(REG_STATUS)?;
            if confirm & STATUS_FEATURES_OK == 0 {
                bus.write32(REG_STATUS, STATUS_FAILED)?;
                return Err(VirtioError::FeaturesRejected);
            }
        } else {
            // Legacy v1 expects 4 KiB page size configuration.
            bus.write32(REG_GUEST_PAGE_SIZE, 4096)?;
        }

        Ok(Self {
            irq: info.irq,
            version: probe.version,
            device_id: probe.device_id,
            vendor_id: probe.vendor_id,
            negotiated_features: requested,
            generation: 1,
            driver_ok: false,
        })
    }

    /// Configures a single split virtqueue in VirtIO-MMIO v2 registers.
    pub fn setup_queue<B: MmioBus>(
        &mut self,
        bus: &mut B,
        queue_index: u32,
        queue_size: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) -> Result<(), VirtioError> {
        if queue_size == 0 || !queue_size.is_power_of_two() || queue_size > 32768 {
            return Err(VirtioError::InvalidQueueSize);
        }
        bus.write32(REG_QUEUE_SEL, queue_index)?;
        if self.version >= 2 && bus.read32(REG_QUEUE_READY)? != 0 {
            return Err(VirtioError::QueueAlreadyReady);
        }
        let max_num = bus.read32(REG_QUEUE_NUM_MAX)?;
        if max_num == 0 || u32::from(queue_size) > max_num {
            return Err(VirtioError::QueueOutOfRange);
        }
        bus.write32(REG_QUEUE_NUM, u32::from(queue_size))?;
        if self.version >= 2 {
            bus.write32(REG_QUEUE_DESC_LOW, desc_phys as u32)?;
            bus.write32(REG_QUEUE_DESC_HIGH, (desc_phys >> 32) as u32)?;
            bus.write32(REG_QUEUE_AVAIL_LOW, avail_phys as u32)?;
            bus.write32(REG_QUEUE_AVAIL_HIGH, (avail_phys >> 32) as u32)?;
            bus.write32(REG_QUEUE_USED_LOW, used_phys as u32)?;
            bus.write32(REG_QUEUE_USED_HIGH, (used_phys >> 32) as u32)?;
            bus.write32(REG_QUEUE_READY, 1)?;
        } else {
            if !desc_phys.is_multiple_of(4096) {
                return Err(VirtioError::InvalidQueueSize);
            }
            bus.write32(REG_QUEUE_ALIGN, 4096)?;
            bus.write32(REG_QUEUE_PFN, (desc_phys >> 12) as u32)?;
        }
        Ok(())
    }

    pub fn mark_driver_ok<B: MmioBus>(&mut self, bus: &mut B) -> Result<(), VirtioError> {
        let base_bits = if self.version >= 2 {
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK
        } else {
            STATUS_ACKNOWLEDGE | STATUS_DRIVER
        };
        bus.write32(REG_STATUS, base_bits | STATUS_DRIVER_OK)?;
        self.driver_ok = true;
        Ok(())
    }

    pub fn notify_queue<B: MmioBus>(
        &self,
        bus: &mut B,
        queue_index: u32,
    ) -> Result<(), VirtioError> {
        if !self.driver_ok {
            return Err(VirtioError::DeviceFault);
        }
        bus.write32(REG_QUEUE_NOTIFY, queue_index)
    }

    pub fn ack_interrupt<B: MmioBus>(&self, bus: &mut B) -> Result<u32, VirtioError> {
        let status = bus.read32(REG_INTERRUPT_STATUS)?;
        if status != 0 {
            bus.write32(REG_INTERRUPT_ACK, status)?;
        }
        Ok(status)
    }

    /// Resets the device and bumps transport generation so stale completions fail closed.
    pub fn reset_and_revoke<B: MmioBus>(&mut self, bus: &mut B) -> Result<(), VirtioError> {
        bus.write32(REG_STATUS, 0)?;
        self.driver_ok = false;
        self.negotiated_features = 0;
        self.generation = self.generation.wrapping_add(1).max(1);
        Ok(())
    }
}
