// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! VideoCore IV Mailbox Property Interface (`0x3F00_B880`, channel 8) for Raspberry Pi 3B+
//! (`BCM2837B0`, board revision `0x00A0_20D3`).

use crate::{
    ARM_MEM_SIZE_DEFAULT, BOARD_SERIAL_DEFAULT, CORE_CLOCK_HZ_DEFAULT, EMMC_CLOCK_HZ_DEFAULT,
    MAX_CLOCK_ARM_HZ, RPI3B_PLUS_BOARD_MODEL, RPI3B_PLUS_BOARD_REVISION, RPI3B_PLUS_DEFAULT_MAC,
    RPI3B_PLUS_FIRMWARE_REV, RpiError, UART_CLOCK_HZ_DEFAULT, VC_MEM_BASE_DEFAULT,
    VC_MEM_SIZE_DEFAULT, arm_phys_to_vc_bus,
};
use kernal_capability::{CapRights, Capability};

pub const MBOX_REG_READ: u64 = 0x00;
pub const MBOX_REG_PEEK: u64 = 0x10;
pub const MBOX_REG_SENDER: u64 = 0x14;
pub const MBOX_REG_STATUS: u64 = 0x18;
pub const MBOX_REG_CONFIG: u64 = 0x1C;
pub const MBOX_REG_WRITE: u64 = 0x20;

pub const MBOX_STATUS_FULL: u32 = 0x8000_0000;
pub const MBOX_STATUS_EMPTY: u32 = 0x4000_0000;

pub const MBOX_CH_POWER: u8 = 0;
pub const MBOX_CH_FB: u8 = 1;
pub const MBOX_CH_VUART: u8 = 2;
pub const MBOX_CH_VCHIQ: u8 = 3;
pub const MBOX_CH_LEDS: u8 = 4;
pub const MBOX_CH_BUTTONS: u8 = 5;
pub const MBOX_CH_TOUCH: u8 = 6;
pub const MBOX_CH_PROP: u8 = 8;

pub const MBOX_REQUEST_CODE: u32 = 0x0000_0000;
pub const MBOX_RESPONSE_SUCCESS: u32 = 0x8000_0000;
pub const MBOX_RESPONSE_ERROR: u32 = 0x8000_0001;
pub const MBOX_TAG_RESPONSE_BIT: u32 = 0x8000_0000;

// Property tags
pub const TAG_END: u32 = 0x0000_0000;
pub const TAG_GET_FIRMWARE_REV: u32 = 0x0000_0001;
pub const TAG_GET_BOARD_MODEL: u32 = 0x0001_0001;
pub const TAG_GET_BOARD_REVISION: u32 = 0x0001_0002;
pub const TAG_GET_BOARD_MAC: u32 = 0x0001_0003;
pub const TAG_GET_BOARD_SERIAL: u32 = 0x0001_0004;
pub const TAG_GET_ARM_MEMORY: u32 = 0x0001_0005;
pub const TAG_GET_VC_MEMORY: u32 = 0x0001_0006;

pub const TAG_GET_POWER_STATE: u32 = 0x0002_0001;
pub const TAG_SET_POWER_STATE: u32 = 0x0002_8001;

pub const TAG_GET_CLOCK_RATE: u32 = 0x0003_0002;
pub const TAG_GET_MAX_CLOCK_RATE: u32 = 0x0003_0004;
pub const TAG_GET_TEMPERATURE: u32 = 0x0003_0006;
pub const TAG_GET_MAX_TEMPERATURE: u32 = 0x0003_000A;
pub const TAG_SET_CLOCK_RATE: u32 = 0x0003_8002;

pub const TAG_ALLOCATE_BUFFER: u32 = 0x0004_0001;
pub const TAG_GET_PHYS_WH: u32 = 0x0004_0003;
pub const TAG_GET_PITCH: u32 = 0x0004_0008;
pub const TAG_SET_PHYS_WH: u32 = 0x0004_8003;
pub const TAG_SET_VIRT_WH: u32 = 0x0004_8004;
pub const TAG_SET_DEPTH: u32 = 0x0004_8005;
pub const TAG_SET_PIXEL_ORDER: u32 = 0x0004_8006;

/// VideoCore Power Domain Device IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PowerDomain {
    SdCard = 0,
    Uart0 = 1,
    Uart1 = 2,
    UsbHcd = 3,
    I2c0 = 4,
    I2c1 = 5,
    I2c2 = 6,
    Spi = 7,
}

impl PowerDomain {
    pub const fn from_id(id: u32) -> Option<Self> {
        match id {
            0 => Some(Self::SdCard),
            1 => Some(Self::Uart0),
            2 => Some(Self::Uart1),
            3 => Some(Self::UsbHcd),
            4 => Some(Self::I2c0),
            5 => Some(Self::I2c1),
            6 => Some(Self::I2c2),
            7 => Some(Self::Spi),
            _ => None,
        }
    }
}

/// VideoCore Clock Domain IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ClockDomain {
    Emmc = 1,
    Uart = 2,
    Arm = 3,
    Core = 4,
}

impl ClockDomain {
    pub const fn from_id(id: u32) -> Option<Self> {
        match id {
            1 => Some(Self::Emmc),
            2 => Some(Self::Uart),
            3 => Some(Self::Arm),
            4 => Some(Self::Core),
            _ => None,
        }
    }
}

/// Negotiated VideoCore framebuffer geometry and bus buffer allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VcFramebufferInfo {
    pub phys_width: u32,
    pub phys_height: u32,
    pub virt_width: u32,
    pub virt_height: u32,
    pub depth_bpp: u32,
    pub is_rgb: bool,
    pub pitch: u32,
    pub arm_phys_base: u32,
    pub bus_addr_base: u32,
    pub size_bytes: u32,
}

/// VideoCore IV Mailbox controller state machine for Raspberry Pi 3B+.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoCoreMailbox {
    pub firmware_rev: u32,
    pub board_model: u32,
    pub board_revision: u32,
    pub mac_address: [u8; 6],
    pub board_serial: u64,
    pub arm_mem_base: u32,
    pub arm_mem_size: u32,
    pub vc_mem_base: u32,
    pub vc_mem_size: u32,
    pub power_mask: u32,
    pub emmc_clock_hz: u32,
    pub uart_clock_hz: u32,
    pub arm_clock_hz: u32,
    pub core_clock_hz: u32,
    pub temperature_millicelsius: u32,
    pub max_temperature_millicelsius: u32,
    pub fb: VcFramebufferInfo,
}

impl Default for VideoCoreMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoCoreMailbox {
    pub const fn new() -> Self {
        let fb_arm_phys = 0x3C10_0000;
        Self {
            firmware_rev: RPI3B_PLUS_FIRMWARE_REV,
            board_model: RPI3B_PLUS_BOARD_MODEL,
            board_revision: RPI3B_PLUS_BOARD_REVISION,
            mac_address: RPI3B_PLUS_DEFAULT_MAC,
            board_serial: BOARD_SERIAL_DEFAULT,
            arm_mem_base: 0,
            arm_mem_size: ARM_MEM_SIZE_DEFAULT,
            vc_mem_base: VC_MEM_BASE_DEFAULT,
            vc_mem_size: VC_MEM_SIZE_DEFAULT,
            // SD card, UART0, UART1, USB HCD powered on by default
            power_mask: (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3),
            emmc_clock_hz: EMMC_CLOCK_HZ_DEFAULT,
            uart_clock_hz: UART_CLOCK_HZ_DEFAULT,
            arm_clock_hz: MAX_CLOCK_ARM_HZ,
            core_clock_hz: CORE_CLOCK_HZ_DEFAULT,
            temperature_millicelsius: 44_250,
            max_temperature_millicelsius: 85_000,
            fb: VcFramebufferInfo {
                phys_width: 1280,
                phys_height: 800,
                virt_width: 1280,
                virt_height: 800,
                depth_bpp: 32,
                is_rgb: true,
                pitch: 1280 * 4,
                arm_phys_base: fb_arm_phys,
                bus_addr_base: arm_phys_to_vc_bus(fb_arm_phys),
                size_bytes: 1280 * 800 * 4,
            },
        }
    }

    pub const fn is_domain_powered(&self, domain: PowerDomain) -> bool {
        (self.power_mask & (1 << (domain as u32))) != 0
    }

    pub fn set_domain_power(
        &mut self,
        cap: Capability,
        domain: PowerDomain,
        on: bool,
    ) -> Result<bool, RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let bit = 1u32 << (domain as u32);
        if on {
            self.power_mask |= bit;
        } else {
            self.power_mask &= !bit;
        }
        Ok(on)
    }

    pub const fn clock_rate(&self, domain: ClockDomain) -> u32 {
        match domain {
            ClockDomain::Emmc => self.emmc_clock_hz,
            ClockDomain::Uart => self.uart_clock_hz,
            ClockDomain::Arm => self.arm_clock_hz,
            ClockDomain::Core => self.core_clock_hz,
        }
    }

    pub fn set_clock_rate(
        &mut self,
        cap: Capability,
        domain: ClockDomain,
        rate_hz: u32,
    ) -> Result<u32, RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if rate_hz < 1_000_000 {
            return Err(RpiError::InvalidArgument);
        }
        let clamped = match domain {
            ClockDomain::Arm => rate_hz.min(MAX_CLOCK_ARM_HZ),
            ClockDomain::Core => rate_hz.min(400_000_000),
            ClockDomain::Emmc => rate_hz.min(250_000_000),
            ClockDomain::Uart => rate_hz.min(100_000_000),
        };
        match domain {
            ClockDomain::Emmc => self.emmc_clock_hz = clamped,
            ClockDomain::Uart => self.uart_clock_hz = clamped,
            ClockDomain::Arm => self.arm_clock_hz = clamped,
            ClockDomain::Core => self.core_clock_hz = clamped,
        }
        Ok(clamped)
    }

    /// Processes a 16-byte-aligned VideoCore Property Tag buffer (`MBOX_CH_PROP = 8`) in place.
    ///
    /// Buffer format (u32 words):
    /// - `buf[0]`: total buffer size in bytes (`len * 4`, must be `>= 12`)
    /// - `buf[1]`: request/response code (`0x0000_0000` on request, `0x8000_0000` on success)
    /// - `buf[2..]`: sequence of tags `[tag_id, value_buf_bytes, req_resp_indicator, values...]`,
    ///   terminated by `TAG_END (0x0000_0000)`.
    pub fn process_property_buffer(
        &mut self,
        cap: Capability,
        phys_addr: u64,
        buf: &mut [u32],
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(RpiError::PermissionDenied);
        }
        // VideoCore mailbox requires 16-byte alignment (low 4 bits of address carry channel ID).
        if (phys_addr & 0xF) != 0 {
            return Err(RpiError::UnalignedBuffer);
        }
        if buf.len() < 3 {
            return Err(RpiError::BufferTooSmall);
        }
        let declared_words = (buf[0] as usize) / 4;
        if declared_words < 3 || declared_words > buf.len() || (buf[0] & 3) != 0 {
            return Err(RpiError::MalformedPropertyBuffer);
        }
        if buf[1] != MBOX_REQUEST_CODE {
            return Err(RpiError::MalformedPropertyBuffer);
        }

        let mut idx = 2usize;
        while idx < declared_words {
            let tag = buf[idx];
            if tag == TAG_END {
                buf[1] = MBOX_RESPONSE_SUCCESS;
                return Ok(());
            }
            if idx + 3 > declared_words {
                buf[1] = MBOX_RESPONSE_ERROR;
                return Err(RpiError::MalformedPropertyBuffer);
            }
            let val_bytes = buf[idx + 1] as usize;
            let val_words = val_bytes.div_ceil(4);
            let val_start = idx + 3;
            if val_start + val_words > declared_words {
                buf[1] = MBOX_RESPONSE_ERROR;
                return Err(RpiError::MalformedPropertyBuffer);
            }

            let resp_bytes =
                self.handle_single_tag(cap, tag, &mut buf[val_start..val_start + val_words])?;
            buf[idx + 2] = MBOX_TAG_RESPONSE_BIT | (resp_bytes as u32);
            idx = val_start + val_words;
        }

        buf[1] = MBOX_RESPONSE_ERROR;
        Err(RpiError::MalformedPropertyBuffer)
    }

    fn handle_single_tag(
        &mut self,
        cap: Capability,
        tag: u32,
        vals: &mut [u32],
    ) -> Result<usize, RpiError> {
        match tag {
            TAG_GET_FIRMWARE_REV => {
                if vals.is_empty() {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[0] = self.firmware_rev;
                Ok(4)
            }
            TAG_GET_BOARD_MODEL => {
                if vals.is_empty() {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[0] = self.board_model;
                Ok(4)
            }
            TAG_GET_BOARD_REVISION => {
                if vals.is_empty() {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[0] = self.board_revision;
                Ok(4)
            }
            TAG_GET_BOARD_MAC => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                let m = self.mac_address;
                vals[0] = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
                vals[1] = u32::from_le_bytes([m[4], m[5], 0, 0]);
                Ok(6)
            }
            TAG_GET_BOARD_SERIAL => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[0] = self.board_serial as u32;
                vals[1] = (self.board_serial >> 32) as u32;
                Ok(8)
            }
            TAG_GET_ARM_MEMORY => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[0] = self.arm_mem_base;
                vals[1] = self.arm_mem_size;
                Ok(8)
            }
            TAG_GET_VC_MEMORY => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[0] = self.vc_mem_base;
                vals[1] = self.vc_mem_size;
                Ok(8)
            }
            TAG_GET_POWER_STATE => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                let Some(dom) = PowerDomain::from_id(vals[0]) else {
                    vals[1] = 0b10; // device does not exist
                    return Ok(8);
                };
                vals[1] = u32::from(self.is_domain_powered(dom));
                Ok(8)
            }
            TAG_SET_POWER_STATE => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                let Some(dom) = PowerDomain::from_id(vals[0]) else {
                    vals[1] = 0b10;
                    return Ok(8);
                };
                let want_on = (vals[1] & 1) != 0;
                let powered = self.set_domain_power(cap, dom, want_on)?;
                vals[1] = u32::from(powered);
                Ok(8)
            }
            TAG_GET_CLOCK_RATE | TAG_GET_MAX_CLOCK_RATE => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                let Some(clk) = ClockDomain::from_id(vals[0]) else {
                    vals[1] = 0;
                    return Ok(8);
                };
                vals[1] = if tag == TAG_GET_MAX_CLOCK_RATE && clk == ClockDomain::Arm {
                    MAX_CLOCK_ARM_HZ
                } else {
                    self.clock_rate(clk)
                };
                Ok(8)
            }
            TAG_SET_CLOCK_RATE => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                let Some(clk) = ClockDomain::from_id(vals[0]) else {
                    return Err(RpiError::InvalidArgument);
                };
                let applied = self.set_clock_rate(cap, clk, vals[1])?;
                vals[1] = applied;
                Ok(8)
            }
            TAG_GET_TEMPERATURE | TAG_GET_MAX_TEMPERATURE => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[1] = if tag == TAG_GET_MAX_TEMPERATURE {
                    self.max_temperature_millicelsius
                } else {
                    self.temperature_millicelsius
                };
                Ok(8)
            }
            TAG_SET_PHYS_WH => {
                if !cap.rights.contains(CapRights::CONTROL) {
                    return Err(RpiError::PermissionDenied);
                }
                if vals.len() < 2
                    || vals[0] == 0
                    || vals[1] == 0
                    || vals[0] > 4096
                    || vals[1] > 4096
                {
                    return Err(RpiError::InvalidArgument);
                }
                self.fb.phys_width = vals[0];
                self.fb.phys_height = vals[1];
                let bytes_per_pixel = (self.fb.depth_bpp.max(8)) / 8;
                self.fb.pitch = self.fb.phys_width * bytes_per_pixel;
                self.fb.size_bytes = self.fb.pitch * self.fb.virt_height.max(self.fb.phys_height);
                Ok(8)
            }
            TAG_GET_PHYS_WH => {
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[0] = self.fb.phys_width;
                vals[1] = self.fb.phys_height;
                Ok(8)
            }
            TAG_SET_VIRT_WH => {
                if !cap.rights.contains(CapRights::CONTROL) {
                    return Err(RpiError::PermissionDenied);
                }
                if vals.len() < 2
                    || vals[0] == 0
                    || vals[1] == 0
                    || vals[0] > 4096
                    || vals[1] > 4096
                {
                    return Err(RpiError::InvalidArgument);
                }
                self.fb.virt_width = vals[0];
                self.fb.virt_height = vals[1];
                self.fb.size_bytes = self.fb.pitch * self.fb.virt_height;
                Ok(8)
            }
            TAG_SET_DEPTH => {
                if !cap.rights.contains(CapRights::CONTROL) {
                    return Err(RpiError::PermissionDenied);
                }
                if vals.is_empty() || !matches!(vals[0], 16 | 24 | 32) {
                    return Err(RpiError::InvalidArgument);
                }
                self.fb.depth_bpp = vals[0];
                self.fb.pitch = self.fb.phys_width * (self.fb.depth_bpp / 8);
                self.fb.size_bytes = self.fb.pitch * self.fb.virt_height;
                Ok(4)
            }
            TAG_SET_PIXEL_ORDER => {
                if !cap.rights.contains(CapRights::CONTROL) {
                    return Err(RpiError::PermissionDenied);
                }
                if vals.is_empty() {
                    return Err(RpiError::BufferTooSmall);
                }
                self.fb.is_rgb = vals[0] != 0;
                Ok(4)
            }
            TAG_ALLOCATE_BUFFER => {
                if !cap.rights.contains(CapRights::CONTROL) {
                    return Err(RpiError::PermissionDenied);
                }
                if vals.len() < 2 {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[0] = self.fb.bus_addr_base;
                vals[1] = self.fb.size_bytes;
                Ok(8)
            }
            TAG_GET_PITCH => {
                if vals.is_empty() {
                    return Err(RpiError::BufferTooSmall);
                }
                vals[0] = self.fb.pitch;
                Ok(4)
            }
            _ => Err(RpiError::UnsupportedTag),
        }
    }
}
