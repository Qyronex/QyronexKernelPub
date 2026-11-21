// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! BCM2837 54-pin GPIO controller (`0x3F20_0000`, `brcm,bcm2835-gpio`) for Raspberry Pi 3B+.
//! Supports `GPFSEL0..5`, `GPSET0..1`, `GPCLR0..1`, `GPLEV0..1`, `GPEDS0..1`, `GPPUD`/`GPPUDCLK0..1`,
//! and Raspberry Pi 3B+ pin multiplexing presets (PL011 UART0, Mini-UART1, Arasan SDHCI/EMMC, I2C1,
//! SPI0, and Activity LED on GPIO29).

use crate::RpiError;
use kernal_capability::{CapRights, Capability};

pub const BCM2837_GPIO_PIN_COUNT: usize = 54;
pub const RPI3B_PLUS_ACT_LED_PIN: u8 = 29;

pub const REG_GPFSEL0: u64 = 0x00;
pub const REG_GPFSEL1: u64 = 0x04;
pub const REG_GPFSEL2: u64 = 0x08;
pub const REG_GPFSEL3: u64 = 0x0C;
pub const REG_GPFSEL4: u64 = 0x10;
pub const REG_GPFSEL5: u64 = 0x14;
pub const REG_GPSET0: u64 = 0x1C;
pub const REG_GPSET1: u64 = 0x20;
pub const REG_GPCLR0: u64 = 0x28;
pub const REG_GPCLR1: u64 = 0x2C;
pub const REG_GPLEV0: u64 = 0x34;
pub const REG_GPLEV1: u64 = 0x38;
pub const REG_GPEDS0: u64 = 0x40;
pub const REG_GPEDS1: u64 = 0x44;
pub const REG_GPPUD: u64 = 0x94;
pub const REG_GPPUDCLK0: u64 = 0x98;
pub const REG_GPPUDCLK1: u64 = 0x9C;

/// BCM2835/BCM2837 3-bit `FSEL` pin function encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GpioFunction {
    Input = 0b000,
    Output = 0b001,
    Alt0 = 0b100,
    Alt1 = 0b101,
    Alt2 = 0b110,
    Alt3 = 0b111,
    Alt4 = 0b011,
    Alt5 = 0b010,
}

impl GpioFunction {
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b111 {
            0b000 => Self::Input,
            0b001 => Self::Output,
            0b100 => Self::Alt0,
            0b101 => Self::Alt1,
            0b110 => Self::Alt2,
            0b111 => Self::Alt3,
            0b011 => Self::Alt4,
            _ => Self::Alt5,
        }
    }
}

/// BCM2837 `GPPUD` resistor pull configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GpioPull {
    None = 0b00,
    PullDown = 0b01,
    PullUp = 0b10,
}

/// BCM2837 54-pin GPIO controller state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bcm2837Gpio {
    gpfsel: [u32; 6],
    level_bitmap: u64,
    event_detect_bitmap: u64,
    pulls: [GpioPull; BCM2837_GPIO_PIN_COUNT],
}

impl Default for Bcm2837Gpio {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcm2837Gpio {
    pub const fn new() -> Self {
        Self {
            gpfsel: [0; 6],
            level_bitmap: 0,
            event_detect_bitmap: 0,
            pulls: [GpioPull::None; BCM2837_GPIO_PIN_COUNT],
        }
    }

    const fn validate_pin(pin: u8) -> Result<usize, RpiError> {
        let idx = pin as usize;
        if idx >= BCM2837_GPIO_PIN_COUNT {
            Err(RpiError::PinOutOfRange)
        } else {
            Ok(idx)
        }
    }

    pub fn set_function(
        &mut self,
        cap: Capability,
        pin: u8,
        func: GpioFunction,
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let idx = Self::validate_pin(pin)?;
        let reg = idx / 10;
        let shift = (idx % 10) * 3;
        self.gpfsel[reg] =
            (self.gpfsel[reg] & !(0b111 << shift)) | (u32::from(func as u8) << shift);
        Ok(())
    }

    pub fn get_function(&self, pin: u8) -> Result<GpioFunction, RpiError> {
        let idx = Self::validate_pin(pin)?;
        let reg = idx / 10;
        let shift = (idx % 10) * 3;
        Ok(GpioFunction::from_bits(
            ((self.gpfsel[reg] >> shift) & 0b111) as u8,
        ))
    }

    pub fn set_pull(&mut self, cap: Capability, pin: u8, pull: GpioPull) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let idx = Self::validate_pin(pin)?;
        self.pulls[idx] = pull;
        Ok(())
    }

    pub fn get_pull(&self, pin: u8) -> Result<GpioPull, RpiError> {
        let idx = Self::validate_pin(pin)?;
        Ok(self.pulls[idx])
    }

    pub fn set_pin(&mut self, cap: Capability, pin: u8) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        let idx = Self::validate_pin(pin)?;
        self.level_bitmap |= 1u64 << idx;
        Ok(())
    }

    pub fn clear_pin(&mut self, cap: Capability, pin: u8) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        let idx = Self::validate_pin(pin)?;
        self.level_bitmap &= !(1u64 << idx);
        Ok(())
    }

    pub fn read_pin(&self, pin: u8) -> Result<bool, RpiError> {
        let idx = Self::validate_pin(pin)?;
        Ok(((self.level_bitmap >> idx) & 1) != 0)
    }

    pub const fn gpfsel_register(&self, index: usize) -> Result<u32, RpiError> {
        if index >= 6 {
            return Err(RpiError::OutOfRange);
        }
        Ok(self.gpfsel[index])
    }

    pub const fn gplev0(&self) -> u32 {
        self.level_bitmap as u32
    }

    pub const fn gplev1(&self) -> u32 {
        ((self.level_bitmap >> 32) as u32) & 0x003F_FFFF
    }

    /// Configures GPIO14 (`TXD0`) and GPIO15 (`RXD0`) for PL011 `UART0` (`Alt0`).
    pub fn configure_pl011_uart0(&mut self, cap: Capability) -> Result<(), RpiError> {
        self.set_function(cap, 14, GpioFunction::Alt0)?;
        self.set_function(cap, 15, GpioFunction::Alt0)?;
        self.set_pull(cap, 14, GpioPull::None)?;
        self.set_pull(cap, 15, GpioPull::PullUp)
    }

    /// Configures GPIO14 (`TXD1`) and GPIO15 (`RXD1`) for AUX Mini-UART `UART1` (`Alt5`).
    pub fn configure_mini_uart1(&mut self, cap: Capability) -> Result<(), RpiError> {
        self.set_function(cap, 14, GpioFunction::Alt5)?;
        self.set_function(cap, 15, GpioFunction::Alt5)?;
        self.set_pull(cap, 14, GpioPull::None)?;
        self.set_pull(cap, 15, GpioPull::PullUp)
    }

    /// Configures GPIO48..53 (`CLK`, `CMD`, `DAT0..3`) for Arasan SDHCI/EMMC (`Alt3`).
    pub fn configure_sdhci_emmc(&mut self, cap: Capability) -> Result<(), RpiError> {
        self.set_function(cap, 48, GpioFunction::Alt3)?;
        self.set_pull(cap, 48, GpioPull::None)?;
        for pin in 49..=53 {
            self.set_function(cap, pin, GpioFunction::Alt3)?;
            self.set_pull(cap, pin, GpioPull::PullUp)?;
        }
        Ok(())
    }

    /// Configures GPIO2 (`SDA1`) and GPIO3 (`SCL1`) for BSC1 I2C (`Alt0`, internal pull-ups).
    pub fn configure_i2c1(&mut self, cap: Capability) -> Result<(), RpiError> {
        for pin in [2u8, 3u8] {
            self.set_function(cap, pin, GpioFunction::Alt0)?;
            self.set_pull(cap, pin, GpioPull::PullUp)?;
        }
        Ok(())
    }

    /// Configures GPIO7..11 (`CE1`, `CE0`, `MISO`, `MOSI`, `SCLK`) for `SPI0` (`Alt0`).
    pub fn configure_spi0(&mut self, cap: Capability) -> Result<(), RpiError> {
        for pin in 7..=11 {
            self.set_function(cap, pin, GpioFunction::Alt0)?;
            self.set_pull(cap, pin, GpioPull::None)?;
        }
        Ok(())
    }

    /// Drives the Raspberry Pi 3B+ green Activity LED (`GPIO29`).
    pub fn set_act_led(&mut self, cap: Capability, on: bool) -> Result<(), RpiError> {
        if cap.rights.contains(CapRights::CONTROL) {
            self.set_function(cap, RPI3B_PLUS_ACT_LED_PIN, GpioFunction::Output)?;
        }
        if on {
            self.set_pin(cap, RPI3B_PLUS_ACT_LED_PIN)
        } else {
            self.clear_pin(cap, RPI3B_PLUS_ACT_LED_PIN)
        }
    }

    pub fn act_led_is_on(&self) -> bool {
        self.read_pin(RPI3B_PLUS_ACT_LED_PIN).unwrap_or(false)
    }
}
