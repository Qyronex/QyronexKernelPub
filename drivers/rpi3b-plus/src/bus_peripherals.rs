// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! BCM2837 System Timer (`0x3F00_3000`), Power Management / Watchdog (`0x3F10_0000`),
//! Hardware RNG (`0x3F10_4000`), BSC I2C Master (`0x3F80_4000`), and SPI0 Master (`0x3F20_4000`)
//! drivers for Raspberry Pi 3B+.

use crate::RpiError;
use kernal_capability::{CapRights, Capability};

// BCM2837 1 MHz System Timer (`0x3F00_3000`)
pub const SYSTIMER_FREQ_HZ: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bcm2837SysTimer {
    pub counter_us: u64,
    pub compare: [u32; 4],
    pub match_status: u8,
}

impl Default for Bcm2837SysTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcm2837SysTimer {
    pub const fn new() -> Self {
        Self {
            counter_us: 0,
            compare: [0; 4],
            match_status: 0,
        }
    }

    pub const fn clo(&self) -> u32 {
        self.counter_us as u32
    }

    pub const fn chi(&self) -> u32 {
        (self.counter_us >> 32) as u32
    }

    pub fn arm_compare(
        &mut self,
        cap: Capability,
        channel: u8,
        target_us: u32,
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if channel >= 4 {
            return Err(RpiError::OutOfRange);
        }
        self.compare[channel as usize] = target_us;
        self.match_status &= !(1 << channel);
        Ok(())
    }

    pub fn advance_us(&mut self, delta_us: u64) -> u8 {
        let prev = self.counter_us;
        let next = prev.wrapping_add(delta_us);
        self.counter_us = next;
        for ch in 0..4 {
            let cmp = u64::from(self.compare[ch]);
            let prev_low = prev & 0xFFFF_FFFF;
            let reached = if delta_us >= 0x1_0000_0000 {
                true
            } else if prev_low <= (next & 0xFFFF_FFFF) {
                cmp > prev_low && cmp <= (next & 0xFFFF_FFFF)
            } else {
                cmp > prev_low || cmp <= (next & 0xFFFF_FFFF)
            };
            if reached {
                self.match_status |= 1 << ch;
            }
        }
        self.match_status
    }

    pub fn clear_match(&mut self, cap: Capability, mask: u8) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        self.match_status &= !(mask & 0xF);
        Ok(())
    }
}

// BCM2837 Power Management & Hardware Watchdog (`0x3F10_0000`)
pub const PM_PASSWORD: u32 = 0x5A00_0000;
pub const PM_PASSWORD_MASK: u32 = 0xFFFF_0000;
pub const PM_RSTC_WRCFG_MASK: u32 = 0x0000_0030;
pub const PM_RSTC_WRCFG_FULL_RESET: u32 = 0x0000_0020;
pub const PM_RSTC_RESET: u32 = 0x0000_0102;
pub const PM_WDOG_TIME_MASK: u32 = 0x000F_FFFF;
pub const PM_WDOG_TICKS_PER_SEC: u32 = 65_536; // ~16-bit fractional seconds counter

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bcm2837PmWatchdog {
    pub rstc: u32,
    pub rsts: u32,
    pub wdog_ticks: u32,
    pub reset_triggered: bool,
}

impl Default for Bcm2837PmWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcm2837PmWatchdog {
    pub const fn new() -> Self {
        Self {
            rstc: PM_RSTC_RESET,
            rsts: 0,
            wdog_ticks: 0,
            reset_triggered: false,
        }
    }

    const fn check_password(word: u32) -> Result<u32, RpiError> {
        if (word & PM_PASSWORD_MASK) != PM_PASSWORD {
            Err(RpiError::InvalidWatchdogPassword)
        } else {
            Ok(word & !PM_PASSWORD_MASK)
        }
    }

    pub fn write_wdog(&mut self, cap: Capability, raw_word: u32) -> Result<u32, RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let payload = Self::check_password(raw_word)?;
        self.wdog_ticks = payload & PM_WDOG_TIME_MASK;
        Ok(self.wdog_ticks)
    }

    pub fn write_rstc(&mut self, cap: Capability, raw_word: u32) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let payload = Self::check_password(raw_word)?;
        self.rstc = payload;
        Ok(())
    }

    pub const fn is_armed(&self) -> bool {
        (self.rstc & PM_RSTC_WRCFG_MASK) == PM_RSTC_WRCFG_FULL_RESET && self.wdog_ticks > 0
    }

    pub fn tick(&mut self, elapsed_ticks: u32) -> bool {
        if !self.is_armed() {
            return false;
        }
        if elapsed_ticks >= self.wdog_ticks {
            self.wdog_ticks = 0;
            self.reset_triggered = true;
            true
        } else {
            self.wdog_ticks -= elapsed_ticks;
            false
        }
    }
}

// BCM2837 Hardware Random Number Generator (`0x3F10_4000`, `brcm,bcm2835-rng`)
pub const RNG_CTRL_EN: u32 = 1 << 0;
pub const RNG_WARMUP_COUNT: u32 = 0x0004_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bcm2837HwRng {
    pub ctrl: u32,
    pub status: u32,
    state: u64,
}

impl Default for Bcm2837HwRng {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcm2837HwRng {
    pub const fn new() -> Self {
        Self {
            ctrl: 0,
            status: 0,
            state: 0x9E37_79B9_7F4A_7C15,
        }
    }

    pub fn enable(&mut self, cap: Capability, initial_seed: u64) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if initial_seed == 0 {
            return Err(RpiError::InvalidArgument);
        }
        self.state ^= initial_seed.rotate_left(17) ^ 0xBF58_476D_1CE4_E5B9;
        self.status = RNG_WARMUP_COUNT | (4 << 24); // 4 words available in FIFO after warmup
        self.ctrl = RNG_CTRL_EN;
        Ok(())
    }

    pub fn read_word(&mut self, cap: Capability) -> Result<u32, RpiError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(RpiError::PermissionDenied);
        }
        if (self.ctrl & RNG_CTRL_EN) == 0 || (self.status & 0x00FF_FFFF) < RNG_WARMUP_COUNT {
            return Err(RpiError::DeviceNotReady);
        }
        // SplitMix64 mixing step
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        Ok(z as u32)
    }
}

// BCM2837 Broadcom Serial Controller (BSC0/1/2 I2C Master, `0x3F80_4000`)
pub const BSC_FIFO_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bcm2837BscI2c {
    pub enabled: bool,
    pub clock_divider: u16,
    pub slave_addr: u8,
    last_tx: [u8; BSC_FIFO_SIZE],
    last_tx_len: usize,
}

impl Default for Bcm2837BscI2c {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcm2837BscI2c {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            clock_divider: 1500, // 150 MHz / 1500 = 100 kHz standard I2C
            slave_addr: 0,
            last_tx: [0; BSC_FIFO_SIZE],
            last_tx_len: 0,
        }
    }

    pub fn write_transfer(
        &mut self,
        cap: Capability,
        addr_7bit: u8,
        payload: &[u8],
    ) -> Result<usize, RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        if !self.enabled {
            return Err(RpiError::DeviceNotReady);
        }
        // Reserved I2C 7-bit ranges: 0x00..=0x07 and 0x78..=0x7F
        if !(0x08..=0x77).contains(&addr_7bit)
            || payload.is_empty()
            || payload.len() > BSC_FIFO_SIZE
        {
            return Err(RpiError::InvalidArgument);
        }
        self.slave_addr = addr_7bit;
        self.last_tx[..payload.len()].copy_from_slice(payload);
        self.last_tx_len = payload.len();
        Ok(payload.len())
    }

    pub fn last_written(&self) -> &[u8] {
        &self.last_tx[..self.last_tx_len]
    }
}

// BCM2837 SPI0 Master Controller (`0x3F20_4000`, `brcm,bcm2835-spi`)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bcm2837Spi0 {
    pub clock_divider: u16,
    pub mode: u8,
    pub active_cs: u8,
    pub loopback: bool,
}

impl Default for Bcm2837Spi0 {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcm2837Spi0 {
    pub const fn new() -> Self {
        Self {
            clock_divider: 256,
            mode: 0,
            active_cs: 0,
            loopback: true,
        }
    }

    pub fn configure(
        &mut self,
        cap: Capability,
        cs: u8,
        mode: u8,
        clock_divider: u16,
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if cs > 2 || mode > 3 || clock_divider < 2 {
            return Err(RpiError::InvalidArgument);
        }
        self.active_cs = cs;
        self.mode = mode;
        self.clock_divider = clock_divider;
        Ok(())
    }

    pub fn transfer_full_duplex(
        &self,
        cap: Capability,
        tx: &[u8],
        rx: &mut [u8],
    ) -> Result<usize, RpiError> {
        if !cap.rights.contains(CapRights::READ) || !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        if tx.is_empty() || tx.len() != rx.len() || tx.len() > 64 {
            return Err(RpiError::InvalidArgument);
        }
        if self.loopback {
            rx.copy_from_slice(tx);
        } else {
            rx.fill(0xFF);
        }
        Ok(tx.len())
    }
}
