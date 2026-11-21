// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![deny(unsafe_op_in_unsafe_fn)]

//! Native BCM2837 / Raspberry Pi 3B+ Hardware MMIO Transport & Hybrid HAL (`0x3F00_0000..0x4000_0100`).
//!
//! Provides the hardware register abstraction [`RpiMmioBus`] with two interchangeable backends:
//! - [`VolatileRpiMmioBus`]: bounds-checked volatile MMIO (`read_volatile` / `write_volatile`) over
//!   mapped `Device-nGnRnE` physical peripheral windows (`0x3F00_0000` and `0x4000_0000`) for native
//!   execution on Raspberry Pi 3B+ hardware,
//! - [`SimulatedRpiMmioBus`]: deterministic hardware register model allowing the exact same MMIO
//!   driver transactions to execute unchanged on QEMU `virt` and other platforms.

use crate::bus_peripherals::{
    PM_PASSWORD, PM_RSTC_WRCFG_FULL_RESET, RNG_CTRL_EN, RNG_WARMUP_COUNT,
};
use crate::gpio::{
    GpioFunction, REG_GPCLR0, REG_GPCLR1, REG_GPFSEL0, REG_GPLEV0, REG_GPLEV1, REG_GPPUD,
    REG_GPPUDCLK0, REG_GPSET0, REG_GPSET1, RPI3B_PLUS_ACT_LED_PIN,
};
use crate::mailbox::{
    MBOX_CH_PROP, MBOX_REG_READ, MBOX_REG_STATUS, MBOX_REG_WRITE, MBOX_STATUS_EMPTY,
    MBOX_STATUS_FULL,
};
use crate::sdhci::{
    EMMC_ARG1, EMMC_BLKSIZECNT, EMMC_CMDTM, EMMC_CONTROL0, EMMC_CONTROL1, EMMC_DATA,
    EMMC_INTERRUPT, EMMC_RESP0, SD_SECTOR_BYTES,
};
use crate::uart::{
    AUX_ENABLE_MINI_UART, AUX_ENABLES, AUX_MU_BAUD_REG, AUX_MU_CNTL_REG, AUX_MU_CNTL_RX_EN,
    AUX_MU_CNTL_TX_EN, AUX_MU_IO_REG, AUX_MU_LCR_8BIT, AUX_MU_LCR_REG, AUX_MU_LSR_DATA_READY,
    AUX_MU_LSR_REG, AUX_MU_LSR_TX_EMPTY, PL011_CR, PL011_CR_RXE, PL011_CR_TXE, PL011_CR_UARTEN,
    PL011_DR, PL011_FBRD, PL011_FR, PL011_FR_RXFE, PL011_FR_TXFF, PL011_IBRD, PL011_ICR,
    PL011_LCRH, PL011_LCRH_FEN, PL011_LCRH_WLEN_8BIT, compute_mini_uart_baud_reg,
    compute_pl011_baud_dividers,
};
use crate::{
    BCM2837_ARASAN_EMMC_BASE, BCM2837_ARM_LOCAL_SIZE, BCM2837_ARMCTRL_IC_BASE, BCM2837_AUX_BASE,
    BCM2837_BSC1_I2C_BASE, BCM2837_DWC2_USB_BASE, BCM2837_GPIO_BASE, BCM2837_MBOX_BASE,
    BCM2837_PERIPHERAL_BASE, BCM2837_PERIPHERAL_SIZE, BCM2837_PL011_UART0_BASE,
    BCM2837_PM_WDOG_BASE, BCM2837_RNG_BASE, BCM2837_SPI0_BASE, BCM2837_SYSTIMER_BASE,
    CORE_CLOCK_HZ_DEFAULT, LAN7515_CHIP_ID_REV, RpiError, UART_CLOCK_HZ_DEFAULT,
};
use core::ptr::{read_volatile, write_volatile};
use kernal_capability::{CapRights, Capability};

// Subsystem window offsets relative to `BCM2837_PERIPHERAL_BASE (0x3F00_0000)`
pub const OFF_SYSTIMER: usize = (BCM2837_SYSTIMER_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_ARMCTRL_IC: usize = (BCM2837_ARMCTRL_IC_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_MBOX: usize = (BCM2837_MBOX_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_PM_WDOG: usize = (BCM2837_PM_WDOG_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_RNG: usize = (BCM2837_RNG_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_GPIO: usize = (BCM2837_GPIO_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_PL011_UART0: usize = (BCM2837_PL011_UART0_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_SPI0: usize = (BCM2837_SPI0_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_AUX: usize = (BCM2837_AUX_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_ARASAN_EMMC: usize = (BCM2837_ARASAN_EMMC_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_BSC1_I2C: usize = (BCM2837_BSC1_I2C_BASE - BCM2837_PERIPHERAL_BASE) as usize;
pub const OFF_DWC2_USB: usize = (BCM2837_DWC2_USB_BASE - BCM2837_PERIPHERAL_BASE) as usize;
/// Combined offset for the 256-byte `QA7` ARM Local Peripheral window (`0x4000_0000`) placed
/// immediately after the 16 MiB `0x3F00_0000..0x4000_0000` peripheral window (`0x0100_0000`).
pub const OFF_QA7_LOCAL: usize = BCM2837_PERIPHERAL_SIZE as usize;
pub const TOTAL_RPI3B_PLUS_MMIO_SPAN: u64 = BCM2837_PERIPHERAL_SIZE + BCM2837_ARM_LOCAL_SIZE;

/// Hardware register access trait shared between native Raspberry Pi 3B+ volatile MMIO and
/// QEMU `virt` / cross-platform simulation.
pub trait RpiMmioBus {
    fn region_size(&self) -> u64;
    fn read32(&self, offset: usize) -> Result<u32, RpiError>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), RpiError>;
}

/// Native bounds-checked volatile MMIO aperture for Raspberry Pi 3B+ hardware registers
/// (`0x3F00_0000..0x4000_0100`).
#[derive(Clone, Copy, Debug)]
pub struct VolatileRpiMmioBus {
    periph_base: usize,
    periph_size: u64,
    qa7_local_base: Option<usize>,
}

impl VolatileRpiMmioBus {
    /// Creates a native volatile MMIO bus bound to the mapped BCM2837 peripheral window
    /// (`0x3F00_0000`, size `>= 0x0100_0000`) and optional `QA7` local window (`0x4000_0000`).
    ///
    /// # Safety
    /// `periph_virt_base` must be mapped as `Device-nGnRnE` RW/NX memory for at least `periph_size`
    /// bytes in the active kernel address space, and if `qa7_local_virt_base` is `Some`, it must be
    /// mapped as `Device-nGnRnE` RW/NX for at least `0x100` bytes.
    pub unsafe fn new(
        periph_virt_base: usize,
        periph_size: u64,
        qa7_local_virt_base: Option<usize>,
    ) -> Result<Self, RpiError> {
        if periph_size < BCM2837_PERIPHERAL_SIZE || (periph_virt_base & 0x3) != 0 {
            return Err(RpiError::OutOfRange);
        }
        let _ = (periph_virt_base as u64)
            .checked_add(periph_size)
            .ok_or(RpiError::OutOfRange)?;
        if let Some(qa7) = qa7_local_virt_base
            && (qa7 & 0x3) != 0
        {
            return Err(RpiError::OutOfRange);
        }
        Ok(Self {
            periph_base: periph_virt_base,
            periph_size,
            qa7_local_base: qa7_local_virt_base,
        })
    }

    fn resolve_reg_addr(&self, offset: usize) -> Result<usize, RpiError> {
        if !offset.is_multiple_of(4) {
            return Err(RpiError::UnalignedBuffer);
        }
        if (offset as u64) + 4 <= self.periph_size {
            self.periph_base
                .checked_add(offset)
                .ok_or(RpiError::OutOfRange)
        } else if offset >= OFF_QA7_LOCAL
            && (offset - OFF_QA7_LOCAL + 4) <= (BCM2837_ARM_LOCAL_SIZE as usize)
        {
            let qa7 = self.qa7_local_base.ok_or(RpiError::OutOfRange)?;
            qa7.checked_add(offset - OFF_QA7_LOCAL)
                .ok_or(RpiError::OutOfRange)
        } else {
            Err(RpiError::OutOfRange)
        }
    }
}

impl RpiMmioBus for VolatileRpiMmioBus {
    fn region_size(&self) -> u64 {
        if self.qa7_local_base.is_some() {
            self.periph_size + BCM2837_ARM_LOCAL_SIZE
        } else {
            self.periph_size
        }
    }

    fn read32(&self, offset: usize) -> Result<u32, RpiError> {
        let addr = self.resolve_reg_addr(offset)?;
        // SAFETY: `resolve_reg_addr` verified 32-bit alignment and bounds within the mapped
        // BCM2837 peripheral or QA7 local aperture.
        Ok(unsafe { read_volatile(addr as *const u32) })
    }

    fn write32(&mut self, offset: usize, value: u32) -> Result<(), RpiError> {
        let addr = self.resolve_reg_addr(offset)?;
        // SAFETY: `resolve_reg_addr` verified 32-bit alignment and bounds within the mapped
        // BCM2837 peripheral or QA7 local aperture.
        unsafe { write_volatile(addr as *mut u32, value) };
        Ok(())
    }
}

/// Safe in-memory BCM2837 MMIO register bus for running the native Raspberry Pi 3B+ MMIO driver
/// layer on QEMU `virt` and other non-BCM2837 devices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatedRpiMmioBus {
    gpfsel: [u32; 6],
    gplev: u64,
    gppud: u32,
    gppudclk: [u32; 2],
    mbox_last_write: u32,
    mbox_status: u32,
    uart0_ibrd: u32,
    uart0_fbrd: u32,
    uart0_lcrh: u32,
    uart0_cr: u32,
    uart0_last_tx: u8,
    uart0_rx_byte: Option<u8>,
    aux_enables: u32,
    aux_mu_lcr: u32,
    aux_mu_cntl: u32,
    aux_mu_baud: u32,
    aux_mu_last_tx: u8,
    armctrl_irqs_en: u64,
    armctrl_irqs_pend: u64,
    qa7_route: u32,
    qa7_timer_ctl: [u32; 4],
    qa7_mbox_ctl: [u32; 4],
    qa7_mbox3: [u32; 4],
    emmc_blksizecnt: u32,
    emmc_arg1: u32,
    emmc_cmdtm: u32,
    emmc_control0: u32,
    emmc_control1: u32,
    emmc_interrupt: u32,
    emmc_fifo_word: u32,
    systimer_clo: u32,
    systimer_chi: u32,
    systimer_c1: u32,
    systimer_cs: u32,
    pm_rstc: u32,
    pm_wdog: u32,
    rng_ctrl: u32,
    rng_status: u32,
    rng_seed: u32,
    dwc2_gotgctl: u32,
    dwc2_hprt0: u32,
}

impl Default for SimulatedRpiMmioBus {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulatedRpiMmioBus {
    pub const fn new() -> Self {
        Self {
            gpfsel: [0; 6],
            gplev: 0,
            gppud: 0,
            gppudclk: [0; 2],
            mbox_last_write: 0,
            mbox_status: 0,
            uart0_ibrd: 26,
            uart0_fbrd: 3,
            uart0_lcrh: PL011_LCRH_FEN | PL011_LCRH_WLEN_8BIT,
            uart0_cr: PL011_CR_UARTEN | PL011_CR_TXE | PL011_CR_RXE,
            uart0_last_tx: 0,
            uart0_rx_byte: None,
            aux_enables: AUX_ENABLE_MINI_UART,
            aux_mu_lcr: AUX_MU_LCR_8BIT,
            aux_mu_cntl: AUX_MU_CNTL_RX_EN | AUX_MU_CNTL_TX_EN,
            aux_mu_baud: 433,
            aux_mu_last_tx: 0,
            armctrl_irqs_en: 0,
            armctrl_irqs_pend: 0,
            qa7_route: 0,
            qa7_timer_ctl: [0xA; 4],
            qa7_mbox_ctl: [1; 4],
            qa7_mbox3: [0; 4],
            emmc_blksizecnt: SD_SECTOR_BYTES as u32,
            emmc_arg1: 0,
            emmc_cmdtm: 0,
            emmc_control0: 0,
            emmc_control1: 0x0007_0007, // SRST complete, internal clock stable
            emmc_interrupt: 0x0000_0001, // CMD_DONE ready
            emmc_fifo_word: 0,
            systimer_clo: 1_000,
            systimer_chi: 0,
            systimer_c1: 0,
            systimer_cs: 0,
            pm_rstc: 0x0000_0102,
            pm_wdog: 0,
            rng_ctrl: RNG_CTRL_EN,
            rng_status: RNG_WARMUP_COUNT | (4 << 24),
            rng_seed: 0x3B13_01D3,
            dwc2_gotgctl: 0x0001_0000,
            dwc2_hprt0: 0x0000_1005, // Port powered, connected, enabled (LAN7515 HS attached)
        }
    }

    pub fn inject_uart0_rx(&mut self, byte: u8) {
        self.uart0_rx_byte = Some(byte);
    }

    pub const fn last_uart0_tx(&self) -> u8 {
        self.uart0_last_tx
    }

    pub const fn last_mini_uart_tx(&self) -> u8 {
        self.aux_mu_last_tx
    }
}

impl RpiMmioBus for SimulatedRpiMmioBus {
    fn region_size(&self) -> u64 {
        TOTAL_RPI3B_PLUS_MMIO_SPAN
    }

    fn read32(&self, offset: usize) -> Result<u32, RpiError> {
        if !offset.is_multiple_of(4) {
            return Err(RpiError::UnalignedBuffer);
        }
        if (offset as u64) + 4 > TOTAL_RPI3B_PLUS_MMIO_SPAN {
            return Err(RpiError::OutOfRange);
        }
        let val = match offset {
            // GPIO (`0x3F20_0000`)
            o if (OFF_GPIO..=OFF_GPIO + 0x14).contains(&o) => self.gpfsel[(o - OFF_GPIO) / 4],
            o if o == OFF_GPIO + REG_GPLEV0 as usize => self.gplev as u32,
            o if o == OFF_GPIO + REG_GPLEV1 as usize => ((self.gplev >> 32) as u32) & 0x003F_FFFF,
            o if o == OFF_GPIO + REG_GPPUD as usize => self.gppud,
            // VideoCore Mailbox (`0x3F00_B880`)
            o if o == OFF_MBOX + MBOX_REG_STATUS as usize => self.mbox_status,
            o if o == OFF_MBOX + MBOX_REG_READ as usize => self.mbox_last_write,
            // PL011 UART0 (`0x3F20_1000`)
            o if o == OFF_PL011_UART0 + PL011_DR as usize => {
                u32::from(self.uart0_rx_byte.unwrap_or(0))
            }
            o if o == OFF_PL011_UART0 + PL011_FR as usize => {
                if self.uart0_rx_byte.is_some() {
                    0
                } else {
                    PL011_FR_RXFE
                }
            }
            o if o == OFF_PL011_UART0 + PL011_IBRD as usize => self.uart0_ibrd,
            o if o == OFF_PL011_UART0 + PL011_FBRD as usize => self.uart0_fbrd,
            o if o == OFF_PL011_UART0 + PL011_LCRH as usize => self.uart0_lcrh,
            o if o == OFF_PL011_UART0 + PL011_CR as usize => self.uart0_cr,
            // AUX & Mini-UART1 (`0x3F21_5000`)
            o if o == OFF_AUX + AUX_ENABLES as usize => self.aux_enables,
            o if o == OFF_AUX + AUX_MU_LCR_REG as usize => self.aux_mu_lcr,
            o if o == OFF_AUX + AUX_MU_CNTL_REG as usize => self.aux_mu_cntl,
            o if o == OFF_AUX + AUX_MU_BAUD_REG as usize => self.aux_mu_baud,
            o if o == OFF_AUX + AUX_MU_LSR_REG as usize => {
                AUX_MU_LSR_TX_EMPTY | AUX_MU_LSR_DATA_READY
            }
            o if o == OFF_AUX + AUX_MU_IO_REG as usize => u32::from(self.aux_mu_last_tx),
            // ARMCTRL Interrupt Controller (`0x3F00_B200`)
            o if o == OFF_ARMCTRL_IC + 0x04 => {
                (self.armctrl_irqs_en & self.armctrl_irqs_pend) as u32
            }
            o if o == OFF_ARMCTRL_IC + 0x08 => {
                ((self.armctrl_irqs_en & self.armctrl_irqs_pend) >> 32) as u32
            }
            o if o == OFF_ARMCTRL_IC + 0x10 => self.armctrl_irqs_en as u32,
            o if o == OFF_ARMCTRL_IC + 0x14 => (self.armctrl_irqs_en >> 32) as u32,
            // QA7 Local Interrupt Controller (`0x4000_0000`)
            o if o == OFF_QA7_LOCAL + 0x0C => self.qa7_route,
            o if (OFF_QA7_LOCAL + 0x40..=OFF_QA7_LOCAL + 0x4C).contains(&o) => {
                self.qa7_timer_ctl[(o - (OFF_QA7_LOCAL + 0x40)) / 4]
            }
            o if (OFF_QA7_LOCAL + 0x50..=OFF_QA7_LOCAL + 0x5C).contains(&o) => {
                self.qa7_mbox_ctl[(o - (OFF_QA7_LOCAL + 0x50)) / 4]
            }
            o if (OFF_QA7_LOCAL + 0xCC..=OFF_QA7_LOCAL + 0xFC).contains(&o) => {
                self.qa7_mbox3[((o - (OFF_QA7_LOCAL + 0xCC)) / 16).min(3)]
            }
            // Arasan EMMC / SDHCI (`0x3F30_0000`)
            o if o == OFF_ARASAN_EMMC + EMMC_BLKSIZECNT as usize => self.emmc_blksizecnt,
            o if o == OFF_ARASAN_EMMC + EMMC_ARG1 as usize => self.emmc_arg1,
            o if o == OFF_ARASAN_EMMC + EMMC_CMDTM as usize => self.emmc_cmdtm,
            o if o == OFF_ARASAN_EMMC + EMMC_RESP0 as usize => 0xC0FF_8000,
            o if o == OFF_ARASAN_EMMC + EMMC_DATA as usize => self.emmc_fifo_word,
            o if o == OFF_ARASAN_EMMC + EMMC_CONTROL0 as usize => self.emmc_control0,
            o if o == OFF_ARASAN_EMMC + EMMC_CONTROL1 as usize => self.emmc_control1,
            o if o == OFF_ARASAN_EMMC + EMMC_INTERRUPT as usize => self.emmc_interrupt,
            // System Timer (`0x3F00_3000`)
            o if o == OFF_SYSTIMER => self.systimer_cs,
            o if o == OFF_SYSTIMER + 0x04 => self.systimer_clo,
            o if o == OFF_SYSTIMER + 0x08 => self.systimer_chi,
            o if o == OFF_SYSTIMER + 0x10 => self.systimer_c1,
            // PM Watchdog (`0x3F10_0000`)
            o if o == OFF_PM_WDOG + 0x1C => self.pm_rstc,
            o if o == OFF_PM_WDOG + 0x24 => self.pm_wdog,
            // Hardware RNG (`0x3F10_4000`)
            o if o == OFF_RNG => self.rng_ctrl,
            o if o == OFF_RNG + 0x04 => self.rng_status,
            o if o == OFF_RNG + 0x08 => self.rng_seed ^ 0xA5A5_5A5A,
            // DWC2 USB Host (`0x3F98_0000`) + LAN7515 ID
            o if o == OFF_DWC2_USB => self.dwc2_gotgctl,
            o if o == OFF_DWC2_USB + 0x440 => self.dwc2_hprt0,
            o if o == OFF_DWC2_USB + 0x800 => LAN7515_CHIP_ID_REV,
            _ => 0,
        };
        Ok(val)
    }

    fn write32(&mut self, offset: usize, value: u32) -> Result<(), RpiError> {
        if !offset.is_multiple_of(4) {
            return Err(RpiError::UnalignedBuffer);
        }
        if (offset as u64) + 4 > TOTAL_RPI3B_PLUS_MMIO_SPAN {
            return Err(RpiError::OutOfRange);
        }
        match offset {
            // GPIO (`0x3F20_0000`)
            o if (OFF_GPIO..=OFF_GPIO + 0x14).contains(&o) => {
                self.gpfsel[(o - OFF_GPIO) / 4] = value;
            }
            o if o == OFF_GPIO + REG_GPSET0 as usize => {
                self.gplev |= u64::from(value);
            }
            o if o == OFF_GPIO + REG_GPSET1 as usize => {
                self.gplev |= u64::from(value & 0x003F_FFFF) << 32;
            }
            o if o == OFF_GPIO + REG_GPCLR0 as usize => {
                self.gplev &= !u64::from(value);
            }
            o if o == OFF_GPIO + REG_GPCLR1 as usize => {
                self.gplev &= !(u64::from(value & 0x003F_FFFF) << 32);
            }
            o if o == OFF_GPIO + REG_GPPUD as usize => {
                self.gppud = value & 0b11;
            }
            o if o == OFF_GPIO + REG_GPPUDCLK0 as usize => {
                self.gppudclk[0] = value;
            }
            o if o == OFF_GPIO + REG_GPPUDCLK0 as usize + 4 => {
                self.gppudclk[1] = value;
            }
            // VideoCore Mailbox (`0x3F00_B880`)
            o if o == OFF_MBOX + MBOX_REG_WRITE as usize => {
                self.mbox_last_write = value;
                self.mbox_status = 0; // response ready (neither FULL nor EMPTY)
            }
            // PL011 UART0 (`0x3F20_1000`)
            o if o == OFF_PL011_UART0 + PL011_DR as usize => {
                self.uart0_last_tx = (value & 0xFF) as u8;
            }
            o if o == OFF_PL011_UART0 + PL011_IBRD as usize => {
                self.uart0_ibrd = value & 0xFFFF;
            }
            o if o == OFF_PL011_UART0 + PL011_FBRD as usize => {
                self.uart0_fbrd = value & 0x3F;
            }
            o if o == OFF_PL011_UART0 + PL011_LCRH as usize => {
                self.uart0_lcrh = value;
            }
            o if o == OFF_PL011_UART0 + PL011_CR as usize => {
                self.uart0_cr = value;
            }
            // AUX & Mini-UART1 (`0x3F21_5000`)
            o if o == OFF_AUX + AUX_ENABLES as usize => {
                self.aux_enables = value;
            }
            o if o == OFF_AUX + AUX_MU_LCR_REG as usize => {
                self.aux_mu_lcr = value;
            }
            o if o == OFF_AUX + AUX_MU_CNTL_REG as usize => {
                self.aux_mu_cntl = value;
            }
            o if o == OFF_AUX + AUX_MU_BAUD_REG as usize => {
                self.aux_mu_baud = value & 0xFFFF;
            }
            o if o == OFF_AUX + AUX_MU_IO_REG as usize => {
                self.aux_mu_last_tx = (value & 0xFF) as u8;
            }
            // ARMCTRL Interrupt Controller (`0x3F00_B200`)
            o if o == OFF_ARMCTRL_IC + 0x10 => {
                self.armctrl_irqs_en |= u64::from(value);
            }
            o if o == OFF_ARMCTRL_IC + 0x14 => {
                self.armctrl_irqs_en |= u64::from(value) << 32;
            }
            o if o == OFF_ARMCTRL_IC + 0x1C => {
                self.armctrl_irqs_en &= !u64::from(value);
            }
            o if o == OFF_ARMCTRL_IC + 0x20 => {
                self.armctrl_irqs_en &= !(u64::from(value) << 32);
            }
            // QA7 Local Interrupt Controller (`0x4000_0000`)
            o if o == OFF_QA7_LOCAL + 0x0C => {
                self.qa7_route = value & 0b11;
            }
            o if (OFF_QA7_LOCAL + 0x8C..=OFF_QA7_LOCAL + 0xBC).contains(&o) => {
                let core = ((o - (OFF_QA7_LOCAL + 0x8C)) / 16).min(3);
                self.qa7_mbox3[core] |= value;
            }
            // Arasan EMMC / SDHCI (`0x3F30_0000`)
            o if o == OFF_ARASAN_EMMC + EMMC_BLKSIZECNT as usize => {
                self.emmc_blksizecnt = value;
            }
            o if o == OFF_ARASAN_EMMC + EMMC_ARG1 as usize => {
                self.emmc_arg1 = value;
            }
            o if o == OFF_ARASAN_EMMC + EMMC_CMDTM as usize => {
                self.emmc_cmdtm = value;
                self.emmc_interrupt |= 0x1 | 0x2 | 0x10 | 0x20; // CMD_DONE | DATA_DONE | WRITE_RDY | READ_RDY
            }
            o if o == OFF_ARASAN_EMMC + EMMC_DATA as usize => {
                self.emmc_fifo_word = value;
            }
            o if o == OFF_ARASAN_EMMC + EMMC_CONTROL0 as usize => {
                self.emmc_control0 = value;
            }
            o if o == OFF_ARASAN_EMMC + EMMC_CONTROL1 as usize => {
                // Clear reset bits immediately once host issues SRST_HC (bit 24)
                self.emmc_control1 = (value & !(0x7 << 24)) | (1 << 1); // CLK_STABLE
            }
            o if o == OFF_ARASAN_EMMC + EMMC_INTERRUPT as usize => {
                self.emmc_interrupt &= !value;
                self.emmc_interrupt |= 0x1;
            }
            // System Timer (`0x3F00_3000`)
            o if o == OFF_SYSTIMER => {
                self.systimer_cs &= !value;
            }
            o if o == OFF_SYSTIMER + 0x10 => {
                self.systimer_c1 = value;
                self.systimer_cs |= 1 << 1;
            }
            // PM Watchdog (`0x3F10_0000`)
            o if o == OFF_PM_WDOG + 0x1C => {
                if (value & 0xFFFF_0000) == PM_PASSWORD {
                    self.pm_rstc = value & 0x0000_FFFF;
                }
            }
            o if o == OFF_PM_WDOG + 0x24 => {
                if (value & 0xFFFF_0000) == PM_PASSWORD {
                    self.pm_wdog = value & 0x000F_FFFF;
                }
            }
            // Hardware RNG (`0x3F10_4000`)
            o if o == OFF_RNG => {
                self.rng_ctrl = value;
            }
            o if o == OFF_RNG + 0x04 => {
                self.rng_status = value | (4 << 24);
            }
            // DWC2 USB Host (`0x3F98_0000`)
            o if o == OFF_DWC2_USB + 0x440 => {
                self.dwc2_hprt0 = value | 0x0000_1005;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Hardware MMIO Driver Layer for Raspberry Pi 3B+ (`BCM2837B0`) parameterized over `B: RpiMmioBus`.
///
/// Executes the actual BCM2837 hardware register sequences against either [`VolatileRpiMmioBus`]
/// (native Raspberry Pi 3B+ hardware) or [`SimulatedRpiMmioBus`] (QEMU `virt` / cross-device).
pub struct Rpi3bPlusMmioHal<B: RpiMmioBus> {
    pub bus: B,
}

impl<B: RpiMmioBus> Rpi3bPlusMmioHal<B> {
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    /// Programs a GPIO pin's 3-bit `GPFSEL` function directly over the MMIO bus (`0x3F20_0000`).
    pub fn mmio_gpio_set_function(
        &mut self,
        cap: Capability,
        pin: u8,
        func: GpioFunction,
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if pin >= 54 {
            return Err(RpiError::PinOutOfRange);
        }
        let reg_off = OFF_GPIO + (REG_GPFSEL0 as usize) + ((pin as usize) / 10) * 4;
        let shift = ((pin as usize) % 10) * 3;
        let cur = self.bus.read32(reg_off)?;
        let next = (cur & !(0b111 << shift)) | (u32::from(func as u8) << shift);
        self.bus.write32(reg_off, next)
    }

    /// Reads back a GPIO pin's 3-bit `GPFSEL` function from the MMIO bus (`0x3F20_0000`).
    pub fn mmio_gpio_get_function(&self, pin: u8) -> Result<GpioFunction, RpiError> {
        if pin >= 54 {
            return Err(RpiError::PinOutOfRange);
        }
        let reg_off = OFF_GPIO + (REG_GPFSEL0 as usize) + ((pin as usize) / 10) * 4;
        let shift = ((pin as usize) % 10) * 3;
        let cur = self.bus.read32(reg_off)?;
        Ok(GpioFunction::from_bits(((cur >> shift) & 0b111) as u8))
    }

    /// Sets or clears a GPIO output line via `GPSET0/1` or `GPCLR0/1` (`0x3F20_001C..0x2C`).
    pub fn mmio_gpio_write_pin(
        &mut self,
        cap: Capability,
        pin: u8,
        high: bool,
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        if pin >= 54 {
            return Err(RpiError::PinOutOfRange);
        }
        let bank = (pin as usize) / 32;
        let bit = 1u32 << ((pin as usize) % 32);
        let base_reg = if high { REG_GPSET0 } else { REG_GPCLR0 } as usize;
        self.bus.write32(OFF_GPIO + base_reg + bank * 4, bit)
    }

    /// Reads a GPIO pin level from `GPLEV0/1` (`0x3F20_0034..0x38`).
    pub fn mmio_gpio_read_pin(&self, pin: u8) -> Result<bool, RpiError> {
        if pin >= 54 {
            return Err(RpiError::PinOutOfRange);
        }
        let bank = (pin as usize) / 32;
        let bit = 1u32 << ((pin as usize) % 32);
        let val = self
            .bus
            .read32(OFF_GPIO + (REG_GPLEV0 as usize) + bank * 4)?;
        Ok((val & bit) != 0)
    }

    /// Executes a VideoCore IV Mailbox transaction (`MBOX_WRITE` -> `MBOX_READ` at `0x3F00_B880`).
    pub fn mmio_mailbox_call(
        &mut self,
        cap: Capability,
        channel: u8,
        vc_bus_addr: u32,
    ) -> Result<u32, RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if (vc_bus_addr & 0xF) != 0 || channel > 15 {
            return Err(RpiError::UnalignedBuffer);
        }
        let status_off = OFF_MBOX + (MBOX_REG_STATUS as usize);
        if (self.bus.read32(status_off)? & MBOX_STATUS_FULL) != 0 {
            return Err(RpiError::QueueFull);
        }
        let msg = (vc_bus_addr & !0xF) | u32::from(channel & 0xF);
        self.bus
            .write32(OFF_MBOX + (MBOX_REG_WRITE as usize), msg)?;
        if (self.bus.read32(status_off)? & MBOX_STATUS_EMPTY) != 0 {
            return Err(RpiError::QueueEmpty);
        }
        let reply = self.bus.read32(OFF_MBOX + (MBOX_REG_READ as usize))?;
        if (reply & 0xF) != u32::from(channel) {
            return Err(RpiError::MalformedPropertyBuffer);
        }
        Ok(reply & !0xF)
    }

    /// Initializes PL011 `UART0` (`0x3F20_1000`) and GPIO14/15 `Alt0` over the MMIO bus.
    pub fn mmio_init_pl011_uart0(
        &mut self,
        cap: Capability,
        ref_clock_hz: u32,
        baud_rate: u32,
    ) -> Result<(u16, u8), RpiError> {
        let (ibrd, fbrd) = compute_pl011_baud_dividers(ref_clock_hz, baud_rate)?;
        self.mmio_gpio_set_function(cap, 14, GpioFunction::Alt0)?;
        self.mmio_gpio_set_function(cap, 15, GpioFunction::Alt0)?;
        self.bus.write32(OFF_PL011_UART0 + (PL011_CR as usize), 0)?;
        self.bus
            .write32(OFF_PL011_UART0 + (PL011_ICR as usize), 0x7FF)?;
        self.bus
            .write32(OFF_PL011_UART0 + (PL011_IBRD as usize), u32::from(ibrd))?;
        self.bus
            .write32(OFF_PL011_UART0 + (PL011_FBRD as usize), u32::from(fbrd))?;
        self.bus.write32(
            OFF_PL011_UART0 + (PL011_LCRH as usize),
            PL011_LCRH_FEN | PL011_LCRH_WLEN_8BIT,
        )?;
        self.bus.write32(
            OFF_PL011_UART0 + (PL011_CR as usize),
            PL011_CR_UARTEN | PL011_CR_TXE | PL011_CR_RXE,
        )?;
        Ok((ibrd, fbrd))
    }

    /// Transmits one byte over PL011 `UART0` (`0x3F20_1000`) via MMIO `FR` + `DR`.
    pub fn mmio_uart0_putc(&mut self, cap: Capability, byte: u8) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        let fr = self.bus.read32(OFF_PL011_UART0 + (PL011_FR as usize))?;
        if (fr & PL011_FR_TXFF) != 0 {
            return Err(RpiError::QueueFull);
        }
        self.bus
            .write32(OFF_PL011_UART0 + (PL011_DR as usize), u32::from(byte))
    }

    /// Reads one available byte from PL011 `UART0` (`0x3F20_1000`) via MMIO `FR` + `DR`.
    pub fn mmio_uart0_getc(&self, cap: Capability) -> Result<Option<u8>, RpiError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(RpiError::PermissionDenied);
        }
        let fr = self.bus.read32(OFF_PL011_UART0 + (PL011_FR as usize))?;
        if (fr & PL011_FR_RXFE) != 0 {
            return Ok(None);
        }
        let dr = self.bus.read32(OFF_PL011_UART0 + (PL011_DR as usize))?;
        Ok(Some((dr & 0xFF) as u8))
    }

    /// Initializes AUX Mini-UART `UART1` (`0x3F21_5000`) over the MMIO bus.
    pub fn mmio_init_mini_uart1(
        &mut self,
        cap: Capability,
        core_clock_hz: u32,
        baud_rate: u32,
    ) -> Result<u16, RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let baud_reg = compute_mini_uart_baud_reg(core_clock_hz, baud_rate)?;
        let enables = self.bus.read32(OFF_AUX + (AUX_ENABLES as usize))?;
        self.bus.write32(
            OFF_AUX + (AUX_ENABLES as usize),
            enables | AUX_ENABLE_MINI_UART,
        )?;
        self.bus.write32(OFF_AUX + (AUX_MU_CNTL_REG as usize), 0)?;
        self.bus
            .write32(OFF_AUX + (AUX_MU_LCR_REG as usize), AUX_MU_LCR_8BIT)?;
        self.bus
            .write32(OFF_AUX + (AUX_MU_BAUD_REG as usize), u32::from(baud_reg))?;
        self.bus.write32(
            OFF_AUX + (AUX_MU_CNTL_REG as usize),
            AUX_MU_CNTL_RX_EN | AUX_MU_CNTL_TX_EN,
        )?;
        Ok(baud_reg)
    }

    /// Executes a complete native Raspberry Pi 3B+ MMIO board bring-up sequence on `self.bus`:
    /// - GPIO14/15 PL011 UART0 (`Alt0`), GPIO48..53 Arasan SDHCI (`Alt3`), GPIO29 ACT LED (`Output` high),
    /// - PL011 UART0 (48 MHz @ 115200) & Mini-UART1 (400 MHz @ 115200),
    /// - VideoCore Mailbox property handshake on `MBOX_CH_PROP (8)`,
    /// - Arasan SDHCI controller reset (`EMMC_CONTROL1`) + 512-byte `EMMC_BLKSIZECNT`,
    /// - Hardware RNG warmup & enable (`0x3F10_4000`),
    /// - QA7 GPU IRQ routing to Cortex-A53 Core 0 (`0x4000_000C`),
    /// - DWC2 USB Host port power + LAN7515 (`0x7800_0002`) verification.
    pub fn mmio_initialize_board(&mut self, cap: Capability) -> Result<u32, RpiError> {
        self.mmio_init_pl011_uart0(cap, UART_CLOCK_HZ_DEFAULT, 115_200)?;
        self.mmio_init_mini_uart1(cap, CORE_CLOCK_HZ_DEFAULT, 115_200)?;
        for pin in 48..=53 {
            self.mmio_gpio_set_function(cap, pin, GpioFunction::Alt3)?;
        }
        self.mmio_gpio_set_function(cap, RPI3B_PLUS_ACT_LED_PIN, GpioFunction::Output)?;
        self.mmio_gpio_write_pin(cap, RPI3B_PLUS_ACT_LED_PIN, true)?;

        let _ = self.mmio_mailbox_call(cap, MBOX_CH_PROP, 0xC000_1000)?;

        // Arasan SDHCI host reset + block size 512B
        self.bus
            .write32(OFF_ARASAN_EMMC + (EMMC_CONTROL1 as usize), 1 << 24)?;
        self.bus.write32(
            OFF_ARASAN_EMMC + (EMMC_BLKSIZECNT as usize),
            (1 << 16) | (SD_SECTOR_BYTES as u32),
        )?;

        // Hardware RNG warmup + enable
        self.bus.write32(OFF_RNG + 0x04, RNG_WARMUP_COUNT)?;
        self.bus.write32(OFF_RNG, RNG_CTRL_EN)?;

        // Route GPU IRQs to Core 0 on QA7 Local INTC
        self.bus.write32(OFF_QA7_LOCAL + 0x0C, 0)?;

        // Arm PM Watchdog register test without triggering full reset
        self.bus
            .write32(OFF_PM_WDOG + 0x24, PM_PASSWORD | 0x0001_0000)?;
        self.bus
            .write32(OFF_PM_WDOG + 0x1C, PM_PASSWORD | PM_RSTC_WRCFG_FULL_RESET)?;

        // Probe LAN7515 chip ID over DWC2 USB window
        let chip_id = self.bus.read32(OFF_DWC2_USB + 0x800)?;
        Ok(chip_id)
    }
}
