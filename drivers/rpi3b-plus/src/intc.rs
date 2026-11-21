// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! BCM2837 Interrupt Controllers for Raspberry Pi 3B+:
//! - Legacy BCM2835/2837 ARM Peripheral Interrupt Controller (`0x3F00_B200`, `brcm,bcm2836-armctrl-ic`)
//! - Quad-Core Cortex-A53 Local Interrupt Controller & SMP Mailbox (`QA7`, `0x4000_0000`, `brcm,bcm2836-l1-intc`)

use crate::RpiError;
use kernal_capability::{CapRights, Capability};

pub const BCM2837_CORE_COUNT: usize = 4;

// GPU peripheral IRQ numbers on BCM2837
pub const GPU_IRQ_SYSTIMER_C1: u8 = 1;
pub const GPU_IRQ_SYSTIMER_C3: u8 = 3;
pub const GPU_IRQ_USB_DWC2: u8 = 9;
pub const GPU_IRQ_AUX_MINI_UART: u8 = 29;
pub const GPU_IRQ_I2C_SPI_SLV: u8 = 43;
pub const GPU_IRQ_SMI: u8 = 48;
pub const GPU_IRQ_GPIO0: u8 = 49;
pub const GPU_IRQ_GPIO1: u8 = 50;
pub const GPU_IRQ_GPIO2: u8 = 51;
pub const GPU_IRQ_GPIO3: u8 = 52;
pub const GPU_IRQ_I2C: u8 = 53;
pub const GPU_IRQ_SPI: u8 = 54;
pub const GPU_IRQ_PL011_UART0: u8 = 57;
pub const GPU_IRQ_ARASAN_SDHCI: u8 = 62;

// QA7 local interrupt source bits (`CORE0_IRQ_SOURCE .. CORE3_IRQ_SOURCE` at `0x60..0x6C`)
pub const QA7_IRQ_SRC_CNTPSIRQ: u32 = 1 << 0;
pub const QA7_IRQ_SRC_CNTPNSIRQ: u32 = 1 << 1;
pub const QA7_IRQ_SRC_CNTHPIRQ: u32 = 1 << 2;
pub const QA7_IRQ_SRC_CNTVIRQ: u32 = 1 << 3;
pub const QA7_IRQ_SRC_MBOX0: u32 = 1 << 4;
pub const QA7_IRQ_SRC_MBOX1: u32 = 1 << 5;
pub const QA7_IRQ_SRC_MBOX2: u32 = 1 << 6;
pub const QA7_IRQ_SRC_MBOX3: u32 = 1 << 7;
pub const QA7_IRQ_SRC_GPU: u32 = 1 << 8;
pub const QA7_IRQ_SRC_PMU: u32 = 1 << 9;

/// BCM2837 ARM Peripheral Interrupt Controller (`0x3F00_B200`) covering 64 GPU IRQs + 8 basic IRQs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bcm2837ArmCtrlIc {
    pub enabled_gpu_irqs: u64,
    pub pending_gpu_irqs: u64,
    pub enabled_basic_irqs: u8,
    pub pending_basic_irqs: u8,
}

impl Default for Bcm2837ArmCtrlIc {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcm2837ArmCtrlIc {
    pub const fn new() -> Self {
        Self {
            enabled_gpu_irqs: 0,
            pending_gpu_irqs: 0,
            enabled_basic_irqs: 0,
            pending_basic_irqs: 0,
        }
    }

    pub fn enable_gpu_irq(&mut self, cap: Capability, irq: u8) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if irq >= 64 {
            return Err(RpiError::OutOfRange);
        }
        self.enabled_gpu_irqs |= 1u64 << irq;
        Ok(())
    }

    pub fn disable_gpu_irq(&mut self, cap: Capability, irq: u8) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if irq >= 64 {
            return Err(RpiError::OutOfRange);
        }
        self.enabled_gpu_irqs &= !(1u64 << irq);
        Ok(())
    }

    pub fn assert_gpu_irq(&mut self, irq: u8) -> Result<(), RpiError> {
        if irq >= 64 {
            return Err(RpiError::OutOfRange);
        }
        self.pending_gpu_irqs |= 1u64 << irq;
        Ok(())
    }

    pub fn clear_gpu_irq(&mut self, irq: u8) -> Result<(), RpiError> {
        if irq >= 64 {
            return Err(RpiError::OutOfRange);
        }
        self.pending_gpu_irqs &= !(1u64 << irq);
        Ok(())
    }

    pub const fn active_gpu_irqs(&self) -> u64 {
        self.enabled_gpu_irqs & self.pending_gpu_irqs
    }

    pub const fn irq_pending_1(&self) -> u32 {
        self.active_gpu_irqs() as u32
    }

    pub const fn irq_pending_2(&self) -> u32 {
        (self.active_gpu_irqs() >> 32) as u32
    }

    pub const fn irq_basic_pending(&self) -> u32 {
        let mut basic = (self.enabled_basic_irqs & self.pending_basic_irqs) as u32;
        if self.irq_pending_1() != 0 {
            basic |= 1 << 8;
        }
        if self.irq_pending_2() != 0 {
            basic |= 1 << 9;
        }
        basic
    }
}

/// BCM2837 `QA7` Quad-A53 Local Interrupt Controller (`0x4000_0000`) + SMP Core Mailbox wakeup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Qa7LocalIntc {
    pub gpu_irq_target_core: u8,
    pub timer_irq_ctrl: [u32; BCM2837_CORE_COUNT],
    pub mbox_irq_ctrl: [u32; BCM2837_CORE_COUNT],
    pub mailboxes: [[u32; 4]; BCM2837_CORE_COUNT],
    pub timer_pending_mask: [u32; BCM2837_CORE_COUNT],
    pub core_entry_address: [u64; BCM2837_CORE_COUNT],
    pub core_online: [bool; BCM2837_CORE_COUNT],
}

impl Default for Qa7LocalIntc {
    fn default() -> Self {
        Self::new()
    }
}

impl Qa7LocalIntc {
    pub const fn new() -> Self {
        Self {
            gpu_irq_target_core: 0,
            // Enable CNTPNSIRQ and CNTVIRQ on all 4 Cortex-A53 cores by default
            timer_irq_ctrl: [QA7_IRQ_SRC_CNTPNSIRQ | QA7_IRQ_SRC_CNTVIRQ; BCM2837_CORE_COUNT],
            mbox_irq_ctrl: [1; BCM2837_CORE_COUNT], // Mailbox 0 IPI IRQ enabled per core
            mailboxes: [[0; 4]; BCM2837_CORE_COUNT],
            timer_pending_mask: [0; BCM2837_CORE_COUNT],
            core_entry_address: [0; BCM2837_CORE_COUNT],
            core_online: [true, false, false, false],
        }
    }

    const fn validate_core(core: u8) -> Result<usize, RpiError> {
        let idx = core as usize;
        if idx >= BCM2837_CORE_COUNT {
            Err(RpiError::CoreOutOfRange)
        } else {
            Ok(idx)
        }
    }

    pub fn route_gpu_irqs_to_core(&mut self, cap: Capability, core: u8) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let _ = Self::validate_core(core)?;
        self.gpu_irq_target_core = core;
        Ok(())
    }

    /// Writes-to-set bits in `core`'s `mbox` (`0..4`), used for SMP IPIs and secondary core wakeup.
    pub fn write_set_mailbox(
        &mut self,
        cap: Capability,
        core: u8,
        mbox: u8,
        bits: u32,
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        let c = Self::validate_core(core)?;
        if mbox >= 4 {
            return Err(RpiError::OutOfRange);
        }
        self.mailboxes[c][mbox as usize] |= bits;
        Ok(())
    }

    /// Writes-to-clear bits in `core`'s `mbox` (`0..4`), returns value prior to clearing.
    pub fn read_clear_mailbox(
        &mut self,
        cap: Capability,
        core: u8,
        mbox: u8,
        clear_bits: u32,
    ) -> Result<u32, RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        let c = Self::validate_core(core)?;
        if mbox >= 4 {
            return Err(RpiError::OutOfRange);
        }
        let prev = self.mailboxes[c][mbox as usize];
        self.mailboxes[c][mbox as usize] &= !clear_bits;
        Ok(prev)
    }

    /// Wakes secondary Cortex-A53 core `1..=3` via BCM2837 spin-table / QA7 mailbox 3 jump address.
    pub fn wake_secondary_core(
        &mut self,
        cap: Capability,
        core: u8,
        entry_phys_addr: u64,
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let c = Self::validate_core(core)?;
        if c == 0 || entry_phys_addr == 0 || (entry_phys_addr & 0x3) != 0 {
            return Err(RpiError::InvalidArgument);
        }
        self.core_entry_address[c] = entry_phys_addr;
        self.mailboxes[c][3] = entry_phys_addr as u32;
        self.core_online[c] = true;
        Ok(())
    }

    /// Computes the `CORE<n>_IRQ_SOURCE` (`0x60 + 4*n`) pending bitmask for `core`.
    pub fn core_irq_source(&self, core: u8, armctrl: &Bcm2837ArmCtrlIc) -> Result<u32, RpiError> {
        let c = Self::validate_core(core)?;
        let mut src = self.timer_pending_mask[c] & self.timer_irq_ctrl[c];
        for m in 0..4 {
            if self.mailboxes[c][m] != 0 && (self.mbox_irq_ctrl[c] & (1 << m)) != 0 {
                src |= QA7_IRQ_SRC_MBOX0 << m;
            }
        }
        if self.gpu_irq_target_core == core && armctrl.irq_basic_pending() != 0 {
            src |= QA7_IRQ_SRC_GPU;
        }
        Ok(src)
    }
}
