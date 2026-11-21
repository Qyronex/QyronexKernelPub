// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! BCM2837 Dual UART Drivers for Raspberry Pi 3B+:
//! - PrimeCell PL011 `UART0` (`0x3F20_1000`, `brcm,bcm2835-pl011`, 48 MHz reference clock)
//! - AUX Mini-UART `UART1` (`0x3F21_5000` / `0x3F21_5040`, `brcm,bcm2835-aux-uart`, VPU core clock)

use crate::{CORE_CLOCK_HZ_DEFAULT, RpiError, UART_CLOCK_HZ_DEFAULT};
use kernal_capability::{CapRights, Capability};

pub const UART_FIFO_CAPACITY: usize = 64;

// PL011 register offsets
pub const PL011_DR: u64 = 0x00;
pub const PL011_FR: u64 = 0x18;
pub const PL011_IBRD: u64 = 0x24;
pub const PL011_FBRD: u64 = 0x28;
pub const PL011_LCRH: u64 = 0x2C;
pub const PL011_CR: u64 = 0x30;
pub const PL011_IMSC: u64 = 0x38;
pub const PL011_ICR: u64 = 0x44;

pub const PL011_FR_RXFE: u32 = 1 << 4;
pub const PL011_FR_TXFF: u32 = 1 << 5;
pub const PL011_LCRH_FEN: u32 = 1 << 4;
pub const PL011_LCRH_WLEN_8BIT: u32 = 0b11 << 5;
pub const PL011_CR_UARTEN: u32 = 1 << 0;
pub const PL011_CR_TXE: u32 = 1 << 8;
pub const PL011_CR_RXE: u32 = 1 << 9;

// AUX Mini-UART register offsets from `0x3F21_5000`
pub const AUX_IRQ: u64 = 0x00;
pub const AUX_ENABLES: u64 = 0x04;
pub const AUX_MU_IO_REG: u64 = 0x40;
pub const AUX_MU_IER_REG: u64 = 0x44;
pub const AUX_MU_IIR_REG: u64 = 0x48;
pub const AUX_MU_LCR_REG: u64 = 0x4C;
pub const AUX_MU_MCR_REG: u64 = 0x50;
pub const AUX_MU_LSR_REG: u64 = 0x54;
pub const AUX_MU_CNTL_REG: u64 = 0x60;
pub const AUX_MU_STAT_REG: u64 = 0x64;
pub const AUX_MU_BAUD_REG: u64 = 0x68;

pub const AUX_ENABLE_MINI_UART: u32 = 1 << 0;
pub const AUX_MU_LCR_8BIT: u32 = 0x03;
pub const AUX_MU_LSR_DATA_READY: u32 = 1 << 0;
pub const AUX_MU_LSR_TX_EMPTY: u32 = 1 << 5;
pub const AUX_MU_LSR_TX_IDLE: u32 = 1 << 6;
pub const AUX_MU_CNTL_RX_EN: u32 = 1 << 0;
pub const AUX_MU_CNTL_TX_EN: u32 = 1 << 1;

/// Computes PL011 `(IBRD, FBRD)` dividers for `ref_clock_hz` and `baud_rate`.
/// Formula: `divider = ref_clock_hz / (16 * baud_rate)`, `FBRD = round(frac * 64)`.
pub const fn compute_pl011_baud_dividers(
    ref_clock_hz: u32,
    baud_rate: u32,
) -> Result<(u16, u8), RpiError> {
    if baud_rate == 0 || ref_clock_hz < 16 * baud_rate {
        return Err(RpiError::InvalidArgument);
    }
    let denom = 16u64 * (baud_rate as u64);
    let ibrd = (ref_clock_hz as u64) / denom;
    if ibrd == 0 || ibrd > u16::MAX as u64 {
        return Err(RpiError::InvalidArgument);
    }
    let rem = (ref_clock_hz as u64) % denom;
    let fbrd = ((rem * 64 + (denom / 2)) / denom) as u8;
    Ok((ibrd as u16, fbrd & 0x3F))
}

/// Computes BCM2837 AUX Mini-UART 16-bit `AUX_MU_BAUD` register value.
/// Formula: `baud_reg = (core_clock_hz / (8 * baud_rate)) - 1`.
pub const fn compute_mini_uart_baud_reg(
    core_clock_hz: u32,
    baud_rate: u32,
) -> Result<u16, RpiError> {
    if baud_rate == 0 || core_clock_hz < 8 * baud_rate {
        return Err(RpiError::InvalidArgument);
    }
    let div = (core_clock_hz as u64) / (8u64 * (baud_rate as u64));
    if div == 0 || div - 1 > u16::MAX as u64 {
        return Err(RpiError::InvalidArgument);
    }
    Ok((div - 1) as u16)
}

/// BCM2837 PL011 `UART0` (`0x3F20_1000`) driver state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pl011Uart0 {
    pub ref_clock_hz: u32,
    pub baud_rate: u32,
    pub ibrd: u16,
    pub fbrd: u8,
    pub lcrh: u32,
    pub cr: u32,
    pub imsc: u32,
    tx_fifo: [u8; UART_FIFO_CAPACITY],
    tx_len: usize,
    rx_fifo: [u8; UART_FIFO_CAPACITY],
    rx_head: usize,
    rx_len: usize,
}

impl Default for Pl011Uart0 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pl011Uart0 {
    pub const fn new() -> Self {
        Self {
            ref_clock_hz: UART_CLOCK_HZ_DEFAULT,
            baud_rate: 115_200,
            ibrd: 26,
            fbrd: 3,
            lcrh: PL011_LCRH_FEN | PL011_LCRH_WLEN_8BIT,
            cr: PL011_CR_UARTEN | PL011_CR_TXE | PL011_CR_RXE,
            imsc: 0,
            tx_fifo: [0; UART_FIFO_CAPACITY],
            tx_len: 0,
            rx_fifo: [0; UART_FIFO_CAPACITY],
            rx_head: 0,
            rx_len: 0,
        }
    }

    pub fn configure(
        &mut self,
        cap: Capability,
        ref_clock_hz: u32,
        baud_rate: u32,
    ) -> Result<(u16, u8), RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let (ibrd, fbrd) = compute_pl011_baud_dividers(ref_clock_hz, baud_rate)?;
        self.ref_clock_hz = ref_clock_hz;
        self.baud_rate = baud_rate;
        self.ibrd = ibrd;
        self.fbrd = fbrd;
        self.lcrh = PL011_LCRH_FEN | PL011_LCRH_WLEN_8BIT;
        self.cr = PL011_CR_UARTEN | PL011_CR_TXE | PL011_CR_RXE;
        Ok((ibrd, fbrd))
    }

    pub const fn flag_register(&self) -> u32 {
        let mut fr = 0u32;
        if self.rx_len == 0 {
            fr |= PL011_FR_RXFE;
        }
        if self.tx_len >= UART_FIFO_CAPACITY {
            fr |= PL011_FR_TXFF;
        }
        fr
    }

    pub fn write_bytes(&mut self, cap: Capability, data: &[u8]) -> Result<usize, RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        if (self.cr & (PL011_CR_UARTEN | PL011_CR_TXE)) != (PL011_CR_UARTEN | PL011_CR_TXE) {
            return Err(RpiError::DeviceNotReady);
        }
        let avail = UART_FIFO_CAPACITY.saturating_sub(self.tx_len);
        let take = data.len().min(avail);
        self.tx_fifo[self.tx_len..self.tx_len + take].copy_from_slice(&data[..take]);
        self.tx_len += take;
        Ok(take)
    }

    pub fn drain_tx(&mut self, out: &mut [u8]) -> usize {
        let take = self.tx_len.min(out.len());
        out[..take].copy_from_slice(&self.tx_fifo[..take]);
        self.tx_fifo.copy_within(take..self.tx_len, 0);
        self.tx_len -= take;
        take
    }

    pub fn inject_rx(&mut self, data: &[u8]) -> usize {
        let mut pushed = 0usize;
        for &b in data {
            if self.rx_len >= UART_FIFO_CAPACITY {
                break;
            }
            let pos = (self.rx_head + self.rx_len) % UART_FIFO_CAPACITY;
            self.rx_fifo[pos] = b;
            self.rx_len += 1;
            pushed += 1;
        }
        pushed
    }

    pub fn read_bytes(&mut self, cap: Capability, out: &mut [u8]) -> Result<usize, RpiError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(RpiError::PermissionDenied);
        }
        let take = self.rx_len.min(out.len());
        for slot in out.iter_mut().take(take) {
            *slot = self.rx_fifo[self.rx_head];
            self.rx_head = (self.rx_head + 1) % UART_FIFO_CAPACITY;
            self.rx_len -= 1;
        }
        Ok(take)
    }
}

/// BCM2837 AUX Mini-UART `UART1` (`0x3F21_5000` / `0x3F21_5040`) driver state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiniUart1 {
    pub aux_enables: u32,
    pub core_clock_hz: u32,
    pub baud_rate: u32,
    pub baud_reg: u16,
    pub lcr: u32,
    pub cntl: u32,
    tx_fifo: [u8; UART_FIFO_CAPACITY],
    tx_len: usize,
    rx_fifo: [u8; UART_FIFO_CAPACITY],
    rx_len: usize,
}

impl Default for MiniUart1 {
    fn default() -> Self {
        Self::new()
    }
}

impl MiniUart1 {
    pub const fn new() -> Self {
        Self {
            aux_enables: AUX_ENABLE_MINI_UART,
            core_clock_hz: CORE_CLOCK_HZ_DEFAULT,
            baud_rate: 115_200,
            baud_reg: 433, // 400_000_000 / (8 * 115200) - 1 = 433
            lcr: AUX_MU_LCR_8BIT,
            cntl: AUX_MU_CNTL_RX_EN | AUX_MU_CNTL_TX_EN,
            tx_fifo: [0; UART_FIFO_CAPACITY],
            tx_len: 0,
            rx_fifo: [0; UART_FIFO_CAPACITY],
            rx_len: 0,
        }
    }

    pub fn configure(
        &mut self,
        cap: Capability,
        core_clock_hz: u32,
        baud_rate: u32,
    ) -> Result<u16, RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        let baud_reg = compute_mini_uart_baud_reg(core_clock_hz, baud_rate)?;
        self.aux_enables |= AUX_ENABLE_MINI_UART;
        self.core_clock_hz = core_clock_hz;
        self.baud_rate = baud_rate;
        self.baud_reg = baud_reg;
        self.lcr = AUX_MU_LCR_8BIT;
        self.cntl = AUX_MU_CNTL_RX_EN | AUX_MU_CNTL_TX_EN;
        Ok(baud_reg)
    }

    pub const fn line_status(&self) -> u32 {
        let mut lsr = 0u32;
        if self.rx_len > 0 {
            lsr |= AUX_MU_LSR_DATA_READY;
        }
        if self.tx_len < UART_FIFO_CAPACITY {
            lsr |= AUX_MU_LSR_TX_EMPTY;
        }
        if self.tx_len == 0 {
            lsr |= AUX_MU_LSR_TX_IDLE;
        }
        lsr
    }

    pub fn write_bytes(&mut self, cap: Capability, data: &[u8]) -> Result<usize, RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        if (self.aux_enables & AUX_ENABLE_MINI_UART) == 0 || (self.cntl & AUX_MU_CNTL_TX_EN) == 0 {
            return Err(RpiError::DeviceNotReady);
        }
        let avail = UART_FIFO_CAPACITY.saturating_sub(self.tx_len);
        let take = data.len().min(avail);
        self.tx_fifo[self.tx_len..self.tx_len + take].copy_from_slice(&data[..take]);
        self.tx_len += take;
        Ok(take)
    }
}
