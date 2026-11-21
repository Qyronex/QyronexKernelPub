// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! BCM2837 Arasan SDHCI / EMMC Controller (`0x3F30_0000`, `brcm,bcm2835-sdhci` / `brcm,bcm2835-mmc`)
//! for Raspberry Pi 3B+.
//!
//! Mediates SDHC/SDXC block storage (512-byte sectors) with explicit SD command state transitions
//! (`CMD0`, `CMD8`, `CMD55` + `ACMD41`, `CMD2`, `CMD3`, `CMD7`, `CMD16`, `CMD17`, `CMD18`, `CMD24`,
//! `CMD25`), capability enforcement (`CapRights::READ`, `CapRights::WRITE`, `CapRights::CONTROL`),
//! IOMMU/DMA window verification (`DmaMapping`), and controller generation revocation on reset.

use crate::{RpiError, verify_dma_window};
use kernal_capability::{CapRights, Capability};
use kernal_iommu::{DmaMapping, DmaPerms};

pub const SD_SECTOR_BYTES: usize = 512;

// Arasan EMMC register offsets from `0x3F30_0000`
pub const EMMC_ARG2: u64 = 0x00;
pub const EMMC_BLKSIZECNT: u64 = 0x04;
pub const EMMC_ARG1: u64 = 0x08;
pub const EMMC_CMDTM: u64 = 0x0C;
pub const EMMC_RESP0: u64 = 0x10;
pub const EMMC_RESP1: u64 = 0x14;
pub const EMMC_RESP2: u64 = 0x18;
pub const EMMC_RESP3: u64 = 0x1C;
pub const EMMC_DATA: u64 = 0x20;
pub const EMMC_STATUS: u64 = 0x24;
pub const EMMC_CONTROL0: u64 = 0x28;
pub const EMMC_CONTROL1: u64 = 0x2C;
pub const EMMC_INTERRUPT: u64 = 0x30;
pub const EMMC_IRPT_MASK: u64 = 0x34;
pub const EMMC_IRPT_EN: u64 = 0x38;
pub const EMMC_CONTROL2: u64 = 0x3C;
pub const EMMC_SLOTISR_VER: u64 = 0xFC;

// SD command indices
pub const SD_CMD_GO_IDLE_STATE: u8 = 0;
pub const SD_CMD_ALL_SEND_CID: u8 = 2;
pub const SD_CMD_SEND_RELATIVE_ADDR: u8 = 3;
pub const SD_CMD_SELECT_CARD: u8 = 7;
pub const SD_CMD_SEND_IF_COND: u8 = 8;
pub const SD_CMD_STOP_TRANSMISSION: u8 = 12;
pub const SD_CMD_SET_BLOCKLEN: u8 = 16;
pub const SD_CMD_READ_SINGLE_BLOCK: u8 = 17;
pub const SD_CMD_READ_MULTIPLE_BLOCK: u8 = 18;
pub const SD_CMD_WRITE_BLOCK: u8 = 24;
pub const SD_CMD_WRITE_MULTIPLE_BLOCK: u8 = 25;
pub const SD_CMD_APP_CMD: u8 = 55;
pub const SD_ACMD_SD_SEND_OP_COND: u8 = 41;

/// SD Card protocol initialization state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdCardState {
    Reset,
    Idle,
    VoltageChecked,
    Ready,
    Identification,
    Standby,
    Transfer,
}

/// BCM2837 Arasan SDHCI / EMMC controller with `SECTORS` in-memory 512-byte blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bcm2837ArasanSdhci<const SECTORS: usize> {
    pub state: SdCardState,
    pub generation: u64,
    pub rca: u16,
    pub high_capacity_sdhc: bool,
    pub bus_width_4bit: bool,
    pub clock_hz: u32,
    pub app_cmd_pending: bool,
    pub last_resp: [u32; 4],
    pub read_only: bool,
    storage: [[u8; SD_SECTOR_BYTES]; SECTORS],
}

impl<const SECTORS: usize> Default for Bcm2837ArasanSdhci<SECTORS> {
    fn default() -> Self {
        Self::new(false)
    }
}

impl<const SECTORS: usize> Bcm2837ArasanSdhci<SECTORS> {
    pub const fn new(read_only: bool) -> Self {
        Self {
            state: SdCardState::Reset,
            generation: 1,
            rca: 0,
            high_capacity_sdhc: true,
            bus_width_4bit: false,
            clock_hz: 400_000,
            app_cmd_pending: false,
            last_resp: [0; 4],
            read_only,
            storage: [[0u8; SD_SECTOR_BYTES]; SECTORS],
        }
    }

    pub const fn capacity_sectors(&self) -> u64 {
        SECTORS as u64
    }

    /// Resets the Arasan SDHCI host controller (`CONTROL1.SRST_HC`), revoking previous generation.
    pub fn reset_controller(&mut self, cap: Capability) -> Result<u64, RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        self.state = SdCardState::Reset;
        self.generation = self.generation.saturating_add(1);
        self.rca = 0;
        self.bus_width_4bit = false;
        self.clock_hz = 400_000;
        self.app_cmd_pending = false;
        self.last_resp = [0; 4];
        Ok(self.generation)
    }

    /// Executes the full Raspberry Pi 3B+ SDHC initialization handshake (`CMD0 -> CMD8 -> ACMD41 -> CMD2 -> CMD3 -> CMD7 -> CMD16`).
    pub fn initialize_sdhc_card(&mut self, cap: Capability) -> Result<u64, RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        self.issue_command(cap, SD_CMD_GO_IDLE_STATE, 0)?;
        self.issue_command(cap, SD_CMD_SEND_IF_COND, 0x0000_01AA)?;
        self.issue_command(cap, SD_CMD_APP_CMD, 0)?;
        self.issue_command(cap, SD_ACMD_SD_SEND_OP_COND, 0x40FF_8000)?;
        self.issue_command(cap, SD_CMD_ALL_SEND_CID, 0)?;
        self.issue_command(cap, SD_CMD_SEND_RELATIVE_ADDR, 0)?;
        let rca_arg = u32::from(self.rca) << 16;
        self.issue_command(cap, SD_CMD_SELECT_CARD, rca_arg)?;
        self.issue_command(cap, SD_CMD_SET_BLOCKLEN, SD_SECTOR_BYTES as u32)?;
        self.bus_width_4bit = true;
        self.clock_hz = 50_000_000; // High-Speed 50 MHz SD clock
        Ok(self.generation)
    }

    /// Issues an individual SD/SDHCI command and updates `last_resp` and card state.
    pub fn issue_command(
        &mut self,
        cap: Capability,
        cmd_index: u8,
        arg: u32,
    ) -> Result<[u32; 4], RpiError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(RpiError::PermissionDenied);
        }
        if self.app_cmd_pending {
            self.app_cmd_pending = false;
            if cmd_index == SD_ACMD_SD_SEND_OP_COND {
                if self.state != SdCardState::VoltageChecked {
                    return Err(RpiError::DeviceNotReady);
                }
                self.high_capacity_sdhc = (arg & 0x4000_0000) != 0;
                // OCR busy cleared (bit 31) + CCS (bit 30) + 3.2-3.4V window
                self.last_resp = [0xC0FF_8000, 0, 0, 0];
                self.state = SdCardState::Ready;
                return Ok(self.last_resp);
            }
            return Err(RpiError::InvalidArgument);
        }

        match cmd_index {
            SD_CMD_GO_IDLE_STATE => {
                self.state = SdCardState::Idle;
                self.last_resp = [0; 4];
            }
            SD_CMD_SEND_IF_COND => {
                if self.state != SdCardState::Idle || (arg & 0xFF) != 0xAA {
                    return Err(RpiError::InvalidArgument);
                }
                self.state = SdCardState::VoltageChecked;
                self.last_resp = [arg & 0xFFF, 0, 0, 0];
            }
            SD_CMD_APP_CMD => {
                self.app_cmd_pending = true;
                self.last_resp = [0x0000_0120, 0, 0, 0];
            }
            SD_CMD_ALL_SEND_CID => {
                if self.state != SdCardState::Ready {
                    return Err(RpiError::DeviceNotReady);
                }
                self.state = SdCardState::Identification;
                // Synthetic Broadcom/Qyronex SDHC CID
                self.last_resp = [0x5159_5258, 0x5250_4933, 0x4250_3133, 0x0001_0000];
            }
            SD_CMD_SEND_RELATIVE_ADDR => {
                if self.state != SdCardState::Identification {
                    return Err(RpiError::DeviceNotReady);
                }
                self.rca = 0xB368;
                self.state = SdCardState::Standby;
                self.last_resp = [(u32::from(self.rca) << 16) | 0x0500, 0, 0, 0];
            }
            SD_CMD_SELECT_CARD => {
                if self.state != SdCardState::Standby || (arg >> 16) as u16 != self.rca {
                    return Err(RpiError::DeviceNotReady);
                }
                self.state = SdCardState::Transfer;
                self.last_resp = [0x0000_0700, 0, 0, 0];
            }
            SD_CMD_SET_BLOCKLEN => {
                if self.state != SdCardState::Transfer || arg as usize != SD_SECTOR_BYTES {
                    return Err(RpiError::InvalidArgument);
                }
                self.last_resp = [0x0000_0900, 0, 0, 0];
            }
            _ => return Err(RpiError::InvalidArgument),
        }
        Ok(self.last_resp)
    }

    /// Reads 512-byte block(s) (`CMD17` / `CMD18`) into `out` and validates DMA write permissions.
    pub fn read_blocks(
        &self,
        cap: Capability,
        dma: &DmaMapping,
        expected_generation: u64,
        dma_iova: u64,
        lba: u64,
        out: &mut [u8],
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(RpiError::PermissionDenied);
        }
        if self.generation != expected_generation {
            return Err(RpiError::StaleGeneration);
        }
        if self.state != SdCardState::Transfer {
            return Err(RpiError::DeviceNotReady);
        }
        if out.is_empty() || !out.len().is_multiple_of(SD_SECTOR_BYTES) {
            return Err(RpiError::InvalidArgument);
        }
        verify_dma_window(dma, dma_iova, out.len(), DmaPerms::WRITE)?;
        let blocks = out.len() / SD_SECTOR_BYTES;
        let start = usize::try_from(lba).map_err(|_| RpiError::OutOfRange)?;
        let end = start.checked_add(blocks).ok_or(RpiError::OutOfRange)?;
        if end > SECTORS {
            return Err(RpiError::OutOfRange);
        }
        for (i, chunk) in out
            .as_chunks_mut::<SD_SECTOR_BYTES>()
            .0
            .iter_mut()
            .enumerate()
        {
            *chunk = self.storage[start + i];
        }
        Ok(())
    }

    /// Writes 512-byte block(s) (`CMD24` / `CMD25`) from `data` and validates DMA read permissions.
    pub fn write_blocks(
        &mut self,
        cap: Capability,
        dma: &DmaMapping,
        expected_generation: u64,
        dma_iova: u64,
        lba: u64,
        data: &[u8],
    ) -> Result<(), RpiError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(RpiError::PermissionDenied);
        }
        if self.read_only {
            return Err(RpiError::ReadOnly);
        }
        if self.generation != expected_generation {
            return Err(RpiError::StaleGeneration);
        }
        if self.state != SdCardState::Transfer {
            return Err(RpiError::DeviceNotReady);
        }
        if data.is_empty() || !data.len().is_multiple_of(SD_SECTOR_BYTES) {
            return Err(RpiError::InvalidArgument);
        }
        verify_dma_window(dma, dma_iova, data.len(), DmaPerms::READ)?;
        let blocks = data.len() / SD_SECTOR_BYTES;
        let start = usize::try_from(lba).map_err(|_| RpiError::OutOfRange)?;
        let end = start.checked_add(blocks).ok_or(RpiError::OutOfRange)?;
        if end > SECTORS {
            return Err(RpiError::OutOfRange);
        }
        for (i, chunk) in data.as_chunks::<SD_SECTOR_BYTES>().0.iter().enumerate() {
            self.storage[start + i] = *chunk;
        }
        Ok(())
    }
}
