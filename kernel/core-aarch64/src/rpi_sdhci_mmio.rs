// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Live MMIO Standard SDHCI 3.0 / Broadcom Arasan EMMC / BCM2711 EMMC2 block driver.
//!
//! Works against:
//! - QEMU `raspi3b` `generic-sdhci` (`0x3F30_0000`) with `-sd <image>`
//! - Native Raspberry Pi 3B+ (`BCM2837B0` Arasan SDHCI at `0x3F30_0000`)
//! - Native Raspberry Pi 4B (`BCM2711` EMMC2 at `0xFE34_0000`)
//! - Native Raspberry Pi 5 (`BCM2712` SDIO0 at `0x10_00FF_F000`)

use alloc::boxed::Box;
use alloc::vec;
use core::ptr::{read_volatile, write_volatile};
use kernal_linux_abi::Errno;
use kernal_linux_mounts::BlockDevice;

const SECTOR_BYTES: usize = 512;
const CACHE_SLOTS: usize = 16384; // 8 MiB direct-mapped write-through sector cache (keeps libc/libsystemd/ext4 hot)
const CACHE_EMPTY_TAG: u64 = u64::MAX;

// Standard SDHCI 3.0 / Arasan EMMC register offsets (32-bit aligned accesses for BCM283x safety)
const SDHCI_BLKSIZECNT: u64 = 0x04;
const SDHCI_ARG1: u64 = 0x08;
const SDHCI_CMDTM: u64 = 0x0C;
const SDHCI_RESP0: u64 = 0x10;
const SDHCI_RESP1: u64 = 0x14;
const SDHCI_RESP2: u64 = 0x18;
const SDHCI_RESP3: u64 = 0x1C;
const SDHCI_DATA: u64 = 0x20;
const SDHCI_PRESENT_STATE: u64 = 0x24;
const SDHCI_HOST_PWR_CTL: u64 = 0x28;
const SDHCI_CLK_TO_RST: u64 = 0x2C;
const SDHCI_INT_STATUS: u64 = 0x30;
const SDHCI_INT_STATUS_EN: u64 = 0x34;
const SDHCI_INT_SIGNAL_EN: u64 = 0x38;

// PRESENT_STATE bits
const STATE_CMD_INHIBIT: u32 = 1 << 0;
const STATE_DAT_INHIBIT: u32 = 1 << 1;

// HOST_PWR_CTL (0x28..0x2B): byte 0x29 = POWER_CONTROL (3.3V = 0x7 << 1, bus power = 1 -> 0x0F)
const PWR_BUS_3V3: u32 = 0x0F << 8;

// CLK_TO_RST (0x2C..0x2F)
const CLK_INT_EN: u32 = 1 << 0;
const CLK_INT_STABLE: u32 = 1 << 1;
const CLK_SD_EN: u32 = 1 << 2;
const TIMEOUT_MAX: u32 = 0x0E << 16;
const SRST_ALL: u32 = 1 << 24;
const SRST_CMD: u32 = 1 << 25;
const SRST_DAT: u32 = 1 << 26;

// INT_STATUS bits
const INT_CMD_DONE: u32 = 1 << 0;
const INT_DATA_DONE: u32 = 1 << 1;
const INT_WRITE_RDY: u32 = 1 << 4;
const INT_READ_RDY: u32 = 1 << 5;
const INT_ERR_MASK: u32 = 0xFFFF_8000;

// CMDTM flags (low 16 bits = Transfer Mode, high 16 bits = Command)
const TM_BLKCNT_EN: u32 = 1 << 1;
const TM_DAT_DIR_READ: u32 = 1 << 4;
const CMD_RSPNS_NONE: u32 = 0 << 16;
const CMD_RSPNS_136: u32 = 1 << 16;
const CMD_RSPNS_48: u32 = 2 << 16;
const CMD_RSPNS_48B: u32 = 3 << 16;
const CMD_CRCCHK_EN: u32 = 1 << 19;
const CMD_IXCHK_EN: u32 = 1 << 20;
const CMD_ISDATA: u32 = 1 << 21;

const fn cmd_word(index: u32, flags: u32) -> u32 {
    (index << 24) | flags
}

const CMD0_GO_IDLE: u32 = cmd_word(0, CMD_RSPNS_NONE);
const CMD2_ALL_SEND_CID: u32 = cmd_word(2, CMD_RSPNS_136 | CMD_CRCCHK_EN);
const CMD3_SEND_RCA: u32 = cmd_word(3, CMD_RSPNS_48 | CMD_CRCCHK_EN | CMD_IXCHK_EN);
const CMD7_SELECT_CARD: u32 = cmd_word(7, CMD_RSPNS_48B | CMD_CRCCHK_EN | CMD_IXCHK_EN);
const CMD8_SEND_IF_COND: u32 = cmd_word(8, CMD_RSPNS_48 | CMD_CRCCHK_EN | CMD_IXCHK_EN);
const CMD9_SEND_CSD: u32 = cmd_word(9, CMD_RSPNS_136 | CMD_CRCCHK_EN);
const CMD16_SET_BLOCKLEN: u32 = cmd_word(16, CMD_RSPNS_48 | CMD_CRCCHK_EN | CMD_IXCHK_EN);
const CMD17_READ_SINGLE: u32 = cmd_word(
    17,
    CMD_RSPNS_48 | CMD_CRCCHK_EN | CMD_IXCHK_EN | CMD_ISDATA | TM_DAT_DIR_READ | TM_BLKCNT_EN,
);
const CMD24_WRITE_SINGLE: u32 = cmd_word(
    24,
    CMD_RSPNS_48 | CMD_CRCCHK_EN | CMD_IXCHK_EN | CMD_ISDATA | TM_BLKCNT_EN,
);
const CMD55_APP_CMD: u32 = cmd_word(55, CMD_RSPNS_48 | CMD_CRCCHK_EN | CMD_IXCHK_EN);
const ACMD41_SD_SEND_OP_COND: u32 = cmd_word(41, CMD_RSPNS_48);

const POLL_TIMEOUT: u32 = 500_000;

/// Live MMIO SDHCI/EMMC block device backed by a real or emulated Raspberry Pi SD card.
pub struct RpiSdhciMmioBlock {
    base: u64,
    rca: u32,
    is_sdhc: bool,
    total_sectors: u64,
    cache_tags: Box<[u64]>,
    cache_data: Box<[[u8; SECTOR_BYTES]]>,
}

impl RpiSdhciMmioBlock {
    /// Resets the SDHCI/EMMC controller at TTBR1-mapped `base`, enumerates the inserted SD/SDHC
    /// card, parses its CSD capacity, and selects it for 512-byte sector transfers.
    ///
    /// # Safety
    /// `base` must point to a permanently mapped `DeviceNgnre` RW/NX SDHCI MMIO aperture of at
    /// least `0x100` bytes.
    pub unsafe fn initialize(base: u64) -> Result<Self, Errno> {
        if base == 0 || (base & 3) != 0 {
            return Err(Errno::EINVAL);
        }
        let mut dev = Self {
            base,
            rca: 0,
            is_sdhc: false,
            total_sectors: 0,
            cache_tags: vec![CACHE_EMPTY_TAG; CACHE_SLOTS].into_boxed_slice(),
            cache_data: vec![[0u8; SECTOR_BYTES]; CACHE_SLOTS].into_boxed_slice(),
        };

        // 1. Software reset entire SDHCI host controller.
        dev.write32(SDHCI_CLK_TO_RST, SRST_ALL);
        dev.wait_clear(SDHCI_CLK_TO_RST, SRST_ALL)?;

        // 2. Enable 3.3V SD bus power, configure internal + SD clock (~400 kHz divider) & max data timeout.
        dev.write32(SDHCI_HOST_PWR_CTL, PWR_BUS_3V3);
        let init_clk = TIMEOUT_MAX | (0x40 << 8) | CLK_INT_EN;
        dev.write32(SDHCI_CLK_TO_RST, init_clk);
        dev.wait_set(SDHCI_CLK_TO_RST, CLK_INT_STABLE)?;
        dev.write32(SDHCI_CLK_TO_RST, init_clk | CLK_SD_EN);

        // 3. Latch all status flags for polling; keep IRQ signals masked.
        dev.write32(SDHCI_INT_SIGNAL_EN, 0);
        dev.write32(SDHCI_INT_STATUS_EN, 0xFFFF_FFFF);
        dev.write32(SDHCI_INT_STATUS, 0xFFFF_FFFF);

        // 4. CMD0: GO_IDLE_STATE.
        dev.send_cmd(CMD0_GO_IDLE, 0)?;

        // 5. CMD8: SEND_IF_COND (SD v2.0 voltage check 0x1AA). Ignore error for SD v1.x cards.
        let v2 = dev
            .send_cmd(CMD8_SEND_IF_COND, 0x0000_01AA)
            .map(|r| (r & 0xFFF) == 0x1AA)
            .unwrap_or(false);

        // 6. CMD55 + ACMD41: wait until card power-up completes (OCR bit 31 = busy/ready).
        let ocr_arg = if v2 { 0x51FF_8000 } else { 0x00FF_8000 };
        let mut ocr = 0u32;
        let mut ready = false;
        for _ in 0..2000u32 {
            dev.send_cmd(CMD55_APP_CMD, 0)?;
            ocr = dev.send_cmd(ACMD41_SD_SEND_OP_COND, ocr_arg)?;
            if (ocr & (1 << 31)) != 0 {
                ready = true;
                break;
            }
            for _ in 0..500u32 {
                core::hint::spin_loop();
            }
        }
        if !ready {
            return Err(Errno::ENODEV);
        }
        dev.is_sdhc = (ocr & (1 << 30)) != 0;

        // 7. CMD2 (CID) + CMD3 (RCA).
        let _ = dev.send_cmd(CMD2_ALL_SEND_CID, 0)?;
        let rca_resp = dev.send_cmd(CMD3_SEND_RCA, 0)?;
        dev.rca = rca_resp & 0xFFFF_0000;
        if dev.rca == 0 {
            return Err(Errno::EIO);
        }

        // 8. CMD9 (SEND_CSD) to determine exact capacity in 512-byte sectors.
        let _ = dev.send_cmd(CMD9_SEND_CSD, dev.rca)?;
        let resp1 = dev.read32(SDHCI_RESP1);
        let resp2 = dev.read32(SDHCI_RESP2);
        let resp3 = dev.read32(SDHCI_RESP3);
        dev.total_sectors = decode_csd_sectors(resp1, resp2, resp3);
        if dev.total_sectors == 0 {
            // Safe fallback if controller strips CSD differently on legacy cards.
            dev.total_sectors = 2 * 1024 * 1024; // 1 GiB
        }

        // 9. CMD7: SELECT_CARD into Transfer state, raise SD clock divider to fast mode (~12-25 MHz).
        let _ = dev.send_cmd(CMD7_SELECT_CARD, dev.rca)?;
        let fast_clk = TIMEOUT_MAX | (0x04 << 8) | CLK_INT_EN;
        dev.write32(SDHCI_CLK_TO_RST, fast_clk);
        dev.wait_set(SDHCI_CLK_TO_RST, CLK_INT_STABLE)?;
        dev.write32(SDHCI_CLK_TO_RST, fast_clk | CLK_SD_EN);

        // 10. CMD16: SET_BLOCKLEN = 512 bytes (required for SDSC, harmless no-op on SDHC).
        let _ = dev.send_cmd(CMD16_SET_BLOCKLEN, SECTOR_BYTES as u32)?;

        Ok(dev)
    }

    pub const fn capacity_sectors(&self) -> u64 {
        self.total_sectors
    }

    #[inline]
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: `initialize` verified `base` is an aligned mapped SDHCI MMIO region.
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    #[inline]
    fn write32(&self, offset: u64, value: u32) {
        // SAFETY: `initialize` verified `base` is an aligned mapped SDHCI MMIO region.
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }

    fn wait_clear(&self, offset: u64, mask: u32) -> Result<(), Errno> {
        for _ in 0..POLL_TIMEOUT {
            if (self.read32(offset) & mask) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Errno::EIO)
    }

    fn wait_set(&self, offset: u64, mask: u32) -> Result<(), Errno> {
        for _ in 0..POLL_TIMEOUT {
            if (self.read32(offset) & mask) != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Errno::EIO)
    }

    fn reset_cmd_dat_on_err(&self) {
        let cur = self.read32(SDHCI_CLK_TO_RST);
        self.write32(SDHCI_CLK_TO_RST, cur | SRST_CMD | SRST_DAT);
        let _ = self.wait_clear(SDHCI_CLK_TO_RST, SRST_CMD | SRST_DAT);
        self.write32(SDHCI_INT_STATUS, 0xFFFF_FFFF);
    }

    fn send_cmd(&self, cmd: u32, arg: u32) -> Result<u32, Errno> {
        let inhibit = if (cmd & CMD_ISDATA) != 0 || (cmd & CMD_RSPNS_48B) == CMD_RSPNS_48B {
            STATE_CMD_INHIBIT | STATE_DAT_INHIBIT
        } else {
            STATE_CMD_INHIBIT
        };
        self.wait_clear(SDHCI_PRESENT_STATE, inhibit)?;
        self.write32(SDHCI_INT_STATUS, 0xFFFF_FFFF);
        self.write32(SDHCI_ARG1, arg);
        self.write32(SDHCI_CMDTM, cmd);

        for _ in 0..POLL_TIMEOUT {
            let st = self.read32(SDHCI_INT_STATUS);
            if (st & INT_ERR_MASK) != 0 {
                self.reset_cmd_dat_on_err();
                return Err(Errno::EIO);
            }
            if (st & INT_CMD_DONE) != 0 {
                self.write32(SDHCI_INT_STATUS, INT_CMD_DONE);
                return Ok(self.read32(SDHCI_RESP0));
            }
            core::hint::spin_loop();
        }
        self.reset_cmd_dat_on_err();
        Err(Errno::EIO)
    }

    fn read_single_sector(&self, sector: u64, dst: &mut [u8; SECTOR_BYTES]) -> Result<(), Errno> {
        let addr = if self.is_sdhc {
            u32::try_from(sector).map_err(|_| Errno::EINVAL)?
        } else {
            u32::try_from(
                sector
                    .checked_mul(SECTOR_BYTES as u64)
                    .ok_or(Errno::EINVAL)?,
            )
            .map_err(|_| Errno::EINVAL)?
        };

        self.wait_clear(SDHCI_PRESENT_STATE, STATE_CMD_INHIBIT | STATE_DAT_INHIBIT)?;
        self.write32(SDHCI_BLKSIZECNT, (1u32 << 16) | (SECTOR_BYTES as u32));
        self.send_cmd(CMD17_READ_SINGLE, addr)?;

        // Wait for Buffer Read Ready.
        let mut rdy = false;
        for _ in 0..POLL_TIMEOUT {
            let st = self.read32(SDHCI_INT_STATUS);
            if (st & INT_ERR_MASK) != 0 {
                self.reset_cmd_dat_on_err();
                return Err(Errno::EIO);
            }
            if (st & INT_READ_RDY) != 0 {
                self.write32(SDHCI_INT_STATUS, INT_READ_RDY);
                rdy = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !rdy {
            self.reset_cmd_dat_on_err();
            return Err(Errno::EIO);
        }

        for chunk in dst.chunks_exact_mut(4) {
            let word = self.read32(SDHCI_DATA).to_le_bytes();
            chunk.copy_from_slice(&word);
        }

        // Wait for Transfer Complete.
        for _ in 0..POLL_TIMEOUT {
            let st = self.read32(SDHCI_INT_STATUS);
            if (st & INT_ERR_MASK) != 0 {
                self.reset_cmd_dat_on_err();
                return Err(Errno::EIO);
            }
            if (st & INT_DATA_DONE) != 0 {
                self.write32(SDHCI_INT_STATUS, INT_DATA_DONE);
                return Ok(());
            }
            core::hint::spin_loop();
        }
        self.reset_cmd_dat_on_err();
        Err(Errno::EIO)
    }

    fn write_single_sector(&self, sector: u64, src: &[u8; SECTOR_BYTES]) -> Result<(), Errno> {
        let addr = if self.is_sdhc {
            u32::try_from(sector).map_err(|_| Errno::EINVAL)?
        } else {
            u32::try_from(
                sector
                    .checked_mul(SECTOR_BYTES as u64)
                    .ok_or(Errno::EINVAL)?,
            )
            .map_err(|_| Errno::EINVAL)?
        };

        self.wait_clear(SDHCI_PRESENT_STATE, STATE_CMD_INHIBIT | STATE_DAT_INHIBIT)?;
        self.write32(SDHCI_BLKSIZECNT, (1u32 << 16) | (SECTOR_BYTES as u32));
        self.send_cmd(CMD24_WRITE_SINGLE, addr)?;

        // Wait for Buffer Write Ready.
        let mut rdy = false;
        for _ in 0..POLL_TIMEOUT {
            let st = self.read32(SDHCI_INT_STATUS);
            if (st & INT_ERR_MASK) != 0 {
                self.reset_cmd_dat_on_err();
                return Err(Errno::EIO);
            }
            if (st & INT_WRITE_RDY) != 0 {
                self.write32(SDHCI_INT_STATUS, INT_WRITE_RDY);
                rdy = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !rdy {
            self.reset_cmd_dat_on_err();
            return Err(Errno::EIO);
        }

        for chunk in src.chunks_exact(4) {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            self.write32(SDHCI_DATA, word);
        }

        // Wait for Transfer Complete.
        for _ in 0..POLL_TIMEOUT {
            let st = self.read32(SDHCI_INT_STATUS);
            if (st & INT_ERR_MASK) != 0 {
                self.reset_cmd_dat_on_err();
                return Err(Errno::EIO);
            }
            if (st & INT_DATA_DONE) != 0 {
                self.write32(SDHCI_INT_STATUS, INT_DATA_DONE);
                return Ok(());
            }
            core::hint::spin_loop();
        }
        self.reset_cmd_dat_on_err();
        Err(Errno::EIO)
    }
}

/// Decodes SDHCI R2 (`CMD9`) CSD registers (CRC byte stripped by hardware) into 512-byte sectors.
fn decode_csd_sectors(resp1: u32, resp2: u32, resp3: u32) -> u64 {
    let csd_structure = (resp3 >> 22) & 0x3;
    match csd_structure {
        1 => {
            // CSD Version 2.0 (SDHC / SDXC): C_SIZE in CSD[69:48] == resp1[29:8]
            let c_size = u64::from((resp1 >> 8) & 0x3F_FFFF);
            (c_size + 1).saturating_mul(1024)
        }
        0 => {
            // CSD Version 1.0 (SDSC)
            let read_bl_len = (resp2 >> 8) & 0xF;
            let c_size = u64::from(((resp2 & 0x3) << 10) | ((resp1 >> 22) & 0x3FF));
            let c_size_mult = (resp1 >> 7) & 0x7;
            if read_bl_len > 11 {
                return 0;
            }
            let block_nr = (c_size + 1).saturating_mul(1u64 << (c_size_mult + 2));
            let bytes = block_nr.saturating_mul(1u64 << read_bl_len);
            bytes / (SECTOR_BYTES as u64)
        }
        _ => 0,
    }
}

impl BlockDevice for RpiSdhciMmioBlock {
    fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    fn read_only(&self) -> bool {
        false
    }

    fn read_sectors(&mut self, start_sector: u64, out: &mut [u8]) -> Result<(), Errno> {
        if !out.len().is_multiple_of(SECTOR_BYTES) {
            return Err(Errno::EINVAL);
        }
        for (i, chunk) in out.chunks_exact_mut(SECTOR_BYTES).enumerate() {
            let sec_no = start_sector + (i as u64);
            let slot = (sec_no as usize) & (CACHE_SLOTS - 1);
            if self.cache_tags[slot] == sec_no {
                chunk.copy_from_slice(&self.cache_data[slot]);
            } else {
                let mut sec = [0u8; SECTOR_BYTES];
                self.read_single_sector(sec_no, &mut sec)?;
                self.cache_tags[slot] = sec_no;
                self.cache_data[slot] = sec;
                chunk.copy_from_slice(&sec);
            }
        }
        Ok(())
    }

    fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> Result<(), Errno> {
        if !data.len().is_multiple_of(SECTOR_BYTES) {
            return Err(Errno::EINVAL);
        }
        for (i, chunk) in data.chunks_exact(SECTOR_BYTES).enumerate() {
            let sec_no = start_sector + (i as u64);
            let mut sec = [0u8; SECTOR_BYTES];
            sec.copy_from_slice(chunk);
            self.write_single_sector(sec_no, &sec)?;
            let slot = (sec_no as usize) & (CACHE_SLOTS - 1);
            self.cache_tags[slot] = sec_no;
            self.cache_data[slot] = sec;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Errno> {
        Ok(())
    }
}
