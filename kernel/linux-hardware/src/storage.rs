// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapRights, Capability};
use kernal_iommu::{DmaMapping, DmaPerms};
use kernal_linux_abi::Errno;
use kernal_pci::{Address as PciAddress, EcamWindow};

pub const STORAGE_SECTOR_SIZE: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    NotReady,
    PermissionDenied,
    ReadOnly,
    InvalidRange,
    DmaViolation,
    StaleGeneration,
    QueueFull,
    UnsupportedPort,
    InvalidPciAddress,
}

impl StorageError {
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::ReadOnly => Errno::EROFS,
            Self::PermissionDenied | Self::DmaViolation | Self::StaleGeneration => Errno::EACCES,
            Self::QueueFull => Errno::EAGAIN,
            Self::NotReady => Errno::EIO,
            Self::InvalidRange | Self::UnsupportedPort | Self::InvalidPciAddress => Errno::EINVAL,
        }
    }
}

fn check_dma_transfer(
    mapping: &DmaMapping,
    expected_gen: u32,
    actual_gen: u32,
    iova: u64,
    len: usize,
    need_write: bool,
) -> Result<(), StorageError> {
    if expected_gen != actual_gen {
        return Err(StorageError::StaleGeneration);
    }
    if len == 0 {
        return Err(StorageError::InvalidRange);
    }
    if need_write && (mapping.perms.bits() & DmaPerms::WRITE.bits()) == 0 {
        return Err(StorageError::DmaViolation);
    }
    if !need_write && (mapping.perms.bits() & DmaPerms::READ.bits()) == 0 {
        return Err(StorageError::DmaViolation);
    }
    let map_end = mapping.iova_end().ok_or(StorageError::DmaViolation)?;
    let req_end = iova
        .checked_add(len as u64)
        .ok_or(StorageError::InvalidRange)?;
    if iova < mapping.iova || req_end > map_end {
        return Err(StorageError::DmaViolation);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeNamespace {
    pub nsid: u32,
    pub block_count: usize,
    pub block_size: usize,
    pub read_only: bool,
    pub online: bool,
}

/// Capability- and IOMMU-mediated NVMe PCIe controller state machine.
#[derive(Clone, Debug)]
pub struct NvmeController<const SECTORS: usize> {
    pub pci: PciAddress,
    pub ecam_base: u64,
    pub enabled: bool,
    pub ready: bool,
    pub queue_generation: u32,
    pub admin_sq_depth: u16,
    pub io_sq_depth: u16,
    pub namespace: NvmeNamespace,
    pub cqe_phase: bool,
    pub completed_commands: u64,
    pub flush_generation: u64,
    storage: [[u8; STORAGE_SECTOR_SIZE]; SECTORS],
}

impl<const SECTORS: usize> NvmeController<SECTORS> {
    pub fn new(ecam: EcamWindow, pci: PciAddress, read_only: bool) -> Result<Self, StorageError> {
        let ecam_base = ecam
            .config_address(pci)
            .map_err(|_| StorageError::InvalidPciAddress)?;
        Ok(Self {
            pci,
            ecam_base,
            enabled: false,
            ready: false,
            queue_generation: 1,
            admin_sq_depth: 0,
            io_sq_depth: 0,
            namespace: NvmeNamespace {
                nsid: 1,
                block_count: SECTORS,
                block_size: STORAGE_SECTOR_SIZE,
                read_only,
                online: true,
            },
            cqe_phase: true,
            completed_commands: 0,
            flush_generation: 0,
            storage: [[0u8; STORAGE_SECTOR_SIZE]; SECTORS],
        })
    }

    pub fn enable(
        &mut self,
        cap: Capability,
        admin_depth: u16,
        io_depth: u16,
    ) -> Result<(), StorageError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(StorageError::PermissionDenied);
        }
        if !(2..=4096).contains(&admin_depth) || !(2..=4096).contains(&io_depth) {
            return Err(StorageError::InvalidRange);
        }
        self.admin_sq_depth = admin_depth;
        self.io_sq_depth = io_depth;
        self.enabled = true;
        self.ready = true;
        Ok(())
    }

    pub fn controller_reset(&mut self, cap: Capability) -> Result<(), StorageError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(StorageError::PermissionDenied);
        }
        self.enabled = false;
        self.ready = false;
        self.queue_generation = self.queue_generation.wrapping_add(1).max(1);
        Ok(())
    }

    fn validate_lba(&self, lba: u64, sectors: usize) -> Result<usize, StorageError> {
        if !self.enabled || !self.ready || !self.namespace.online {
            return Err(StorageError::NotReady);
        }
        let start = usize::try_from(lba).map_err(|_| StorageError::InvalidRange)?;
        let end = start
            .checked_add(sectors)
            .ok_or(StorageError::InvalidRange)?;
        if sectors == 0 || end > self.namespace.block_count {
            return Err(StorageError::InvalidRange);
        }
        Ok(start)
    }

    pub fn read_blocks(
        &mut self,
        cap: Capability,
        dma: &DmaMapping,
        expected_gen: u32,
        prp_iova: u64,
        lba: u64,
        out: &mut [u8],
    ) -> Result<(), StorageError> {
        if !cap.rights.contains(CapRights::READ) {
            return Err(StorageError::PermissionDenied);
        }
        if !out.len().is_multiple_of(STORAGE_SECTOR_SIZE) {
            return Err(StorageError::InvalidRange);
        }
        let sectors = out.len() / STORAGE_SECTOR_SIZE;
        let start = self.validate_lba(lba, sectors)?;
        // Controller writes into guest memory -> DMA mapping requires WRITE permission.
        check_dma_transfer(
            dma,
            expected_gen,
            self.queue_generation,
            prp_iova,
            out.len(),
            true,
        )?;
        for i in 0..sectors {
            let off = i * STORAGE_SECTOR_SIZE;
            out[off..off + STORAGE_SECTOR_SIZE].copy_from_slice(&self.storage[start + i]);
        }
        self.completed_commands = self.completed_commands.saturating_add(1);
        Ok(())
    }

    pub fn write_blocks(
        &mut self,
        cap: Capability,
        dma: &DmaMapping,
        expected_gen: u32,
        prp_iova: u64,
        lba: u64,
        data: &[u8],
    ) -> Result<(), StorageError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(StorageError::PermissionDenied);
        }
        if self.namespace.read_only {
            return Err(StorageError::ReadOnly);
        }
        if !data.len().is_multiple_of(STORAGE_SECTOR_SIZE) {
            return Err(StorageError::InvalidRange);
        }
        let sectors = data.len() / STORAGE_SECTOR_SIZE;
        let start = self.validate_lba(lba, sectors)?;
        // Controller reads from guest memory -> DMA mapping requires READ permission.
        check_dma_transfer(
            dma,
            expected_gen,
            self.queue_generation,
            prp_iova,
            data.len(),
            false,
        )?;
        for i in 0..sectors {
            let off = i * STORAGE_SECTOR_SIZE;
            self.storage[start + i].copy_from_slice(&data[off..off + STORAGE_SECTOR_SIZE]);
        }
        self.completed_commands = self.completed_commands.saturating_add(1);
        Ok(())
    }

    pub fn flush(&mut self, cap: Capability) -> Result<(), StorageError> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(StorageError::PermissionDenied);
        }
        if !self.ready {
            return Err(StorageError::NotReady);
        }
        self.flush_generation = self.flush_generation.saturating_add(1);
        self.completed_commands = self.completed_commands.saturating_add(1);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct AhciPortState {
    implemented: bool,
    link_up: bool,
    read_only: bool,
    generation: u32,
    sector_count: usize,
}

impl AhciPortState {
    const EMPTY: Self = Self {
        implemented: false,
        link_up: false,
        read_only: false,
        generation: 1,
        sector_count: 0,
    };
}

/// AHCI SATA HBA controller with up to 4 ports and 32 command slots.
#[derive(Clone, Debug)]
pub struct AhciController<const PORTS: usize, const SECTORS_PER_PORT: usize> {
    ports: [AhciPortState; PORTS],
    sectors: [[[u8; STORAGE_SECTOR_SIZE]; SECTORS_PER_PORT]; PORTS],
    ghc_ae: bool,
}

impl<const PORTS: usize, const SECTORS_PER_PORT: usize> Default
    for AhciController<PORTS, SECTORS_PER_PORT>
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SataCommand {
    pub port: usize,
    pub command_slot: u8,
    pub expected_generation: u32,
    pub prdt_iova: u64,
    pub lba: u64,
    pub write: bool,
}

impl<const PORTS: usize, const SECTORS_PER_PORT: usize> AhciController<PORTS, SECTORS_PER_PORT> {
    pub const fn new() -> Self {
        Self {
            ports: [AhciPortState::EMPTY; PORTS],
            sectors: [[[0u8; STORAGE_SECTOR_SIZE]; SECTORS_PER_PORT]; PORTS],
            ghc_ae: true,
        }
    }

    pub fn enable_port(
        &mut self,
        cap: Capability,
        port: usize,
        read_only: bool,
    ) -> Result<u32, StorageError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(StorageError::PermissionDenied);
        }
        let slot = self
            .ports
            .get_mut(port)
            .ok_or(StorageError::UnsupportedPort)?;
        slot.implemented = true;
        slot.link_up = true;
        slot.read_only = read_only;
        slot.sector_count = SECTORS_PER_PORT;
        Ok(slot.generation)
    }

    pub fn comreset_port(&mut self, cap: Capability, port: usize) -> Result<u32, StorageError> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(StorageError::PermissionDenied);
        }
        let slot = self
            .ports
            .get_mut(port)
            .ok_or(StorageError::UnsupportedPort)?;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        Ok(slot.generation)
    }

    pub fn sata_rw(
        &mut self,
        cap: Capability,
        dma: &DmaMapping,
        cmd: SataCommand,
        buf: &mut [u8],
    ) -> Result<(), StorageError> {
        if !self.ghc_ae || cmd.command_slot >= 32 {
            return Err(StorageError::InvalidRange);
        }
        let needed_right = if cmd.write {
            CapRights::WRITE
        } else {
            CapRights::READ
        };
        if !cap.rights.contains(needed_right) {
            return Err(StorageError::PermissionDenied);
        }
        let state = self
            .ports
            .get(cmd.port)
            .ok_or(StorageError::UnsupportedPort)?;
        if !state.implemented || !state.link_up {
            return Err(StorageError::NotReady);
        }
        if cmd.write && state.read_only {
            return Err(StorageError::ReadOnly);
        }
        if buf.is_empty() || !buf.len().is_multiple_of(STORAGE_SECTOR_SIZE) {
            return Err(StorageError::InvalidRange);
        }
        let count = buf.len() / STORAGE_SECTOR_SIZE;
        let start = usize::try_from(cmd.lba).map_err(|_| StorageError::InvalidRange)?;
        let end = start.checked_add(count).ok_or(StorageError::InvalidRange)?;
        if end > state.sector_count {
            return Err(StorageError::InvalidRange);
        }
        check_dma_transfer(
            dma,
            cmd.expected_generation,
            state.generation,
            cmd.prdt_iova,
            buf.len(),
            !cmd.write,
        )?;

        for i in 0..count {
            let off = i * STORAGE_SECTOR_SIZE;
            if cmd.write {
                self.sectors[cmd.port][start + i]
                    .copy_from_slice(&buf[off..off + STORAGE_SECTOR_SIZE]);
            } else {
                buf[off..off + STORAGE_SECTOR_SIZE]
                    .copy_from_slice(&self.sectors[cmd.port][start + i]);
            }
        }
        Ok(())
    }
}
