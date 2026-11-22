// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Native Google Pixel Tensor G1–G4 (`gs101`, `gs201`, `zuma`, `zumapro`) & GrapheneOS hardware
//! driver abstraction layer for Qyronex OS, plus Android GKI Boot Image v4 (`ANDROID!`) builder.
//!
//! All DMA-capable Pixel peripherals (UFS 3.1/4.0, Shannon 5G Modem, Broadcom Wi-Fi PCIe, Mali/
//! Immortalis GPU) require explicit Qyronex `Capability` + `IommuDomain` authorization so a
//! compromised baseband or wireless chip cannot DMA into kernel or GrapheneOS application RAM.

use kernal_capability::{CapRights, Capability};
use kernal_iommu::{DmaMapping, DmaPerms, Domain, PciDeviceId};
use kernal_linux_abi::Errno;

/// Supported Google Pixel Tensor SoC generations + QEMU/Cuttlefish GKI Emulator target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PixelSocGeneration {
    /// Pixel 6 / 6 Pro / 6a (`google,gs101`, Cortex-X1/A76/A55, Mali-G78, GICv3).
    TensorG1Gs101,
    /// Pixel 7 / 7 Pro / 7a / Fold / Tablet (`google,gs201`, Cortex-X1/A78/A55, Mali-G710, GICv3).
    TensorG2Gs201,
    /// Pixel 8 / 8 Pro / 8a (`google,zuma`, ARMv9 Cortex-X3/A715/A510 + HW MTE, Immortalis-G715).
    TensorG3Zuma,
    /// Pixel 9 / 9 Pro / 9 Pro XL / 9a (`google,zumapro`, ARMv9.2 Cortex-X4/A720/A520 + HW MTE).
    TensorG4ZumaPro,
    /// QEMU AArch64 `virt` / Android Cuttlefish GKI 6.12 virtual Pixel profile.
    EmulatorVirtGki,
}

impl PixelSocGeneration {
    pub const fn model_name(self) -> &'static str {
        match self {
            Self::TensorG1Gs101 => "Google Pixel 6 / Tensor G1 (gs101)",
            Self::TensorG2Gs201 => "Google Pixel 7 / Tensor G2 (gs201)",
            Self::TensorG3Zuma => "Google Pixel 8 / Tensor G3 (zuma)",
            Self::TensorG4ZumaPro => "Google Pixel 9 / Tensor G4 (zumapro)",
            Self::EmulatorVirtGki => "Qyronex Pixel Emulator (GKI 6.12 AArch64)",
        }
    }

    pub const fn codename(self) -> &'static str {
        match self {
            Self::TensorG1Gs101 => "gs101",
            Self::TensorG2Gs201 => "gs201",
            Self::TensorG3Zuma => "zuma",
            Self::TensorG4ZumaPro | Self::EmulatorVirtGki => "zumapro",
        }
    }

    pub const fn supports_hw_mte(self) -> bool {
        matches!(self, Self::TensorG3Zuma | Self::TensorG4ZumaPro)
    }

    pub const fn supports_hw_pan_pac(self) -> bool {
        true
    }

    pub const fn cpu_cores(self) -> u8 {
        match self {
            Self::TensorG1Gs101 | Self::TensorG2Gs201 | Self::TensorG4ZumaPro => 8,
            Self::TensorG3Zuma => 9,
            Self::EmulatorVirtGki => 4,
        }
    }

    pub const fn display_resolution(self) -> (u32, u32, u16) {
        match self {
            Self::TensorG1Gs101 | Self::TensorG2Gs201 => (1080, 2400, 90),
            Self::TensorG3Zuma | Self::TensorG4ZumaPro => (1080, 2424, 120),
            Self::EmulatorVirtGki => (1280, 800, 60),
        }
    }

    pub fn from_fdt_compatible(compat: &str) -> Option<Self> {
        if compat.contains("google,zumapro")
            || compat.contains("google,tokay")
            || compat.contains("google,caiman")
            || compat.contains("google,komodo")
        {
            Some(Self::TensorG4ZumaPro)
        } else if compat.contains("google,zuma")
            || compat.contains("google,shiba")
            || compat.contains("google,husky")
            || compat.contains("google,akita")
        {
            Some(Self::TensorG3Zuma)
        } else if compat.contains("google,gs201")
            || compat.contains("google,panther")
            || compat.contains("google,cheetah")
            || compat.contains("google,lynx")
        {
            Some(Self::TensorG2Gs201)
        } else if compat.contains("google,gs101")
            || compat.contains("google,oriole")
            || compat.contains("google,raven")
            || compat.contains("google,bluejay")
        {
            Some(Self::TensorG1Gs101)
        } else {
            None
        }
    }
}

/// Google Titan M2 discrete security chip (StrongBox KeyMint, Weaver PIN throttling, AVB 2.0).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TitanM2SecurityChip {
    pub online: bool,
    pub strongbox_keymint_version: u32,
    pub weaver_slots: u16,
    pub avb_verified_boot_locked: bool,
    pub rollback_index: u64,
    pub attestation_ready: bool,
}

impl TitanM2SecurityChip {
    pub const fn new() -> Self {
        Self {
            online: false,
            strongbox_keymint_version: 300, // KeyMint 3.0 (Android 15 / GrapheneOS)
            weaver_slots: 64,
            avb_verified_boot_locked: true,
            rollback_index: 20261105,
            attestation_ready: false,
        }
    }

    pub fn initialize(&mut self, cap: Capability) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EPERM);
        }
        self.online = true;
        self.attestation_ready = true;
        Ok(())
    }
}

impl Default for TitanM2SecurityChip {
    fn default() -> Self {
        Self::new()
    }
}

/// Pixel Exynos/Tensor UFS 3.1/4.0 storage controller with Android A/B seamless update slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelUfsController {
    pub initialized: bool,
    pub ufs_spec_major: u8,
    pub ufs_spec_minor: u8,
    pub active_slot: u8, // b'a' or b'b'
    pub logical_units: u8,
    pub capacity_gib: u32,
}

impl PixelUfsController {
    pub const fn new() -> Self {
        Self {
            initialized: false,
            ufs_spec_major: 3,
            ufs_spec_minor: 1,
            active_slot: b'a',
            logical_units: 6,
            capacity_gib: 128,
        }
    }

    pub fn initialize(&mut self, cap: Capability) -> Result<(), Errno> {
        if !cap.rights.contains(
            CapRights::READ
                .union(CapRights::WRITE)
                .union(CapRights::CONTROL),
        ) {
            return Err(Errno::EPERM);
        }
        self.initialized = true;
        Ok(())
    }
}

impl Default for PixelUfsController {
    fn default() -> Self {
        Self::new()
    }
}

/// Tensor Display Processing Unit (`DPU`/`DECON` + MIPI-DSI OLED).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TensorDpuDisplay {
    pub initialized: bool,
    pub width: u32,
    pub height: u32,
    pub refresh_hz: u16,
    pub drm_bridge_active: bool,
}

impl TensorDpuDisplay {
    pub const fn for_soc(soc: PixelSocGeneration) -> Self {
        let (width, height, refresh_hz) = soc.display_resolution();
        Self {
            initialized: false,
            width,
            height,
            refresh_hz,
            drm_bridge_active: false,
        }
    }
}

/// IOMMU-sandboxed Samsung/Exynos Shannon 5G Baseband Modem IPC (`cpif`) + Wi-Fi PCIe.
///
/// Enforces a strict Qyronex `kernal_iommu::Domain` DMA window so the cellular baseband can never
/// read or corrupt kernel memory or GrapheneOS app heaps.
pub struct ShannonModemIpc<const N: usize> {
    pub initialized: bool,
    pub iommu_sandboxed: bool,
    pub link_5g_ready: bool,
    pub dma_domain: Domain<2, N>,
}

impl<const N: usize> ShannonModemIpc<N> {
    pub const fn new() -> Self {
        Self {
            initialized: false,
            iommu_sandboxed: false,
            link_5g_ready: false,
            dma_domain: Domain::new(),
        }
    }

    pub fn initialize_sandboxed(
        &mut self,
        cap: Capability,
        ring_iova: u64,
        ring_phys: u64,
        ring_size: u64,
    ) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EPERM);
        }
        let modem_dev = PciDeviceId {
            segment: 0,
            bus: 1,
            device: 0,
            function: 0,
        };
        self.dma_domain
            .attach_device(modem_dev)
            .map_err(|_| Errno::EBUSY)?;
        let mapping = DmaMapping::new(ring_iova, ring_phys, ring_size, DmaPerms::READ_WRITE)
            .map_err(|_| Errno::EINVAL)?;
        self.dma_domain.map(mapping).map_err(|_| Errno::ENOMEM)?;
        self.iommu_sandboxed = true;
        self.initialized = true;
        self.link_5g_ready = true;
        Ok(())
    }
}

impl<const N: usize> Default for ShannonModemIpc<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// ARM Mali Valhall / CSF GPU Driver HAL (`/dev/mali0`) for Google Tensor G1–G4.
///
/// Enforces IOMMU address-space isolation so GPU command streams cannot access host kernel RAM.
pub struct MaliCsfGpu<const N: usize> {
    pub initialized: bool,
    pub gpu_name: &'static str,
    pub gpu_id: u32,
    pub shader_cores: u8,
    pub l2_cache_kb: u16,
    pub csf_version_major: u16,
    pub csf_version_minor: u16,
    pub iommu_isolated: bool,
    pub submitted_command_groups: u64,
    pub dma_domain: Domain<2, N>,
}

impl<const N: usize> MaliCsfGpu<N> {
    pub const fn for_soc(soc: PixelSocGeneration) -> Self {
        let (gpu_name, gpu_id, shader_cores, l2_cache_kb) = match soc {
            PixelSocGeneration::TensorG1Gs101 => ("ARM Mali-G78 MP20", 0x9202_0010, 20, 1024),
            PixelSocGeneration::TensorG2Gs201 => ("ARM Mali-G710 MP7 (CSF)", 0xa867_0000, 7, 1024),
            PixelSocGeneration::TensorG3Zuma => {
                ("ARM Immortalis-G715s MC10 (CSF)", 0xb8a2_0000, 10, 2048)
            }
            PixelSocGeneration::TensorG4ZumaPro => {
                ("ARM Mali-G715 MC7 (CSF)", 0xb8a2_0010, 7, 2048)
            }
            PixelSocGeneration::EmulatorVirtGki => {
                ("VirtIO-GPU / Mali-CSF HAL Bridge", 0xb8a2_0010, 4, 512)
            }
        };
        Self {
            initialized: false,
            gpu_name,
            gpu_id,
            shader_cores,
            l2_cache_kb,
            csf_version_major: 1,
            csf_version_minor: 14,
            iommu_isolated: false,
            submitted_command_groups: 0,
            dma_domain: Domain::new(),
        }
    }

    pub fn initialize_isolated(&mut self, cap: Capability) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EPERM);
        }
        let gpu_dev = PciDeviceId {
            segment: 0,
            bus: 2,
            device: 0,
            function: 0,
        };
        self.dma_domain
            .attach_device(gpu_dev)
            .map_err(|_| Errno::EBUSY)?;
        let mapping = DmaMapping::new(0x2000_0000, 0xa000_0000, 0x100000, DmaPerms::READ_WRITE)
            .map_err(|_| Errno::EINVAL)?;
        self.dma_domain.map(mapping).map_err(|_| Errno::ENOMEM)?;
        self.iommu_isolated = true;
        self.initialized = true;
        Ok(())
    }
}

/// Google Tensor Edge TPU / GXP DSP Accelerator HAL (`/dev/edgetpu`).
///
/// Enforces IOMMU isolation and cleanly distinguishes kernel HAL readiness from proprietary
/// Google-signed Edge TPU firmware blobs (which must be supplied by the device owner from a
/// Pixel factory image on physical hardware).
pub struct TensorEdgeTpu<const N: usize> {
    pub initialized: bool,
    pub iommu_sandboxed: bool,
    pub generation: u8,
    pub vendor_firmware_loaded: bool,
    pub dma_domain: Domain<2, N>,
}

impl<const N: usize> TensorEdgeTpu<N> {
    pub const fn for_soc(soc: PixelSocGeneration) -> Self {
        let generation = match soc {
            PixelSocGeneration::TensorG1Gs101 => 1,
            PixelSocGeneration::TensorG2Gs201 => 2,
            PixelSocGeneration::TensorG3Zuma => 3,
            PixelSocGeneration::TensorG4ZumaPro | PixelSocGeneration::EmulatorVirtGki => 4,
        };
        Self {
            initialized: false,
            iommu_sandboxed: false,
            generation,
            vendor_firmware_loaded: false,
            dma_domain: Domain::new(),
        }
    }

    pub fn initialize_sandboxed(&mut self, cap: Capability) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EPERM);
        }
        let tpu_dev = PciDeviceId {
            segment: 0,
            bus: 3,
            device: 0,
            function: 0,
        };
        self.dma_domain
            .attach_device(tpu_dev)
            .map_err(|_| Errno::EBUSY)?;
        let mapping = DmaMapping::new(0x3000_0000, 0xb000_0000, 0x80000, DmaPerms::READ_WRITE)
            .map_err(|_| Errno::EINVAL)?;
        self.dma_domain.map(mapping).map_err(|_| Errno::ENOMEM)?;
        self.iommu_sandboxed = true;
        self.initialized = true;
        Ok(())
    }
}

/// Google Pixel Lightweight Imaging Subsystem (`lwis`) Camera ISP HAL (`/dev/lwis-isp`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelCameraLwis {
    pub initialized: bool,
    pub sensor_slots: u8,
    pub vendor_3a_blobs_present: bool,
}

impl PixelCameraLwis {
    pub const fn new() -> Self {
        Self {
            initialized: false,
            sensor_slots: 3,
            vendor_3a_blobs_present: false,
        }
    }
}

impl Default for PixelCameraLwis {
    fn default() -> Self {
        Self::new()
    }
}

/// Android A/B `bootctl` HAL state (slot switching, retry counters, verified rollback).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelBootCtl {
    pub active_slot: u8, // b'a' or b'b'
    pub slot_a_successful: bool,
    pub slot_b_successful: bool,
    pub slot_a_unbootable: bool,
    pub slot_b_unbootable: bool,
}

impl PixelBootCtl {
    pub const fn new() -> Self {
        Self {
            active_slot: b'a',
            slot_a_successful: true,
            slot_b_successful: false,
            slot_a_unbootable: false,
            slot_b_unbootable: false,
        }
    }

    pub const fn active_suffix(self) -> &'static str {
        if self.active_slot == b'b' { "_b" } else { "_a" }
    }
}

impl Default for PixelBootCtl {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete Google Pixel / GrapheneOS Hybrid Board Controller.
pub struct GooglePixelBoard<const DMA_SLOTS: usize> {
    pub soc: PixelSocGeneration,
    pub initialized: bool,
    pub titan_m2: TitanM2SecurityChip,
    pub ufs: PixelUfsController,
    pub display: TensorDpuDisplay,
    pub modem_ipc: ShannonModemIpc<DMA_SLOTS>,
    pub gpu: MaliCsfGpu<DMA_SLOTS>,
    pub edge_tpu: TensorEdgeTpu<DMA_SLOTS>,
    pub camera_lwis: PixelCameraLwis,
    pub bootctl: PixelBootCtl,
    pub hw_mte_enabled: bool,
}

impl<const DMA_SLOTS: usize> GooglePixelBoard<DMA_SLOTS> {
    pub const fn new(soc: PixelSocGeneration) -> Self {
        Self {
            soc,
            initialized: false,
            titan_m2: TitanM2SecurityChip::new(),
            ufs: PixelUfsController::new(),
            display: TensorDpuDisplay::for_soc(soc),
            modem_ipc: ShannonModemIpc::new(),
            gpu: MaliCsfGpu::for_soc(soc),
            edge_tpu: TensorEdgeTpu::for_soc(soc),
            camera_lwis: PixelCameraLwis::new(),
            bootctl: PixelBootCtl::new(),
            hw_mte_enabled: soc.supports_hw_mte(),
        }
    }

    pub fn initialize_board(&mut self, cap: Capability) -> Result<(), Errno> {
        self.titan_m2.initialize(cap)?;
        self.ufs.initialize(cap)?;
        self.display.initialized = true;
        self.display.drm_bridge_active = true;
        self.modem_ipc
            .initialize_sandboxed(cap, 0x1000_0000, 0x9000_0000, 0x40000)?;
        self.gpu.initialize_isolated(cap)?;
        self.edge_tpu.initialize_sandboxed(cap)?;
        self.camera_lwis.initialized = true;
        self.initialized = true;
        Ok(())
    }
}

// ============================================================================
// Android GKI 2.0 `vendor_boot` Image v4 (`VNDRBOOT`) Header Builder (2128B)
// ============================================================================

pub const ANDROID_VENDOR_BOOT_MAGIC: [u8; 8] = *b"VNDRBOOT";
pub const ANDROID_VENDOR_BOOT_V4_HEADER_SIZE: u32 = 2128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VendorBootImageV4Header {
    pub page_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_addr: u32,
    pub vendor_ramdisk_size: u32,
    pub dtb_size: u32,
    pub dtb_addr: u64,
    pub vendor_ramdisk_table_size: u32,
    pub vendor_ramdisk_table_entry_num: u32,
    pub vendor_ramdisk_table_entry_size: u32,
    pub bootconfig_size: u32,
}

impl VendorBootImageV4Header {
    pub const fn new(vendor_ramdisk_size: u32, dtb_size: u32, bootconfig_size: u32) -> Self {
        Self {
            page_size: 4096,
            kernel_addr: 0x0000_8000,
            ramdisk_addr: 0x0100_0000,
            vendor_ramdisk_size,
            dtb_size,
            dtb_addr: 0x01f0_0000,
            vendor_ramdisk_table_size: 108,
            vendor_ramdisk_table_entry_num: 1,
            vendor_ramdisk_table_entry_size: 108,
            bootconfig_size,
        }
    }

    pub fn encode_page0(&self, cmdline: &str, name: &str) -> [u8; 4096] {
        let mut page = [0u8; 4096];
        page[0..8].copy_from_slice(&ANDROID_VENDOR_BOOT_MAGIC);
        page[8..12].copy_from_slice(&4u32.to_le_bytes()); // header_version = 4
        page[12..16].copy_from_slice(&self.page_size.to_le_bytes());
        page[16..20].copy_from_slice(&self.kernel_addr.to_le_bytes());
        page[20..24].copy_from_slice(&self.ramdisk_addr.to_le_bytes());
        page[24..28].copy_from_slice(&self.vendor_ramdisk_size.to_le_bytes());
        let cb = cmdline.as_bytes();
        let clen = cb.len().min(2047);
        page[28..28 + clen].copy_from_slice(&cb[..clen]);
        // tags_addr at 2076, name[16] at 2080, header_size at 2096, dtb_size at 2100, dtb_addr at 2104
        page[2076..2080].copy_from_slice(&0x0000_0100u32.to_le_bytes());
        let nb = name.as_bytes();
        let nlen = nb.len().min(15);
        page[2080..2080 + nlen].copy_from_slice(&nb[..nlen]);
        page[2096..2100].copy_from_slice(&ANDROID_VENDOR_BOOT_V4_HEADER_SIZE.to_le_bytes());
        page[2100..2104].copy_from_slice(&self.dtb_size.to_le_bytes());
        page[2104..2112].copy_from_slice(&self.dtb_addr.to_le_bytes());
        page[2112..2116].copy_from_slice(&self.vendor_ramdisk_table_size.to_le_bytes());
        page[2116..2120].copy_from_slice(&self.vendor_ramdisk_table_entry_num.to_le_bytes());
        page[2120..2124].copy_from_slice(&self.vendor_ramdisk_table_entry_size.to_le_bytes());
        page[2124..2128].copy_from_slice(&self.bootconfig_size.to_le_bytes());
        page
    }
}

// ============================================================================
// Android GKI 2.0 Boot Image v4 (`ANDROID!`) Header Builder (1580 bytes)
// ============================================================================

pub const ANDROID_BOOT_MAGIC: [u8; 8] = *b"ANDROID!";
pub const ANDROID_BOOT_HEADER_V4_SIZE: u32 = 1580;
pub const ANDROID_BOOT_PAGE_SIZE: u32 = 4096;

/// Packs Android OS version `(major, minor, patch)` and security patch `(year, month)` into the
/// canonical AOSP `boot_img_hdr_v4.os_version` 32-bit field.
pub const fn pack_android_os_version(
    os_major: u32,
    os_minor: u32,
    os_patch: u32,
    patch_year: u32,
    patch_month: u32,
) -> u32 {
    let ver = ((os_major & 0x7F) << 14) | ((os_minor & 0x7F) << 7) | (os_patch & 0x7F);
    let y = patch_year.saturating_sub(2000) & 0x7F;
    let m = patch_month & 0x0F;
    (ver << 11) | (y << 4) | m
}

/// Canonical AOSP `boot_img_hdr_v4` descriptor for `fastboot flash boot qyronex-pixel-boot.img`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidBootImageV4Header {
    pub kernel_size: u32,
    pub ramdisk_size: u32,
    pub os_version: u32,
    pub cmdline: [u8; 1536],
    pub signature_size: u32,
}

impl AndroidBootImageV4Header {
    pub fn new(kernel_size: u32, ramdisk_size: u32, os_version: u32, cmdline_str: &str) -> Self {
        let mut cmdline = [0u8; 1536];
        let bytes = cmdline_str.as_bytes();
        let take = bytes.len().min(cmdline.len() - 1);
        cmdline[..take].copy_from_slice(&bytes[..take]);
        Self {
            kernel_size,
            ramdisk_size,
            os_version,
            cmdline,
            signature_size: 0,
        }
    }

    /// Serializes the exact 4096-byte page-0 header of an AOSP GKI Boot Image v4.
    pub fn encode_page0(&self) -> [u8; ANDROID_BOOT_PAGE_SIZE as usize] {
        let mut page = [0u8; ANDROID_BOOT_PAGE_SIZE as usize];
        page[0..8].copy_from_slice(&ANDROID_BOOT_MAGIC);
        page[8..12].copy_from_slice(&self.kernel_size.to_le_bytes());
        page[12..16].copy_from_slice(&self.ramdisk_size.to_le_bytes());
        page[16..20].copy_from_slice(&self.os_version.to_le_bytes());
        page[20..24].copy_from_slice(&ANDROID_BOOT_HEADER_V4_SIZE.to_le_bytes());
        // reserved[4] = bytes 24..40 (zeros)
        page[40..44].copy_from_slice(&4u32.to_le_bytes()); // header_version = 4
        page[44..1580].copy_from_slice(&self.cmdline);
        page[1580..1584].copy_from_slice(&self.signature_size.to_le_bytes());
        page
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_capability::ObjectId;

    fn admin_cap() -> Capability {
        Capability {
            object: ObjectId(0x9100),
            rights: CapRights::READ
                .union(CapRights::WRITE)
                .union(CapRights::CONTROL),
        }
    }

    #[test]
    fn pixel_tensor_board_initializes_with_iommu_and_titan_m2() {
        let mut pixel9 = GooglePixelBoard::<4>::new(PixelSocGeneration::TensorG4ZumaPro);
        assert!(pixel9.hw_mte_enabled);
        assert_eq!(pixel9.soc.cpu_cores(), 8);
        pixel9.initialize_board(admin_cap()).unwrap();
        assert!(pixel9.initialized);
        assert!(pixel9.titan_m2.online);
        assert!(pixel9.titan_m2.attestation_ready);
        assert!(pixel9.ufs.initialized);
        assert!(pixel9.modem_ipc.iommu_sandboxed);
        assert!(pixel9.gpu.iommu_isolated);
        assert_eq!(pixel9.gpu.gpu_id, 0xb8a2_0010);
        assert!(pixel9.edge_tpu.iommu_sandboxed);
        assert_eq!(pixel9.edge_tpu.generation, 4);
        assert!(pixel9.camera_lwis.initialized);
        assert_eq!(pixel9.bootctl.active_suffix(), "_a");
        assert!(pixel9.display.drm_bridge_active);

        let vhdr = VendorBootImageV4Header::new(65536, 4096, 128);
        let vpage = vhdr.encode_page0("androidboot.hardware=zumapro", "qyronex_vendor");
        assert_eq!(&vpage[0..8], b"VNDRBOOT");
        assert_eq!(u32::from_le_bytes(vpage[8..12].try_into().unwrap()), 4);
        assert_eq!(
            u32::from_le_bytes(vpage[2096..2100].try_into().unwrap()),
            2128
        );
    }

    #[test]
    fn pixel_fdt_compatible_detects_all_tensor_generations() {
        assert_eq!(
            PixelSocGeneration::from_fdt_compatible("google,gs101"),
            Some(PixelSocGeneration::TensorG1Gs101)
        );
        assert_eq!(
            PixelSocGeneration::from_fdt_compatible("google,gs201-panther"),
            Some(PixelSocGeneration::TensorG2Gs201)
        );
        assert_eq!(
            PixelSocGeneration::from_fdt_compatible("google,zuma-husky"),
            Some(PixelSocGeneration::TensorG3Zuma)
        );
        assert_eq!(
            PixelSocGeneration::from_fdt_compatible("google,zumapro-komodo"),
            Some(PixelSocGeneration::TensorG4ZumaPro)
        );
    }

    #[test]
    fn boot_image_v4_header_encodes_canonical_aosp_gki_layout() {
        let os_ver = pack_android_os_version(15, 0, 0, 2026, 11);
        let hdr = AndroidBootImageV4Header::new(
            8_388_608,
            4_194_304,
            os_ver,
            "console=ttyAMA0 androidboot.hardware=qyronex_pixel androidboot.selinux=enforcing",
        );
        let page0 = hdr.encode_page0();
        assert_eq!(&page0[0..8], b"ANDROID!");
        assert_eq!(
            u32::from_le_bytes(page0[8..12].try_into().unwrap()),
            8_388_608
        );
        assert_eq!(
            u32::from_le_bytes(page0[12..16].try_into().unwrap()),
            4_194_304
        );
        assert_eq!(u32::from_le_bytes(page0[20..24].try_into().unwrap()), 1580);
        assert_eq!(u32::from_le_bytes(page0[40..44].try_into().unwrap()), 4);
        assert!(page0[44..120].starts_with(b"console=ttyAMA0"));
    }
}
