// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

pub const EFER_MSR: u32 = 0xc000_0080;
pub const EFER_NXE: u64 = 1 << 11;
pub const CR0_WP: u64 = 1 << 16;
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FeatureLeaves {
    pub leaf1_ecx: u32,
    pub leaf7_ebx: u32,
    pub ext1_edx: u32,
    pub ext7_edx: u32,
}

impl FeatureLeaves {
    /// Clears feature words whose architectural CPUID leaves are not reported as supported.
    ///
    /// Unsupported CPUID leaves may return implementation-defined data from another leaf. Treating
    /// that data as feature bits can incorrectly enable privileged hardening such as SMEP/SMAP.
    /// Filtering by the advertised maxima keeps feature detection fail-closed.
    pub const fn filtered_by_maxima(self, max_basic: u32, max_extended: u32) -> Self {
        Self {
            leaf1_ecx: if max_basic >= 1 { self.leaf1_ecx } else { 0 },
            leaf7_ebx: if max_basic >= 7 { self.leaf7_ebx } else { 0 },
            ext1_edx: if max_extended >= 0x8000_0001 {
                self.ext1_edx
            } else {
                0
            },
            ext7_edx: if max_extended >= 0x8000_0007 {
                self.ext7_edx
            } else {
                0
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CpuVendor {
    Intel,
    Amd,
    #[default]
    Unknown,
}

impl CpuVendor {
    #[must_use]
    pub const fn from_cpuid0(ebx: u32, edx: u32, ecx: u32) -> Self {
        let b0 = ebx.to_le_bytes();
        let b1 = edx.to_le_bytes();
        let b2 = ecx.to_le_bytes();
        let vendor = [
            b0[0], b0[1], b0[2], b0[3], b1[0], b1[1], b1[2], b1[3], b2[0], b2[1], b2[2], b2[3],
        ];
        if matches!(&vendor, b"GenuineIntel") {
            Self::Intel
        } else if matches!(&vendor, b"AuthenticAMD") {
            Self::Amd
        } else {
            Self::Unknown
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intel => "GenuineIntel",
            Self::Amd => "AuthenticAMD",
            Self::Unknown => "UnknownX86_64",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuFamilyModel {
    pub stepping: u8,
    pub base_model: u8,
    pub base_family: u8,
    pub extended_model: u8,
    pub extended_family: u8,
}

impl CpuFamilyModel {
    #[must_use]
    pub const fn from_leaf1_eax(eax: u32) -> Self {
        Self {
            stepping: (eax & 0x0F) as u8,
            base_model: ((eax >> 4) & 0x0F) as u8,
            base_family: ((eax >> 8) & 0x0F) as u8,
            extended_model: ((eax >> 16) & 0x0F) as u8,
            extended_family: ((eax >> 20) & 0xFF) as u8,
        }
    }

    #[must_use]
    pub const fn display_family(self) -> u16 {
        if self.base_family == 0x0F {
            self.base_family as u16 + self.extended_family as u16
        } else {
            self.base_family as u16
        }
    }

    #[must_use]
    pub const fn display_model(self) -> u8 {
        if self.base_family == 0x06 || self.base_family == 0x0F {
            (self.extended_model << 4) | self.base_model
        } else {
            self.base_model
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessorLeaves {
    pub leaf0_eax: u32,
    pub leaf0_ebx: u32,
    pub leaf0_ecx: u32,
    pub leaf0_edx: u32,
    pub leaf1_eax: u32,
    pub leaf1_ecx: u32,
    pub leaf1_edx: u32,
    pub leaf7_ebx: u32,
    pub leaf7_ecx: u32,
    pub ext0_eax: u32,
    pub ext1_ecx: u32,
    pub ext1_edx: u32,
    pub ext7_edx: u32,
    pub ext8_eax: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExtendedCpuFeatures {
    pub sse2: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub popcnt: bool,
    pub aesni: bool,
    pub xsave: bool,
    pub osxsave: bool,
    pub avx: bool,
    pub avx2: bool,
    pub pcid: bool,
    pub invpcid: bool,
    pub fsgsbase: bool,
    pub rdrand: bool,
    pub rdseed: bool,
    pub umip: bool,
    pub vmx: bool,
    pub svm: bool,
    pub syscall_sysret: bool,
    pub lahf_lm: bool,
    pub abm_lzcnt: bool,
    pub sse4a: bool,
    pub topoext: bool,
    pub page1gb: bool,
    pub physical_address_bits: u8,
    pub linear_address_bits: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessorProfile {
    pub vendor: CpuVendor,
    pub family_model: CpuFamilyModel,
    pub core_features: CpuFeatures,
    pub extended: ExtendedCpuFeatures,
}

impl ProcessorProfile {
    #[must_use]
    pub const fn from_leaves(leaves: ProcessorLeaves) -> Self {
        let vendor = CpuVendor::from_cpuid0(leaves.leaf0_ebx, leaves.leaf0_edx, leaves.leaf0_ecx);
        let family_model = CpuFamilyModel::from_leaf1_eax(leaves.leaf1_eax);
        let core_features = CpuFeatures::from_leaves(FeatureLeaves {
            leaf1_ecx: leaves.leaf1_ecx,
            leaf7_ebx: leaves.leaf7_ebx,
            ext1_edx: leaves.ext1_edx,
            ext7_edx: leaves.ext7_edx,
        });
        let phys_bits = (leaves.ext8_eax & 0xFF) as u8;
        let lin_bits = ((leaves.ext8_eax >> 8) & 0xFF) as u8;
        let extended = ExtendedCpuFeatures {
            sse2: (leaves.leaf1_edx & (1 << 26)) != 0,
            sse3: (leaves.leaf1_ecx & (1 << 0)) != 0,
            ssse3: (leaves.leaf1_ecx & (1 << 9)) != 0,
            sse4_1: (leaves.leaf1_ecx & (1 << 19)) != 0,
            sse4_2: (leaves.leaf1_ecx & (1 << 20)) != 0,
            popcnt: (leaves.leaf1_ecx & (1 << 23)) != 0,
            aesni: (leaves.leaf1_ecx & (1 << 25)) != 0,
            xsave: (leaves.leaf1_ecx & (1 << 26)) != 0,
            osxsave: (leaves.leaf1_ecx & (1 << 27)) != 0,
            avx: (leaves.leaf1_ecx & (1 << 28)) != 0,
            avx2: (leaves.leaf7_ebx & (1 << 5)) != 0,
            pcid: (leaves.leaf1_ecx & (1 << 17)) != 0,
            invpcid: (leaves.leaf7_ebx & (1 << 10)) != 0,
            fsgsbase: (leaves.leaf7_ebx & (1 << 0)) != 0,
            rdrand: (leaves.leaf1_ecx & (1 << 30)) != 0,
            rdseed: (leaves.leaf7_ebx & (1 << 18)) != 0,
            umip: (leaves.leaf7_ecx & (1 << 2)) != 0,
            vmx: (leaves.leaf1_ecx & (1 << 5)) != 0,
            svm: (leaves.ext1_ecx & (1 << 2)) != 0,
            syscall_sysret: (leaves.ext1_edx & (1 << 11)) != 0,
            lahf_lm: (leaves.ext1_ecx & (1 << 0)) != 0,
            abm_lzcnt: (leaves.ext1_ecx & (1 << 5)) != 0,
            sse4a: (leaves.ext1_ecx & (1 << 6)) != 0,
            topoext: (leaves.ext1_ecx & (1 << 22)) != 0,
            page1gb: (leaves.ext1_edx & (1 << 26)) != 0,
            physical_address_bits: if phys_bits == 0 { 36 } else { phys_bits },
            linear_address_bits: if lin_bits == 0 { 48 } else { lin_bits },
        };

        Self {
            vendor,
            family_model,
            core_features,
            extended,
        }
    }

    #[must_use]
    pub const fn supports_hardware_virtualization(self) -> bool {
        self.extended.vmx || self.extended.svm
    }

    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub fn detect() -> Self {
        use core::arch::x86_64::{__cpuid, __cpuid_count};

        let leaf0 = __cpuid(0);
        let leaf1 = if leaf0.eax >= 1 {
            __cpuid(1)
        } else {
            core::arch::x86_64::CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        };
        let leaf7 = if leaf0.eax >= 7 {
            __cpuid_count(7, 0)
        } else {
            core::arch::x86_64::CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        };
        let ext0 = __cpuid(0x8000_0000);
        let ext1 = if ext0.eax >= 0x8000_0001 {
            __cpuid(0x8000_0001)
        } else {
            core::arch::x86_64::CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        };
        let ext7 = if ext0.eax >= 0x8000_0007 {
            __cpuid(0x8000_0007)
        } else {
            core::arch::x86_64::CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        };
        let ext8 = if ext0.eax >= 0x8000_0008 {
            __cpuid(0x8000_0008)
        } else {
            core::arch::x86_64::CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        };

        Self::from_leaves(ProcessorLeaves {
            leaf0_eax: leaf0.eax,
            leaf0_ebx: leaf0.ebx,
            leaf0_ecx: leaf0.ecx,
            leaf0_edx: leaf0.edx,
            leaf1_eax: leaf1.eax,
            leaf1_ecx: leaf1.ecx,
            leaf1_edx: leaf1.edx,
            leaf7_ebx: leaf7.ebx,
            leaf7_ecx: leaf7.ecx,
            ext0_eax: ext0.eax,
            ext1_ecx: ext1.ecx,
            ext1_edx: ext1.edx,
            ext7_edx: ext7.edx,
            ext8_eax: ext8.eax,
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[must_use]
    pub const fn detect() -> Self {
        Self::from_leaves(ProcessorLeaves {
            leaf0_eax: 0,
            leaf0_ebx: 0,
            leaf0_ecx: 0,
            leaf0_edx: 0,
            leaf1_eax: 0,
            leaf1_ecx: 0,
            leaf1_edx: 0,
            leaf7_ebx: 0,
            leaf7_ecx: 0,
            ext0_eax: 0,
            ext1_ecx: 0,
            ext1_edx: 0,
            ext7_edx: 0,
            ext8_eax: 0,
        })
    }
}

#[cfg(test)]
mod vendor_profile_tests {
    use super::{CpuVendor, ProcessorLeaves, ProcessorProfile};

    #[test]
    fn decodes_genuine_intel_processor_profile() {
        let profile = ProcessorProfile::from_leaves(ProcessorLeaves {
            leaf0_eax: 0x20,
            leaf0_ebx: u32::from_le_bytes(*b"Genu"),
            leaf0_edx: u32::from_le_bytes(*b"ineI"),
            leaf0_ecx: u32::from_le_bytes(*b"ntel"),
            // Family 6, Extended Model 0x9, Base Model 0x7 (Alder Lake 0x97), Stepping 2
            leaf1_eax: (0x09 << 16) | (0x06 << 8) | (0x07 << 4) | 0x02,
            leaf1_ecx: (1 << 0)
                | (1 << 5)
                | (1 << 9)
                | (1 << 17)
                | (1 << 19)
                | (1 << 20)
                | (1 << 21)
                | (1 << 23)
                | (1 << 24)
                | (1 << 25)
                | (1 << 26)
                | (1 << 27)
                | (1 << 28)
                | (1 << 30),
            leaf1_edx: 1 << 26,
            leaf7_ebx: (1 << 0) | (1 << 5) | (1 << 7) | (1 << 10) | (1 << 18) | (1 << 20),
            leaf7_ecx: 1 << 2,
            ext0_eax: 0x8000_0008,
            ext1_ecx: 1 << 0,
            ext1_edx: (1 << 11) | (1 << 20) | (1 << 26) | (1 << 27),
            ext7_edx: 1 << 8,
            ext8_eax: (48 << 8) | 46,
        });

        assert_eq!(profile.vendor, CpuVendor::Intel);
        assert_eq!(profile.vendor.as_str(), "GenuineIntel");
        assert_eq!(profile.family_model.display_family(), 6);
        assert_eq!(profile.family_model.display_model(), 0x97);
        assert_eq!(profile.family_model.stepping, 2);
        assert!(profile.extended.vmx);
        assert!(!profile.extended.svm);
        assert!(profile.extended.avx2);
        assert!(profile.extended.pcid);
        assert!(profile.extended.invpcid);
        assert!(profile.extended.aesni);
        assert!(profile.extended.rdrand);
        assert!(profile.extended.rdseed);
        assert!(profile.core_features.nx);
        assert!(profile.core_features.x2apic);
        assert!(profile.core_features.smep);
        assert!(profile.core_features.smap);
        assert_eq!(profile.extended.physical_address_bits, 46);
        assert_eq!(profile.extended.linear_address_bits, 48);
        assert!(profile.supports_hardware_virtualization());
    }

    #[test]
    fn decodes_authentic_amd_zen_processor_profile() {
        let profile = ProcessorProfile::from_leaves(ProcessorLeaves {
            leaf0_eax: 0x10,
            leaf0_ebx: u32::from_le_bytes(*b"Auth"),
            leaf0_edx: u32::from_le_bytes(*b"enti"),
            leaf0_ecx: u32::from_le_bytes(*b"cAMD"),
            // Base family 0x0F + Extended family 0x0A = Family 0x19 (Zen 3/4), Model 0x61, Stepping 1
            leaf1_eax: (0x0A << 20) | (0x06 << 16) | (0x0F << 8) | (0x01 << 4) | 0x01,
            leaf1_ecx: (1 << 0)
                | (1 << 9)
                | (1 << 19)
                | (1 << 20)
                | (1 << 21)
                | (1 << 23)
                | (1 << 25)
                | (1 << 26)
                | (1 << 27)
                | (1 << 28)
                | (1 << 30),
            leaf1_edx: 1 << 26,
            leaf7_ebx: (1 << 0) | (1 << 5) | (1 << 7) | (1 << 18) | (1 << 20),
            leaf7_ecx: 1 << 2,
            ext0_eax: 0x8000_001F,
            ext1_ecx: (1 << 0) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 22),
            ext1_edx: (1 << 11) | (1 << 20) | (1 << 26) | (1 << 27),
            ext7_edx: 1 << 8,
            ext8_eax: (48 << 8) | 48,
        });

        assert_eq!(profile.vendor, CpuVendor::Amd);
        assert_eq!(profile.vendor.as_str(), "AuthenticAMD");
        assert_eq!(profile.family_model.display_family(), 0x19);
        assert_eq!(profile.family_model.display_model(), 0x61);
        assert_eq!(profile.family_model.stepping, 1);
        assert!(profile.extended.svm);
        assert!(!profile.extended.vmx);
        assert!(profile.extended.topoext);
        assert!(profile.extended.sse4a);
        assert!(profile.extended.abm_lzcnt);
        assert!(profile.extended.page1gb);
        assert!(profile.extended.syscall_sysret);
        assert!(profile.core_features.invariant_tsc);
        assert_eq!(profile.extended.physical_address_bits, 48);
        assert!(profile.supports_hardware_virtualization());
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuFeatures {
    pub nx: bool,
    pub x2apic: bool,
    pub tsc_deadline: bool,
    pub invariant_tsc: bool,
    pub rdtscp: bool,
    pub smep: bool,
    pub smap: bool,
}

impl CpuFeatures {
    pub const fn from_leaves(leaves: FeatureLeaves) -> Self {
        Self {
            nx: leaves.ext1_edx & (1 << 20) != 0,
            x2apic: leaves.leaf1_ecx & (1 << 21) != 0,
            tsc_deadline: leaves.leaf1_ecx & (1 << 24) != 0,
            invariant_tsc: leaves.ext7_edx & (1 << 8) != 0,
            rdtscp: leaves.ext1_edx & (1 << 27) != 0,
            smep: leaves.leaf7_ebx & (1 << 7) != 0,
            smap: leaves.leaf7_ebx & (1 << 20) != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardeningError {
    NxRequired,
}

/// Detects features used by hardening, APIC, timer and context-switch policy.
#[cfg(target_arch = "x86_64")]
pub fn detect_features() -> CpuFeatures {
    use core::arch::x86_64::__cpuid;

    let basic = __cpuid(0);
    let ext_max = __cpuid(0x8000_0000);
    let leaves = FeatureLeaves {
        leaf1_ecx: if basic.eax >= 1 { __cpuid(1).ecx } else { 0 },
        leaf7_ebx: if basic.eax >= 7 { __cpuid(7).ebx } else { 0 },
        ext1_edx: if ext_max.eax >= 0x8000_0001 {
            __cpuid(0x8000_0001).edx
        } else {
            0
        },
        ext7_edx: if ext_max.eax >= 0x8000_0007 {
            __cpuid(0x8000_0007).edx
        } else {
            0
        },
    }
    .filtered_by_maxima(basic.eax, ext_max.eax);
    CpuFeatures::from_leaves(leaves)
}

/// Reads TSC with an LFENCE before RDTSC so prior loads are ordered before the sample.
/// This is appropriate for kernel-local monotonic sampling once TSC suitability is established.
#[cfg(target_arch = "x86_64")]
pub fn read_tsc_ordered() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: RDTSC is available on x86_64; LFENCE prevents earlier loads passing the sample.
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    ((high as u64) << 32) | low as u64
}

/// Non-x86 host-test guard. The x86 support crates are allowed to compile on AArch64 developer
/// hosts, but executing an x86 TSC operation there is always a programming error.
#[cfg(not(target_arch = "x86_64"))]
pub fn read_tsc_ordered() -> u64 {
    panic!("x86 TSC access attempted on a non-x86_64 host")
}

/// Reads RDTSCP and returns `(cycles, TSC_AUX)`; call only after feature detection.
///
/// # Safety
/// `features.rdtscp` must be true for the current CPU.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_rdtscp(features: CpuFeatures) -> Option<(u64, u32)> {
    if !features.rdtscp {
        return None;
    }
    let low: u32;
    let high: u32;
    let aux: u32;
    // SAFETY: feature bit was checked above; LFENCE prevents later loads from moving before sample.
    unsafe {
        asm!(
            "rdtscp",
            out("eax") low,
            out("edx") high,
            out("ecx") aux,
            options(nomem, nostack)
        );
        asm!("lfence", options(nomem, nostack));
    }
    Some((((high as u64) << 32) | low as u64, aux))
}

/// Enables baseline WP+NX invariants.
///
/// # Safety
/// Caller must execute in ring 0 with valid MSR support and compatible current mappings.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_baseline_hardening(features: CpuFeatures) -> Result<(), HardeningError> {
    if !features.nx {
        return Err(HardeningError::NxRequired);
    }
    let mut cr0: u64;
    // SAFETY: caller guarantees ring 0.
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags)) };
    cr0 |= CR0_WP;
    // SAFETY: only WP is added.
    unsafe { asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags)) };
    // SAFETY: caller guarantees ring 0.
    let mut efer = unsafe { rdmsr(EFER_MSR) };
    efer |= EFER_NXE;
    // SAFETY: existing EFER mode bits are preserved.
    unsafe { wrmsr(EFER_MSR, efer) };
    Ok(())
}

/// Enables SMEP after all intended kernel instruction mappings are supervisor mappings.
///
/// # Safety
/// Must run in ring 0 after page-table privilege bits are correct.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_smep(features: CpuFeatures) {
    if !features.smep {
        return;
    }
    let mut cr4: u64;
    // SAFETY: caller guarantees ring 0.
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)) };
    cr4 |= CR4_SMEP;
    // SAFETY: feature was detected.
    unsafe { asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags)) };
}

/// Enables SMAP. User-copy helpers must bracket intentional accesses with STAC/CLAC.
///
/// # Safety
/// Must run in ring 0 only after all user-copy paths are SMAP-aware.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_smap(features: CpuFeatures) {
    if !features.smap {
        return;
    }
    let mut cr4: u64;
    // SAFETY: caller guarantees ring 0.
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)) };
    cr4 |= CR4_SMAP;
    // SAFETY: feature was detected.
    unsafe { asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags)) };
}

/// Reads one x86 MSR. The symbol stays visible on foreign developer hosts so support crates and IDE
/// analysis can resolve the API, but any attempted non-x86 execution fails closed.
///
/// # Safety
/// On x86_64, caller must execute in ring 0 and provide a valid MSR index. On any other architecture
/// this function always panics before touching hardware.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let low: u32;
        let high: u32;
        // SAFETY: delegated to caller.
        unsafe {
            asm!(
                "rdmsr",
                in("ecx") msr,
                out("eax") low,
                out("edx") high,
                options(nostack, preserves_flags)
            )
        };
        return ((high as u64) << 32) | low as u64;
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = msr;
        panic!("x86 RDMSR attempted on a non-x86_64 host")
    }
}

/// Writes one x86 MSR. Like `rdmsr`, the API remains structurally visible on foreign hosts while
/// hardware access itself remains strictly x86_64-only and fail-closed elsewhere.
///
/// # Safety
/// On x86_64, caller must execute in ring 0 and ensure value validity for the MSR. On any other
/// architecture this function always panics before touching hardware.
pub unsafe fn wrmsr(msr: u32, value: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        let low = value as u32;
        let high = (value >> 32) as u32;
        // SAFETY: delegated to caller.
        unsafe {
            asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") low,
                in("edx") high,
                options(nostack, preserves_flags)
            )
        };
        return;
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (msr, value);
        panic!("x86 WRMSR attempted on a non-x86_64 host")
    }
}

pub mod idt {
    #[cfg(target_arch = "x86_64")]
    use core::arch::asm;

    pub const ENTRY_COUNT: usize = 256;
    pub const INTERRUPT_GATE: u8 = 0x0e;

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct Entry {
        offset_low: u16,
        selector: u16,
        ist: u8,
        type_attributes: u8,
        offset_mid: u16,
        offset_high: u32,
        reserved: u32,
    }

    impl Entry {
        pub const MISSING: Self = Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attributes: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        };

        pub fn interrupt_gate(handler: u64, selector: u16, ist_index: u8, dpl: u8) -> Option<Self> {
            if ist_index > 7 || dpl > 3 {
                return None;
            }
            Some(Self {
                offset_low: handler as u16,
                selector,
                ist: ist_index & 0x7,
                type_attributes: 0x80 | ((dpl & 0x3) << 5) | INTERRUPT_GATE,
                offset_mid: (handler >> 16) as u16,
                offset_high: (handler >> 32) as u32,
                reserved: 0,
            })
        }

        pub const fn handler_address(&self) -> u64 {
            self.offset_low as u64
                | ((self.offset_mid as u64) << 16)
                | ((self.offset_high as u64) << 32)
        }

        pub const fn present(&self) -> bool {
            self.type_attributes & 0x80 != 0
        }

        pub const fn ist_index(&self) -> u8 {
            self.ist & 0x7
        }
    }

    #[repr(C, align(16))]
    pub struct Table(pub [Entry; ENTRY_COUNT]);

    impl Table {
        pub const fn new() -> Self {
            Self([Entry::MISSING; ENTRY_COUNT])
        }

        pub fn set(&mut self, vector: u8, entry: Entry) {
            self.0[vector as usize] = entry;
        }
    }

    impl Default for Table {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[repr(C, packed)]
    struct DescriptorTablePointer {
        limit: u16,
        base: u64,
    }

    /// # Safety
    /// `table` must remain resident/mapped for as long as interrupts can reference it.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn load(table: &'static Table) {
        let pointer = DescriptorTablePointer {
            limit: (core::mem::size_of::<Table>() - 1) as u16,
            base: table as *const Table as u64,
        };
        // SAFETY: caller guarantees table lifetime and privileged execution.
        unsafe { asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_decoder_maps_architectural_bits() {
        let leaves = FeatureLeaves {
            leaf1_ecx: (1 << 21) | (1 << 24),
            leaf7_ebx: (1 << 7) | (1 << 20),
            ext1_edx: (1 << 20) | (1 << 27),
            ext7_edx: 1 << 8,
        };
        assert_eq!(
            CpuFeatures::from_leaves(leaves),
            CpuFeatures {
                nx: true,
                x2apic: true,
                tsc_deadline: true,
                invariant_tsc: true,
                rdtscp: true,
                smep: true,
                smap: true,
            }
        );
    }

    #[test]
    fn unsupported_cpuid_leaves_are_filtered_fail_closed() {
        let bogus = FeatureLeaves {
            leaf1_ecx: u32::MAX,
            leaf7_ebx: u32::MAX,
            ext1_edx: u32::MAX,
            ext7_edx: u32::MAX,
        };
        assert_eq!(
            bogus.filtered_by_maxima(0, 0x8000_0000),
            FeatureLeaves::default()
        );

        let partial = bogus.filtered_by_maxima(1, 0x8000_0001);
        assert_eq!(partial.leaf1_ecx, u32::MAX);
        assert_eq!(partial.leaf7_ebx, 0);
        assert_eq!(partial.ext1_edx, u32::MAX);
        assert_eq!(partial.ext7_edx, 0);
        assert_eq!(
            CpuFeatures::from_leaves(bogus.filtered_by_maxima(0, 0x8000_0000)),
            CpuFeatures::default()
        );
    }

    #[test]
    fn idt_gate_round_trips_handler_and_validates_ist() {
        let handler = 0xffff_ffff_8123_4567;
        let gate = idt::Entry::interrupt_gate(handler, 0x8, 1, 0).unwrap();
        assert_eq!(gate.handler_address(), handler);
        assert!(gate.present());
        assert_eq!(gate.ist_index(), 1);
        assert!(idt::Entry::interrupt_gate(handler, 0x8, 8, 0).is_none());
    }
}
