// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 44 — Debian 13 compatibility release gate, conformance, deterministic fuzz/stress,
//! and ambient-authority audit across Linux ABI, VirtIO drivers, server hardware, and desktop seats.

use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_fdt::Blob;
use kernal_fdt_aarch64::parse_device_inventory;
use kernal_iommu::{DmaMapping, DmaPerms};
use kernal_linux_abi::{
    Errno, OPENAT2_KNOWN_RESOLVE_MASK, SyscallReturn, validate_openat2_resolve,
};
use kernal_linux_cgroup::{
    ProcessSecurityState, SECCOMP_RET_ALLOW, SECCOMP_SET_MODE_FILTER, SeccompBpfInsn,
};
use kernal_linux_debian_profile::KernelCmdline;
use kernal_linux_desktop::{DrmDevice, EV_KEY, InputEvent, PcmAudioDevice, SeatManager};
use kernal_linux_dpkg::parse_shebang;
use kernal_linux_hardware::{
    AhciController, HardwareEntropyPool, NvmeController, RtcPl031, RtcTime, StorageError,
    WatchdogDevice, parse_config_descriptors,
};
use kernal_pci::{Address as PciAddress, EcamWindow};
use kernal_virtio::blk::{
    SUPPORTED_BLK_FEATURES, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, validate_blk_request,
};
use kernal_virtio::net::{
    NetDirection, VIRTIO_NET_F_MAC, VirtioNetL3, VirtioNetL4, VirtioNetValidation,
    validate_net_request,
};
use kernal_virtio::{
    DmaBufferGrant, SECTOR_SIZE, VIRTIO_F_VERSION_1, VirtioBlkOp, VirtioError, VirtqDesc,
    validate_descriptor_chain,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateResult {
    pub id: &'static str,
    pub passed: u32,
    pub failed: u32,
}

impl GateResult {
    const fn check(&mut self, ok: bool) {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseGateReport {
    pub gates: [GateResult; 5],
}

impl ReleaseGateReport {
    pub fn total_passed(&self) -> u32 {
        self.gates.iter().map(|g| g.passed).sum()
    }

    pub fn total_failed(&self) -> u32 {
        self.gates.iter().map(|g| g.failed).sum()
    }

    pub fn all_passed(&self) -> bool {
        self.total_failed() == 0 && self.total_passed() > 0
    }

    pub fn format_summary(&self, out: &mut [u8]) -> usize {
        let mut cursor = 0usize;
        cursor += copy_ascii(out, cursor, b"KERNAL_RELEASE_GATE_STEP44 status=");
        cursor += copy_ascii(
            out,
            cursor,
            if self.all_passed() { b"PASS" } else { b"FAIL" },
        );
        cursor += copy_ascii(out, cursor, b"\n");
        for g in &self.gates {
            cursor += copy_ascii(out, cursor, g.id.as_bytes());
            cursor += copy_ascii(out, cursor, b": passed=");
            cursor += write_u32(out, cursor, g.passed);
            cursor += copy_ascii(out, cursor, b" failed=");
            cursor += write_u32(out, cursor, g.failed);
            cursor += copy_ascii(out, cursor, b"\n");
        }
        cursor
    }
}

fn copy_ascii(dst: &mut [u8], offset: usize, src: &[u8]) -> usize {
    if offset >= dst.len() {
        return 0;
    }
    let avail = dst.len() - offset;
    let take = core::cmp::min(avail, src.len());
    dst[offset..offset + take].copy_from_slice(&src[..take]);
    take
}

fn write_u32(dst: &mut [u8], offset: usize, mut v: u32) -> usize {
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    loop {
        tmp[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut written = 0usize;
    for i in 0..len {
        written += copy_ascii(dst, offset + written, &[tmp[len - 1 - i]]);
    }
    written
}

/// Runs all five Step-44 conformance, driver-corpus, authority-audit, and stress/fuzz gates.
pub fn run_all_gates() -> ReleaseGateReport {
    ReleaseGateReport {
        gates: [
            gate_syscall_abi_and_boot(),
            gate_virtio_driver_negative_positive(),
            gate_server_hardware_bounds(),
            gate_authority_and_desktop_isolation(),
            gate_deterministic_fuzz_stress(),
        ],
    }
}

pub fn gate_syscall_abi_and_boot() -> GateResult {
    let mut r = GateResult {
        id: "gate1.syscall_abi_boot",
        passed: 0,
        failed: 0,
    };
    r.check(SyscallReturn::error(Errno::ENOSYS).as_u64_bits() == (-38i64) as u64);
    r.check(validate_openat2_resolve(OPENAT2_KNOWN_RESOLVE_MASK + 1).is_err());
    r.check(KernelCmdline::parse(&[b'a'; 300]) == Err(Errno::ENAMETOOLONG));
    r.check(
        KernelCmdline::parse(b"root=/dev/vda1 rw rootfstype=ext4 console=ttyAMA0")
            .map(|c| c.root_rw())
            .unwrap_or(false),
    );
    r
}

pub fn gate_virtio_driver_negative_positive() -> GateResult {
    let mut r = GateResult {
        id: "gate2.virtio_corpus",
        passed: 0,
        failed: 0,
    };
    let grant = DmaBufferGrant {
        base_addr: 0x8000_0000,
        len: 0x4000,
        writable: true,
        dma_assigned: true,
        buffer_generation: 4,
        expected_generation: 4,
        revoked: false,
    };
    let linear_desc = [
        VirtqDesc {
            addr: 0x8000_0000,
            len: 16,
            flags: 1, // NEXT
            next: 1,
        },
        VirtqDesc {
            addr: 0x8000_0100,
            len: SECTOR_SIZE as u32,
            flags: 2, // WRITE
            next: 0,
        },
    ];
    r.check(
        validate_blk_request(
            8,
            VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH,
            VirtioBlkOp::Read,
            &linear_desc,
            0,
            &grant,
        )
        .is_ok(),
    );
    let cycle_desc = [
        VirtqDesc {
            addr: 0x8000_0000,
            len: 16,
            flags: 1,
            next: 1,
        },
        VirtqDesc {
            addr: 0x8000_0100,
            len: 16,
            flags: 1,
            next: 0,
        },
    ];
    r.check(
        validate_descriptor_chain(8, &cycle_desc, 0, Some(&grant))
            == Err(VirtioError::DescriptorCycle),
    );
    r.check(
        validate_descriptor_chain(6, &linear_desc, 0, Some(&grant))
            == Err(VirtioError::InvalidQueueSize),
    );
    r.check(
        validate_blk_request(
            8,
            VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_RO,
            VirtioBlkOp::Write,
            &linear_desc,
            0,
            &grant,
        ) == Err(VirtioError::ReadOnlyDevice),
    );
    r.check(
        validate_blk_request(
            8,
            VIRTIO_F_VERSION_1,
            VirtioBlkOp::Flush,
            &linear_desc,
            0,
            &grant,
        ) == Err(VirtioError::UnsupportedOp),
    );
    r.check(
        validate_blk_request(
            8,
            SUPPORTED_BLK_FEATURES | (1u64 << 60),
            VirtioBlkOp::Read,
            &linear_desc,
            0,
            &grant,
        ) == Err(VirtioError::UnsupportedFeature),
    );

    let net_desc = [VirtqDesc {
        addr: 0x8000_0000,
        len: 128,
        flags: 0,
        next: 0,
    }];
    r.check(
        validate_net_request(VirtioNetValidation {
            queue_size: 256,
            features: VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC,
            direction: NetDirection::Tx,
            packet_len: 1600,
            mtu: 1500,
            l3: VirtioNetL3::Ipv4,
            l4: Some(VirtioNetL4::Udp),
            descriptors: &net_desc,
            head: 0,
            grant: &grant,
        }) == Err(VirtioError::InvalidPacket),
    );
    r
}

pub fn gate_server_hardware_bounds() -> GateResult {
    let mut r = GateResult {
        id: "gate3.server_hardware",
        passed: 0,
        failed: 0,
    };
    let cap_ro = Capability {
        object: ObjectId(44),
        rights: CapRights::READ,
    };
    let cap_ctrl = Capability {
        object: ObjectId(44),
        rights: CapRights::CONTROL
            .union(CapRights::READ)
            .union(CapRights::WRITE),
    };
    let ecam = EcamWindow {
        base: 0x40_1000_0000,
        segment: 0,
        start_bus: 0,
        end_bus: 3,
    };
    let pci = PciAddress {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    let dma_rw = DmaMapping::new(0x1000_0000, 0x8000_0000, 0x1000, DmaPerms::READ_WRITE).unwrap();
    let mut nvme = NvmeController::<4>::new(ecam, pci, false).unwrap();
    let mut buf = [0u8; 512];
    r.check(
        nvme.read_blocks(cap_ro, &dma_rw, 1, 0x1000_0000, 0, &mut buf)
            == Err(StorageError::NotReady),
    );
    r.check(nvme.enable(cap_ro, 16, 16) == Err(StorageError::PermissionDenied));
    r.check(nvme.enable(cap_ctrl, 16, 16).is_ok());

    let mut ahci = AhciController::<2, 4>::new();
    let g0 = ahci.enable_port(cap_ctrl, 0, true).unwrap();
    r.check(
        ahci.sata_rw(
            cap_ctrl,
            &dma_rw,
            kernal_linux_hardware::SataCommand {
                port: 0,
                command_slot: 0,
                expected_generation: g0,
                prdt_iova: 0x1000_0000,
                lba: 0,
                write: true,
            },
            &mut buf,
        ) == Err(StorageError::ReadOnly),
    );

    let mut rtc = RtcPl031::new(0);
    let invalid_date = RtcTime {
        sec: 0,
        min: 0,
        hour: 0,
        mday: 30,
        mon: 1, // Feb 30 invalid
        year: 125,
        wday: 0,
        yday: 0,
        isdst: 0,
    };
    r.check(rtc.set_time(cap_ctrl, invalid_date) == Err(Errno::EINVAL));
    let mut wdt = WatchdogDevice::new(15, false);
    r.check(wdt.set_timeout(cap_ctrl, 0) == Err(Errno::EINVAL));
    let mut entropy = HardwareEntropyPool::new();
    let mut bytes = [0u8; 16];
    r.check(entropy.fill_bytes(&mut bytes) == Err(Errno::EAGAIN));
    r
}

pub fn gate_authority_and_desktop_isolation() -> GateResult {
    let mut r = GateResult {
        id: "gate4.authority_desktop",
        passed: 0,
        failed: 0,
    };
    let unpriv_cap = Capability {
        object: ObjectId(99),
        rights: CapRights::NONE,
    };
    let ctrl_cap = Capability {
        object: ObjectId(99),
        rights: CapRights::CONTROL
            .union(CapRights::READ)
            .union(CapRights::WRITE),
    };

    let mut proc_sec = ProcessSecurityState::new_unprivileged(unpriv_cap);
    let insn = [SeccompBpfInsn {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    }];
    // Without NO_NEW_PRIVS or CAP_SYS_ADMIN, installing a seccomp filter fails closed.
    r.check(proc_sec.seccomp_syscall(SECCOMP_SET_MODE_FILTER, 0, &insn) == Err(Errno::EACCES));

    let mut seat = SeatManager::new();
    let s1 = seat.open_session(ctrl_cap, 1000, 1).unwrap();
    let s2 = seat.open_session(ctrl_cap, 1001, 2).unwrap();
    let g1 = seat.activate_session(ctrl_cap, s1.session_id).unwrap();
    seat.evdev
        .push_event(InputEvent {
            sec: 1,
            usec: 0,
            event_type: EV_KEY,
            code: 28,
            value: 1,
        })
        .unwrap();
    let _g2 = seat.activate_session(ctrl_cap, s2.session_id).unwrap();
    r.check(
        seat.evdev
            .read_event(g1.session_id, g1.generation, seat.active_session())
            == Err(Errno::EACCES),
    );
    let mut drm = DrmDevice::new();
    r.check(
        drm.set_master(
            unpriv_cap,
            s1.session_id,
            g1.generation,
            seat.seat_generation(),
        ) == Err(Errno::EACCES),
    );
    let mut pcm = PcmAudioDevice::new();
    r.check(pcm.prepare() == Err(Errno::EBADF));
    r
}

pub fn gate_deterministic_fuzz_stress() -> GateResult {
    let mut r = GateResult {
        id: "gate5.fuzz_stress",
        passed: 0,
        failed: 0,
    };
    let mut seed = 0x517c_c1b7_2722_0a95u64;
    let mut fuzzed_inputs = [0u8; 128];
    for iter in 0..64u32 {
        for chunk in fuzzed_inputs.chunks_mut(8) {
            seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes());
        }
        let slice_len = ((iter * 7) % 128) as usize;
        let sample = &fuzzed_inputs[..slice_len];
        if let Ok(blob) = Blob::parse(sample) {
            let _ = parse_device_inventory::<4>(&blob);
        }
        let _ = parse_config_descriptors(sample);
        let _ = parse_shebang(sample, 0);
        let _ = KernelCmdline::parse(sample);
        r.passed += 1;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_gate_passes_all_conformance_security_and_fuzz_suites() {
        let report = run_all_gates();
        assert!(report.all_passed(), "report had failures: {report:?}");
        assert_eq!(report.total_failed(), 0);
        assert!(report.total_passed() >= 80);

        let mut summary = [0u8; 512];
        let n = report.format_summary(&mut summary);
        let text = core::str::from_utf8(&summary[..n]).unwrap();
        assert!(text.contains("status=PASS"));
        assert!(text.contains("gate2.virtio_corpus"));
        assert!(text.contains("gate5.fuzz_stress"));
    }
}
