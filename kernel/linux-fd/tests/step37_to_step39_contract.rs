// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP15_QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const STEP33_MOUNTS: &str = include_str!("../../core-aarch64/src/step33_mounts.rs");
const STEP34_NET: &str = include_str!("../../core-aarch64/src/step34_net.rs");
const STEP35_EVENTS_CGROUP: &str = include_str!("../../core-aarch64/src/step35_events_cgroup.rs");
const STEP37_38: &str = include_str!("../../core-aarch64/src/step37_38_systemd_udev.rs");
const STEP39: &str = include_str!("../../core-aarch64/src/step39_dpkg.rs");

#[test]
fn steps37_to_39_are_wired_into_aarch64_svc_dispatch() {
    assert!(STEP15_QEMU.contains("#[path = \"step37_38_systemd_udev.rs\"]"));
    assert!(STEP15_QEMU.contains("step37_38_systemd_udev::try_handle_syscall(request)"));
    assert!(STEP15_QEMU.contains("#[path = \"step39_dpkg.rs\"]"));
    assert!(
        STEP15_QEMU.contains("step39_dpkg::try_handle_syscall(request)")
            || STEP15_QEMU.contains("step39_dpkg::try_handle_syscall_with_frame(request,")
    );
}

#[test]
fn step33_converts_proc_and_sys_option_reads_and_delegates_udev_attrs() {
    assert!(STEP33_MOUNTS.contains("fn synthesize_proc_or_sys_node"));
    assert!(
        STEP33_MOUNTS
            .contains("read_procfs_node(rel, mounts, snap, node_buf).ok_or(Errno::ENOENT)")
    );
    assert!(STEP33_MOUNTS.contains("read_sysfs_node(rel, snap, node_buf).ok_or(Errno::ENOENT)"));
    assert!(
        STEP33_MOUNTS.contains("step37_38_systemd_udev::read_sysfs_device_attr(rel, node_buf)")
    );
    assert!(STEP33_MOUNTS.contains("step37_38_systemd_udev::is_sysfs_uevent_trigger_rel(rel)"));
}

#[test]
fn steps37_38_enforce_capability_reboot_and_netlink_uevent_broadcast() {
    assert!(STEP34_NET.contains("pub(super) fn broadcast_netlink_uevent"));
    assert!(STEP35_EVENTS_CGROUP.contains("pub(super) fn has_effective_capability"));
    assert!(STEP37_38.contains("has_effective_capability(CAP_SYS_BOOT)"));
    assert!(STEP37_38.contains("kernal_psci_aarch64::Psci::new"));
    assert!(STEP37_38.contains("step34_net::broadcast_netlink_uevent"));
    assert!(!STEP37_38.contains("== b\"systemd\""));
}

#[test]
fn step39_routes_locks_xattrs_and_metadata_preservation() {
    for symbol in [
        "NR_FLOCK",
        "NR_FCNTL",
        "NR_SETXATTR",
        "NR_GETXATTR",
        "NR_LISTXATTR",
        "NR_REMOVEXATTR",
        "NR_FCHMOD",
        "NR_FCHMODAT",
        "NR_FCHOWNAT",
        "NR_FCHOWN",
        "NR_UTIMENSAT",
        "AdvisoryLockTable",
        "XattrTable",
        "PackageMetadataTable",
    ] {
        assert!(
            STEP39.contains(symbol),
            "expected Step 39 AArch64 dispatcher to contain {symbol}"
        );
    }
}
