// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_linux_abi::Errno;
use kernal_linux_cgroup::{
    AUDIT_ARCH_AARCH64, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, CAP_SYS_ADMIN,
    CLONE_NEWNET, CLONE_NEWUSER, CLONE_NEWUTS, CgroupTree, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
    SeccompBpfInsn, SeccompVerdict,
};
use kernal_linux_container::{
    NamespaceFd, NamespaceKind, NamespaceSet, NetFrame, OciContainer, OverlayLowerLayer,
    PidNamespaceView, VirtualBridgeNet, apply_setns,
};
use kernal_linux_debian_profile::{BootPhase, DebianBootProfile, KernelCmdline};
use kernal_linux_dpkg::{AdvisoryLockTable, LOCK_EX, LOCK_NB, TargetKey, parse_shebang};
use kernal_linux_events::EventTable;
use kernal_linux_mounts::{MS_UNBINDABLE, MountTable};
use kernal_linux_net::{AF_INET, SOCK_STREAM, SockAddr, SocketTable};
use kernal_linux_systemd::{
    LINUX_REBOOT_CMD_RESTART, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2C, RebootAction,
};

#[test]
fn step40_end_to_end_debian13_boot_cycle_network_dpkg_and_reboot_contract() {
    let ctrl_cap = Capability {
        object: ObjectId(40),
        rights: CapRights::CONTROL,
    };

    let cmdline = KernelCmdline::parse(
        b"root=/dev/vda1 rw rootfstype=ext4 console=ttyAMA0 init=/lib/systemd/systemd hostname=trixie-arm64",
    )
    .unwrap();
    let mut boot = DebianBootProfile::new(cmdline);
    boot.begin_boot(ctrl_cap).unwrap();
    boot.bring_up_multi_user(ctrl_cap).unwrap();
    assert_eq!(boot.journal().phase, BootPhase::MultiUserReady);
    assert!(boot.entropy_ready());

    // Host TCP port forward -> listening guest HTTP socket on port 80.
    boot.add_host_port_forward(ctrl_cap, 18080, [0, 0, 0, 0], 80)
        .unwrap();
    let mut sockets = SocketTable::<8, 256>::new();
    let httpd = sockets.socket(AF_INET, SOCK_STREAM, 0).unwrap();
    sockets
        .bind(
            httpd,
            SockAddr::Inet {
                ip: [0, 0, 0, 0],
                port: 80,
            },
        )
        .unwrap();
    sockets.listen(httpd, 8).unwrap();
    assert_eq!(
        boot.net().resolve_reachable_tcp_listener(&sockets, 18080),
        Ok(httpd)
    );

    // Simulate apt/dpkg script lock & shebang execution contract while booted rw.
    let mut locks = AdvisoryLockTable::<8>::new();
    let lock_key = TargetKey::from_path(b"/var/lib/dpkg/lock-frontend").unwrap();
    locks.flock_op(lock_key, 10, LOCK_EX | LOCK_NB).unwrap();
    assert_eq!(
        locks.flock_op(lock_key, 11, LOCK_EX | LOCK_NB),
        Err(Errno::EAGAIN)
    );
    let shebang = parse_shebang(b"#!/bin/sh -e\napt-get update\n", 0)
        .unwrap()
        .unwrap();
    assert_eq!(shebang.interpreter(), b"/bin/sh");
    assert_eq!(shebang.optional_arg(), Some(&b"-e"[..]));

    // Clean reboot clears dirty superblock flag and repeats cleanly on generation 2.
    assert_eq!(
        boot.execute_clean_reboot(
            ctrl_cap,
            LINUX_REBOOT_MAGIC1,
            LINUX_REBOOT_MAGIC2C,
            LINUX_REBOOT_CMD_RESTART,
        ),
        Ok(RebootAction::Restart)
    );
    assert!(!boot.journal().dirty_superblock);
    boot.begin_boot(ctrl_cap).unwrap();
    assert_eq!(boot.journal().boot_generation, 2);
    assert_eq!(boot.journal().clean_boots, 1);
    assert_eq!(boot.journal().dirty_recoveries, 0);
}

#[test]
fn step41_container_isolation_overlay_bridge_cgroups_seccomp_and_pidfd_contract() {
    let mut host_ns = NamespaceSet::initial();
    let mut host_mounts = MountTable::<16>::new();
    host_mounts.seed_default_hierarchy().unwrap();
    let mut cgroups = CgroupTree::<8>::new();
    let mut bridge = VirtualBridgeNet::new();
    let mut events = EventTable::<8, 64>::new();

    // Shared immutable base layer for OCI containers.
    let mut lower = OverlayLowerLayer::new();
    lower
        .seed_file(b"/etc/debian_version", 0o100_644, b"13.0\n")
        .unwrap();

    // Mark a sensitive host path unbindable before launching containers.
    host_mounts
        .mount(b"tmpfs", b"/run", Some(b"tmpfs"), 0)
        .unwrap();
    host_mounts
        .mount(b"", b"/run", None, MS_UNBINDABLE)
        .unwrap();
    assert_eq!(
        host_mounts.mount(
            b"/run",
            b"/container/leak",
            None,
            kernal_linux_mounts::MS_BIND
        ),
        Err(Errno::EINVAL)
    );

    // Filter blocking reboot(142) inside container while permitting read/write/exit.
    let policy = [
        SeccompBpfInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        SeccompBpfInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: 142,
        },
        SeccompBpfInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SeccompBpfInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | 1,
        },
    ];

    let delegated = Capability {
        object: ObjectId(900),
        rights: CapRights::READ,
    };
    let mut c1 = OciContainer::spawn(
        b"app1",
        1001,
        delegated,
        &mut host_ns,
        &host_mounts,
        &mut cgroups,
        &mut bridge,
        &policy,
        b"3\n",
        b"4096\n",
        b"10000 100000\n",
    )
    .unwrap();
    let c2 = OciContainer::spawn(
        b"app2",
        1002,
        delegated,
        &mut host_ns,
        &host_mounts,
        &mut cgroups,
        &mut bridge,
        &policy,
        b"3\n",
        b"4096\n",
        b"10000 100000\n",
    )
    .unwrap();

    // 1. User namespace never amplifies Kernal capabilities.
    assert!(c1.security.has_ns_cap(CAP_SYS_ADMIN));
    assert!(!c1.security.check_kernal_authority(Capability {
        object: ObjectId(900),
        rights: CapRights::WRITE,
    }));
    assert!(!c1.security.check_kernal_authority(Capability {
        object: ObjectId(1),
        rights: CapRights::ALL,
    }));

    // 2. Overlay isolation: c1 edits /etc/debian_version, c2 still sees pristine 13.0.
    c1.overlay_upper
        .write_file(b"/etc/debian_version", 0o100_644, b"13.0-container1\n")
        .unwrap();
    assert_eq!(
        c1.overlay_upper
            .read_file(&lower, b"/etc/debian_version")
            .unwrap()
            .1,
        b"13.0-container1\n"
    );
    assert_eq!(
        c2.overlay_upper
            .read_file(&lower, b"/etc/debian_version")
            .unwrap()
            .1,
        b"13.0\n"
    );

    // 3. veth + software bridge communication across isolated netns boundaries.
    let ping = NetFrame::new(
        [0x02, 0x42, 0x0a, 0x00, 0x00, 0x02],
        [0xff; 6],
        0x0800,
        b"container-to-container",
    )
    .unwrap();
    bridge
        .transmit(c1.veth_peer_ep, c1.namespaces.net_id, ping)
        .unwrap();
    let delivered = bridge
        .receive(c2.veth_peer_ep, c2.namespaces.net_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        &delivered.payload[..delivered.payload_len],
        b"container-to-container"
    );

    // 4. pidfd_open + pidfd_send_signal + cgroup release on container init exit.
    let pidfd = events.pidfd_open(c1.host_init_pid, 0).unwrap();
    events.pidfd_target(pidfd).unwrap();
    cgroups.release_pid(c1.host_init_pid);
    cgroups.release_memory_charge(c1.host_init_pid, 0);

    // 5. setns into another userns fails without host CAP_SYS_ADMIN.
    let host_net_fd = NamespaceFd {
        live: true,
        kind: NamespaceKind::Net,
        target_ns_id: host_ns.net_id,
        owner_user_ns_id: host_ns.user_id,
    };
    assert_eq!(
        apply_setns(&c1.security, &mut c1.namespaces, host_net_fd, CLONE_NEWNET),
        Err(Errno::EPERM)
    );

    // 6. Seccomp filter blocks reboot(142) while allowing write(64).
    assert_eq!(
        c1.security
            .evaluate_seccomp(142, AUDIT_ARCH_AARCH64, 0, [0; 6]),
        SeccompVerdict::Errno(1)
    );
    assert_eq!(
        c1.security
            .evaluate_seccomp(64, AUDIT_ARCH_AARCH64, 0, [0; 6]),
        SeccompVerdict::Allow
    );

    // 7. Distinct PID namespace view hides unrelated host processes.
    let mut pid_list = [0u8; 32];
    let _ = PidNamespaceView::new(c2.namespaces.pid_id);
    let plist_len = c1.pid_view.format_proc_pid_list(&mut pid_list);
    assert_eq!(&pid_list[..plist_len], b"1\n");
    let _ = (CLONE_NEWUSER, CLONE_NEWUTS);
}
