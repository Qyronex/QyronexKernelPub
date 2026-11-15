// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 41 — Container-oriented Linux compatibility: user/pid/mnt/uts/ipc/cgroup/network
//! namespaces (`setns`, `/proc/<pid>/ns/*`), virtual Ethernet pairs (`veth`) + software L2
//! bridge forwarding, Copy-on-Write OverlayFS storage (`lower` + `upper` + `.wh.` whiteouts),
//! and delegated OCI container lifecycle without ambient Kernal authority.

use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;
use kernal_linux_cgroup::{
    CAP_SYS_ADMIN, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID,
    CLONE_NEWUSER, CLONE_NEWUTS, CgroupTree, ProcessSecurityState, SECCOMP_SET_MODE_FILTER,
    SeccompBpfInsn,
};
use kernal_linux_mounts::{MS_NODEV, MS_NOSUID, MS_PRIVATE, MS_REC, MS_SLAVE, MountTable};

pub const MAX_NS_PROCS: usize = 8;
pub const MAX_BRIDGE_PORTS: usize = 4;
pub const MAX_FRAMES_PER_QUEUE: usize = 4;
pub const MAX_FRAME_LEN: usize = 128;
pub const MAX_OVERLAY_ENTRIES: usize = 16;
pub const MAX_PATH_BYTES: usize = 64;
pub const MAX_FILE_BYTES: usize = 128;

/// Linux namespace type identifiers (`setns(2)` and `/proc/<pid>/ns/<name>`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceKind {
    Mnt,
    Pid,
    Net,
    User,
    Uts,
    Ipc,
    Cgroup,
}

impl NamespaceKind {
    pub fn from_proc_name(name: &[u8]) -> Option<Self> {
        match name {
            b"mnt" => Some(Self::Mnt),
            b"pid" => Some(Self::Pid),
            b"net" => Some(Self::Net),
            b"user" => Some(Self::User),
            b"uts" => Some(Self::Uts),
            b"ipc" => Some(Self::Ipc),
            b"cgroup" => Some(Self::Cgroup),
            _ => None,
        }
    }

    pub const fn proc_name(self) -> &'static [u8] {
        match self {
            Self::Mnt => b"mnt",
            Self::Pid => b"pid",
            Self::Net => b"net",
            Self::User => b"user",
            Self::Uts => b"uts",
            Self::Ipc => b"ipc",
            Self::Cgroup => b"cgroup",
        }
    }

    pub const fn clone_flag(self) -> u64 {
        match self {
            Self::Mnt => CLONE_NEWNS,
            Self::Pid => CLONE_NEWPID,
            Self::Net => CLONE_NEWNET,
            Self::User => CLONE_NEWUSER,
            Self::Uts => CLONE_NEWUTS,
            Self::Ipc => CLONE_NEWIPC,
            Self::Cgroup => CLONE_NEWCGROUP,
        }
    }

    pub fn from_clone_flag(flag: u64) -> Option<Self> {
        match flag {
            CLONE_NEWNS => Some(Self::Mnt),
            CLONE_NEWPID => Some(Self::Pid),
            CLONE_NEWNET => Some(Self::Net),
            CLONE_NEWUSER => Some(Self::User),
            CLONE_NEWUTS => Some(Self::Uts),
            CLONE_NEWIPC => Some(Self::Ipc),
            CLONE_NEWCGROUP => Some(Self::Cgroup),
            _ => None,
        }
    }
}

/// Per-process namespace membership IDs (`inode` numbers shown in `/proc/<pid>/ns/*`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceSet {
    pub mnt_id: u32,
    pub pid_id: u32,
    pub net_id: u32,
    pub user_id: u32,
    pub uts_id: u32,
    pub ipc_id: u32,
    pub cgroup_id: u32,
    next_alloc_id: u32,
    pub hostname: [u8; 64],
    pub hostname_len: usize,
}

impl Default for NamespaceSet {
    fn default() -> Self {
        Self::initial()
    }
}

impl NamespaceSet {
    pub const fn initial() -> Self {
        let mut hostname = [0u8; 64];
        hostname[0] = b'd';
        hostname[1] = b'e';
        hostname[2] = b'b';
        hostname[3] = b'i';
        hostname[4] = b'a';
        hostname[5] = b'n';
        Self {
            mnt_id: 0xf000_0001,
            pid_id: 0xf000_0002,
            net_id: 0xf000_0003,
            user_id: 0xf000_0004,
            uts_id: 0xf000_0005,
            ipc_id: 0xf000_0006,
            cgroup_id: 0xf000_0007,
            next_alloc_id: 0xf000_0100,
            hostname,
            hostname_len: 6,
        }
    }

    pub const fn id_of(&self, kind: NamespaceKind) -> u32 {
        match kind {
            NamespaceKind::Mnt => self.mnt_id,
            NamespaceKind::Pid => self.pid_id,
            NamespaceKind::Net => self.net_id,
            NamespaceKind::User => self.user_id,
            NamespaceKind::Uts => self.uts_id,
            NamespaceKind::Ipc => self.ipc_id,
            NamespaceKind::Cgroup => self.cgroup_id,
        }
    }

    pub fn set_id(&mut self, kind: NamespaceKind, new_id: u32) {
        match kind {
            NamespaceKind::Mnt => self.mnt_id = new_id,
            NamespaceKind::Pid => self.pid_id = new_id,
            NamespaceKind::Net => self.net_id = new_id,
            NamespaceKind::User => self.user_id = new_id,
            NamespaceKind::Uts => self.uts_id = new_id,
            NamespaceKind::Ipc => self.ipc_id = new_id,
            NamespaceKind::Cgroup => self.cgroup_id = new_id,
        }
    }

    /// Allocates fresh namespace IDs for every `CLONE_NEW*` bit present in `flags`.
    pub fn fork_namespaces(&mut self, flags: u64) -> Self {
        let mut child = *self;
        for kind in [
            NamespaceKind::Mnt,
            NamespaceKind::Pid,
            NamespaceKind::Net,
            NamespaceKind::User,
            NamespaceKind::Uts,
            NamespaceKind::Ipc,
            NamespaceKind::Cgroup,
        ] {
            if (flags & kind.clone_flag()) != 0 {
                let id = self.next_alloc_id;
                self.next_alloc_id = self.next_alloc_id.saturating_add(1);
                child.set_id(kind, id);
            }
        }
        child
    }

    pub fn set_hostname(&mut self, name: &[u8]) -> Result<(), Errno> {
        if name.is_empty() || name.len() > 64 {
            return Err(Errno::EINVAL);
        }
        self.hostname = [0u8; 64];
        self.hostname[..name.len()].copy_from_slice(name);
        self.hostname_len = name.len();
        Ok(())
    }

    pub fn hostname(&self) -> &[u8] {
        &self.hostname[..self.hostname_len]
    }

    /// Formats `/proc/<pid>/ns/<kind>` `readlink` target (e.g. `net:[4026532096]`).
    pub fn format_ns_link(&self, kind: NamespaceKind, out: &mut [u8]) -> usize {
        let mut pos = copy_slice(out, kind.proc_name());
        pos += copy_slice(&mut out[pos..], b":[");
        pos += format_u64_dec(u64::from(self.id_of(kind)), &mut out[pos..]);
        pos += copy_slice(&mut out[pos..], b"]");
        pos
    }
}

/// Open `/proc/<pid>/ns/<kind>` handle used by `setns(fd, nstype)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceFd {
    pub live: bool,
    pub kind: NamespaceKind,
    pub target_ns_id: u32,
    pub owner_user_ns_id: u32,
}

impl NamespaceFd {
    pub const EMPTY: Self = Self {
        live: false,
        kind: NamespaceKind::Mnt,
        target_ns_id: 0,
        owner_user_ns_id: 0,
    };
}

/// Validates and applies `setns(2)` on a process security & namespace state without permitting
/// non-CAP_SYS_ADMIN processes or unprivileged escape across user namespace boundaries.
pub fn apply_setns(
    sec: &ProcessSecurityState,
    ns: &mut NamespaceSet,
    fd: NamespaceFd,
    nstype: u64,
) -> Result<(), Errno> {
    if !fd.live {
        return Err(Errno::EBADF);
    }
    if nstype != 0 && nstype != fd.kind.clone_flag() {
        return Err(Errno::EINVAL);
    }
    let has_privilege = if fd.owner_user_ns_id == ns.user_id {
        sec.has_ns_cap(CAP_SYS_ADMIN)
    } else {
        sec.has_cap(CAP_SYS_ADMIN)
    };
    if !has_privilege {
        return Err(Errno::EPERM);
    }
    ns.set_id(fd.kind, fd.target_ns_id);
    Ok(())
}

/// Maps host PIDs to container-local PIDs within an isolated PID namespace (`CLONE_NEWPID`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PidNamespaceView {
    pub ns_id: u32,
    entries: [(u32, u32); MAX_NS_PROCS], // (host_pid, ns_vpid)
    count: usize,
    next_vpid: u32,
}

impl PidNamespaceView {
    pub const fn new(ns_id: u32) -> Self {
        Self {
            ns_id,
            entries: [(0, 0); MAX_NS_PROCS],
            count: 0,
            next_vpid: 1,
        }
    }

    pub fn insert_process(&mut self, host_pid: u32) -> Result<u32, Errno> {
        if host_pid == 0 {
            return Err(Errno::EINVAL);
        }
        if let Some(existing) = self.vpid_for_host(host_pid) {
            return Ok(existing);
        }
        if self.count >= MAX_NS_PROCS {
            return Err(Errno::EAGAIN);
        }
        let vpid = self.next_vpid;
        self.next_vpid = self.next_vpid.saturating_add(1);
        self.entries[self.count] = (host_pid, vpid);
        self.count += 1;
        Ok(vpid)
    }

    pub fn vpid_for_host(&self, host_pid: u32) -> Option<u32> {
        self.entries[..self.count]
            .iter()
            .find(|&&(hp, _)| hp == host_pid)
            .map(|&(_, vp)| vp)
    }

    pub fn host_pid_for_vpid(&self, vpid: u32) -> Option<u32> {
        self.entries[..self.count]
            .iter()
            .find(|&&(_, vp)| vp == vpid)
            .map(|&(hp, _)| hp)
    }

    /// Formats `/proc` PID directories visible inside this PID namespace.
    pub fn format_proc_pid_list(&self, out: &mut [u8]) -> usize {
        let mut pos = 0usize;
        for &(_, vpid) in &self.entries[..self.count] {
            pos += format_u64_dec(u64::from(vpid), &mut out[pos..]);
            pos += copy_slice(&mut out[pos..], b"\n");
        }
        pos
    }
}

/// One Layer-2 Ethernet frame passed across `veth` and software `bridge` links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: [u8; MAX_FRAME_LEN],
    pub payload_len: usize,
}

impl NetFrame {
    pub const EMPTY: Self = Self {
        dst_mac: [0; 6],
        src_mac: [0; 6],
        ethertype: 0x0800,
        payload: [0; MAX_FRAME_LEN],
        payload_len: 0,
    };

    pub fn new(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        ethertype: u16,
        data: &[u8],
    ) -> Result<Self, Errno> {
        if data.len() > MAX_FRAME_LEN {
            return Err(Errno::EMSGSIZE);
        }
        let mut f = Self {
            dst_mac,
            src_mac,
            ethertype,
            payload: [0; MAX_FRAME_LEN],
            payload_len: data.len(),
        };
        f.payload[..data.len()].copy_from_slice(data);
        Ok(f)
    }
}

/// One network endpoint attached to a `net_ns_id`, a `veth` peer, or a software bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VethEndpoint {
    pub live: bool,
    pub net_ns_id: u32,
    pub mac: [u8; 6],
    pub ipv4: [u8; 4],
    pub prefix_len: u8,
    pub peer_idx: Option<usize>,
    rx_queue: [NetFrame; MAX_FRAMES_PER_QUEUE],
    rx_count: usize,
}

impl VethEndpoint {
    const EMPTY: Self = Self {
        live: false,
        net_ns_id: 0,
        mac: [0; 6],
        ipv4: [0; 4],
        prefix_len: 24,
        peer_idx: None,
        rx_queue: [NetFrame::EMPTY; MAX_FRAMES_PER_QUEUE],
        rx_count: 0,
    };
}

/// Software Layer-2 bridge connecting host `br0` and multiple `veth` endpoints across netns
/// boundaries without exposing cross-namespace sockets directly.
pub struct VirtualBridgeNet {
    endpoints: [VethEndpoint; MAX_BRIDGE_PORTS],
    bridge_ports: [Option<usize>; MAX_BRIDGE_PORTS],
}

impl Default for VirtualBridgeNet {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualBridgeNet {
    pub const fn new() -> Self {
        Self {
            endpoints: [VethEndpoint::EMPTY; MAX_BRIDGE_PORTS],
            bridge_ports: [None; MAX_BRIDGE_PORTS],
        }
    }

    /// Creates a connected `veth` pair between `(host_ns_id, host_ip)` and `(peer_ns_id, peer_ip)`,
    /// automatically attaching the host side to the bridge.
    pub fn create_veth_pair(
        &mut self,
        host_ns_id: u32,
        host_mac: [u8; 6],
        host_ip: [u8; 4],
        peer_ns_id: u32,
        peer_mac: [u8; 6],
        peer_ip: [u8; 4],
    ) -> Result<(usize, usize), Errno> {
        let a = self
            .endpoints
            .iter()
            .position(|e| !e.live)
            .ok_or(Errno::ENOSPC)?;
        let b = self
            .endpoints
            .iter()
            .enumerate()
            .position(|(i, e)| i != a && !e.live)
            .ok_or(Errno::ENOSPC)?;

        self.endpoints[a] = VethEndpoint {
            live: true,
            net_ns_id: host_ns_id,
            mac: host_mac,
            ipv4: host_ip,
            prefix_len: 24,
            peer_idx: Some(b),
            rx_queue: [NetFrame::EMPTY; MAX_FRAMES_PER_QUEUE],
            rx_count: 0,
        };
        self.endpoints[b] = VethEndpoint {
            live: true,
            net_ns_id: peer_ns_id,
            mac: peer_mac,
            ipv4: peer_ip,
            prefix_len: 24,
            peer_idx: Some(a),
            rx_queue: [NetFrame::EMPTY; MAX_FRAMES_PER_QUEUE],
            rx_count: 0,
        };

        if let Some(slot) = self.bridge_ports.iter_mut().find(|p| p.is_none()) {
            *slot = Some(a);
        }
        Ok((a, b))
    }

    /// Transmits a frame from `src_ep_idx` across its `veth` peer (and onto bridge peers if the
    /// peer side is a bridge port).
    pub fn transmit(
        &mut self,
        src_ep_idx: usize,
        net_ns_id: u32,
        frame: NetFrame,
    ) -> Result<(), Errno> {
        let src = self.endpoints.get(src_ep_idx).ok_or(Errno::ENODEV)?;
        if !src.live || src.net_ns_id != net_ns_id {
            return Err(Errno::ENODEV);
        }
        let peer_idx = src.peer_idx.ok_or(Errno::ENODEV)?;
        if self.bridge_ports.contains(&Some(peer_idx)) {
            return self.bridge_forward(peer_idx, frame);
        }
        self.push_rx(peer_idx, frame)
    }

    fn bridge_forward(&mut self, ingress_host_ep: usize, frame: NetFrame) -> Result<(), Errno> {
        let broadcast = frame.dst_mac == [0xff; 6];
        let mut delivered = 0usize;
        for port_opt in self.bridge_ports {
            let Some(host_ep_idx) = port_opt else {
                continue;
            };
            if host_ep_idx == ingress_host_ep {
                continue;
            }
            let Some(container_ep_idx) = self.endpoints[host_ep_idx].peer_idx else {
                continue;
            };
            if !self.endpoints[container_ep_idx].live {
                continue;
            }
            if broadcast || self.endpoints[container_ep_idx].mac == frame.dst_mac {
                self.push_rx(container_ep_idx, frame)?;
                delivered += 1;
            }
        }
        if delivered == 0 && !broadcast {
            // Unicast to bridge/host itself goes into ingress host endpoint queue.
            self.push_rx(ingress_host_ep, frame)?;
        }
        Ok(())
    }

    fn push_rx(&mut self, ep_idx: usize, frame: NetFrame) -> Result<(), Errno> {
        let ep = self.endpoints.get_mut(ep_idx).ok_or(Errno::ENODEV)?;
        if !ep.live {
            return Err(Errno::ENODEV);
        }
        if ep.rx_count >= MAX_FRAMES_PER_QUEUE {
            return Err(Errno::ENOBUFS);
        }
        ep.rx_queue[ep.rx_count] = frame;
        ep.rx_count += 1;
        Ok(())
    }

    /// Receives the oldest queued frame for `ep_idx`, enforcing `net_ns_id` namespace isolation.
    pub fn receive(&mut self, ep_idx: usize, net_ns_id: u32) -> Result<Option<NetFrame>, Errno> {
        let ep = self.endpoints.get_mut(ep_idx).ok_or(Errno::ENODEV)?;
        if !ep.live || ep.net_ns_id != net_ns_id {
            return Err(Errno::ENODEV);
        }
        if ep.rx_count == 0 {
            return Ok(None);
        }
        let first = ep.rx_queue[0];
        for i in 0..ep.rx_count - 1 {
            ep.rx_queue[i] = ep.rx_queue[i + 1];
        }
        ep.rx_count -= 1;
        Ok(Some(first))
    }
}

/// OverlayFS layer entry (`lower` = shared read-only base image, `upper` = CoW container layer).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OverlayKind {
    Empty,
    Regular,
    Whiteout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OverlayEntry {
    kind: OverlayKind,
    mode: u32,
    path: [u8; MAX_PATH_BYTES],
    path_len: usize,
    data: [u8; MAX_FILE_BYTES],
    data_len: usize,
}

impl OverlayEntry {
    const EMPTY: Self = Self {
        kind: OverlayKind::Empty,
        mode: 0,
        path: [0; MAX_PATH_BYTES],
        path_len: 0,
        data: [0; MAX_FILE_BYTES],
        data_len: 0,
    };

    fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// Read-only shared container image lower layer (`lowerdir`).
pub struct OverlayLowerLayer {
    entries: [OverlayEntry; MAX_OVERLAY_ENTRIES],
}

impl Default for OverlayLowerLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlayLowerLayer {
    pub const fn new() -> Self {
        Self {
            entries: [OverlayEntry::EMPTY; MAX_OVERLAY_ENTRIES],
        }
    }

    pub fn seed_file(&mut self, path: &[u8], mode: u32, data: &[u8]) -> Result<(), Errno> {
        upsert_overlay_entry(&mut self.entries, OverlayKind::Regular, path, mode, data)
    }

    pub fn read_raw(&self, path: &[u8]) -> Option<(u32, &[u8])> {
        self.entries
            .iter()
            .find(|e| e.kind == OverlayKind::Regular && e.path() == path)
            .map(|e| (e.mode, &e.data[..e.data_len]))
    }
}

/// Per-container writable upper + work layer (`upperdir` / `workdir`) layered on an immutable
/// `OverlayLowerLayer` with CoW copy-up and `.wh.` whiteouts.
pub struct OverlayUpperMount {
    upper: [OverlayEntry; MAX_OVERLAY_ENTRIES],
    pub workdir_clean: bool,
}

impl Default for OverlayUpperMount {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlayUpperMount {
    pub const fn new() -> Self {
        Self {
            upper: [OverlayEntry::EMPTY; MAX_OVERLAY_ENTRIES],
            workdir_clean: true,
        }
    }

    /// Reads merged view (`upper` shadows `lower`; `.wh.` whiteout hides deleted `lower` entries).
    pub fn read_file<'a>(
        &'a self,
        lower: &'a OverlayLowerLayer,
        path: &[u8],
    ) -> Result<(u32, &'a [u8]), Errno> {
        if let Some(u) = self
            .upper
            .iter()
            .find(|e| e.kind != OverlayKind::Empty && e.path() == path)
        {
            return match u.kind {
                OverlayKind::Whiteout => Err(Errno::ENOENT),
                OverlayKind::Regular => Ok((u.mode, &u.data[..u.data_len])),
                OverlayKind::Empty => Err(Errno::ENOENT),
            };
        }
        lower.read_raw(path).ok_or(Errno::ENOENT)
    }

    /// Writes or copies-up `path` exclusively into `upper`, leaving `lower` untouched.
    pub fn write_file(&mut self, path: &[u8], mode: u32, data: &[u8]) -> Result<(), Errno> {
        self.workdir_clean = false;
        let res = upsert_overlay_entry(&mut self.upper, OverlayKind::Regular, path, mode, data);
        self.workdir_clean = true;
        res
    }

    /// Unlinks `path`: creates a whiteout marker in `upper` if `path` exists in `lower`.
    pub fn unlink(&mut self, lower: &OverlayLowerLayer, path: &[u8]) -> Result<(), Errno> {
        let in_lower = lower.read_raw(path).is_some();
        let in_upper = self
            .upper
            .iter()
            .any(|e| e.kind == OverlayKind::Regular && e.path() == path);
        if !in_lower && !in_upper {
            return Err(Errno::ENOENT);
        }
        if in_lower {
            upsert_overlay_entry(&mut self.upper, OverlayKind::Whiteout, path, 0, &[])
        } else {
            for e in &mut self.upper {
                if e.kind == OverlayKind::Regular && e.path() == path {
                    *e = OverlayEntry::EMPTY;
                    return Ok(());
                }
            }
            Ok(())
        }
    }
}

/// Complete Step-41 delegated OCI minimal container instance combining:
/// - unprivileged `CLONE_NEWUSER` security state (never exceeding `delegated_authority`)
/// - isolated `NamespaceSet` & `PidNamespaceView` (`PID 1` inside container)
/// - private `MountTable` rooted on `overlay` with `MS_SLAVE` propagation
/// - cgroup v2 `cpu.max`/`memory.max`/`pids.max` accounting
/// - `seccomp(2)` filter policy & `veth` endpoint in its own `net` namespace
pub struct OciContainer {
    pub host_init_pid: u32,
    pub cgroup_slice: [u8; 32],
    pub cgroup_slice_len: usize,
    pub security: ProcessSecurityState,
    pub namespaces: NamespaceSet,
    pub pid_view: PidNamespaceView,
    pub mounts: MountTable<16>,
    pub overlay_upper: OverlayUpperMount,
    pub veth_peer_ep: usize,
    pub active: bool,
}

impl OciContainer {
    /// Launches an isolated OCI minimal container without leaking ambient Kernal capabilities.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        slice_name: &[u8],
        host_init_pid: u32,
        delegated_authority: Capability,
        parent_namespaces: &mut NamespaceSet,
        host_mounts: &MountTable<16>,
        cgroups: &mut CgroupTree<8>,
        bridge: &mut VirtualBridgeNet,
        seccomp_policy: &[SeccompBpfInsn],
        pids_max: &[u8],
        memory_max: &[u8],
        cpu_max: &[u8],
    ) -> Result<Self, Errno> {
        if !delegated_authority.rights.contains(CapRights::READ) || slice_name.len() > 32 {
            return Err(Errno::EPERM);
        }

        // 1. Configure isolated cgroup v2 slice and enforce quotas cleanly.
        let mut full_slice = [0u8; 48];
        let mut p = copy_slice(&mut full_slice, b"container.slice/");
        p += copy_slice(&mut full_slice[p..], slice_name);
        let slice_path = &full_slice[..p];
        cgroups.mkdir(slice_path)?;

        let write_ctrl =
            |cgroups: &mut CgroupTree<8>, file: &[u8], val: &[u8]| -> Result<(), Errno> {
                let mut ctrl_path = [0u8; 72];
                let mut q = copy_slice(&mut ctrl_path, slice_path);
                q += copy_slice(&mut ctrl_path[q..], b"/");
                q += copy_slice(&mut ctrl_path[q..], file);
                cgroups.write_control_file(&ctrl_path[..q], val)
            };
        write_ctrl(cgroups, b"pids.max", pids_max)?;
        write_ctrl(cgroups, b"memory.max", memory_max)?;
        write_ctrl(cgroups, b"cpu.max", cpu_max)?;

        let mut pid_ascii = [0u8; 20];
        let pid_len = format_u64_dec(u64::from(host_init_pid), &mut pid_ascii);
        write_ctrl(cgroups, b"cgroup.procs", &pid_ascii[..pid_len])?;

        // 2. Build unprivileged CLONE_NEWUSER + full namespace isolation + NO_NEW_PRIVS + seccomp.
        let mut sec = ProcessSecurityState::new_unprivileged(delegated_authority);
        sec.unshare(
            CLONE_NEWUSER
                | CLONE_NEWNS
                | CLONE_NEWPID
                | CLONE_NEWNET
                | CLONE_NEWUTS
                | CLONE_NEWCGROUP,
        )?;
        sec.write_setgroups(b"deny\n")?;
        sec.write_uid_map(b"0 1000 1\n")?;
        sec.write_gid_map(b"0 1000 1\n")?;
        sec.no_new_privs = true;
        if !seccomp_policy.is_empty() {
            sec.seccomp_syscall(SECCOMP_SET_MODE_FILTER, 0, seccomp_policy)?;
        }

        // 3. Allocate fresh namespace IDs + container UTS hostname + container PID 1 map.
        let host_net_ns = parent_namespaces.net_id;
        let mut child_ns = parent_namespaces.fork_namespaces(sec.active_namespaces);
        child_ns.set_hostname(slice_name)?;
        let mut pid_view = PidNamespaceView::new(child_ns.pid_id);
        let _vpid1 = pid_view.insert_process(host_init_pid)?;

        // 4. Clone mount table as MS_SLAVE / private + mount overlay rootfs cleanly.
        let mut mounts = host_mounts.clone_into_child_namespace(true);
        let _ = mounts.mount(b"", b"/", None, MS_SLAVE | MS_REC);
        mounts.mount(b"overlay", b"/container/rootfs", Some(b"overlay"), MS_NODEV)?;
        mounts.mount(
            b"proc",
            b"/container/rootfs/proc",
            Some(b"proc"),
            MS_NOSUID | MS_NODEV,
        )?;
        mounts.mount(b"", b"/container/rootfs", None, MS_PRIVATE)?;

        // 5. Connect container network namespace to host bridge via veth pair.
        let (_, peer_ep) = bridge.create_veth_pair(
            host_net_ns,
            [0x02, 0x42, 0x00, 0x00, 0x00, 0x01],
            [172, 17, 0, 1],
            child_ns.net_id,
            [0x02, 0x42, 0x0a, 0x00, 0x00, 0x02],
            [172, 17, 0, 2],
        )?;

        let mut slice_buf = [0u8; 32];
        slice_buf[..slice_name.len()].copy_from_slice(slice_name);

        Ok(Self {
            host_init_pid,
            cgroup_slice: slice_buf,
            cgroup_slice_len: slice_name.len(),
            security: sec,
            namespaces: child_ns,
            pid_view,
            mounts,
            overlay_upper: OverlayUpperMount::new(),
            veth_peer_ep: peer_ep,
            active: true,
        })
    }
}

fn upsert_overlay_entry(
    table: &mut [OverlayEntry; MAX_OVERLAY_ENTRIES],
    kind: OverlayKind,
    path: &[u8],
    mode: u32,
    data: &[u8],
) -> Result<(), Errno> {
    if path.is_empty() || path[0] != b'/' || path.len() > MAX_PATH_BYTES {
        return Err(Errno::EINVAL);
    }
    if data.len() > MAX_FILE_BYTES {
        return Err(Errno::ENOSPC);
    }
    let idx = if let Some(pos) = table
        .iter()
        .position(|e| e.kind != OverlayKind::Empty && e.path() == path)
    {
        pos
    } else {
        table
            .iter()
            .position(|e| e.kind == OverlayKind::Empty)
            .ok_or(Errno::ENOSPC)?
    };
    let mut entry = OverlayEntry::EMPTY;
    entry.kind = kind;
    entry.mode = mode;
    entry.path[..path.len()].copy_from_slice(path);
    entry.path_len = path.len();
    entry.data[..data.len()].copy_from_slice(data);
    entry.data_len = data.len();
    table[idx] = entry;
    Ok(())
}

fn copy_slice(dst: &mut [u8], src: &[u8]) -> usize {
    let take = dst.len().min(src.len());
    dst[..take].copy_from_slice(&src[..take]);
    take
}

fn format_u64_dec(mut v: u64, out: &mut [u8]) -> usize {
    if v == 0 {
        return copy_slice(out, b"0");
    }
    let mut rev = [0u8; 20];
    let mut len = 0usize;
    while v > 0 {
        rev[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let mut pos = 0usize;
    while len > 0 && pos < out.len() {
        len -= 1;
        out[pos] = rev[len];
        pos += 1;
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_capability::ObjectId;
    use kernal_linux_cgroup::{
        AUDIT_ARCH_AARCH64, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W,
        SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SeccompVerdict,
    };

    #[test]
    fn overlay_copy_up_and_whiteout_leave_shared_lower_immutable() {
        let mut lower = OverlayLowerLayer::new();
        lower
            .seed_file(b"/etc/os-release", 0o100_644, b"ID=debian\nVERSION_ID=13\n")
            .unwrap();
        lower
            .seed_file(b"/etc/secret-default", 0o100_600, b"base\n")
            .unwrap();

        let mut c1 = OverlayUpperMount::new();
        let c2 = OverlayUpperMount::new();

        // Container 1 writes copy-up to /etc/os-release and deletes /etc/secret-default.
        c1.write_file(b"/etc/os-release", 0o100_644, b"ID=debian-custom\n")
            .unwrap();
        c1.unlink(&lower, b"/etc/secret-default").unwrap();

        assert_eq!(
            c1.read_file(&lower, b"/etc/os-release").unwrap().1,
            b"ID=debian-custom\n"
        );
        assert_eq!(
            c1.read_file(&lower, b"/etc/secret-default"),
            Err(Errno::ENOENT)
        );
        // Container 2 still sees unmodified lower layer!
        assert_eq!(
            c2.read_file(&lower, b"/etc/os-release").unwrap().1,
            b"ID=debian\nVERSION_ID=13\n"
        );
        assert_eq!(
            c2.read_file(&lower, b"/etc/secret-default").unwrap().1,
            b"base\n"
        );
    }

    #[test]
    fn veth_and_software_bridge_isolate_and_deliver_across_netns() {
        let mut root_ns = NamespaceSet::initial();
        let c1_ns = root_ns.fork_namespaces(CLONE_NEWNET);
        let c2_ns = root_ns.fork_namespaces(CLONE_NEWNET);

        let mut bridge = VirtualBridgeNet::new();
        let (_h1, c1_ep) = bridge
            .create_veth_pair(
                root_ns.net_id,
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                [172, 17, 0, 1],
                c1_ns.net_id,
                [0x02, 0x00, 0x00, 0x00, 0x01, 0x02],
                [172, 17, 0, 2],
            )
            .unwrap();
        let (_h2, c2_ep) = bridge
            .create_veth_pair(
                root_ns.net_id,
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                [172, 17, 0, 1],
                c2_ns.net_id,
                [0x02, 0x00, 0x00, 0x00, 0x01, 0x03],
                [172, 17, 0, 3],
            )
            .unwrap();

        let frame = NetFrame::new(
            [0x02, 0x00, 0x00, 0x00, 0x01, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x01, 0x03],
            0x0800,
            b"GET /health HTTP/1.0\r\n\r\n",
        )
        .unwrap();
        // Wrong netns cannot transmit or receive on c1_ep!
        assert_eq!(
            bridge.transmit(c1_ep, c2_ns.net_id, frame),
            Err(Errno::ENODEV)
        );
        bridge.transmit(c1_ep, c1_ns.net_id, frame).unwrap();
        assert_eq!(bridge.receive(c2_ep, root_ns.net_id), Err(Errno::ENODEV));
        let rx = bridge.receive(c2_ep, c2_ns.net_id).unwrap().unwrap();
        assert_eq!(
            &rx.payload[..rx.payload_len],
            b"GET /health HTTP/1.0\r\n\r\n"
        );
    }

    #[test]
    fn oci_container_lifecycle_enforces_delegated_authority_seccomp_and_limits() {
        let container_cap = Capability {
            object: ObjectId(41),
            rights: CapRights::READ,
        };
        let mut host_ns = NamespaceSet::initial();
        let mut host_mounts = MountTable::<16>::new();
        host_mounts.seed_default_hierarchy().unwrap();
        let mut cgroups = CgroupTree::<8>::new();
        let mut bridge = VirtualBridgeNet::new();

        let deny_mount = [
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
                k: 40, // mount(2) on aarch64
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

        let mut oci = OciContainer::spawn(
            b"oci-web",
            512,
            container_cap,
            &mut host_ns,
            &host_mounts,
            &mut cgroups,
            &mut bridge,
            &deny_mount,
            b"2\n",
            b"16384\n",
            b"5000 100000\n",
        )
        .unwrap();

        // Container sees PID 1 inside its PID namespace and isolated hostname + netns link.
        assert_eq!(oci.pid_view.vpid_for_host(512), Some(1));
        assert_eq!(oci.namespaces.hostname(), b"oci-web");
        let mut link = [0u8; 64];
        let llen = oci.namespaces.format_ns_link(NamespaceKind::Net, &mut link);
        assert!(
            core::str::from_utf8(&link[..llen])
                .unwrap()
                .starts_with("net:[")
        );

        // Container authority remains strictly delegated (cannot acquire WRITE or host object 1).
        assert!(oci.security.has_ns_cap(CAP_SYS_ADMIN));
        assert!(!oci.security.check_kernal_authority(Capability {
            object: ObjectId(41),
            rights: CapRights::WRITE,
        }));
        assert!(!oci.security.check_kernal_authority(Capability {
            object: ObjectId(1),
            rights: CapRights::READ,
        }));

        // Cgroups v2 enforces pids.max=2, memory.max=16384, cpu.max=5000us.
        cgroups.enforce_fork(512, 513).unwrap();
        assert_eq!(cgroups.enforce_fork(512, 514), Err(Errno::EAGAIN));
        cgroups.enforce_memory_charge(512, 8192).unwrap();
        assert_eq!(
            cgroups.enforce_memory_charge(512, 16384),
            Err(Errno::ENOMEM)
        );
        cgroups.enforce_cpu_consume(512, 4000).unwrap();
        assert_eq!(cgroups.enforce_cpu_consume(512, 2000), Err(Errno::EAGAIN));

        // Seccomp denies host mount(40) while permitting ordinary read(63).
        assert_eq!(
            oci.security
                .evaluate_seccomp(40, AUDIT_ARCH_AARCH64, 0, [0; 6]),
            SeccompVerdict::Errno(1)
        );
        assert_eq!(
            oci.security
                .evaluate_seccomp(63, AUDIT_ARCH_AARCH64, 0, [0; 6]),
            SeccompVerdict::Allow
        );

        // Unprivileged setns into target PID ns works with userns CAP_SYS_ADMIN when same userns,
        // while unprivileged cross-userns setns fails with EPERM.
        let fd_same_user = NamespaceFd {
            live: true,
            kind: NamespaceKind::Uts,
            target_ns_id: 0xf000_0999,
            owner_user_ns_id: oci.namespaces.user_id,
        };
        apply_setns(
            &oci.security,
            &mut oci.namespaces,
            fd_same_user,
            CLONE_NEWUTS,
        )
        .unwrap();
        assert_eq!(oci.namespaces.uts_id, 0xf000_0999);

        let fd_host = NamespaceFd {
            live: true,
            kind: NamespaceKind::Net,
            target_ns_id: host_ns.net_id,
            owner_user_ns_id: host_ns.user_id,
        };
        assert_eq!(
            apply_setns(&oci.security, &mut oci.namespaces, fd_host, CLONE_NEWNET),
            Err(Errno::EPERM)
        );
    }
}
