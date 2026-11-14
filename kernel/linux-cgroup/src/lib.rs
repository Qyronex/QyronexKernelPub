// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 36 — Namespaces, cgroups v2 hierarchy & controller enforcement, Linux capability sets
//! (`capget`/`capset`), `prctl` security options, and explicit rejection of unsupported
//! seccomp/BPF/keyring interfaces.

use kernal_linux_abi::Errno;

/// Linux capability ABI v3 (`_LINUX_CAPABILITY_VERSION_3`).
pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
pub const CAP_LAST_CAP: u32 = 40;
pub const ALL_VALID_CAPS_MASK: u64 = (1u64 << (CAP_LAST_CAP + 1)) - 1;

/// Key Linux capabilities (`<linux/capability.h>`).
pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_SYS_RESOURCE: u32 = 24;

/// `unshare(2)` / `setns(2)` namespace flags (`<sched.h>`).
pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
const SUPPORTED_NS_FLAGS: u64 =
    CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET;

/// `prctl(2)` option numbers (`<sys/prctl.h>`).
pub const PR_SET_PDEATHSIG: u32 = 1;
pub const PR_GET_PDEATHSIG: u32 = 2;
pub const PR_GET_DUMPABLE: u32 = 3;
pub const PR_SET_DUMPABLE: u32 = 4;
pub const PR_GET_KEEPCAPS: u32 = 7;
pub const PR_SET_KEEPCAPS: u32 = 8;
pub const PR_SET_NAME: u32 = 15;
pub const PR_GET_NAME: u32 = 16;
pub const PR_CAPBSET_READ: u32 = 23;
pub const PR_CAPBSET_DROP: u32 = 24;
pub const PR_GET_SECUREBITS: u32 = 27;
pub const PR_SET_SECUREBITS: u32 = 28;
pub const PR_SET_CHILD_SUBREAPER: u32 = 36;
pub const PR_GET_CHILD_SUBREAPER: u32 = 37;
pub const PR_SET_NO_NEW_PRIVS: u32 = 38;
pub const PR_GET_NO_NEW_PRIVS: u32 = 39;
pub const PR_CAP_AMBIENT: u32 = 47;

pub const PR_CAP_AMBIENT_IS_SET: u64 = 1;
pub const PR_CAP_AMBIENT_RAISE: u64 = 2;
pub const PR_CAP_AMBIENT_LOWER: u64 = 3;
pub const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;

/// Per-process Linux capability & security state (`capget`/`capset`/`prctl`).
/// Authority is monotonically bounded: a process can never raise permitted or bounding bits
/// that it does not already hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessSecurityState {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
    pub securebits: u32,
    pub keepcaps: bool,
    pub dumpable: u8,
    pub no_new_privs: bool,
    pub child_subreaper: bool,
    pub pdeathsig: u32,
    pub comm: [u8; 16],
    pub active_namespaces: u64,
}

impl Default for ProcessSecurityState {
    fn default() -> Self {
        Self::new_root_init()
    }
}

impl ProcessSecurityState {
    pub const fn new_root_init() -> Self {
        let mut comm = [0u8; 16];
        comm[0] = b's';
        comm[1] = b'y';
        comm[2] = b's';
        comm[3] = b't';
        comm[4] = b'e';
        comm[5] = b'm';
        comm[6] = b'd';
        Self {
            effective: ALL_VALID_CAPS_MASK,
            permitted: ALL_VALID_CAPS_MASK,
            inheritable: 0,
            bounding: ALL_VALID_CAPS_MASK,
            ambient: 0,
            securebits: 0,
            keepcaps: false,
            dumpable: 1,
            no_new_privs: false,
            child_subreaper: true,
            pdeathsig: 0,
            comm,
            active_namespaces: 0,
        }
    }

    pub const fn has_cap(&self, cap: u32) -> bool {
        if cap > CAP_LAST_CAP {
            return false;
        }
        (self.effective & (1u64 << cap)) != 0
    }

    /// Encodes v3 `cap_user_data_t[2]` (24 bytes: effective/permitted/inheritable low+high u32s).
    pub const fn encode_cap_data_v3(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        write_u32(&mut out, 0, self.effective as u32);
        write_u32(&mut out, 4, self.permitted as u32);
        write_u32(&mut out, 8, self.inheritable as u32);
        write_u32(&mut out, 12, (self.effective >> 32) as u32);
        write_u32(&mut out, 16, (self.permitted >> 32) as u32);
        write_u32(&mut out, 20, (self.inheritable >> 32) as u32);
        out
    }

    /// Applies `capset(2)` v3 `cap_user_data_t[2]` while enforcing monotone capability bounds.
    pub fn apply_cap_data_v3(&mut self, raw: &[u8; 24]) -> Result<(), Errno> {
        let eff_lo = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as u64;
        let prm_lo = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as u64;
        let inh_lo = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as u64;
        let eff_hi = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as u64;
        let prm_hi = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]) as u64;
        let inh_hi = u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]) as u64;

        let new_eff = ((eff_hi << 32) | eff_lo) & ALL_VALID_CAPS_MASK;
        let new_prm = ((prm_hi << 32) | prm_lo) & ALL_VALID_CAPS_MASK;
        let new_inh = ((inh_hi << 32) | inh_lo) & ALL_VALID_CAPS_MASK;

        // Effective must be a subset of new Permitted, and new Permitted cannot exceed old Permitted.
        if (new_eff & !new_prm) != 0 || (new_prm & !self.permitted) != 0 {
            return Err(Errno::EPERM);
        }
        // New Inheritable cannot add bits outside (old Inheritable | old Permitted), or outside
        // (old Inheritable | Bounding) unless CAP_SETPCAP is held.
        let allowed_inh = if self.has_cap(CAP_SETPCAP) {
            self.inheritable | self.bounding
        } else {
            self.inheritable | self.permitted
        };
        if (new_inh & !allowed_inh) != 0 {
            return Err(Errno::EPERM);
        }

        self.effective = new_eff;
        self.permitted = new_prm;
        self.inheritable = new_inh;
        self.ambient &= new_prm & new_inh;
        Ok(())
    }

    /// Executes `unshare(2)` namespace creation flags, requiring `CAP_SYS_ADMIN` and rejecting
    /// `CLONE_NEWUSER` until Step 41 so unprivileged callers cannot fabricate root capabilities.
    pub fn unshare(&mut self, flags: u64) -> Result<(), Errno> {
        if flags == 0 {
            return Ok(());
        }
        if (flags & CLONE_NEWUSER) != 0 {
            return Err(Errno::EPERM);
        }
        if (flags & !SUPPORTED_NS_FLAGS) != 0 {
            return Err(Errno::EINVAL);
        }
        if !self.has_cap(CAP_SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
        self.active_namespaces |= flags;
        Ok(())
    }

    /// Executes security/process `prctl(2)` options.
    pub fn prctl(
        &mut self,
        option: u32,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<i64, Errno> {
        match option {
            PR_CAPBSET_READ => {
                let cap = u32::try_from(arg2).map_err(|_| Errno::EINVAL)?;
                if cap > CAP_LAST_CAP {
                    return Err(Errno::EINVAL);
                }
                Ok(i64::from((self.bounding & (1u64 << cap)) != 0))
            }
            PR_CAPBSET_DROP => {
                if !self.has_cap(CAP_SETPCAP) {
                    return Err(Errno::EPERM);
                }
                let cap = u32::try_from(arg2).map_err(|_| Errno::EINVAL)?;
                if cap > CAP_LAST_CAP {
                    return Err(Errno::EINVAL);
                }
                self.bounding &= !(1u64 << cap);
                Ok(0)
            }
            PR_GET_KEEPCAPS => Ok(i64::from(self.keepcaps)),
            PR_SET_KEEPCAPS => {
                if arg2 > 1 {
                    return Err(Errno::EINVAL);
                }
                self.keepcaps = arg2 == 1;
                Ok(0)
            }
            PR_GET_DUMPABLE => Ok(i64::from(self.dumpable)),
            PR_SET_DUMPABLE => {
                if arg2 > 1 {
                    return Err(Errno::EINVAL);
                }
                self.dumpable = arg2 as u8;
                Ok(0)
            }
            PR_GET_SECUREBITS => Ok(i64::from(self.securebits)),
            PR_SET_SECUREBITS => {
                if !self.has_cap(CAP_SETPCAP) {
                    return Err(Errno::EPERM);
                }
                self.securebits = u32::try_from(arg2).map_err(|_| Errno::EINVAL)?;
                Ok(0)
            }
            PR_GET_NO_NEW_PRIVS => Ok(i64::from(self.no_new_privs)),
            PR_SET_NO_NEW_PRIVS => {
                if arg2 != 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                    return Err(Errno::EINVAL);
                }
                self.no_new_privs = true;
                Ok(0)
            }
            PR_GET_CHILD_SUBREAPER => Ok(i64::from(self.child_subreaper)),
            PR_SET_CHILD_SUBREAPER => {
                self.child_subreaper = arg2 != 0;
                Ok(0)
            }
            PR_SET_PDEATHSIG => {
                let sig = u32::try_from(arg2).map_err(|_| Errno::EINVAL)?;
                if sig > 64 {
                    return Err(Errno::EINVAL);
                }
                self.pdeathsig = sig;
                Ok(0)
            }
            PR_CAP_AMBIENT => {
                if arg4 != 0 || arg5 != 0 {
                    return Err(Errno::EINVAL);
                }
                match arg2 {
                    PR_CAP_AMBIENT_IS_SET => {
                        let cap = u32::try_from(arg3).map_err(|_| Errno::EINVAL)?;
                        if cap > CAP_LAST_CAP {
                            return Err(Errno::EINVAL);
                        }
                        Ok(i64::from((self.ambient & (1u64 << cap)) != 0))
                    }
                    PR_CAP_AMBIENT_RAISE => {
                        let cap = u32::try_from(arg3).map_err(|_| Errno::EINVAL)?;
                        if cap > CAP_LAST_CAP {
                            return Err(Errno::EINVAL);
                        }
                        let bit = 1u64 << cap;
                        if (self.permitted & bit) == 0 || (self.inheritable & bit) == 0 {
                            return Err(Errno::EPERM);
                        }
                        self.ambient |= bit;
                        Ok(0)
                    }
                    PR_CAP_AMBIENT_LOWER => {
                        let cap = u32::try_from(arg3).map_err(|_| Errno::EINVAL)?;
                        if cap > CAP_LAST_CAP {
                            return Err(Errno::EINVAL);
                        }
                        self.ambient &= !(1u64 << cap);
                        Ok(0)
                    }
                    PR_CAP_AMBIENT_CLEAR_ALL => {
                        if arg3 != 0 {
                            return Err(Errno::EINVAL);
                        }
                        self.ambient = 0;
                        Ok(0)
                    }
                    _ => Err(Errno::EINVAL),
                }
            }
            _ => Err(Errno::EINVAL),
        }
    }

    pub fn set_comm(&mut self, name: &[u8]) {
        self.comm = [0u8; 16];
        let take = name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name.len())
            .min(15);
        self.comm[..take].copy_from_slice(&name[..take]);
    }
}

const fn write_u32(out: &mut [u8; 24], off: usize, val: u32) {
    let b = val.to_le_bytes();
    out[off] = b[0];
    out[off + 1] = b[1];
    out[off + 2] = b[2];
    out[off + 3] = b[3];
}

/// One node in the Step-36 cgroups v2 unified hierarchy (`/sys/fs/cgroup/<slice>`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupNode {
    live: bool,
    path: [u8; 48],
    path_len: usize,
    pids_max: u32,
    pids_current: u32,
    memory_max: u64,
    memory_current: u64,
    subtree_control: u32, // bit 0 = pids, bit 1 = memory, bit 2 = cpu
    attached_pids: [u32; 8],
    attached_count: usize,
}

impl CgroupNode {
    const EMPTY: Self = Self {
        live: false,
        path: [0u8; 48],
        path_len: 0,
        pids_max: u32::MAX,
        pids_current: 0,
        memory_max: u64::MAX,
        memory_current: 0,
        subtree_control: 0,
        attached_pids: [0; 8],
        attached_count: 0,
    };

    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// Cgroups v2 unified hierarchy table enforcing real `pids.max` and `memory.max` limits.
pub struct CgroupTree<const MAX_GROUPS: usize> {
    nodes: [CgroupNode; MAX_GROUPS],
}

impl<const MAX_GROUPS: usize> Default for CgroupTree<MAX_GROUPS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_GROUPS: usize> CgroupTree<MAX_GROUPS> {
    pub const fn new() -> Self {
        let mut nodes = [CgroupNode::EMPTY; MAX_GROUPS];
        if MAX_GROUPS > 0 {
            let mut root = CgroupNode::EMPTY;
            root.live = true;
            root.pids_current = 1;
            root.attached_pids[0] = 1;
            root.attached_count = 1;
            root.subtree_control = 0b111;
            nodes[0] = root;
        }
        Self { nodes }
    }

    /// Creates a child cgroup directory (`mkdir("/sys/fs/cgroup/<rel>")`).
    pub fn mkdir(&mut self, rel_path: &[u8]) -> Result<usize, Errno> {
        let clean = trim_slashes(rel_path);
        if clean.is_empty() {
            return Err(Errno::EEXIST);
        }
        if clean.len() > 48 {
            return Err(Errno::ENAMETOOLONG);
        }
        if self.nodes.iter().any(|n| n.live && n.path() == clean) {
            return Err(Errno::EEXIST);
        }
        let (idx, slot) = self
            .nodes
            .iter_mut()
            .enumerate()
            .find(|(_, n)| !n.live)
            .ok_or(Errno::ENOSPC)?;
        let mut p = [0u8; 48];
        p[..clean.len()].copy_from_slice(clean);
        *slot = CgroupNode {
            live: true,
            path: p,
            path_len: clean.len(),
            ..CgroupNode::EMPTY
        };
        Ok(idx)
    }

    /// Removes an empty child cgroup (`rmdir("/sys/fs/cgroup/<rel>")`).
    pub fn rmdir(&mut self, rel_path: &[u8]) -> Result<(), Errno> {
        let clean = trim_slashes(rel_path);
        if clean.is_empty() {
            return Err(Errno::EBUSY);
        }
        let slot = self
            .nodes
            .iter_mut()
            .find(|n| n.live && n.path() == clean)
            .ok_or(Errno::ENOENT)?;
        if slot.attached_count > 0 {
            return Err(Errno::EBUSY);
        }
        *slot = CgroupNode::EMPTY;
        Ok(())
    }

    /// Writes a cgroup v2 control file (`pids.max`, `memory.max`, `cgroup.procs`, `cgroup.subtree_control`).
    pub fn write_control_file(&mut self, rel_path: &[u8], value: &[u8]) -> Result<(), Errno> {
        let (group_path, file_name) = split_cgroup_path(rel_path)?;
        let idx = self
            .nodes
            .iter()
            .position(|n| n.live && n.path() == group_path)
            .ok_or(Errno::ENOENT)?;
        let trimmed = trim_ascii_whitespace(value);

        match file_name {
            b"pids.max" => {
                self.nodes[idx].pids_max = if trimmed == b"max" {
                    u32::MAX
                } else {
                    parse_u64_ascii(trimmed)? as u32
                };
                Ok(())
            }
            b"memory.max" => {
                self.nodes[idx].memory_max = if trimmed == b"max" {
                    u64::MAX
                } else {
                    parse_u64_ascii(trimmed)?
                };
                Ok(())
            }
            b"cgroup.subtree_control" => {
                if trimmed.windows(4).any(|w| w == b"pids") {
                    self.nodes[idx].subtree_control |= 1;
                }
                if trimmed.windows(6).any(|w| w == b"memory") {
                    self.nodes[idx].subtree_control |= 2;
                }
                if trimmed.windows(3).any(|w| w == b"cpu") {
                    self.nodes[idx].subtree_control |= 4;
                }
                Ok(())
            }
            b"cgroup.procs" => {
                let pid = parse_u64_ascii(trimmed)? as u32;
                if pid == 0 {
                    return Err(Errno::EINVAL);
                }
                if self.nodes[idx].pids_current >= self.nodes[idx].pids_max {
                    return Err(Errno::EAGAIN);
                }
                // Detach from any previous cgroup first.
                for node in &mut self.nodes {
                    if !node.live {
                        continue;
                    }
                    if let Some(pos) = node.attached_pids[..node.attached_count]
                        .iter()
                        .position(|&p| p == pid)
                    {
                        for j in pos..node.attached_count - 1 {
                            node.attached_pids[j] = node.attached_pids[j + 1];
                        }
                        node.attached_count -= 1;
                        node.pids_current = node.pids_current.saturating_sub(1);
                    }
                }
                let node = &mut self.nodes[idx];
                if node.attached_count >= node.attached_pids.len() {
                    return Err(Errno::ENOSPC);
                }
                node.attached_pids[node.attached_count] = pid;
                node.attached_count += 1;
                node.pids_current += 1;
                Ok(())
            }
            _ => Err(Errno::EACCES),
        }
    }

    /// Reads a cgroup v2 control file (`cgroup.controllers`, `pids.max`, `pids.current`,
    /// `memory.max`, `memory.current`, `cgroup.procs`, `cgroup.events`).
    pub fn read_control_file(&self, rel_path: &[u8], out: &mut [u8]) -> Result<usize, Errno> {
        let (group_path, file_name) = split_cgroup_path(rel_path)?;
        let node = self
            .nodes
            .iter()
            .find(|n| n.live && n.path() == group_path)
            .ok_or(Errno::ENOENT)?;

        match file_name {
            b"cgroup.controllers" => Ok(copy_bytes(out, b"cpu memory pids\n")),
            b"cgroup.subtree_control" => Ok(copy_bytes(out, b"cpu memory pids\n")),
            b"cgroup.events" => {
                let populated = if node.pids_current > 0 {
                    &b"populated 1\nfrozen 0\n"[..]
                } else {
                    &b"populated 0\nfrozen 0\n"[..]
                };
                Ok(copy_bytes(out, populated))
            }
            b"pids.max" => {
                if node.pids_max == u32::MAX {
                    Ok(copy_bytes(out, b"max\n"))
                } else {
                    Ok(write_u64_line(u64::from(node.pids_max), out))
                }
            }
            b"pids.current" => Ok(write_u64_line(u64::from(node.pids_current), out)),
            b"memory.max" => {
                if node.memory_max == u64::MAX {
                    Ok(copy_bytes(out, b"max\n"))
                } else {
                    Ok(write_u64_line(node.memory_max, out))
                }
            }
            b"memory.current" => Ok(write_u64_line(node.memory_current, out)),
            b"cgroup.procs" => {
                if node.attached_count == 0 {
                    Ok(0)
                } else {
                    Ok(write_u64_line(u64::from(node.attached_pids[0]), out))
                }
            }
            _ => Err(Errno::ENOENT),
        }
    }

    /// Enforces `pids.max` when `pid` attempts to fork/clone a new child.
    pub fn enforce_fork(&mut self, parent_pid: u32, child_pid: u32) -> Result<(), Errno> {
        for node in &mut self.nodes {
            if !node.live {
                continue;
            }
            if node.attached_pids[..node.attached_count].contains(&parent_pid) {
                if node.pids_current >= node.pids_max {
                    return Err(Errno::EAGAIN);
                }
                if node.attached_count < node.attached_pids.len() {
                    node.attached_pids[node.attached_count] = child_pid;
                    node.attached_count += 1;
                }
                node.pids_current += 1;
                return Ok(());
            }
        }
        Ok(())
    }

    /// Enforces `memory.max` when `pid` requests `bytes` of anonymous memory.
    pub fn enforce_memory_charge(&mut self, pid: u32, bytes: u64) -> Result<(), Errno> {
        for node in &mut self.nodes {
            if !node.live {
                continue;
            }
            if node.attached_pids[..node.attached_count].contains(&pid) {
                let next = node.memory_current.saturating_add(bytes);
                if next > node.memory_max {
                    return Err(Errno::ENOMEM);
                }
                node.memory_current = next;
                return Ok(());
            }
        }
        Ok(())
    }
}

fn trim_slashes(mut s: &[u8]) -> &[u8] {
    while let Some((&b'/', rest)) = s.split_first() {
        s = rest;
    }
    while let Some((&b'/', rest)) = s.split_last() {
        s = rest;
    }
    s
}

fn trim_ascii_whitespace(mut s: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = s.split_first() {
        if b == b' ' || b == b'\n' || b == b'\r' || b == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&b, rest)) = s.split_last() {
        if b == b' ' || b == b'\n' || b == b'\r' || b == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn split_cgroup_path(rel_path: &[u8]) -> Result<(&[u8], &[u8]), Errno> {
    let clean = trim_slashes(rel_path);
    if clean.is_empty() {
        return Err(Errno::EISDIR);
    }
    if let Some(pos) = clean.iter().rposition(|&b| b == b'/') {
        Ok((&clean[..pos], &clean[pos + 1..]))
    } else {
        Ok((b"", clean))
    }
}

fn parse_u64_ascii(s: &[u8]) -> Result<u64, Errno> {
    if s.is_empty() {
        return Err(Errno::EINVAL);
    }
    let mut acc = 0u64;
    for &b in s {
        if !b.is_ascii_digit() {
            return Err(Errno::EINVAL);
        }
        acc = acc
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(b - b'0')))
            .ok_or(Errno::EINVAL)?;
    }
    Ok(acc)
}

fn copy_bytes(out: &mut [u8], src: &[u8]) -> usize {
    let take = out.len().min(src.len());
    out[..take].copy_from_slice(&src[..take]);
    take
}

fn write_u64_line(mut value: u64, out: &mut [u8]) -> usize {
    let mut digits = [0u8; 21];
    let mut len = 0usize;
    if value == 0 {
        digits[0] = b'0';
        len = 1;
    } else {
        let mut temp = [0u8; 20];
        let mut t = 0usize;
        while value > 0 {
            temp[t] = b'0' + (value % 10) as u8;
            value /= 10;
            t += 1;
        }
        while t > 0 {
            t -= 1;
            digits[len] = temp[t];
            len += 1;
        }
    }
    digits[len] = b'\n';
    copy_bytes(out, &digits[..len + 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_bounding_and_capset_never_amplify_authority() {
        let mut sec = ProcessSecurityState::new_root_init();
        // Drop CAP_NET_RAW from bounding set via prctl.
        sec.prctl(PR_CAPBSET_DROP, u64::from(CAP_NET_RAW), 0, 0, 0)
            .unwrap();
        assert_eq!(
            sec.prctl(PR_CAPBSET_READ, u64::from(CAP_NET_RAW), 0, 0, 0)
                .unwrap(),
            0
        );

        // Drop CAP_SYS_ADMIN from permitted & effective via capset.
        let new_mask = ALL_VALID_CAPS_MASK & !(1u64 << CAP_SYS_ADMIN);
        let mut raw = [0u8; 24];
        write_u32(&mut raw, 0, new_mask as u32);
        write_u32(&mut raw, 4, new_mask as u32);
        write_u32(&mut raw, 12, (new_mask >> 32) as u32);
        write_u32(&mut raw, 16, (new_mask >> 32) as u32);
        sec.apply_cap_data_v3(&raw).unwrap();
        assert!(!sec.has_cap(CAP_SYS_ADMIN));

        // Attempting to re-acquire CAP_SYS_ADMIN must fail with EPERM!
        let full = ProcessSecurityState::new_root_init().encode_cap_data_v3();
        assert_eq!(sec.apply_cap_data_v3(&full), Err(Errno::EPERM));
        // Without CAP_SYS_ADMIN, unshare(CLONE_NEWNS) must fail with EPERM!
        assert_eq!(sec.unshare(CLONE_NEWNS), Err(Errno::EPERM));
    }

    #[test]
    fn cgroup_v2_enforces_pids_max_and_memory_max_limits() {
        let mut tree = CgroupTree::<8>::new();
        tree.mkdir(b"system.slice/sshd.service").unwrap();
        tree.write_control_file(b"system.slice/sshd.service/pids.max", b"2\n")
            .unwrap();
        tree.write_control_file(b"system.slice/sshd.service/memory.max", b"8192\n")
            .unwrap();
        tree.write_control_file(b"system.slice/sshd.service/cgroup.procs", b"100\n")
            .unwrap();

        // First fork (100 -> 101) reaches pids.current = 2 (allowed).
        tree.enforce_fork(100, 101).unwrap();
        // Second fork (100 -> 102) exceeds pids.max = 2 -> EAGAIN!
        assert_eq!(tree.enforce_fork(100, 102), Err(Errno::EAGAIN));

        // First 4096-byte allocation succeeds; second 8192-byte allocation exceeds memory.max -> ENOMEM!
        tree.enforce_memory_charge(100, 4096).unwrap();
        assert_eq!(tree.enforce_memory_charge(100, 8192), Err(Errno::ENOMEM));

        let mut buf = [0u8; 32];
        let n = tree
            .read_control_file(b"system.slice/sshd.service/pids.current", &mut buf)
            .unwrap();
        assert_eq!(&buf[..n], b"2\n");
    }
}
