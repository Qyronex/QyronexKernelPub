// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 36 & Step 41 — Namespaces (including unprivileged `CLONE_NEWUSER` without ambient
//! Kernal authority), cgroups v2 hierarchy & controller enforcement (`cpu`, `memory`, `pids`),
//! Linux capability sets (`capget`/`capset`), `prctl`, and bounded `seccomp(2)` cBPF policy.

use kernal_capability::{CapRights, Capability, ObjectId};
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
const SUPPORTED_NS_FLAGS: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET;

/// Linux `seccomp(2)` operations and return actions (`<linux/seccomp.h>`).
pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
pub const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
pub const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;
pub const SECCOMP_FILTER_FLAG_LOG: u32 = 1 << 3;
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 4;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
pub const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
pub const MAX_SECCOMP_INSNS: usize = 32;
pub const MAX_UID_GID_EXTENTS: usize = 4;

/// Classic BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompBpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SeccompBpfInsn {
    pub const ZERO: Self = Self {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    };

    pub fn from_le_bytes(raw: [u8; 8]) -> Self {
        Self {
            code: u16::from_le_bytes([raw[0], raw[1]]),
            jt: raw[2],
            jf: raw[3],
            k: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
        }
    }
}

/// Evaluation outcome of an active seccomp policy for a syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompVerdict {
    Allow,
    Errno(u16),
    Trap,
    Kill,
}

/// One ID range mapping entry in `/proc/<pid>/uid_map` or `/proc/<pid>/gid_map`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UidGidExtent {
    pub inside_id: u32,
    pub outside_id: u32,
    pub length: u32,
}

impl UidGidExtent {
    pub const EMPTY: Self = Self {
        inside_id: 0,
        outside_id: 0,
        length: 0,
    };
}

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
pub const PR_GET_SECCOMP: u32 = 21;
pub const PR_SET_SECCOMP: u32 = 22;

/// Per-process Linux capability, namespace, seccomp, and non-ambient Kernal authority state.
/// Linux namespace capabilities (`ns_caps`) NEVER expand `delegated_authority`.
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
    pub user_ns_depth: u8,
    pub ns_caps: u64,
    pub delegated_authority: Capability,
    pub uid_map: [UidGidExtent; MAX_UID_GID_EXTENTS],
    pub uid_map_len: usize,
    pub gid_map: [UidGidExtent; MAX_UID_GID_EXTENTS],
    pub gid_map_len: usize,
    pub setgroups_denied: bool,
    pub setgroups_locked: bool,
    pub seccomp_mode: u8,
    pub seccomp_insns: [SeccompBpfInsn; MAX_SECCOMP_INSNS],
    pub seccomp_len: usize,
    pub seccomp_filter_lens: [u8; 4],
    pub seccomp_filter_count: usize,
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
            user_ns_depth: 0,
            ns_caps: 0,
            delegated_authority: Capability {
                object: ObjectId(1),
                rights: CapRights::ALL,
            },
            uid_map: [UidGidExtent::EMPTY; MAX_UID_GID_EXTENTS],
            uid_map_len: 0,
            gid_map: [UidGidExtent::EMPTY; MAX_UID_GID_EXTENTS],
            gid_map_len: 0,
            setgroups_denied: false,
            setgroups_locked: false,
            seccomp_mode: 0,
            seccomp_insns: [SeccompBpfInsn::ZERO; MAX_SECCOMP_INSNS],
            seccomp_len: 0,
            seccomp_filter_lens: [0; 4],
            seccomp_filter_count: 0,
        }
    }

    /// Creates an unprivileged non-root process holding only explicit delegated `authority`.
    pub const fn new_unprivileged(delegated_authority: Capability) -> Self {
        let mut s = Self::new_root_init();
        s.effective = 0;
        s.permitted = 0;
        s.bounding = 0;
        s.child_subreaper = false;
        s.delegated_authority = delegated_authority;
        s
    }

    pub const fn has_cap(&self, cap: u32) -> bool {
        if cap > CAP_LAST_CAP {
            return false;
        }
        (self.effective & (1u64 << cap)) != 0
    }

    /// Checks whether capability `cap` holds inside the process's current user namespace
    /// (which does NOT grant host/Kernal object authority).
    pub const fn has_ns_cap(&self, cap: u32) -> bool {
        if cap > CAP_LAST_CAP {
            return false;
        }
        ((self.effective | self.ns_caps) & (1u64 << cap)) != 0
    }

    /// Verifies non-ambient Kernal object authority: entering `CLONE_NEWUSER` and holding full
    /// Linux `ns_caps` inside a container can NEVER satisfy a host capability check beyond
    /// `self.delegated_authority`.
    pub const fn check_kernal_authority(&self, requested: Capability) -> bool {
        self.delegated_authority.object.0 == requested.object.0
            && self.delegated_authority.rights.contains(requested.rights)
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

    /// Executes `unshare(2)` namespace creation flags.
    /// `CLONE_NEWUSER` may be created unprivileged (alongside child namespaces in the same call),
    /// granting userns-local `ns_caps` while never expanding `delegated_authority`.
    /// Entering host namespaces without `CLONE_NEWUSER` requires `CAP_SYS_ADMIN` or being inside
    /// an already-unshared user namespace (`user_ns_depth > 0`).
    pub fn unshare(&mut self, flags: u64) -> Result<(), Errno> {
        if flags == 0 {
            return Ok(());
        }
        if (flags & !SUPPORTED_NS_FLAGS) != 0 {
            return Err(Errno::EINVAL);
        }
        let creating_user_ns = (flags & CLONE_NEWUSER) != 0;
        let non_user_flags = flags & !CLONE_NEWUSER;
        if creating_user_ns {
            if self.user_ns_depth >= 8 {
                return Err(Errno::EINVAL);
            }
            self.user_ns_depth += 1;
            self.ns_caps = ALL_VALID_CAPS_MASK;
        } else if non_user_flags != 0 && self.user_ns_depth == 0 && !self.has_cap(CAP_SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
        self.active_namespaces |= flags;
        Ok(())
    }

    /// Writes `/proc/self/setgroups` (`"deny"` or `"allow"`). Unprivileged userns processes must
    /// deny `setgroups` before writing `gid_map`.
    pub fn write_setgroups(&mut self, value: &[u8]) -> Result<(), Errno> {
        if self.setgroups_locked || self.gid_map_len > 0 {
            return Err(Errno::EPERM);
        }
        let trimmed = trim_ascii_whitespace(value);
        match trimmed {
            b"deny" => {
                self.setgroups_denied = true;
                self.setgroups_locked = true;
                Ok(())
            }
            b"allow" => {
                if !self.has_cap(CAP_SETGID) {
                    return Err(Errno::EPERM);
                }
                self.setgroups_denied = false;
                self.setgroups_locked = true;
                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// Writes `/proc/self/uid_map` once (`"<inside> <outside> <len>"`).
    pub fn write_uid_map(&mut self, data: &[u8]) -> Result<(), Errno> {
        if self.uid_map_len > 0 {
            return Err(Errno::EPERM);
        }
        let count = parse_id_map(data, &mut self.uid_map)?;
        self.uid_map_len = count;
        Ok(())
    }

    /// Writes `/proc/self/gid_map` once, enforcing Linux's `setgroups = deny` rule for
    /// unprivileged user namespaces without `CAP_SETGID`.
    pub fn write_gid_map(&mut self, data: &[u8]) -> Result<(), Errno> {
        if self.gid_map_len > 0 {
            return Err(Errno::EPERM);
        }
        if !self.setgroups_denied && !self.has_cap(CAP_SETGID) {
            return Err(Errno::EPERM);
        }
        let count = parse_id_map(data, &mut self.gid_map)?;
        self.gid_map_len = count;
        Ok(())
    }

    pub fn map_uid(&self, inside_uid: u32) -> Option<u32> {
        lookup_mapped_id(&self.uid_map[..self.uid_map_len], inside_uid)
    }

    pub fn map_gid(&self, inside_gid: u32) -> Option<u32> {
        lookup_mapped_id(&self.gid_map[..self.gid_map_len], inside_gid)
    }

    pub fn format_uid_map(&self, out: &mut [u8]) -> usize {
        format_id_map(&self.uid_map[..self.uid_map_len], out)
    }

    pub fn format_gid_map(&self, out: &mut [u8]) -> usize {
        format_id_map(&self.gid_map[..self.gid_map_len], out)
    }

    pub fn format_setgroups(&self, out: &mut [u8]) -> usize {
        if self.setgroups_denied {
            copy_bytes(out, b"deny\n")
        } else {
            copy_bytes(out, b"allow\n")
        }
    }

    /// Installs or inspects bounded Step-41 `seccomp(2)` filters.
    pub fn seccomp_syscall(
        &mut self,
        operation: u32,
        flags: u32,
        filter_insns: &[SeccompBpfInsn],
    ) -> Result<i64, Errno> {
        match operation {
            SECCOMP_SET_MODE_STRICT => {
                if flags != 0 || !filter_insns.is_empty() {
                    return Err(Errno::EINVAL);
                }
                if self.seccomp_mode == 2 {
                    return Err(Errno::EINVAL);
                }
                self.seccomp_mode = 1;
                Ok(0)
            }
            SECCOMP_SET_MODE_FILTER => {
                let allowed_flags = SECCOMP_FILTER_FLAG_TSYNC
                    | SECCOMP_FILTER_FLAG_LOG
                    | SECCOMP_FILTER_FLAG_SPEC_ALLOW;
                if (flags & !allowed_flags) != 0 {
                    return Err(Errno::EINVAL);
                }
                if !self.no_new_privs && !self.has_ns_cap(CAP_SYS_ADMIN) {
                    return Err(Errno::EACCES);
                }
                if self.seccomp_mode == 1 {
                    return Err(Errno::EINVAL);
                }
                verify_seccomp_bpf(filter_insns)?;
                if self.seccomp_filter_count >= self.seccomp_filter_lens.len() {
                    return Err(Errno::ENOMEM);
                }
                let remaining = MAX_SECCOMP_INSNS.saturating_sub(self.seccomp_len);
                if filter_insns.len() > remaining {
                    return Err(Errno::ENOMEM);
                }
                let start = self.seccomp_len;
                self.seccomp_insns[start..start + filter_insns.len()].copy_from_slice(filter_insns);
                self.seccomp_len += filter_insns.len();
                self.seccomp_filter_lens[self.seccomp_filter_count] = filter_insns.len() as u8;
                self.seccomp_filter_count += 1;
                self.seccomp_mode = 2;
                Ok(0)
            }
            SECCOMP_GET_ACTION_AVAIL => {
                if flags != 0 || filter_insns.len() != 1 {
                    // Use k of first insn or handle raw u32 action at caller layer.
                    return Err(Errno::EINVAL);
                }
                let action = filter_insns[0].k;
                if matches!(
                    action,
                    SECCOMP_RET_ALLOW
                        | SECCOMP_RET_ERRNO
                        | SECCOMP_RET_TRAP
                        | SECCOMP_RET_KILL_THREAD
                        | SECCOMP_RET_KILL_PROCESS
                ) {
                    Ok(0)
                } else {
                    Err(Errno::EOPNOTSUPP)
                }
            }
            SECCOMP_GET_NOTIF_SIZES => {
                if flags != 0 {
                    return Err(Errno::EINVAL);
                }
                // Return fixed 0 notification support signal unless notif enabled, or EOPNOTSUPP?
                // Returning sizeof(seccomp_notif_sizes)=6 is standard Linux ABI (notif=80, resp=24, data=64).
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// Evaluates active seccomp strict/cBPF filter against `(nr, arch, pc, args)`.
    pub fn evaluate_seccomp(&self, nr: u32, arch: u32, ip: u64, args: [u64; 6]) -> SeccompVerdict {
        match self.seccomp_mode {
            0 => SeccompVerdict::Allow,
            1 => {
                // Linux strict mode on AArch64: read(63), write(64), exit(93), rt_sigreturn(139).
                if matches!(nr, 63 | 64 | 93 | 139) {
                    SeccompVerdict::Allow
                } else {
                    SeccompVerdict::Kill
                }
            }
            _ => {
                let lens = &self.seccomp_filter_lens[..self.seccomp_filter_count];
                if lens.is_empty() {
                    return SeccompVerdict::Allow;
                }
                eval_seccomp_bpf_chain(
                    &self.seccomp_insns[..self.seccomp_len],
                    lens,
                    nr,
                    arch,
                    ip,
                    args,
                )
            }
        }
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
            PR_GET_SECCOMP => Ok(i64::from(self.seccomp_mode)),
            PR_SET_SECCOMP => {
                if arg2 == 1 && arg3 == 0 {
                    self.seccomp_syscall(SECCOMP_SET_MODE_STRICT, 0, &[])
                } else {
                    Err(Errno::EINVAL)
                }
            }
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

/// Maximum relative cgroup v2 path length (`/sys/fs/cgroup/<rel>`).
pub const MAX_CGROUP_PATH_LEN: usize = 128;
/// Maximum number of PIDs directly attached to a single cgroup node.
pub const MAX_CGROUP_ATTACHED_PIDS: usize = 32;

/// One node in the Step-36/41 cgroups v2 unified hierarchy (`/sys/fs/cgroup/<slice>`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupNode {
    live: bool,
    path: [u8; MAX_CGROUP_PATH_LEN],
    path_len: usize,
    pids_max: u32,
    pids_current: u32,
    memory_max: u64,
    memory_current: u64,
    cpu_quota_us: u64,
    cpu_period_us: u64,
    cpu_usage_us: u64,
    cpu_nr_throttled: u64,
    subtree_control: u32, // bit 0 = pids, bit 1 = memory, bit 2 = cpu
    attached_pids: [u32; MAX_CGROUP_ATTACHED_PIDS],
    attached_count: usize,
    oom_group: bool,
    frozen: bool,
}

impl CgroupNode {
    const EMPTY: Self = Self {
        live: false,
        path: [0u8; MAX_CGROUP_PATH_LEN],
        path_len: 0,
        pids_max: u32::MAX,
        pids_current: 0,
        memory_max: u64::MAX,
        memory_current: 0,
        cpu_quota_us: u64::MAX,
        cpu_period_us: 100_000,
        cpu_usage_us: 0,
        cpu_nr_throttled: 0,
        subtree_control: 0,
        attached_pids: [0; MAX_CGROUP_ATTACHED_PIDS],
        attached_count: 0,
        oom_group: false,
        frozen: false,
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

    /// Creates a child cgroup directory (`mkdir("/sys/fs/cgroup/<rel>")`), allowing direct
    /// multi-level slice creation for legacy callers and unit tests.
    pub fn mkdir(&mut self, rel_path: &[u8]) -> Result<usize, Errno> {
        self.mkdir_inner(rel_path, false)
    }

    /// Creates a child cgroup directory with POSIX parent validation (`ENOENT` if missing).
    pub fn mkdir_strict(&mut self, rel_path: &[u8]) -> Result<usize, Errno> {
        self.mkdir_inner(rel_path, true)
    }

    fn mkdir_inner(&mut self, rel_path: &[u8], require_parent: bool) -> Result<usize, Errno> {
        let clean = trim_slashes(rel_path);
        if clean.is_empty() {
            return Err(Errno::EEXIST);
        }
        if clean.len() > MAX_CGROUP_PATH_LEN {
            return Err(Errno::ENAMETOOLONG);
        }
        if self.nodes.iter().any(|n| n.live && n.path() == clean) {
            return Err(Errno::EEXIST);
        }
        if require_parent && let Some(pos) = clean.iter().rposition(|&b| b == b'/') {
            let parent = &clean[..pos];
            if !self.nodes.iter().any(|n| n.live && n.path() == parent) {
                return Err(Errno::ENOENT);
            }
        }
        let (idx, slot) = self
            .nodes
            .iter_mut()
            .enumerate()
            .find(|(_, n)| !n.live)
            .ok_or(Errno::ENOSPC)?;
        let mut p = [0u8; MAX_CGROUP_PATH_LEN];
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
        let has_child = self.nodes.iter().any(|n| {
            n.live
                && n.path_len > clean.len()
                && n.path().starts_with(clean)
                && n.path()[clean.len()] == b'/'
        });
        if has_child {
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
            b"cpu.max" => {
                let (quota, period) = parse_cpu_max(trimmed)?;
                self.nodes[idx].cpu_quota_us = quota;
                self.nodes[idx].cpu_period_us = period;
                Ok(())
            }
            b"cgroup.subtree_control" => {
                for tok in trimmed.split(|&b| b == b' ' || b == b'\t' || b == b'\n') {
                    if let Some(name) = tok.strip_prefix(b"+") {
                        match name {
                            b"pids" => self.nodes[idx].subtree_control |= 1,
                            b"memory" => self.nodes[idx].subtree_control |= 2,
                            b"cpu" => self.nodes[idx].subtree_control |= 4,
                            _ => {}
                        }
                    } else if let Some(name) = tok.strip_prefix(b"-") {
                        match name {
                            b"pids" => self.nodes[idx].subtree_control &= !1,
                            b"memory" => self.nodes[idx].subtree_control &= !2,
                            b"cpu" => self.nodes[idx].subtree_control &= !4,
                            _ => {}
                        }
                    } else if tok.windows(4).any(|w| w == b"pids") {
                        self.nodes[idx].subtree_control |= 1;
                    } else if tok.windows(6).any(|w| w == b"memory") {
                        self.nodes[idx].subtree_control |= 2;
                    } else if tok.windows(3).any(|w| w == b"cpu") {
                        self.nodes[idx].subtree_control |= 4;
                    }
                }
                Ok(())
            }
            b"cgroup.procs" | b"cgroup.threads" => {
                let pid = parse_u64_ascii(trimmed)? as u32;
                if pid == 0 {
                    return Err(Errno::EINVAL);
                }
                if self.nodes[idx].pids_current >= self.nodes[idx].pids_max {
                    return Err(Errno::EAGAIN);
                }
                if self.nodes[idx].attached_pids[..self.nodes[idx].attached_count].contains(&pid) {
                    return Ok(());
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
            b"cgroup.freeze" => {
                self.nodes[idx].frozen = parse_u64_ascii(trimmed)? != 0;
                Ok(())
            }
            b"cgroup.type" => Ok(()),
            b"cgroup.kill" => Ok(()),
            b"memory.oom.group" => {
                self.nodes[idx].oom_group = parse_u64_ascii(trimmed)? != 0;
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
            b"cgroup.subtree_control" => {
                let mut pos = 0usize;
                for (bit, name) in [(4u32, &b"cpu"[..]), (2, b"memory"), (1, b"pids")] {
                    if node.subtree_control & bit != 0 {
                        if pos > 0 {
                            pos += copy_bytes(&mut out[pos..], b" ");
                        }
                        pos += copy_bytes(&mut out[pos..], name);
                    }
                }
                pos += copy_bytes(&mut out[pos..], b"\n");
                Ok(pos)
            }
            b"cgroup.events" => {
                let mut populated = node.pids_current > 0;
                if !populated && !group_path.is_empty() {
                    populated = self.nodes.iter().any(|n| {
                        n.live
                            && n.pids_current > 0
                            && n.path_len > group_path.len()
                            && n.path().starts_with(group_path)
                            && n.path()[group_path.len()] == b'/'
                    });
                }
                let txt = match (populated, node.frozen) {
                    (true, true) => &b"populated 1\nfrozen 1\n"[..],
                    (true, false) => &b"populated 1\nfrozen 0\n"[..],
                    (false, true) => &b"populated 0\nfrozen 1\n"[..],
                    (false, false) => &b"populated 0\nfrozen 0\n"[..],
                };
                Ok(copy_bytes(out, txt))
            }
            b"cgroup.freeze" => Ok(copy_bytes(out, if node.frozen { b"1\n" } else { b"0\n" })),
            b"cgroup.type" => Ok(copy_bytes(out, b"domain\n")),
            b"memory.oom.group" => Ok(copy_bytes(
                out,
                if node.oom_group { b"1\n" } else { b"0\n" },
            )),
            b"cgroup.stat" => Ok(copy_bytes(
                out,
                b"nr_descendants 0\nnr_dying_descendants 0\n",
            )),
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
            b"cpu.max" => Ok(write_cpu_max_line(
                node.cpu_quota_us,
                node.cpu_period_us,
                out,
            )),
            b"cpu.stat" => Ok(write_cpu_stat(
                node.cpu_usage_us,
                node.cpu_nr_throttled,
                out,
            )),
            b"memory.stat" => Ok(write_memory_stat(node.memory_current, out)),
            b"cgroup.procs" | b"cgroup.threads" => {
                let mut pos = 0usize;
                for &pid in &node.attached_pids[..node.attached_count] {
                    pos += write_u64_line(u64::from(pid), &mut out[pos..]);
                }
                Ok(pos)
            }
            _ => Err(Errno::ENOENT),
        }
    }

    pub fn has_dir(&self, rel_path: &[u8]) -> bool {
        let clean = trim_slashes(rel_path);
        self.nodes.iter().any(|n| n.live && n.path() == clean)
    }

    pub fn list_dir(&self, rel_path: &[u8], mut emit: impl FnMut(&[u8], bool)) -> bool {
        let clean = trim_slashes(rel_path);
        if !self.has_dir(clean) {
            return false;
        }
        for name in [
            &b"cgroup.controllers"[..],
            b"cgroup.events",
            b"cgroup.freeze",
            b"cgroup.procs",
            b"cgroup.stat",
            b"cgroup.subtree_control",
            b"cgroup.threads",
            b"cgroup.type",
            b"cpu.max",
            b"cpu.stat",
            b"memory.current",
            b"memory.max",
            b"memory.oom.group",
            b"memory.stat",
            b"pids.current",
            b"pids.max",
        ] {
            emit(name, false);
        }
        if !clean.is_empty() {
            emit(b"cgroup.kill", false);
        }
        for node in &self.nodes {
            if !node.live {
                continue;
            }
            let p = node.path();
            if p.is_empty() {
                continue;
            }
            let child_name = if clean.is_empty() {
                if !p.contains(&b'/') { Some(p) } else { None }
            } else if p.len() > clean.len() + 1 && p.starts_with(clean) && p[clean.len()] == b'/' {
                let rest = &p[clean.len() + 1..];
                if !rest.contains(&b'/') {
                    Some(rest)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(name) = child_name {
                emit(name, true);
            }
        }
        true
    }

    pub fn pid_cgroup_path(&self, pid: u32, out: &mut [u8]) -> usize {
        for node in &self.nodes {
            if node.live && node.attached_pids[..node.attached_count].contains(&pid) {
                let mut pos = copy_bytes(out, b"/");
                pos += copy_bytes(&mut out[pos..], node.path());
                return pos;
            }
        }
        copy_bytes(out, b"/")
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

    /// Releases previously charged memory when pages are unmapped or a container exits.
    pub fn release_memory_charge(&mut self, pid: u32, bytes: u64) {
        for node in &mut self.nodes {
            if node.live && node.attached_pids[..node.attached_count].contains(&pid) {
                node.memory_current = node.memory_current.saturating_sub(bytes);
                return;
            }
        }
    }

    /// Removes `pid` from its cgroup on process exit so `pids.current` recovers cleanly.
    pub fn release_pid(&mut self, pid: u32) {
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
                return;
            }
        }
    }

    /// Enforces `cpu.max` bandwidth quota for the current period (`EAGAIN` when throttled).
    pub fn enforce_cpu_consume(&mut self, pid: u32, delta_us: u64) -> Result<(), Errno> {
        for node in &mut self.nodes {
            if !node.live {
                continue;
            }
            if node.attached_pids[..node.attached_count].contains(&pid) {
                let next = node.cpu_usage_us.saturating_add(delta_us);
                if node.cpu_quota_us != u64::MAX && next > node.cpu_quota_us {
                    node.cpu_nr_throttled = node.cpu_nr_throttled.saturating_add(1);
                    return Err(Errno::EAGAIN);
                }
                node.cpu_usage_us = next;
                return Ok(());
            }
        }
        Ok(())
    }

    /// Refills period counters at the start of a new scheduler bandwidth window.
    pub fn reset_cpu_period(&mut self, rel_path: &[u8]) -> Result<(), Errno> {
        let clean = trim_slashes(rel_path);
        let node = self
            .nodes
            .iter_mut()
            .find(|n| n.live && n.path() == clean)
            .ok_or(Errno::ENOENT)?;
        node.cpu_usage_us = 0;
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

fn format_u64_into(mut value: u64, out: &mut [u8]) -> usize {
    if value == 0 {
        return copy_bytes(out, b"0");
    }
    let mut temp = [0u8; 20];
    let mut t = 0usize;
    while value > 0 {
        temp[t] = b'0' + (value % 10) as u8;
        value /= 10;
        t += 1;
    }
    let mut pos = 0usize;
    while t > 0 && pos < out.len() {
        t -= 1;
        out[pos] = temp[t];
        pos += 1;
    }
    pos
}

fn parse_cpu_max(trimmed: &[u8]) -> Result<(u64, u64), Errno> {
    let split = trimmed.iter().position(|&b| b == b' ' || b == b'\t');
    match split {
        None => {
            let quota = if trimmed == b"max" {
                u64::MAX
            } else {
                parse_u64_ascii(trimmed)?
            };
            Ok((quota, 100_000))
        }
        Some(idx) => {
            let q_part = trim_ascii_whitespace(&trimmed[..idx]);
            let p_part = trim_ascii_whitespace(&trimmed[idx + 1..]);
            let quota = if q_part == b"max" {
                u64::MAX
            } else {
                parse_u64_ascii(q_part)?
            };
            let period = parse_u64_ascii(p_part)?;
            if !(1_000..=1_000_000).contains(&period) {
                return Err(Errno::EINVAL);
            }
            Ok((quota, period))
        }
    }
}

fn write_cpu_max_line(quota: u64, period: u64, out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    if quota == u64::MAX {
        pos += copy_bytes(&mut out[pos..], b"max");
    } else {
        pos += format_u64_into(quota, &mut out[pos..]);
    }
    pos += copy_bytes(&mut out[pos..], b" ");
    pos += format_u64_into(period, &mut out[pos..]);
    pos += copy_bytes(&mut out[pos..], b"\n");
    pos
}

fn write_cpu_stat(usage_us: u64, nr_throttled: u64, out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    pos += copy_bytes(&mut out[pos..], b"usage_usec ");
    pos += format_u64_into(usage_us, &mut out[pos..]);
    pos += copy_bytes(&mut out[pos..], b"\nnr_throttled ");
    pos += format_u64_into(nr_throttled, &mut out[pos..]);
    pos += copy_bytes(&mut out[pos..], b"\n");
    pos
}

fn write_memory_stat(memory_current: u64, out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    pos += copy_bytes(&mut out[pos..], b"anon ");
    pos += format_u64_into(memory_current, &mut out[pos..]);
    pos += copy_bytes(&mut out[pos..], b"\n");
    pos
}

fn parse_id_map(
    data: &[u8],
    dst: &mut [UidGidExtent; MAX_UID_GID_EXTENTS],
) -> Result<usize, Errno> {
    let mut count = 0usize;
    for raw_line in data.split(|&b| b == b'\n') {
        let line = trim_ascii_whitespace(raw_line);
        if line.is_empty() {
            continue;
        }
        if count >= MAX_UID_GID_EXTENTS {
            return Err(Errno::EINVAL);
        }
        let mut fields = [0u32; 3];
        let mut idx = 0usize;
        for token in line.split(|&b| b == b' ' || b == b'\t') {
            if token.is_empty() {
                continue;
            }
            if idx >= 3 {
                return Err(Errno::EINVAL);
            }
            fields[idx] = u32::try_from(parse_u64_ascii(token)?).map_err(|_| Errno::EINVAL)?;
            idx += 1;
        }
        if idx != 3 || fields[2] == 0 {
            return Err(Errno::EINVAL);
        }
        dst[count] = UidGidExtent {
            inside_id: fields[0],
            outside_id: fields[1],
            length: fields[2],
        };
        count += 1;
    }
    if count == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(count)
}

fn lookup_mapped_id(extents: &[UidGidExtent], inside: u32) -> Option<u32> {
    for e in extents {
        if inside >= e.inside_id && (inside - e.inside_id) < e.length {
            return e.outside_id.checked_add(inside - e.inside_id);
        }
    }
    None
}

fn format_id_map(extents: &[UidGidExtent], out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    for e in extents {
        pos += format_u64_into(u64::from(e.inside_id), &mut out[pos..]);
        pos += copy_bytes(&mut out[pos..], b" ");
        pos += format_u64_into(u64::from(e.outside_id), &mut out[pos..]);
        pos += copy_bytes(&mut out[pos..], b" ");
        pos += format_u64_into(u64::from(e.length), &mut out[pos..]);
        pos += copy_bytes(&mut out[pos..], b"\n");
    }
    pos
}

// Classic BPF opcode masks (`<linux/bpf_common.h>`, `<linux/filter.h>`).
pub const BPF_CLASS_MASK: u16 = 0x07;
pub const BPF_LD: u16 = 0x00;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;

fn verify_seccomp_bpf(insns: &[SeccompBpfInsn]) -> Result<(), Errno> {
    if insns.is_empty() || insns.len() > MAX_SECCOMP_INSNS {
        return Err(Errno::EINVAL);
    }
    for (pc, insn) in insns.iter().enumerate() {
        let class = insn.code & BPF_CLASS_MASK;
        match class {
            BPF_LD => {
                // Allow aligned 32-bit loads within `struct seccomp_data` (64 bytes).
                if insn.code != (BPF_LD | BPF_W | BPF_ABS) || (insn.k & 3) != 0 || insn.k >= 64 {
                    return Err(Errno::EINVAL);
                }
            }
            BPF_JMP => {
                let op = insn.code & 0xf0;
                let src = insn.code & 0x08;
                if src != BPF_K {
                    return Err(Errno::EINVAL);
                }
                if op == BPF_JA {
                    let target = pc
                        .checked_add(1)
                        .and_then(|v| v.checked_add(insn.k as usize));
                    if target.is_none_or(|t| t >= insns.len()) {
                        return Err(Errno::EINVAL);
                    }
                } else if matches!(op, BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET) {
                    let t_dst = pc + 1 + usize::from(insn.jt);
                    let f_dst = pc + 1 + usize::from(insn.jf);
                    if t_dst >= insns.len() || f_dst >= insns.len() {
                        return Err(Errno::EINVAL);
                    }
                } else {
                    return Err(Errno::EINVAL);
                }
            }
            BPF_RET => {
                if insn.code != (BPF_RET | BPF_K) {
                    return Err(Errno::EINVAL);
                }
            }
            _ => return Err(Errno::EINVAL),
        }
    }
    // Guarantee every path ends at a return instruction.
    if insns.last().map(|i| i.code & BPF_CLASS_MASK) != Some(BPF_RET) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

fn eval_single_seccomp_bpf(
    insns: &[SeccompBpfInsn],
    nr: u32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
) -> u32 {
    let mut acc = 0u32;
    let mut pc = 0usize;
    while pc < insns.len() {
        let insn = insns[pc];
        match insn.code & BPF_CLASS_MASK {
            BPF_LD => {
                acc = load_seccomp_data_word(insn.k, nr, arch, ip, args);
                pc += 1;
            }
            BPF_JMP => {
                let op = insn.code & 0xf0;
                if op == BPF_JA {
                    pc += 1 + insn.k as usize;
                } else {
                    let cond = match op {
                        BPF_JEQ => acc == insn.k,
                        BPF_JGT => acc > insn.k,
                        BPF_JGE => acc >= insn.k,
                        BPF_JSET => (acc & insn.k) != 0,
                        _ => false,
                    };
                    pc += 1 + if cond {
                        usize::from(insn.jt)
                    } else {
                        usize::from(insn.jf)
                    };
                }
            }
            BPF_RET => return insn.k,
            _ => return SECCOMP_RET_KILL_PROCESS,
        }
    }
    SECCOMP_RET_KILL_PROCESS
}

fn load_seccomp_data_word(off: u32, nr: u32, arch: u32, ip: u64, args: [u64; 6]) -> u32 {
    match off {
        0 => nr,
        4 => arch,
        8 => ip as u32,
        12 => (ip >> 32) as u32,
        16..=60 => {
            let arg_idx = ((off - 16) / 8) as usize;
            let hi = !(off - 16).is_multiple_of(8);
            if arg_idx >= 6 {
                0
            } else if hi {
                (args[arg_idx] >> 32) as u32
            } else {
                args[arg_idx] as u32
            }
        }
        _ => 0,
    }
}

fn eval_seccomp_bpf_chain(
    all_insns: &[SeccompBpfInsn],
    lens: &[u8],
    nr: u32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
) -> SeccompVerdict {
    let mut offset = 0usize;
    let mut lowest_raw = SECCOMP_RET_ALLOW;
    for &len in lens {
        let len = usize::from(len);
        let prog = &all_insns[offset..offset + len];
        let action = eval_single_seccomp_bpf(prog, nr, arch, ip, args);
        if ((action & SECCOMP_RET_ACTION_FULL) as i32)
            < ((lowest_raw & SECCOMP_RET_ACTION_FULL) as i32)
        {
            lowest_raw = action;
        }
        offset += len;
    }
    match lowest_raw & SECCOMP_RET_ACTION_FULL {
        SECCOMP_RET_ALLOW => SeccompVerdict::Allow,
        SECCOMP_RET_ERRNO => SeccompVerdict::Errno((lowest_raw & SECCOMP_RET_DATA) as u16),
        SECCOMP_RET_TRAP => SeccompVerdict::Trap,
        _ => SeccompVerdict::Kill,
    }
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

    #[test]
    fn user_namespace_never_amplifies_delegated_kernal_authority() {
        let host_obj = ObjectId(77);
        let child_auth = Capability {
            object: host_obj,
            rights: CapRights::READ,
        };
        let mut sec = ProcessSecurityState::new_unprivileged(child_auth);
        assert!(!sec.has_cap(CAP_SYS_ADMIN));

        // Direct unshare(CLONE_NEWNET) without CLONE_NEWUSER must still fail with EPERM.
        assert_eq!(sec.unshare(CLONE_NEWNET), Err(Errno::EPERM));

        // Unprivileged unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS) succeeds,
        // grants ns_caps inside the userns, yet NEVER escalates Kernal object rights!
        sec.unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)
            .unwrap();
        assert!(sec.has_ns_cap(CAP_NET_ADMIN));
        assert!(!sec.has_cap(CAP_SYS_ADMIN));
        assert!(sec.check_kernal_authority(Capability {
            object: host_obj,
            rights: CapRights::READ,
        }));
        assert!(!sec.check_kernal_authority(Capability {
            object: host_obj,
            rights: CapRights::WRITE,
        }));
        assert!(!sec.check_kernal_authority(Capability {
            object: ObjectId(999),
            rights: CapRights::READ,
        }));

        // gid_map before setgroups=deny is rejected with EPERM; setgroups=deny unlocks write-once gid_map.
        assert_eq!(sec.write_gid_map(b"0 1000 1\n"), Err(Errno::EPERM));
        sec.write_setgroups(b"deny\n").unwrap();
        sec.write_uid_map(b"0 1000 1\n").unwrap();
        sec.write_gid_map(b"0 1000 1\n").unwrap();
        assert_eq!(sec.map_uid(0), Some(1000));
        assert_eq!(sec.map_gid(0), Some(1000));
        assert_eq!(sec.write_uid_map(b"0 0 1\n"), Err(Errno::EPERM));
    }

    #[test]
    fn cgroup_v2_cpu_max_and_seccomp_bpf_policies_are_enforced() {
        let mut tree = CgroupTree::<8>::new();
        tree.mkdir(b"container.slice/oci-1").unwrap();
        tree.write_control_file(b"container.slice/oci-1/cpu.max", b"20000 100000\n")
            .unwrap();
        tree.write_control_file(b"container.slice/oci-1/cgroup.procs", b"201\n")
            .unwrap();
        tree.enforce_cpu_consume(201, 15_000).unwrap();
        assert_eq!(tree.enforce_cpu_consume(201, 10_000), Err(Errno::EAGAIN));
        tree.reset_cpu_period(b"container.slice/oci-1").unwrap();
        tree.enforce_cpu_consume(201, 10_000).unwrap();

        let mut stat = [0u8; 64];
        let slen = tree
            .read_control_file(b"container.slice/oci-1/cpu.stat", &mut stat)
            .unwrap();
        let stext = core::str::from_utf8(&stat[..slen]).unwrap();
        assert!(stext.contains("nr_throttled 1\n"));

        // Seccomp cBPF filter: block reboot(142) with EPERM (1) after setting NO_NEW_PRIVS.
        let mut sec = ProcessSecurityState::new_unprivileged(Capability {
            object: ObjectId(88),
            rights: CapRights::READ,
        });
        let prog = [
            // [0] load arch (offset 4)
            SeccompBpfInsn {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            // [1] if arch == AUDIT_ARCH_AARCH64 -> +0 else -> kill (offset +3 -> idx 5)
            SeccompBpfInsn {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0,
                jf: 3,
                k: AUDIT_ARCH_AARCH64,
            },
            // [2] load nr (offset 0)
            SeccompBpfInsn {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // [3] if nr == 142 (reboot) -> +2 (idx 6 return ERRNO|1) else +0 (idx 4 allow)
            SeccompBpfInsn {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 2,
                jf: 0,
                k: 142,
            },
            // [4] allow
            SeccompBpfInsn {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            // [5] kill on wrong arch
            SeccompBpfInsn {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            // [6] return EPERM
            SeccompBpfInsn {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | 1,
            },
        ];
        // Without no_new_privs and without CAP_SYS_ADMIN -> EACCES.
        assert_eq!(
            sec.seccomp_syscall(SECCOMP_SET_MODE_FILTER, 0, &prog),
            Err(Errno::EACCES)
        );
        sec.no_new_privs = true;
        sec.seccomp_syscall(SECCOMP_SET_MODE_FILTER, 0, &prog)
            .unwrap();
        assert_eq!(
            sec.evaluate_seccomp(63, AUDIT_ARCH_AARCH64, 0, [0; 6]),
            SeccompVerdict::Allow
        );
        assert_eq!(
            sec.evaluate_seccomp(142, AUDIT_ARCH_AARCH64, 0, [0; 6]),
            SeccompVerdict::Errno(1)
        );
        assert_eq!(
            sec.evaluate_seccomp(63, 0x8000_003e, 0, [0; 6]),
            SeccompVerdict::Kill
        );
    }

    #[test]
    fn cgroup_v2_nested_hierarchy_listing_and_pid_lookup_work() {
        let mut tree = CgroupTree::<8>::new();
        assert_eq!(
            tree.mkdir_strict(b"system.slice/journald.service"),
            Err(Errno::ENOENT)
        );
        tree.mkdir_strict(b"system.slice").unwrap();
        tree.mkdir_strict(b"system.slice/journald.service").unwrap();
        tree.write_control_file(
            b"system.slice/cgroup.subtree_control",
            b"+cpu +memory +pids\n",
        )
        .unwrap();
        tree.write_control_file(b"system.slice/journald.service/cgroup.procs", b"42\n")
            .unwrap();

        let mut path = [0u8; MAX_CGROUP_PATH_LEN];
        let plen = tree.pid_cgroup_path(42, &mut path);
        assert_eq!(&path[..plen], b"/system.slice/journald.service");

        let mut entries = [[0u8; 32]; 32];
        let mut entry_lens = [0usize; 32];
        let mut entry_dirs = [false; 32];
        let mut count = 0usize;
        assert!(tree.list_dir(b"system.slice", |name, is_dir| {
            if count < entries.len() {
                let n = name.len().min(32);
                entries[count][..n].copy_from_slice(&name[..n]);
                entry_lens[count] = n;
                entry_dirs[count] = is_dir;
                count += 1;
            }
        }));
        assert!(
            entries[..count]
                .iter()
                .zip(entry_lens[..count].iter())
                .zip(entry_dirs[..count].iter())
                .any(|((buf, &l), &is_dir)| is_dir && &buf[..l] == b"journald.service")
        );
        assert!(
            entries[..count]
                .iter()
                .zip(entry_lens[..count].iter())
                .zip(entry_dirs[..count].iter())
                .any(|((buf, &l), &is_dir)| !is_dir && &buf[..l] == b"cgroup.procs")
        );

        assert_eq!(tree.rmdir(b"system.slice"), Err(Errno::EBUSY));
        assert_eq!(
            tree.rmdir(b"system.slice/journald.service"),
            Err(Errno::EBUSY)
        );
    }
}
