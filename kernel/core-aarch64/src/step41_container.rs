// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_linux_abi::{
    Errno, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_cgroup::{
    MAX_SECCOMP_INSNS, SECCOMP_GET_ACTION_AVAIL, SECCOMP_GET_NOTIF_SIZES, SECCOMP_SET_MODE_FILTER,
    SECCOMP_SET_MODE_STRICT, SeccompBpfInsn,
};
use kernal_linux_container::{
    NamespaceFd, NamespaceKind, NamespaceSet, OverlayLowerLayer, OverlayUpperMount, apply_setns,
};
use kernal_usercopy::Error as UsercopyError;

/// Dedicated file-descriptor base for Step-41 container namespace, cgroup-write, and proc-idmap
/// descriptors (`224..240`), cleanly partitioned above `BOOT_FD_BASE` (`208..224`).
pub(super) const CONTAINER_FD_BASE: i32 = 224;
const MAX_CONTAINER_FDS: usize = 16;
const O_ACCMODE: u64 = 0o3;
const O_RDONLY: u64 = 0o0;
const ARM64_STAT_BYTES: usize = 128;
const S_IFREG_MODE: u32 = 0o100_644;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ContainerFileKind {
    None,
    UidMap,
    GidMap,
    Setgroups,
    Ns(NamespaceFd),
    CgroupCtrl {
        rel: [u8; 48],
        rel_len: usize,
        writable: bool,
    },
    OverlayFile {
        path: [u8; 64],
        path_len: usize,
        writable: bool,
    },
}

#[derive(Clone, Copy)]
struct ContainerFdSlot {
    kind: ContainerFileKind,
    offset: usize,
}

impl ContainerFdSlot {
    const EMPTY: Self = Self {
        kind: ContainerFileKind::None,
        offset: 0,
    };
}

struct Step41State {
    initialized: bool,
    namespaces: NamespaceSet,
    overlay_lower: OverlayLowerLayer,
    overlay_upper: OverlayUpperMount,
    fds: [ContainerFdSlot; MAX_CONTAINER_FDS],
}

impl Step41State {
    const fn new() -> Self {
        Self {
            initialized: false,
            namespaces: NamespaceSet::initial(),
            overlay_lower: OverlayLowerLayer::new(),
            overlay_upper: OverlayUpperMount::new(),
            fds: [ContainerFdSlot::EMPTY; MAX_CONTAINER_FDS],
        }
    }

    fn ensure_initialized(&mut self) {
        if !self.initialized {
            let _ = self.overlay_lower.seed_file(
                b"/etc/os-release",
                0o100_644,
                b"PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n",
            );
            self.initialized = true;
        }
    }
}

struct Step41Cell {
    state: AtomicU8,
    value: UnsafeCell<Step41State>,
}

// SAFETY: lower-EL trap dispatch serializes access cleanly via atomic `0 -> 1 -> 0`.
unsafe impl Sync for Step41Cell {}

static STEP41_STATE: Step41Cell = Step41Cell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step41State::new()),
};

fn with_step41_state<R>(f: impl FnOnce(&mut Step41State) -> R) -> Result<R, ()> {
    if STEP41_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state `1` grants exclusive mutable access for this synchronous handler scope.
    let state = unsafe { &mut *STEP41_STATE.value.get() };
    state.ensure_initialized();
    let res = f(state);
    STEP41_STATE.state.store(0, Ordering::Release);
    Ok(res)
}

pub(super) const fn is_container_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= CONTAINER_FD_BASE && fd < CONTAINER_FD_BASE + (MAX_CONTAINER_FDS as i32)
}

fn container_idx(raw_fd: u64) -> Result<usize, Errno> {
    if !is_container_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    Ok((linux_signed_int(raw_fd) - CONTAINER_FD_BASE) as usize)
}

pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        // mkdirat(dirfd, pathname, mode) on `/sys/fs/cgroup/...`
        34 => handle_mkdirat_if_cgroup(request.args[1]),
        // openat(dirfd, pathname, flags, mode)
        56 => handle_openat_if_container(request.args[1], request.args[2]),
        // close(fd)
        57 if is_container_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        // lseek(fd, offset, whence)
        62 if is_container_fd(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
        )?))),
        // read(fd, buf, count)
        63 if is_container_fd(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // write(fd, buf, count)
        64 if is_container_fd(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // readlinkat(dirfd, pathname, buf, bufsiz) for `/proc/<pid>/ns/*`
        78 => handle_readlinkat_if_ns(request.args[1], request.args[2], request.args[3]),
        // fstat(fd, statbuf)
        80 if is_container_fd(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        // unshare(flags) — delegates security validation and updates NamespaceSet
        97 => Ok(Some(encode_result(handle_unshare(request.args[0])?))),
        // setns(fd, nstype)
        268 => Ok(Some(encode_result(handle_setns(
            request.args[0],
            request.args[1],
        )?))),
        // seccomp(operation, flags, args)
        277 => Ok(Some(encode_result(handle_seccomp(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        _ => Ok(None),
    }
}

fn encode_result(res: Result<i64, Errno>) -> SyscallReturn {
    match res {
        Ok(val) => SyscallReturn::success(val).unwrap_or(SyscallReturn::error(Errno::EINVAL)),
        Err(errno) => SyscallReturn::error(errno),
    }
}

fn handle_mkdirat_if_cgroup(user_path: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 96];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let Some(rel) = path_buf[..len].strip_prefix(b"/sys/fs/cgroup/") else {
        return Ok(None);
    };
    let res = super::step35_events_cgroup::cgroup_mkdir(rel).map(|()| 0i64);
    Ok(Some(encode_result(res)))
}

fn parse_proc_container_path(path: &[u8]) -> Option<(&[u8], &[u8])> {
    let after_proc = path.strip_prefix(b"/proc/")?;
    let slash = after_proc.iter().position(|&b| b == b'/')?;
    let pid_part = &after_proc[..slash];
    let valid_pid = pid_part == b"self"
        || pid_part == b"thread-self"
        || (!pid_part.is_empty() && pid_part.iter().all(|b| b.is_ascii_digit()));
    if !valid_pid {
        return None;
    }
    Some((pid_part, &after_proc[slash + 1..]))
}

fn handle_readlinkat_if_ns(
    user_path: u64,
    user_buf: u64,
    bufsiz: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 96];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let Some((_, rest)) = parse_proc_container_path(&path_buf[..len]) else {
        return Ok(None);
    };
    let Some(ns_name) = rest.strip_prefix(b"ns/") else {
        return Ok(None);
    };
    let Some(kind) = NamespaceKind::from_proc_name(ns_name) else {
        return Ok(Some(SyscallReturn::error(Errno::ENOENT)));
    };
    let mut target = [0u8; 64];
    let n = with_step41_state(|state| state.namespaces.format_ns_link(kind, &mut target))?;
    let copy_len = n.min(bufsiz as usize);
    let res = if copy_len > 0 {
        copy_to_user(user_buf, &target[..copy_len]).map(|()| copy_len as i64)
    } else {
        Ok(0)
    };
    Ok(Some(encode_result(res)))
}

fn handle_openat_if_container(user_path: u64, flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 96];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let path = &path_buf[..len];
    let writable = (flags & O_ACCMODE) != O_RDONLY;

    let kind = if let Some((_, rest)) = parse_proc_container_path(path) {
        if rest == b"uid_map" {
            Some(ContainerFileKind::UidMap)
        } else if rest == b"gid_map" {
            Some(ContainerFileKind::GidMap)
        } else if rest == b"setgroups" {
            Some(ContainerFileKind::Setgroups)
        } else if let Some(ns_name) = rest.strip_prefix(b"ns/") {
            let Some(ns_kind) = NamespaceKind::from_proc_name(ns_name) else {
                return Ok(Some(SyscallReturn::error(Errno::ENOENT)));
            };
            let ns_fd = with_step41_state(|state| NamespaceFd {
                live: true,
                kind: ns_kind,
                target_ns_id: state.namespaces.id_of(ns_kind),
                owner_user_ns_id: state.namespaces.user_id,
            })?;
            Some(ContainerFileKind::Ns(ns_fd))
        } else {
            None
        }
    } else if writable && let Some(cg_rel) = path.strip_prefix(b"/sys/fs/cgroup/") {
        if cg_rel.len() > 48 {
            return Ok(Some(SyscallReturn::error(Errno::ENAMETOOLONG)));
        }
        let mut rel = [0u8; 48];
        rel[..cg_rel.len()].copy_from_slice(cg_rel);
        Some(ContainerFileKind::CgroupCtrl {
            rel,
            rel_len: cg_rel.len(),
            writable: true,
        })
    } else if let Some(ov_rel) = path.strip_prefix(b"/container/rootfs") {
        let norm = if ov_rel.is_empty() { b"/" } else { ov_rel };
        if norm.len() > 64 {
            return Ok(Some(SyscallReturn::error(Errno::ENAMETOOLONG)));
        }
        let mut p = [0u8; 64];
        p[..norm.len()].copy_from_slice(norm);
        Some(ContainerFileKind::OverlayFile {
            path: p,
            path_len: norm.len(),
            writable,
        })
    } else {
        None
    };

    let Some(file_kind) = kind else {
        return Ok(None);
    };

    let res = with_step41_state(|state| {
        let Some((idx, slot)) = state
            .fds
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.kind == ContainerFileKind::None)
        else {
            return Err(Errno::EMFILE);
        };
        *slot = ContainerFdSlot {
            kind: file_kind,
            offset: 0,
        };
        Ok(i64::from(CONTAINER_FD_BASE + (idx as i32)))
    })?;
    Ok(Some(encode_result(res)))
}

fn handle_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match container_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let (kind, offset) = with_step41_state(|state| (state.fds[idx].kind, state.fds[idx].offset))?;
    let mut data = [0u8; 256];
    let total = match kind {
        ContainerFileKind::None => return Ok(Err(Errno::EBADF)),
        ContainerFileKind::Ns(_) => 0,
        ContainerFileKind::UidMap => {
            match super::step35_events_cgroup::with_security_state(|sec| {
                sec.format_uid_map(&mut data)
            }) {
                Ok(n) => n,
                Err(()) => return Err(()),
            }
        }
        ContainerFileKind::GidMap => {
            match super::step35_events_cgroup::with_security_state(|sec| {
                sec.format_gid_map(&mut data)
            }) {
                Ok(n) => n,
                Err(()) => return Err(()),
            }
        }
        ContainerFileKind::Setgroups => {
            match super::step35_events_cgroup::with_security_state(|sec| {
                sec.format_setgroups(&mut data)
            }) {
                Ok(n) => n,
                Err(()) => return Err(()),
            }
        }
        ContainerFileKind::CgroupCtrl { rel, rel_len, .. } => {
            match super::step35_events_cgroup::read_cgroup_control_file(&rel[..rel_len], &mut data)
            {
                Ok(n) => n,
                Err(e) => return Ok(Err(e)),
            }
        }
        ContainerFileKind::OverlayFile { path, path_len, .. } => {
            match with_step41_state(|state| {
                let (_, content) = state
                    .overlay_upper
                    .read_file(&state.overlay_lower, &path[..path_len])?;
                let take = content.len().min(data.len());
                data[..take].copy_from_slice(&content[..take]);
                Ok(take)
            })? {
                Ok(n) => n,
                Err(e) => return Ok(Err(e)),
            }
        }
    };
    let avail = &data[offset.min(total)..total];
    let to_copy = avail.len().min(count as usize);
    if to_copy > 0 {
        if let Err(e) = copy_to_user(user_buf, &avail[..to_copy]) {
            return Ok(Err(e));
        }
        with_step41_state(|state| {
            state.fds[idx].offset += to_copy;
        })?;
    }
    Ok(Ok(to_copy as i64))
}

fn handle_write(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match container_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let write_len = (count as usize).min(128);
    let mut buf = [0u8; 128];
    if write_len > 0
        && let Err(e) = copy_from_user(&mut buf[..write_len], user_buf)
    {
        return Ok(Err(e));
    }
    let payload = &buf[..write_len];
    let kind = with_step41_state(|state| state.fds[idx].kind)?;
    let res = match kind {
        ContainerFileKind::None => Err(Errno::EBADF),
        ContainerFileKind::Ns(_) => Err(Errno::EINVAL),
        ContainerFileKind::UidMap => {
            super::step35_events_cgroup::with_security_state(|sec| sec.write_uid_map(payload))?
                .map(|()| write_len as i64)
        }
        ContainerFileKind::GidMap => {
            super::step35_events_cgroup::with_security_state(|sec| sec.write_gid_map(payload))?
                .map(|()| write_len as i64)
        }
        ContainerFileKind::Setgroups => {
            super::step35_events_cgroup::with_security_state(|sec| sec.write_setgroups(payload))?
                .map(|()| write_len as i64)
        }
        ContainerFileKind::CgroupCtrl { rel, rel_len, .. } => {
            super::step35_events_cgroup::write_cgroup_control_file(&rel[..rel_len], payload)
                .map(|()| write_len as i64)
        }
        ContainerFileKind::OverlayFile {
            path,
            path_len,
            writable,
        } => {
            if !writable {
                Err(Errno::EBADF)
            } else {
                with_step41_state(|state| {
                    state
                        .overlay_upper
                        .write_file(&path[..path_len], S_IFREG_MODE, payload)
                })?
                .map(|()| write_len as i64)
            }
        }
    };
    Ok(res)
}

fn handle_lseek(raw_fd: u64, offset: i64) -> Result<Result<i64, Errno>, ()> {
    let idx = match container_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    if offset < 0 {
        return Ok(Err(Errno::EINVAL));
    }
    with_step41_state(|state| {
        if state.fds[idx].kind == ContainerFileKind::None {
            return Err(Errno::EBADF);
        }
        state.fds[idx].offset = offset as usize;
        Ok(offset)
    })
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match container_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step41_state(|state| {
        if state.fds[idx].kind == ContainerFileKind::None {
            return Err(Errno::EBADF);
        }
        state.fds[idx] = ContainerFdSlot::EMPTY;
        Ok(0)
    })
}

fn handle_fstat(raw_fd: u64, user_stat: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match container_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let kind = with_step41_state(|state| state.fds[idx].kind)?;
    if kind == ContainerFileKind::None {
        return Ok(Err(Errno::EBADF));
    }
    let mut stat = [0u8; ARM64_STAT_BYTES];
    stat[16..20].copy_from_slice(&S_IFREG_MODE.to_le_bytes());
    stat[20..24].copy_from_slice(&1u32.to_le_bytes());
    stat[56..60].copy_from_slice(&4096i32.to_le_bytes());
    if let Err(e) = copy_to_user(user_stat, &stat) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn handle_unshare(flags: u64) -> Result<Result<i64, Errno>, ()> {
    let res = super::step35_events_cgroup::with_security_state(|sec| sec.unshare(flags))?;
    if res.is_ok() {
        with_step41_state(|state| {
            state.namespaces = state.namespaces.fork_namespaces(flags);
        })?;
        return Ok(Ok(0));
    }
    Ok(res.map(|()| 0))
}

fn handle_setns(raw_fd: u64, nstype: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match container_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let kind = with_step41_state(|state| state.fds[idx].kind)?;
    let ContainerFileKind::Ns(ns_fd) = kind else {
        return Ok(Err(Errno::EINVAL));
    };
    let mut ns_copy = with_step41_state(|state| state.namespaces)?;
    let sec_res = super::step35_events_cgroup::with_security_state(|sec| {
        apply_setns(sec, &mut ns_copy, ns_fd, nstype)
    })?;
    match sec_res {
        Ok(()) => {
            with_step41_state(|state| {
                state.namespaces = ns_copy;
            })?;
            Ok(Ok(0))
        }
        Err(e) => Ok(Err(e)),
    }
}

fn handle_seccomp(raw_op: u64, raw_flags: u64, user_args: u64) -> Result<Result<i64, Errno>, ()> {
    let op = linux_unsigned_int(raw_op);
    let flags = linux_unsigned_int(raw_flags);
    match op {
        SECCOMP_SET_MODE_STRICT => {
            if user_args != 0 {
                return Ok(Err(Errno::EINVAL));
            }
            super::step35_events_cgroup::with_security_state(|sec| {
                sec.seccomp_syscall(SECCOMP_SET_MODE_STRICT, flags, &[])
            })
        }
        SECCOMP_SET_MODE_FILTER => {
            if user_args == 0 {
                return Ok(Err(Errno::EFAULT));
            }
            // AArch64 `struct sock_fprog`: `{ u16 len; u8 pad[6]; u64 filter_ptr; }` (16 bytes).
            let mut fprog = [0u8; 16];
            if let Err(e) = copy_from_user(&mut fprog, user_args) {
                return Ok(Err(e));
            }
            let len = usize::from(u16::from_le_bytes([fprog[0], fprog[1]]));
            let filter_ptr = u64::from_le_bytes(fprog[8..16].try_into().unwrap());
            if len == 0 || len > MAX_SECCOMP_INSNS {
                return Ok(Err(Errno::EINVAL));
            }
            if filter_ptr == 0 {
                return Ok(Err(Errno::EFAULT));
            }
            let mut insns = [SeccompBpfInsn::ZERO; MAX_SECCOMP_INSNS];
            for (i, slot) in insns[..len].iter_mut().enumerate() {
                let mut raw_insn = [0u8; 8];
                let addr = match filter_ptr.checked_add((i * 8) as u64) {
                    Some(a) => a,
                    None => return Ok(Err(Errno::EFAULT)),
                };
                if let Err(e) = copy_from_user(&mut raw_insn, addr) {
                    return Ok(Err(e));
                }
                *slot = SeccompBpfInsn::from_le_bytes(raw_insn);
            }
            super::step35_events_cgroup::with_security_state(|sec| {
                sec.seccomp_syscall(SECCOMP_SET_MODE_FILTER, flags, &insns[..len])
            })
        }
        SECCOMP_GET_ACTION_AVAIL => {
            if user_args == 0 {
                return Ok(Err(Errno::EFAULT));
            }
            let mut raw = [0u8; 4];
            if let Err(e) = copy_from_user(&mut raw, user_args) {
                return Ok(Err(e));
            }
            let probe = [SeccompBpfInsn {
                code: 0,
                jt: 0,
                jf: 0,
                k: u32::from_le_bytes(raw),
            }];
            super::step35_events_cgroup::with_security_state(|sec| {
                sec.seccomp_syscall(SECCOMP_GET_ACTION_AVAIL, flags, &probe)
            })
        }
        SECCOMP_GET_NOTIF_SIZES => {
            if user_args == 0 {
                return Ok(Err(Errno::EFAULT));
            }
            // struct seccomp_notif_sizes { u16 seccomp_notif; u16 seccomp_notif_resp; u16 seccomp_data; }
            let sizes = [0u8; 6];
            if let Err(e) = copy_to_user(user_args, &sizes) {
                return Ok(Err(e));
            }
            Ok(Ok(0))
        }
        _ => Ok(Err(Errno::EINVAL)),
    }
}

fn read_user_cstr(user_ptr: u64, out: &mut [u8]) -> Result<usize, Errno> {
    if user_ptr == 0 {
        return Err(Errno::EFAULT);
    }
    for (idx, slot) in out.iter_mut().enumerate() {
        let addr = user_ptr.checked_add(idx as u64).ok_or(Errno::EFAULT)?;
        let mut byte = [0u8; 1];
        copy_from_user(&mut byte, addr)?;
        if byte[0] == 0 {
            return Ok(idx);
        }
        *slot = byte[0];
    }
    Err(Errno::ENAMETOOLONG)
}

fn map_usercopy_error(err: UsercopyError) -> Errno {
    match err {
        UsercopyError::NullGuard
        | UsercopyError::Overflow
        | UsercopyError::OutsideUserRange
        | UsercopyError::Fault => Errno::EFAULT,
        UsercopyError::TooLarge
        | UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => Errno::EINVAL,
    }
}

fn copy_from_user(dst: &mut [u8], user_src: u64) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_from_user(dst, user_src).map_err(map_usercopy_error)
}

fn copy_to_user(user_dst: u64, src: &[u8]) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_to_user(user_dst, src).map_err(map_usercopy_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_fd_window_is_disjoint() {
        assert!(!is_container_fd(208));
        assert!(!is_container_fd(223));
        assert!(is_container_fd(CONTAINER_FD_BASE as u64));
        assert!(is_container_fd((CONTAINER_FD_BASE + 15) as u64));
        assert!(!is_container_fd((CONTAINER_FD_BASE + 16) as u64));
    }
}
