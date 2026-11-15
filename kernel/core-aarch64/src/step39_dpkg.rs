// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_linux_abi::{
    Errno, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_cgroup::CAP_CHOWN;
use kernal_linux_dpkg::{
    AdvisoryLockTable, F_GETLK, F_SETLK, F_SETLKW, PackageMetadataTable, PosixFlock, TargetKey,
    TimespecPair, XattrTable,
};

const CAP_FOWNER: u32 = 3;
const MAX_LOCKS: usize = 32;
const MAX_XATTRS: usize = 32;
const MAX_XATTR_VAL: usize = 128;
const MAX_META: usize = 32;
const MAX_PATH_BYTES: usize = 96;
const MAX_XATTR_NAME: usize = 64;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;

const NR_SETXATTR: u64 = 5;
const NR_LSETXATTR: u64 = 6;
const NR_FSETXATTR: u64 = 7;
const NR_GETXATTR: u64 = 8;
const NR_LGETXATTR: u64 = 9;
const NR_FGETXATTR: u64 = 10;
const NR_LISTXATTR: u64 = 11;
const NR_LLISTXATTR: u64 = 12;
const NR_FLISTXATTR: u64 = 13;
const NR_REMOVEXATTR: u64 = 14;
const NR_LREMOVEXATTR: u64 = 15;
const NR_FREMOVEXATTR: u64 = 16;
const NR_FCNTL: u64 = 25;
const NR_FLOCK: u64 = 32;
const NR_FCHMOD: u64 = 52;
const NR_FCHMODAT: u64 = 53;
const NR_FCHOWNAT: u64 = 54;
const NR_FCHOWN: u64 = 55;
const NR_UTIMENSAT: u64 = 88;

struct Step39State {
    locks: AdvisoryLockTable<MAX_LOCKS>,
    xattrs: XattrTable<MAX_XATTRS, MAX_XATTR_VAL>,
    meta: PackageMetadataTable<MAX_META>,
}

impl Step39State {
    const fn new() -> Self {
        Self {
            locks: AdvisoryLockTable::new(),
            xattrs: XattrTable::new(),
            meta: PackageMetadataTable::new(),
        }
    }
}

struct Step39Cell {
    state: AtomicU8,
    value: UnsafeCell<Step39State>,
}

// SAFETY: access is serialized by the atomic state transition (`0 -> 1 -> 0`) inside the IRQ-masked
// synchronous lower-EL trap window.
unsafe impl Sync for Step39Cell {}

static STEP39_STATE: Step39Cell = Step39Cell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step39State::new()),
};

fn with_step39_state<R>(f: impl FnOnce(&mut Step39State) -> R) -> Result<R, ()> {
    if STEP39_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state transition `0 -> 1` grants exclusive mutable access for this synchronous scope.
    let result = f(unsafe { &mut *STEP39_STATE.value.get() });
    STEP39_STATE.state.store(0, Ordering::Release);
    Ok(result)
}

/// Dispatches Step-39 (`flock`, `fcntl` record locks, `xattr`, `fchmod`/`fchown`/`utimensat`)
/// syscalls on AArch64.
pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        NR_SETXATTR | NR_LSETXATTR => Ok(Some(encode_result(handle_setxattr(
            TargetSource::Path(request.args[0]),
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        )?))),
        NR_FSETXATTR => Ok(Some(encode_result(handle_setxattr(
            TargetSource::Fd(request.args[0]),
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        )?))),
        NR_GETXATTR | NR_LGETXATTR => Ok(Some(encode_result(handle_getxattr(
            TargetSource::Path(request.args[0]),
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        NR_FGETXATTR => Ok(Some(encode_result(handle_getxattr(
            TargetSource::Fd(request.args[0]),
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        NR_LISTXATTR | NR_LLISTXATTR => Ok(Some(encode_result(handle_listxattr(
            TargetSource::Path(request.args[0]),
            request.args[1],
            request.args[2],
        )?))),
        NR_FLISTXATTR => Ok(Some(encode_result(handle_listxattr(
            TargetSource::Fd(request.args[0]),
            request.args[1],
            request.args[2],
        )?))),
        NR_REMOVEXATTR | NR_LREMOVEXATTR => Ok(Some(encode_result(handle_removexattr(
            TargetSource::Path(request.args[0]),
            request.args[1],
        )?))),
        NR_FREMOVEXATTR => Ok(Some(encode_result(handle_removexattr(
            TargetSource::Fd(request.args[0]),
            request.args[1],
        )?))),
        NR_FCNTL => {
            let cmd = linux_unsigned_int(request.args[1]);
            if matches!(cmd, F_GETLK | F_SETLK | F_SETLKW) {
                Ok(Some(encode_result(handle_fcntl_lock(
                    request.args[0],
                    cmd,
                    request.args[2],
                )?)))
            } else {
                Ok(None)
            }
        }
        NR_FLOCK => Ok(Some(encode_result(handle_flock(
            request.args[0],
            request.args[1],
        )?))),
        NR_FCHMOD => Ok(Some(encode_result(handle_chmod(
            TargetSource::Fd(request.args[0]),
            request.args[1],
            0,
        )?))),
        NR_FCHMODAT => Ok(Some(encode_result(handle_chmod(
            TargetSource::At(request.args[0], request.args[1]),
            request.args[2],
            request.args[3],
        )?))),
        NR_FCHOWNAT => Ok(Some(encode_result(handle_chown(
            TargetSource::At(request.args[0], request.args[1]),
            request.args[2],
            request.args[3],
            request.args[4],
        )?))),
        NR_FCHOWN => Ok(Some(encode_result(handle_chown(
            TargetSource::Fd(request.args[0]),
            request.args[1],
            request.args[2],
            0,
        )?))),
        NR_UTIMENSAT => Ok(Some(encode_result(handle_utimensat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        _ => Ok(None),
    }
}

#[derive(Clone, Copy)]
enum TargetSource {
    Path(u64),
    Fd(u64),
    At(u64, u64),
}

fn resolve_target(src: TargetSource, flags: u64) -> Result<TargetKey, Errno> {
    match src {
        TargetSource::Path(user_path) => {
            let mut buf = [0u8; MAX_PATH_BYTES];
            let len = read_user_cstr(user_path, &mut buf)?;
            TargetKey::from_path(&buf[..len])
        }
        TargetSource::Fd(raw_fd) => TargetKey::from_fd(linux_signed_int(raw_fd)),
        TargetSource::At(raw_dirfd, user_path) => {
            if user_path == 0 {
                if (flags & AT_EMPTY_PATH) != 0 || flags == 0 {
                    return TargetKey::from_fd(linux_signed_int(raw_dirfd));
                }
                return Err(Errno::EFAULT);
            }
            let mut buf = [0u8; MAX_PATH_BYTES];
            let len = read_user_cstr(user_path, &mut buf)?;
            TargetKey::from_path(&buf[..len])
        }
    }
}

fn encode_result(res: Result<i64, Errno>) -> SyscallReturn {
    match res {
        Ok(val) => SyscallReturn::success(val).unwrap_or(SyscallReturn::error(Errno::EINVAL)),
        Err(errno) => SyscallReturn::error(errno),
    }
}

fn handle_flock(raw_fd: u64, raw_op: u64) -> Result<Result<i64, Errno>, ()> {
    let fd = linux_signed_int(raw_fd);
    let key = match TargetKey::from_fd(fd) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    let op = linux_unsigned_int(raw_op);
    let owner_ofd = u64::from(current_pid()).wrapping_shl(32) | (u64::from(fd as u32));
    with_step39_state(|state| state.locks.flock_op(key, owner_ofd, op).map(|()| 0))
}

fn handle_fcntl_lock(raw_fd: u64, cmd: u32, user_flock: u64) -> Result<Result<i64, Errno>, ()> {
    let key = match TargetKey::from_fd(linux_signed_int(raw_fd)) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    if user_flock == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut raw = [0u8; 32];
    if let Err(e) = copy_from_user(&mut raw, user_flock) {
        return Ok(Err(e));
    }
    let req = match PosixFlock::from_aarch64_bytes(raw) {
        Ok(r) => r,
        Err(e) => return Ok(Err(e)),
    };
    let pid = current_pid();
    if cmd == F_GETLK {
        let res = with_step39_state(|state| state.locks.fcntl_getlk(key, pid, req, 0, 0))?;
        let out = match res {
            Ok(f) => f,
            Err(e) => return Ok(Err(e)),
        };
        if let Err(e) = copy_to_user(user_flock, &out.to_aarch64_bytes()) {
            return Ok(Err(e));
        }
        return Ok(Ok(0));
    }
    with_step39_state(|state| state.locks.fcntl_setlk(key, pid, req, 0, 0).map(|()| 0))
}

fn handle_setxattr(
    src: TargetSource,
    user_name: u64,
    user_val: u64,
    raw_size: u64,
    raw_flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    let key = match resolve_target(src, 0) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    let mut name = [0u8; MAX_XATTR_NAME];
    let name_len = match read_user_cstr(user_name, &mut name) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    let Ok(size) = usize::try_from(raw_size) else {
        return Ok(Err(Errno::ENOSPC));
    };
    if size > MAX_XATTR_VAL {
        return Ok(Err(Errno::ENOSPC));
    }
    let mut val = [0u8; MAX_XATTR_VAL];
    if size > 0 {
        if user_val == 0 {
            return Ok(Err(Errno::EFAULT));
        }
        if let Err(e) = copy_from_user(&mut val[..size], user_val) {
            return Ok(Err(e));
        }
    }
    let flags = linux_unsigned_int(raw_flags);
    with_step39_state(|state| {
        state
            .xattrs
            .set(key, &name[..name_len], &val[..size], flags)
            .map(|()| 0)
    })
}

fn handle_getxattr(
    src: TargetSource,
    user_name: u64,
    user_out: u64,
    raw_size: u64,
) -> Result<Result<i64, Errno>, ()> {
    let key = match resolve_target(src, 0) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    let mut name = [0u8; MAX_XATTR_NAME];
    let name_len = match read_user_cstr(user_name, &mut name) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    let caller_cap = usize::try_from(raw_size).unwrap_or(MAX_XATTR_VAL);
    let mut buf = [0u8; MAX_XATTR_VAL];
    let res = with_step39_state(|state| {
        if raw_size == 0 {
            state.xattrs.get(key, &name[..name_len], None)
        } else {
            let take = caller_cap.min(MAX_XATTR_VAL);
            state
                .xattrs
                .get(key, &name[..name_len], Some(&mut buf[..take]))
        }
    })?;
    let n = match res {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    if raw_size > 0 && n > 0 {
        if user_out == 0 {
            return Ok(Err(Errno::EFAULT));
        }
        if let Err(e) = copy_to_user(user_out, &buf[..n]) {
            return Ok(Err(e));
        }
    }
    Ok(Ok(n as i64))
}

fn handle_listxattr(
    src: TargetSource,
    user_list: u64,
    raw_size: u64,
) -> Result<Result<i64, Errno>, ()> {
    let key = match resolve_target(src, 0) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    let mut buf = [0u8; 512];
    let res = with_step39_state(|state| {
        if raw_size == 0 {
            state.xattrs.list(key, None)
        } else {
            let cap = usize::try_from(raw_size)
                .unwrap_or(buf.len())
                .min(buf.len());
            state.xattrs.list(key, Some(&mut buf[..cap]))
        }
    })?;
    let n = match res {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    if raw_size > 0 && n > 0 {
        if user_list == 0 {
            return Ok(Err(Errno::EFAULT));
        }
        if let Err(e) = copy_to_user(user_list, &buf[..n]) {
            return Ok(Err(e));
        }
    }
    Ok(Ok(n as i64))
}

fn handle_removexattr(src: TargetSource, user_name: u64) -> Result<Result<i64, Errno>, ()> {
    let key = match resolve_target(src, 0) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    let mut name = [0u8; MAX_XATTR_NAME];
    let name_len = match read_user_cstr(user_name, &mut name) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    with_step39_state(|state| state.xattrs.remove(key, &name[..name_len]).map(|()| 0))
}

fn handle_chmod(
    src: TargetSource,
    raw_mode: u64,
    raw_flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    if (raw_flags & !AT_SYMLINK_NOFOLLOW) != 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let key = match resolve_target(src, raw_flags) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    let mode = linux_unsigned_int(raw_mode);
    let euid = current_euid();
    let cap_fowner = super::step35_events_cgroup::has_effective_capability(CAP_FOWNER)?;
    with_step39_state(|state| state.meta.chmod(key, mode, euid, cap_fowner).map(|()| 0))
}

fn handle_chown(
    src: TargetSource,
    raw_uid: u64,
    raw_gid: u64,
    raw_flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    if (raw_flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let key = match resolve_target(src, raw_flags) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    let uid = linux_unsigned_int(raw_uid);
    let gid = linux_unsigned_int(raw_gid);
    let euid = current_euid();
    let cap_chown = super::step35_events_cgroup::has_effective_capability(CAP_CHOWN)?;
    with_step39_state(|state| state.meta.chown(key, uid, gid, euid, cap_chown).map(|()| 0))
}

fn handle_utimensat(
    raw_dirfd: u64,
    user_path: u64,
    user_times: u64,
    raw_flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    if (raw_flags & !AT_SYMLINK_NOFOLLOW) != 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let key = match resolve_target(TargetSource::At(raw_dirfd, user_path), raw_flags) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    let times = if user_times == 0 {
        None
    } else {
        let mut raw = [0u8; 32];
        if let Err(e) = copy_from_user(&mut raw, user_times) {
            return Ok(Err(e));
        }
        match TimespecPair::from_aarch64_bytes(raw) {
            Ok(pair) => Some(pair),
            Err(e) => return Ok(Err(e)),
        }
    };
    let euid = current_euid();
    let cap_fowner = super::step35_events_cgroup::has_effective_capability(CAP_FOWNER)?;
    with_step39_state(|state| {
        state
            .meta
            .utimens(key, times, 1_700_000_000, euid, cap_fowner)
            .map(|()| 0)
    })
}

fn current_pid() -> u32 {
    let mut pid = 1u32;
    let current_cpu = super::super::current_cpu_index();
    if let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) {
        // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
        if let Ok(current) = unsafe { scheduler.bootstrap_current_global_thread() } {
            let _ = super::runtime::with_linux_runtime(|state| {
                let _ = state.with_current_process_identity(current, |proc_ref, identities| {
                    if let Ok(p) = identities.bound_pid(proc_ref) {
                        pid = p.get();
                    }
                });
            });
        }
    }
    pid
}

fn current_euid() -> u32 {
    let mut uid = 0u32;
    let current_cpu = super::super::current_cpu_index();
    if let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) {
        // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
        if let Ok(current) = unsafe { scheduler.bootstrap_current_global_thread() } {
            let _ = super::runtime::with_linux_runtime(|state| {
                let _ = state.with_current_process_credentials(current, |proc_ref, credentials| {
                    if let Ok(creds) = credentials.credentials(proc_ref) {
                        uid = creds.euid();
                    }
                });
            });
        }
    }
    uid
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

fn copy_from_user(dst: &mut [u8], user_src: u64) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_from_user(dst, user_src).map_err(super::map_usercopy_errno)
}

fn copy_to_user(user_dst: u64, src: &[u8]) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_to_user(user_dst, src).map_err(super::map_usercopy_errno)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fcntl_lock_cmd_filter_preserves_non_lock_commands() {
        assert!(matches!(F_GETLK, 5 | 6 | 7));
        assert!(matches!(F_SETLK, 5 | 6 | 7));
        assert!(matches!(F_SETLKW, 5 | 6 | 7));
        let non_lock = SyscallRequest::new(NR_FCNTL, [0, 1, 0, 0, 0, 0]);
        assert_eq!(try_handle_syscall(non_lock).unwrap(), None);
    }
}
