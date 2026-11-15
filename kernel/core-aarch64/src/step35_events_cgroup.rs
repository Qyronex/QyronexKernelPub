// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_linux_abi::{
    Errno, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_cgroup::{
    CgroupTree, LINUX_CAPABILITY_VERSION_3, PR_GET_NAME, PR_GET_NO_NEW_PRIVS, PR_GET_PDEATHSIG,
    PR_SET_NAME, PR_SET_NO_NEW_PRIVS, ProcessSecurityState,
};
use kernal_linux_events::{
    CLOSE_RANGE_CLOEXEC, CLOSE_RANGE_UNSHARE, EPOLLIN, EPOLLOUT, EpollEvent, EventTable,
    F_ADD_SEALS, F_GET_SEALS,
};
use kernal_usercopy::Error as UsercopyError;

/// Dedicated file-descriptor base for Step-35 event/memfd/pidfd descriptors (`160..192`),
/// partitioned cleanly above `SOCK_FD_BASE` (`128..160`).
pub(super) const EVENT_FD_BASE: i32 = 160;
const MAX_EVENT_FDS: usize = 16;
const MEMFD_CAP: usize = 512;
const MAX_CGROUPS: usize = 8;
const ARM64_STAT_BYTES: usize = 128;
const S_IFREG_MODE: u32 = 0o100_600;

struct Step35State {
    events: EventTable<MAX_EVENT_FDS, MEMFD_CAP>,
    security: ProcessSecurityState,
    cgroups: CgroupTree<MAX_CGROUPS>,
}

impl Step35State {
    const fn new() -> Self {
        Self {
            events: EventTable::new(),
            security: ProcessSecurityState::new_root_init(),
            cgroups: CgroupTree::new(),
        }
    }
}

struct Step35Cell {
    state: AtomicU8,
    value: UnsafeCell<Step35State>,
}

// SAFETY: access is serialized by the atomic state transition (`0 -> 1 -> 0`) inside the IRQ-masked
// synchronous lower-EL trap window.
unsafe impl Sync for Step35Cell {}

static STEP35_STATE: Step35Cell = Step35Cell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step35State::new()),
};

fn with_step35_state<R>(f: impl FnOnce(&mut Step35State) -> R) -> Result<R, ()> {
    if STEP35_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state transition `0 -> 1` grants exclusive mutable access for this synchronous scope.
    let result = f(unsafe { &mut *STEP35_STATE.value.get() });
    STEP35_STATE.state.store(0, Ordering::Release);
    Ok(result)
}

/// Returns `true` if `raw_fd` lies in the Step-35 event descriptor window (`160..176`).
pub(super) const fn is_event_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= EVENT_FD_BASE && fd < EVENT_FD_BASE + (MAX_EVENT_FDS as i32)
}

/// Reads a cgroup v2 control file under `/sys/fs/cgroup/<rel>` (Step 36).
pub(super) fn read_cgroup_control_file(rel: &[u8], out: &mut [u8]) -> Result<usize, Errno> {
    with_step35_state(|state| state.cgroups.read_control_file(rel, out)).map_err(|()| Errno::EIO)?
}

/// Reports whether the current Step-36 security state retains effective capability `cap`.
pub(super) fn has_effective_capability(cap: u32) -> Result<bool, ()> {
    with_step35_state(|state| state.security.has_cap(cap))
}

/// Dispatches Step-35 event/notification/memfd/pidfd/close_range syscalls and Step-36
/// capability/namespace/prctl/security syscalls on AArch64.
pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        // eventfd2(initval, flags)
        19 => Ok(Some(encode_result(handle_eventfd2(
            request.args[0],
            request.args[1],
        )?))),
        // epoll_create1(flags)
        20 => Ok(Some(encode_result(handle_epoll_create1(request.args[0])?))),
        // epoll_ctl(epfd, op, fd, event)
        21 => Ok(Some(encode_result(handle_epoll_ctl(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        // epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)
        22 => Ok(Some(encode_result(handle_epoll_pwait(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // fcntl(fd, cmd, arg) for Step-35 memfd sealing
        25 if is_event_fd(request.args[0]) => Ok(Some(encode_result(handle_event_fcntl(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // inotify_init1(flags)
        26 => Ok(Some(encode_result(handle_inotify_init1(request.args[0])?))),
        // inotify_add_watch(fd, pathname, mask)
        27 => Ok(Some(encode_result(handle_inotify_add_watch(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // inotify_rm_watch(fd, wd)
        28 => Ok(Some(encode_result(handle_inotify_rm_watch(
            request.args[0],
            request.args[1],
        )?))),
        // ftruncate(fd, length) on memfd
        46 if is_event_fd(request.args[0]) => Ok(Some(encode_result(handle_memfd_truncate(
            request.args[0],
            request.args[1],
        )?))),
        // close(fd)
        57 if is_event_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        // lseek(fd, offset, whence)
        62 if is_event_fd(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            linux_signed_int(request.args[2]),
        )?))),
        // read(fd, buf, count)
        63 if is_event_fd(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // write(fd, buf, count)
        64 if is_event_fd(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // signalfd4(ufd, user_mask, sizemask, flags)
        74 => Ok(Some(encode_result(handle_signalfd4(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        // fstat(fd, statbuf)
        80 if is_event_fd(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        // timerfd_create(clockid, flags)
        85 => Ok(Some(encode_result(handle_timerfd_create(
            request.args[0],
            request.args[1],
        )?))),
        // timerfd_settime(ufd, flags, utmr,FB otmr)
        86 => Ok(Some(encode_result(handle_timerfd_settime(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        // timerfd_gettime(ufd, otmr)
        87 => Ok(Some(encode_result(handle_timerfd_gettime(
            request.args[0],
            request.args[1],
        )?))),
        // capget(hdrp, datap)
        90 => Ok(Some(encode_result(handle_capget(
            request.args[0],
            request.args[1],
        )?))),
        // capset(hdrp, datap)
        91 => Ok(Some(encode_result(handle_capset(
            request.args[0],
            request.args[1],
        )?))),
        // unshare(flags)
        97 => Ok(Some(encode_result(handle_unshare(request.args[0])?))),
        // prctl(option, arg2, arg3, arg4, arg5) — delegate PR_SET_NO_NEW_PRIVS/PR_GET_NO_NEW_PRIVS
        // to step30_runtime so existing Step-30 contracts remain untouched.
        167 => handle_prctl_if_step36(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // add_key(217), request_key(218), keyctl(219), seccomp(277), bpf(280):
        // Step 36 requires unsupported security/keyring/seccomp/BPF calls to fail explicitly.
        217..=219 | 277 | 280 => Ok(Some(SyscallReturn::error(Errno::ENOSYS))),
        // memfd_create(uname, flags)
        279 => Ok(Some(encode_result(handle_memfd_create(
            request.args[0],
            request.args[1],
        )?))),
        // pidfd_send_signal(pidfd, sig, info, flags)
        424 => Ok(Some(encode_result(handle_pidfd_send_signal(
            request.args[0],
            request.args[1],
            request.args[3],
        )?))),
        // pidfd_open(pid, flags)
        434 => Ok(Some(encode_result(handle_pidfd_open(
            request.args[0],
            request.args[1],
        )?))),
        // close_range(first, last, flags)
        436 => Ok(Some(encode_result(handle_close_range(
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

fn event_idx(raw_fd: u64) -> Result<usize, Errno> {
    if !is_event_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    Ok((linux_signed_int(raw_fd) - EVENT_FD_BASE) as usize)
}

fn handle_eventfd2(raw_initval: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let initval = linux_unsigned_int(raw_initval);
    let flags = linux_unsigned_int(raw_flags);
    with_step35_state(|state| {
        let idx = state.events.eventfd2(initval, flags)?;
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_epoll_create1(raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let flags = linux_unsigned_int(raw_flags);
    with_step35_state(|state| {
        let idx = state.events.epoll_create1(flags)?;
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_epoll_ctl(
    raw_epfd: u64,
    raw_op: u64,
    raw_fd: u64,
    user_event: u64,
) -> Result<Result<i64, Errno>, ()> {
    let ep_idx = match event_idx(raw_epfd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let op = linux_unsigned_int(raw_op);
    let target_fd = linux_signed_int(raw_fd);
    let ev = if user_event != 0 {
        let mut raw = [0u8; 16];
        if let Err(e) = copy_from_user(&mut raw, user_event) {
            return Ok(Err(e));
        }
        Some(EpollEvent::from_aarch64_bytes(raw))
    } else {
        None
    };
    with_step35_state(|state| {
        state
            .events
            .epoll_ctl(ep_idx, op, target_fd, ev)
            .map(|()| 0)
    })
}

fn handle_epoll_pwait(
    raw_epfd: u64,
    user_events: u64,
    raw_maxevents: u64,
) -> Result<Result<i64, Errno>, ()> {
    let ep_idx = match event_idx(raw_epfd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let maxevents = linux_signed_int(raw_maxevents);
    if maxevents <= 0 || user_events == 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let cap = (maxevents as usize).min(8);
    let mut ready = [EpollEvent { events: 0, data: 0 }; 8];
    let n = with_step35_state(|state| {
        state.events.epoll_wait(
            ep_idx,
            EVENT_FD_BASE,
            |fd| {
                if super::step34_net::socket_has_readable_data(fd as u64) {
                    EPOLLIN | EPOLLOUT
                } else {
                    EPOLLOUT
                }
            },
            &mut ready[..cap],
        )
    })?;
    let count = match n {
        Ok(c) => c,
        Err(e) => return Ok(Err(e)),
    };
    for (i, item) in ready.iter().enumerate().take(count) {
        let Some(dest) = user_events.checked_add((i * 16) as u64) else {
            return Ok(Err(Errno::EFAULT));
        };
        if let Err(e) = copy_to_user(dest, &item.to_aarch64_bytes()) {
            return Ok(Err(e));
        }
    }
    Ok(Ok(count as i64))
}

fn handle_event_fcntl(raw_fd: u64, raw_cmd: u64, raw_arg: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let cmd = linux_unsigned_int(raw_cmd);
    let arg = linux_unsigned_int(raw_arg);
    with_step35_state(|state| match cmd {
        F_ADD_SEALS => state.events.memfd_add_seals(idx, arg).map(|()| 0),
        F_GET_SEALS => state.events.memfd_get_seals(idx).map(i64::from),
        _ => Ok(0),
    })
}

fn handle_inotify_init1(raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let flags = linux_unsigned_int(raw_flags);
    with_step35_state(|state| {
        let idx = state.events.inotify_init1(flags)?;
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_inotify_add_watch(
    raw_fd: u64,
    user_path: u64,
    raw_mask: u64,
) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let mut path = [0u8; 64];
    let len = match read_user_cstr(user_path, &mut path) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    let mask = linux_unsigned_int(raw_mask);
    with_step35_state(|state| {
        state
            .events
            .inotify_add_watch(idx, &path[..len], mask)
            .map(i64::from)
    })
}

fn handle_inotify_rm_watch(raw_fd: u64, raw_wd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let wd = linux_signed_int(raw_wd);
    with_step35_state(|state| state.events.inotify_rm_watch(idx, wd).map(|()| 0))
}

fn handle_memfd_create(user_name: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let mut name = [0u8; 64];
    let len = match read_user_cstr(user_name, &mut name) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    let flags = linux_unsigned_int(raw_flags);
    with_step35_state(|state| {
        let idx = state.events.memfd_create(&name[..len], flags)?;
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_memfd_truncate(raw_fd: u64, raw_len: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let Ok(new_len) = usize::try_from(raw_len) else {
        return Ok(Err(Errno::EINVAL));
    };
    with_step35_state(|state| state.events.memfd_truncate(idx, new_len).map(|()| 0))
}

fn handle_signalfd4(
    raw_ufd: u64,
    user_mask: u64,
    sizemask: u64,
    raw_flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    if sizemask != 8 || user_mask == 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let mut mask_bytes = [0u8; 8];
    if let Err(e) = copy_from_user(&mut mask_bytes, user_mask) {
        return Ok(Err(e));
    }
    let mask = u64::from_le_bytes(mask_bytes);
    let ufd = linux_signed_int(raw_ufd);
    let existing = if ufd == -1 {
        None
    } else {
        match event_idx(raw_ufd) {
            Ok(i) => Some(i),
            Err(e) => return Ok(Err(e)),
        }
    };
    let flags = linux_unsigned_int(raw_flags);
    with_step35_state(|state| {
        let idx = state.events.signalfd4(existing, mask, flags)?;
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_timerfd_create(raw_clockid: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let clock_id = linux_unsigned_int(raw_clockid);
    let flags = linux_unsigned_int(raw_flags);
    with_step35_state(|state| {
        let idx = state.events.timerfd_create(clock_id, flags)?;
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_timerfd_settime(
    raw_ufd: u64,
    raw_flags: u64,
    user_new: u64,
    user_old: u64,
) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_ufd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    if user_new == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    // struct itimerspec (32 bytes): it_interval(tv_sec: i64, tv_nsec: i64), it_value(tv_sec: i64, tv_nsec: i64)
    let mut raw_spec = [0u8; 32];
    if let Err(e) = copy_from_user(&mut raw_spec, user_new) {
        return Ok(Err(e));
    }
    let int_sec = i64::from_le_bytes(raw_spec[0..8].try_into().unwrap());
    let int_nsec = i64::from_le_bytes(raw_spec[8..16].try_into().unwrap());
    let val_sec = i64::from_le_bytes(raw_spec[16..24].try_into().unwrap());
    let val_nsec = i64::from_le_bytes(raw_spec[24..32].try_into().unwrap());
    if int_sec < 0
        || !(0..1_000_000_000).contains(&int_nsec)
        || val_sec < 0
        || !(0..1_000_000_000).contains(&val_nsec)
    {
        return Ok(Err(Errno::EINVAL));
    }
    let new_int = (int_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(int_nsec as u64);
    let new_val = (val_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(val_nsec as u64);
    let flags = linux_unsigned_int(raw_flags);
    let old =
        with_step35_state(|state| state.events.timerfd_settime(idx, flags, new_int, new_val))?;
    let (old_int, old_val) = match old {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    if user_old != 0 {
        let encoded = encode_itimerspec(old_int, old_val);
        if let Err(e) = copy_to_user(user_old, &encoded) {
            return Ok(Err(e));
        }
    }
    Ok(Ok(0))
}

fn handle_timerfd_gettime(raw_ufd: u64, user_curr: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_ufd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    if user_curr == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let res = with_step35_state(|state| state.events.timerfd_gettime(idx))?;
    let (int_ns, val_ns) = match res {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let encoded = encode_itimerspec(int_ns, val_ns);
    if let Err(e) = copy_to_user(user_curr, &encoded) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn encode_itimerspec(int_ns: u64, val_ns: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&((int_ns / 1_000_000_000) as i64).to_le_bytes());
    out[8..16].copy_from_slice(&((int_ns % 1_000_000_000) as i64).to_le_bytes());
    out[16..24].copy_from_slice(&((val_ns / 1_000_000_000) as i64).to_le_bytes());
    out[24..32].copy_from_slice(&((val_ns % 1_000_000_000) as i64).to_le_bytes());
    out
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step35_state(|state| state.events.close(idx).map(|()| 0))
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step35_state(|state| state.events.lseek(idx, offset, whence))
}

fn handle_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let take = usize::try_from(count).unwrap_or(MEMFD_CAP).min(MEMFD_CAP);
    if take == 0 {
        return Ok(Ok(0));
    }
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut buf = [0u8; MEMFD_CAP];
    let res = with_step35_state(|state| state.events.read(idx, &mut buf[..take]))?;
    let n = match res {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    if n > 0 {
        if let Err(e) = copy_to_user(user_buf, &buf[..n]) {
            return Ok(Err(e));
        }
    }
    Ok(Ok(n as i64))
}

fn handle_write(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match event_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let take = usize::try_from(count).unwrap_or(MEMFD_CAP).min(MEMFD_CAP);
    if take == 0 {
        return Ok(Ok(0));
    }
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut buf = [0u8; MEMFD_CAP];
    if let Err(e) = copy_from_user(&mut buf[..take], user_buf) {
        return Ok(Err(e));
    }
    with_step35_state(|state| state.events.write(idx, &buf[..take]).map(|w| w as i64))
}

fn handle_fstat(raw_fd: u64, user_statbuf: u64) -> Result<Result<i64, Errno>, ()> {
    if !is_event_fd(raw_fd) {
        return Ok(Err(Errno::EBADF));
    }
    if user_statbuf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut stat = [0u8; ARM64_STAT_BYTES];
    stat[8..16].copy_from_slice(&2000u64.to_le_bytes()); // st_ino
    stat[16..20].copy_from_slice(&S_IFREG_MODE.to_le_bytes());
    stat[20..24].copy_from_slice(&1u32.to_le_bytes());
    stat[56..60].copy_from_slice(&4096i32.to_le_bytes());
    if let Err(e) = copy_to_user(user_statbuf, &stat) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn handle_pidfd_open(raw_pid: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let pid = linux_signed_int(raw_pid);
    if pid <= 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let flags = linux_unsigned_int(raw_flags);
    with_step35_state(|state| {
        let idx = state.events.pidfd_open(pid as u32, flags)?;
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_pidfd_send_signal(
    raw_pidfd: u64,
    raw_sig: u64,
    raw_flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    if raw_flags != 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let idx = match event_idx(raw_pidfd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let sig = linux_signed_int(raw_sig);
    if !(0..=64).contains(&sig) {
        return Ok(Err(Errno::EINVAL));
    }
    with_step35_state(|state| {
        let target_pid = state.events.pidfd_target(idx)?;
        if sig > 0 {
            state.events.notify_signal(sig as u32, target_pid, 0);
        }
        Ok(0)
    })
}

fn handle_close_range(
    raw_first: u64,
    raw_last: u64,
    raw_flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    let first = linux_unsigned_int(raw_first);
    let last = linux_unsigned_int(raw_last);
    let flags = linux_unsigned_int(raw_flags);
    if first > last || (flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC)) != 0 {
        return Ok(Err(Errno::EINVAL));
    }
    if (flags & CLOSE_RANGE_CLOEXEC) == 0 {
        with_step35_state(|state| {
            for idx in 0..MAX_EVENT_FDS {
                let fd = (EVENT_FD_BASE as u32) + (idx as u32);
                if fd >= first && fd <= last {
                    let _ = state.events.close(idx);
                }
            }
        })?;
    }
    Ok(Ok(0))
}

fn handle_capget(user_hdr: u64, user_data: u64) -> Result<Result<i64, Errno>, ()> {
    if user_hdr == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut hdr = [0u8; 8];
    if let Err(e) = copy_from_user(&mut hdr, user_hdr) {
        return Ok(Err(e));
    }
    let version = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let pid = i32::from_le_bytes(hdr[4..8].try_into().unwrap());
    if version != LINUX_CAPABILITY_VERSION_3 {
        let mut fixed = [0u8; 8];
        fixed[0..4].copy_from_slice(&LINUX_CAPABILITY_VERSION_3.to_le_bytes());
        fixed[4..8].copy_from_slice(&pid.to_le_bytes());
        let _ = copy_to_user(user_hdr, &fixed);
        return Ok(Err(Errno::EINVAL));
    }
    if pid < 0 {
        return Ok(Err(Errno::EINVAL));
    }
    if user_data != 0 {
        let data = with_step35_state(|state| state.security.encode_cap_data_v3())?;
        if let Err(e) = copy_to_user(user_data, &data) {
            return Ok(Err(e));
        }
    }
    Ok(Ok(0))
}

fn handle_capset(user_hdr: u64, user_data: u64) -> Result<Result<i64, Errno>, ()> {
    if user_hdr == 0 || user_data == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut hdr = [0u8; 8];
    if let Err(e) = copy_from_user(&mut hdr, user_hdr) {
        return Ok(Err(e));
    }
    let version = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let pid = i32::from_le_bytes(hdr[4..8].try_into().unwrap());
    if version != LINUX_CAPABILITY_VERSION_3 || pid < 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let mut data = [0u8; 24];
    if let Err(e) = copy_from_user(&mut data, user_data) {
        return Ok(Err(e));
    }
    with_step35_state(|state| state.security.apply_cap_data_v3(&data).map(|()| 0))
}

fn handle_unshare(raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    with_step35_state(|state| state.security.unshare(raw_flags).map(|()| 0))
}

fn handle_prctl_if_step36(
    raw_option: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let option = linux_unsigned_int(raw_option);
    // Keep PR_SET_NO_NEW_PRIVS / PR_GET_NO_NEW_PRIVS in step30_runtime for Step-30 proof fidelity.
    if option == PR_SET_NO_NEW_PRIVS || option == PR_GET_NO_NEW_PRIVS {
        return Ok(None);
    }
    if option == PR_SET_NAME {
        let mut name = [0u8; 16];
        if let Err(e) = copy_from_user(&mut name, arg2) {
            return Ok(Some(SyscallReturn::error(e)));
        }
        with_step35_state(|state| state.security.set_comm(&name))?;
        return Ok(Some(SyscallReturn::success(0).ok_or(())?));
    }
    if option == PR_GET_NAME {
        let comm = with_step35_state(|state| state.security.comm)?;
        if let Err(e) = copy_to_user(arg2, &comm) {
            return Ok(Some(SyscallReturn::error(e)));
        }
        return Ok(Some(SyscallReturn::success(0).ok_or(())?));
    }
    if option == PR_GET_PDEATHSIG {
        let sig = with_step35_state(|state| state.security.pdeathsig)?;
        if let Err(e) = copy_to_user(arg2, &sig.to_le_bytes()) {
            return Ok(Some(SyscallReturn::error(e)));
        }
        return Ok(Some(SyscallReturn::success(0).ok_or(())?));
    }
    let res = with_step35_state(|state| state.security.prctl(option, arg2, arg3, arg4, arg5))?;
    Ok(Some(encode_result(res)))
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
    kernal_usercopy_aarch64::copy_from_user(dst, user_src).map_err(|err| match err {
        UsercopyError::NullPointer
        | UsercopyError::AddressOverflow
        | UsercopyError::OutsideUserRange
        | UsercopyError::PageFault => Errno::EFAULT,
        UsercopyError::LengthExceedsMaximum | UsercopyError::PrivilegeAccessNotDisabled => {
            Errno::EINVAL
        }
    })
}

fn copy_to_user(user_dst: u64, src: &[u8]) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_to_user(user_dst, src).map_err(|err| match err {
        UsercopyError::NullPointer
        | UsercopyError::AddressOverflow
        | UsercopyError::OutsideUserRange
        | UsercopyError::PageFault => Errno::EFAULT,
        UsercopyError::LengthExceedsMaximum | UsercopyError::PrivilegeAccessNotDisabled => {
            Errno::EINVAL
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_fd_window_is_disjoint_from_earlier_subsystems() {
        assert!(!is_event_fd(0));
        assert!(!is_event_fd(64));
        assert!(!is_event_fd(96));
        assert!(!is_event_fd(128));
        assert!(is_event_fd(EVENT_FD_BASE as u64));
        assert!(is_event_fd((EVENT_FD_BASE + 15) as u64));
        assert!(!is_event_fd((EVENT_FD_BASE + 16) as u64));
    }

    #[test]
    fn unsupported_seccomp_bpf_and_keyctl_fail_explicitly_with_enosys() {
        for nr in [217u64, 218, 219, 277, 280] {
            let req = SyscallRequest::new(nr, [0; 6]);
            let ret = try_handle_syscall(req).unwrap().unwrap();
            assert_eq!(ret, SyscallReturn::error(Errno::ENOSYS));
        }
    }
}
