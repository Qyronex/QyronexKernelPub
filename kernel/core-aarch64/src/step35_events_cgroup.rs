// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use alloc::vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::ObjectId;
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_abi::{
    Errno, POLLERR, POLLFD_BYTES, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI, POLLRDHUP,
    SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_bootstrap::time::{LINUX_TIMESPEC64_BYTES, LinuxTimespec64};
use kernal_linux_cgroup::{
    CgroupTree, LINUX_CAPABILITY_VERSION_3, PR_GET_NAME, PR_GET_NO_NEW_PRIVS, PR_GET_PDEATHSIG,
    PR_SET_NAME, PR_SET_NO_NEW_PRIVS, ProcessSecurityState,
};
use kernal_linux_events::{
    CLOSE_RANGE_CLOEXEC, CLOSE_RANGE_UNSHARE, EpollEvent, EventTable, F_ADD_SEALS, F_GET_SEALS,
};
use kernal_linux_fd::{ExternalObject, OpenObjectKind, SubsystemHandle};
use kernal_linux_pipe::End as PipeEnd;
use kernal_linux_signal::SignalSet;

use super::step_fd_util::{
    DirectProcessRefs, SUBSYS_EVENT, current_process_object, fd_in_close_range,
    lookup_aliased_subsystem, lookup_aliased_subsystem_current,
};

/// Dedicated file-descriptor base for Step-35 event/memfd/pidfd descriptors (`672..736`),
/// partitioned cleanly above `PROC_SYS_FD_BASE` (`416..672`).
pub(super) const EVENT_FD_BASE: i32 = 672;
const MAX_EVENT_FDS: usize = 64;
const MEMFD_CAP: usize = 32768;
const MAX_CGROUPS: usize = 64;
const ARM64_STAT_BYTES: usize = 128;
const S_IFREG_MODE: u32 = 0o100_600;
const EVENT_CLOEXEC_FLAG: u32 = 0x0008_0000;
const EVENT_NONBLOCK_FLAG: u32 = 0x0000_0800;
const MFD_CLOEXEC_FLAG: u32 = 0x0001;
const MFD_NOEXEC_SEAL_FLAG: u32 = 0x0008;
const O_RDWR_U64: u64 = 2;

#[derive(Clone, Copy)]
struct EventMeta {
    live: bool,
    generation: u64,
    owners: DirectProcessRefs<{ super::step29_runtime::STEP29_RUNTIME_PROCESS_VIEWS }>,
    alias_refs: usize,
    nonblocking: bool,
}

impl EventMeta {
    const EMPTY: Self = Self {
        live: false,
        generation: 0,
        owners: DirectProcessRefs::empty(),
        alias_refs: 0,
        nonblocking: false,
    };
}

const MAX_SECURITY_PROCS: usize = 64;
const PRIO_PROCESS: i32 = 0;
const PRIO_PGRP: i32 = 1;
const PRIO_USER: i32 = 2;
const PRIORITY_OFFSET: i64 = 20;

#[derive(Clone, Copy)]
struct SecurityProcSlot {
    live: bool,
    process: ObjectId,
    sec: ProcessSecurityState,
    nice: i8,
}

impl SecurityProcSlot {
    const EMPTY: Self = Self {
        live: false,
        process: ObjectId(0),
        sec: ProcessSecurityState::new_root_init(),
        nice: 0,
    };
}

struct Step35State {
    next_generation: u64,
    events: EventTable<MAX_EVENT_FDS, MEMFD_CAP>,
    meta: [EventMeta; MAX_EVENT_FDS],
    default_security: ProcessSecurityState,
    security_slots: [SecurityProcSlot; MAX_SECURITY_PROCS],
    cgroups: CgroupTree<MAX_CGROUPS>,
}

impl Step35State {
    const fn new() -> Self {
        Self {
            next_generation: 1,
            events: EventTable::new(),
            meta: [EventMeta::EMPTY; MAX_EVENT_FDS],
            default_security: ProcessSecurityState::new_root_init(),
            security_slots: [SecurityProcSlot::EMPTY; MAX_SECURITY_PROCS],
            cgroups: CgroupTree::new(),
        }
    }

    fn security_for(&self, process: ObjectId) -> &ProcessSecurityState {
        self.security_slots
            .iter()
            .find(|s| s.live && s.process == process)
            .map_or(&self.default_security, |s| &s.sec)
    }

    fn security_for_mut(&mut self, process: ObjectId) -> &mut ProcessSecurityState {
        if let Some(pos) = self
            .security_slots
            .iter()
            .position(|s| s.live && s.process == process)
        {
            return &mut self.security_slots[pos].sec;
        }
        if let Some(pos) = self.security_slots.iter().position(|s| !s.live) {
            self.security_slots[pos] = SecurityProcSlot {
                live: true,
                process,
                sec: self.default_security,
                nice: 0,
            };
            return &mut self.security_slots[pos].sec;
        }
        &mut self.default_security
    }

    fn nice_for(&self, process: ObjectId) -> i8 {
        self.security_slots
            .iter()
            .find(|s| s.live && s.process == process)
            .map_or(0, |s| s.nice)
    }

    fn set_nice_for(&mut self, process: ObjectId, nice: i8) {
        if let Some(slot) = self
            .security_slots
            .iter_mut()
            .find(|s| s.live && s.process == process)
        {
            slot.nice = nice;
            return;
        }
        if let Some(pos) = self.security_slots.iter().position(|s| !s.live) {
            self.security_slots[pos] = SecurityProcSlot {
                live: true,
                process,
                sec: self.default_security,
                nice,
            };
        }
    }

    fn init_slot(&mut self, idx: usize, owner: ObjectId, cloexec: bool, nonblocking: bool) {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        let mut owners = DirectProcessRefs::empty();
        owners.init(owner, cloexec);
        self.meta[idx] = EventMeta {
            live: true,
            generation,
            owners,
            alias_refs: 0,
            nonblocking,
        };
    }

    fn check_slot(
        &self,
        process: ObjectId,
        idx: usize,
        alias_gen: Option<u64>,
    ) -> Result<(), Errno> {
        let Some(m) = self.meta.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !m.live {
            return Err(Errno::EBADF);
        }
        match alias_gen {
            Some(expected_gen) if m.generation == expected_gen && m.alias_refs > 0 => Ok(()),
            Some(_) => Err(Errno::EBADF),
            None if m.owners.has_owner(process) => Ok(()),
            None => Err(Errno::EBADF),
        }
    }

    fn retire_if_unused(&mut self, idx: usize) {
        if let Some(m) = self.meta.get_mut(idx)
            && m.live
            && m.owners.is_empty()
            && m.alias_refs == 0
        {
            let _ = self.events.close(idx);
            *m = EventMeta::EMPTY;
        }
    }

    fn close_native_slot(&mut self, process: ObjectId, idx: usize) -> Result<(), Errno> {
        let Some(m) = self.meta.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !m.live || !m.owners.close_owner(process) {
            return Err(Errno::EBADF);
        }
        self.retire_if_unused(idx);
        Ok(())
    }
}

fn slot_process_id() -> ObjectId {
    current_process_object().unwrap_or(ObjectId(1))
}

fn event_status_flags(nonblocking: bool) -> u64 {
    if nonblocking {
        O_RDWR_U64 | u64::from(EVENT_NONBLOCK_FLAG)
    } else {
        O_RDWR_U64
    }
}

fn is_aliased_event_fd(raw_fd: u64) -> bool {
    lookup_aliased_subsystem_current(raw_fd).is_some_and(|h| h.kind == SUBSYS_EVENT)
}

fn resolve_event_target_for_process(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(usize, Option<u64>), Errno> {
    if is_event_fd(raw_fd) {
        return Ok(((linux_signed_int(raw_fd) - EVENT_FD_BASE) as usize, None));
    }
    if let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
        && handle.kind == SUBSYS_EVENT
    {
        return Ok((handle.slot as usize, Some(handle.generation)));
    }
    Err(Errno::EBADF)
}

fn resolve_event_target(raw_fd: u64) -> Result<(usize, Option<u64>), Errno> {
    resolve_event_target_for_process(slot_process_id(), raw_fd)
}

fn retain_event_slot(
    idx: usize,
    owner: Option<ObjectId>,
    expected_gen: Option<u64>,
) -> Result<(SubsystemHandle, u64), Errno> {
    with_step35_state(|state| {
        let Some(m) = state.meta.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        let valid = m.live
            && owner.map_or(true, |p| m.owners.has_owner(p))
            && expected_gen.map_or(true, |g| m.generation == g);
        if !valid {
            return Err(Errno::EBADF);
        }
        m.alias_refs += 1;
        Ok((
            SubsystemHandle {
                kind: SUBSYS_EVENT,
                slot: idx as u16,
                generation: m.generation,
            },
            event_status_flags(m.nonblocking),
        ))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn retain_alias_handle(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(SubsystemHandle, u64), Errno> {
    if !is_event_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let idx = (linux_signed_int(raw_fd) - EVENT_FD_BASE) as usize;
    retain_event_slot(idx, Some(process), None)
}

pub(super) fn retain_existing_handle(
    handle: SubsystemHandle,
) -> Result<(SubsystemHandle, u64), Errno> {
    if handle.kind != SUBSYS_EVENT {
        return Err(Errno::EBADF);
    }
    retain_event_slot(handle.slot as usize, None, Some(handle.generation))
}

pub(super) fn release_alias_handle(handle: SubsystemHandle) {
    if handle.kind != SUBSYS_EVENT {
        return;
    }
    let idx = handle.slot as usize;
    let _ = with_step35_state(|state| {
        let Some(m) = state.meta.get_mut(idx) else {
            return;
        };
        if m.live && m.generation == handle.generation && m.alias_refs > 0 {
            m.alias_refs -= 1;
            state.retire_if_unused(idx);
        }
    });
}

pub(super) fn handle_native_fcntl(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    if cmd == F_ADD_SEALS || cmd == F_GET_SEALS {
        return None;
    }
    let (idx, alias_gen) = if is_event_fd(raw_fd) {
        ((linux_signed_int(raw_fd) - EVENT_FD_BASE) as usize, None)
    } else if let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
        && handle.kind == SUBSYS_EVENT
        && matches!(cmd, 3 | 4)
    {
        (handle.slot as usize, Some(handle.generation))
    } else {
        return None;
    };
    let res = with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        let Some(m) = state.meta.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        match cmd {
            1 => Ok(i64::from(i32::from(
                m.owners.get_cloexec(process).unwrap_or(false),
            ))),
            2 => {
                let _ = m.owners.set_cloexec(process, (argi & 1) != 0);
                Ok(0)
            }
            3 => Ok(event_status_flags(m.nonblocking) as i64),
            4 => {
                m.nonblocking = ((argi as u32) & EVENT_NONBLOCK_FLAG) != 0;
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    });
    Some(match res {
        Ok(inner) => inner,
        Err(()) => Err(Errno::EIO),
    })
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

pub(super) fn is_open_event_fd(process: ObjectId, raw_fd: u64) -> bool {
    if !is_event_fd(raw_fd) {
        return false;
    }
    let idx = (linux_signed_int(raw_fd) - EVENT_FD_BASE) as usize;
    with_step35_state(|state| {
        state
            .meta
            .get(idx)
            .is_some_and(|m| m.live && m.owners.has_owner(process))
    })
    .unwrap_or(false)
}

pub(super) fn append_open_event_fds(process: ObjectId, out: &mut alloc::vec::Vec<i32>) {
    let _ = with_step35_state(|state| {
        for (idx, m) in state.meta.iter().enumerate() {
            if m.live && m.owners.has_owner(process) {
                out.push(EVENT_FD_BASE + (idx as i32));
            }
        }
    });
}

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    let _ = with_step35_state(|state| {
        for m in &mut state.meta {
            if m.live {
                m.owners.on_fork(parent, child);
            }
        }
        let parent_sec = *state.security_for(parent);
        if parent_sec != state.default_security {
            *state.security_for_mut(child) = parent_sec;
        }
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    let _ = with_step35_state(|state| {
        for idx in 0..MAX_EVENT_FDS {
            if state.meta[idx].live {
                state.meta[idx].owners.close_cloexec_for(process);
                state.retire_if_unused(idx);
            }
        }
        if let Some(slot) = state
            .security_slots
            .iter_mut()
            .find(|s| s.live && s.process == process)
        {
            slot.sec.pdeathsig = 0;
        }
    });
}

pub(super) fn on_process_exit(process: ObjectId) {
    let _ = with_step35_state(|state| {
        for idx in 0..MAX_EVENT_FDS {
            if state.meta[idx].live {
                let _ = state.meta[idx].owners.close_owner(process);
                state.retire_if_unused(idx);
            }
        }
        for slot in &mut state.security_slots {
            if slot.live && slot.process == process {
                *slot = SecurityProcSlot::EMPTY;
            }
        }
    });
}

pub(super) fn on_child_process_exited(parent_process: ObjectId, child_pid: u32, child_uid: u32) {
    let _ = with_step35_state(|state| {
        for idx in 0..MAX_EVENT_FDS {
            if !state.meta[idx].live {
                continue;
            }
            if state.events.pidfd_target(idx) == Ok(child_pid) {
                state.events.mark_slot_pidfd_exited(idx);
            }
            if state.meta[idx].owners.has_owner(parent_process) {
                state
                    .events
                    .notify_signal_slot(idx, 17, child_pid, child_uid);
            }
        }
    });
}

pub(super) fn pidfd_target_for_process_fd(process: ObjectId, raw_fd: i32) -> Option<u32> {
    if raw_fd < 0 {
        return None;
    }
    let (idx, alias_gen) = resolve_event_target_for_process(process, raw_fd as u64).ok()?;
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen).ok()?;
        state.events.pidfd_target(idx).ok()
    })
    .ok()
    .flatten()
}

pub(super) fn pidfd_target_for_current(raw_fd: u64) -> Result<u32, Errno> {
    let process = slot_process_id();
    let (idx, alias_gen) = resolve_event_target_for_process(process, raw_fd)?;
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        state.events.pidfd_target(idx)
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn close_range_for_process(
    process: ObjectId,
    first: u32,
    last: u32,
    cloexec_only: bool,
) {
    let _ = with_step35_state(|state| {
        for idx in 0..MAX_EVENT_FDS {
            let fd = EVENT_FD_BASE + (idx as i32);
            if fd_in_close_range(fd, first, last)
                && state.meta[idx].live
                && state.meta[idx]
                    .owners
                    .apply_close_range(process, cloexec_only)
            {
                state.retire_if_unused(idx);
            }
        }
    });
}

/// Reads a cgroup v2 control file under `/sys/fs/cgroup/<rel>` (Step 36/41).
pub(super) fn read_cgroup_control_file(rel: &[u8], out: &mut [u8]) -> Result<usize, Errno> {
    with_step35_state(|state| state.cgroups.read_control_file(rel, out)).map_err(|()| Errno::EIO)?
}

/// Writes a cgroup v2 control file under `/sys/fs/cgroup/<rel>` (Step 41).
pub(super) fn write_cgroup_control_file(rel: &[u8], val: &[u8]) -> Result<(), Errno> {
    with_step35_state(|state| state.cgroups.write_control_file(rel, val))
        .map_err(|()| Errno::EIO)?
}

/// Creates a cgroup v2 subdirectory `/sys/fs/cgroup/<rel>` with POSIX parent checks.
pub(super) fn cgroup_mkdir_strict(rel: &[u8]) -> Result<(), Errno> {
    with_step35_state(|state| state.cgroups.mkdir_strict(rel))
        .map_err(|()| Errno::EIO)?
        .map(|_| ())
}

/// Removes an empty cgroup v2 subdirectory `/sys/fs/cgroup/<rel>`.
pub(super) fn cgroup_rmdir(rel: &[u8]) -> Result<(), Errno> {
    with_step35_state(|state| state.cgroups.rmdir(rel)).map_err(|()| Errno::EIO)?
}

/// Returns `true` if `/sys/fs/cgroup/<rel>` is a live cgroup directory.
pub(super) fn cgroup_has_dir(rel: &[u8]) -> bool {
    with_step35_state(|state| state.cgroups.has_dir(rel)).unwrap_or(false)
}

/// Lists immediate entries under `/sys/fs/cgroup/<rel>`, calling `emit(name, is_dir)`.
pub(super) fn cgroup_list_dir(rel: &[u8], emit: impl FnMut(&[u8], bool)) -> bool {
    with_step35_state(|state| state.cgroups.list_dir(rel, emit)).unwrap_or(false)
}

/// Formats the relative cgroup v2 path (`"/"` or `"/system.slice/..."`) for `pid`.
pub(super) fn pid_cgroup_path(pid: u32, out: &mut [u8]) -> usize {
    with_step35_state(|state| state.cgroups.pid_cgroup_path(pid, out)).unwrap_or_else(|()| {
        if !out.is_empty() {
            out[0] = b'/';
            1
        } else {
            0
        }
    })
}

/// Mutates the shared process security state (userns maps, seccomp policy, unshare) for Step 41.
pub(super) fn with_security_state<R>(
    f: impl FnOnce(&mut ProcessSecurityState) -> R,
) -> Result<R, ()> {
    let process = slot_process_id();
    with_step35_state(|state| f(state.security_for_mut(process)))
}

/// Evaluates active seccomp filter before dispatching sensitive AArch64 syscalls.
#[allow(dead_code)]
pub(super) fn evaluate_seccomp_request(
    request: SyscallRequest,
) -> Result<kernal_linux_cgroup::SeccompVerdict, ()> {
    let process = slot_process_id();
    with_step35_state(|state| {
        state.security_for(process).evaluate_seccomp(
            request.number as u32,
            kernal_linux_cgroup::AUDIT_ARCH_AARCH64,
            0,
            request.args,
        )
    })
}

/// Reports whether the current Step-36 security state retains effective capability `cap`.
pub(super) fn has_effective_capability(cap: u32) -> Result<bool, ()> {
    let process = slot_process_id();
    with_step35_state(|state| state.security_for(process).has_cap(cap))
}

/// Dispatches Step-35 event/notification/memfd/pidfd/close_range syscalls, synchronous I/O
/// multiplexing (`epoll_pwait`, `pselect6`, `ppoll`), monotonic sleeps (`nanosleep`,
/// `clock_nanosleep`), and Step-36 capability/namespace/prctl/security syscalls on AArch64.
pub(super) fn try_handle_syscall(
    request: SyscallRequest,
    mut frame: Option<&mut ExceptionFrame>,
) -> Result<Option<SyscallReturn>, ()> {
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
        22 => Ok(Some(encode_blocking(handle_epoll_pwait(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
            request.args[5],
            frame.as_deref_mut(),
        )?)?)),
        // fcntl(fd, cmd, arg) for Step-35 memfd sealing
        25 if (is_event_fd(request.args[0]) || is_aliased_event_fd(request.args[0]))
            && matches!(
                linux_unsigned_int(request.args[1]),
                F_ADD_SEALS | F_GET_SEALS
            ) =>
        {
            Ok(Some(encode_result(handle_event_fcntl(
                request.args[0],
                request.args[1],
                request.args[2],
            )?)))
        }
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
        46 if is_event_fd(request.args[0]) || is_aliased_event_fd(request.args[0]) => Ok(Some(
            encode_result(handle_memfd_truncate(request.args[0], request.args[1])?),
        )),
        // fallocate(fd, mode, offset, len) on memfd
        47 if is_event_fd(request.args[0]) || is_aliased_event_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_memfd_fallocate(
                request.args[0],
                request.args[1],
                request.args[2] as i64,
                request.args[3] as i64,
            )?)))
        }
        // close(fd)
        57 if is_event_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        // lseek(fd, offset, whence)
        62 if is_event_fd(request.args[0]) || is_aliased_event_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_lseek(
                request.args[0],
                request.args[1] as i64,
                linux_signed_int(request.args[2]),
            )?)))
        }
        // read(fd, buf, count)
        63 if is_event_fd(request.args[0]) || is_aliased_event_fd(request.args[0]) => {
            Ok(Some(encode_blocking(handle_read(
                request.args[0],
                request.args[1],
                request.args[2],
                frame,
            )?)?))
        }
        // write(fd, buf, count)
        64 if is_event_fd(request.args[0]) || is_aliased_event_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_write(
                request.args[0],
                request.args[1],
                request.args[2],
            )?)))
        }
        // pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask)
        72 => Ok(Some(encode_blocking(handle_pselect6(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
            request.args[5],
            frame.as_deref_mut(),
        )?)?)),
        // ppoll(fds, nfds, tmo_p, sigmask, sigsetsize)
        73 => Ok(Some(encode_blocking(handle_ppoll(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
            frame.as_deref_mut(),
        )?)?)),
        // signalfd4(ufd, user_mask, sizemask, flags)
        74 => Ok(Some(encode_result(handle_signalfd4(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        // fstat(fd, statbuf)
        80 if is_event_fd(request.args[0]) || is_aliased_event_fd(request.args[0]) => Ok(Some(
            encode_result(handle_fstat(request.args[0], request.args[1])?),
        )),
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
        // nanosleep(rqtp, rmtp)
        101 => Ok(Some(encode_result(handle_clock_nanosleep(
            CLOCK_MONOTONIC_ID as u64,
            0,
            request.args[0],
            request.args[1],
            frame,
        )?))),
        // clock_gettime(clockid, tp) for non-MONOTONIC Step-35/Linux clocks; keep CLOCK_MONOTONIC (1)
        // on Step 15's authoritative runtime path.
        113 => handle_clock_gettime(request.args[0], request.args[1]),
        // clock_getres(clockid, res)
        114 => Ok(Some(encode_result(handle_clock_getres(
            request.args[0],
            request.args[1],
        )))),
        // clock_nanosleep(which_clock, flags, rqtp, rmtp)
        115 => Ok(Some(encode_result(handle_clock_nanosleep(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            frame,
        )?))),
        // sched_setaffinity(pid, cpusetsize, user_mask_ptr)
        122 => Ok(Some(encode_result(handle_sched_setaffinity(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // sched_getaffinity(pid, cpusetsize, user_mask_ptr)
        123 => Ok(Some(encode_result(handle_sched_getaffinity(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // setpriority(which, who, prio)
        140 => Ok(Some(encode_result(handle_setpriority(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // getpriority(which, who)
        141 => Ok(Some(encode_result(handle_getpriority(
            request.args[0],
            request.args[1],
        )?))),
        // gettimeofday(tv, tz)
        169 => Ok(Some(encode_result(handle_gettimeofday(
            request.args[0],
            request.args[1],
        )))),
        // prctl(option, arg2, arg3, arg4, arg5) — delegate PR_SET_NO_NEW_PRIVS/PR_GET_NO_NEW_PRIVS
        // to step30_runtime so existing Step-30 contracts remain untouched.
        167 => handle_prctl_if_step36(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // add_key(217), request_key(218), keyctl(219), bpf(280):
        // Unsupported keyring and eBPF operations fail explicitly with ENOSYS (`seccomp(277)` is
        // handled in Step 41's step41_container dispatcher).
        217..=219 | 280 => Ok(Some(SyscallReturn::error(Errno::ENOSYS))),
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

fn handle_eventfd2(raw_initval: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let initval = linux_unsigned_int(raw_initval);
    let flags = linux_unsigned_int(raw_flags);
    let process = slot_process_id();
    with_step35_state(|state| {
        let idx = state.events.eventfd2(initval, flags)?;
        state.init_slot(
            idx,
            process,
            (flags & EVENT_CLOEXEC_FLAG) != 0,
            (flags & EVENT_NONBLOCK_FLAG) != 0,
        );
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_epoll_create1(raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let flags = linux_unsigned_int(raw_flags);
    let process = slot_process_id();
    with_step35_state(|state| {
        let idx = state.events.epoll_create1(flags)?;
        state.init_slot(idx, process, (flags & EVENT_CLOEXEC_FLAG) != 0, false);
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_epoll_ctl(
    raw_epfd: u64,
    raw_op: u64,
    raw_fd: u64,
    user_event: u64,
) -> Result<Result<i64, Errno>, ()> {
    let (ep_idx, alias_gen) = match resolve_event_target(raw_epfd) {
        Ok(pair) => pair,
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
    let process = slot_process_id();
    with_step35_state(|state| {
        state.check_slot(process, ep_idx, alias_gen)?;
        state
            .events
            .epoll_ctl(ep_idx, op, target_fd, ev)
            .map(|()| 0)
    })
}

const SIGSET_BYTES: usize = 8;
const MAX_POLL_FDS: usize = 256;
const MAX_SELECT_NFDS: i32 = 1024;
const TIMER_ABSTIME: i32 = 1;
const CLOCK_REALTIME_ID: i32 = 0;
const CLOCK_MONOTONIC_ID: i32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
const CLOCK_MONOTONIC_RAW_ID: i32 = 4;
const CLOCK_REALTIME_COARSE_ID: i32 = 5;
const CLOCK_MONOTONIC_COARSE_ID: i32 = 6;
const CLOCK_BOOTTIME_ID: i32 = 7;

enum BlockingCallResult {
    Value(i64),
    Err(Errno),
    HandledInFrame(u64),
}

fn encode_blocking(result: BlockingCallResult) -> Result<SyscallReturn, ()> {
    match result {
        BlockingCallResult::Value(v) => SyscallReturn::success(v).ok_or(()),
        BlockingCallResult::Err(e) => Ok(SyscallReturn::error(e)),
        BlockingCallResult::HandledInFrame(raw_x0) => {
            let signed = raw_x0 as i64;
            if let Some(ret) = SyscallReturn::success(signed) {
                Ok(ret)
            } else if (-4095..0).contains(&signed) {
                Ok(SyscallReturn::error(
                    Errno::new((-signed) as u16).ok_or(())?,
                ))
            } else {
                Err(())
            }
        }
    }
}

enum WaitTick {
    Continue,
    Interrupted(Option<u64>),
}

fn parse_user_timespec(user_ptr: u64) -> Result<u64, Errno> {
    if user_ptr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut raw = [0u8; LINUX_TIMESPEC64_BYTES];
    copy_from_user(&mut raw, user_ptr)?;
    let tv_sec = i64::from_le_bytes(raw[..8].try_into().map_err(|_| Errno::EINVAL)?);
    let tv_nsec = i64::from_le_bytes(raw[8..16].try_into().map_err(|_| Errno::EINVAL)?);
    if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
        return Err(Errno::EINVAL);
    }
    Ok((tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(tv_nsec as u64))
}

fn parse_optional_timespec(user_ptr: u64) -> Result<Option<u64>, Errno> {
    if user_ptr == 0 {
        return Ok(None);
    }
    parse_user_timespec(user_ptr).map(Some)
}

fn deadline_from_relative_ns(rel_ns: Option<u64>) -> Result<Option<u64>, ()> {
    match rel_ns {
        None => Ok(None),
        Some(0) => Ok(Some(0)),
        Some(ns) => Ok(Some(
            kernal_timer_aarch64::monotonic_now_ns()
                .map_err(|_| ())?
                .saturating_add(ns),
        )),
    }
}

fn parse_user_sigmask(user_mask: u64, raw_sigsetsize: u64) -> Result<Option<SignalSet>, Errno> {
    if user_mask == 0 {
        return Ok(None);
    }
    if raw_sigsetsize != SIGSET_BYTES as u64 {
        return Err(Errno::EINVAL);
    }
    let mut bytes = [0u8; SIGSET_BYTES];
    copy_from_user(&mut bytes, user_mask)?;
    Ok(Some(SignalSet::from_bits(u64::from_le_bytes(bytes))))
}

fn apply_optional_sigmask(temp_mask: Option<SignalSet>) -> Result<Option<SignalSet>, ()> {
    match temp_mask {
        Some(mask) => Ok(Some(super::step30_runtime::swap_current_thread_sigmask(
            mask,
        )?)),
        None => Ok(None),
    }
}

fn restore_optional_sigmask(old_mask: Option<SignalSet>) {
    if let Some(prev) = old_mask {
        let _ = super::step30_runtime::swap_current_thread_sigmask(prev);
    }
}

fn poll_wait_step(
    mut frame: Option<&mut ExceptionFrame>,
    old_sigmask: Option<SignalSet>,
) -> Result<WaitTick, ()> {
    super::step32_dev::poll_console_rx_and_deliver_signals();
    super::step34_net::pump_hardware_net();
    if super::step30_runtime::check_pending_signal_during_wait(frame.as_deref_mut())? {
        if let (Some(prev), Some(frame_ref)) = (old_sigmask, frame.as_deref_mut()) {
            let saved_pc = frame_ref.elr_el1;
            frame_ref.x[0] = SyscallReturn::error(Errno::EINTR).as_u64_bits();
            super::deliver_step30_signal_on_return_with_saved_mask(frame_ref, prev)?;
            if frame_ref.elr_el1 != saved_pc {
                return Ok(WaitTick::Interrupted(Some(frame_ref.x[0])));
            }
            let _ = super::step30_runtime::swap_current_thread_sigmask(prev);
        }
        return Ok(WaitTick::Interrupted(None));
    }
    super::step30_runtime::yield_and_rebind_frame(frame)?;
    for _ in 0..64 {
        core::hint::spin_loop();
    }
    Ok(WaitTick::Continue)
}

fn wait_interrupted_result(handled_x0: Option<u64>) -> BlockingCallResult {
    match handled_x0 {
        Some(x0) => BlockingCallResult::HandledInFrame(x0),
        None => BlockingCallResult::Err(Errno::EINTR),
    }
}

pub(super) fn blocking_wait_step(
    mut frame: Option<&mut ExceptionFrame>,
) -> Result<Option<SyscallReturn>, ()> {
    match poll_wait_step(frame.as_deref_mut(), None)? {
        WaitTick::Continue => Ok(None),
        WaitTick::Interrupted(handled_x0) => {
            Ok(Some(encode_blocking(wait_interrupted_result(handled_x0))?))
        }
    }
}

fn probe_external_fd_readiness(process: ObjectId, raw_fd: u64) -> Result<u32, Errno> {
    if let Some(res) = super::step32_dev::probe_dev_fd_readiness(process, raw_fd) {
        return res;
    }
    if let Some(res) = super::step33_mounts::probe_proc_sys_readiness(process, raw_fd) {
        return res;
    }
    if let Some(res) = super::step34_net::probe_socket_readiness(process, raw_fd) {
        return res;
    }
    if let Some(res) = super::step33_ext4_vfs::probe_ext4_fd_readiness(process, raw_fd) {
        return res;
    }

    let fd = linux_signed_int(raw_fd);
    if fd < 0 || fd >= super::step29_runtime::STEP29_RUNTIME_FDS as i32 {
        return Err(Errno::EBADF);
    }

    enum Step29Probe {
        Ready(u32),
        ConsoleStdin,
    }

    let probe = super::step29_runtime::with_process(process, |runtime| {
        let (fds, pipes) = runtime.fd_pipe_parts();
        let kind = fds.object_kind(fd).map_err(|_| Errno::EBADF)?;
        match kind {
            OpenObjectKind::File | OpenObjectKind::Directory => {
                Ok(Step29Probe::Ready(u32::from(POLLIN) | u32::from(POLLOUT)))
            }
            OpenObjectKind::Pipe => {
                let endpoint = fds.pipe_endpoint(fd).map_err(|_| Errno::EBADF)?;
                let len = pipes.len(endpoint).map_err(|_| Errno::EBADF)?;
                let free = pipes.free_capacity(endpoint).map_err(|_| Errno::EBADF)?;
                let readers = pipes.reader_count(endpoint).map_err(|_| Errno::EBADF)?;
                let writers = pipes.writer_count(endpoint).map_err(|_| Errno::EBADF)?;
                let mut mask = 0u32;
                match endpoint.end() {
                    PipeEnd::Read => {
                        if len > 0 {
                            mask |= u32::from(POLLIN);
                        }
                        if writers == 0 {
                            mask |= u32::from(POLLHUP);
                        }
                    }
                    PipeEnd::Write => {
                        if readers == 0 {
                            mask |= u32::from(POLLERR);
                        } else if free > 0 {
                            mask |= u32::from(POLLOUT);
                        }
                    }
                }
                Ok(Step29Probe::Ready(mask))
            }
            OpenObjectKind::External(ExternalObject::Stdin) => Ok(Step29Probe::ConsoleStdin),
            OpenObjectKind::External(ExternalObject::Stdout | ExternalObject::Stderr) => {
                Ok(Step29Probe::Ready(u32::from(POLLOUT)))
            }
            OpenObjectKind::Subsystem(_) => Ok(Step29Probe::Ready(0)),
        }
    })
    .map_err(|_| Errno::EIO)??;

    match probe {
        Step29Probe::Ready(mask) => Ok(mask),
        Step29Probe::ConsoleStdin => {
            super::step32_dev::probe_console_readiness().map_err(|()| Errno::EIO)
        }
    }
}

fn probe_epoll_external_fds_snapshot(
    process: ObjectId,
    ep_idx: usize,
    alias_gen: Option<u64>,
) -> Result<([i32; 128], [u32; 128], usize), Errno> {
    let mut ext_fds = [-1i32; 128];
    let ext_n = with_step35_state(|state| {
        state.check_slot(process, ep_idx, alias_gen)?;
        Ok::<usize, Errno>(state.events.collect_epoll_external_fds(
            ep_idx,
            EVENT_FD_BASE,
            &mut ext_fds,
        ))
    })
    .map_err(|()| Errno::EIO)??;
    let mut ext_masks = [0u32; 128];
    for i in 0..ext_n {
        let fd = ext_fds[i];
        if fd >= 0 {
            ext_masks[i] = probe_external_fd_readiness(process, fd as u64).unwrap_or(0);
        }
    }
    Ok((ext_fds, ext_masks, ext_n))
}

fn lookup_snapshot_mask(ext_fds: &[i32], ext_masks: &[u32], fd: i32) -> u32 {
    ext_fds
        .iter()
        .position(|&f| f == fd)
        .map_or(0, |i| ext_masks[i])
}

fn probe_event_slot_readiness(
    process: ObjectId,
    idx: usize,
    alias_gen: Option<u64>,
) -> Result<u32, Errno> {
    let (ext_fds, ext_masks, ext_n) = probe_epoll_external_fds_snapshot(process, idx, alias_gen)?;
    let (mono_ns, real_ns) = timerfd_clocks_now_ns();
    with_step35_state(|state| {
        state.events.refresh_timers(mono_ns, real_ns);
        state.check_slot(process, idx, alias_gen)?;
        state.events.poll_readiness_with(idx, EVENT_FD_BASE, |fd| {
            lookup_snapshot_mask(&ext_fds[..ext_n], &ext_masks[..ext_n], fd)
        })
    })
    .map_err(|()| Errno::EIO)?
}

fn probe_fd_readiness(process: ObjectId, raw_fd: u64) -> Result<u32, Errno> {
    if linux_signed_int(raw_fd) < 0 {
        return Err(Errno::EBADF);
    }
    if is_event_fd(raw_fd) {
        let idx = (linux_signed_int(raw_fd) - EVENT_FD_BASE) as usize;
        return probe_event_slot_readiness(process, idx, None);
    }
    if let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
        && handle.kind == SUBSYS_EVENT
    {
        return probe_event_slot_readiness(
            process,
            usize::from(handle.slot),
            Some(handle.generation),
        );
    }
    probe_external_fd_readiness(process, raw_fd)
}

fn handle_epoll_pwait(
    raw_epfd: u64,
    user_events: u64,
    raw_maxevents: u64,
    raw_timeout_ms: u64,
    user_sigmask: u64,
    raw_sigsetsize: u64,
    mut frame: Option<&mut ExceptionFrame>,
) -> Result<BlockingCallResult, ()> {
    let (ep_idx, alias_gen) = match resolve_event_target(raw_epfd) {
        Ok(pair) => pair,
        Err(e) => return Ok(BlockingCallResult::Err(e)),
    };
    let maxevents = linux_signed_int(raw_maxevents);
    if maxevents <= 0 || user_events == 0 {
        return Ok(BlockingCallResult::Err(Errno::EINVAL));
    }
    let temp_mask = match parse_user_sigmask(user_sigmask, raw_sigsetsize) {
        Ok(mask) => mask,
        Err(e) => return Ok(BlockingCallResult::Err(e)),
    };
    let timeout_ms = linux_signed_int(raw_timeout_ms);
    let rel_ns = if timeout_ms < 0 {
        None
    } else {
        Some(u64::from(timeout_ms as u32).saturating_mul(1_000_000))
    };
    let deadline = deadline_from_relative_ns(rel_ns)?;
    let process = current_process_object().ok_or(())?;
    let cap = (maxevents as usize).min(64);
    let mut ready = [EpollEvent { events: 0, data: 0 }; 64];
    let mut ready_fds = [-1i32; 64];
    let old_sigmask = apply_optional_sigmask(temp_mask)?;

    let count = loop {
        super::step32_dev::poll_console_rx_and_deliver_signals();
        let (mono_ns, real_ns) = timerfd_clocks_now_ns();
        let (ext_fds, ext_masks, ext_n) =
            match probe_epoll_external_fds_snapshot(process, ep_idx, alias_gen) {
                Ok(snap) => snap,
                Err(e) => {
                    restore_optional_sigmask(old_sigmask);
                    return Ok(BlockingCallResult::Err(e));
                }
            };
        let n = with_step35_state(|state| {
            state.events.refresh_timers(mono_ns, real_ns);
            state.check_slot(process, ep_idx, alias_gen)?;
            state.events.epoll_wait_with_fds(
                ep_idx,
                EVENT_FD_BASE,
                |fd| lookup_snapshot_mask(&ext_fds[..ext_n], &ext_masks[..ext_n], fd),
                &mut ready[..cap],
                &mut ready_fds[..cap],
            )
        })?;
        match n {
            Err(e) => {
                restore_optional_sigmask(old_sigmask);
                return Ok(BlockingCallResult::Err(e));
            }
            Ok(c) if c > 0 => {
                let mut pri_fds = [-1i32; 64];
                let mut pri_n = 0usize;
                for i in 0..c {
                    if (ready[i].events & (u32::from(POLLPRI) | u32::from(POLLERR))) != 0
                        && ready_fds[i] >= 0
                        && super::step33_mounts::ack_mountinfo_poll_change(
                            process,
                            ready_fds[i] as u64,
                        )
                        && pri_n < pri_fds.len()
                    {
                        pri_fds[pri_n] = ready_fds[i];
                        pri_n += 1;
                    }
                }
                if pri_n > 0 {
                    let _ = with_step35_state(|state| {
                        for &pfd in &pri_fds[..pri_n] {
                            state.events.clear_watch_edge_bits(
                                ep_idx,
                                pfd,
                                u32::from(POLLPRI) | u32::from(POLLERR),
                            );
                        }
                        if state
                            .events
                            .poll_readiness_with(ep_idx, EVENT_FD_BASE, |fd| {
                                let m = lookup_snapshot_mask(
                                    &ext_fds[..ext_n],
                                    &ext_masks[..ext_n],
                                    fd,
                                );
                                if pri_fds[..pri_n].contains(&fd) {
                                    m & !(u32::from(POLLPRI) | u32::from(POLLERR))
                                } else {
                                    m
                                }
                            })
                            .unwrap_or(0)
                            == 0
                        {
                            state.events.clear_parent_epoll_edge_bits(
                                ep_idx,
                                EVENT_FD_BASE,
                                u32::from(POLLIN),
                            );
                        }
                    });
                }
                break c;
            }
            Ok(0) if deadline == Some(0) => break 0,
            Ok(0) => {
                if let Some(dl) = deadline
                    && kernal_timer_aarch64::monotonic_now_ns().map_err(|_| ())? >= dl
                {
                    break 0;
                }
                match poll_wait_step(frame.as_deref_mut(), old_sigmask)? {
                    WaitTick::Continue => {}
                    WaitTick::Interrupted(handled_x0) => {
                        return Ok(wait_interrupted_result(handled_x0));
                    }
                }
            }
            Ok(c) => break c,
        }
    };

    restore_optional_sigmask(old_sigmask);
    for (i, item) in ready.iter().enumerate().take(count) {
        let Some(dest) = user_events.checked_add((i * 16) as u64) else {
            return Ok(BlockingCallResult::Err(Errno::EFAULT));
        };
        if let Err(e) = copy_to_user(dest, &item.to_aarch64_bytes()) {
            return Ok(BlockingCallResult::Err(e));
        }
    }
    Ok(BlockingCallResult::Value(count as i64))
}

fn handle_ppoll(
    user_fds: u64,
    raw_nfds: u64,
    user_tmo: u64,
    user_sigmask: u64,
    raw_sigsetsize: u64,
    mut frame: Option<&mut ExceptionFrame>,
) -> Result<BlockingCallResult, ()> {
    let Ok(nfds) = usize::try_from(raw_nfds) else {
        return Ok(BlockingCallResult::Err(Errno::EINVAL));
    };
    if nfds > MAX_POLL_FDS {
        return Ok(BlockingCallResult::Err(Errno::EINVAL));
    }
    let temp_mask = match parse_user_sigmask(user_sigmask, raw_sigsetsize) {
        Ok(mask) => mask,
        Err(e) => return Ok(BlockingCallResult::Err(e)),
    };
    let rel_ns = match parse_optional_timespec(user_tmo) {
        Ok(ns) => ns,
        Err(e) => return Ok(BlockingCallResult::Err(e)),
    };

    let mut entries = vec![(0i32, 0u16); nfds];
    if nfds > 0 {
        if user_fds == 0 {
            return Ok(BlockingCallResult::Err(Errno::EFAULT));
        }
        for (i, entry) in entries.iter_mut().enumerate() {
            let Some(src) = user_fds.checked_add((i * POLLFD_BYTES) as u64) else {
                return Ok(BlockingCallResult::Err(Errno::EFAULT));
            };
            let mut raw = [0u8; POLLFD_BYTES];
            if let Err(e) = copy_from_user(&mut raw, src) {
                return Ok(BlockingCallResult::Err(e));
            }
            let fd = i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let events = u16::from_le_bytes([raw[4], raw[5]]);
            *entry = (fd, events);
        }
    }

    let deadline = deadline_from_relative_ns(rel_ns)?;
    let process = current_process_object().ok_or(())?;
    let mut revents_out = vec![0u16; nfds];
    let old_sigmask = apply_optional_sigmask(temp_mask)?;

    let ready_count = loop {
        super::step32_dev::poll_console_rx_and_deliver_signals();
        let mut ready = 0usize;
        for (i, &(fd, events)) in entries.iter().enumerate() {
            if fd < 0 {
                revents_out[i] = 0;
                continue;
            }
            let avail = match probe_fd_readiness(process, fd as u64) {
                Ok(mask) => mask,
                Err(Errno::EBADF) => {
                    revents_out[i] = POLLNVAL;
                    ready += 1;
                    continue;
                }
                Err(e) => {
                    restore_optional_sigmask(old_sigmask);
                    return Ok(BlockingCallResult::Err(e));
                }
            };
            let masked = (avail as u16) & (events | POLLERR | POLLHUP | POLLNVAL);
            revents_out[i] = masked;
            if masked != 0 {
                ready += 1;
            }
        }
        if ready > 0 || deadline == Some(0) {
            if ready > 0 {
                for (i, &(fd, _)) in entries.iter().enumerate() {
                    if fd >= 0 && (revents_out[i] & (POLLPRI | POLLERR)) != 0 {
                        let _ = super::step33_mounts::ack_mountinfo_poll_change(process, fd as u64);
                    }
                }
            }
            break ready;
        }
        if let Some(dl) = deadline
            && kernal_timer_aarch64::monotonic_now_ns().map_err(|_| ())? >= dl
        {
            break 0;
        }
        match poll_wait_step(frame.as_deref_mut(), old_sigmask)? {
            WaitTick::Continue => {}
            WaitTick::Interrupted(handled_x0) => return Ok(wait_interrupted_result(handled_x0)),
        }
    };

    restore_optional_sigmask(old_sigmask);
    for (i, &revents) in revents_out.iter().enumerate() {
        let Some(dst) = user_fds.checked_add((i * POLLFD_BYTES + 6) as u64) else {
            return Ok(BlockingCallResult::Err(Errno::EFAULT));
        };
        if let Err(e) = copy_to_user(dst, &revents.to_le_bytes()) {
            return Ok(BlockingCallResult::Err(e));
        }
    }
    Ok(BlockingCallResult::Value(ready_count as i64))
}

fn read_user_fd_set(user_ptr: u64, nbytes: usize, dst: &mut [u8; 128]) -> Result<bool, Errno> {
    if user_ptr == 0 {
        return Ok(false);
    }
    if nbytes > 0 {
        copy_from_user(&mut dst[..nbytes], user_ptr)?;
    }
    Ok(true)
}

fn write_user_fd_set(
    present: bool,
    user_ptr: u64,
    nbytes: usize,
    src: &[u8; 128],
) -> Result<(), Errno> {
    if present && nbytes > 0 {
        copy_to_user(user_ptr, &src[..nbytes])?;
    }
    Ok(())
}

fn handle_pselect6(
    raw_nfds: u64,
    user_readfds: u64,
    user_writefds: u64,
    user_exceptfds: u64,
    user_tmo: u64,
    user_sigmask_pair: u64,
    mut frame: Option<&mut ExceptionFrame>,
) -> Result<BlockingCallResult, ()> {
    let nfds = linux_signed_int(raw_nfds);
    if !(0..=MAX_SELECT_NFDS).contains(&nfds) {
        return Ok(BlockingCallResult::Err(Errno::EINVAL));
    }
    let nfds_u = nfds as usize;
    let nbytes = nfds_u.div_ceil(8);

    let mut in_read = [0u8; 128];
    let mut in_write = [0u8; 128];
    let mut in_except = [0u8; 128];
    let has_read = match read_user_fd_set(user_readfds, nbytes, &mut in_read) {
        Ok(b) => b,
        Err(e) => return Ok(BlockingCallResult::Err(e)),
    };
    let has_write = match read_user_fd_set(user_writefds, nbytes, &mut in_write) {
        Ok(b) => b,
        Err(e) => return Ok(BlockingCallResult::Err(e)),
    };
    let has_except = match read_user_fd_set(user_exceptfds, nbytes, &mut in_except) {
        Ok(b) => b,
        Err(e) => return Ok(BlockingCallResult::Err(e)),
    };

    let rel_ns = match parse_optional_timespec(user_tmo) {
        Ok(ns) => ns,
        Err(e) => return Ok(BlockingCallResult::Err(e)),
    };
    let temp_mask = if user_sigmask_pair == 0 {
        None
    } else {
        let mut pair = [0u8; 16];
        if let Err(e) = copy_from_user(&mut pair, user_sigmask_pair) {
            return Ok(BlockingCallResult::Err(e));
        }
        let ss = u64::from_le_bytes(pair[..8].try_into().map_err(|_| ())?);
        let ss_len = u64::from_le_bytes(pair[8..16].try_into().map_err(|_| ())?);
        match parse_user_sigmask(ss, ss_len) {
            Ok(mask) => mask,
            Err(e) => return Ok(BlockingCallResult::Err(e)),
        }
    };

    let deadline = deadline_from_relative_ns(rel_ns)?;
    let process = current_process_object().ok_or(())?;
    let mut out_read = [0u8; 128];
    let mut out_write = [0u8; 128];
    let mut out_except = [0u8; 128];
    let old_sigmask = apply_optional_sigmask(temp_mask)?;

    let ready_bits = loop {
        super::step32_dev::poll_console_rx_and_deliver_signals();
        out_read[..nbytes].fill(0);
        out_write[..nbytes].fill(0);
        out_except[..nbytes].fill(0);
        let mut total_bits = 0usize;

        for fd in 0..nfds_u {
            let byte_idx = fd / 8;
            let bit = 1u8 << (fd % 8);
            let want_r = has_read && (in_read[byte_idx] & bit) != 0;
            let want_w = has_write && (in_write[byte_idx] & bit) != 0;
            let want_x = has_except && (in_except[byte_idx] & bit) != 0;
            if !want_r && !want_w && !want_x {
                continue;
            }
            let avail = match probe_fd_readiness(process, fd as u64) {
                Ok(mask) => mask,
                Err(e) => {
                    restore_optional_sigmask(old_sigmask);
                    return Ok(BlockingCallResult::Err(e));
                }
            };
            if want_r
                && (avail
                    & (u32::from(POLLIN)
                        | u32::from(POLLHUP)
                        | u32::from(POLLERR)
                        | u32::from(POLLRDHUP)))
                    != 0
            {
                out_read[byte_idx] |= bit;
                total_bits += 1;
            }
            if want_w && (avail & (u32::from(POLLOUT) | u32::from(POLLERR))) != 0 {
                out_write[byte_idx] |= bit;
                total_bits += 1;
            }
            if want_x && (avail & u32::from(POLLPRI)) != 0 {
                out_except[byte_idx] |= bit;
                total_bits += 1;
            }
        }

        if total_bits > 0 || deadline == Some(0) {
            break total_bits;
        }
        if let Some(dl) = deadline
            && kernal_timer_aarch64::monotonic_now_ns().map_err(|_| ())? >= dl
        {
            break 0;
        }
        match poll_wait_step(frame.as_deref_mut(), old_sigmask)? {
            WaitTick::Continue => {}
            WaitTick::Interrupted(handled_x0) => return Ok(wait_interrupted_result(handled_x0)),
        }
    };

    restore_optional_sigmask(old_sigmask);
    if let Err(e) = write_user_fd_set(has_read, user_readfds, nbytes, &out_read)
        .and_then(|()| write_user_fd_set(has_write, user_writefds, nbytes, &out_write))
        .and_then(|()| write_user_fd_set(has_except, user_exceptfds, nbytes, &out_except))
    {
        return Ok(BlockingCallResult::Err(e));
    }
    Ok(BlockingCallResult::Value(ready_bits as i64))
}

fn read_step35_clock(clockid: i32) -> Result<Option<LinuxTimespec64>, Errno> {
    match clockid {
        CLOCK_REALTIME_ID | CLOCK_REALTIME_COARSE_ID => {
            let mono_ns = kernal_timer_aarch64::monotonic_now_ns().map_err(|_| Errno::EINVAL)?;
            let base_secs = super::step42_hardware::rtc_epoch_base_seconds();
            let tv_sec = base_secs.saturating_add(mono_ns / 1_000_000_000);
            let tv_nsec = mono_ns % 1_000_000_000;
            Ok(Some(LinuxTimespec64 {
                tv_sec: i64::try_from(tv_sec).unwrap_or(i64::MAX),
                tv_nsec: tv_nsec as i64,
            }))
        }
        CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID
        | CLOCK_MONOTONIC_RAW_ID
        | CLOCK_MONOTONIC_COARSE_ID
        | CLOCK_BOOTTIME_ID => {
            let mono_ns = kernal_timer_aarch64::monotonic_now_ns().map_err(|_| Errno::EINVAL)?;
            let ts = LinuxTimespec64::from_monotonic_ns(mono_ns).map_err(|_| Errno::EINVAL)?;
            Ok(Some(ts))
        }
        _ => Ok(None),
    }
}

fn handle_clock_gettime(raw_clockid: u64, user_ts: u64) -> Result<Option<SyscallReturn>, ()> {
    let clockid = linux_signed_int(raw_clockid);
    let ts = match read_step35_clock(clockid) {
        Ok(Some(ts)) => ts,
        Ok(None) => return Ok(None),
        Err(e) => return Ok(Some(SyscallReturn::error(e))),
    };
    if user_ts == 0 {
        return Ok(Some(SyscallReturn::error(Errno::EFAULT)));
    }
    if let Err(e) = copy_to_user(user_ts, &ts.to_le_bytes()) {
        return Ok(Some(SyscallReturn::error(e)));
    }
    Ok(Some(encode_result(Ok(0))))
}

fn handle_clock_getres(raw_clockid: u64, user_ts: u64) -> Result<i64, Errno> {
    let clockid = linux_signed_int(raw_clockid);
    if !matches!(
        clockid,
        CLOCK_REALTIME_ID
            | CLOCK_MONOTONIC_ID
            | CLOCK_PROCESS_CPUTIME_ID
            | CLOCK_THREAD_CPUTIME_ID
            | CLOCK_MONOTONIC_RAW_ID
            | CLOCK_REALTIME_COARSE_ID
            | CLOCK_MONOTONIC_COARSE_ID
            | CLOCK_BOOTTIME_ID
    ) {
        return Err(Errno::EINVAL);
    }
    if user_ts != 0 {
        let res = LinuxTimespec64 {
            tv_sec: 0,
            tv_nsec: 1,
        };
        copy_to_user(user_ts, &res.to_le_bytes())?;
    }
    Ok(0)
}

fn handle_gettimeofday(user_tv: u64, user_tz: u64) -> Result<i64, Errno> {
    if user_tv != 0 {
        let ts = read_step35_clock(CLOCK_REALTIME_ID)?.ok_or(Errno::EINVAL)?;
        let tv = LinuxTimespec64 {
            tv_sec: ts.tv_sec,
            tv_nsec: ts.tv_nsec / 1_000,
        };
        copy_to_user(user_tv, &tv.to_le_bytes())?;
    }
    if user_tz != 0 {
        copy_to_user(user_tz, &[0u8; 8])?;
    }
    Ok(0)
}

fn handle_clock_nanosleep(
    raw_clockid: u64,
    raw_flags: u64,
    user_req: u64,
    user_rem: u64,
    mut frame: Option<&mut ExceptionFrame>,
) -> Result<Result<i64, Errno>, ()> {
    let clockid = linux_signed_int(raw_clockid);
    let flags = linux_signed_int(raw_flags);
    if flags != 0 && flags != TIMER_ABSTIME {
        return Ok(Err(Errno::EINVAL));
    }
    let valid_clock = if flags == TIMER_ABSTIME {
        matches!(
            clockid,
            CLOCK_MONOTONIC_ID
                | CLOCK_MONOTONIC_RAW_ID
                | CLOCK_MONOTONIC_COARSE_ID
                | CLOCK_BOOTTIME_ID
        )
    } else {
        matches!(
            clockid,
            CLOCK_REALTIME_ID
                | CLOCK_MONOTONIC_ID
                | CLOCK_MONOTONIC_RAW_ID
                | CLOCK_REALTIME_COARSE_ID
                | CLOCK_MONOTONIC_COARSE_ID
                | CLOCK_BOOTTIME_ID
        )
    };
    if !valid_clock {
        return Ok(Err(Errno::EINVAL));
    }
    let req_ns = match parse_user_timespec(user_req) {
        Ok(ns) => ns,
        Err(e) => return Ok(Err(e)),
    };
    let deadline = if flags == TIMER_ABSTIME {
        req_ns
    } else if req_ns == 0 {
        return Ok(Ok(0));
    } else {
        kernal_timer_aarch64::monotonic_now_ns()
            .map_err(|_| ())?
            .saturating_add(req_ns)
    };

    loop {
        let now = kernal_timer_aarch64::monotonic_now_ns().map_err(|_| ())?;
        if now >= deadline {
            return Ok(Ok(0));
        }
        match poll_wait_step(frame.as_deref_mut(), None)? {
            WaitTick::Continue => {}
            WaitTick::Interrupted(_) => {
                if flags == 0 && user_rem != 0 {
                    let rem_now = kernal_timer_aarch64::monotonic_now_ns().map_err(|_| ())?;
                    let rem_ns = deadline.saturating_sub(rem_now);
                    let encoded = LinuxTimespec64::from_monotonic_ns(rem_ns)
                        .map_err(|_| ())?
                        .to_le_bytes();
                    if let Err(e) = copy_to_user(user_rem, &encoded) {
                        return Ok(Err(e));
                    }
                }
                return Ok(Err(Errno::EINTR));
            }
        }
    }
}

fn handle_event_fcntl(raw_fd: u64, raw_cmd: u64, raw_arg: u64) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_event_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let cmd = linux_unsigned_int(raw_cmd);
    let arg = linux_unsigned_int(raw_arg);
    let process = slot_process_id();
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        match cmd {
            F_ADD_SEALS => state.events.memfd_add_seals(idx, arg).map(|()| 0),
            F_GET_SEALS => state.events.memfd_get_seals(idx).map(i64::from),
            _ => Ok(0),
        }
    })
}

fn handle_inotify_init1(raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let flags = linux_unsigned_int(raw_flags);
    let process = slot_process_id();
    with_step35_state(|state| {
        let idx = state.events.inotify_init1(flags)?;
        state.init_slot(
            idx,
            process,
            (flags & EVENT_CLOEXEC_FLAG) != 0,
            (flags & EVENT_NONBLOCK_FLAG) != 0,
        );
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_inotify_add_watch(
    raw_fd: u64,
    user_path: u64,
    raw_mask: u64,
) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_event_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let mut path = [0u8; kernal_linux_events::INOTIFY_PATH_CAP];
    let len = match read_user_cstr(user_path, &mut path) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    let mask = linux_unsigned_int(raw_mask);
    let process = slot_process_id();
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        state
            .events
            .inotify_add_watch(idx, &path[..len], mask)
            .map(i64::from)
    })
}

fn handle_inotify_rm_watch(raw_fd: u64, raw_wd: u64) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_event_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let wd = linux_signed_int(raw_wd);
    let process = slot_process_id();
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        state.events.inotify_rm_watch(idx, wd).map(|()| 0)
    })
}

fn handle_memfd_create(user_name: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let mut name = [0u8; 250];
    let len = match read_user_cstr(user_name, &mut name) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    let flags = linux_unsigned_int(raw_flags);
    let process = slot_process_id();
    with_step35_state(|state| {
        let idx = state.events.memfd_create(&name[..len], flags)?;
        state.init_slot(
            idx,
            process,
            (flags & (MFD_CLOEXEC_FLAG | MFD_NOEXEC_SEAL_FLAG)) != 0,
            false,
        );
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_memfd_truncate(raw_fd: u64, raw_len: u64) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_event_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let Ok(new_len) = usize::try_from(raw_len) else {
        return Ok(Err(Errno::EINVAL));
    };
    let process = slot_process_id();
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        state.events.memfd_truncate(idx, new_len).map(|()| 0)
    })
}

fn handle_memfd_fallocate(
    raw_fd: u64,
    raw_mode: u64,
    offset: i64,
    len: i64,
) -> Result<Result<i64, Errno>, ()> {
    let end = match super::step33_mounts::validate_fallocate_args(raw_mode, offset, len) {
        Ok(end) => end,
        Err(e) => return Ok(Err(e)),
    };
    let keep_size =
        (u64::from(linux_unsigned_int(raw_mode)) & super::step33_mounts::FALLOC_FL_KEEP_SIZE) != 0;
    let (idx, alias_gen) = match resolve_event_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let Ok(end) = usize::try_from(end) else {
        return Ok(Err(Errno::EFBIG));
    };
    let process = slot_process_id();
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        // Only memfds are regular files; eventfd/timerfd/epoll report ENODEV like Linux.
        state
            .events
            .memfd_snapshot(idx)
            .map_err(|_| Errno::ENODEV)?;
        if !keep_size && end > state.events.memfd_len(idx) {
            state.events.memfd_truncate(idx, end)?;
        }
        Ok(0)
    })
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
        match resolve_event_target(raw_ufd) {
            Ok(pair) => Some(pair),
            Err(e) => return Ok(Err(e)),
        }
    };
    let flags = linux_unsigned_int(raw_flags);
    let process = slot_process_id();
    with_step35_state(|state| {
        if let Some((idx, alias_gen)) = existing {
            state.check_slot(process, idx, alias_gen)?;
        }
        let idx = state
            .events
            .signalfd4(existing.map(|(i, _)| i), mask, flags)?;
        if existing.is_none() {
            state.init_slot(
                idx,
                process,
                (flags & EVENT_CLOEXEC_FLAG) != 0,
                (flags & EVENT_NONBLOCK_FLAG) != 0,
            );
        }
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn handle_timerfd_create(raw_clockid: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let clock_id = linux_unsigned_int(raw_clockid);
    let flags = linux_unsigned_int(raw_flags);
    let process = slot_process_id();
    with_step35_state(|state| {
        let idx = state.events.timerfd_create(clock_id, flags)?;
        state.init_slot(
            idx,
            process,
            (flags & EVENT_CLOEXEC_FLAG) != 0,
            (flags & EVENT_NONBLOCK_FLAG) != 0,
        );
        Ok(i64::from(EVENT_FD_BASE + (idx as i32)))
    })
}

fn timerfd_clocks_now_ns() -> (u64, u64) {
    let mono_ns = kernal_timer_aarch64::monotonic_now_ns().unwrap_or(0);
    let base_secs = super::step42_hardware::rtc_epoch_base_seconds();
    let real_ns = base_secs
        .saturating_mul(1_000_000_000)
        .saturating_add(mono_ns);
    (mono_ns, real_ns)
}

fn handle_timerfd_settime(
    raw_ufd: u64,
    raw_flags: u64,
    user_new: u64,
    user_old: u64,
) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_event_target(raw_ufd) {
        Ok(pair) => pair,
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
    let (mono_ns, real_ns) = timerfd_clocks_now_ns();
    let process = slot_process_id();
    let old = with_step35_state(|state| {
        state.events.refresh_timers(mono_ns, real_ns);
        state.check_slot(process, idx, alias_gen)?;
        state
            .events
            .timerfd_settime_clocks(idx, flags, new_int, new_val, mono_ns, real_ns)
    })?;
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
    let (idx, alias_gen) = match resolve_event_target(raw_ufd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    if user_curr == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let (mono_ns, real_ns) = timerfd_clocks_now_ns();
    let process = slot_process_id();
    let res = with_step35_state(|state| {
        state.events.refresh_timers(mono_ns, real_ns);
        state.check_slot(process, idx, alias_gen)?;
        state.events.timerfd_gettime_live(idx, mono_ns, real_ns)
    })?;
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
    let idx = (linux_signed_int(raw_fd) - EVENT_FD_BASE) as usize;
    let process = slot_process_id();
    with_step35_state(|state| state.close_native_slot(process, idx).map(|()| 0))
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_event_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let process = slot_process_id();
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        state.events.lseek(idx, offset, whence)
    })
}

fn handle_read(
    raw_fd: u64,
    user_buf: u64,
    count: u64,
    mut frame: Option<&mut ExceptionFrame>,
) -> Result<BlockingCallResult, ()> {
    let (idx, alias_gen) = match resolve_event_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(BlockingCallResult::Err(e)),
    };
    let take = usize::try_from(count).unwrap_or(MEMFD_CAP).min(MEMFD_CAP);
    if take == 0 {
        return Ok(BlockingCallResult::Value(0));
    }
    if user_buf == 0 {
        return Ok(BlockingCallResult::Err(Errno::EFAULT));
    }
    let mut buf = vec![0u8; take];
    let process = slot_process_id();
    let n = loop {
        let (mono_ns, real_ns) = timerfd_clocks_now_ns();
        let (nonblocking, res) = with_step35_state(|state| {
            state.events.refresh_timers(mono_ns, real_ns);
            state.check_slot(process, idx, alias_gen)?;
            let nb = state.meta[idx].nonblocking;
            Ok::<(bool, Result<usize, Errno>), Errno>((
                nb,
                state.events.read(idx, &mut buf[..take]),
            ))
        })?
        .unwrap_or_else(|e| (true, Err(e)));
        match res {
            Ok(n) => break n,
            Err(Errno::EAGAIN) if !nonblocking => match blocking_wait_step(frame.as_deref_mut())? {
                Some(ret) => {
                    return Ok(BlockingCallResult::HandledInFrame(ret.as_u64_bits()));
                }
                None => {}
            },
            Err(e) => return Ok(BlockingCallResult::Err(e)),
        }
    };
    if n > 0 {
        if let Err(e) = copy_to_user(user_buf, &buf[..n]) {
            return Ok(BlockingCallResult::Err(e));
        }
    }
    Ok(BlockingCallResult::Value(n as i64))
}

fn handle_write(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_event_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let take = usize::try_from(count).unwrap_or(MEMFD_CAP).min(MEMFD_CAP);
    if take == 0 {
        return Ok(Ok(0));
    }
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut buf = vec![0u8; take];
    if let Err(e) = copy_from_user(&mut buf[..take], user_buf) {
        return Ok(Err(e));
    }
    let process = slot_process_id();
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        state.events.write(idx, &buf[..take]).map(|w| w as i64)
    })
}

fn handle_fstat(raw_fd: u64, user_statbuf: u64) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_event_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let process = slot_process_id();
    let st_size = with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        Ok(state.events.memfd_len(idx) as i64)
    })?;
    let st_size = match st_size {
        Ok(sz) => sz,
        Err(e) => return Ok(Err(e)),
    };
    if user_statbuf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut stat = [0u8; ARM64_STAT_BYTES];
    stat[8..16].copy_from_slice(&(2000u64 + idx as u64).to_le_bytes()); // st_ino
    stat[16..20].copy_from_slice(&S_IFREG_MODE.to_le_bytes());
    stat[20..24].copy_from_slice(&1u32.to_le_bytes());
    stat[48..56].copy_from_slice(&st_size.to_le_bytes());
    stat[56..60].copy_from_slice(&4096i32.to_le_bytes());
    if let Err(e) = copy_to_user(user_statbuf, &stat) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

pub(super) fn try_read_memfd_for_mmap(
    process: ObjectId,
    raw_fd: u64,
    require_writable: bool,
) -> Result<Option<(alloc::vec::Vec<u8>, usize, u64)>, Errno> {
    let is_ev = is_event_fd(raw_fd)
        || lookup_aliased_subsystem(process, raw_fd).is_some_and(|h| h.kind == SUBSYS_EVENT);
    if !is_ev {
        return Ok(None);
    }
    let (idx, alias_gen) = resolve_event_target(raw_fd)?;
    let res = with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
        let (slice, seals) = state.events.memfd_snapshot(idx)?;
        if require_writable
            && (seals
                & (kernal_linux_events::F_SEAL_WRITE | kernal_linux_events::F_SEAL_FUTURE_WRITE))
                != 0
        {
            return Err(Errno::EPERM);
        }
        let gen_id = state.meta[idx].generation;
        Ok((slice.to_vec(), idx, gen_id))
    })
    .map_err(|()| Errno::EIO)?;
    res.map(Some)
}

pub(super) fn write_back_memfd_mmap(
    idx: usize,
    expected_gen: u64,
    file_offset: usize,
    data: &[u8],
) {
    let _ = with_step35_state(|state| {
        if state
            .meta
            .get(idx)
            .is_some_and(|m| m.live && m.generation == expected_gen)
        {
            let _ = state.events.memfd_write_at(idx, file_offset, data);
        }
    });
}

pub(super) fn open_pidfd_for_process(process: ObjectId, pid: u32) -> Result<i32, Errno> {
    alloc_pidfd_for_process(process, pid, 0)
}

fn alloc_pidfd_for_process(process: ObjectId, pid: u32, flags: u32) -> Result<i32, Errno> {
    let Some(nz_pid) = core::num::NonZeroU32::new(pid) else {
        return Err(Errno::EINVAL);
    };
    let idx = with_step35_state(|state| {
        let idx = state.events.pidfd_open(pid, flags)?;
        state.init_slot(idx, process, true, (flags & EVENT_NONBLOCK_FLAG) != 0);
        Ok(idx)
    })
    .map_err(|()| Errno::EIO)??;
    // Verify target existence and zombie status after slot insertion so a concurrent exit cannot
    // race between the runtime check and PidFd publication without nesting runtime <- step35 locks.
    match super::runtime::with_linux_runtime(|state| state.proc_snapshot_by_pid(nz_pid)) {
        Ok(None) => {
            let _ = with_step35_state(|state| {
                let _ = state.meta[idx].owners.close_owner(process);
                state.retire_if_unused(idx);
            });
            return Err(Errno::ESRCH);
        }
        Ok(Some(snap)) if snap.state_char == b'Z' => {
            let _ = with_step35_state(|state| {
                state.events.mark_slot_pidfd_exited(idx);
            });
        }
        Ok(Some(_)) | Err(_) => {}
    }
    Ok(EVENT_FD_BASE + (idx as i32))
}

fn handle_pidfd_open(raw_pid: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let pid = linux_signed_int(raw_pid);
    if pid <= 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let flags = linux_unsigned_int(raw_flags);
    Ok(alloc_pidfd_for_process(slot_process_id(), pid as u32, flags).map(i64::from))
}

fn handle_pidfd_send_signal(
    raw_pidfd: u64,
    raw_sig: u64,
    raw_flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    if raw_flags != 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let (idx, alias_gen) = match resolve_event_target(raw_pidfd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let sig = linux_signed_int(raw_sig);
    if !(0..=64).contains(&sig) {
        return Ok(Err(Errno::EINVAL));
    }
    let process = slot_process_id();
    with_step35_state(|state| {
        state.check_slot(process, idx, alias_gen)?;
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
    super::step_fd_util::close_range_for_all_subsystems(
        first,
        last,
        (flags & CLOSE_RANGE_CLOEXEC) != 0,
    )?;
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
        let process = slot_process_id();
        let data = with_step35_state(|state| state.security_for(process).encode_cap_data_v3())?;
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
    let process = slot_process_id();
    with_step35_state(|state| {
        state
            .security_for_mut(process)
            .apply_cap_data_v3(&data)
            .map(|()| 0)
    })
}

fn handle_unshare(raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    let process = slot_process_id();
    with_step35_state(|state| {
        state
            .security_for_mut(process)
            .unshare(raw_flags)
            .map(|()| 0)
    })
}

fn handle_prctl_if_step36(
    raw_option: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let option = linux_unsigned_int(raw_option);
    let process = slot_process_id();
    // Keep PR_SET_NO_NEW_PRIVS / PR_GET_NO_NEW_PRIVS in step30_runtime for Step-30 proof fidelity.
    if option == PR_SET_NO_NEW_PRIVS {
        if arg2 == 1 && arg3 == 0 && arg4 == 0 && arg5 == 0 {
            let _ = with_step35_state(|state| {
                state.security_for_mut(process).no_new_privs = true;
            });
        }
        return Ok(None);
    }
    if option == PR_GET_NO_NEW_PRIVS {
        return Ok(None);
    }
    if option == PR_SET_NAME {
        let mut name = [0u8; 16];
        if let Err(e) = copy_from_user(&mut name, arg2) {
            return Ok(Some(SyscallReturn::error(e)));
        }
        with_step35_state(|state| state.security_for_mut(process).set_comm(&name))?;
        if let Some(current) = super::step_fd_util::current_scheduler_thread() {
            let _ = super::runtime::with_linux_runtime(|state| {
                let _ = state.set_current_process_comm(current, &name);
            });
        }
        return Ok(Some(SyscallReturn::success(0).ok_or(())?));
    }
    if option == PR_GET_NAME {
        let mut comm = with_step35_state(|state| state.security_for(process).comm)?;
        if let Some(current) = super::step_fd_util::current_scheduler_thread() {
            let _ = super::runtime::with_linux_runtime(|state| {
                if let Ok(proc_comm) = state.current_process_comm(current) {
                    comm = proc_comm;
                }
            });
        }
        if let Err(e) = copy_to_user(arg2, &comm) {
            return Ok(Some(SyscallReturn::error(e)));
        }
        return Ok(Some(SyscallReturn::success(0).ok_or(())?));
    }
    if option == PR_GET_PDEATHSIG {
        let sig = with_step35_state(|state| state.security_for(process).pdeathsig)?;
        if let Err(e) = copy_to_user(arg2, &sig.to_le_bytes()) {
            return Ok(Some(SyscallReturn::error(e)));
        }
        return Ok(Some(SyscallReturn::success(0).ok_or(())?));
    }
    let res = with_step35_state(|state| {
        state
            .security_for_mut(process)
            .prctl(option, arg2, arg3, arg4, arg5)
    })?;
    Ok(Some(encode_result(res)))
}

fn resolve_priority_targets(
    which: i32,
    who: i32,
) -> Result<
    (
        [Option<(ObjectId, u32)>; super::runtime::STEP15_RUNTIME_PROCESSES],
        usize,
    ),
    Errno,
> {
    if !matches!(which, PRIO_PROCESS | PRIO_PGRP | PRIO_USER) {
        return Err(Errno::EINVAL);
    }
    if who < 0 && which != PRIO_USER {
        return Err(Errno::ESRCH);
    }
    let fallback_proc = slot_process_id();
    let (fallback_uid, _) = super::step_fd_util::current_uid_gid();
    let mut targets = [None; super::runtime::STEP15_RUNTIME_PROCESSES];
    let Some(tid) = super::step_fd_util::current_scheduler_thread() else {
        if who == 0 {
            targets[0] = Some((fallback_proc, fallback_uid));
            return Ok((targets, 1));
        }
        return Err(Errno::ESRCH);
    };

    let Ok(count) = super::runtime::with_linux_runtime(|rt| {
        let Some(cur) = rt.proc_snapshot_for_scheduler_thread(tid) else {
            return Err(Errno::ESRCH);
        };
        if which == PRIO_PROCESS {
            let target_pid = if who == 0 { cur.pid } else { who as u32 };
            if target_pid == cur.pid {
                targets[0] = Some((cur.process, cur.uid));
                return Ok(1usize);
            }
            let Some(nz) = core::num::NonZeroU32::new(target_pid) else {
                return Err(Errno::ESRCH);
            };
            let Some(snap) = rt.proc_snapshot_by_pid(nz) else {
                return Err(Errno::ESRCH);
            };
            targets[0] = Some((snap.process, snap.uid));
            return Ok(1usize);
        }

        let mut snaps = [None; super::runtime::STEP15_RUNTIME_PROCESSES];
        let snap_count = rt.collect_proc_snapshots(&mut snaps);
        let mut matched = 0usize;
        for snap in snaps.into_iter().take(snap_count).flatten() {
            let matches_group = match which {
                PRIO_PGRP => {
                    let target_pgid = if who == 0 { cur.pgid } else { who as u32 };
                    snap.pgid == target_pgid
                }
                PRIO_USER => {
                    let target_uid = if who == 0 { cur.uid } else { who as u32 };
                    snap.uid == target_uid
                }
                _ => false,
            };
            if matches_group && matched < targets.len() {
                targets[matched] = Some((snap.process, snap.uid));
                matched += 1;
            }
        }
        if matched == 0 {
            return Err(Errno::ESRCH);
        }
        Ok(matched)
    }) else {
        if who == 0 {
            targets[0] = Some((fallback_proc, fallback_uid));
            return Ok((targets, 1));
        }
        return Err(Errno::ESRCH);
    };

    let count = count?;
    Ok((targets, count))
}

fn handle_getpriority(raw_which: u64, raw_who: u64) -> Result<Result<i64, Errno>, ()> {
    let which = linux_signed_int(raw_which);
    let who = linux_signed_int(raw_who);
    let (targets, count) = match resolve_priority_targets(which, who) {
        Ok(found) => found,
        Err(err) => return Ok(Err(err)),
    };
    with_step35_state(|state| {
        let mut best_nice = i8::MAX;
        for (proc_id, _) in targets.into_iter().take(count).flatten() {
            best_nice = best_nice.min(state.nice_for(proc_id));
        }
        Ok(PRIORITY_OFFSET - i64::from(best_nice))
    })
}

fn handle_setpriority(
    raw_which: u64,
    raw_who: u64,
    raw_prio: u64,
) -> Result<Result<i64, Errno>, ()> {
    let which = linux_signed_int(raw_which);
    let who = linux_signed_int(raw_who);
    let niceval = linux_signed_int(raw_prio).clamp(-20, 19) as i8;
    let (targets, count) = match resolve_priority_targets(which, who) {
        Ok(found) => found,
        Err(err) => return Ok(Err(err)),
    };
    let (caller_uid, _) = super::step_fd_util::current_uid_gid();
    let is_root = caller_uid == 0;
    with_step35_state(|state| {
        for (proc_id, target_uid) in targets.into_iter().take(count).flatten() {
            if !is_root && caller_uid != target_uid {
                return Err(Errno::EPERM);
            }
            if !is_root && niceval < state.nice_for(proc_id) {
                return Err(Errno::EACCES);
            }
        }
        for (proc_id, _) in targets.into_iter().take(count).flatten() {
            state.set_nice_for(proc_id, niceval);
        }
        Ok(0)
    })
}

fn validate_affinity_args(
    raw_pid: u64,
    cpusetsize: u64,
    user_mask: u64,
) -> Result<(u64, u64), Errno> {
    let pid = linux_signed_int(raw_pid);
    if pid < 0 {
        return Err(Errno::ESRCH);
    }
    if pid > 0
        && let Some(_tid) = super::step_fd_util::current_scheduler_thread()
        && let Some(nz) = core::num::NonZeroU32::new(pid as u32)
        && super::runtime::with_linux_runtime(|rt| rt.proc_snapshot_by_pid(nz).is_none())
            .unwrap_or(false)
    {
        return Err(Errno::ESRCH);
    }
    if cpusetsize < 8 || cpusetsize % 8 != 0 {
        return Err(Errno::EINVAL);
    }
    if user_mask == 0 {
        return Err(Errno::EFAULT);
    }
    let count = super::super::online_cpu_count();
    let online_mask = (1u64 << count) - 1;
    Ok((online_mask, user_mask))
}

fn handle_sched_getaffinity(
    raw_pid: u64,
    cpusetsize: u64,
    user_mask: u64,
) -> Result<Result<i64, Errno>, ()> {
    let (online_mask, dst) = match validate_affinity_args(raw_pid, cpusetsize, user_mask) {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    if let Err(e) = copy_to_user(dst, &online_mask.to_le_bytes()) {
        return Ok(Err(e));
    }
    Ok(Ok(8))
}

fn handle_sched_setaffinity(
    raw_pid: u64,
    cpusetsize: u64,
    user_mask: u64,
) -> Result<Result<i64, Errno>, ()> {
    let (online_mask, src) = match validate_affinity_args(raw_pid, cpusetsize, user_mask) {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    let mut raw = [0u8; 8];
    if let Err(e) = copy_from_user(&mut raw, src) {
        return Ok(Err(e));
    }
    if (u64::from_le_bytes(raw) & online_mask) == 0 {
        return Ok(Err(Errno::EINVAL));
    }
    Ok(Ok(0))
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
    fn event_fd_window_is_disjoint_from_earlier_subsystems() {
        assert!(!is_event_fd(0));
        assert!(!is_event_fd(64));
        assert!(!is_event_fd(96));
        assert!(!is_event_fd(128));
        assert!(is_event_fd(EVENT_FD_BASE as u64));
        assert!(is_event_fd(
            (EVENT_FD_BASE + (MAX_EVENT_FDS as i32) - 1) as u64
        ));
        assert!(!is_event_fd(
            (EVENT_FD_BASE + (MAX_EVENT_FDS as i32)) as u64
        ));
    }

    #[test]
    fn unsupported_bpf_and_keyctl_fail_explicitly_with_enosys() {
        for nr in [217u64, 218, 219, 280] {
            let req = SyscallRequest::new(nr, [0; 6]);
            let ret = try_handle_syscall(req, None).unwrap().unwrap();
            assert_eq!(ret, SyscallReturn::error(Errno::ENOSYS));
        }
    }

    #[test]
    fn getpriority_and_setpriority_validate_and_track_nice() {
        let get_req = SyscallRequest::new(141, [0, 0, 0, 0, 0, 0]);
        assert_eq!(
            try_handle_syscall(get_req, None).unwrap().unwrap(),
            SyscallReturn::success(20).unwrap()
        );

        let set_req = SyscallRequest::new(140, [0, 0, (-5i64) as u64, 0, 0, 0]);
        assert_eq!(
            try_handle_syscall(set_req, None).unwrap().unwrap(),
            SyscallReturn::success(0).unwrap()
        );
        assert_eq!(
            try_handle_syscall(get_req, None).unwrap().unwrap(),
            SyscallReturn::success(25).unwrap()
        );

        let bad_which = SyscallRequest::new(141, [9, 0, 0, 0, 0, 0]);
        assert_eq!(
            try_handle_syscall(bad_which, None).unwrap().unwrap(),
            SyscallReturn::error(Errno::EINVAL)
        );

        let reset_req = SyscallRequest::new(140, [0, 0, 0, 0, 0, 0]);
        assert_eq!(
            try_handle_syscall(reset_req, None).unwrap().unwrap(),
            SyscallReturn::success(0).unwrap()
        );
    }

    #[test]
    fn sched_affinity_validates_cpuset_size_and_null_mask() {
        let bad_size = SyscallRequest::new(123, [0, 4, 0x1000, 0, 0, 0]);
        assert_eq!(
            try_handle_syscall(bad_size, None).unwrap().unwrap(),
            SyscallReturn::error(Errno::EINVAL)
        );
        let null_mask = SyscallRequest::new(123, [0, 128, 0, 0, 0, 0]);
        assert_eq!(
            try_handle_syscall(null_mask, None).unwrap().unwrap(),
            SyscallReturn::error(Errno::EFAULT)
        );
    }
}
