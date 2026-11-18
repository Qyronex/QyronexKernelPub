// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_linux_abi::{
    Errno, KERNEL_TERMIOS_BYTES, POLLIN, POLLOUT, SyscallRequest, SyscallReturn, TCGETS, TCSETS,
    TCSETSF, TCSETSW, TIOCGPGRP, TIOCGPTN, TIOCGWINSZ, TIOCSCTTY, TIOCSPGRP, TIOCSPTLCK,
    TIOCSWINSZ, WINSIZE_BYTES, WinSize, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_dev::{
    DeviceNodeKind, EntropyReadiness, JobControlCheck, LineDiscipline, PtyMasterEndpoint,
    PtySlaveEndpoint, PtySlaveIoResult, PtyTable, Termios, TtySessionState, classify_dev_path,
    read_pseudo_device, write_pseudo_device,
};

/// Dedicated file-descriptor base for Step-32 `/dev` pseudo-device descriptors (`64..96`),
/// partitioned cleanly above `STEP29_RUNTIME_FDS` (`0..32`).
pub(super) const DEV_FD_BASE: i32 = 64;
const MAX_DEV_FDS: usize = 32;
const MAX_PTYS: usize = 16;
const PTY_RING_BYTES: usize = 2048;
const DEV_IO_CHUNK: usize = 256;
const IOVEC_BYTES_LEN: usize = 16;
const S_IFCHR_MODE: u32 = 0o020_666;

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_NONBLOCK: u64 = 0x0000_0800;
const O_DIRECTORY: u64 = 0x0000_4000;
const O_CLOEXEC: u64 = 0x0008_0000;
const O_PATH: u64 = 0x0020_0000;
const TIOCNOTTY: u32 = 0x5422;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    PathOnly,
}

impl DeviceAccess {
    const fn allows_read(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }

    const fn allows_write(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }

    fn required_rights(self) -> CapRights {
        match self {
            Self::ReadOnly => CapRights::READ,
            Self::WriteOnly => CapRights::WRITE,
            Self::ReadWrite => CapRights::READ.union(CapRights::WRITE),
            Self::PathOnly => CapRights::READ,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DevBacking {
    Node(DeviceNodeKind),
    PtyMaster(PtyMasterEndpoint),
    PtySlave(PtySlaveEndpoint),
}

impl DevBacking {
    const fn node_kind(self) -> DeviceNodeKind {
        match self {
            Self::Node(kind) => kind,
            Self::PtyMaster(_) => DeviceNodeKind::Ptmx,
            Self::PtySlave(ep) => DeviceNodeKind::Pts(ep.pty().index()),
        }
    }
}

use super::step_fd_util::{
    DirectProcessRefs, SUBSYS_DEV, lookup_aliased_subsystem, lookup_aliased_subsystem_current,
};
use kernal_linux_fd::SubsystemHandle;

const O_NONBLOCK_U64: u64 = 0x800;

#[derive(Clone, Copy)]
struct DevFdEntry {
    live: bool,
    generation: u64,
    alias_refs: usize,
    owners: DirectProcessRefs<{ super::step29_runtime::STEP29_RUNTIME_PROCESS_VIEWS }>,
    backing: DevBacking,
    access: DeviceAccess,
    nonblocking: bool,
}

impl DevFdEntry {
    const EMPTY: Self = Self {
        live: false,
        generation: 0,
        alias_refs: 0,
        owners: DirectProcessRefs::empty(),
        backing: DevBacking::Node(DeviceNodeKind::Null),
        access: DeviceAccess::ReadOnly,
        nonblocking: false,
    };
}

struct Step32DevState {
    next_generation: u64,
    fds: [DevFdEntry; MAX_DEV_FDS],
    ptys: PtyTable<MAX_PTYS, PTY_RING_BYTES>,
    console_ldisc: LineDiscipline<PTY_RING_BYTES>,
    console_session: TtySessionState,
    vt_ldisc: LineDiscipline<PTY_RING_BYTES>,
    vt_session: TtySessionState,
}

impl Step32DevState {
    const fn new() -> Self {
        Self {
            next_generation: 1,
            fds: [DevFdEntry::EMPTY; MAX_DEV_FDS],
            ptys: PtyTable::new(),
            console_ldisc: LineDiscipline::new(),
            #[cfg(feature = "step31-debian-shell")]
            console_session: TtySessionState::with_session(NonZeroU32::MIN, NonZeroU32::MIN),
            #[cfg(not(feature = "step31-debian-shell"))]
            console_session: TtySessionState::new(),
            vt_ldisc: LineDiscipline::new(),
            vt_session: TtySessionState::new(),
        }
    }
}

fn dev_status_flags(access: DeviceAccess, nonblocking: bool) -> u64 {
    let acc = match access {
        DeviceAccess::ReadOnly => O_RDONLY,
        DeviceAccess::WriteOnly => O_WRONLY,
        DeviceAccess::ReadWrite => O_RDWR,
        DeviceAccess::PathOnly => O_PATH,
    };
    if nonblocking && access != DeviceAccess::PathOnly {
        acc | O_NONBLOCK_U64
    } else {
        acc
    }
}

fn retire_dev_slot_if_unused(state: &mut Step32DevState, slot_idx: usize) {
    let Some(entry) = state.fds.get_mut(slot_idx) else {
        return;
    };
    if !entry.live || !entry.owners.is_empty() || entry.alias_refs > 0 {
        return;
    }
    let backing = entry.backing;
    *entry = DevFdEntry::EMPTY;
    match backing {
        DevBacking::PtyMaster(master) => {
            let _ = state.ptys.close_master(master);
        }
        DevBacking::PtySlave(slave) => {
            let _ = state.ptys.close_slave(slave);
        }
        DevBacking::Node(_) => {}
    }
}

fn resolve_dev_slot_idx(process: ObjectId, raw_fd: u64) -> Result<(usize, Option<u64>), Errno> {
    if is_dev_fd(raw_fd) {
        let fd = linux_signed_int(raw_fd);
        return Ok(((fd - DEV_FD_BASE) as usize, None));
    }
    if let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
        && handle.kind == SUBSYS_DEV
    {
        return Ok((handle.slot as usize, Some(handle.generation)));
    }
    Err(Errno::EBADF)
}

fn resolve_dev_entry_in_state(
    state: &Step32DevState,
    process: ObjectId,
    slot_idx: usize,
    alias_gen: Option<u64>,
) -> Option<DevFdEntry> {
    let entry = state.fds.get(slot_idx).copied()?;
    if !entry.live {
        return None;
    }
    match alias_gen {
        Some(expected_gen) if entry.generation == expected_gen && entry.alias_refs > 0 => {
            Some(entry)
        }
        Some(_) => None,
        None if entry.owners.has_owner(process) => Some(entry),
        None => None,
    }
}

fn is_aliased_dev_fd(raw_fd: u64) -> bool {
    lookup_aliased_subsystem_current(raw_fd).is_some_and(|h| h.kind == SUBSYS_DEV)
}

fn retain_dev_slot(
    slot_idx: usize,
    owner: Option<ObjectId>,
    expected_gen: Option<u64>,
) -> Result<(SubsystemHandle, u64), Errno> {
    with_dev_state(|state| {
        let Some(entry) = state.fds.get_mut(slot_idx) else {
            return Err(Errno::EBADF);
        };
        let valid = entry.live
            && owner.map_or(true, |p| entry.owners.has_owner(p))
            && expected_gen.map_or(true, |g| entry.generation == g);
        if !valid {
            return Err(Errno::EBADF);
        }
        entry.alias_refs += 1;
        Ok((
            SubsystemHandle {
                kind: SUBSYS_DEV,
                slot: slot_idx as u16,
                generation: entry.generation,
            },
            dev_status_flags(entry.access, entry.nonblocking),
        ))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn retain_alias_handle(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(SubsystemHandle, u64), Errno> {
    if !is_dev_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let slot_idx = (linux_signed_int(raw_fd) - DEV_FD_BASE) as usize;
    retain_dev_slot(slot_idx, Some(process), None)
}

pub(super) fn retain_existing_handle(
    handle: SubsystemHandle,
) -> Result<(SubsystemHandle, u64), Errno> {
    if handle.kind != SUBSYS_DEV {
        return Err(Errno::EBADF);
    }
    retain_dev_slot(handle.slot as usize, None, Some(handle.generation))
}

pub(super) fn append_open_dev_fds(process: ObjectId, out: &mut alloc::vec::Vec<i32>) {
    let _ = with_dev_state(|state| {
        for (idx, entry) in state.fds.iter().enumerate() {
            if entry.live && entry.owners.has_owner(process) {
                out.push(DEV_FD_BASE + (idx as i32));
            }
        }
    });
}

pub(super) fn describe_dev_slot(
    slot: u16,
    generation: Option<u64>,
    process: Option<ObjectId>,
    out: &mut [u8],
) -> Option<usize> {
    let mut written = None;
    let _ = with_dev_state(|state| {
        let Some(entry) = state.fds.get(usize::from(slot)) else {
            return;
        };
        if !entry.live {
            return;
        }
        if let Some(expected_gen) = generation {
            if entry.generation != expected_gen || entry.alias_refs == 0 {
                return;
            }
        } else if let Some(owner) = process
            && !entry.owners.has_owner(owner)
        {
            return;
        }
        written = Some(format_dev_node_path(entry.backing.node_kind(), out));
    });
    written
}

fn format_dev_node_path(kind: DeviceNodeKind, out: &mut [u8]) -> usize {
    let static_path: Option<&[u8]> = match kind {
        DeviceNodeKind::Null => Some(b"/dev/null"),
        DeviceNodeKind::Zero => Some(b"/dev/zero"),
        DeviceNodeKind::Full => Some(b"/dev/full"),
        DeviceNodeKind::Random => Some(b"/dev/random"),
        DeviceNodeKind::Urandom => Some(b"/dev/urandom"),
        DeviceNodeKind::Tty => Some(b"/dev/tty"),
        DeviceNodeKind::Vt(0) => Some(b"/dev/tty0"),
        DeviceNodeKind::Vt(1) => Some(b"/dev/tty1"),
        DeviceNodeKind::Vt(2) => Some(b"/dev/tty2"),
        DeviceNodeKind::Vt(3) => Some(b"/dev/tty3"),
        DeviceNodeKind::Vt(4) => Some(b"/dev/tty4"),
        DeviceNodeKind::Vt(5) => Some(b"/dev/tty5"),
        DeviceNodeKind::Vt(6) => Some(b"/dev/tty6"),
        DeviceNodeKind::Vt(_) => Some(b"/dev/tty7"),
        DeviceNodeKind::Console => Some(b"/dev/console"),
        DeviceNodeKind::TtyAma0 => Some(b"/dev/ttyAMA0"),
        DeviceNodeKind::Ptmx => Some(b"/dev/ptmx"),
        DeviceNodeKind::Pts(_) => None,
    };
    if let Some(path) = static_path {
        let take = path.len().min(out.len());
        out[..take].copy_from_slice(&path[..take]);
        return take;
    }
    let DeviceNodeKind::Pts(idx) = kind else {
        return 0;
    };
    let prefix = b"/dev/pts/";
    let mut c = prefix.len().min(out.len());
    out[..c].copy_from_slice(&prefix[..c]);
    let mut num_buf = [0u8; 16];
    let mut val = idx;
    let mut pos = num_buf.len();
    loop {
        pos -= 1;
        num_buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        if val == 0 {
            break;
        }
    }
    let digits = &num_buf[pos..];
    let avail = out.len().saturating_sub(c).min(digits.len());
    out[c..c + avail].copy_from_slice(&digits[..avail]);
    c += avail;
    c
}

pub(super) fn release_alias_handle(handle: SubsystemHandle) {
    if handle.kind != SUBSYS_DEV {
        return;
    }
    let slot_idx = handle.slot as usize;
    let _ = with_dev_state(|state| {
        let Some(entry) = state.fds.get_mut(slot_idx) else {
            return;
        };
        if entry.live && entry.generation == handle.generation && entry.alias_refs > 0 {
            entry.alias_refs -= 1;
            retire_dev_slot_if_unused(state, slot_idx);
        }
    });
}

pub(super) fn handle_native_fcntl(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) else {
        return None;
    };
    if alias_gen.is_some() && !matches!(cmd, 3 | 4) {
        return None;
    }
    let res = with_dev_state(|state| {
        let Some(entry) = state.fds.get_mut(slot_idx) else {
            return Err(Errno::EBADF);
        };
        if !entry.live {
            return Err(Errno::EBADF);
        }
        match alias_gen {
            Some(expected_gen) if entry.generation == expected_gen && entry.alias_refs > 0 => {}
            Some(_) => return Err(Errno::EBADF),
            None if entry.owners.has_owner(process) => {}
            None => return Err(Errno::EBADF),
        }
        match cmd {
            1 => Ok(i64::from(i32::from(
                entry.owners.get_cloexec(process).unwrap_or(false),
            ))),
            2 => {
                let _ = entry.owners.set_cloexec(process, (argi & 1) != 0);
                Ok(0)
            }
            3 => Ok(dev_status_flags(entry.access, entry.nonblocking) as i64),
            4 => {
                entry.nonblocking = ((argi as u64) & O_NONBLOCK_U64) != 0;
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

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    let _ = with_dev_state(|state| {
        for entry in &mut state.fds {
            if entry.live {
                entry.owners.on_fork(parent, child);
            }
        }
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    let _ = with_dev_state(|state| {
        for idx in 0..MAX_DEV_FDS {
            if state.fds[idx].live {
                state.fds[idx].owners.close_cloexec_for(process);
                retire_dev_slot_if_unused(state, idx);
            }
        }
    });
}

pub(super) fn on_process_exit(process: ObjectId) {
    let _ = with_dev_state(|state| {
        for idx in 0..MAX_DEV_FDS {
            if state.fds[idx].live {
                let _ = state.fds[idx].owners.close_owner(process);
                retire_dev_slot_if_unused(state, idx);
            }
        }
    });
}

pub(super) fn close_range_for_process(
    process: ObjectId,
    first: u32,
    last: u32,
    cloexec_only: bool,
) {
    let _ = with_dev_state(|state| {
        for idx in 0..MAX_DEV_FDS {
            let fd = DEV_FD_BASE + (idx as i32);
            if super::step_fd_util::fd_in_close_range(fd, first, last)
                && state.fds[idx].live
                && state.fds[idx]
                    .owners
                    .apply_close_range(process, cloexec_only)
            {
                retire_dev_slot_if_unused(state, idx);
            }
        }
    });
}

struct Step32DevCell {
    state: AtomicU8,
    value: UnsafeCell<Step32DevState>,
}

// SAFETY: access is serialized by the atomic state transition (`0 -> 1 -> 0`) inside the IRQ-masked
// synchronous lower-EL trap window.
unsafe impl Sync for Step32DevCell {}

static DEV_STATE: Step32DevCell = Step32DevCell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step32DevState::new()),
};

fn deliver_pending_tty_signal(pending_sig: Option<(u8, Option<NonZeroU32>)>) -> Result<(), ()> {
    if let Some((sig_num, Some(pgid))) = pending_sig {
        let _ = super::step30_runtime::deliver_tty_signal_to_pgid(pgid, sig_num)?;
    }
    Ok(())
}

fn await_retry_or_signal(
    mut frame: Option<&mut kernal_exceptions_aarch64::ExceptionFrame>,
) -> Result<bool, ()> {
    #[cfg(feature = "step31-debian-shell")]
    poll_console_rx_and_deliver_signals();
    if super::step30_runtime::check_pending_signal_during_wait(frame.as_deref_mut())? {
        return Ok(true);
    }
    super::step30_runtime::yield_and_rebind_frame(frame)?;
    for _ in 0..64 {
        core::hint::spin_loop();
    }
    Ok(false)
}

#[cfg(feature = "step31-debian-shell")]
fn pump_pl011_rx(state: &mut Step32DevState) -> Option<(u8, Option<NonZeroU32>)> {
    let Some(serial) = super::step15_svc_serial() else {
        return None;
    };
    let mut echo = [0u8; 8];
    let mut pending_sig = None;
    for _ in 0..64 {
        let Some(byte) = serial.try_read_byte() else {
            break;
        };
        let (echo_len, sig) = state.console_ldisc.receive_input_byte(byte, &mut echo);
        for &ch in &echo[..echo_len] {
            serial.write_byte(ch);
        }
        if let Some(sig) = sig {
            pending_sig = Some((
                sig.linux_signal_number(),
                state.console_session.foreground_pgid(),
            ));
        }
    }
    pending_sig
}

/// Drains pending PL011 UART RX bytes into the shared console line discipline and delivers any
/// resulting TTY signal (`SIGINT` / `SIGQUIT` / `SIGTSTP`) to the foreground process group.
/// Polls PL011 RX on every lower-EL syscall return path so `Ctrl+C` / `Ctrl+Z` / `Ctrl+\`
/// interrupt even busy loops or sleeps that do not call `read()`.
fn probe_console_in_state(state: &mut Step32DevState) -> (Option<(u8, Option<NonZeroU32>)>, u32) {
    #[cfg(feature = "step31-debian-shell")]
    let pending_sig = pump_pl011_rx(state);
    #[cfg(not(feature = "step31-debian-shell"))]
    let pending_sig = None;
    let mut mask = u32::from(POLLOUT);
    if state.console_ldisc.has_readable_data() {
        mask |= u32::from(POLLIN);
    }
    (pending_sig, mask)
}

/// Pumps UART RX input, delivers any pending console TTY signal, and returns `POLL*` readiness.
pub(super) fn probe_console_readiness() -> Result<u32, ()> {
    let (pending_sig, mask) = with_dev_state(probe_console_in_state)?;
    deliver_pending_tty_signal(pending_sig)?;
    Ok(mask)
}

/// Probes `POLL*` readiness for a Step-32 device FD or aliased `SUBSYS_DEV` FD owned by `process`.
pub(super) fn probe_dev_fd_readiness(process: ObjectId, raw_fd: u64) -> Option<Result<u32, Errno>> {
    let (slot_idx, alias_gen) = if is_dev_fd(raw_fd) {
        let idx = (linux_signed_int(raw_fd) - DEV_FD_BASE) as usize;
        (idx, None)
    } else {
        let handle = lookup_aliased_subsystem(process, raw_fd)?;
        if handle.kind != SUBSYS_DEV {
            return None;
        }
        (usize::from(handle.slot), Some(handle.generation))
    };

    enum Outcome {
        Ready(u32),
        Console(Option<(u8, Option<NonZeroU32>)>, u32),
        Err(Errno),
    }

    let outcome = match with_dev_state(|state| {
        let entry = match resolve_dev_entry_in_state(state, process, slot_idx, alias_gen) {
            Some(entry) => entry,
            None => return Outcome::Err(Errno::EBADF),
        };
        match entry.backing {
            DevBacking::Node(
                DeviceNodeKind::Tty | DeviceNodeKind::Console | DeviceNodeKind::TtyAma0,
            ) => {
                let (pending_sig, mask) = probe_console_in_state(state);
                Outcome::Console(pending_sig, mask)
            }
            DevBacking::Node(DeviceNodeKind::Vt(_)) => Outcome::Ready(u32::from(POLLOUT)),
            DevBacking::Node(_) => Outcome::Ready(u32::from(POLLIN) | u32::from(POLLOUT)),
            DevBacking::PtyMaster(master) => match state.ptys.master_readiness(master) {
                Ok(mask) => Outcome::Ready(mask),
                Err(_) => Outcome::Err(Errno::EBADF),
            },
            DevBacking::PtySlave(slave) => match state.ptys.slave_readiness(slave) {
                Ok(mask) => Outcome::Ready(mask),
                Err(_) => Outcome::Err(Errno::EBADF),
            },
        }
    }) {
        Ok(outcome) => outcome,
        Err(()) => return Some(Err(Errno::EIO)),
    };

    match outcome {
        Outcome::Ready(mask) => Some(Ok(mask)),
        Outcome::Err(e) => Some(Err(e)),
        Outcome::Console(pending_sig, mask) => {
            if deliver_pending_tty_signal(pending_sig).is_err() {
                return Some(Err(Errno::EIO));
            }
            Some(Ok(mask))
        }
    }
}

pub(super) fn poll_console_rx_and_deliver_signals() {
    let _ = probe_console_readiness();
}

/// Clears Step 31's pre-attached PID 1 console session when PID 1 execs `/sbin/init` (`systemd`)
/// so `console-getty`/`agetty` can acquire `/dev/console` via `TIOCSCTTY`.
pub(super) fn detach_pid1_console_session_on_init_exec() {
    let _ = with_dev_state(|state| {
        state.console_session.clear_pid1_controlling_session();
    });
}

/// Reads committed console line-discipline bytes via PL011 RX into `user_buffer`.
///
/// Shared by `/dev/tty`, `/dev/console`, `read(0)` (`ExternalObject::Stdin`), and `readv(0)` when
/// `step31-debian-shell` is enabled so every console consumer sees one canonical `LineDiscipline`.
#[cfg(feature = "step31-debian-shell")]
pub(super) fn read_console_into_user(
    user_buffer: u64,
    requested: usize,
    nonblocking: bool,
    mut frame: Option<&mut kernal_exceptions_aarch64::ExceptionFrame>,
) -> Result<SyscallReturn, ()> {
    if requested == 0 {
        return Ok(SyscallReturn::success(0).ok_or(())?);
    }
    let (_proc, _pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    let mut chunk = [0u8; DEV_IO_CHUNK];
    let take = requested.min(DEV_IO_CHUNK);

    loop {
        if let JobControlCheck::Stop(sig) = with_dev_state(|state| {
            state
                .console_session
                .check_read_access(caller_sid, caller_pgid)
        })? {
            let sig_num = sig.linux_signal_number();
            if super::step30_runtime::current_signal_is_ignored_or_blocked(sig_num)? {
                return Ok(SyscallReturn::error(Errno::EIO));
            }
            let _ = super::step30_runtime::deliver_tty_signal_to_pgid(caller_pgid, sig_num)?;
            if super::step30_runtime::check_pending_signal_during_wait(frame.as_deref_mut())? {
                return Ok(SyscallReturn::error(Errno::EINTR));
            }
            continue;
        }

        let (pending_sig, read_res) = with_dev_state(|state| {
            let pending_sig = pump_pl011_rx(state);
            let read_res = state
                .console_ldisc
                .read_committed(&mut chunk[..take], nonblocking);
            (pending_sig, read_res)
        })?;
        deliver_pending_tty_signal(pending_sig)?;

        match read_res {
            Ok(0) => return Ok(SyscallReturn::success(0).ok_or(())?),
            Ok(n) => {
                if let Err(err) = kernal_usercopy_aarch64::copy_to_user(user_buffer, &chunk[..n]) {
                    return map_usercopy(err);
                }
                return Ok(SyscallReturn::success(n as i64).ok_or(())?);
            }
            Err(kernal_linux_dev::Error::WouldBlock) => {
                if super::step30_runtime::check_pending_signal_during_wait(frame.as_deref_mut())? {
                    return Ok(SyscallReturn::error(Errno::EINTR));
                }
                if nonblocking {
                    return Ok(SyscallReturn::error(Errno::EAGAIN));
                }
                if await_retry_or_signal(frame.as_deref_mut())? {
                    return Ok(SyscallReturn::error(Errno::EINTR));
                }
            }
            Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
        }
    }
}

/// Applies TTY termios, window-size, and session/job-control ioctls against the shared console
/// state on behalf of serial stdio descriptors (`fd 0/1/2`).
#[cfg(feature = "step31-debian-shell")]
pub(super) fn handle_console_ioctl(raw_request: u64, arg: u64) -> Result<SyscallReturn, ()> {
    let cmd = linux_unsigned_int(raw_request);
    let (_proc, caller_pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    let sigttou_ignored_or_blocked = if cmd == TIOCSPGRP {
        super::step30_runtime::current_signal_is_ignored_or_blocked(kernal_linux_signal::SIGTTOU)?
    } else {
        false
    };
    let (res, stop_sig) = with_dev_state(|state| {
        handle_console_backing_ioctl(
            &mut state.console_ldisc,
            &mut state.console_session,
            caller_pid,
            caller_pgid,
            caller_sid,
            cmd,
            arg,
            sigttou_ignored_or_blocked,
        )
    })??;
    if let Some(sig) = stop_sig {
        let _ = super::step30_runtime::deliver_tty_signal_to_pgid(
            caller_pgid,
            sig.linux_signal_number(),
        )?;
    }
    Ok(res)
}

fn with_dev_state<R>(f: impl FnOnce(&mut Step32DevState) -> R) -> Result<R, ()> {
    if DEV_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state transition `0 -> 1` grants exclusive mutable access for this synchronous scope.
    let result = f(unsafe { &mut *DEV_STATE.value.get() });
    DEV_STATE.state.store(0, Ordering::Release);
    Ok(result)
}

/// Returns `true` if `raw_fd` lies in the Step-32 `/dev` descriptor window (`DEV_FD_BASE..`).
pub(super) const fn is_dev_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= DEV_FD_BASE && fd < DEV_FD_BASE + (MAX_DEV_FDS as i32)
}

/// Returns `true` if `raw_fd` is either a direct Step-32 descriptor or a Step-29 alias to one.
pub(super) fn is_dev_or_aliased_fd(raw_fd: u64) -> bool {
    is_dev_fd(raw_fd) || is_aliased_dev_fd(raw_fd)
}

/// Dispatches blocking `/dev` reads (`read = 63`, `readv = 65`) with the live `ExceptionFrame`
/// so scheduler yields and Stop/Continue signal transitions rebind the frame generation cleanly.
pub(super) fn try_handle_blocking_read(
    request: SyscallRequest,
    frame: &mut kernal_exceptions_aarch64::ExceptionFrame,
) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        63 if is_dev_or_aliased_fd(request.args[0]) => read_dev_fd(
            request.args[0],
            request.args[1],
            request.args[2],
            Some(frame),
        )
        .map(Some),
        65 if is_dev_or_aliased_fd(request.args[0]) => readv_dev_fd(
            request.args[0],
            request.args[1],
            request.args[2],
            Some(frame),
        )
        .map(Some),
        _ => Ok(None),
    }
}

fn meta_noop_dev_fd(raw_fd: u64) -> Result<SyscallReturn, ()> {
    let process = current_process_id()?;
    let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    with_dev_state(|state| {
        if resolve_dev_entry_in_state(state, process, slot_idx, alias_gen).is_none() {
            return Ok(SyscallReturn::error(Errno::EBADF));
        }
        Ok(SyscallReturn::success(0).ok_or(())?)
    })?
}

/// Intercepts `/dev/*` path-based syscalls (`openat = 56`, `newfstatat = 79`) and `/dev` descriptor
/// syscalls (`close = 57`, `lseek = 62`, `read = 63`, `write = 64`, `fstat = 80`).
///
/// Returns `Ok(None)` when the path is not under `/dev` or the descriptor is outside `DEV_FD_BASE..`,
/// leaving existing Step-29 VFS/FD dispatch completely unchanged.
pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        52 | 55 if is_dev_or_aliased_fd(request.args[0]) => {
            meta_noop_dev_fd(request.args[0]).map(Some)
        }
        53 | 54 | 452 => {
            if inspect_user_dev_path(request.args[1])?.is_some() {
                Ok(Some(SyscallReturn::success(0).ok_or(())?))
            } else {
                Ok(None)
            }
        }
        56 => try_openat(request.args[1], request.args[2]),
        57 if is_dev_fd(request.args[0]) => close_dev_fd(request.args[0]).map(Some),
        62 if is_dev_or_aliased_fd(request.args[0]) => lseek_dev_fd(request.args[0]).map(Some),
        63 if is_dev_or_aliased_fd(request.args[0]) => {
            read_dev_fd(request.args[0], request.args[1], request.args[2], None).map(Some)
        }
        64 if is_dev_or_aliased_fd(request.args[0]) => {
            write_dev_fd(request.args[0], request.args[1], request.args[2]).map(Some)
        }
        65 if is_dev_or_aliased_fd(request.args[0]) => {
            readv_dev_fd(request.args[0], request.args[1], request.args[2], None).map(Some)
        }
        66 if is_dev_or_aliased_fd(request.args[0]) => {
            writev_dev_fd(request.args[0], request.args[1], request.args[2]).map(Some)
        }
        79 => try_newfstatat(request.args[1], request.args[2]),
        80 if is_dev_or_aliased_fd(request.args[0]) => {
            fstat_dev_fd(request.args[0], request.args[1]).map(Some)
        }
        291 => try_statx(
            request.args[0],
            request.args[1],
            request.args[3],
            request.args[4],
        ),
        _ => Ok(None),
    }
}

/// Handles `ioctl(2)` on a Step-32 `/dev` descriptor (`DEV_FD_BASE..`), supporting PTY master
/// `TIOCGPTN` / `TIOCSPTLCK` and TTY/slave `TCGETS`, `TCSETS*`, `TIOCGWINSZ`, `TIOCSWINSZ`,
/// `TIOCSCTTY`, `TIOCGPGRP`, and `TIOCSPGRP`.
pub(super) fn handle_dev_ioctl(
    process: ObjectId,
    raw_fd: u64,
    raw_request: u64,
    arg: u64,
) -> Result<SyscallReturn, ()> {
    let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    let cmd = linux_unsigned_int(raw_request);
    let (resolved_proc, caller_pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    if resolved_proc != process {
        return Err(());
    }
    let sigttou_ignored_or_blocked = if cmd == TIOCSPGRP {
        super::step30_runtime::current_signal_is_ignored_or_blocked(kernal_linux_signal::SIGTTOU)?
    } else {
        false
    };

    let (res, stop_sig) = with_dev_state(|state| {
        let Some(entry) = resolve_dev_entry_in_state(state, process, slot_idx, alias_gen) else {
            return Ok((SyscallReturn::error(Errno::EBADF), None));
        };
        if entry.access == DeviceAccess::PathOnly {
            return Ok((SyscallReturn::error(Errno::EBADF), None));
        }

        match entry.backing {
            DevBacking::PtyMaster(master) => {
                let res = match cmd {
                    TIOCGPTN => {
                        if arg == 0 {
                            return Ok((SyscallReturn::error(Errno::EFAULT), None));
                        }
                        let ptn = match state.ptys.pts_number(master) {
                            Ok(ptn) => ptn,
                            Err(err) => return Ok((SyscallReturn::error(err.to_errno()), None)),
                        };
                        if let Err(err) =
                            kernal_usercopy_aarch64::copy_to_user(arg, &ptn.to_le_bytes())
                        {
                            return Ok((map_usercopy(err)?, None));
                        }
                        SyscallReturn::success(0).ok_or(())?
                    }
                    TIOCSPTLCK => {
                        if arg == 0 {
                            return Ok((SyscallReturn::error(Errno::EFAULT), None));
                        }
                        let mut raw_lock = [0u8; 4];
                        if let Err(err) =
                            kernal_usercopy_aarch64::copy_from_user(&mut raw_lock, arg)
                        {
                            return Ok((map_usercopy(err)?, None));
                        }
                        let locked = i32::from_le_bytes(raw_lock) != 0;
                        if let Err(err) = state.ptys.set_slave_lock(master, locked) {
                            return Ok((SyscallReturn::error(err.to_errno()), None));
                        }
                        SyscallReturn::success(0).ok_or(())?
                    }
                    TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ => {
                        let ldisc = match state.ptys.master_ldisc_mut(master) {
                            Ok(ldisc) => ldisc,
                            Err(err) => return Ok((SyscallReturn::error(err.to_errno()), None)),
                        };
                        handle_ldisc_ioctl(ldisc, cmd, arg)?
                    }
                    _ => SyscallReturn::error(Errno::ENOTTY),
                };
                Ok((res, None))
            }
            DevBacking::Node(
                DeviceNodeKind::Tty | DeviceNodeKind::Console | DeviceNodeKind::TtyAma0,
            ) => handle_console_backing_ioctl(
                &mut state.console_ldisc,
                &mut state.console_session,
                caller_pid,
                caller_pgid,
                caller_sid,
                cmd,
                arg,
                sigttou_ignored_or_blocked,
            ),
            DevBacking::Node(DeviceNodeKind::Vt(_)) => handle_vt_backing_ioctl(
                &mut state.vt_ldisc,
                &mut state.vt_session,
                caller_pid,
                caller_pgid,
                caller_sid,
                cmd,
                arg,
                sigttou_ignored_or_blocked,
            ),
            DevBacking::PtySlave(slave) => {
                if matches!(
                    cmd,
                    TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ
                ) {
                    let ldisc = match state.ptys.slave_ldisc_mut(slave) {
                        Ok(ldisc) => ldisc,
                        Err(err) => return Ok((SyscallReturn::error(err.to_errno()), None)),
                    };
                    return Ok((handle_ldisc_ioctl(ldisc, cmd, arg)?, None));
                }
                if matches!(cmd, TIOCSCTTY | TIOCGPGRP | TIOCSPGRP) {
                    let session = match state.ptys.slave_session_mut(slave) {
                        Ok(session) => session,
                        Err(err) => return Ok((SyscallReturn::error(err.to_errno()), None)),
                    };
                    return handle_session_ioctl(
                        session,
                        caller_pid,
                        caller_pgid,
                        caller_sid,
                        cmd,
                        arg,
                        sigttou_ignored_or_blocked,
                    );
                }
                Ok((SyscallReturn::error(Errno::ENOTTY), None))
            }
            DevBacking::Node(_) => Ok((SyscallReturn::error(Errno::ENOTTY), None)),
        }
    })??;
    if let Some(sig) = stop_sig {
        let _ = super::step30_runtime::deliver_tty_signal_to_pgid(
            caller_pgid,
            sig.linux_signal_number(),
        )?;
    }
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
fn handle_console_backing_ioctl(
    ldisc: &mut LineDiscipline<PTY_RING_BYTES>,
    session: &mut TtySessionState,
    caller_pid: NonZeroU32,
    caller_pgid: NonZeroU32,
    caller_sid: NonZeroU32,
    cmd: u32,
    arg: u64,
    sigttou_ignored_or_blocked: bool,
) -> Result<(SyscallReturn, Option<kernal_linux_dev::TtySignal>), ()> {
    match cmd {
        TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ => {
            Ok((handle_ldisc_ioctl(ldisc, cmd, arg)?, None))
        }
        TIOCSCTTY | TIOCNOTTY | TIOCGPGRP | TIOCSPGRP => handle_session_ioctl(
            session,
            caller_pid,
            caller_pgid,
            caller_sid,
            cmd,
            arg,
            sigttou_ignored_or_blocked,
        ),
        _ => Ok((SyscallReturn::error(Errno::ENOTTY), None)),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_vt_backing_ioctl(
    ldisc: &mut LineDiscipline<PTY_RING_BYTES>,
    session: &mut TtySessionState,
    caller_pid: NonZeroU32,
    caller_pgid: NonZeroU32,
    caller_sid: NonZeroU32,
    cmd: u32,
    arg: u64,
    sigttou_ignored_or_blocked: bool,
) -> Result<(SyscallReturn, Option<kernal_linux_dev::TtySignal>), ()> {
    match cmd {
        TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ => {
            Ok((handle_ldisc_ioctl(ldisc, cmd, arg)?, None))
        }
        TIOCSCTTY | TIOCNOTTY | TIOCGPGRP | TIOCSPGRP => handle_session_ioctl(
            session,
            caller_pid,
            caller_pgid,
            caller_sid,
            cmd,
            arg,
            sigttou_ignored_or_blocked,
        ),
        // VT_OPENQRY (0x5600): return VT 1 as first available virtual console
        0x5600 => {
            if arg == 0 {
                return Ok((SyscallReturn::error(Errno::EFAULT), None));
            }
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &1i32.to_le_bytes()) {
                return Ok((map_usercopy(err)?, None));
            }
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        // VT_GETMODE (0x5601): struct vt_mode (8 bytes)
        0x5601 => {
            if arg == 0 {
                return Ok((SyscallReturn::error(Errno::EFAULT), None));
            }
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &[0u8; 8]) {
                return Ok((map_usercopy(err)?, None));
            }
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        // VT_GETSTATE (0x5603): struct vt_stat { v_active = 1, v_signal = 0, v_state = 0x3 }
        0x5603 => {
            if arg == 0 {
                return Ok((SyscallReturn::error(Errno::EFAULT), None));
            }
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &[1, 0, 0, 0, 3, 0]) {
                return Ok((map_usercopy(err)?, None));
            }
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        // VT_SETMODE, VT_SENDSIG, VT_RELDISP, VT_ACTIVATE, VT_WAITACTIVE, VT_DISALLOCATE
        0x5602 | 0x5604 | 0x5605 | 0x5606 | 0x5607 | 0x5608 => {
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        // KDGKBTYPE (0x4b33): KB_101 (0x02)
        0x4b33 => {
            if arg == 0 {
                return Ok((SyscallReturn::error(Errno::EFAULT), None));
            }
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &[0x02u8]) {
                return Ok((map_usercopy(err)?, None));
            }
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        // KDGETMODE (0x4b3b): KD_TEXT (0)
        0x4b3b => {
            if arg == 0 {
                return Ok((SyscallReturn::error(Errno::EFAULT), None));
            }
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &0i32.to_le_bytes()) {
                return Ok((map_usercopy(err)?, None));
            }
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        // KDGKBMODE (0x4b44): K_UNICODE (3)
        0x4b44 => {
            if arg == 0 {
                return Ok((SyscallReturn::error(Errno::EFAULT), None));
            }
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &3i32.to_le_bytes()) {
                return Ok((map_usercopy(err)?, None));
            }
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        // KDSETMODE (0x4b3a), KDSKBMODE (0x4b45), KDSKBMUTE (0x4b51), KDSETLED (0x4b32)
        0x4b32 | 0x4b3a | 0x4b45 | 0x4b51 => Ok((SyscallReturn::success(0).ok_or(())?, None)),
        _ => Ok((SyscallReturn::error(Errno::ENOTTY), None)),
    }
}

fn handle_ldisc_ioctl(
    ldisc: &mut LineDiscipline<PTY_RING_BYTES>,
    cmd: u32,
    arg: u64,
) -> Result<SyscallReturn, ()> {
    match cmd {
        TCGETS => {
            if arg == 0 {
                return Ok(SyscallReturn::error(Errno::EFAULT));
            }
            let bytes = ldisc.termios().to_le_bytes();
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &bytes) {
                return map_usercopy(err);
            }
            Ok(SyscallReturn::success(0).ok_or(())?)
        }
        TCSETS | TCSETSW | TCSETSF => {
            if arg == 0 {
                return Ok(SyscallReturn::error(Errno::EFAULT));
            }
            let mut raw = [0u8; KERNEL_TERMIOS_BYTES];
            if let Err(err) = kernal_usercopy_aarch64::copy_from_user(&mut raw, arg) {
                return map_usercopy(err);
            }
            ldisc.set_termios(Termios::from_le_bytes(raw), cmd == TCSETSF);
            Ok(SyscallReturn::success(0).ok_or(())?)
        }
        TIOCGWINSZ => {
            if arg == 0 {
                return Ok(SyscallReturn::error(Errno::EFAULT));
            }
            let ws = ldisc.winsize().to_le_bytes();
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &ws) {
                return map_usercopy(err);
            }
            Ok(SyscallReturn::success(0).ok_or(())?)
        }
        TIOCSWINSZ => {
            if arg == 0 {
                return Ok(SyscallReturn::error(Errno::EFAULT));
            }
            let mut raw = [0u8; WINSIZE_BYTES];
            if let Err(err) = kernal_usercopy_aarch64::copy_from_user(&mut raw, arg) {
                return map_usercopy(err);
            }
            ldisc.set_winsize(WinSize::from_le_bytes(raw));
            Ok(SyscallReturn::success(0).ok_or(())?)
        }
        _ => Ok(SyscallReturn::error(Errno::ENOTTY)),
    }
}

fn handle_session_ioctl(
    session: &mut TtySessionState,
    caller_pid: NonZeroU32,
    caller_pgid: NonZeroU32,
    caller_sid: NonZeroU32,
    cmd: u32,
    arg: u64,
    sigttou_ignored_or_blocked: bool,
) -> Result<(SyscallReturn, Option<kernal_linux_dev::TtySignal>), ()> {
    match cmd {
        TIOCSCTTY => {
            if let Err(err) = session.attach_controlling_session_with_force(
                caller_pid,
                caller_sid,
                caller_pgid,
                arg == 1,
            ) {
                return Ok((SyscallReturn::error(err.to_errno()), None));
            }
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        TIOCNOTTY => {
            if let Err(err) = session.detach_controlling_session(caller_sid) {
                return Ok((SyscallReturn::error(err.to_errno()), None));
            }
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        TIOCGPGRP => {
            if arg == 0 {
                return Ok((SyscallReturn::error(Errno::EFAULT), None));
            }
            let pgid = match session.get_foreground_pgid(caller_sid) {
                Ok(pgid) => pgid.get(),
                Err(err) => return Ok((SyscallReturn::error(err.to_errno()), None)),
            };
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &pgid.to_le_bytes()) {
                return Ok((map_usercopy(err)?, None));
            }
            Ok((SyscallReturn::success(0).ok_or(())?, None))
        }
        TIOCSPGRP => {
            if arg == 0 {
                return Ok((SyscallReturn::error(Errno::EFAULT), None));
            }
            let mut raw = [0u8; 4];
            if let Err(err) = kernal_usercopy_aarch64::copy_from_user(&mut raw, arg) {
                return Ok((map_usercopy(err)?, None));
            }
            let pgid = i32::from_le_bytes(raw);
            let Some(target_pgid) = u32::try_from(pgid).ok().and_then(NonZeroU32::new) else {
                return Ok((SyscallReturn::error(Errno::EINVAL), None));
            };
            match session.set_foreground_pgid_checked(
                caller_sid,
                caller_pgid,
                target_pgid,
                sigttou_ignored_or_blocked,
            ) {
                Ok(JobControlCheck::Allowed) => Ok((SyscallReturn::success(0).ok_or(())?, None)),
                Ok(JobControlCheck::Stop(sig)) => {
                    Ok((SyscallReturn::error(Errno::EINTR), Some(sig)))
                }
                Err(err) => Ok((SyscallReturn::error(err.to_errno()), None)),
            }
        }
        _ => Ok((SyscallReturn::error(Errno::ENOTTY), None)),
    }
}

fn try_openat(user_path: u64, raw_flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let Some(kind) = inspect_user_dev_path(user_path)? else {
        return Ok(None);
    };
    open_dev_kind(kind, raw_flags).map(Some)
}

pub(super) fn try_open_dev_bytes(path: &[u8], raw_flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let Some(kind) = classify_dev_path(path) else {
        return Ok(None);
    };
    open_dev_kind(kind, raw_flags).map(Some)
}

fn open_dev_kind(kind: DeviceNodeKind, raw_flags: u64) -> Result<SyscallReturn, ()> {
    if raw_flags & O_DIRECTORY != 0 {
        return Ok(SyscallReturn::error(Errno::ENOTDIR));
    }
    let is_path = (raw_flags & O_PATH) != 0;
    let access = if is_path {
        DeviceAccess::PathOnly
    } else {
        match raw_flags & O_ACCMODE {
            O_RDONLY => DeviceAccess::ReadOnly,
            O_WRONLY => DeviceAccess::WriteOnly,
            O_RDWR => DeviceAccess::ReadWrite,
            _ => return Ok(SyscallReturn::error(Errno::EINVAL)),
        }
    };
    let nonblocking = !is_path && (raw_flags & O_NONBLOCK != 0);
    let close_on_exec = raw_flags & O_CLOEXEC != 0;
    let process = current_process_id()?;

    if !is_path {
        // Enforce capability mediation for the process opening this device node.
        let cap = Capability {
            object: process,
            rights: CapRights::READ.union(CapRights::WRITE),
        };
        if let Err(err) = kind.authorize_capability(&cap, access.required_rights()) {
            return Ok(SyscallReturn::error(err.to_errno()));
        }
    }

    with_dev_state(|state| {
        let Some((slot_idx, slot)) = state
            .fds
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| !entry.live)
        else {
            return Ok(SyscallReturn::error(Errno::EMFILE));
        };

        let backing = if is_path {
            DevBacking::Node(kind)
        } else {
            match kind {
                DeviceNodeKind::Ptmx => match state.ptys.allocate_ptmx() {
                    Ok(master) => DevBacking::PtyMaster(master),
                    Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
                },
                DeviceNodeKind::Pts(idx) => match state.ptys.open_slave(idx) {
                    Ok(slave) => DevBacking::PtySlave(slave),
                    Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
                },
                other => DevBacking::Node(other),
            }
        };

        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1).max(1);
        let mut owners = DirectProcessRefs::empty();
        owners.init(process, close_on_exec);
        *slot = DevFdEntry {
            live: true,
            generation,
            alias_refs: 0,
            owners,
            backing,
            access,
            nonblocking,
        };
        let fd = DEV_FD_BASE + (slot_idx as i32);
        Ok(SyscallReturn::success(i64::from(fd)).ok_or(())?)
    })?
}

fn close_dev_fd(raw_fd: u64) -> Result<SyscallReturn, ()> {
    let fd = linux_signed_int(raw_fd);
    let slot_idx = usize::try_from(fd - DEV_FD_BASE).map_err(|_| ())?;
    let process = current_process_id()?;

    with_dev_state(|state| {
        let Some(entry) = state.fds.get_mut(slot_idx) else {
            return Ok(SyscallReturn::error(Errno::EBADF));
        };
        if !entry.live || !entry.owners.close_owner(process) {
            return Ok(SyscallReturn::error(Errno::EBADF));
        }
        retire_dev_slot_if_unused(state, slot_idx);
        Ok(SyscallReturn::success(0).ok_or(())?)
    })?
}

fn lseek_dev_fd(raw_fd: u64) -> Result<SyscallReturn, ()> {
    let process = current_process_id()?;
    let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };

    with_dev_state(|state| {
        let Some(entry) = resolve_dev_entry_in_state(state, process, slot_idx, alias_gen) else {
            return Ok(SyscallReturn::error(Errno::EBADF));
        };
        match entry.backing.node_kind() {
            DeviceNodeKind::Null
            | DeviceNodeKind::Zero
            | DeviceNodeKind::Full
            | DeviceNodeKind::Random
            | DeviceNodeKind::Urandom => Ok(SyscallReturn::success(0).ok_or(())?),
            DeviceNodeKind::Tty
            | DeviceNodeKind::Vt(_)
            | DeviceNodeKind::Console
            | DeviceNodeKind::TtyAma0
            | DeviceNodeKind::Ptmx
            | DeviceNodeKind::Pts(_) => Ok(SyscallReturn::error(Errno::ESPIPE)),
        }
    })?
}

fn read_dev_fd(
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
    frame: Option<&mut kernal_exceptions_aarch64::ExceptionFrame>,
) -> Result<SyscallReturn, ()> {
    let (process, _pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    let requested = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(0x7fff_f000);

    let entry =
        with_dev_state(|state| resolve_dev_entry_in_state(state, process, slot_idx, alias_gen))?;
    let Some(entry) = entry else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    read_dev_entry(
        entry,
        caller_pgid,
        caller_sid,
        user_buffer,
        requested,
        frame,
    )
}

fn read_dev_entry(
    entry: DevFdEntry,
    caller_pgid: NonZeroU32,
    caller_sid: NonZeroU32,
    user_buffer: u64,
    requested: usize,
    mut frame: Option<&mut kernal_exceptions_aarch64::ExceptionFrame>,
) -> Result<SyscallReturn, ()> {
    if !entry.access.allows_read() {
        return Ok(SyscallReturn::error(Errno::EBADF));
    }
    if requested == 0 {
        return Ok(SyscallReturn::success(0).ok_or(())?);
    }

    match entry.backing {
        DevBacking::Node(
            kind @ (DeviceNodeKind::Null
            | DeviceNodeKind::Zero
            | DeviceNodeKind::Full
            | DeviceNodeKind::Random
            | DeviceNodeKind::Urandom),
        ) => {
            let readiness = if super::entropy::is_csprng_ready() {
                EntropyReadiness::Ready
            } else {
                EntropyReadiness::Unseeded
            };
            let mut chunk = [0u8; DEV_IO_CHUNK];
            let mut total = 0usize;
            while total < requested {
                let take = (requested - total).min(DEV_IO_CHUNK);
                let read_len = match read_pseudo_device(
                    kind,
                    &mut chunk[..take],
                    entry.nonblocking,
                    readiness,
                    |dst| {
                        super::entropy::fill_getrandom(dst)
                            .map_err(|_| kernal_linux_dev::Error::EntropyNotReady)
                    },
                ) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) => {
                        return if total == 0 {
                            Ok(SyscallReturn::error(err.to_errno()))
                        } else {
                            Ok(SyscallReturn::success(total as i64).ok_or(())?)
                        };
                    }
                };
                let target = match user_buffer.checked_add(total as u64) {
                    Some(addr) => addr,
                    None => {
                        return if total == 0 {
                            Ok(SyscallReturn::error(Errno::EFAULT))
                        } else {
                            Ok(SyscallReturn::success(total as i64).ok_or(())?)
                        };
                    }
                };
                if let Err(err) = kernal_usercopy_aarch64::copy_to_user(target, &chunk[..read_len])
                {
                    return if total == 0 {
                        map_usercopy(err)
                    } else {
                        Ok(SyscallReturn::success(total as i64).ok_or(())?)
                    };
                }
                total += read_len;
            }
            Ok(SyscallReturn::success(total as i64).ok_or(())?)
        }
        DevBacking::Node(DeviceNodeKind::Vt(_)) => {
            if entry.nonblocking {
                return Ok(SyscallReturn::error(Errno::EAGAIN));
            }
            loop {
                if await_retry_or_signal(frame.as_deref_mut())? {
                    return Ok(SyscallReturn::error(Errno::EINTR));
                }
            }
        }
        DevBacking::Node(
            DeviceNodeKind::Tty | DeviceNodeKind::Console | DeviceNodeKind::TtyAma0,
        ) => {
            #[cfg(feature = "step31-debian-shell")]
            {
                return read_console_into_user(user_buffer, requested, entry.nonblocking, frame);
            }
            #[cfg(not(feature = "step31-debian-shell"))]
            {
                let mut chunk = [0u8; DEV_IO_CHUNK];
                let take = requested.min(DEV_IO_CHUNK);
                loop {
                    let read_res = with_dev_state(|state| {
                        state
                            .console_ldisc
                            .read_committed(&mut chunk[..take], entry.nonblocking)
                    })?;
                    match read_res {
                        Ok(0) => return Ok(SyscallReturn::success(0).ok_or(())?),
                        Ok(n) => {
                            if let Err(err) =
                                kernal_usercopy_aarch64::copy_to_user(user_buffer, &chunk[..n])
                            {
                                return map_usercopy(err);
                            }
                            return Ok(SyscallReturn::success(n as i64).ok_or(())?);
                        }
                        Err(kernal_linux_dev::Error::WouldBlock) if !entry.nonblocking => {
                            if await_retry_or_signal(frame.as_deref_mut())? {
                                return Ok(SyscallReturn::error(Errno::EINTR));
                            }
                        }
                        Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
                    }
                }
            }
        }
        DevBacking::PtyMaster(master) => {
            let mut chunk = [0u8; DEV_IO_CHUNK];
            let take = requested.min(DEV_IO_CHUNK);
            loop {
                let read_res = with_dev_state(|state| {
                    state
                        .ptys
                        .master_read(master, &mut chunk[..take], entry.nonblocking)
                })?;
                match read_res {
                    Ok(0) => return Ok(SyscallReturn::success(0).ok_or(())?),
                    Ok(n) => {
                        if let Err(err) =
                            kernal_usercopy_aarch64::copy_to_user(user_buffer, &chunk[..n])
                        {
                            return map_usercopy(err);
                        }
                        return Ok(SyscallReturn::success(n as i64).ok_or(())?);
                    }
                    Err(kernal_linux_dev::Error::WouldBlock) if !entry.nonblocking => {
                        if await_retry_or_signal(frame.as_deref_mut())? {
                            return Ok(SyscallReturn::error(Errno::EINTR));
                        }
                    }
                    Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
                }
            }
        }
        DevBacking::PtySlave(slave) => {
            let mut chunk = [0u8; DEV_IO_CHUNK];
            let take = requested.min(DEV_IO_CHUNK);
            loop {
                let read_res = with_dev_state(|state| {
                    state.ptys.slave_read(
                        slave,
                        caller_sid,
                        caller_pgid,
                        &mut chunk[..take],
                        entry.nonblocking,
                    )
                })?;
                match read_res {
                    Ok(PtySlaveIoResult::Transferred(0)) => {
                        return Ok(SyscallReturn::success(0).ok_or(())?);
                    }
                    Ok(PtySlaveIoResult::Transferred(n)) => {
                        if let Err(err) =
                            kernal_usercopy_aarch64::copy_to_user(user_buffer, &chunk[..n])
                        {
                            return map_usercopy(err);
                        }
                        return Ok(SyscallReturn::success(n as i64).ok_or(())?);
                    }
                    Ok(PtySlaveIoResult::JobControlStop(sig)) => {
                        let sig_num = sig.linux_signal_number();
                        if super::step30_runtime::current_signal_is_ignored_or_blocked(sig_num)? {
                            return Ok(SyscallReturn::error(Errno::EIO));
                        }
                        let _ = super::step30_runtime::deliver_tty_signal_to_pgid(
                            caller_pgid,
                            sig_num,
                        )?;
                        if super::step30_runtime::check_pending_signal_during_wait(
                            frame.as_deref_mut(),
                        )? {
                            return Ok(SyscallReturn::error(Errno::EINTR));
                        }
                    }
                    Err(kernal_linux_dev::Error::WouldBlock) if !entry.nonblocking => {
                        if await_retry_or_signal(frame.as_deref_mut())? {
                            return Ok(SyscallReturn::error(Errno::EINTR));
                        }
                    }
                    Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
                }
            }
        }
        DevBacking::Node(DeviceNodeKind::Ptmx | DeviceNodeKind::Pts(_)) => {
            Ok(SyscallReturn::error(Errno::EIO))
        }
    }
}

fn write_dev_fd(raw_fd: u64, user_buffer: u64, count: u64) -> Result<SyscallReturn, ()> {
    let (process, _pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    let requested = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(0x7fff_f000);

    let entry =
        with_dev_state(|state| resolve_dev_entry_in_state(state, process, slot_idx, alias_gen))?;
    let Some(entry) = entry else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    write_dev_entry(entry, caller_pgid, caller_sid, user_buffer, requested)
}

fn readv_dev_fd(
    raw_fd: u64,
    user_iov: u64,
    raw_iovcnt: u64,
    mut frame: Option<&mut kernal_exceptions_aarch64::ExceptionFrame>,
) -> Result<SyscallReturn, ()> {
    let (process, _pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    let Ok(iovcnt) = kernal_linux_abi::decode_iovcnt(raw_iovcnt) else {
        return Ok(SyscallReturn::error(Errno::EINVAL));
    };
    let entry =
        with_dev_state(|state| resolve_dev_entry_in_state(state, process, slot_idx, alias_gen))?;
    let Some(entry) = entry else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    if !entry.access.allows_read() {
        return Ok(SyscallReturn::error(Errno::EBADF));
    }
    if iovcnt == 0 {
        return Ok(SyscallReturn::success(0).ok_or(())?);
    }
    if user_iov == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }

    let mut total = 0usize;
    for idx in 0..iovcnt {
        let Some(iov_ptr) = user_iov.checked_add((idx * IOVEC_BYTES_LEN) as u64) else {
            return if total == 0 {
                Ok(SyscallReturn::error(Errno::EFAULT))
            } else {
                Ok(SyscallReturn::success(total as i64).ok_or(())?)
            };
        };
        let mut raw_iov = [0u8; IOVEC_BYTES_LEN];
        if let Err(err) = kernal_usercopy_aarch64::copy_from_user(&mut raw_iov, iov_ptr) {
            return if total == 0 {
                map_usercopy(err)
            } else {
                Ok(SyscallReturn::success(total as i64).ok_or(())?)
            };
        }
        let base = u64::from_le_bytes(raw_iov[0..8].try_into().unwrap());
        let len = usize::try_from(u64::from_le_bytes(raw_iov[8..16].try_into().unwrap()))
            .unwrap_or(usize::MAX)
            .min(0x7fff_f000usize.saturating_sub(total));
        if len == 0 {
            continue;
        }
        let res = read_dev_entry(
            entry,
            caller_pgid,
            caller_sid,
            base,
            len,
            frame.as_deref_mut(),
        )?;
        let raw = res.raw();
        if raw < 0 {
            return if total == 0 {
                Ok(res)
            } else {
                Ok(SyscallReturn::success(total as i64).ok_or(())?)
            };
        }
        let n = raw as usize;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(SyscallReturn::success(total as i64).ok_or(())?)
}

fn writev_dev_fd(raw_fd: u64, user_iov: u64, raw_iovcnt: u64) -> Result<SyscallReturn, ()> {
    let (process, _pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    let Ok(iovcnt) = kernal_linux_abi::decode_iovcnt(raw_iovcnt) else {
        return Ok(SyscallReturn::error(Errno::EINVAL));
    };
    let entry =
        with_dev_state(|state| resolve_dev_entry_in_state(state, process, slot_idx, alias_gen))?;
    let Some(entry) = entry else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    if !entry.access.allows_write() {
        return Ok(SyscallReturn::error(Errno::EBADF));
    }
    if iovcnt == 0 {
        return Ok(SyscallReturn::success(0).ok_or(())?);
    }
    if user_iov == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }

    let mut total = 0usize;
    for idx in 0..iovcnt {
        let Some(iov_ptr) = user_iov.checked_add((idx * IOVEC_BYTES_LEN) as u64) else {
            return if total == 0 {
                Ok(SyscallReturn::error(Errno::EFAULT))
            } else {
                Ok(SyscallReturn::success(total as i64).ok_or(())?)
            };
        };
        let mut raw_iov = [0u8; IOVEC_BYTES_LEN];
        if let Err(err) = kernal_usercopy_aarch64::copy_from_user(&mut raw_iov, iov_ptr) {
            return if total == 0 {
                map_usercopy(err)
            } else {
                Ok(SyscallReturn::success(total as i64).ok_or(())?)
            };
        }
        let base = u64::from_le_bytes(raw_iov[0..8].try_into().unwrap());
        let len = usize::try_from(u64::from_le_bytes(raw_iov[8..16].try_into().unwrap()))
            .unwrap_or(usize::MAX)
            .min(0x7fff_f000usize.saturating_sub(total));
        if len == 0 {
            continue;
        }
        let res = write_dev_entry(entry, caller_pgid, caller_sid, base, len)?;
        let raw = res.raw();
        if raw < 0 {
            return if total == 0 {
                Ok(res)
            } else {
                Ok(SyscallReturn::success(total as i64).ok_or(())?)
            };
        }
        let n = raw as usize;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(SyscallReturn::success(total as i64).ok_or(())?)
}

fn write_dev_entry(
    entry: DevFdEntry,
    caller_pgid: NonZeroU32,
    caller_sid: NonZeroU32,
    user_buffer: u64,
    requested: usize,
) -> Result<SyscallReturn, ()> {
    if !entry.access.allows_write() {
        return Ok(SyscallReturn::error(Errno::EBADF));
    }
    if matches!(entry.backing, DevBacking::Node(DeviceNodeKind::Full)) {
        if let Err(err) = write_pseudo_device(DeviceNodeKind::Full, &[]) {
            return Ok(SyscallReturn::error(err.to_errno()));
        }
        return Ok(SyscallReturn::error(Errno::ENOSPC));
    }
    if requested == 0 {
        return Ok(SyscallReturn::success(0).ok_or(())?);
    }

    let mut chunk = [0u8; DEV_IO_CHUNK];
    let mut total = 0usize;
    while total < requested {
        let take = (requested - total).min(DEV_IO_CHUNK);
        let source = match user_buffer.checked_add(total as u64) {
            Some(addr) => addr,
            None => {
                return if total == 0 {
                    Ok(SyscallReturn::error(Errno::EFAULT))
                } else {
                    Ok(SyscallReturn::success(total as i64).ok_or(())?)
                };
            }
        };
        if let Err(err) = kernal_usercopy_aarch64::copy_from_user(&mut chunk[..take], source) {
            return if total == 0 {
                map_usercopy(err)
            } else {
                Ok(SyscallReturn::success(total as i64).ok_or(())?)
            };
        }

        match entry.backing {
            DevBacking::Node(
                kind @ (DeviceNodeKind::Null
                | DeviceNodeKind::Zero
                | DeviceNodeKind::Random
                | DeviceNodeKind::Urandom),
            ) => match write_pseudo_device(kind, &chunk[..take]) {
                Ok(written) => total += written,
                Err(err) => {
                    return if total == 0 {
                        Ok(SyscallReturn::error(err.to_errno()))
                    } else {
                        Ok(SyscallReturn::success(total as i64).ok_or(())?)
                    };
                }
            },
            DevBacking::Node(DeviceNodeKind::Vt(_)) => {
                total += take;
            }
            DevBacking::Node(
                DeviceNodeKind::Tty | DeviceNodeKind::Console | DeviceNodeKind::TtyAma0,
            ) => {
                let sigttou_ignored_or_blocked =
                    super::step30_runtime::current_signal_is_ignored_or_blocked(
                        kernal_linux_signal::SIGTTOU,
                    )?;
                if let JobControlCheck::Stop(sig) = with_dev_state(|state| {
                    let tostop =
                        state.console_ldisc.termios().is_tostop() && !sigttou_ignored_or_blocked;
                    state
                        .console_session
                        .check_write_access(caller_sid, caller_pgid, tostop)
                })? {
                    let _ = super::step30_runtime::deliver_tty_signal_to_pgid(
                        caller_pgid,
                        sig.linux_signal_number(),
                    )?;
                    return if total == 0 {
                        Ok(SyscallReturn::error(Errno::EINTR))
                    } else {
                        Ok(SyscallReturn::success(total as i64).ok_or(())?)
                    };
                }
                if let Some(serial) = super::step15_svc_serial() {
                    for &byte in &chunk[..take] {
                        serial.write_byte(byte);
                    }
                }
                total += take;
            }
            DevBacking::PtyMaster(master) => {
                let write_res =
                    with_dev_state(|state| state.ptys.master_write(master, &chunk[..take]))?;
                match write_res {
                    Ok(res) => {
                        let pending_sig =
                            res.signal.map(|(sig, fg)| (sig.linux_signal_number(), fg));
                        deliver_pending_tty_signal(pending_sig)?;
                        total += res.written;
                        if res.written < take {
                            break;
                        }
                    }
                    Err(err) => {
                        return if total == 0 {
                            Ok(SyscallReturn::error(err.to_errno()))
                        } else {
                            Ok(SyscallReturn::success(total as i64).ok_or(())?)
                        };
                    }
                }
            }
            DevBacking::PtySlave(slave) => {
                let sigttou_ignored_or_blocked =
                    super::step30_runtime::current_signal_is_ignored_or_blocked(
                        kernal_linux_signal::SIGTTOU,
                    )?;
                let write_res = with_dev_state(|state| {
                    state.ptys.slave_write_checked(
                        slave,
                        caller_sid,
                        caller_pgid,
                        &chunk[..take],
                        sigttou_ignored_or_blocked,
                    )
                })?;
                match write_res {
                    Ok(PtySlaveIoResult::Transferred(written)) => {
                        total += written;
                        if written < take {
                            break;
                        }
                    }
                    Ok(PtySlaveIoResult::JobControlStop(sig)) => {
                        let _ = super::step30_runtime::deliver_tty_signal_to_pgid(
                            caller_pgid,
                            sig.linux_signal_number(),
                        )?;
                        return if total == 0 {
                            Ok(SyscallReturn::error(Errno::EINTR))
                        } else {
                            Ok(SyscallReturn::success(total as i64).ok_or(())?)
                        };
                    }
                    Err(err) => {
                        return if total == 0 {
                            Ok(SyscallReturn::error(err.to_errno()))
                        } else {
                            Ok(SyscallReturn::success(total as i64).ok_or(())?)
                        };
                    }
                }
            }
            DevBacking::Node(
                DeviceNodeKind::Full | DeviceNodeKind::Ptmx | DeviceNodeKind::Pts(_),
            ) => {
                return Ok(SyscallReturn::error(Errno::EIO));
            }
        }
    }
    Ok(SyscallReturn::success(total as i64).ok_or(())?)
}

fn fstat_dev_fd(raw_fd: u64, user_stat: u64) -> Result<SyscallReturn, ()> {
    let process = current_process_id()?;
    let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };

    let kind = with_dev_state(|state| {
        resolve_dev_entry_in_state(state, process, slot_idx, alias_gen)
            .map(|e| e.backing.node_kind())
    })?;
    let Some(kind) = kind else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
    copy_chrdev_stat_to_user(kind, user_stat)
}

fn try_newfstatat(user_path: u64, user_stat: u64) -> Result<Option<SyscallReturn>, ()> {
    let Some(kind) = inspect_user_dev_path(user_path)? else {
        return Ok(None);
    };
    copy_chrdev_stat_to_user(kind, user_stat).map(Some)
}

pub(super) fn try_stat_dev_bytes(path: &[u8], user_stat: u64) -> Result<Option<SyscallReturn>, ()> {
    let Some(kind) = classify_dev_path(path) else {
        return Ok(None);
    };
    copy_chrdev_stat_to_user(kind, user_stat).map(Some)
}

fn try_statx(
    raw_fd: u64,
    user_path: u64,
    _raw_mask: u64,
    user_statx: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if let Some(kind) = inspect_user_dev_path(user_path)? {
        return copy_chrdev_statx_to_user(kind, user_statx).map(Some);
    }
    if user_path == 0 || is_user_cstr_empty(user_path) {
        let Ok(process) = current_process_id() else {
            return Ok(None);
        };
        if let Ok((slot_idx, alias_gen)) = resolve_dev_slot_idx(process, raw_fd) {
            return with_dev_state(|state| {
                let Some(entry) = resolve_dev_entry_in_state(state, process, slot_idx, alias_gen)
                else {
                    return Ok(Some(SyscallReturn::error(Errno::EBADF)));
                };
                copy_chrdev_statx_to_user(entry.backing.node_kind(), user_statx).map(Some)
            })?;
        }
    }
    Ok(None)
}

pub(super) fn try_statx_dev_bytes(
    path: &[u8],
    user_statx: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let Some(kind) = classify_dev_path(path) else {
        return Ok(None);
    };
    copy_chrdev_statx_to_user(kind, user_statx).map(Some)
}

fn is_user_cstr_empty(user_path: u64) -> bool {
    if user_path == 0 {
        return false;
    }
    let mut byte = [0u8; 1];
    kernal_usercopy_aarch64::copy_from_user(&mut byte, user_path).is_ok() && byte[0] == 0
}

pub(super) fn list_active_pts(mut emit: impl FnMut(u32)) {
    let mut seen = [false; MAX_PTYS];
    let _ = with_dev_state(|state| {
        for entry in &state.fds {
            if !entry.live {
                continue;
            }
            let idx = match entry.backing {
                DevBacking::PtyMaster(m) => Some(m.pty().index()),
                DevBacking::PtySlave(s) => Some(s.pty().index()),
                DevBacking::Node(DeviceNodeKind::Pts(i)) => Some(i),
                DevBacking::Node(_) => None,
            };
            if let Some(i) = idx
                && (i as usize) < MAX_PTYS
                && !seen[i as usize]
            {
                seen[i as usize] = true;
            }
        }
    });
    for (idx, active) in seen.iter().enumerate() {
        if *active {
            emit(idx as u32);
        }
    }
}

fn dev_stat_meta(kind: DeviceNodeKind) -> super::step_fd_util::StatMeta {
    let fstype = if matches!(kind, DeviceNodeKind::Pts(_)) {
        kernal_linux_mounts::FilesystemType::Devpts
    } else {
        kernal_linux_mounts::FilesystemType::Devtmpfs
    };
    let (dev, _, _, mnt_id) = super::step33_mounts::dev_and_mnt_id_for_fstype(fstype);
    let rdev = kind.rdev();
    super::step_fd_util::StatMeta {
        dev,
        ino: (1u64 << 61) | rdev,
        mode: S_IFCHR_MODE,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev,
        size: 0,
        blksize: 4096,
        blocks: 0,
        atime_sec: 1_784_000_000,
        atime_nsec: 0,
        mtime_sec: 1_784_000_000,
        mtime_nsec: 0,
        ctime_sec: 1_784_000_000,
        ctime_nsec: 0,
        mnt_id,
        is_mount_root: false,
    }
}

fn copy_chrdev_statx_to_user(kind: DeviceNodeKind, user_statx: u64) -> Result<SyscallReturn, ()> {
    if user_statx == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }
    let meta = dev_stat_meta(kind);
    let res = super::step_fd_util::write_aarch64_statx_meta(user_statx, &meta);
    Ok(super::step_fd_util::encode_result(res))
}

fn copy_chrdev_stat_to_user(kind: DeviceNodeKind, user_stat: u64) -> Result<SyscallReturn, ()> {
    if user_stat == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }
    let meta = dev_stat_meta(kind);
    let res = super::step_fd_util::write_aarch64_stat_meta(user_stat, &meta);
    Ok(super::step_fd_util::encode_result(res))
}

fn inspect_user_dev_path(user_path: u64) -> Result<Option<DeviceNodeKind>, ()> {
    if user_path == 0 {
        return Ok(None);
    }
    let mut buf = [0u8; 64];
    for (idx, slot) in buf.iter_mut().enumerate() {
        let Some(addr) = user_path.checked_add(idx as u64) else {
            return Ok(None);
        };
        let mut byte = [0u8; 1];
        if kernal_usercopy_aarch64::copy_from_user(&mut byte, addr).is_err() {
            return Ok(None);
        }
        if byte[0] == 0 {
            return Ok(classify_dev_path(&buf[..idx]));
        }
        *slot = byte[0];
    }
    Ok(None)
}

fn current_process_tty_ids() -> Result<(ObjectId, NonZeroU32, NonZeroU32, NonZeroU32), ()> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(());
    }
    super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _) = state
            .process_parts_for_scheduler_thread(current)
            .map_err(|_| ())?;
        address_space.current_owner(process).map_err(|_| ())?;
        let proc_id = process.id();
        let (pid, pgid, sid) = state
            .with_current_process_identity(current, |proc_ref, identities| {
                let pid = identities.bound_pid(proc_ref).map_err(|_| ())?;
                let pgid = identities.getpgid(proc_ref).map_err(|_| ())?;
                let sid = identities.getsid(proc_ref).map_err(|_| ())?;
                Ok::<_, ()>((pid, pgid, sid))
            })
            .map_err(|_| ())??;
        Ok((proc_id, pid, pgid, sid))
    })
    .map_err(|_| ())?
}

fn current_process_id() -> Result<ObjectId, ()> {
    current_process_tty_ids().map(|(id, _, _, _)| id)
}

fn map_usercopy(error: kernal_usercopy::Error) -> Result<SyscallReturn, ()> {
    Ok(SyscallReturn::error(super::map_usercopy_errno(error)))
}
