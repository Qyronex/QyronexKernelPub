// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_linux_abi::{
    Errno, KERNEL_TERMIOS_BYTES, SyscallRequest, SyscallReturn, TCGETS, TCSETS, TCSETSF, TCSETSW,
    TIOCGPGRP, TIOCGPTN, TIOCGWINSZ, TIOCSCTTY, TIOCSPGRP, TIOCSPTLCK, TIOCSWINSZ, WINSIZE_BYTES,
    WinSize, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_dev::{
    DeviceNodeKind, EntropyReadiness, JobControlCheck, LineDiscipline, PtyMasterEndpoint,
    PtySlaveEndpoint, PtySlaveIoResult, PtyTable, Termios, TtySessionState, classify_dev_path,
    read_pseudo_device, write_pseudo_device,
};

/// Dedicated file-descriptor base for Step-32 `/dev` pseudo-device descriptors (`64..96`),
/// partitioned cleanly above `STEP29_RUNTIME_FDS` (`0..32`).
pub(super) const DEV_FD_BASE: i32 = 64;
const MAX_DEV_FDS: usize = 16;
const MAX_PTYS: usize = 4;
const PTY_RING_BYTES: usize = 256;
const DEV_IO_CHUNK: usize = 256;
const S_IFCHR_MODE: u32 = 0o020_666;
const ARM64_STAT_BYTES: usize = 128;

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_NONBLOCK: u64 = 0x0000_0800;
const O_CLOEXEC: u64 = 0x0008_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DevFdEntry {
    live: bool,
    owner_process: ObjectId,
    backing: DevBacking,
    access: DeviceAccess,
    nonblocking: bool,
    close_on_exec: bool,
}

impl DevFdEntry {
    const EMPTY: Self = Self {
        live: false,
        owner_process: ObjectId(0),
        backing: DevBacking::Node(DeviceNodeKind::Null),
        access: DeviceAccess::ReadOnly,
        nonblocking: false,
        close_on_exec: false,
    };
}

struct Step32DevState {
    fds: [DevFdEntry; MAX_DEV_FDS],
    ptys: PtyTable<MAX_PTYS, PTY_RING_BYTES>,
    console_ldisc: LineDiscipline<PTY_RING_BYTES>,
    console_session: TtySessionState,
}

impl Step32DevState {
    const fn new() -> Self {
        Self {
            fds: [DevFdEntry::EMPTY; MAX_DEV_FDS],
            ptys: PtyTable::new(),
            console_ldisc: LineDiscipline::new(),
            console_session: TtySessionState::new(),
        }
    }
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

/// Intercepts `/dev/*` path-based syscalls (`openat = 56`, `newfstatat = 79`) and `/dev` descriptor
/// syscalls (`close = 57`, `lseek = 62`, `read = 63`, `write = 64`, `fstat = 80`).
///
/// Returns `Ok(None)` when the path is not under `/dev` or the descriptor is outside `DEV_FD_BASE..`,
/// leaving existing Step-29 VFS/FD dispatch completely unchanged.
pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        56 => try_openat(request.args[1], request.args[2]),
        57 if is_dev_fd(request.args[0]) => close_dev_fd(request.args[0]).map(Some),
        62 if is_dev_fd(request.args[0]) => lseek_dev_fd(request.args[0]).map(Some),
        63 if is_dev_fd(request.args[0]) => {
            read_dev_fd(request.args[0], request.args[1], request.args[2]).map(Some)
        }
        64 if is_dev_fd(request.args[0]) => {
            write_dev_fd(request.args[0], request.args[1], request.args[2]).map(Some)
        }
        79 => try_newfstatat(request.args[1], request.args[2]),
        80 if is_dev_fd(request.args[0]) => {
            fstat_dev_fd(request.args[0], request.args[1]).map(Some)
        }
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
    let fd = linux_signed_int(raw_fd);
    let slot_idx = usize::try_from(fd - DEV_FD_BASE).map_err(|_| ())?;
    let cmd = linux_unsigned_int(raw_request);
    let (resolved_proc, caller_pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    if resolved_proc != process {
        return Err(());
    }

    with_dev_state(|state| {
        let Some(entry) = state.fds.get(slot_idx).copied() else {
            return Ok(SyscallReturn::error(Errno::EBADF));
        };
        if !entry.live || entry.owner_process != process {
            return Ok(SyscallReturn::error(Errno::EBADF));
        }

        match entry.backing {
            DevBacking::PtyMaster(master) => match cmd {
                TIOCGPTN => {
                    if arg == 0 {
                        return Ok(SyscallReturn::error(Errno::EFAULT));
                    }
                    let ptn = match state.ptys.pts_number(master) {
                        Ok(ptn) => ptn,
                        Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
                    };
                    if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &ptn.to_le_bytes())
                    {
                        return map_usercopy(err);
                    }
                    Ok(SyscallReturn::success(0).ok_or(())?)
                }
                TIOCSPTLCK => {
                    if arg == 0 {
                        return Ok(SyscallReturn::error(Errno::EFAULT));
                    }
                    let mut raw_lock = [0u8; 4];
                    if let Err(err) = kernal_usercopy_aarch64::copy_from_user(&mut raw_lock, arg) {
                        return map_usercopy(err);
                    }
                    let locked = i32::from_le_bytes(raw_lock) != 0;
                    if let Err(err) = state.ptys.set_slave_lock(master, locked) {
                        return Ok(SyscallReturn::error(err.to_errno()));
                    }
                    Ok(SyscallReturn::success(0).ok_or(())?)
                }
                _ => Ok(SyscallReturn::error(Errno::ENOTTY)),
            },
            DevBacking::Node(DeviceNodeKind::Tty | DeviceNodeKind::Console) => match cmd {
                TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ => {
                    handle_ldisc_ioctl(&mut state.console_ldisc, cmd, arg)
                }
                TIOCSCTTY | TIOCGPGRP | TIOCSPGRP => handle_session_ioctl(
                    &mut state.console_session,
                    caller_pid,
                    caller_pgid,
                    caller_sid,
                    cmd,
                    arg,
                ),
                _ => Ok(SyscallReturn::error(Errno::ENOTTY)),
            },
            DevBacking::PtySlave(slave) => match cmd {
                TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ => {
                    let ldisc = match state.ptys.slave_ldisc_mut(slave) {
                        Ok(ldisc) => ldisc,
                        Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
                    };
                    handle_ldisc_ioctl(ldisc, cmd, arg)
                }
                TIOCSCTTY | TIOCGPGRP | TIOCSPGRP => {
                    let session = match state.ptys.slave_session_mut(slave) {
                        Ok(session) => session,
                        Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
                    };
                    handle_session_ioctl(session, caller_pid, caller_pgid, caller_sid, cmd, arg)
                }
                _ => Ok(SyscallReturn::error(Errno::ENOTTY)),
            },
            DevBacking::Node(_) => Ok(SyscallReturn::error(Errno::ENOTTY)),
        }
    })?
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
) -> Result<SyscallReturn, ()> {
    match cmd {
        TIOCSCTTY => {
            if let Err(err) =
                session.attach_controlling_session(caller_pid, caller_sid, caller_pgid)
            {
                return Ok(SyscallReturn::error(err.to_errno()));
            }
            Ok(SyscallReturn::success(0).ok_or(())?)
        }
        TIOCGPGRP => {
            if arg == 0 {
                return Ok(SyscallReturn::error(Errno::EFAULT));
            }
            let pgid = match session.get_foreground_pgid(caller_sid) {
                Ok(pgid) => pgid.get(),
                Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
            };
            if let Err(err) = kernal_usercopy_aarch64::copy_to_user(arg, &pgid.to_le_bytes()) {
                return map_usercopy(err);
            }
            Ok(SyscallReturn::success(0).ok_or(())?)
        }
        TIOCSPGRP => {
            if arg == 0 {
                return Ok(SyscallReturn::error(Errno::EFAULT));
            }
            let mut raw = [0u8; 4];
            if let Err(err) = kernal_usercopy_aarch64::copy_from_user(&mut raw, arg) {
                return map_usercopy(err);
            }
            let pgid = i32::from_le_bytes(raw);
            let Some(target_pgid) = u32::try_from(pgid).ok().and_then(NonZeroU32::new) else {
                return Ok(SyscallReturn::error(Errno::EINVAL));
            };
            match session.set_foreground_pgid(caller_sid, caller_pgid, target_pgid) {
                Ok(JobControlCheck::Allowed) => Ok(SyscallReturn::success(0).ok_or(())?),
                Ok(JobControlCheck::Stop(_)) => Ok(SyscallReturn::error(Errno::EINTR)),
                Err(err) => Ok(SyscallReturn::error(err.to_errno())),
            }
        }
        _ => Ok(SyscallReturn::error(Errno::ENOTTY)),
    }
}

fn try_openat(user_path: u64, raw_flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let Some(kind) = inspect_user_dev_path(user_path)? else {
        return Ok(None);
    };
    let access = match raw_flags & O_ACCMODE {
        O_RDONLY => DeviceAccess::ReadOnly,
        O_WRONLY => DeviceAccess::WriteOnly,
        O_RDWR => DeviceAccess::ReadWrite,
        _ => return Ok(Some(SyscallReturn::error(Errno::EINVAL))),
    };
    let nonblocking = raw_flags & O_NONBLOCK != 0;
    let close_on_exec = raw_flags & O_CLOEXEC != 0;
    let process = current_process_id()?;

    // Enforce capability mediation for the process opening this device node.
    let cap = Capability {
        object: process,
        rights: CapRights::READ.union(CapRights::WRITE),
    };
    if let Err(err) = kind.authorize_capability(&cap, access.required_rights()) {
        return Ok(Some(SyscallReturn::error(err.to_errno())));
    }

    let result = with_dev_state(|state| {
        let Some((slot_idx, slot)) = state
            .fds
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| !entry.live)
        else {
            return Ok(SyscallReturn::error(Errno::EMFILE));
        };

        let backing = match kind {
            DeviceNodeKind::Ptmx => match state.ptys.allocate_ptmx() {
                Ok(master) => DevBacking::PtyMaster(master),
                Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
            },
            DeviceNodeKind::Pts(idx) => match state.ptys.open_slave(idx) {
                Ok(slave) => DevBacking::PtySlave(slave),
                Err(err) => return Ok(SyscallReturn::error(err.to_errno())),
            },
            other => DevBacking::Node(other),
        };

        *slot = DevFdEntry {
            live: true,
            owner_process: process,
            backing,
            access,
            nonblocking,
            close_on_exec,
        };
        let fd = DEV_FD_BASE + (slot_idx as i32);
        Ok(SyscallReturn::success(i64::from(fd)).ok_or(())?)
    })?;
    result.map(Some)
}

fn close_dev_fd(raw_fd: u64) -> Result<SyscallReturn, ()> {
    let fd = linux_signed_int(raw_fd);
    let slot_idx = usize::try_from(fd - DEV_FD_BASE).map_err(|_| ())?;
    let process = current_process_id()?;

    with_dev_state(|state| {
        let Some(entry) = state.fds.get_mut(slot_idx) else {
            return Ok(SyscallReturn::error(Errno::EBADF));
        };
        if !entry.live || entry.owner_process != process {
            return Ok(SyscallReturn::error(Errno::EBADF));
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
        Ok(SyscallReturn::success(0).ok_or(())?)
    })?
}

fn lseek_dev_fd(raw_fd: u64) -> Result<SyscallReturn, ()> {
    let fd = linux_signed_int(raw_fd);
    let slot_idx = usize::try_from(fd - DEV_FD_BASE).map_err(|_| ())?;
    let process = current_process_id()?;

    with_dev_state(|state| {
        let Some(entry) = state.fds.get(slot_idx).copied() else {
            return Ok(SyscallReturn::error(Errno::EBADF));
        };
        if !entry.live || entry.owner_process != process {
            return Ok(SyscallReturn::error(Errno::EBADF));
        }
        match entry.backing.node_kind() {
            DeviceNodeKind::Null
            | DeviceNodeKind::Zero
            | DeviceNodeKind::Full
            | DeviceNodeKind::Random
            | DeviceNodeKind::Urandom => Ok(SyscallReturn::success(0).ok_or(())?),
            DeviceNodeKind::Tty
            | DeviceNodeKind::Console
            | DeviceNodeKind::Ptmx
            | DeviceNodeKind::Pts(_) => Ok(SyscallReturn::error(Errno::ESPIPE)),
        }
    })?
}

fn read_dev_fd(raw_fd: u64, user_buffer: u64, count: u64) -> Result<SyscallReturn, ()> {
    let fd = linux_signed_int(raw_fd);
    let slot_idx = usize::try_from(fd - DEV_FD_BASE).map_err(|_| ())?;
    let (process, _pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    let requested = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(0x7fff_f000);

    let entry = with_dev_state(|state| {
        state
            .fds
            .get(slot_idx)
            .copied()
            .filter(|e| e.live && e.owner_process == process)
    })?;
    let Some(entry) = entry else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
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
        DevBacking::Node(DeviceNodeKind::Tty | DeviceNodeKind::Console) => {
            let mut chunk = [0u8; DEV_IO_CHUNK];
            let take = requested.min(DEV_IO_CHUNK);
            let read_res = with_dev_state(|state| {
                state
                    .console_ldisc
                    .read_committed(&mut chunk[..take], entry.nonblocking)
            })?;
            match read_res {
                Ok(0) => Ok(SyscallReturn::success(0).ok_or(())?),
                Ok(n) => {
                    if let Err(err) =
                        kernal_usercopy_aarch64::copy_to_user(user_buffer, &chunk[..n])
                    {
                        return map_usercopy(err);
                    }
                    Ok(SyscallReturn::success(n as i64).ok_or(())?)
                }
                Err(err) => Ok(SyscallReturn::error(err.to_errno())),
            }
        }
        DevBacking::PtyMaster(master) => {
            let mut chunk = [0u8; DEV_IO_CHUNK];
            let take = requested.min(DEV_IO_CHUNK);
            let read_res = with_dev_state(|state| {
                state
                    .ptys
                    .master_read(master, &mut chunk[..take], entry.nonblocking)
            })?;
            match read_res {
                Ok(0) => Ok(SyscallReturn::success(0).ok_or(())?),
                Ok(n) => {
                    if let Err(err) =
                        kernal_usercopy_aarch64::copy_to_user(user_buffer, &chunk[..n])
                    {
                        return map_usercopy(err);
                    }
                    Ok(SyscallReturn::success(n as i64).ok_or(())?)
                }
                Err(err) => Ok(SyscallReturn::error(err.to_errno())),
            }
        }
        DevBacking::PtySlave(slave) => {
            let mut chunk = [0u8; DEV_IO_CHUNK];
            let take = requested.min(DEV_IO_CHUNK);
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
                Ok(PtySlaveIoResult::Transferred(0)) => Ok(SyscallReturn::success(0).ok_or(())?),
                Ok(PtySlaveIoResult::Transferred(n)) => {
                    if let Err(err) =
                        kernal_usercopy_aarch64::copy_to_user(user_buffer, &chunk[..n])
                    {
                        return map_usercopy(err);
                    }
                    Ok(SyscallReturn::success(n as i64).ok_or(())?)
                }
                Ok(PtySlaveIoResult::JobControlStop(_)) => Ok(SyscallReturn::error(Errno::EINTR)),
                Err(err) => Ok(SyscallReturn::error(err.to_errno())),
            }
        }
        DevBacking::Node(DeviceNodeKind::Ptmx | DeviceNodeKind::Pts(_)) => {
            Ok(SyscallReturn::error(Errno::EIO))
        }
    }
}

fn write_dev_fd(raw_fd: u64, user_buffer: u64, count: u64) -> Result<SyscallReturn, ()> {
    let fd = linux_signed_int(raw_fd);
    let slot_idx = usize::try_from(fd - DEV_FD_BASE).map_err(|_| ())?;
    let (process, _pid, caller_pgid, caller_sid) = current_process_tty_ids()?;
    let requested = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(0x7fff_f000);

    let entry = with_dev_state(|state| {
        state
            .fds
            .get(slot_idx)
            .copied()
            .filter(|e| e.live && e.owner_process == process)
    })?;
    let Some(entry) = entry else {
        return Ok(SyscallReturn::error(Errno::EBADF));
    };
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
            DevBacking::Node(DeviceNodeKind::Tty | DeviceNodeKind::Console) => {
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
                let write_res = with_dev_state(|state| {
                    state
                        .ptys
                        .slave_write(slave, caller_sid, caller_pgid, &chunk[..take])
                })?;
                match write_res {
                    Ok(PtySlaveIoResult::Transferred(written)) => {
                        total += written;
                        if written < take {
                            break;
                        }
                    }
                    Ok(PtySlaveIoResult::JobControlStop(_)) => {
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
    let fd = linux_signed_int(raw_fd);
    let slot_idx = usize::try_from(fd - DEV_FD_BASE).map_err(|_| ())?;
    let process = current_process_id()?;

    let kind = with_dev_state(|state| {
        state
            .fds
            .get(slot_idx)
            .copied()
            .filter(|e| e.live && e.owner_process == process)
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

fn copy_chrdev_stat_to_user(kind: DeviceNodeKind, user_stat: u64) -> Result<SyscallReturn, ()> {
    if user_stat == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }
    let mut stat = [0u8; ARM64_STAT_BYTES];
    let rdev = kind.rdev();
    let ino = (1u64 << 61) | rdev;
    stat[0..8].copy_from_slice(&5u64.to_le_bytes()); // st_dev (devtmpfs = 5)
    stat[8..16].copy_from_slice(&ino.to_le_bytes()); // st_ino
    stat[16..20].copy_from_slice(&S_IFCHR_MODE.to_le_bytes()); // st_mode (S_IFCHR | 0666)
    stat[20..24].copy_from_slice(&1u32.to_le_bytes()); // st_nlink = 1
    stat[32..40].copy_from_slice(&rdev.to_le_bytes()); // st_rdev = makedev(major, minor)
    stat[56..60].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize = 4096

    if let Err(err) = kernal_usercopy_aarch64::copy_to_user(user_stat, &stat) {
        return map_usercopy(err);
    }
    Ok(SyscallReturn::success(0).ok_or(())?)
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
