// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::ObjectId;
use kernal_linux_abi::{
    Errno, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_cgroup::CAP_SYS_BOOT;
use kernal_linux_systemd::{Pid1Orchestrator, RebootAction, encode_sysinfo_64};
use kernal_linux_udev::{UdevDeviceRegistry, UeventAction};

/// Dedicated file-descriptor base for Step-37 `/dev/kmsg` and Step-38 sysfs `uevent` trigger
/// descriptors (`192..208`), partitioned cleanly above `EVENT_FD_BASE` (`160..192`).
pub(super) const KMSG_FD_BASE: i32 = 192;
const MAX_KMSG_FDS: usize = 16;
const MAX_SERVICES: usize = 16;
const KMSG_CAP: usize = 1024;
const MAX_DEVS: usize = 16;

const S_IFCHR_MODE: u32 = 0o020_644;
const KMSG_RDEV: u64 = (1u64 << 8) | 11u64; // makedev(1, 11) for /dev/kmsg

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_NONBLOCK: u64 = 0x0000_0800;
const O_DIRECTORY: u64 = 0x0000_4000;
const O_CLOEXEC: u64 = 0x0008_0000;
const O_PATH: u64 = 0x0020_0000;

const SEEK_SET: i64 = 0;
const SEEK_CUR: i64 = 1;
const SEEK_END: i64 = 2;

const NR_OPENAT: u64 = 56;
const NR_CLOSE: u64 = 57;
const NR_LSEEK: u64 = 62;
const NR_READ: u64 = 63;
const NR_WRITE: u64 = 64;
const NR_READV: u64 = 65;
const NR_WRITEV: u64 = 66;
const NR_NEWFSTATAT: u64 = 79;
const NR_FSTAT: u64 = 80;
const NR_REBOOT: u64 = 142;
const NR_SYSINFO: u64 = 179;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Step37FdKind {
    Kmsg {
        offset: usize,
        can_read: bool,
        can_write: bool,
    },
    UeventTrigger {
        dev_name: [u8; 16],
        dev_len: usize,
    },
}

#[derive(Clone, Copy)]
struct KmsgFdEntry {
    live: bool,
    generation: u64,
    alias_refs: usize,
    nonblocking: bool,
    owners: super::step_fd_util::DirectProcessRefs<
        { super::step29_runtime::STEP29_RUNTIME_PROCESS_VIEWS },
    >,
    kind: Step37FdKind,
}

impl KmsgFdEntry {
    const EMPTY: Self = Self {
        live: false,
        generation: 0,
        alias_refs: 0,
        nonblocking: false,
        owners: super::step_fd_util::DirectProcessRefs::empty(),
        kind: Step37FdKind::Kmsg {
            offset: 0,
            can_read: false,
            can_write: false,
        },
    };

    fn status_flags(self) -> u64 {
        let acc = match self.kind {
            Step37FdKind::Kmsg {
                can_read: true,
                can_write: true,
                ..
            } => O_RDWR,
            Step37FdKind::Kmsg {
                can_read: false,
                can_write: true,
                ..
            } => O_WRONLY,
            Step37FdKind::Kmsg {
                can_read: true,
                can_write: false,
                ..
            } => O_RDONLY,
            Step37FdKind::Kmsg { .. } => O_PATH,
            Step37FdKind::UeventTrigger { .. } => O_WRONLY,
        };
        if self.nonblocking && acc != O_PATH {
            acc | O_NONBLOCK
        } else {
            acc
        }
    }
}

struct Step37And38State {
    initialized: bool,
    next_generation: u64,
    pid1: Pid1Orchestrator<MAX_SERVICES, KMSG_CAP>,
    udev: UdevDeviceRegistry<MAX_DEVS>,
    kmsg_fds: [KmsgFdEntry; MAX_KMSG_FDS],
}

impl Step37And38State {
    const fn new() -> Self {
        Self {
            initialized: false,
            next_generation: 1,
            pid1: Pid1Orchestrator::new(),
            udev: UdevDeviceRegistry::new(),
            kmsg_fds: [KmsgFdEntry::EMPTY; MAX_KMSG_FDS],
        }
    }

    fn ensure_initialized(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        let _ = self.udev.seed_supported_devices();
        self.pid1.write_kmsg(
            6,
            b"kernal",
            b"systemd PID 1 and udev device registry ready",
        );
    }
}

struct Step37And38Cell {
    state: AtomicU8,
    value: UnsafeCell<Step37And38State>,
}

// SAFETY: access is serialized by the atomic state transition (`0 -> 1 -> 0`) inside the IRQ-masked
// synchronous lower-EL trap window.
unsafe impl Sync for Step37And38Cell {}

static STEP37_38_STATE: Step37And38Cell = Step37And38Cell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step37And38State::new()),
};

fn with_systemd_udev_state<R>(f: impl FnOnce(&mut Step37And38State) -> R) -> Result<R, ()> {
    if STEP37_38_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state transition `0 -> 1` grants exclusive mutable access for this synchronous scope.
    let result = f(unsafe { &mut *STEP37_38_STATE.value.get() });
    STEP37_38_STATE.state.store(0, Ordering::Release);
    Ok(result)
}

/// Returns `true` if `raw_fd` lies in the Step-37/38 descriptor window (`192..208`).
pub(super) const fn is_kmsg_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= KMSG_FD_BASE && fd < KMSG_FD_BASE + (MAX_KMSG_FDS as i32)
}

pub(super) fn is_open_kmsg_fd(process: ObjectId, raw_fd: u64) -> bool {
    if !is_kmsg_fd(raw_fd) {
        return false;
    }
    let idx = (linux_signed_int(raw_fd) - KMSG_FD_BASE) as usize;
    with_systemd_udev_state(|state| {
        let entry = &state.kmsg_fds[idx];
        entry.live && entry.owners.has_owner(process)
    })
    .unwrap_or(false)
}

pub(super) fn append_open_kmsg_fds(process: ObjectId, out: &mut alloc::vec::Vec<i32>) {
    let _ = with_systemd_udev_state(|state| {
        for (idx, entry) in state.kmsg_fds.iter().enumerate() {
            if entry.live && entry.owners.has_owner(process) {
                out.push(KMSG_FD_BASE + (idx as i32));
            }
        }
    });
}

fn is_kmsg_or_alias_fd(raw_fd: u64) -> bool {
    is_kmsg_fd(raw_fd)
        || super::step_fd_util::lookup_aliased_subsystem_current(raw_fd)
            .is_some_and(|h| h.kind == super::step_fd_util::SUBSYS_KMSG)
}

fn resolve_kmsg_slot(process: ObjectId, raw_fd: u64) -> Option<(usize, Option<u64>)> {
    if is_kmsg_fd(raw_fd) {
        return Some(((linux_signed_int(raw_fd) - KMSG_FD_BASE) as usize, None));
    }
    let handle = super::step_fd_util::lookup_aliased_subsystem(process, raw_fd)?;
    if handle.kind != super::step_fd_util::SUBSYS_KMSG {
        return None;
    }
    Some((usize::from(handle.slot), Some(handle.generation)))
}

fn kmsg_entry_authorized(entry: &KmsgFdEntry, owner: ObjectId, alias_gen: Option<u64>) -> bool {
    if !entry.live {
        return false;
    }
    match alias_gen {
        None => entry.owners.has_owner(owner),
        Some(expected_gen) => entry.generation == expected_gen && entry.alias_refs > 0,
    }
}

pub(super) fn retain_alias_handle(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(kernal_linux_fd::SubsystemHandle, u64), Errno> {
    if !is_kmsg_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let idx = (linux_signed_int(raw_fd) - KMSG_FD_BASE) as usize;
    with_systemd_udev_state(|state| {
        let entry = &mut state.kmsg_fds[idx];
        if !entry.live || !entry.owners.has_owner(process) {
            return Err(Errno::EBADF);
        }
        entry.alias_refs = entry.alias_refs.saturating_add(1);
        Ok((
            kernal_linux_fd::SubsystemHandle {
                kind: super::step_fd_util::SUBSYS_KMSG,
                slot: idx as u16,
                generation: entry.generation,
            },
            entry.status_flags(),
        ))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn retain_existing_handle(
    handle: kernal_linux_fd::SubsystemHandle,
) -> Result<(kernal_linux_fd::SubsystemHandle, u64), Errno> {
    if handle.kind != super::step_fd_util::SUBSYS_KMSG {
        return Err(Errno::EBADF);
    }
    let idx = usize::from(handle.slot);
    with_systemd_udev_state(|state| {
        let Some(entry) = state.kmsg_fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry.live || entry.generation != handle.generation || entry.alias_refs == 0 {
            return Err(Errno::EBADF);
        }
        entry.alias_refs = entry.alias_refs.saturating_add(1);
        Ok((handle, entry.status_flags()))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn release_alias_handle(handle: kernal_linux_fd::SubsystemHandle) {
    if handle.kind != super::step_fd_util::SUBSYS_KMSG {
        return;
    }
    let idx = usize::from(handle.slot);
    let _ = with_systemd_udev_state(|state| {
        if let Some(entry) = state.kmsg_fds.get_mut(idx)
            && entry.live
            && entry.generation == handle.generation
            && entry.alias_refs > 0
        {
            entry.alias_refs -= 1;
            retire_kmsg_slot_if_unused(state, idx);
        }
    });
}

pub(super) fn handle_native_fcntl(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    let (idx, alias_gen) = resolve_kmsg_slot(process, raw_fd)?;
    if alias_gen.is_some() && !matches!(cmd, 3 | 4) {
        return None;
    }
    let res = with_systemd_udev_state(|state| {
        let Some(entry) = state.kmsg_fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !kmsg_entry_authorized(entry, process, alias_gen) {
            return Err(Errno::EBADF);
        }
        match cmd {
            1 => Ok(i64::from(i32::from(
                entry.owners.get_cloexec(process).unwrap_or(false),
            ))),
            2 => {
                let _ = entry.owners.set_cloexec(process, (argi & 1) != 0);
                Ok(0)
            }
            3 => Ok(entry.status_flags() as i64),
            4 => {
                entry.nonblocking = (u64::from(argi as u32) & O_NONBLOCK) != 0;
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    });
    Some(res.unwrap_or(Err(Errno::EIO)))
}

fn retire_kmsg_slot_if_unused(state: &mut Step37And38State, idx: usize) {
    let entry = &state.kmsg_fds[idx];
    if entry.live && entry.owners.is_empty() && entry.alias_refs == 0 {
        state.kmsg_fds[idx] = KmsgFdEntry::EMPTY;
    }
}

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    let _ = with_systemd_udev_state(|state| {
        for entry in &mut state.kmsg_fds {
            if entry.live {
                entry.owners.on_fork(parent, child);
            }
        }
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    let _ = with_systemd_udev_state(|state| {
        for idx in 0..MAX_KMSG_FDS {
            if state.kmsg_fds[idx].live {
                state.kmsg_fds[idx].owners.close_cloexec_for(process);
                retire_kmsg_slot_if_unused(state, idx);
            }
        }
    });
}

pub(super) fn on_process_exit(process: ObjectId) {
    let _ = with_systemd_udev_state(|state| {
        for idx in 0..MAX_KMSG_FDS {
            if state.kmsg_fds[idx].live {
                let _ = state.kmsg_fds[idx].owners.close_owner(process);
                retire_kmsg_slot_if_unused(state, idx);
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
    let _ = with_systemd_udev_state(|state| {
        for idx in 0..MAX_KMSG_FDS {
            let fd = KMSG_FD_BASE + (idx as i32);
            if super::step_fd_util::fd_in_close_range(fd, first, last)
                && state.kmsg_fds[idx].live
                && state.kmsg_fds[idx]
                    .owners
                    .apply_close_range(process, cloexec_only)
            {
                retire_kmsg_slot_if_unused(state, idx);
            }
        }
    });
}

/// Maps a `/sys`-relative `uevent` trigger path to its logical device name (`vda`, `eth0`, `ttyAMA0`).
fn uevent_device_from_sysfs_rel(rel: &[u8]) -> Option<&'static [u8]> {
    match rel {
        b"class/block/vda/uevent" | b"devices/virtio0/block/vda/uevent" => Some(b"vda"),
        b"class/net/eth0/uevent" | b"devices/virtio1/net/eth0/uevent" => Some(b"eth0"),
        b"class/tty/ttyAMA0/uevent" | b"devices/platform/pl011/tty/ttyAMA0/uevent" => {
            Some(b"ttyAMA0")
        }
        _ => None,
    }
}

/// Reports whether `rel` under `/sys` is a writable `systemd-udev-trigger` `uevent` file.
pub(super) fn is_sysfs_uevent_trigger_rel(rel: &[u8]) -> bool {
    uevent_device_from_sysfs_rel(rel).is_some()
}

/// Synthesizes `/sys/class/...`, `/sys/devices/...`, and `/sys/kernel/uevent_seqnum` attributes
/// from the live Step-38 device registry.
pub(super) fn read_sysfs_device_attr(rel_path: &[u8], out: &mut [u8]) -> Result<usize, Errno> {
    with_systemd_udev_state(|state| {
        state.ensure_initialized();
        state.udev.read_sysfs_device_attr(rel_path, out)
    })
    .map_err(|()| Errno::EIO)?
}

/// Broadcasts a formatted `NETLINK_KOBJECT_UEVENT` packet for `dev_name` to all bound udev sockets.
pub(super) fn emit_device_uevent(dev_name: &[u8], action: UeventAction) -> Result<usize, Errno> {
    emit_device_uevent_with_uuid(dev_name, action, None)
}

fn emit_device_uevent_with_uuid(
    dev_name: &[u8],
    action: UeventAction,
    synth_uuid: Option<&[u8]>,
) -> Result<usize, Errno> {
    let mut pkt = [0u8; 320];
    let len = with_systemd_udev_state(|state| {
        state.ensure_initialized();
        state
            .udev
            .emit_uevent_with_uuid(dev_name, action, synth_uuid, &mut pkt)
    })
    .map_err(|()| Errno::EIO)??;
    let delivered =
        super::step34_net::broadcast_netlink_uevent(&pkt[..len]).map_err(|()| Errno::EIO)?;
    Ok(delivered)
}

/// Dispatches Step-37 (`/dev/kmsg`, `reboot(2)`, `sysinfo(2)`) and Step-38 (sysfs `uevent`
/// trigger) syscalls on AArch64.
pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        NR_OPENAT => handle_openat_if_kmsg_or_uevent(request.args[1], request.args[2]),
        NR_CLOSE if is_kmsg_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_kmsg_close(request.args[0])?)))
        }
        NR_LSEEK if is_kmsg_or_alias_fd(request.args[0]) => Ok(Some(encode_result(
            handle_kmsg_lseek(request.args[0], request.args[1], request.args[2])?,
        ))),
        NR_READ if is_kmsg_or_alias_fd(request.args[0]) => Ok(Some(encode_result(
            handle_kmsg_read(request.args[0], request.args[1], request.args[2])?,
        ))),
        NR_WRITE if is_kmsg_or_alias_fd(request.args[0]) => Ok(Some(encode_result(
            handle_kmsg_write(request.args[0], request.args[1], request.args[2])?,
        ))),
        NR_READV if is_kmsg_or_alias_fd(request.args[0]) => Ok(Some(encode_result(
            handle_kmsg_readv(request.args[0], request.args[1], request.args[2])?,
        ))),
        NR_WRITEV if is_kmsg_or_alias_fd(request.args[0]) => Ok(Some(encode_result(
            handle_kmsg_writev(request.args[0], request.args[1], request.args[2])?,
        ))),
        NR_NEWFSTATAT => handle_newfstatat_if_kmsg(request.args[1], request.args[2]),
        NR_FSTAT if is_kmsg_or_alias_fd(request.args[0]) => Ok(Some(encode_result(
            handle_kmsg_fstat(request.args[0], request.args[1])?,
        ))),
        NR_REBOOT => Ok(Some(encode_result(handle_reboot(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        NR_SYSINFO => Ok(Some(encode_result(handle_sysinfo(request.args[0])?))),
        _ => Ok(None),
    }
}

fn encode_result(res: Result<i64, Errno>) -> SyscallReturn {
    match res {
        Ok(val) => SyscallReturn::success(val).unwrap_or(SyscallReturn::error(Errno::EINVAL)),
        Err(errno) => SyscallReturn::error(errno),
    }
}

fn handle_openat_if_kmsg_or_uevent(
    user_path: u64,
    raw_flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Some(path_len) = read_short_user_path(user_path, &mut path_buf) else {
        return Ok(None);
    };
    try_open_kmsg_or_uevent_bytes(&path_buf[..path_len], raw_flags)
}

pub(super) fn try_open_kmsg_or_uevent_bytes(
    path: &[u8],
    raw_flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let is_path = (raw_flags & O_PATH) != 0;
    let acc = raw_flags & O_ACCMODE;
    let kind = if path == b"/dev/kmsg" {
        if (raw_flags & O_DIRECTORY) != 0 {
            return Ok(Some(SyscallReturn::error(Errno::ENOTDIR)));
        }
        let (can_read, can_write) = if is_path {
            (false, false)
        } else {
            match acc {
                O_RDONLY => (true, false),
                O_WRONLY => (false, true),
                O_RDWR => (true, true),
                _ => return Ok(Some(SyscallReturn::error(Errno::EINVAL))),
            }
        };
        Step37FdKind::Kmsg {
            offset: 0,
            can_read,
            can_write,
        }
    } else if !is_path
        && acc != O_RDONLY
        && let Some(sys_rel) = path.strip_prefix(b"/sys/")
        && let Some(dev_name) = uevent_device_from_sysfs_rel(sys_rel)
    {
        if (raw_flags & O_DIRECTORY) != 0 {
            return Ok(Some(SyscallReturn::error(Errno::ENOTDIR)));
        }
        let mut name_buf = [0u8; 16];
        name_buf[..dev_name.len()].copy_from_slice(dev_name);
        Step37FdKind::UeventTrigger {
            dev_name: name_buf,
            dev_len: dev_name.len(),
        }
    } else {
        return Ok(None);
    };

    let owner = current_process_id()?;
    let cloexec = (raw_flags & O_CLOEXEC) != 0;
    let nonblocking = !is_path && (raw_flags & O_NONBLOCK) != 0;
    let res = with_systemd_udev_state(|state| {
        state.ensure_initialized();
        let Some((idx, _)) = state.kmsg_fds.iter().enumerate().find(|(_, e)| !e.live) else {
            return Err(Errno::EMFILE);
        };
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1).max(1);
        let mut owners = super::step_fd_util::DirectProcessRefs::empty();
        owners.init(owner, cloexec);
        state.kmsg_fds[idx] = KmsgFdEntry {
            live: true,
            generation,
            alias_refs: 0,
            nonblocking,
            owners,
            kind,
        };
        Ok(i64::from(KMSG_FD_BASE + (idx as i32)))
    })?;
    Ok(Some(encode_result(res)))
}

fn handle_kmsg_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = (linux_signed_int(raw_fd) - KMSG_FD_BASE) as usize;
    let owner = current_process_id()?;
    with_systemd_udev_state(|state| {
        let entry = &mut state.kmsg_fds[idx];
        if !entry.live || !entry.owners.close_owner(owner) {
            return Err(Errno::EBADF);
        }
        retire_kmsg_slot_if_unused(state, idx);
        Ok(0)
    })
}

fn handle_kmsg_lseek(
    raw_fd: u64,
    raw_offset: u64,
    raw_whence: u64,
) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_kmsg_slot(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let offset_arg = raw_offset as i64;
    let whence = linux_unsigned_int(raw_whence) as i64;
    with_systemd_udev_state(|state| {
        state.ensure_initialized();
        let total = state.pid1.kmsg_bytes().len() as i64;
        let Some(entry) = state.kmsg_fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !kmsg_entry_authorized(entry, owner, alias_gen) {
            return Err(Errno::EBADF);
        }
        let Step37FdKind::Kmsg { offset, .. } = &mut entry.kind else {
            return Err(Errno::ESPIPE);
        };
        let target = match whence {
            SEEK_SET => offset_arg,
            SEEK_CUR => (*offset as i64).saturating_add(offset_arg),
            SEEK_END => total.saturating_add(offset_arg),
            _ => return Err(Errno::EINVAL),
        };
        if target < 0 || target > total {
            return Err(Errno::EINVAL);
        }
        *offset = target as usize;
        Ok(target)
    })
}

fn handle_kmsg_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_kmsg_slot(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let requested = usize::try_from(count).unwrap_or(KMSG_CAP).min(KMSG_CAP);
    let mut tmp = [0u8; KMSG_CAP];
    let take_res = with_systemd_udev_state(|state| {
        state.ensure_initialized();
        let entry = state.kmsg_fds[idx];
        if !kmsg_entry_authorized(&entry, owner, alias_gen) {
            return Err(Errno::EBADF);
        }
        let Step37FdKind::Kmsg {
            offset,
            can_read,
            can_write,
        } = entry.kind
        else {
            return Err(Errno::EBADF);
        };
        if !can_read {
            return Err(Errno::EBADF);
        }
        let bytes = state.pid1.kmsg_bytes();
        let avail = bytes.len().saturating_sub(offset);
        let take = requested.min(avail);
        tmp[..take].copy_from_slice(&bytes[offset..offset + take]);
        state.kmsg_fds[idx].kind = Step37FdKind::Kmsg {
            offset: offset + take,
            can_read,
            can_write,
        };
        Ok(take)
    })?;
    let take = match take_res {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    if take > 0 {
        if user_buf == 0 {
            return Ok(Err(Errno::EFAULT));
        }
        if let Err(e) = copy_to_user(user_buf, &tmp[..take]) {
            return Ok(Err(e));
        }
    }
    Ok(Ok(take as i64))
}

fn handle_kmsg_readv(
    raw_fd: u64,
    user_iov: u64,
    raw_iovcnt: u64,
) -> Result<Result<i64, Errno>, ()> {
    let iovcnt = linux_signed_int(raw_iovcnt);
    if !(0..=1024).contains(&iovcnt) {
        return Ok(Err(Errno::EINVAL));
    }
    for index in 0..(iovcnt as usize) {
        let (base, len) = match super::step_fd_util::read_user_iovec(user_iov, index) {
            Ok(pair) => pair,
            Err(e) => return Ok(Err(e)),
        };
        if len > 0 {
            return handle_kmsg_read(raw_fd, base, len as u64);
        }
    }
    Ok(Ok(0))
}

fn handle_kmsg_writev(
    raw_fd: u64,
    user_iov: u64,
    raw_iovcnt: u64,
) -> Result<Result<i64, Errno>, ()> {
    let iovcnt = linux_signed_int(raw_iovcnt);
    if !(0..=1024).contains(&iovcnt) {
        return Ok(Err(Errno::EINVAL));
    }
    let mut msg = [0u8; 256];
    let mut captured = 0usize;
    let mut total = 0usize;
    for index in 0..(iovcnt as usize) {
        let (base, seg_len) = match super::step_fd_util::read_user_iovec(user_iov, index) {
            Ok(pair) => pair,
            Err(e) => return Ok(Err(e)),
        };
        total = total.saturating_add(seg_len);
        if seg_len == 0 || captured >= msg.len() {
            continue;
        }
        let take = seg_len.min(msg.len() - captured);
        if let Err(e) = copy_from_user(&mut msg[captured..captured + take], base) {
            return Ok(Err(e));
        }
        captured += take;
    }
    handle_kmsg_write_bytes(raw_fd, &msg[..captured], total)
}

fn handle_kmsg_write(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let requested = usize::try_from(count).unwrap_or(256).min(256);
    let mut msg = [0u8; 256];
    if requested > 0 {
        if user_buf == 0 {
            return Ok(Err(Errno::EFAULT));
        }
        if let Err(e) = copy_from_user(&mut msg[..requested], user_buf) {
            return Ok(Err(e));
        }
    }
    handle_kmsg_write_bytes(raw_fd, &msg[..requested], requested)
}

fn handle_kmsg_write_bytes(
    raw_fd: u64,
    msg: &[u8],
    report_len: usize,
) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_kmsg_slot(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let trimmed_len = msg
        .iter()
        .position(|&b| b == b'\n' || b == b'\r' || b == 0)
        .unwrap_or(msg.len())
        .min(256);
    enum WriteTarget {
        Kmsg,
        Uevent {
            dev_name: [u8; 16],
            dev_len: usize,
            action: UeventAction,
            synth_uuid: [u8; 64],
            synth_uuid_len: usize,
        },
    }
    let action_res = with_systemd_udev_state(|state| {
        state.ensure_initialized();
        let entry = state.kmsg_fds[idx];
        if !kmsg_entry_authorized(&entry, owner, alias_gen) {
            return Err(Errno::EBADF);
        }
        match entry.kind {
            Step37FdKind::Kmsg { can_write, .. } => {
                if !can_write {
                    return Err(Errno::EBADF);
                }
                state.pid1.write_kmsg(6, b"userspace", &msg[..trimmed_len]);
                Ok(WriteTarget::Kmsg)
            }
            Step37FdKind::UeventTrigger { dev_name, dev_len } => {
                let raw = &msg[..trimmed_len];
                let trimmed = raw
                    .iter()
                    .rposition(|&b| b != b' ' && b != b'\t')
                    .map_or(&raw[..0], |end| &raw[..=end]);
                let (action_bytes, uuid_bytes) =
                    match trimmed.iter().position(|&b| b == b' ' || b == b'\t') {
                        Some(sp) => (&trimmed[..sp], trimmed[sp + 1..].trim_ascii_start()),
                        None => (trimmed, &trimmed[..0]),
                    };
                let action = match action_bytes {
                    b"add" => UeventAction::Add,
                    b"remove" => UeventAction::Remove,
                    b"change" => UeventAction::Change,
                    _ => return Err(Errno::EINVAL),
                };
                let mut synth_uuid = [0u8; 64];
                let synth_uuid_len = uuid_bytes.len().min(synth_uuid.len());
                synth_uuid[..synth_uuid_len].copy_from_slice(&uuid_bytes[..synth_uuid_len]);
                Ok(WriteTarget::Uevent {
                    dev_name,
                    dev_len,
                    action,
                    synth_uuid,
                    synth_uuid_len,
                })
            }
        }
    })?;
    let target = match action_res {
        Ok(t) => t,
        Err(e) => return Ok(Err(e)),
    };
    if let WriteTarget::Uevent {
        dev_name,
        dev_len,
        action,
        synth_uuid,
        synth_uuid_len,
    } = target
    {
        if let Err(e) = if synth_uuid_len > 0 {
            emit_device_uevent_with_uuid(
                &dev_name[..dev_len],
                action,
                Some(&synth_uuid[..synth_uuid_len]),
            )
        } else {
            emit_device_uevent(&dev_name[..dev_len], action)
        } {
            return Ok(Err(e));
        }
    }
    Ok(Ok(report_len as i64))
}

fn handle_newfstatat_if_kmsg(user_path: u64, user_stat: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Some(path_len) = read_short_user_path(user_path, &mut path_buf) else {
        return Ok(None);
    };
    if &path_buf[..path_len] != b"/dev/kmsg" {
        return Ok(None);
    }
    Ok(Some(encode_result(write_kmsg_stat(user_stat))))
}

fn handle_kmsg_fstat(raw_fd: u64, user_stat: u64) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_kmsg_slot(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let kind_opt = with_systemd_udev_state(|state| {
        let entry = &state.kmsg_fds[idx];
        kmsg_entry_authorized(entry, owner, alias_gen).then_some(entry.kind)
    })?;
    let Some(kind) = kind_opt else {
        return Ok(Err(Errno::EBADF));
    };
    match kind {
        Step37FdKind::Kmsg { .. } => Ok(write_kmsg_stat(user_stat)),
        Step37FdKind::UeventTrigger { .. } => {
            if user_stat == 0 {
                return Ok(Err(Errno::EFAULT));
            }
            let (dev, _, _, mnt_id) = super::step33_mounts::dev_and_mnt_id_for_fstype(
                kernal_linux_mounts::FilesystemType::Sysfs,
            );
            let meta = super::step_fd_util::StatMeta {
                dev,
                ino: (1u64 << 61) | 0x7565,
                mode: 0o100_644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
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
            };
            Ok(super::step_fd_util::write_aarch64_stat_meta(
                user_stat, &meta,
            ))
        }
    }
}

fn kmsg_stat_meta() -> super::step_fd_util::StatMeta {
    let (dev, _, _, mnt_id) = super::step33_mounts::dev_and_mnt_id_for_fstype(
        kernal_linux_mounts::FilesystemType::Devtmpfs,
    );
    super::step_fd_util::StatMeta {
        dev,
        ino: (1u64 << 61) | KMSG_RDEV,
        mode: S_IFCHR_MODE,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: KMSG_RDEV,
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

pub(super) fn try_stat_kmsg_bytes(
    path: &[u8],
    user_stat: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if path != b"/dev/kmsg" {
        return Ok(None);
    }
    Ok(Some(encode_result(write_kmsg_stat(user_stat))))
}

pub(super) fn try_statx_kmsg_bytes(
    path: &[u8],
    user_statx: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if path != b"/dev/kmsg" {
        return Ok(None);
    }
    let meta = kmsg_stat_meta();
    Ok(Some(encode_result(
        super::step_fd_util::write_aarch64_statx_meta(user_statx, &meta),
    )))
}

fn write_kmsg_stat(user_stat: u64) -> Result<i64, Errno> {
    if user_stat == 0 {
        return Err(Errno::EFAULT);
    }
    let meta = kmsg_stat_meta();
    super::step_fd_util::write_aarch64_stat_meta(user_stat, &meta)
}

fn handle_reboot(raw_magic1: u64, raw_magic2: u64, raw_cmd: u64) -> Result<Result<i64, Errno>, ()> {
    let magic1 = linux_unsigned_int(raw_magic1);
    let magic2 = linux_unsigned_int(raw_magic2);
    let cmd = linux_unsigned_int(raw_cmd);
    let cap_boot = super::step35_events_cgroup::has_effective_capability(CAP_SYS_BOOT)?;
    let is_root = current_euid().unwrap_or(0) == 0;
    let action = with_systemd_udev_state(|state| {
        state.ensure_initialized();
        state
            .pid1
            .execute_reboot(magic1, magic2, cmd, cap_boot && is_root)
    })?;
    let action = match action {
        Ok(a) => a,
        Err(e) => return Ok(Err(e)),
    };
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    match action {
        RebootAction::PowerOff | RebootAction::Halt => {
            if let Some(serial) = super::step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 37 reboot(POWER_OFF) via PSCI\n");
            }
            // SAFETY: CAP_SYS_BOOT + euid==0 + LINUX_REBOOT_MAGIC* validated before PSCI poweroff.
            let _ = unsafe {
                kernal_psci_aarch64::Psci::new(kernal_psci_aarch64::Conduit::Hvc).system_off()
            };
        }
        RebootAction::Restart => {
            if let Some(serial) = super::step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 37 reboot(RESTART) via PSCI\n");
            }
            // SAFETY: CAP_SYS_BOOT + euid==0 + LINUX_REBOOT_MAGIC* validated before PSCI reset.
            let _ = unsafe {
                kernal_psci_aarch64::Psci::new(kernal_psci_aarch64::Conduit::Hvc).system_reset()
            };
        }
        RebootAction::CadEnable(_) => {}
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    let _ = action;
    Ok(Ok(0))
}

fn handle_sysinfo(user_info: u64) -> Result<Result<i64, Errno>, ()> {
    if user_info == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let payload = encode_sysinfo_64(1, 65536, 52428, 1);
    if let Err(e) = copy_to_user(user_info, &payload) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn read_short_user_path(user_path: u64, buf: &mut [u8]) -> Option<usize> {
    if user_path == 0 {
        return None;
    }
    for (idx, slot) in buf.iter_mut().enumerate() {
        let addr = user_path.checked_add(idx as u64)?;
        let mut byte = [0u8; 1];
        if kernal_usercopy_aarch64::copy_from_user(&mut byte, addr).is_err() {
            return None;
        }
        if byte[0] == 0 {
            return Some(idx);
        }
        *slot = byte[0];
    }
    None
}

fn current_process_id() -> Result<ObjectId, ()> {
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
        Ok(process.id())
    })
    .map_err(|_| ())?
}

fn current_euid() -> Option<u32> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu)?;
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.ok()?;
    let mut uid = 0u32;
    let _ = super::runtime::with_linux_runtime(|state| {
        let _ = state.with_current_process_credentials(current, |proc_ref, credentials| {
            if let Ok(creds) = credentials.credentials(proc_ref) {
                uid = creds.euid();
            }
        });
    });
    Some(uid)
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
    fn kmsg_fd_window_is_disjoint_from_earlier_subsystems() {
        assert!(!is_kmsg_fd(0));
        assert!(!is_kmsg_fd(64));
        assert!(!is_kmsg_fd(96));
        assert!(!is_kmsg_fd(128));
        assert!(!is_kmsg_fd(160));
        assert!(is_kmsg_fd(KMSG_FD_BASE as u64));
        assert!(is_kmsg_fd((KMSG_FD_BASE + 15) as u64));
        assert!(!is_kmsg_fd((KMSG_FD_BASE + 16) as u64));
    }

    #[test]
    fn sysfs_device_attr_reports_vda_and_uevent_seqnum() {
        let mut buf = [0u8; 64];
        let n = read_sysfs_device_attr(b"class/block/vda/dev", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"254:0\n");
        let s = read_sysfs_device_attr(b"kernel/uevent_seqnum", &mut buf).unwrap();
        assert!(s >= 2);
    }

    #[test]
    fn sysfs_uevent_trigger_paths_map_expected_devices() {
        assert!(is_sysfs_uevent_trigger_rel(b"class/block/vda/uevent"));
        assert!(is_sysfs_uevent_trigger_rel(
            b"devices/virtio1/net/eth0/uevent"
        ));
        assert!(!is_sysfs_uevent_trigger_rel(b"class/block/vda/dev"));
    }
}
