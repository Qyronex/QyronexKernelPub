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
use kernal_usercopy::Error as UsercopyError;

/// Dedicated file-descriptor base for Step-37 `/dev/kmsg` and Step-38 sysfs `uevent` trigger
/// descriptors (`192..208`), partitioned cleanly above `EVENT_FD_BASE` (`160..192`).
pub(super) const KMSG_FD_BASE: i32 = 192;
const MAX_KMSG_FDS: usize = 16;
const MAX_SERVICES: usize = 16;
const KMSG_CAP: usize = 1024;
const MAX_DEVS: usize = 16;

const ARM64_STAT_BYTES: usize = 128;
const S_IFCHR_MODE: u32 = 0o020_644;
const KMSG_RDEV: u64 = (1u64 << 8) | 11u64; // makedev(1, 11) for /dev/kmsg

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;

const SEEK_SET: i64 = 0;
const SEEK_CUR: i64 = 1;
const SEEK_END: i64 = 2;

const NR_OPENAT: u64 = 56;
const NR_CLOSE: u64 = 57;
const NR_LSEEK: u64 = 62;
const NR_READ: u64 = 63;
const NR_WRITE: u64 = 64;
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
    owner_process: ObjectId,
    kind: Step37FdKind,
}

impl KmsgFdEntry {
    const EMPTY: Self = Self {
        live: false,
        owner_process: ObjectId(0),
        kind: Step37FdKind::Kmsg {
            offset: 0,
            can_read: false,
            can_write: false,
        },
    };
}

struct Step37And38State {
    initialized: bool,
    pid1: Pid1Orchestrator<MAX_SERVICES, KMSG_CAP>,
    udev: UdevDeviceRegistry<MAX_DEVS>,
    kmsg_fds: [KmsgFdEntry; MAX_KMSG_FDS],
}

impl Step37And38State {
    const fn new() -> Self {
        Self {
            initialized: false,
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
    let mut pkt = [0u8; 256];
    let len = with_systemd_udev_state(|state| {
        state.ensure_initialized();
        state.udev.format_uevent(dev_name, action, &mut pkt)
    })
    .map_err(|()| Errno::EIO)??;
    super::step34_net::broadcast_netlink_uevent(&pkt[..len]).map_err(|()| Errno::EIO)
}

/// Dispatches Step-37 (`/dev/kmsg`, `reboot(2)`, `sysinfo(2)`) and Step-38 (sysfs `uevent`
/// trigger) syscalls on AArch64.
pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        NR_OPENAT => handle_openat_if_kmsg_or_uevent(request.args[1], request.args[2]),
        NR_CLOSE if is_kmsg_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_kmsg_close(request.args[0])?)))
        }
        NR_LSEEK if is_kmsg_fd(request.args[0]) => Ok(Some(encode_result(handle_kmsg_lseek(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        NR_READ if is_kmsg_fd(request.args[0]) => Ok(Some(encode_result(handle_kmsg_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        NR_WRITE if is_kmsg_fd(request.args[0]) => Ok(Some(encode_result(handle_kmsg_write(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        NR_NEWFSTATAT => handle_newfstatat_if_kmsg(request.args[1], request.args[2]),
        NR_FSTAT if is_kmsg_fd(request.args[0]) => Ok(Some(encode_result(handle_kmsg_fstat(
            request.args[0],
            request.args[1],
        )?))),
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
    let path = &path_buf[..path_len];

    let acc = raw_flags & O_ACCMODE;
    let kind = if path == b"/dev/kmsg" {
        let (can_read, can_write) = match acc {
            O_RDONLY => (true, false),
            O_WRONLY => (false, true),
            O_RDWR => (true, true),
            _ => return Ok(Some(SyscallReturn::error(Errno::EINVAL))),
        };
        Step37FdKind::Kmsg {
            offset: 0,
            can_read,
            can_write,
        }
    } else if acc != O_RDONLY
        && let Some(sys_rel) = path.strip_prefix(b"/sys/")
        && let Some(dev_name) = uevent_device_from_sysfs_rel(sys_rel)
    {
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
    let res = with_systemd_udev_state(|state| {
        state.ensure_initialized();
        let Some((idx, slot)) = state
            .kmsg_fds
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| !entry.live)
        else {
            return Err(Errno::EMFILE);
        };
        *slot = KmsgFdEntry {
            live: true,
            owner_process: owner,
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
        if !entry.live || entry.owner_process != owner {
            return Err(Errno::EBADF);
        }
        *entry = KmsgFdEntry::EMPTY;
        Ok(0)
    })
}

fn handle_kmsg_lseek(
    raw_fd: u64,
    raw_offset: u64,
    raw_whence: u64,
) -> Result<Result<i64, Errno>, ()> {
    let idx = (linux_signed_int(raw_fd) - KMSG_FD_BASE) as usize;
    let owner = current_process_id()?;
    let offset_arg = raw_offset as i64;
    let whence = linux_unsigned_int(raw_whence) as i64;
    with_systemd_udev_state(|state| {
        state.ensure_initialized();
        let total = state.pid1.kmsg_bytes().len() as i64;
        let entry = &mut state.kmsg_fds[idx];
        if !entry.live || entry.owner_process != owner {
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
    let idx = (linux_signed_int(raw_fd) - KMSG_FD_BASE) as usize;
    let owner = current_process_id()?;
    let requested = usize::try_from(count).unwrap_or(KMSG_CAP).min(KMSG_CAP);
    let mut tmp = [0u8; KMSG_CAP];
    let take_res = with_systemd_udev_state(|state| {
        state.ensure_initialized();
        let entry = state.kmsg_fds[idx];
        if !entry.live || entry.owner_process != owner {
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

fn handle_kmsg_write(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = (linux_signed_int(raw_fd) - KMSG_FD_BASE) as usize;
    let owner = current_process_id()?;
    let requested = usize::try_from(count).unwrap_or(128).min(128);
    let mut msg = [0u8; 128];
    if requested > 0 {
        if user_buf == 0 {
            return Ok(Err(Errno::EFAULT));
        }
        if let Err(e) = copy_from_user(&mut msg[..requested], user_buf) {
            return Ok(Err(e));
        }
    }
    let trimmed_len = msg[..requested]
        .iter()
        .position(|&b| b == b'\n' || b == b'\r' || b == 0)
        .unwrap_or(requested);
    enum WriteTarget {
        Kmsg,
        Uevent {
            dev_name: [u8; 16],
            dev_len: usize,
            action: UeventAction,
        },
    }
    let action_res = with_systemd_udev_state(|state| {
        state.ensure_initialized();
        let entry = state.kmsg_fds[idx];
        if !entry.live || entry.owner_process != owner {
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
                let action = match &msg[..trimmed_len] {
                    b"add" => UeventAction::Add,
                    b"remove" => UeventAction::Remove,
                    b"change" => UeventAction::Change,
                    _ => return Err(Errno::EINVAL),
                };
                Ok(WriteTarget::Uevent {
                    dev_name,
                    dev_len,
                    action,
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
    } = target
        && let Err(e) = emit_device_uevent(&dev_name[..dev_len], action)
    {
        return Ok(Err(e));
    }
    Ok(Ok(requested as i64))
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
    let idx = (linux_signed_int(raw_fd) - KMSG_FD_BASE) as usize;
    let owner = current_process_id()?;
    let live = with_systemd_udev_state(|state| {
        let entry = state.kmsg_fds[idx];
        entry.live && entry.owner_process == owner
    })?;
    if !live {
        return Ok(Err(Errno::EBADF));
    }
    Ok(write_kmsg_stat(user_stat))
}

fn write_kmsg_stat(user_stat: u64) -> Result<i64, Errno> {
    if user_stat == 0 {
        return Err(Errno::EFAULT);
    }
    let mut stat = [0u8; ARM64_STAT_BYTES];
    let ino = (1u64 << 61) | KMSG_RDEV;
    stat[0..8].copy_from_slice(&5u64.to_le_bytes()); // st_dev (devtmpfs)
    stat[8..16].copy_from_slice(&ino.to_le_bytes()); // st_ino
    stat[16..20].copy_from_slice(&S_IFCHR_MODE.to_le_bytes()); // st_mode (S_IFCHR | 0644)
    stat[20..24].copy_from_slice(&1u32.to_le_bytes()); // st_nlink
    stat[32..40].copy_from_slice(&KMSG_RDEV.to_le_bytes()); // st_rdev = makedev(1, 11)
    stat[56..60].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize
    copy_to_user(user_stat, &stat)?;
    Ok(0)
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
        let _ = state.with_current_process_credentials(current, |creds| {
            uid = creds.euid();
        });
    });
    Some(uid)
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
