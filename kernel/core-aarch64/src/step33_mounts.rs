// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::ObjectId;
use kernal_linux_abi::{Errno, SyscallRequest, SyscallReturn, linux_signed_int};
use kernal_linux_mounts::{
    Ext4WriteJournal, FilesystemType, MAX_MOUNT_PATH, MountTable, ProcSysSnapshot,
    read_procfs_node, read_sysfs_node,
};
use kernal_usercopy::Error as UsercopyError;

/// Dedicated file-descriptor base for Step-33 `/proc` and `/sys` virtual nodes (`96..128`),
/// partitioned cleanly above `STEP29_RUNTIME_FDS` (`0..32`) and `DEV_FD_BASE` (`64..96`).
pub(super) const PROC_SYS_FD_BASE: i32 = 96;
const MAX_PROC_SYS_FDS: usize = 16;
const MAX_MOUNTS: usize = 16;
const MAX_JOURNAL_ENTRIES: usize = 16;
const MAX_JOURNAL_DATA: usize = 256;
const MAX_VIRTUAL_NODE_BYTES: usize = 512;
const MAX_HOSTNAME_BYTES: usize = 64;
const ARM64_STAT_BYTES: usize = 128;
const ARM64_STATFS_BYTES: usize = 120;
const S_IFREG_RO_MODE: u32 = 0o100_444;

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_CLOEXEC: u64 = 0x0008_0000;

const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

#[derive(Clone, Copy)]
struct ProcSysFdEntry {
    live: bool,
    owner_process: ObjectId,
    fstype: FilesystemType,
    close_on_exec: bool,
    offset: usize,
    len: usize,
    data: [u8; MAX_VIRTUAL_NODE_BYTES],
}

impl ProcSysFdEntry {
    const EMPTY: Self = Self {
        live: false,
        owner_process: ObjectId(0),
        fstype: FilesystemType::Procfs,
        close_on_exec: false,
        offset: 0,
        len: 0,
        data: [0u8; MAX_VIRTUAL_NODE_BYTES],
    };
}

struct Step33MountState {
    initialized: bool,
    mounts: MountTable<MAX_MOUNTS>,
    fds: [ProcSysFdEntry; MAX_PROC_SYS_FDS],
    journal: Ext4WriteJournal<MAX_JOURNAL_ENTRIES, MAX_JOURNAL_DATA>,
    hostname: [u8; MAX_HOSTNAME_BYTES],
    hostname_len: usize,
    boot_id_seed: [u8; 16],
}

impl Step33MountState {
    const fn new() -> Self {
        let mut hostname = [0u8; MAX_HOSTNAME_BYTES];
        hostname[0] = b'q';
        hostname[1] = b'y';
        hostname[2] = b'r';
        hostname[3] = b'o';
        hostname[4] = b'n';
        hostname[5] = b'e';
        hostname[6] = b'x';
        Self {
            initialized: false,
            mounts: MountTable::new(),
            fds: [ProcSysFdEntry::EMPTY; MAX_PROC_SYS_FDS],
            journal: Ext4WriteJournal::new(),
            hostname,
            hostname_len: 7,
            boot_id_seed: [
                0x4b, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x51, 0x79, 0x72, 0x6f, 0x6e, 0x65, 0x78, 0x33,
                0x33, 0x01,
            ],
        }
    }

    fn ensure_initialized(&mut self) {
        if self.initialized {
            return;
        }
        let _ = self.mounts.seed_default_hierarchy();
        let mut random_seed = [0u8; 16];
        if super::entropy::fill_getrandom(&mut random_seed).is_ok() {
            self.boot_id_seed = random_seed;
        }
        self.initialized = true;
    }
}

struct Step33MountCell {
    state: AtomicU8,
    value: UnsafeCell<Step33MountState>,
}

// SAFETY: access is serialized by the atomic state transition (`0 -> 1 -> 0`) inside the IRQ-masked
// synchronous lower-EL trap window.
unsafe impl Sync for Step33MountCell {}

static MOUNT_STATE: Step33MountCell = Step33MountCell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step33MountState::new()),
};

fn with_mount_state<R>(f: impl FnOnce(&mut Step33MountState) -> R) -> Result<R, ()> {
    if MOUNT_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state transition `0 -> 1` grants exclusive mutable access for this synchronous scope.
    let result = f(unsafe { &mut *MOUNT_STATE.value.get() });
    MOUNT_STATE.state.store(0, Ordering::Release);
    Ok(result)
}

/// Returns `true` if `raw_fd` lies in the Step-33 `/proc` & `/sys` descriptor window.
pub(super) const fn is_proc_sys_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= PROC_SYS_FD_BASE && fd < PROC_SYS_FD_BASE + (MAX_PROC_SYS_FDS as i32)
}

/// Intercepts Step-33 mount/filesystem syscalls (`umount2`, `mount`, `pivot_root`, `statfs`,
/// `fstatfs`, `sync`, `fsync`, `fdatasync`, `syncfs`, `sethostname`) and `/proc` + `/sys`
/// virtual-node file operations (`openat`, `close`, `lseek`, `read`, `newfstatat`, `fstat`).
pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        // umount2(target, flags)
        39 => Ok(Some(encode_result(handle_umount2(
            request.args[0],
            request.args[1],
        )?))),
        // mount(source, target, filesystemtype, mountflags, data)
        40 => Ok(Some(encode_result(handle_mount(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        // pivot_root(new_root, put_old)
        41 => Ok(Some(encode_result(handle_pivot_root(
            request.args[0],
            request.args[1],
        )?))),
        // statfs(path, buf)
        43 => Ok(Some(encode_result(handle_statfs(
            request.args[0],
            request.args[1],
        )?))),
        // fstatfs(fd, buf)
        44 => Ok(Some(encode_result(handle_fstatfs(
            request.args[0],
            request.args[1],
        )?))),
        // openat(dirfd, pathname, flags, mode)
        56 => handle_openat_if_proc_or_sys(request.args[1], request.args[2]),
        // close(fd)
        57 if is_proc_sys_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        // lseek(fd, offset, whence)
        62 if is_proc_sys_fd(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            linux_signed_int(request.args[2]),
        )?))),
        // read(fd, buf, count)
        63 if is_proc_sys_fd(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // newfstatat(dirfd, pathname, statbuf, flags)
        79 => handle_newfstatat_if_proc_or_sys(request.args[1], request.args[2]),
        // fstat(fd, statbuf)
        80 if is_proc_sys_fd(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        // sync()
        81 => Ok(Some(encode_result(handle_sync()?))),
        // fsync(fd) | fdatasync(fd) | syncfs(fd)
        82 | 83 | 267 => Ok(Some(encode_result(handle_fsync(request.args[0])?))),
        // sethostname(name, len)
        161 => Ok(Some(encode_result(handle_sethostname(
            request.args[0],
            request.args[1],
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

fn build_live_snapshot(hostname: &[u8], boot_id_seed: [u8; 16]) -> ProcSysSnapshot<'_> {
    let mut pid = 1u32;
    let mut ppid = 0u32;
    let mut pgid = 1u32;
    let mut sid = 1u32;
    let mut uid = 0u32;
    let mut gid = 0u32;

    let current_cpu = super::super::current_cpu_index();
    if let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) {
        // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
        if let Ok(current) = unsafe { scheduler.bootstrap_current_global_thread() } {
            let _ = super::runtime::with_linux_runtime(|state| {
                let _ = state.with_current_process_identity(current, |proc_ref, identities| {
                    if let Ok(p) = identities.bound_pid(proc_ref) {
                        pid = p.get();
                    }
                    if let Ok(pp) = identities.getppid(proc_ref) {
                        ppid = pp;
                    }
                    if let Ok(pg) = identities.getpgid(proc_ref) {
                        pgid = pg.get();
                    }
                    if let Ok(s) = identities.getsid(proc_ref) {
                        sid = s.get();
                    }
                });
                let _ = state.with_current_process_credentials(current, |creds| {
                    uid = creds.euid();
                    gid = creds.egid();
                });
            });
        }
    }

    ProcSysSnapshot {
        pid,
        ppid,
        pgid,
        sid,
        uid,
        gid,
        comm: b"init",
        total_pages: 65536,
        free_pages: 52428,
        uptime_seconds: 1,
        online_cpus: super::super::MAX_PROOF_CPUS as u32,
        hostname,
        boot_id_seed,
    }
}

fn require_root_admin() -> Result<(), Errno> {
    let current_cpu = super::super::current_cpu_index();
    let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) else {
        return Ok(());
    };
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let Ok(current) = (unsafe { scheduler.bootstrap_current_global_thread() }) else {
        return Ok(());
    };
    let mut is_root = true;
    let _ = super::runtime::with_linux_runtime(|state| {
        let _ = state.with_current_process_credentials(current, |creds| {
            is_root = creds.euid() == 0;
        });
    });
    if !is_root {
        return Err(Errno::EPERM);
    }
    Ok(())
}

fn handle_mount(
    user_source: u64,
    user_target: u64,
    user_fstype: u64,
    flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    if let Err(errno) = require_root_admin() {
        return Ok(Err(errno));
    }
    let mut target_buf = [0u8; MAX_MOUNT_PATH];
    let target_len = match read_user_cstr(user_target, &mut target_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut source_buf = [0u8; MAX_MOUNT_PATH];
    let source_len = if user_source == 0 {
        0
    } else {
        match read_user_cstr(user_source, &mut source_buf) {
            Ok(len) => len,
            Err(errno) => return Ok(Err(errno)),
        }
    };
    let mut fstype_buf = [0u8; 32];
    let fstype_opt = if user_fstype == 0 {
        None
    } else {
        match read_user_cstr(user_fstype, &mut fstype_buf) {
            Ok(len) => Some(len),
            Err(errno) => return Ok(Err(errno)),
        }
    };

    with_mount_state(|state| {
        state.ensure_initialized();
        let fstype_slice = fstype_opt.map(|n| &fstype_buf[..n]);
        state
            .mounts
            .mount(
                &source_buf[..source_len],
                &target_buf[..target_len],
                fstype_slice,
                flags,
            )
            .map(|_| 0)
    })
}

fn handle_umount2(user_target: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    if let Err(errno) = require_root_admin() {
        return Ok(Err(errno));
    }
    let Ok(flags) = u32::try_from(raw_flags) else {
        return Ok(Err(Errno::EINVAL));
    };
    let mut target_buf = [0u8; MAX_MOUNT_PATH];
    let target_len = match read_user_cstr(user_target, &mut target_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    with_mount_state(|state| {
        state.ensure_initialized();
        state
            .mounts
            .umount2(&target_buf[..target_len], flags)
            .map(|()| 0)
    })
}

fn handle_pivot_root(user_new_root: u64, user_put_old: u64) -> Result<Result<i64, Errno>, ()> {
    if let Err(errno) = require_root_admin() {
        return Ok(Err(errno));
    }
    let mut new_buf = [0u8; MAX_MOUNT_PATH];
    let new_len = match read_user_cstr(user_new_root, &mut new_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut old_buf = [0u8; MAX_MOUNT_PATH];
    let old_len = match read_user_cstr(user_put_old, &mut old_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    with_mount_state(|state| {
        state.ensure_initialized();
        state
            .mounts
            .pivot_root(&new_buf[..new_len], &old_buf[..old_len])
            .map(|()| 0)
    })
}

fn handle_statfs(user_path: u64, user_buf: u64) -> Result<Result<i64, Errno>, ()> {
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut path_buf = [0u8; MAX_MOUNT_PATH];
    let path_len = match read_user_cstr(user_path, &mut path_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let resolved = with_mount_state(|state| {
        state.ensure_initialized();
        state
            .mounts
            .resolve(&path_buf[..path_len])
            .map(|(entry, _)| (entry.fstype(), entry.flags()))
    })?;
    let (fstype, flags) = match resolved {
        Ok(pair) => pair,
        Err(errno) => return Ok(Err(errno)),
    };
    let bytes = encode_statfs(fstype, flags);
    if let Err(errno) = copy_to_user(user_buf, &bytes) {
        return Ok(Err(errno));
    }
    Ok(Ok(0))
}

fn handle_fstatfs(raw_fd: u64, user_buf: u64) -> Result<Result<i64, Errno>, ()> {
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let owner = current_process_id()?;
    let fstype = if is_proc_sys_fd(raw_fd) {
        let fd_idx = (linux_signed_int(raw_fd) - PROC_SYS_FD_BASE) as usize;
        let res = with_mount_state(|state| {
            let entry = &state.fds[fd_idx];
            if !entry.live || entry.owner_process != owner {
                Err(Errno::EBADF)
            } else {
                Ok(entry.fstype)
            }
        })?;
        match res {
            Ok(fs) => fs,
            Err(errno) => return Ok(Err(errno)),
        }
    } else if super::step32_dev::is_dev_fd(raw_fd) {
        FilesystemType::Devtmpfs
    } else {
        let fd = linux_signed_int(raw_fd);
        if !(0..32).contains(&fd) {
            return Ok(Err(Errno::EBADF));
        }
        FilesystemType::Initramfs
    };
    let bytes = encode_statfs(fstype, 0);
    if let Err(errno) = copy_to_user(user_buf, &bytes) {
        return Ok(Err(errno));
    }
    Ok(Ok(0))
}

fn handle_openat_if_proc_or_sys(user_path: u64, flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; MAX_MOUNT_PATH];
    let Ok(path_len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let path = &path_buf[..path_len];
    let target_fs = if path == b"/proc" || path.starts_with(b"/proc/") {
        FilesystemType::Procfs
    } else if path == b"/sys" || path.starts_with(b"/sys/") {
        FilesystemType::Sysfs
    } else {
        return Ok(None);
    };

    if (flags & O_ACCMODE) != O_RDONLY {
        return Ok(Some(SyscallReturn::error(Errno::EACCES)));
    }
    let rel = if path.len() <= 5 {
        &b""[..]
    } else {
        &path[6..]
    };

    let owner = current_process_id()?;
    let close_on_exec = (flags & O_CLOEXEC) != 0;
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let mut node_buf = [0u8; MAX_VIRTUAL_NODE_BYTES];
        let snap = build_live_snapshot(&state.hostname[..state.hostname_len], state.boot_id_seed);
        let len = match target_fs {
            FilesystemType::Procfs => read_procfs_node(rel, &state.mounts, &snap, &mut node_buf)?,
            FilesystemType::Sysfs => {
                if let Some(cg_rel) = rel.strip_prefix(b"fs/cgroup/") {
                    super::step35_events_cgroup::read_cgroup_control_file(cg_rel, &mut node_buf)?
                } else {
                    read_sysfs_node(rel, &snap, &mut node_buf)?
                }
            }
            _ => return Err(Errno::ENOENT),
        };
        let Some((slot_idx, slot)) = state.fds.iter_mut().enumerate().find(|(_, e)| !e.live) else {
            return Err(Errno::EMFILE);
        };
        *slot = ProcSysFdEntry {
            live: true,
            owner_process: owner,
            fstype: target_fs,
            close_on_exec,
            offset: 0,
            len,
            data: node_buf,
        };
        Ok(i64::from(PROC_SYS_FD_BASE + (slot_idx as i32)))
    })?;
    Ok(Some(encode_result(res)))
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let idx = (linux_signed_int(raw_fd) - PROC_SYS_FD_BASE) as usize;
    with_mount_state(|state| {
        let entry = &mut state.fds[idx];
        if !entry.live || entry.owner_process != owner {
            return Err(Errno::EBADF);
        }
        *entry = ProcSysFdEntry::EMPTY;
        Ok(0)
    })
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let idx = (linux_signed_int(raw_fd) - PROC_SYS_FD_BASE) as usize;
    with_mount_state(|state| {
        let entry = &mut state.fds[idx];
        if !entry.live || entry.owner_process != owner {
            return Err(Errno::EBADF);
        }
        let base: i64 = match whence {
            SEEK_SET => 0,
            SEEK_CUR => entry.offset as i64,
            SEEK_END => entry.len as i64,
            _ => return Err(Errno::EINVAL),
        };
        let next = base.checked_add(offset).ok_or(Errno::EINVAL)?;
        if next < 0 {
            return Err(Errno::EINVAL);
        }
        entry.offset = usize::try_from(next).map_err(|_| Errno::EINVAL)?;
        Ok(next)
    })
}

fn handle_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    if count == 0 {
        return Ok(Ok(0));
    }
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let owner = current_process_id()?;
    let idx = (linux_signed_int(raw_fd) - PROC_SYS_FD_BASE) as usize;
    let mut temp = [0u8; MAX_VIRTUAL_NODE_BYTES];
    let copied = with_mount_state(|state| {
        let entry = &mut state.fds[idx];
        if !entry.live || entry.owner_process != owner {
            return Err(Errno::EBADF);
        }
        if entry.offset >= entry.len {
            return Ok((0usize, 0usize));
        }
        let avail = entry.len - entry.offset;
        let take = usize::try_from(count).unwrap_or(avail).min(avail);
        temp[..take].copy_from_slice(&entry.data[entry.offset..entry.offset + take]);
        let old_offset = entry.offset;
        entry.offset += take;
        Ok((take, old_offset))
    })?;
    let (take, old_offset) = match copied {
        Ok(pair) => pair,
        Err(errno) => return Ok(Err(errno)),
    };
    if take == 0 {
        return Ok(Ok(0));
    }
    if let Err(errno) = copy_to_user(user_buf, &temp[..take]) {
        with_mount_state(|state| {
            state.fds[idx].offset = old_offset;
        })?;
        return Ok(Err(errno));
    }
    Ok(Ok(take as i64))
}

fn handle_newfstatat_if_proc_or_sys(
    user_path: u64,
    user_statbuf: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; MAX_MOUNT_PATH];
    let Ok(path_len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let path = &path_buf[..path_len];
    let target_fs = if path == b"/proc" || path.starts_with(b"/proc/") {
        FilesystemType::Procfs
    } else if path == b"/sys" || path.starts_with(b"/sys/") {
        FilesystemType::Sysfs
    } else {
        return Ok(None);
    };
    if user_statbuf == 0 {
        return Ok(Some(SyscallReturn::error(Errno::EFAULT)));
    }
    let rel = if path.len() <= 5 {
        &b""[..]
    } else {
        &path[6..]
    };
    let check = with_mount_state(|state| {
        state.ensure_initialized();
        let mut node_buf = [0u8; MAX_VIRTUAL_NODE_BYTES];
        let snap = build_live_snapshot(&state.hostname[..state.hostname_len], state.boot_id_seed);
        match target_fs {
            FilesystemType::Procfs => read_procfs_node(rel, &state.mounts, &snap, &mut node_buf),
            FilesystemType::Sysfs => read_sysfs_node(rel, &snap, &mut node_buf),
            _ => Err(Errno::ENOENT),
        }
    })?;
    let size = match check {
        Ok(n) => n as u64,
        Err(errno) => return Ok(Some(SyscallReturn::error(errno))),
    };
    let stat_bytes = encode_virtual_stat(size);
    if let Err(errno) = copy_to_user(user_statbuf, &stat_bytes) {
        return Ok(Some(SyscallReturn::error(errno)));
    }
    Ok(Some(SyscallReturn::success(0).ok_or(())?))
}

fn handle_fstat(raw_fd: u64, user_statbuf: u64) -> Result<Result<i64, Errno>, ()> {
    if user_statbuf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let owner = current_process_id()?;
    let idx = (linux_signed_int(raw_fd) - PROC_SYS_FD_BASE) as usize;
    let size = with_mount_state(|state| {
        let entry = &state.fds[idx];
        if !entry.live || entry.owner_process != owner {
            Err(Errno::EBADF)
        } else {
            Ok(entry.len as u64)
        }
    })?;
    let size = match size {
        Ok(s) => s,
        Err(errno) => return Ok(Err(errno)),
    };
    let stat_bytes = encode_virtual_stat(size);
    if let Err(errno) = copy_to_user(user_statbuf, &stat_bytes) {
        return Ok(Err(errno));
    }
    Ok(Ok(0))
}

fn handle_sync() -> Result<Result<i64, Errno>, ()> {
    with_mount_state(|state| {
        state.ensure_initialized();
        let _ = state.journal.sync_all();
        Ok(0)
    })
}

fn handle_fsync(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let fd = linux_signed_int(raw_fd);
    if fd < 0 {
        return Ok(Err(Errno::EBADF));
    }
    if super::step32_dev::is_dev_fd(raw_fd) {
        return Ok(Err(Errno::EINVAL));
    }
    with_mount_state(|state| {
        state.ensure_initialized();
        let _ = state.journal.sync_all();
        Ok(0)
    })
}

fn handle_sethostname(user_name: u64, len: u64) -> Result<Result<i64, Errno>, ()> {
    if let Err(errno) = require_root_admin() {
        return Ok(Err(errno));
    }
    let Ok(n) = usize::try_from(len) else {
        return Ok(Err(Errno::EINVAL));
    };
    if n > MAX_HOSTNAME_BYTES {
        return Ok(Err(Errno::EINVAL));
    }
    let mut buf = [0u8; MAX_HOSTNAME_BYTES];
    if n > 0 {
        if user_name == 0 {
            return Ok(Err(Errno::EFAULT));
        }
        if let Err(errno) = copy_from_user(&mut buf[..n], user_name) {
            return Ok(Err(errno));
        }
    }
    with_mount_state(|state| {
        state.ensure_initialized();
        state.hostname = [0u8; MAX_HOSTNAME_BYTES];
        state.hostname[..n].copy_from_slice(&buf[..n]);
        state.hostname_len = n;
        Ok(0)
    })
}

fn encode_virtual_stat(size: u64) -> [u8; ARM64_STAT_BYTES] {
    let mut buf = [0u8; ARM64_STAT_BYTES];
    buf[8..16].copy_from_slice(&1u64.to_le_bytes()); // st_ino
    buf[16..20].copy_from_slice(&S_IFREG_RO_MODE.to_le_bytes()); // st_mode
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // st_nlink
    buf[48..56].copy_from_slice(&(size as i64).to_le_bytes()); // st_size
    buf[56..60].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize
    buf
}

fn encode_statfs(fstype: FilesystemType, flags: u64) -> [u8; ARM64_STATFS_BYTES] {
    let mut buf = [0u8; ARM64_STATFS_BYTES];
    buf[0..8].copy_from_slice(&fstype.f_type_magic().to_le_bytes()); // f_type
    buf[8..16].copy_from_slice(&4096u64.to_le_bytes()); // f_bsize
    buf[16..24].copy_from_slice(&65536u64.to_le_bytes()); // f_blocks
    buf[24..32].copy_from_slice(&48000u64.to_le_bytes()); // f_bfree
    buf[32..40].copy_from_slice(&48000u64.to_le_bytes()); // f_bavail
    buf[40..48].copy_from_slice(&16384u64.to_le_bytes()); // f_files
    buf[48..56].copy_from_slice(&14000u64.to_le_bytes()); // f_ffree
    buf[64..72].copy_from_slice(&255u64.to_le_bytes()); // f_namelen
    buf[72..80].copy_from_slice(&4096u64.to_le_bytes()); // f_frsize
    buf[80..88].copy_from_slice(&flags.to_le_bytes()); // f_flags
    buf
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
    fn proc_sys_fd_range_is_disjoint_from_step29_and_step32() {
        assert!(!is_proc_sys_fd(0));
        assert!(!is_proc_sys_fd(64));
        assert!(is_proc_sys_fd(PROC_SYS_FD_BASE as u64));
        assert!(is_proc_sys_fd((PROC_SYS_FD_BASE + 15) as u64));
        assert!(!is_proc_sys_fd((PROC_SYS_FD_BASE + 16) as u64));
    }

    #[test]
    fn statfs_encoding_publishes_expected_filesystem_magic() {
        let proc_buf = encode_statfs(FilesystemType::Procfs, 1);
        let magic = u64::from_le_bytes(proc_buf[0..8].try_into().unwrap());
        assert_eq!(magic, 0x9fa0);
        let bsize = u64::from_le_bytes(proc_buf[8..16].try_into().unwrap());
        assert_eq!(bsize, 4096);
    }
}
