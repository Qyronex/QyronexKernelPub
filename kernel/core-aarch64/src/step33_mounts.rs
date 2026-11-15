// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use kernal_capability::ObjectId;
use kernal_linux_abi::{
    Errno, POLLIN, POLLOUT, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_fd::SubsystemHandle;
use kernal_linux_mounts::{
    BlockDevice, Ext4DurableJournal, Ext4StatFsInfo, Ext4Volume, FilesystemType, MAX_MOUNT_PATH,
    MS_BIND, MS_MOVE, MS_RDONLY, MS_REMOUNT, MountTable, ProcPidSelector, ProcProcessInfo,
    ProcSysSnapshot, enumerate_sysfs_dir, parse_proc_pid_subpath, read_procfs_node,
    read_procfs_process_node, read_sysfs_node,
};
use kernal_linux_vfs::{LINUX_PATH_MAX, NodeKind};

use super::step_fd_util::{
    DirectProcessRefs, SUBSYS_DEV, SUBSYS_PROC_SYS, collect_process_fd_numbers,
    current_scheduler_thread, describe_process_fd_target, lookup_aliased_subsystem,
    lookup_aliased_subsystem_current,
};

/// Dedicated file-descriptor base for Step-33 `/proc` and `/sys` virtual nodes (`96..128`),
/// partitioned cleanly above `STEP29_RUNTIME_FDS` (`0..64`) and `DEV_FD_BASE` (`64..96`).
pub(super) const PROC_SYS_FD_BASE: i32 = 96;
const MAX_PROC_SYS_FDS: usize = 32;
const MAX_MOUNTS: usize = 16;
pub(super) const MAX_EXT4_MOUNTS: usize = 4;
const MAX_JOURNAL_ENTRIES: usize = 16;
const MAX_JOURNAL_DATA: usize = 256;
const MAX_VIRTUAL_NODE_BYTES: usize = 4096;
const MAX_HOSTNAME_BYTES: usize = 64;
const ARM64_STAT_BYTES: usize = 128;
const ARM64_STATX_BYTES: usize = 256;
const ARM64_STATFS_BYTES: usize = 120;
const STATX_BASIC_STATS: u32 = 0x07ff;
const S_IFREG_RO_MODE: u32 = 0o100_444;
const S_IFDIR_RX_MODE: u32 = 0o040_555;
const S_IFLNK_MODE: u32 = 0o120_777;

const AT_FDCWD_I32: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_STATX_SYNC_TYPE: u64 = 0x6000;
const W_OK: u64 = 2;
const ACCESS_MODE_MASK: u64 = 0x7;

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_DIRECTORY: u64 = 0x4000;
const O_NOFOLLOW: u64 = 0x8000;
const O_CLOEXEC: u64 = 0x0008_0000;
const O_PATH: u64 = 0x0020_0000;

const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

#[derive(Clone)]
struct VirtualDirEntry {
    ino: u64,
    kind: NodeKind,
    name: Vec<u8>,
}

struct ProcSysFdEntry {
    live: bool,
    is_dir: bool,
    generation: u64,
    alias_refs: usize,
    owners: DirectProcessRefs<{ super::step29_runtime::STEP29_RUNTIME_PROCESS_VIEWS }>,
    fstype: FilesystemType,
    rel_path: Vec<u8>,
    offset: usize,
    content: Vec<u8>,
    dir_entries: Vec<VirtualDirEntry>,
}

impl ProcSysFdEntry {
    const EMPTY: Self = Self {
        live: false,
        is_dir: false,
        generation: 0,
        alias_refs: 0,
        owners: DirectProcessRefs::empty(),
        fstype: FilesystemType::Procfs,
        rel_path: Vec::new(),
        offset: 0,
        content: Vec::new(),
        dir_entries: Vec::new(),
    };
}

struct Ext4MountSlot {
    live: bool,
    mount_id: u32,
    start_sector: u64,
    sector_count: u64,
    flags: u64,
    mount_path: [u8; MAX_MOUNT_PATH],
    mount_path_len: usize,
    source: [u8; MAX_MOUNT_PATH],
    source_len: usize,
    vol: Option<Ext4Volume>,
}

impl Ext4MountSlot {
    const EMPTY: Self = Self {
        live: false,
        mount_id: 0,
        start_sector: 0,
        sector_count: 0,
        flags: 0,
        mount_path: [0u8; MAX_MOUNT_PATH],
        mount_path_len: 0,
        source: [0u8; MAX_MOUNT_PATH],
        source_len: 0,
        vol: None,
    };
}

static HAS_LIVE_EXT4_MOUNTS: AtomicBool = AtomicBool::new(false);

struct Step33MountState {
    initialized: bool,
    next_generation: u64,
    next_ext4_mount_id: u32,
    mounts: MountTable<MAX_MOUNTS>,
    ext4_mounts: [Ext4MountSlot; MAX_EXT4_MOUNTS],
    initramfs_prefix: [u8; MAX_MOUNT_PATH],
    initramfs_prefix_len: usize,
    initramfs_unmounted: bool,
    fds: [ProcSysFdEntry; MAX_PROC_SYS_FDS],
    journal: Ext4DurableJournal<MAX_JOURNAL_ENTRIES, MAX_JOURNAL_DATA>,
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
        let mut initramfs_prefix = [0u8; MAX_MOUNT_PATH];
        initramfs_prefix[0] = b'/';
        Self {
            initialized: false,
            next_generation: 1,
            next_ext4_mount_id: 1,
            mounts: MountTable::new(),
            ext4_mounts: [const { Ext4MountSlot::EMPTY }; MAX_EXT4_MOUNTS],
            initramfs_prefix,
            initramfs_prefix_len: 1,
            initramfs_unmounted: false,
            fds: [const { ProcSysFdEntry::EMPTY }; MAX_PROC_SYS_FDS],
            journal: Ext4DurableJournal::new(),
            hostname,
            hostname_len: 7,
            boot_id_seed: [
                0x4b, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x51, 0x79, 0x72, 0x6f, 0x6e, 0x65, 0x78, 0x33,
                0x33, 0x01,
            ],
        }
    }

    fn refresh_live_ext4_flag(&self) {
        let any = self.ext4_mounts.iter().any(|m| m.live);
        HAS_LIVE_EXT4_MOUNTS.store(any, Ordering::Release);
    }

    fn ensure_initialized(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        let _ = self.mounts.seed_default_hierarchy();
        let mut random_seed = [0u8; 16];
        if super::entropy::fill_getrandom(&mut random_seed).is_ok() {
            self.boot_id_seed = random_seed;
        }
        self.try_auto_mount_boot_root();
    }

    fn try_auto_mount_boot_root(&mut self) {
        let mut bootargs = [0u8; 256];
        let len = super::step42_hardware::copy_bootargs(&mut bootargs);
        if len == 0 {
            return;
        }
        let mut root_dev: Option<&[u8]> = None;
        let mut req_ro = false;
        for token in bootargs[..len].split(|&b| b == b' ' || b == b'\t' || b == b'\n') {
            if let Some(val) = token.strip_prefix(b"root=") {
                if val.starts_with(b"/dev/vda") {
                    root_dev = Some(val);
                }
            } else if token == b"ro" {
                req_ro = true;
            } else if token == b"rw" {
                req_ro = false;
            }
        }
        let Some(source) = root_dev else {
            return;
        };
        let flags = if req_ro { MS_RDONLY } else { 0 };
        if mount_ext4_slot(self, source, b"/", flags).is_ok() {
            let _ = self.mounts.mount(source, b"/", Some(b"ext4"), flags);
            self.initramfs_unmounted = true;
        }
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

fn retire_proc_sys_slot_if_unused(state: &mut Step33MountState, slot_idx: usize) {
    let Some(entry) = state.fds.get_mut(slot_idx) else {
        return;
    };
    if entry.live && entry.owners.is_empty() && entry.alias_refs == 0 {
        *entry = ProcSysFdEntry::EMPTY;
    }
}

fn resolve_proc_sys_slot_idx(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(usize, Option<u64>), Errno> {
    if is_proc_sys_fd(raw_fd) {
        let fd = linux_signed_int(raw_fd);
        return Ok(((fd - PROC_SYS_FD_BASE) as usize, None));
    }
    if let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
        && handle.kind == SUBSYS_PROC_SYS
    {
        return Ok((handle.slot as usize, Some(handle.generation)));
    }
    Err(Errno::EBADF)
}

fn resolve_proc_sys_entry_mut<'a>(
    state: &'a mut Step33MountState,
    process: ObjectId,
    slot_idx: usize,
    alias_gen: Option<u64>,
) -> Option<&'a mut ProcSysFdEntry> {
    let entry = state.fds.get_mut(slot_idx)?;
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

fn resolve_proc_sys_entry<'a>(
    state: &'a Step33MountState,
    process: ObjectId,
    slot_idx: usize,
    alias_gen: Option<u64>,
) -> Option<&'a ProcSysFdEntry> {
    let entry = state.fds.get(slot_idx)?;
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

/// Probes `POLL*` readiness for a Step-33 `/proc`/`/sys` FD or aliased `SUBSYS_PROC_SYS` FD.
pub(super) fn probe_proc_sys_readiness(
    process: ObjectId,
    raw_fd: u64,
) -> Option<Result<u32, Errno>> {
    let is_native = is_proc_sys_fd(raw_fd);
    let is_alias = !is_native
        && lookup_aliased_subsystem(process, raw_fd).is_some_and(|h| h.kind == SUBSYS_PROC_SYS);
    if !is_native && !is_alias {
        return None;
    }
    let res: Result<u32, Errno> = (|| {
        let (slot_idx, alias_gen) = resolve_proc_sys_slot_idx(process, raw_fd)?;
        with_mount_state(|state| {
            resolve_proc_sys_entry(state, process, slot_idx, alias_gen)
                .map(|_| u32::from(POLLIN) | u32::from(POLLOUT))
                .ok_or(Errno::EBADF)
        })
        .map_err(|()| Errno::EIO)?
    })();
    Some(res)
}

pub(super) fn append_open_proc_sys_fds(process: ObjectId, out: &mut Vec<i32>) {
    let _ = with_mount_state(|state| {
        for (idx, entry) in state.fds.iter().enumerate() {
            if entry.live && entry.owners.has_owner(process) {
                out.push(PROC_SYS_FD_BASE + (idx as i32));
            }
        }
    });
}

pub(super) fn describe_proc_sys_slot(
    slot: u16,
    generation: Option<u64>,
    process: Option<ObjectId>,
    out: &mut [u8],
) -> Option<usize> {
    let mut written = None;
    let _ = with_mount_state(|state| {
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
        let prefix = match entry.fstype {
            FilesystemType::Procfs => &b"/proc"[..],
            _ => &b"/sys"[..],
        };
        let mut c = prefix.len().min(out.len());
        out[..c].copy_from_slice(&prefix[..c]);
        if !entry.rel_path.is_empty() && c < out.len() {
            out[c] = b'/';
            c += 1;
            let take = out.len().saturating_sub(c).min(entry.rel_path.len());
            out[c..c + take].copy_from_slice(&entry.rel_path[..take]);
            c += take;
        }
        written = Some(c);
    });
    written
}

fn is_aliased_proc_sys_fd(raw_fd: u64) -> bool {
    lookup_aliased_subsystem_current(raw_fd).is_some_and(|h| h.kind == SUBSYS_PROC_SYS)
}

pub(super) fn retain_alias_handle(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(SubsystemHandle, u64), Errno> {
    if !is_proc_sys_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let idx = (linux_signed_int(raw_fd) - PROC_SYS_FD_BASE) as usize;
    with_mount_state(|state| {
        let Some(entry) = state.fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry.live || !entry.owners.has_owner(process) {
            return Err(Errno::EBADF);
        }
        entry.alias_refs += 1;
        Ok((
            SubsystemHandle {
                kind: SUBSYS_PROC_SYS,
                slot: idx as u16,
                generation: entry.generation,
            },
            O_RDONLY,
        ))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn release_alias_handle(handle: SubsystemHandle) {
    if handle.kind != SUBSYS_PROC_SYS {
        return;
    }
    let idx = handle.slot as usize;
    let _ = with_mount_state(|state| {
        let Some(entry) = state.fds.get_mut(idx) else {
            return;
        };
        if entry.live && entry.generation == handle.generation && entry.alias_refs > 0 {
            entry.alias_refs -= 1;
            retire_proc_sys_slot_if_unused(state, idx);
        }
    });
}

pub(super) fn handle_native_fcntl(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(process, raw_fd) else {
        return None;
    };
    if alias_gen.is_some() && !matches!(cmd, 3 | 4) {
        return None;
    }
    let res = with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry_mut(state, process, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        match cmd {
            1 => Ok(i64::from(i32::from(
                entry.owners.get_cloexec(process).unwrap_or(false),
            ))),
            2 => {
                let _ = entry.owners.set_cloexec(process, (argi & 1) != 0);
                Ok(0)
            }
            3 => Ok(O_RDONLY as i64),
            4 => Ok(0),
            _ => Err(Errno::EINVAL),
        }
    });
    Some(match res {
        Ok(inner) => inner,
        Err(()) => Err(Errno::EIO),
    })
}

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    let _ = with_mount_state(|state| {
        for entry in &mut state.fds {
            if entry.live {
                entry.owners.on_fork(parent, child);
            }
        }
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    let _ = with_mount_state(|state| {
        for idx in 0..MAX_PROC_SYS_FDS {
            if state.fds[idx].live {
                state.fds[idx].owners.close_cloexec_for(process);
                retire_proc_sys_slot_if_unused(state, idx);
            }
        }
    });
}

pub(super) fn on_process_exit(process: ObjectId) {
    let _ = with_mount_state(|state| {
        for idx in 0..MAX_PROC_SYS_FDS {
            if state.fds[idx].live {
                let _ = state.fds[idx].owners.close_owner(process);
                retire_proc_sys_slot_if_unused(state, idx);
            }
        }
    });
}

/// Intercepts Step-33 mount/filesystem syscalls (`umount2`, `mount`, `pivot_root`, `statfs`,
/// `fstatfs`, `sync`, `fsync`, `fdatasync`, `syncfs`, `sethostname`) and `/proc` + `/sys`
/// virtual-node operations (`openat`, `close`, `getdents64`, `lseek`, `read`, `readlinkat`,
/// `newfstatat`, `fstat`).
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
        // faccessat(dirfd, pathname, mode)
        48 => handle_faccessat_if_proc_or_sys(request.args[0], request.args[1], request.args[2], 0),
        // openat(dirfd, pathname, flags, mode)
        56 => handle_openat_if_proc_or_sys(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // close(fd)
        57 if is_proc_sys_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        // getdents64(fd, dirp, count)
        61 if is_proc_sys_fd(request.args[0]) || is_aliased_proc_sys_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_getdents64(
                request.args[0],
                request.args[1],
                request.args[2],
            )?)))
        }
        // lseek(fd, offset, whence)
        62 if is_proc_sys_fd(request.args[0]) || is_aliased_proc_sys_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_lseek(
                request.args[0],
                request.args[1] as i64,
                linux_signed_int(request.args[2]),
            )?)))
        }
        // read(fd, buf, count)
        63 if is_proc_sys_fd(request.args[0]) || is_aliased_proc_sys_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_read(
                request.args[0],
                request.args[1],
                request.args[2],
            )?)))
        }
        // readlinkat(dirfd, pathname, buf, bufsiz)
        78 => handle_readlinkat_if_proc_or_sys(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // newfstatat(dirfd, pathname, statbuf, flags)
        79 => handle_newfstatat_if_proc_or_sys(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // fstat(fd, statbuf)
        80 if is_proc_sys_fd(request.args[0]) || is_aliased_proc_sys_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_fstat(
                request.args[0],
                request.args[1],
            )?)))
        }
        // sync()
        81 => Ok(Some(encode_result(handle_sync()?))),
        // fsync(fd) | fdatasync(fd) | syncfs(fd)
        82 | 83 | 267 => Ok(Some(encode_result(handle_fsync(request.args[0])?))),
        // sethostname(name, len)
        161 => Ok(Some(encode_result(handle_sethostname(
            request.args[0],
            request.args[1],
        )?))),
        // statx(dirfd, pathname, flags, mask, statxbuf)
        291 => handle_statx_if_proc_or_sys(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // faccessat2(dirfd, pathname, mode, flags)
        439 => handle_faccessat_if_proc_or_sys(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
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

struct CallerSnapshotData {
    pid: u32,
    ppid: u32,
    pgid: u32,
    sid: u32,
    uid: u32,
    gid: u32,
    comm: [u8; 16],
    comm_len: usize,
    total_pages: u64,
    free_pages: u64,
    uptime_seconds: u64,
}

impl CallerSnapshotData {
    fn capture() -> Self {
        let mut pid = 1u32;
        let mut ppid = 0u32;
        let mut pgid = 1u32;
        let mut sid = 1u32;
        let mut uid = 0u32;
        let mut gid = 0u32;
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"init");
        let mut comm_len = 4usize;

        if let Some(current) = current_scheduler_thread() {
            let _ = super::runtime::with_linux_runtime(|state| {
                if let Some(proc_snap) = state.proc_snapshot_for_scheduler_thread(current) {
                    pid = proc_snap.pid;
                    ppid = proc_snap.ppid;
                    pgid = proc_snap.pgid;
                    sid = proc_snap.sid;
                    uid = proc_snap.uid;
                    gid = proc_snap.gid;
                    comm = proc_snap.comm;
                    comm_len = proc_snap.comm_len;
                }
            });
        }

        let mut free_pages = 52428u64;
        let _ = super::memory::with_live_frame_pool(|pool| {
            free_pages = pool.allocator_mut().free_pages();
        });
        let total_pages = (kernal_qemu_initrd_aarch64::QEMU_VIRT_RAM_BYTES / 4096).max(free_pages);
        let uptime_seconds =
            kernal_timer_aarch64::monotonic_now_ns().map_or(1, |ns| (ns / 1_000_000_000).max(1));

        Self {
            pid,
            ppid,
            pgid,
            sid,
            uid,
            gid,
            comm,
            comm_len,
            total_pages,
            free_pages,
            uptime_seconds,
        }
    }

    fn as_proc_sys_snapshot<'a>(
        &'a self,
        hostname: &'a [u8],
        boot_id_seed: [u8; 16],
    ) -> ProcSysSnapshot<'a> {
        ProcSysSnapshot {
            pid: self.pid,
            ppid: self.ppid,
            pgid: self.pgid,
            sid: self.sid,
            uid: self.uid,
            gid: self.gid,
            comm: &self.comm[..self.comm_len],
            total_pages: self.total_pages,
            free_pages: self.free_pages,
            uptime_seconds: self.uptime_seconds,
            online_cpus: super::super::MAX_PROOF_CPUS as u32,
            hostname,
            boot_id_seed,
        }
    }
}

pub(super) fn require_root_admin() -> Result<(), Errno> {
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
        let _ = state.with_current_process_credentials(current, |proc_ref, credentials| {
            if let Ok(creds) = credentials.credentials(proc_ref) {
                is_root = creds.euid() == 0;
            }
        });
    });
    if !is_root {
        return Err(Errno::EPERM);
    }
    Ok(())
}

fn normalize_mount_path_slice(raw: &[u8], out: &mut [u8; MAX_MOUNT_PATH]) -> Result<usize, Errno> {
    if raw.is_empty() || raw.len() > MAX_MOUNT_PATH {
        return Err(Errno::EINVAL);
    }
    let mut trimmed = raw;
    while trimmed.len() > 1 && trimmed.ends_with(b"/") {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    out[..trimmed.len()].copy_from_slice(trimmed);
    Ok(trimmed.len())
}

fn path_matches_prefix(path: &[u8], prefix: &[u8]) -> bool {
    if prefix == b"/" {
        return path.starts_with(b"/");
    }
    path == prefix
        || (path.len() > prefix.len() && path.starts_with(prefix) && path[prefix.len()] == b'/')
}

fn remap_path_across_pivot(
    path: &[u8],
    new_root: &[u8],
    put_old: &[u8],
    out: &mut [u8; MAX_MOUNT_PATH],
) -> usize {
    if path == new_root {
        out[0] = b'/';
        return 1;
    }
    if new_root != b"/"
        && path.len() > new_root.len()
        && path.starts_with(new_root)
        && path[new_root.len()] == b'/'
    {
        let rest = &path[new_root.len()..];
        let take = rest.len().min(MAX_MOUNT_PATH);
        out[..take].copy_from_slice(&rest[..take]);
        return take;
    }
    if path == b"/" {
        let take = put_old.len().min(MAX_MOUNT_PATH);
        out[..take].copy_from_slice(&put_old[..take]);
        return take;
    }
    let mut len = 0usize;
    let take_old = put_old.len().min(MAX_MOUNT_PATH);
    out[..take_old].copy_from_slice(&put_old[..take_old]);
    len += take_old;
    let take_rest = path.len().min(MAX_MOUNT_PATH - len);
    out[len..len + take_rest].copy_from_slice(&path[..take_rest]);
    len + take_rest
}

fn mount_ext4_slot(
    state: &mut Step33MountState,
    source: &[u8],
    target: &[u8],
    flags: u64,
) -> Result<u32, Errno> {
    if target.is_empty()
        || target.len() > MAX_MOUNT_PATH
        || source.is_empty()
        || source.len() > MAX_MOUNT_PATH
    {
        return Err(Errno::EINVAL);
    }
    let (start_sector, sector_count, part_ro) =
        super::step42_hardware::block_partition_window(source).ok_or(Errno::ENODEV)?;
    let ro = part_ro || (flags & MS_RDONLY) != 0;
    let vol = super::step42_hardware::with_active_block_device(|dev, _| {
        Ext4Volume::mount(dev, start_sector, sector_count, ro)
    })?;

    if let Some(existing) = state
        .ext4_mounts
        .iter_mut()
        .find(|m| m.live && &m.mount_path[..m.mount_path_len] == target)
    {
        if let Some(ref mut prev) = existing.vol {
            let _ = super::step42_hardware::with_active_block_device(|dev, _| {
                let _ = prev.sync(dev);
                dev.flush()
            });
        }
        existing.start_sector = start_sector;
        existing.sector_count = sector_count;
        existing.flags = flags;
        existing.source = [0u8; MAX_MOUNT_PATH];
        existing.source[..source.len()].copy_from_slice(source);
        existing.source_len = source.len();
        existing.vol = Some(vol);
        let mount_id = existing.mount_id;
        state.refresh_live_ext4_flag();
        return Ok(mount_id);
    }

    let Some(slot) = state.ext4_mounts.iter_mut().find(|m| !m.live) else {
        return Err(Errno::ENOSPC);
    };
    let mount_id = state.next_ext4_mount_id;
    state.next_ext4_mount_id = state.next_ext4_mount_id.saturating_add(1).max(1);
    *slot = Ext4MountSlot {
        live: true,
        mount_id,
        start_sector,
        sector_count,
        flags,
        mount_path: [0u8; MAX_MOUNT_PATH],
        mount_path_len: target.len(),
        source: [0u8; MAX_MOUNT_PATH],
        source_len: source.len(),
        vol: Some(vol),
    };
    slot.mount_path[..target.len()].copy_from_slice(target);
    slot.source[..source.len()].copy_from_slice(source);
    state.refresh_live_ext4_flag();
    Ok(mount_id)
}

pub(super) fn has_live_ext4_mounts() -> bool {
    HAS_LIVE_EXT4_MOUNTS.load(Ordering::Acquire)
}

pub(super) fn has_virtual_mount_prefix(abs_path: &[u8]) -> bool {
    if !abs_path.starts_with(b"/") {
        return false;
    }
    let mut result = false;
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        let Ok((entry, _)) = state.mounts.resolve(abs_path) else {
            return;
        };
        if matches!(
            entry.fstype(),
            FilesystemType::Procfs
                | FilesystemType::Sysfs
                | FilesystemType::Devtmpfs
                | FilesystemType::Cgroup2
        ) {
            let virt_len = entry.target().len();
            let ext4_len = state
                .ext4_mounts
                .iter()
                .filter(|m| {
                    m.live && path_matches_prefix(abs_path, &m.mount_path[..m.mount_path_len])
                })
                .map(|m| m.mount_path_len)
                .max()
                .unwrap_or(0);
            result = virt_len >= ext4_len;
        }
    });
    result
}

pub(super) fn resolve_ext4_mount(abs_path: &[u8]) -> Option<(u32, usize)> {
    if !has_live_ext4_mounts() || !abs_path.starts_with(b"/") {
        return None;
    }
    if has_virtual_mount_prefix(abs_path) {
        return None;
    }
    let mut best: Option<(u32, usize)> = None;
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        for slot in &state.ext4_mounts {
            if !slot.live {
                continue;
            }
            let mp = &slot.mount_path[..slot.mount_path_len];
            if path_matches_prefix(abs_path, mp) {
                if best.is_none_or(|(_, blen)| slot.mount_path_len >= blen) {
                    best = Some((slot.mount_id, slot.mount_path_len));
                }
            }
        }
    });
    best
}

pub(super) fn ext4_mount_at_exact(abs_path: &[u8]) -> Option<u32> {
    if !has_live_ext4_mounts() {
        return None;
    }
    let mut found = None;
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        for slot in &state.ext4_mounts {
            if slot.live && &slot.mount_path[..slot.mount_path_len] == abs_path {
                found = Some(slot.mount_id);
                break;
            }
        }
    });
    found
}

pub(super) fn with_ext4_volume<R>(
    mount_id: u32,
    f: impl FnOnce(&mut Ext4Volume, &mut dyn BlockDevice, &[u8]) -> Result<R, Errno>,
) -> Result<R, Errno> {
    with_mount_state(|state| {
        state.ensure_initialized();
        let Some(slot) = state
            .ext4_mounts
            .iter_mut()
            .find(|m| m.live && m.mount_id == mount_id)
        else {
            return Err(Errno::ENODEV);
        };
        let Some(ref mut vol) = slot.vol else {
            return Err(Errno::EIO);
        };
        let mp = &slot.mount_path[..slot.mount_path_len];
        super::step42_hardware::with_active_block_device(|dev, _| f(vol, dev, mp))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn resolve_initramfs_host_path(abs_path: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut result = None;
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        if state.initramfs_unmounted {
            return;
        }
        let prefix = &state.initramfs_prefix[..state.initramfs_prefix_len];
        if !path_matches_prefix(abs_path, prefix) {
            return;
        }
        if prefix == b"/" {
            if abs_path.len() <= out.len() {
                out[..abs_path.len()].copy_from_slice(abs_path);
                result = Some(abs_path.len());
            }
        } else if abs_path == prefix {
            if !out.is_empty() {
                out[0] = b'/';
                result = Some(1);
            }
        } else {
            let rest = &abs_path[prefix.len()..];
            if rest.len() <= out.len() {
                out[..rest.len()].copy_from_slice(rest);
                result = Some(rest.len());
            }
        }
    });
    result
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
    let raw_target_len = match read_user_cstr(user_target, &mut target_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut abs_target_buf = [0u8; MAX_MOUNT_PATH];
    let target_len = match super::step33_ext4_vfs::resolve_abs_for_current_into(
        &target_buf[..raw_target_len],
        &mut abs_target_buf,
    ) {
        Ok(n) => n,
        Err(errno) => return Ok(Err(errno)),
    };
    let target_slice = &abs_target_buf[..target_len];

    let mut source_buf = [0u8; MAX_MOUNT_PATH];
    let source_len = if user_source == 0 {
        0
    } else {
        match read_user_cstr(user_source, &mut source_buf) {
            Ok(len) => len,
            Err(errno) => return Ok(Err(errno)),
        }
    };
    let mut abs_source_buf = [0u8; MAX_MOUNT_PATH];
    let abs_source_len = if (flags & MS_MOVE) != 0 || (flags & MS_BIND) != 0 {
        match super::step33_ext4_vfs::resolve_abs_for_current_into(
            &source_buf[..source_len],
            &mut abs_source_buf,
        ) {
            Ok(n) => n,
            Err(errno) => return Ok(Err(errno)),
        }
    } else {
        let take = source_len.min(MAX_MOUNT_PATH);
        abs_source_buf[..take].copy_from_slice(&source_buf[..take]);
        take
    };
    let source_slice = &abs_source_buf[..abs_source_len];

    let mut fstype_buf = [0u8; 32];
    let fstype_opt = if user_fstype == 0 {
        None
    } else {
        match read_user_cstr(user_fstype, &mut fstype_buf) {
            Ok(len) => Some(len),
            Err(errno) => return Ok(Err(errno)),
        }
    };

    let mut moved_pair: Option<(u32, [u8; MAX_MOUNT_PATH], usize)> = None;
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let fstype_slice = fstype_opt.map(|n| &fstype_buf[..n]);
        if (flags & MS_REMOUNT) != 0 {
            if let Some(slot) = state
                .ext4_mounts
                .iter_mut()
                .find(|m| m.live && &m.mount_path[..m.mount_path_len] == target_slice)
            {
                let ro = (flags & MS_RDONLY) != 0;
                if let Some(ref mut vol) = slot.vol {
                    super::step42_hardware::with_active_block_device(|dev, _| {
                        vol.sync(dev)?;
                        vol.set_read_only(dev, ro)?;
                        dev.flush()
                    })?;
                }
                slot.flags = flags & !MS_REMOUNT;
            }
            return state
                .mounts
                .mount(source_slice, target_slice, fstype_slice, flags)
                .map(|_| 0);
        }

        if (flags & MS_MOVE) != 0 {
            if let Some(slot) = state
                .ext4_mounts
                .iter_mut()
                .find(|m| m.live && &m.mount_path[..m.mount_path_len] == source_slice)
            {
                let old_mp_len = slot.mount_path_len;
                let mut old_mp = [0u8; MAX_MOUNT_PATH];
                old_mp[..old_mp_len].copy_from_slice(&slot.mount_path[..old_mp_len]);
                slot.mount_path = [0u8; MAX_MOUNT_PATH];
                slot.mount_path[..target_len].copy_from_slice(target_slice);
                slot.mount_path_len = target_len;
                moved_pair = Some((slot.mount_id, old_mp, old_mp_len));
            }
            return state
                .mounts
                .mount(source_slice, target_slice, fstype_slice, flags)
                .map(|_| 0);
        }

        if (flags & MS_BIND) == 0 {
            let wants_ext4 = matches!(fstype_slice, Some(b"ext4" | b"ext3" | b"ext2"))
                || ((fstype_slice.is_none() || fstype_slice == Some(b""))
                    && source_slice.starts_with(b"/dev/vda"));
            if wants_ext4 {
                mount_ext4_slot(state, source_slice, target_slice, flags)?;
                return state
                    .mounts
                    .mount(source_slice, target_slice, Some(b"ext4"), flags)
                    .map(|_| 0);
            }
        }

        state
            .mounts
            .mount(source_slice, target_slice, fstype_slice, flags)
            .map(|_| 0)
    })?;
    if res.is_ok()
        && let Some((mount_id, old_mp, old_len)) = moved_pair
    {
        super::step33_ext4_vfs::on_mount_moved(mount_id, &old_mp[..old_len], target_slice);
    }
    Ok(res)
}

fn handle_umount2(user_target: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    if let Err(errno) = require_root_admin() {
        return Ok(Err(errno));
    }
    let Ok(flags) = u32::try_from(raw_flags) else {
        return Ok(Err(Errno::EINVAL));
    };
    let mut target_buf = [0u8; MAX_MOUNT_PATH];
    let raw_target_len = match read_user_cstr(user_target, &mut target_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut abs_target_buf = [0u8; MAX_MOUNT_PATH];
    let target_len = match super::step33_ext4_vfs::resolve_abs_for_current_into(
        &target_buf[..raw_target_len],
        &mut abs_target_buf,
    ) {
        Ok(n) => n,
        Err(errno) => return Ok(Err(errno)),
    };
    let target_slice = &abs_target_buf[..target_len];

    let mut removed_mount_id: Option<u32> = None;
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        if target_slice == b"/" {
            return Err(Errno::EBUSY);
        }
        if let Some(slot) = state
            .ext4_mounts
            .iter_mut()
            .find(|m| m.live && &m.mount_path[..m.mount_path_len] == target_slice)
        {
            if let Some(ref mut vol) = slot.vol {
                super::step42_hardware::with_active_block_device(|dev, _| {
                    vol.sync(dev)?;
                    dev.flush()
                })?;
            }
            removed_mount_id = Some(slot.mount_id);
            *slot = Ext4MountSlot::EMPTY;
            state.refresh_live_ext4_flag();
        } else if !state.initramfs_unmounted
            && &state.initramfs_prefix[..state.initramfs_prefix_len] == target_slice
        {
            state.initramfs_unmounted = true;
        }
        state.mounts.umount2(target_slice, flags).map(|()| 0)
    })?;
    if res.is_ok()
        && let Some(mount_id) = removed_mount_id
    {
        super::step33_ext4_vfs::on_mount_removed(mount_id);
    }
    Ok(res)
}

fn handle_pivot_root(user_new_root: u64, user_put_old: u64) -> Result<Result<i64, Errno>, ()> {
    if let Err(errno) = require_root_admin() {
        return Ok(Err(errno));
    }
    let mut new_buf = [0u8; MAX_MOUNT_PATH];
    let raw_new_len = match read_user_cstr(user_new_root, &mut new_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut old_buf = [0u8; MAX_MOUNT_PATH];
    let raw_old_len = match read_user_cstr(user_put_old, &mut old_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut new_abs_buf = [0u8; MAX_MOUNT_PATH];
    let new_len = match super::step33_ext4_vfs::resolve_abs_for_current_into(
        &new_buf[..raw_new_len],
        &mut new_abs_buf,
    ) {
        Ok(n) => n,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut old_abs_buf = [0u8; MAX_MOUNT_PATH];
    let old_len = match super::step33_ext4_vfs::resolve_abs_for_current_into(
        &old_buf[..raw_old_len],
        &mut old_abs_buf,
    ) {
        Ok(n) => n,
        Err(errno) => return Ok(Err(errno)),
    };
    let new_slice = &new_abs_buf[..new_len];
    let old_slice = &old_abs_buf[..old_len];
    let mut new_norm = [0u8; MAX_MOUNT_PATH];
    let new_norm_len = match normalize_mount_path_slice(new_slice, &mut new_norm) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    let mut old_norm = [0u8; MAX_MOUNT_PATH];
    let old_norm_len = match normalize_mount_path_slice(old_slice, &mut old_norm) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    let new_root = &new_norm[..new_norm_len];
    let put_old = &old_norm[..old_norm_len];
    let mut rel_put_old = [0u8; MAX_MOUNT_PATH];
    let rel_put_old_len = if put_old.len() > new_root.len() && put_old.starts_with(new_root) {
        let rest = &put_old[new_root.len()..];
        let take = rest.len().min(MAX_MOUNT_PATH);
        rel_put_old[..take].copy_from_slice(&rest[..take]);
        take
    } else {
        put_old.len().min(MAX_MOUNT_PATH)
    };
    let rel_put_old_slice = if put_old.len() > new_root.len() && put_old.starts_with(new_root) {
        &rel_put_old[..rel_put_old_len]
    } else {
        put_old
    };

    let res = with_mount_state(|state| {
        state.ensure_initialized();
        state.mounts.pivot_root(new_root, put_old)?;
        let mut next_ext4_buf = [0u8; MAX_MOUNT_PATH];
        for slot in &mut state.ext4_mounts {
            if !slot.live {
                continue;
            }
            let new_mp_len = remap_path_across_pivot(
                &slot.mount_path[..slot.mount_path_len],
                new_root,
                rel_put_old_slice,
                &mut next_ext4_buf,
            );
            slot.mount_path = [0u8; MAX_MOUNT_PATH];
            slot.mount_path[..new_mp_len].copy_from_slice(&next_ext4_buf[..new_mp_len]);
            slot.mount_path_len = new_mp_len;
        }
        if !state.initramfs_unmounted {
            let mut next_initramfs = [0u8; MAX_MOUNT_PATH];
            let next_len = remap_path_across_pivot(
                &state.initramfs_prefix[..state.initramfs_prefix_len],
                new_root,
                rel_put_old_slice,
                &mut next_initramfs,
            );
            state.initramfs_prefix = next_initramfs;
            state.initramfs_prefix_len = next_len;
        }
        state.refresh_live_ext4_flag();
        Ok(0)
    })?;
    if res.is_ok() {
        super::step33_ext4_vfs::on_pivot_root(new_root, rel_put_old_slice);
    }
    Ok(res)
}

fn handle_statfs(user_path: u64, user_buf: u64) -> Result<Result<i64, Errno>, ()> {
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut path_buf = vec![0u8; LINUX_PATH_MAX];
    let raw_len = match read_user_cstr(user_path, &mut path_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut abs_buf = vec![0u8; LINUX_PATH_MAX];
    let abs_len = match super::step33_ext4_vfs::resolve_abs_for_current_following(
        &path_buf[..raw_len],
        &mut abs_buf,
    ) {
        Ok(n) => n,
        Err(errno) => return Ok(Err(errno)),
    };
    let abs_slice = &abs_buf[..abs_len];

    enum StatfsInfo {
        Virtual(FilesystemType, u64),
        Ext4 {
            info: Ext4StatFsInfo,
            flags: u64,
            ro: bool,
        },
    }

    let resolved = with_mount_state(|state| {
        state.ensure_initialized();
        let mut virt_len = 0usize;
        let virt = state.mounts.resolve(abs_slice);
        if let Ok((entry, _)) = virt
            && matches!(
                entry.fstype(),
                FilesystemType::Procfs
                    | FilesystemType::Sysfs
                    | FilesystemType::Devtmpfs
                    | FilesystemType::Cgroup2
            )
        {
            virt_len = entry.target().len();
        }
        let best_ext4 = state
            .ext4_mounts
            .iter()
            .filter(|m| m.live && path_matches_prefix(abs_slice, &m.mount_path[..m.mount_path_len]))
            .max_by_key(|m| m.mount_path_len);
        if let Some(slot) = best_ext4
            && slot.mount_path_len >= virt_len
            && let Some(ref vol) = slot.vol
        {
            return Ok(StatfsInfo::Ext4 {
                info: vol.statfs(),
                flags: slot.flags,
                ro: vol.is_read_only(),
            });
        }
        virt.map(|(entry, _)| StatfsInfo::Virtual(entry.fstype(), entry.flags()))
    })?;
    let bytes = match resolved {
        Ok(StatfsInfo::Ext4 { info, flags, ro }) => encode_ext4_statfs(info, flags, ro),
        Ok(StatfsInfo::Virtual(fstype, flags)) => encode_statfs(fstype, flags),
        Err(errno) => return Ok(Err(errno)),
    };
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
    if let Some(mount_id) = super::step33_ext4_vfs::ext4_mount_id_for_fd(owner, raw_fd) {
        let info_res = with_mount_state(|state| {
            let Some(slot) = state
                .ext4_mounts
                .iter()
                .find(|m| m.live && m.mount_id == mount_id)
            else {
                return Err(Errno::EBADF);
            };
            let Some(ref vol) = slot.vol else {
                return Err(Errno::EIO);
            };
            Ok((vol.statfs(), slot.flags, vol.is_read_only()))
        })?;
        let (info, flags, ro) = match info_res {
            Ok(v) => v,
            Err(errno) => return Ok(Err(errno)),
        };
        let bytes = encode_ext4_statfs(info, flags, ro);
        if let Err(errno) = copy_to_user(user_buf, &bytes) {
            return Ok(Err(errno));
        }
        return Ok(Ok(0));
    }
    let fstype = if let Ok((fd_idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) {
        let res = with_mount_state(|state| {
            let Some(entry) = resolve_proc_sys_entry_mut(state, owner, fd_idx, alias_gen) else {
                return Err(Errno::EBADF);
            };
            Ok(entry.fstype)
        })?;
        match res {
            Ok(fs) => fs,
            Err(errno) => return Ok(Err(errno)),
        }
    } else if super::step32_dev::is_dev_fd(raw_fd)
        || lookup_aliased_subsystem(owner, raw_fd).is_some_and(|h| h.kind == SUBSYS_DEV)
    {
        FilesystemType::Devtmpfs
    } else {
        let fd = linux_signed_int(raw_fd);
        if !(0..super::step29_runtime::STEP29_RUNTIME_FDS as i32).contains(&fd) {
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

enum VirtualNode {
    Directory(Vec<VirtualDirEntry>),
    Symlink(Vec<u8>),
    Regular(Vec<u8>),
}

fn format_u64_bytes(mut val: u64) -> Vec<u8> {
    let mut digits = [0u8; 20];
    let mut pos = digits.len();
    loop {
        pos -= 1;
        digits[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        if val == 0 {
            break;
        }
    }
    digits[pos..].to_vec()
}

fn parse_u32_decimal(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc = 0u32;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(acc)
}

fn virtual_inode(fstype: FilesystemType, rel: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let tag = match fstype {
        FilesystemType::Procfs => 0x70u8,
        _ => 0x73u8,
    };
    hash ^= u64::from(tag);
    hash = hash.wrapping_mul(0x0100_0000_01b3);
    for &b in rel {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let prefix = match fstype {
        FilesystemType::Procfs => 0x7000_0000_0000_0000u64,
        _ => 0x7100_0000_0000_0000u64,
    };
    prefix | (hash & 0x00ff_ffff_ffff_ffff).max(1)
}

enum ResolvedVirtualTarget {
    Virtual {
        fstype: FilesystemType,
        rel_path: Vec<u8>,
        node: Option<VirtualNode>,
    },
    HostAbsolute(Vec<u8>),
}

enum WalkState {
    Virtual {
        fstype: FilesystemType,
        parts: Vec<Vec<u8>>,
    },
    Host(Vec<Vec<u8>>),
}

fn push_segments_back(queue: &mut VecDeque<Vec<u8>>, path: &[u8]) {
    for seg in path.split(|&b| b == b'/') {
        if !seg.is_empty() && seg != b"." {
            queue.push_back(seg.to_vec());
        }
    }
}

fn prepend_segments_front(queue: &mut VecDeque<Vec<u8>>, path: &[u8]) {
    let mut rev: Vec<&[u8]> = path
        .split(|&b| b == b'/')
        .filter(|seg| !seg.is_empty() && *seg != b".")
        .collect();
    while let Some(seg) = rev.pop() {
        queue.push_front(seg.to_vec());
    }
}

fn join_part_slices(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(part);
    }
    out
}

fn host_absolute_from_parts(parts: &[Vec<u8>]) -> Vec<u8> {
    if parts.is_empty() {
        return b"/".to_vec();
    }
    let mut out = Vec::with_capacity(1 + parts.iter().map(|p| p.len() + 1).sum::<usize>());
    for part in parts {
        out.push(b'/');
        out.extend_from_slice(part);
    }
    out
}

fn split_nonempty_segments(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&b| b == b'/')
        .filter(|seg| !seg.is_empty() && *seg != b".")
        .map(|seg| seg.to_vec())
        .collect()
}

fn join_rel(prefix: &[u8], child: &[u8]) -> Vec<u8> {
    if prefix.is_empty() {
        return child.to_vec();
    }
    let mut out = Vec::with_capacity(prefix.len() + 1 + child.len());
    out.extend_from_slice(prefix);
    out.push(b'/');
    out.extend_from_slice(child);
    out
}

fn parent_rel_path(rel: &[u8]) -> &[u8] {
    match rel.iter().rposition(|&b| b == b'/') {
        Some(idx) => &rel[..idx],
        None => b"",
    }
}

fn make_dir_entry(
    fstype: FilesystemType,
    parent_rel: &[u8],
    name: &[u8],
    kind: NodeKind,
) -> VirtualDirEntry {
    let ino = match name {
        b"." => virtual_inode(fstype, parent_rel),
        b".." => virtual_inode(fstype, parent_rel_path(parent_rel)),
        _ => {
            let full = join_rel(parent_rel, name);
            virtual_inode(fstype, &full)
        }
    };
    VirtualDirEntry {
        ino,
        kind,
        name: name.to_vec(),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_virtual_path<const M: usize>(
    state: &Step33MountState,
    mounts: &kernal_linux_mounts::MountTable<M>,
    owner: ObjectId,
    dirfd: u64,
    user_path: u64,
    allow_empty: bool,
    follow_final: bool,
    caller: &CallerSnapshotData,
    hostname: &[u8],
    boot_id_seed: [u8; 16],
) -> Result<Option<ResolvedVirtualTarget>, Errno> {
    let mut path_buf = vec![0u8; LINUX_PATH_MAX];
    let Ok(path_len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let path = &path_buf[..path_len];
    let trailing_slash = path.ends_with(b"/");
    let mut queue = VecDeque::new();

    let mut walk_state = if path == b"/proc" || path.starts_with(b"/proc/") {
        if path.len() > 5 {
            push_segments_back(&mut queue, &path[6..]);
        }
        WalkState::Virtual {
            fstype: FilesystemType::Procfs,
            parts: Vec::new(),
        }
    } else if path == b"/sys" || path.starts_with(b"/sys/") {
        if path.len() > 4 {
            push_segments_back(&mut queue, &path[5..]);
        }
        WalkState::Virtual {
            fstype: FilesystemType::Sysfs,
            parts: Vec::new(),
        }
    } else if path.starts_with(b"/") || linux_signed_int(dirfd) == AT_FDCWD_I32 {
        return Ok(None);
    } else {
        let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, dirfd) else {
            return Ok(None);
        };
        let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if path.is_empty() {
            if allow_empty {
                return Ok(Some(ResolvedVirtualTarget::Virtual {
                    fstype: entry.fstype,
                    rel_path: entry.rel_path.clone(),
                    node: None,
                }));
            }
            return Err(Errno::ENOENT);
        }
        if !entry.is_dir {
            return Err(Errno::ENOTDIR);
        }
        push_segments_back(&mut queue, path);
        WalkState::Virtual {
            fstype: entry.fstype,
            parts: split_nonempty_segments(&entry.rel_path),
        }
    };

    let mut symlink_depth = 0usize;
    let mut last_node: Option<VirtualNode> = None;

    while let Some(seg) = queue.pop_front() {
        let is_final = queue.is_empty();
        last_node = None;
        match &mut walk_state {
            WalkState::Virtual { fstype, parts } => {
                if seg == b".." {
                    if parts.pop().is_none() {
                        walk_state = WalkState::Host(Vec::new());
                    }
                    continue;
                }
                parts.push(seg);
                let rel = join_part_slices(parts);
                let node =
                    synthesize_virtual_node(*fstype, &rel, mounts, caller, hostname, boot_id_seed)?;
                match node {
                    VirtualNode::Directory(_) => {
                        if is_final {
                            last_node = Some(node);
                        }
                    }
                    VirtualNode::Regular(_) => {
                        if !is_final || trailing_slash {
                            return Err(Errno::ENOTDIR);
                        }
                        last_node = Some(node);
                    }
                    VirtualNode::Symlink(target) => {
                        let must_follow = !is_final || follow_final || trailing_slash;
                        if !must_follow {
                            last_node = Some(VirtualNode::Symlink(target));
                            continue;
                        }
                        if !target.starts_with(b"/") && target.contains(&b':') {
                            if !is_final || trailing_slash {
                                return Err(Errno::ENOTDIR);
                            }
                            last_node = Some(VirtualNode::Symlink(target));
                            continue;
                        }
                        symlink_depth += 1;
                        if symlink_depth > 8 {
                            return Err(Errno::ELOOP);
                        }
                        if target == b"/proc" || target.starts_with(b"/proc/") {
                            *fstype = FilesystemType::Procfs;
                            parts.clear();
                            if target.len() > 5 {
                                prepend_segments_front(&mut queue, &target[6..]);
                            }
                        } else if target == b"/sys" || target.starts_with(b"/sys/") {
                            *fstype = FilesystemType::Sysfs;
                            parts.clear();
                            if target.len() > 4 {
                                prepend_segments_front(&mut queue, &target[5..]);
                            }
                        } else if target.starts_with(b"/") {
                            prepend_segments_front(&mut queue, &target[1..]);
                            walk_state = WalkState::Host(Vec::new());
                        } else {
                            parts.pop();
                            prepend_segments_front(&mut queue, &target);
                        }
                    }
                }
            }
            WalkState::Host(parts) => {
                if seg == b".." {
                    parts.pop();
                } else {
                    parts.push(seg);
                    if parts.len() == 1 {
                        if parts[0].as_slice() == b"proc" {
                            walk_state = WalkState::Virtual {
                                fstype: FilesystemType::Procfs,
                                parts: Vec::new(),
                            };
                        } else if parts[0].as_slice() == b"sys" {
                            walk_state = WalkState::Virtual {
                                fstype: FilesystemType::Sysfs,
                                parts: Vec::new(),
                            };
                        }
                    }
                }
            }
        }
    }

    Ok(Some(match walk_state {
        WalkState::Virtual { fstype, parts } => {
            let rel_path = join_part_slices(&parts);
            let node = match last_node {
                Some(node) => Some(node),
                None => Some(synthesize_virtual_node(
                    fstype,
                    &rel_path,
                    mounts,
                    caller,
                    hostname,
                    boot_id_seed,
                )?),
            };
            ResolvedVirtualTarget::Virtual {
                fstype,
                rel_path,
                node,
            }
        }
        WalkState::Host(parts) => {
            ResolvedVirtualTarget::HostAbsolute(host_absolute_from_parts(&parts))
        }
    }))
}

fn fallback_proc_snapshot(caller: &CallerSnapshotData) -> super::runtime::ProcProcessSnapshot {
    let mut exe_path = [0u8; 128];
    let take_exe = caller.comm_len.min(127);
    exe_path[0] = b'/';
    exe_path[1..1 + take_exe].copy_from_slice(&caller.comm[..take_exe]);
    super::runtime::ProcProcessSnapshot {
        process: ObjectId(1),
        pid: caller.pid,
        ppid: caller.ppid,
        pgid: caller.pgid,
        sid: caller.sid,
        uid: caller.uid,
        gid: caller.gid,
        state_char: b'R',
        comm: caller.comm,
        comm_len: caller.comm_len,
        exe_path,
        exe_len: 1 + take_exe,
        cmdline: [0u8; 128],
        cmdline_len: 0,
    }
}

fn resolve_proc_snapshot_for_selector(
    caller: &CallerSnapshotData,
    sel: ProcPidSelector,
) -> Option<super::runtime::ProcProcessSnapshot> {
    let target_pid = match sel {
        ProcPidSelector::Current => NonZeroU32::new(caller.pid)?,
        ProcPidSelector::Pid(pid) => NonZeroU32::new(pid)?,
    };
    match super::runtime::with_linux_runtime(|state| state.proc_snapshot_by_pid(target_pid)) {
        Ok(found) => found,
        Err(_) if target_pid.get() == caller.pid => Some(fallback_proc_snapshot(caller)),
        Err(_) => None,
    }
}

fn collect_all_proc_snapshots(
    caller: &CallerSnapshotData,
) -> Vec<super::runtime::ProcProcessSnapshot> {
    let mut buf = vec![None; super::runtime::STEP15_RUNTIME_PROCESSES];
    let mut out = Vec::new();
    match super::runtime::with_linux_runtime(|state| state.collect_proc_snapshots(&mut buf)) {
        Ok(count) => {
            for snap in buf.into_iter().take(count).flatten() {
                out.push(snap);
            }
        }
        Err(_) => out.push(fallback_proc_snapshot(caller)),
    }
    out.sort_unstable_by_key(|s| s.pid);
    out
}

fn build_proc_root_entries(caller: &CallerSnapshotData) -> Vec<VirtualDirEntry> {
    let mut entries = Vec::new();
    entries.push(make_dir_entry(
        FilesystemType::Procfs,
        b"",
        b".",
        NodeKind::Directory,
    ));
    entries.push(make_dir_entry(
        FilesystemType::Procfs,
        b"",
        b"..",
        NodeKind::Directory,
    ));
    for proc_snap in collect_all_proc_snapshots(caller) {
        let pid_bytes = format_u64_bytes(u64::from(proc_snap.pid));
        entries.push(make_dir_entry(
            FilesystemType::Procfs,
            b"",
            &pid_bytes,
            NodeKind::Directory,
        ));
    }
    push_encoded_dir_entries(
        &mut entries,
        FilesystemType::Procfs,
        b"",
        b"cmdline:R|cpuinfo:R|filesystems:R|loadavg:R|meminfo:R|mounts:R|partitions:R|self:L|stat:R|sys:D|thread-self:L|uptime:R|version:R",
    );
    entries
}

fn push_encoded_dir_entries(
    entries: &mut Vec<VirtualDirEntry>,
    fstype: FilesystemType,
    parent_rel: &[u8],
    spec: &[u8],
) {
    for item in spec.split(|&b| b == b'|') {
        if item.len() < 3 || item[item.len() - 2] != b':' {
            continue;
        }
        let name = &item[..item.len() - 2];
        let kind = match item[item.len() - 1] {
            b'D' => NodeKind::Directory,
            b'L' => NodeKind::Symlink,
            _ => NodeKind::Regular,
        };
        entries.push(make_dir_entry(fstype, parent_rel, name, kind));
    }
}

fn build_proc_pid_entries(rel_pid: &[u8]) -> Vec<VirtualDirEntry> {
    let mut entries = Vec::with_capacity(15);
    push_encoded_dir_entries(
        &mut entries,
        FilesystemType::Procfs,
        rel_pid,
        b".:D|..:D|cgroup:R|cmdline:R|comm:R|cwd:L|exe:L|fd:D|mountinfo:R|mounts:R|ns:D|oom_score_adj:R|root:L|stat:R|status:R",
    );
    entries
}

fn build_proc_fd_entries(
    rel_fd_dir: &[u8],
    proc_snap: &super::runtime::ProcProcessSnapshot,
) -> Vec<VirtualDirEntry> {
    let mut entries = Vec::new();
    entries.push(make_dir_entry(
        FilesystemType::Procfs,
        rel_fd_dir,
        b".",
        NodeKind::Directory,
    ));
    entries.push(make_dir_entry(
        FilesystemType::Procfs,
        rel_fd_dir,
        b"..",
        NodeKind::Directory,
    ));
    let mut open_fds = Vec::new();
    collect_process_fd_numbers(proc_snap.process, &mut open_fds);
    open_fds.sort_unstable();
    for fd in open_fds {
        if fd >= 0 {
            let name = format_u64_bytes(fd as u64);
            entries.push(make_dir_entry(
                FilesystemType::Procfs,
                rel_fd_dir,
                &name,
                NodeKind::Symlink,
            ));
        }
    }
    entries
}

fn build_proc_ns_entries(rel_ns_dir: &[u8]) -> Vec<VirtualDirEntry> {
    let mut entries = Vec::with_capacity(9);
    push_encoded_dir_entries(
        &mut entries,
        FilesystemType::Procfs,
        rel_ns_dir,
        b".:D|..:D|cgroup:L|ipc:L|mnt:L|net:L|pid:L|user:L|uts:L",
    );
    entries
}

fn synthesize_proc_virtual_node<const M: usize>(
    rel: &[u8],
    mounts: &kernal_linux_mounts::MountTable<M>,
    caller: &CallerSnapshotData,
    hostname: &[u8],
    boot_id_seed: [u8; 16],
) -> Result<VirtualNode, Errno> {
    if rel.is_empty() {
        return Ok(VirtualNode::Directory(build_proc_root_entries(caller)));
    }
    if rel == b"self" {
        return Ok(VirtualNode::Symlink(format_u64_bytes(u64::from(
            caller.pid,
        ))));
    }
    if rel == b"thread-self" {
        let mut target = format_u64_bytes(u64::from(caller.pid));
        target.extend_from_slice(b"/task/");
        target.extend_from_slice(&format_u64_bytes(u64::from(caller.pid)));
        return Ok(VirtualNode::Symlink(target));
    }
    if rel == b"cmdline" {
        let mut cmd = [0u8; 256];
        let cmd_len = super::step42_hardware::copy_bootargs(&mut cmd);
        if cmd_len > 0 {
            let mut out = Vec::with_capacity(cmd_len + 1);
            out.extend_from_slice(&cmd[..cmd_len]);
            out.push(b'\n');
            return Ok(VirtualNode::Regular(out));
        }
    }
    if rel == b"partitions" {
        return Ok(VirtualNode::Regular(build_proc_partitions()));
    }
    match rel {
        b"sys" => {
            return Ok(VirtualNode::Directory(vec![
                make_dir_entry(FilesystemType::Procfs, rel, b".", NodeKind::Directory),
                make_dir_entry(FilesystemType::Procfs, rel, b"..", NodeKind::Directory),
                make_dir_entry(FilesystemType::Procfs, rel, b"kernel", NodeKind::Directory),
            ]));
        }
        b"sys/kernel" => {
            return Ok(VirtualNode::Directory(vec![
                make_dir_entry(FilesystemType::Procfs, rel, b".", NodeKind::Directory),
                make_dir_entry(FilesystemType::Procfs, rel, b"..", NodeKind::Directory),
                make_dir_entry(FilesystemType::Procfs, rel, b"hostname", NodeKind::Regular),
                make_dir_entry(FilesystemType::Procfs, rel, b"osrelease", NodeKind::Regular),
                make_dir_entry(FilesystemType::Procfs, rel, b"random", NodeKind::Directory),
            ]));
        }
        b"sys/kernel/random" => {
            return Ok(VirtualNode::Directory(vec![
                make_dir_entry(FilesystemType::Procfs, rel, b".", NodeKind::Directory),
                make_dir_entry(FilesystemType::Procfs, rel, b"..", NodeKind::Directory),
                make_dir_entry(FilesystemType::Procfs, rel, b"boot_id", NodeKind::Regular),
            ]));
        }
        _ => {}
    }

    if let Some((sel, subpath)) = parse_proc_pid_subpath(rel) {
        let proc_snap = resolve_proc_snapshot_for_selector(caller, sel).ok_or(Errno::ENOENT)?;
        if subpath.is_empty() {
            return Ok(VirtualNode::Directory(build_proc_pid_entries(rel)));
        }
        match subpath {
            b"exe" => {
                return Ok(VirtualNode::Symlink(
                    proc_snap.exe_path[..proc_snap.exe_len].to_vec(),
                ));
            }
            b"root" => {
                let (_, root_vec) =
                    super::step33_ext4_vfs::process_proc_cwd_root(proc_snap.process);
                return Ok(VirtualNode::Symlink(root_vec));
            }
            b"cwd" => {
                let (cwd_vec, _) = super::step33_ext4_vfs::process_proc_cwd_root(proc_snap.process);
                return Ok(VirtualNode::Symlink(cwd_vec));
            }
            b"fd" => {
                return Ok(VirtualNode::Directory(build_proc_fd_entries(
                    rel, &proc_snap,
                )));
            }
            b"ns" => return Ok(VirtualNode::Directory(build_proc_ns_entries(rel))),
            _ => {}
        }
        if let Some(fd_str) = subpath.strip_prefix(b"fd/") {
            let fd_num = parse_u32_decimal(fd_str).ok_or(Errno::ENOENT)? as i32;
            let mut target_buf = [0u8; MAX_MOUNT_PATH];
            let len = describe_process_fd_target(proc_snap.process, fd_num, &mut target_buf)
                .ok_or(Errno::ENOENT)?;
            return Ok(VirtualNode::Symlink(target_buf[..len].to_vec()));
        }
        if let Some(ns_name) = subpath.strip_prefix(b"ns/")
            && matches!(
                ns_name,
                b"cgroup" | b"ipc" | b"mnt" | b"net" | b"pid" | b"user" | b"uts"
            )
        {
            let mut target = Vec::from(ns_name);
            target.extend_from_slice(b":[4026531840]");
            return Ok(VirtualNode::Symlink(target));
        }

        let info = ProcProcessInfo {
            pid: proc_snap.pid,
            ppid: proc_snap.ppid,
            pgid: proc_snap.pgid,
            sid: proc_snap.sid,
            uid: proc_snap.uid,
            gid: proc_snap.gid,
            state_char: proc_snap.state_char,
            comm: &proc_snap.comm[..proc_snap.comm_len],
            cmdline: &proc_snap.cmdline[..proc_snap.cmdline_len],
            vm_size_kb: 4096,
            vm_rss_kb: 1024,
        };
        let mut node_buf = vec![0u8; MAX_VIRTUAL_NODE_BYTES];
        let len =
            read_procfs_process_node(subpath, mounts, &info, &mut node_buf).ok_or(Errno::ENOENT)?;
        node_buf.truncate(len);
        return Ok(VirtualNode::Regular(node_buf));
    }

    let snap = caller.as_proc_sys_snapshot(hostname, boot_id_seed);
    let mut node_buf = vec![0u8; MAX_VIRTUAL_NODE_BYTES];
    let len =
        synthesize_proc_or_sys_node(FilesystemType::Procfs, rel, mounts, &snap, &mut node_buf)?;
    node_buf.truncate(len);
    Ok(VirtualNode::Regular(node_buf))
}

fn synthesize_proc_or_sys_node<const M: usize>(
    target_fs: FilesystemType,
    rel: &[u8],
    mounts: &kernal_linux_mounts::MountTable<M>,
    snap: &ProcSysSnapshot<'_>,
    node_buf: &mut [u8],
) -> Result<usize, Errno> {
    match target_fs {
        FilesystemType::Procfs => {
            read_procfs_node(rel, mounts, snap, node_buf).ok_or(Errno::ENOENT)
        }
        FilesystemType::Sysfs => {
            if let Some(cg_rel) = rel.strip_prefix(b"fs/cgroup/") {
                super::step35_events_cgroup::read_cgroup_control_file(cg_rel, node_buf)
            } else {
                if (rel == b"class/net/eth0/address" || rel == b"devices/virtio1/net/eth0/address")
                    && let Some(mac) = super::step42_hardware::hardware_net_mac()
                {
                    if node_buf.len() < 18 {
                        return Err(Errno::EINVAL);
                    }
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    let mut pos = 0;
                    for (i, b) in mac.iter().enumerate() {
                        if i > 0 {
                            node_buf[pos] = b':';
                            pos += 1;
                        }
                        node_buf[pos] = HEX[usize::from(b >> 4)];
                        node_buf[pos + 1] = HEX[usize::from(b & 0x0f)];
                        pos += 2;
                    }
                    node_buf[pos] = b'\n';
                    return Ok(pos + 1);
                }
                if (rel == b"class/net/eth0/operstate"
                    || rel == b"devices/virtio1/net/eth0/operstate")
                    && super::step42_hardware::has_hardware_net()
                {
                    let state = if super::step42_hardware::hardware_net_link_up() {
                        b"up\n".as_slice()
                    } else {
                        b"down\n".as_slice()
                    };
                    if node_buf.len() < state.len() {
                        return Err(Errno::EINVAL);
                    }
                    node_buf[..state.len()].copy_from_slice(state);
                    return Ok(state.len());
                }
                match super::step37_38_systemd_udev::read_sysfs_device_attr(rel, node_buf) {
                    Ok(len) => Ok(len),
                    Err(Errno::ENOENT) => read_sysfs_node(rel, snap, node_buf).ok_or(Errno::ENOENT),
                    Err(errno) => Err(errno),
                }
            }
        }
        _ => Err(Errno::ENOENT),
    }
}

fn synthesize_sys_virtual_node<const M: usize>(
    rel: &[u8],
    mounts: &kernal_linux_mounts::MountTable<M>,
    caller: &CallerSnapshotData,
    hostname: &[u8],
    boot_id_seed: [u8; 16],
) -> Result<VirtualNode, Errno> {
    if rel == b"fs/cgroup" {
        let mut entries = Vec::with_capacity(13);
        push_encoded_dir_entries(
            &mut entries,
            FilesystemType::Sysfs,
            rel,
            b".:D|..:D|cgroup.controllers:R|cgroup.events:R|cgroup.procs:R|cgroup.subtree_control:R|cpu.max:R|cpu.stat:R|memory.current:R|memory.max:R|memory.stat:R|pids.current:R|pids.max:R",
        );
        return Ok(VirtualNode::Directory(entries));
    }
    let mut entries = Vec::new();
    let is_dir = enumerate_sysfs_dir(rel, |name, sub_dir| {
        entries.push(make_dir_entry(
            FilesystemType::Sysfs,
            rel,
            name,
            if sub_dir {
                NodeKind::Directory
            } else {
                NodeKind::Regular
            },
        ));
    });
    if is_dir {
        let mut full = Vec::with_capacity(entries.len() + 2);
        full.push(make_dir_entry(
            FilesystemType::Sysfs,
            rel,
            b".",
            NodeKind::Directory,
        ));
        full.push(make_dir_entry(
            FilesystemType::Sysfs,
            rel,
            b"..",
            NodeKind::Directory,
        ));
        full.extend(entries);
        return Ok(VirtualNode::Directory(full));
    }

    let snap = caller.as_proc_sys_snapshot(hostname, boot_id_seed);
    let mut node_buf = vec![0u8; MAX_VIRTUAL_NODE_BYTES];
    let len =
        synthesize_proc_or_sys_node(FilesystemType::Sysfs, rel, mounts, &snap, &mut node_buf)?;
    node_buf.truncate(len);
    Ok(VirtualNode::Regular(node_buf))
}

fn synthesize_virtual_node<const M: usize>(
    fstype: FilesystemType,
    rel: &[u8],
    mounts: &kernal_linux_mounts::MountTable<M>,
    caller: &CallerSnapshotData,
    hostname: &[u8],
    boot_id_seed: [u8; 16],
) -> Result<VirtualNode, Errno> {
    match fstype {
        FilesystemType::Procfs => {
            synthesize_proc_virtual_node(rel, mounts, caller, hostname, boot_id_seed)
        }
        FilesystemType::Sysfs => {
            synthesize_sys_virtual_node(rel, mounts, caller, hostname, boot_id_seed)
        }
        _ => Err(Errno::ENOENT),
    }
}

fn resolve_virtual_node_from_target<const M: usize>(
    target: ResolvedVirtualTarget,
    mounts: &kernal_linux_mounts::MountTable<M>,
    caller: &CallerSnapshotData,
    hostname: &[u8],
    boot_id_seed: [u8; 16],
) -> Result<(FilesystemType, Vec<u8>, VirtualNode), Errno> {
    let ResolvedVirtualTarget::Virtual {
        fstype,
        rel_path,
        node,
    } = target
    else {
        return Err(Errno::ENOENT);
    };
    let node = match node {
        Some(node) => node,
        None => synthesize_virtual_node(fstype, &rel_path, mounts, caller, hostname, boot_id_seed)?,
    };
    Ok((fstype, rel_path, node))
}

fn handle_openat_if_proc_or_sys(
    dirfd: u64,
    user_path: u64,
    flags: u64,
    mode: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let close_on_exec = (flags & O_CLOEXEC) != 0;
    let follow = (flags & O_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    enum OpenAction {
        NotOwned,
        HostAbsolute(Vec<u8>),
        Handled(Result<i64, Errno>),
    }
    let action = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return OpenAction::NotOwned,
            Err(errno) => return OpenAction::Handled(Err(errno)),
        };
        if let ResolvedVirtualTarget::HostAbsolute(host_path) = target {
            return OpenAction::HostAbsolute(host_path);
        }
        let (resolved_fs, resolved_rel, node) = match resolve_virtual_node_from_target(
            target,
            &state.mounts,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(v) => v,
            Err(errno) => return OpenAction::Handled(Err(errno)),
        };

        let rel = resolved_rel.as_slice();
        if (flags & O_PATH) == 0 && (flags & O_ACCMODE) != O_RDONLY {
            if resolved_fs == FilesystemType::Sysfs
                && super::step37_38_systemd_udev::is_sysfs_uevent_trigger_rel(rel)
            {
                return OpenAction::NotOwned;
            }
            return OpenAction::Handled(Err(Errno::EACCES));
        }
        if let VirtualNode::Symlink(_) = &node
            && (flags & O_NOFOLLOW) != 0
            && (flags & O_PATH) == 0
        {
            return OpenAction::Handled(Err(Errno::ELOOP));
        }
        let is_dir = matches!(node, VirtualNode::Directory(_));
        if (flags & O_DIRECTORY) != 0 && !is_dir {
            return OpenAction::Handled(Err(Errno::ENOTDIR));
        }

        let Some((slot_idx, _)) = state.fds.iter().enumerate().find(|(_, e)| !e.live) else {
            return OpenAction::Handled(Err(Errno::EMFILE));
        };
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1).max(1);
        let mut owners = DirectProcessRefs::empty();
        owners.init(owner, close_on_exec);
        let (content, dir_entries) = match node {
            VirtualNode::Directory(entries) => (Vec::new(), entries),
            VirtualNode::Regular(bytes) => (bytes, Vec::new()),
            VirtualNode::Symlink(bytes) => (bytes, Vec::new()),
        };
        state.fds[slot_idx] = ProcSysFdEntry {
            live: true,
            is_dir,
            generation,
            alias_refs: 0,
            owners,
            fstype: resolved_fs,
            rel_path: resolved_rel,
            offset: 0,
            content,
            dir_entries,
        };
        OpenAction::Handled(Ok(i64::from(PROC_SYS_FD_BASE + (slot_idx as i32))))
    })?;
    match action {
        OpenAction::NotOwned => Ok(None),
        OpenAction::HostAbsolute(host_path) => {
            if host_path.starts_with(b"/dev/")
                && let Some(ret) = super::step32_dev::try_open_dev_bytes(&host_path, flags)?
            {
                return Ok(Some(ret));
            }
            if let Some(ret) =
                super::step33_ext4_vfs::try_open_host_path(owner, &host_path, flags, mode)?
            {
                return Ok(Some(ret));
            }
            Ok(Some(encode_result(super::step29_fd::openat_host_path(
                owner, &host_path, flags, mode,
            )?)))
        }
        OpenAction::Handled(res) => Ok(Some(encode_result(res))),
    }
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let idx = (linux_signed_int(raw_fd) - PROC_SYS_FD_BASE) as usize;
    with_mount_state(|state| {
        let Some(entry) = state.fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry.live || !entry.owners.close_owner(owner) {
            return Err(Errno::EBADF);
        }
        retire_proc_sys_slot_if_unused(state, idx);
        Ok(0)
    })
}

fn handle_getdents64(
    raw_fd: u64,
    user_dirp: u64,
    raw_count: u64,
) -> Result<Result<i64, Errno>, ()> {
    if raw_count == 0 {
        return Ok(Err(Errno::EINVAL));
    }
    if user_dirp == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let count = usize::try_from(raw_count).unwrap_or(usize::MAX).min(16384);
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };

    let mut out = Vec::new();
    let prep = with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry_mut(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if !entry.is_dir {
            return Err(Errno::ENOTDIR);
        }
        let start_offset = entry.offset;
        while entry.offset < entry.dir_entries.len() {
            let item = &entry.dir_entries[entry.offset];
            let rec = super::step29_dirent::encode_parts_with_inode(
                item.ino,
                &item.name,
                item.kind,
                entry.offset + 1,
            )
            .map_err(|_| Errno::EINVAL)?;
            let bytes = rec.as_bytes();
            if out.len() + bytes.len() > count {
                if out.is_empty() {
                    entry.offset = start_offset;
                    return Err(Errno::EINVAL);
                }
                break;
            }
            out.extend_from_slice(bytes);
            entry.offset += 1;
        }
        Ok((out.len(), start_offset))
    })?;
    let (written, old_offset) = match prep {
        Ok(v) => v,
        Err(errno) => return Ok(Err(errno)),
    };
    if written > 0
        && let Err(errno) = copy_to_user(user_dirp, &out[..written])
    {
        let _ = with_mount_state(|state| {
            state.fds[idx].offset = old_offset;
        });
        return Ok(Err(errno));
    }
    Ok(Ok(written as i64))
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry_mut(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        let end_len = if entry.is_dir {
            entry.dir_entries.len() as i64
        } else {
            entry.content.len() as i64
        };
        let base: i64 = match whence {
            SEEK_SET => 0,
            SEEK_CUR => entry.offset as i64,
            SEEK_END => end_len,
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
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let mut temp = Vec::new();
    let copied = with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry_mut(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if entry.is_dir {
            return Err(Errno::EISDIR);
        }
        if entry.offset >= entry.content.len() {
            return Ok((0usize, 0usize));
        }
        let avail = entry.content.len() - entry.offset;
        let take = usize::try_from(count).unwrap_or(avail).min(avail);
        temp.extend_from_slice(&entry.content[entry.offset..entry.offset + take]);
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

fn virtual_node_mode_nlink_size(node: &VirtualNode, follow: bool) -> (u32, u32, u64) {
    match node {
        VirtualNode::Directory(_) => (S_IFDIR_RX_MODE, 2, 0),
        VirtualNode::Regular(bytes) => (S_IFREG_RO_MODE, 1, bytes.len() as u64),
        VirtualNode::Symlink(target) => {
            if !follow {
                (S_IFLNK_MODE, 1, target.len() as u64)
            } else if target.starts_with(b"/dev/") {
                (0o020_666, 1, 0)
            } else if target == b"/" {
                (S_IFDIR_RX_MODE, 2, 0)
            } else {
                (S_IFREG_RO_MODE, 1, 0)
            }
        }
    }
}

fn handle_readlinkat_if_proc_or_sys(
    dirfd: u64,
    user_path: u64,
    user_buf: u64,
    raw_bufsiz: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let caller = CallerSnapshotData::capture();
    enum ReadlinkAction {
        NotOwned,
        HostAbsolute(Vec<u8>),
        Handled(Result<i64, Errno>),
    }
    let mut target_out = Vec::new();
    let action = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            false,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return ReadlinkAction::NotOwned,
            Err(errno) => return ReadlinkAction::Handled(Err(errno)),
        };
        if (raw_bufsiz as i64) <= 0 {
            return ReadlinkAction::Handled(Err(Errno::EINVAL));
        }
        if user_buf == 0 {
            return ReadlinkAction::Handled(Err(Errno::EFAULT));
        }
        if let ResolvedVirtualTarget::HostAbsolute(host_path) = target {
            return ReadlinkAction::HostAbsolute(host_path);
        }
        match resolve_virtual_node_from_target(
            target,
            &state.mounts,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok((_, _, VirtualNode::Symlink(sym_target))) => {
                target_out = sym_target;
                ReadlinkAction::Handled(Ok(0))
            }
            Ok(_) => ReadlinkAction::Handled(Err(Errno::EINVAL)),
            Err(errno) => ReadlinkAction::Handled(Err(errno)),
        }
    })?;
    match action {
        ReadlinkAction::NotOwned => Ok(None),
        ReadlinkAction::HostAbsolute(host_path) => {
            if let Some(ret) =
                super::step33_ext4_vfs::try_readlink_host_path(&host_path, user_buf, raw_bufsiz)?
            {
                return Ok(Some(ret));
            }
            Ok(Some(encode_result(super::step29_fd::readlinkat_host_path(
                owner, &host_path, user_buf, raw_bufsiz,
            )?)))
        }
        ReadlinkAction::Handled(Err(errno)) => Ok(Some(SyscallReturn::error(errno))),
        ReadlinkAction::Handled(Ok(_)) => {
            let max_len = usize::try_from(raw_bufsiz).unwrap_or(usize::MAX);
            let copy_len = target_out.len().min(max_len);
            if copy_len > 0
                && let Err(errno) = copy_to_user(user_buf, &target_out[..copy_len])
            {
                return Ok(Some(SyscallReturn::error(errno)));
            }
            Ok(Some(encode_result(Ok(copy_len as i64))))
        }
    }
}

fn handle_newfstatat_if_proc_or_sys(
    dirfd: u64,
    user_path: u64,
    user_statbuf: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let allow_empty = (flags & AT_EMPTY_PATH) != 0;
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    enum StatAction {
        NotOwned,
        HostAbsolute(Vec<u8>),
        Err(Errno),
        Ok([u8; ARM64_STAT_BYTES]),
    }
    let result = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            allow_empty,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return StatAction::NotOwned,
            Err(errno) => return StatAction::Err(errno),
        };
        if user_statbuf == 0 {
            return StatAction::Err(Errno::EFAULT);
        }
        if let ResolvedVirtualTarget::HostAbsolute(host_path) = target {
            return StatAction::HostAbsolute(host_path);
        }
        match resolve_virtual_node_from_target(
            target,
            &state.mounts,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok((rfs, rrel, node)) => {
                let ino = virtual_inode(rfs, &rrel);
                let (mode, nlink, size) = virtual_node_mode_nlink_size(&node, follow);
                StatAction::Ok(encode_virtual_stat_with_ino_mode(ino, mode, nlink, size))
            }
            Err(errno) => StatAction::Err(errno),
        }
    })?;
    match result {
        StatAction::NotOwned => Ok(None),
        StatAction::HostAbsolute(host_path) => {
            if host_path.starts_with(b"/dev/")
                && let Some(ret) = super::step32_dev::try_stat_dev_bytes(&host_path, user_statbuf)?
            {
                return Ok(Some(ret));
            }
            if let Some(ret) =
                super::step33_ext4_vfs::try_stat_host_path(&host_path, user_statbuf, flags)?
            {
                return Ok(Some(ret));
            }
            Ok(Some(encode_result(super::step29_fd::newfstatat_host_path(
                owner,
                &host_path,
                user_statbuf,
                linux_unsigned_int(flags),
            )?)))
        }
        StatAction::Err(errno) => Ok(Some(SyscallReturn::error(errno))),
        StatAction::Ok(stat_bytes) => {
            if let Err(errno) = copy_to_user(user_statbuf, &stat_bytes) {
                return Ok(Some(SyscallReturn::error(errno)));
            }
            Ok(Some(SyscallReturn::success(0).ok_or(())?))
        }
    }
}

fn handle_statx_if_proc_or_sys(
    dirfd: u64,
    user_path: u64,
    flags: u64,
    _mask: u64,
    user_statx: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let allow_empty = (flags & AT_EMPTY_PATH) != 0;
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    enum StatxAction {
        NotOwned,
        HostAbsolute(Vec<u8>),
        Err(Errno),
        Ok([u8; ARM64_STATX_BYTES]),
    }
    let result = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            allow_empty,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return StatxAction::NotOwned,
            Err(errno) => return StatxAction::Err(errno),
        };
        let allowed_flags =
            AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE;
        if (flags & !allowed_flags) != 0 {
            return StatxAction::Err(Errno::EINVAL);
        }
        if user_statx == 0 {
            return StatxAction::Err(Errno::EFAULT);
        }
        if let ResolvedVirtualTarget::HostAbsolute(host_path) = target {
            return StatxAction::HostAbsolute(host_path);
        }
        match resolve_virtual_node_from_target(
            target,
            &state.mounts,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok((rfs, rrel, node)) => {
                let ino = virtual_inode(rfs, &rrel);
                let (mode, nlink, size) = virtual_node_mode_nlink_size(&node, follow);
                StatxAction::Ok(encode_virtual_statx(rfs, ino, mode, nlink, size))
            }
            Err(errno) => StatxAction::Err(errno),
        }
    })?;
    match result {
        StatxAction::NotOwned => Ok(None),
        StatxAction::HostAbsolute(host_path) => {
            if host_path.starts_with(b"/dev/")
                && let Some(ret) = super::step32_dev::try_statx_dev_bytes(&host_path, user_statx)?
            {
                return Ok(Some(ret));
            }
            if let Some(ret) =
                super::step33_ext4_vfs::try_statx_host_path(&host_path, user_statx, flags)?
            {
                return Ok(Some(ret));
            }
            Ok(Some(encode_result(super::step29_fd::statx_host_path(
                owner,
                &host_path,
                linux_unsigned_int(flags),
                user_statx,
            )?)))
        }
        StatxAction::Err(errno) => Ok(Some(SyscallReturn::error(errno))),
        StatxAction::Ok(statx_bytes) => {
            if let Err(errno) = copy_to_user(user_statx, &statx_bytes) {
                return Ok(Some(SyscallReturn::error(errno)));
            }
            Ok(Some(SyscallReturn::success(0).ok_or(())?))
        }
    }
}

fn handle_faccessat_if_proc_or_sys(
    dirfd: u64,
    user_path: u64,
    mode: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    enum AccessAction {
        NotOwned,
        HostAbsolute(Vec<u8>),
        Handled(Result<i64, Errno>),
    }
    let action = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return AccessAction::NotOwned,
            Err(errno) => return AccessAction::Handled(Err(errno)),
        };
        if (mode & !ACCESS_MODE_MASK) != 0 || (flags & !(AT_SYMLINK_NOFOLLOW | 0x200)) != 0 {
            return AccessAction::Handled(Err(Errno::EINVAL));
        }
        if let ResolvedVirtualTarget::HostAbsolute(host_path) = target {
            return AccessAction::HostAbsolute(host_path);
        }
        match resolve_virtual_node_from_target(
            target,
            &state.mounts,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok((rfs, rrel, _)) => {
                if (mode & W_OK) != 0
                    && !(rfs == FilesystemType::Sysfs
                        && super::step37_38_systemd_udev::is_sysfs_uevent_trigger_rel(&rrel))
                {
                    AccessAction::Handled(Err(Errno::EACCES))
                } else {
                    AccessAction::Handled(Ok(0))
                }
            }
            Err(errno) => AccessAction::Handled(Err(errno)),
        }
    })?;
    match action {
        AccessAction::NotOwned => Ok(None),
        AccessAction::HostAbsolute(host_path) => {
            if let Some(ret) =
                super::step33_ext4_vfs::try_access_host_path(owner, &host_path, mode, flags)?
            {
                return Ok(Some(ret));
            }
            Ok(Some(encode_result(super::step29_fd::faccessat_host_path(
                owner, &host_path,
            )?)))
        }
        AccessAction::Handled(res) => Ok(Some(encode_result(res))),
    }
}

fn handle_fstat(raw_fd: u64, user_statbuf: u64) -> Result<Result<i64, Errno>, ()> {
    if user_statbuf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let stat_res = with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry_mut(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        let ino = virtual_inode(entry.fstype, &entry.rel_path);
        if entry.is_dir {
            Ok(encode_virtual_stat_with_ino_mode(
                ino,
                S_IFDIR_RX_MODE,
                2,
                0,
            ))
        } else {
            Ok(encode_virtual_stat_with_ino_mode(
                ino,
                S_IFREG_RO_MODE,
                1,
                entry.content.len() as u64,
            ))
        }
    })?;
    let stat_bytes = match stat_res {
        Ok(s) => s,
        Err(errno) => return Ok(Err(errno)),
    };
    if let Err(errno) = copy_to_user(user_statbuf, &stat_bytes) {
        return Ok(Err(errno));
    }
    Ok(Ok(0))
}

fn build_proc_partitions() -> Vec<u8> {
    let mut out = Vec::from(&b"major minor  #blocks  name\n\n"[..]);
    let _ = super::step42_hardware::with_active_block_device(|dev, table| {
        let total_blocks = dev.total_sectors() / 2;
        out.extend_from_slice(b" 254        0 ");
        push_right_aligned_u64(&mut out, total_blocks, 10);
        out.extend_from_slice(b" vda\n");
        for part in table.slice() {
            let p_blocks = part.sector_count / 2;
            out.extend_from_slice(b" 254        ");
            out.extend_from_slice(&format_u64_bytes(u64::from(part.number)));
            out.push(b' ');
            push_right_aligned_u64(&mut out, p_blocks, 10);
            out.extend_from_slice(b" vda");
            out.extend_from_slice(&format_u64_bytes(u64::from(part.number)));
            out.push(b'\n');
        }
        Ok(())
    });
    out
}

fn push_right_aligned_u64(out: &mut Vec<u8>, val: u64, width: usize) {
    let digits = format_u64_bytes(val);
    for _ in digits.len()..width {
        out.push(b' ');
    }
    out.extend_from_slice(&digits);
}

fn sync_all_ext4_mounts(state: &mut Step33MountState) -> Result<(), Errno> {
    if !state.ext4_mounts.iter().any(|m| m.live) {
        return Ok(());
    }
    super::step42_hardware::with_active_block_device(|dev, _| {
        for slot in &mut state.ext4_mounts {
            if slot.live
                && let Some(ref mut vol) = slot.vol
            {
                vol.sync(dev)?;
            }
        }
        dev.flush()
    })
}

fn handle_sync() -> Result<Result<i64, Errno>, ()> {
    with_mount_state(|state| {
        state.ensure_initialized();
        let _ = state.journal.sync_all();
        sync_all_ext4_mounts(state)?;
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
        sync_all_ext4_mounts(state)?;
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

fn encode_virtual_stat_with_ino_mode(
    ino: u64,
    mode: u32,
    nlink: u32,
    size: u64,
) -> [u8; ARM64_STAT_BYTES] {
    let mut buf = [0u8; ARM64_STAT_BYTES];
    buf[8..16].copy_from_slice(&ino.to_le_bytes()); // st_ino
    buf[16..20].copy_from_slice(&mode.to_le_bytes()); // st_mode
    buf[20..24].copy_from_slice(&nlink.to_le_bytes()); // st_nlink
    buf[48..56].copy_from_slice(&(size as i64).to_le_bytes()); // st_size
    buf[56..60].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize
    buf
}

fn encode_virtual_statx(
    fstype: FilesystemType,
    ino: u64,
    mode: u32,
    nlink: u32,
    size: u64,
) -> [u8; ARM64_STATX_BYTES] {
    let mut buf = [0u8; ARM64_STATX_BYTES];
    let dev_minor = match fstype {
        FilesystemType::Procfs => 3u32,
        _ => 4u32,
    };
    let blocks = size.div_ceil(512);
    buf[0..4].copy_from_slice(&STATX_BASIC_STATS.to_le_bytes());
    buf[4..8].copy_from_slice(&4096u32.to_le_bytes());
    buf[16..20].copy_from_slice(&nlink.to_le_bytes());
    buf[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
    buf[32..40].copy_from_slice(&ino.to_le_bytes());
    buf[40..48].copy_from_slice(&size.to_le_bytes());
    buf[48..56].copy_from_slice(&blocks.to_le_bytes());
    buf[140..144].copy_from_slice(&dev_minor.to_le_bytes());
    buf
}

fn encode_ext4_statfs(info: Ext4StatFsInfo, flags: u64, ro: bool) -> [u8; ARM64_STATFS_BYTES] {
    let mut buf = [0u8; ARM64_STATFS_BYTES];
    let st_flags = if ro { flags | 1 } else { flags };
    buf[0..8].copy_from_slice(&FilesystemType::Ext4.f_type_magic().to_le_bytes());
    buf[8..16].copy_from_slice(&info.bsize.to_le_bytes());
    buf[16..24].copy_from_slice(&info.blocks.to_le_bytes());
    buf[24..32].copy_from_slice(&info.bfree.to_le_bytes());
    buf[32..40].copy_from_slice(&info.bavail.to_le_bytes());
    buf[40..48].copy_from_slice(&info.files.to_le_bytes());
    buf[48..56].copy_from_slice(&info.ffree.to_le_bytes());
    buf[64..72].copy_from_slice(&info.namelen.to_le_bytes());
    buf[72..80].copy_from_slice(&info.bsize.to_le_bytes());
    buf[80..88].copy_from_slice(&st_flags.to_le_bytes());
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
    kernal_usercopy_aarch64::copy_from_user(dst, user_src).map_err(super::map_usercopy_errno)
}

fn copy_to_user(user_dst: u64, src: &[u8]) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_to_user(user_dst, src).map_err(super::map_usercopy_errno)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_sys_fd_range_is_disjoint_from_step29_and_step32() {
        assert!(!is_proc_sys_fd(0));
        assert!(!is_proc_sys_fd(64));
        assert!(is_proc_sys_fd(PROC_SYS_FD_BASE as u64));
        assert!(is_proc_sys_fd(
            (PROC_SYS_FD_BASE + (MAX_PROC_SYS_FDS as i32) - 1) as u64
        ));
        assert!(!is_proc_sys_fd(
            (PROC_SYS_FD_BASE + (MAX_PROC_SYS_FDS as i32)) as u64
        ));
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
