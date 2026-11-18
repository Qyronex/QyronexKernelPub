// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use kernal_capability::ObjectId;
use kernal_linux_abi::{
    Errno, POLLERR, POLLIN, POLLOUT, POLLPRI, SyscallRequest, SyscallReturn, linux_signed_int,
    linux_unsigned_int,
};
use kernal_linux_fd::SubsystemHandle;
use kernal_linux_mounts::{
    BlockDevice, Ext4DurableJournal, Ext4StatFsInfo, Ext4Volume, FilesystemType, MAX_MOUNT_PATH,
    MS_BIND, MS_MOVE, MS_NODEV, MS_NOEXEC, MS_NOSUID, MS_PROPAGATION_MASK, MS_RDONLY, MS_REC,
    MS_REMOUNT, MS_SLAVE, MS_UNBINDABLE, MountEntry, MountTable, ProcPidSelector, ProcProcessInfo,
    ProcSysSnapshot, UMOUNT_NOFOLLOW, enumerate_sysfs_dir, parse_proc_pid_subpath,
    read_procfs_node, read_procfs_process_node, read_sysfs_node,
};
use kernal_linux_vfs::{LINUX_PATH_MAX, NodeKind};

use super::step_fd_util::{
    DirectProcessRefs, EPOCH_BASE_SECONDS, SUBSYS_DEV, SUBSYS_PROC_SYS, collect_process_fd_numbers,
    current_epoch_now_secs, current_scheduler_thread, current_uid_gid, decode_chown_id,
    describe_process_fd_target_with_proc_sys, lookup_aliased_subsystem,
    lookup_aliased_subsystem_current, parse_utimens_pair, read_user_iovec, write_aarch64_stat_meta,
    write_aarch64_statx_meta, write_linux_file_handle,
};
use super::step33_memfs::{MemFs, MemNodeKind, MemStat};

/// Dedicated file-descriptor base for Step-33 virtual mounts and filesystems (`416..672`),
/// partitioned cleanly above `EXT4_FD_BASE` (`288..416`).
pub(super) const PROC_SYS_FD_BASE: i32 = 416;
const MAX_PROC_SYS_FDS: usize = 256;
const MAX_MOUNTS: usize = 128;
const INIT_MNT_NS_ID: u32 = 0xf000_0001;
pub(super) const MAX_EXT4_MOUNTS: usize = 4;
const MAX_JOURNAL_ENTRIES: usize = 16;
const MAX_JOURNAL_DATA: usize = 256;
// `/proc/self/mountinfo` with the full systemd mount set (cgroup2, credentials, run-lock, tmp,
// ...) exceeds 4 KiB, and truncation hides the newest mounts from `libmount` observers.
const MAX_VIRTUAL_NODE_BYTES: usize = 16384;
const MAX_HOSTNAME_BYTES: usize = 64;
const ARM64_STATFS_BYTES: usize = 120;
const S_IFREG_RO_MODE: u32 = 0o100_444;
const S_IFREG_RW_MODE: u32 = 0o100_644;
const S_IFDIR_RX_MODE: u32 = 0o040_555;
const S_IFLNK_MODE: u32 = 0o120_777;
const RENAME_NOREPLACE: u64 = 1;

const AT_FDCWD_I32: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_STATX_SYNC_TYPE: u64 = 0x6000;
const W_OK: u64 = 2;
const ACCESS_MODE_MASK: u64 = 0x7;

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0x40;
const O_EXCL: u64 = 0x80;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;
const O_DIRECTORY: u64 = 0x4000;
const O_NOFOLLOW: u64 = 0x8000;
const O_CLOEXEC: u64 = 0x0008_0000;
const O_PATH: u64 = 0x0020_0000;
const O_TMPFILE: u64 = 0x0040_4000;

const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

#[derive(Clone)]
struct VirtualDirEntry {
    ino: u64,
    kind: NodeKind,
    name: Vec<u8>,
}

pub(super) struct ProcSysFdEntry {
    live: bool,
    is_dir: bool,
    generation: u64,
    alias_refs: usize,
    owners: DirectProcessRefs<{ super::step29_runtime::STEP29_RUNTIME_PROCESS_VIEWS }>,
    mount_id: u32,
    mnt_ns_id: u32,
    fstype: FilesystemType,
    mem_ino: u64,
    readable: bool,
    writable: bool,
    append: bool,
    path_only: bool,
    abs_path: Vec<u8>,
    rel_path: Vec<u8>,
    offset: usize,
    content: Vec<u8>,
    dir_entries: Vec<VirtualDirEntry>,
    last_mount_gen: u64,
    last_poll_gen: u64,
}

impl ProcSysFdEntry {
    const EMPTY: Self = Self {
        live: false,
        is_dir: false,
        generation: 0,
        alias_refs: 0,
        owners: DirectProcessRefs::empty(),
        mount_id: 0,
        mnt_ns_id: INIT_MNT_NS_ID,
        fstype: FilesystemType::Procfs,
        mem_ino: 0,
        readable: false,
        writable: false,
        append: false,
        path_only: false,
        abs_path: Vec::new(),
        rel_path: Vec::new(),
        offset: 0,
        content: Vec::new(),
        dir_entries: Vec::new(),
        last_mount_gen: 0,
        last_poll_gen: 0,
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

#[derive(Clone, Copy)]
struct BindMountMeta {
    live: bool,
    mount_id: u32,
    backing_mount_id: u32,
    backing_ext4_id: u32,
    bind_root_ino: u64,
    bind_prefix: [u8; MAX_MOUNT_PATH],
    bind_prefix_len: usize,
}

impl BindMountMeta {
    const EMPTY: Self = Self {
        live: false,
        mount_id: 0,
        backing_mount_id: 0,
        backing_ext4_id: 0,
        bind_root_ino: 0,
        bind_prefix: [0u8; MAX_MOUNT_PATH],
        bind_prefix_len: 0,
    };

    fn bind_prefix(&self) -> &[u8] {
        &self.bind_prefix[..self.bind_prefix_len]
    }
}

struct MountNsSlot {
    mnt_ns_id: u32,
    mounts_gen: u64,
    mounts: MountTable<MAX_MOUNTS>,
    bind_meta: [BindMountMeta; MAX_MOUNTS],
}

fn find_bind_meta(meta: &[BindMountMeta; MAX_MOUNTS], mount_id: u32) -> Option<&BindMountMeta> {
    meta.iter().find(|m| m.live && m.mount_id == mount_id)
}

fn upsert_bind_meta(meta: &mut [BindMountMeta; MAX_MOUNTS], item: BindMountMeta) {
    if let Some(slot) = meta
        .iter_mut()
        .find(|m| m.live && m.mount_id == item.mount_id)
    {
        *slot = item;
        return;
    }
    if let Some(slot) = meta.iter_mut().find(|m| !m.live) {
        *slot = item;
    }
}

struct Step33MountState {
    initialized: bool,
    next_generation: u64,
    mounts_gen: u64,
    next_global_mount_id: u32,
    next_ext4_mount_id: u32,
    mounts: MountTable<MAX_MOUNTS>,
    bind_meta: [BindMountMeta; MAX_MOUNTS],
    child_ns_mounts: Vec<Box<MountNsSlot>>,
    ext4_mounts: [Ext4MountSlot; MAX_EXT4_MOUNTS],
    initramfs_prefix: [u8; MAX_MOUNT_PATH],
    initramfs_prefix_len: usize,
    initramfs_unmounted: bool,
    fds: [ProcSysFdEntry; MAX_PROC_SYS_FDS],
    memfs: MemFs,
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
            mounts_gen: 1,
            next_global_mount_id: 1,
            next_ext4_mount_id: 1,
            mounts: MountTable::new(),
            bind_meta: [const { BindMountMeta::EMPTY }; MAX_MOUNTS],
            child_ns_mounts: Vec::new(),
            ext4_mounts: [const { Ext4MountSlot::EMPTY }; MAX_EXT4_MOUNTS],
            initramfs_prefix,
            initramfs_prefix_len: 1,
            initramfs_unmounted: false,
            fds: [const { ProcSysFdEntry::EMPTY }; MAX_PROC_SYS_FDS],
            memfs: MemFs::new(),
            journal: Ext4DurableJournal::new(),
            hostname,
            hostname_len: 7,
            boot_id_seed: [
                0x4b, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x51, 0x79, 0x72, 0x6f, 0x6e, 0x65, 0x78, 0x33,
                0x33, 0x01,
            ],
        }
    }

    fn ns_view(
        &self,
        mnt_ns_id: u32,
    ) -> (&MountTable<MAX_MOUNTS>, &[BindMountMeta; MAX_MOUNTS], u64) {
        if mnt_ns_id != INIT_MNT_NS_ID
            && let Some(slot) = self
                .child_ns_mounts
                .iter()
                .find(|s| s.mnt_ns_id == mnt_ns_id)
        {
            return (&slot.mounts, &slot.bind_meta, slot.mounts_gen);
        }
        (&self.mounts, &self.bind_meta, self.mounts_gen)
    }

    fn ns_mounts_gen(&self, mnt_ns_id: u32) -> u64 {
        self.ns_view(mnt_ns_id).2
    }

    fn ns_view_mut(
        &mut self,
        mnt_ns_id: u32,
    ) -> (
        &mut MountTable<MAX_MOUNTS>,
        &mut [BindMountMeta; MAX_MOUNTS],
        &mut u64,
    ) {
        if mnt_ns_id != INIT_MNT_NS_ID {
            if let Some(pos) = self
                .child_ns_mounts
                .iter()
                .position(|s| s.mnt_ns_id == mnt_ns_id)
            {
                let slot = &mut self.child_ns_mounts[pos];
                return (&mut slot.mounts, &mut slot.bind_meta, &mut slot.mounts_gen);
            }
        }
        (&mut self.mounts, &mut self.bind_meta, &mut self.mounts_gen)
    }

    fn bump_ns_mounts_gen(&mut self, mnt_ns_id: u32) {
        let (_, _, gen_ref) = self.ns_view_mut(mnt_ns_id);
        *gen_ref = gen_ref.wrapping_add(1).max(1);
    }

    fn sync_next_mount_id_before(&mut self, mnt_ns_id: u32) {
        let next = self.next_global_mount_id;
        let (mounts, _, _) = self.ns_view_mut(mnt_ns_id);
        mounts.set_next_mount_id(next);
    }

    fn sync_next_mount_id_after(&mut self, mnt_ns_id: u32) {
        let after = self.ns_view(mnt_ns_id).0.next_mount_id();
        if after > self.next_global_mount_id {
            self.next_global_mount_id = after;
        }
    }

    fn refresh_live_ext4_flag(&self) {
        let any = self.ext4_mounts.iter().any(|m| m.live);
        HAS_LIVE_EXT4_MOUNTS.store(any, Ordering::Release);
    }

    fn sync_memfs_mounts(&mut self, override_perm: Option<(u32, u32)>) {
        let now = current_epoch_now_secs();
        let memfs = &mut self.memfs;
        self.mounts.for_each_live(|mnt| {
            if (mnt.flags() & MS_BIND) != 0 {
                return;
            }
            let perm = override_perm
                .filter(|(id, _)| *id == mnt.mount_id())
                .map(|(_, p)| p);
            memfs.ensure_mount(mnt.mount_id(), mnt.fstype(), perm, now);
        });
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
        self.sync_memfs_mounts(None);
        self.next_global_mount_id = self.next_global_mount_id.max(self.mounts.next_mount_id());
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
        if let Ok(ext4_id) = mount_ext4_slot(self, source, b"/", flags) {
            if let Ok(tbl_id) = self.mounts.mount(source, b"/", Some(b"ext4"), flags) {
                let mut meta = BindMountMeta::EMPTY;
                meta.live = true;
                meta.mount_id = tbl_id;
                meta.backing_ext4_id = ext4_id;
                upsert_bind_meta(&mut self.bind_meta, meta);
            }
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

pub(super) fn is_open_proc_sys_fd(process: ObjectId, raw_fd: u64) -> bool {
    if !is_proc_sys_fd(raw_fd) {
        return false;
    }
    let idx = (linux_signed_int(raw_fd) - PROC_SYS_FD_BASE) as usize;
    with_mount_state(|state| resolve_proc_sys_entry(state, process, idx, None).is_some())
        .unwrap_or(false)
}

fn retire_proc_sys_slot_if_unused(state: &mut Step33MountState, slot_idx: usize) {
    let Some(entry) = state.fds.get_mut(slot_idx) else {
        return;
    };
    if entry.live && entry.owners.is_empty() && entry.alias_refs == 0 {
        if entry.mem_ino != 0 {
            state.memfs.release_fd(entry.mount_id, entry.mem_ino);
        }
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
            let Some(entry) = resolve_proc_sys_entry(state, process, slot_idx, alias_gen) else {
                return Err(Errno::EBADF);
            };
            if entry.mem_ino != 0
                && let Some(ms) = state.memfs.stat_ino(entry.mount_id, entry.mem_ino)
                && ms.kind == MemNodeKind::Fifo
            {
                let mut mask = u32::from(POLLOUT);
                if ms.size > 0 {
                    mask |= u32::from(POLLIN);
                }
                return Ok(mask);
            }
            let mut mask = u32::from(POLLIN) | u32::from(POLLOUT);
            if entry.fstype == FilesystemType::Procfs
                && !entry.is_dir
                && entry.mem_ino == 0
                && is_live_mountinfo_proc_path(&entry.rel_path)
            {
                if entry.last_poll_gen != state.mounts_gen {
                    mask |= u32::from(POLLPRI) | u32::from(POLLERR);
                }
            }
            Ok(mask)
        })
        .map_err(|()| Errno::EIO)?
    })();
    Some(res)
}

/// Consumes a pending `POLLPRI`/`POLLERR` change notification on an open `/proc/*/mountinfo`
/// or `/proc/mounts` descriptor once `epoll`/`poll` has delivered the event to userspace.
pub(super) fn ack_mountinfo_poll_change(process: ObjectId, raw_fd: u64) -> bool {
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(process, raw_fd) else {
        return false;
    };
    with_mount_state(|state| {
        let cur_gen = state.mounts_gen;
        if let Some(entry) = resolve_proc_sys_entry_mut(state, process, idx, alias_gen)
            && entry.fstype == FilesystemType::Procfs
            && !entry.is_dir
            && entry.mem_ino == 0
            && is_live_mountinfo_proc_path(&entry.rel_path)
        {
            entry.last_poll_gen = cur_gen;
            return true;
        }
        false
    })
    .unwrap_or(false)
}

pub(super) fn try_read_proc_sys_fd_for_mmap(
    process: ObjectId,
    raw_fd: u64,
    require_writable: bool,
) -> Result<Option<(Vec<u8>, Option<(u32, u64)>)>, Errno> {
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(process, raw_fd) else {
        return Ok(None);
    };
    let caller = CallerSnapshotData::capture();
    let res = with_mount_state(|state| {
        refresh_procfs_fd_entry(state, idx, &caller);
        let Some(entry) = resolve_proc_sys_entry(state, process, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if entry.path_only || !entry.readable || entry.is_dir {
            return Err(Errno::EACCES);
        }
        if entry.mem_ino != 0 {
            if require_writable && !entry.writable {
                return Err(Errno::EACCES);
            }
            let mount_id = entry.mount_id;
            let mem_ino = entry.mem_ino;
            let st = state
                .memfs
                .stat_ino(mount_id, mem_ino)
                .ok_or(Errno::EBADF)?;
            let sz = usize::try_from(st.size).map_err(|_| Errno::ENOMEM)?;
            let mut out = vec![0u8; sz];
            let mut read = 0usize;
            while read < sz {
                let n = state
                    .memfs
                    .read_at(mount_id, mem_ino, read, &mut out[read..])?;
                if n == 0 {
                    break;
                }
                read += n;
            }
            out.truncate(read);
            Ok((out, Some((mount_id, mem_ino))))
        } else {
            if require_writable {
                return Err(Errno::EACCES);
            }
            Ok((entry.content.clone(), None))
        }
    })
    .map_err(|()| Errno::EIO)?;
    res.map(Some)
}

pub(super) fn write_back_memfs_mmap(mount_id: u32, mem_ino: u64, file_offset: usize, data: &[u8]) {
    let now = current_epoch_now_secs();
    let _ = with_mount_state(|state| {
        if let Some(st) = state.memfs.stat_ino(mount_id, mem_ino) {
            let take = usize::try_from(st.size)
                .unwrap_or(0)
                .saturating_sub(file_offset)
                .min(data.len());
            if take > 0 {
                let _ =
                    state
                        .memfs
                        .write_at(mount_id, mem_ino, file_offset, &data[..take], false, now);
            }
        }
    });
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

pub(super) fn describe_proc_sys_entry_in_slice(
    fds: &[ProcSysFdEntry],
    slot: u16,
    generation: Option<u64>,
    process: Option<ObjectId>,
    out: &mut [u8],
) -> Option<usize> {
    let entry = fds.get(usize::from(slot))?;
    if !entry.live {
        return None;
    }
    if let Some(expected_gen) = generation {
        if entry.generation != expected_gen || entry.alias_refs == 0 {
            return None;
        }
    } else if let Some(owner) = process
        && !entry.owners.has_owner(owner)
    {
        return None;
    }
    let path_slice: &[u8] = if !entry.abs_path.is_empty() {
        &entry.abs_path
    } else {
        match entry.fstype {
            FilesystemType::Procfs => &b"/proc"[..],
            _ => &b"/sys"[..],
        }
    };
    let c = path_slice.len().min(out.len());
    out[..c].copy_from_slice(&path_slice[..c]);
    Some(c)
}

pub(super) fn describe_proc_sys_slot(
    slot: u16,
    generation: Option<u64>,
    process: Option<ObjectId>,
    out: &mut [u8],
) -> Option<usize> {
    let mut written = None;
    let _ = with_mount_state(|state| {
        written = describe_proc_sys_entry_in_slice(&state.fds, slot, generation, process, out);
    });
    written
}

fn entry_status_flags(entry: &ProcSysFdEntry) -> u64 {
    if entry.path_only {
        return O_PATH;
    }
    let acc = match (entry.readable, entry.writable) {
        (true, true) => O_RDWR,
        (false, true) => O_WRONLY,
        _ => O_RDONLY,
    };
    if entry.append { acc | O_APPEND } else { acc }
}

fn is_aliased_proc_sys_fd(raw_fd: u64) -> bool {
    lookup_aliased_subsystem_current(raw_fd).is_some_and(|h| h.kind == SUBSYS_PROC_SYS)
}

fn retain_mount_slot(
    idx: usize,
    owner: Option<ObjectId>,
    expected_gen: Option<u64>,
) -> Result<(SubsystemHandle, u64), Errno> {
    with_mount_state(|state| {
        let Some(entry) = state.fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        let valid = entry.live
            && owner.map_or(true, |p| entry.owners.has_owner(p))
            && expected_gen.map_or(true, |g| entry.generation == g);
        if !valid {
            return Err(Errno::EBADF);
        }
        entry.alias_refs += 1;
        let status = entry_status_flags(entry);
        Ok((
            SubsystemHandle {
                kind: SUBSYS_PROC_SYS,
                slot: idx as u16,
                generation: entry.generation,
            },
            status,
        ))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn retain_alias_handle(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(SubsystemHandle, u64), Errno> {
    if !is_proc_sys_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let idx = (linux_signed_int(raw_fd) - PROC_SYS_FD_BASE) as usize;
    retain_mount_slot(idx, Some(process), None)
}

pub(super) fn retain_existing_handle(
    handle: SubsystemHandle,
) -> Result<(SubsystemHandle, u64), Errno> {
    if handle.kind != SUBSYS_PROC_SYS {
        return Err(Errno::EBADF);
    }
    retain_mount_slot(handle.slot as usize, None, Some(handle.generation))
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
            3 => Ok(entry_status_flags(entry) as i64),
            4 => {
                if !entry.path_only {
                    entry.append = ((argi as u64) & O_APPEND) != 0;
                }
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

pub(super) fn close_range_for_process(
    process: ObjectId,
    first: u32,
    last: u32,
    cloexec_only: bool,
) {
    let _ = with_mount_state(|state| {
        for idx in 0..MAX_PROC_SYS_FDS {
            let fd = PROC_SYS_FD_BASE + (idx as i32);
            if super::step_fd_util::fd_in_close_range(fd, first, last)
                && state.fds[idx].live
                && state.fds[idx]
                    .owners
                    .apply_close_range(process, cloexec_only)
            {
                retire_proc_sys_slot_if_unused(state, idx);
            }
        }
    });
}

/// Intercepts Step-33 mount/filesystem syscalls and virtual mount operations (`/proc`, `/sys`,
/// `/sys/fs/cgroup`, `/dev`, `/dev/pts`, `/run`, `/dev/shm`, `tmpfs`).
pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    let owns_fd = |fd: u64| is_proc_sys_fd(fd) || is_aliased_proc_sys_fd(fd);
    match request.number {
        // ioctl(fd, req, arg)
        29 if owns_fd(request.args[0]) => Ok(Some(SyscallReturn::error(Errno::ENOTTY))),
        // mknodat(dirfd, pathname, mode, dev)
        33 => handle_mknodat_virtual(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // mkdirat(dirfd, pathname, mode)
        34 => handle_mkdirat_virtual(request.args[0], request.args[1], request.args[2]),
        // unlinkat(dirfd, pathname, flags)
        35 => handle_unlinkat_virtual(request.args[0], request.args[1], request.args[2]),
        // symlinkat(target, newdirfd, linkpath)
        36 => handle_symlinkat_virtual(request.args[0], request.args[1], request.args[2]),
        // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        37 => handle_linkat_virtual(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // renameat(olddirfd, oldpath, newdirfd, newpath)
        38 => handle_renameat_virtual(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            0,
        ),
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
            request.args[4],
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
        // truncate(path, length)
        45 => handle_truncate_virtual(request.args[0], request.args[1] as i64),
        // ftruncate(fd, length)
        46 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_ftruncate(
            request.args[0],
            request.args[1] as i64,
        )?))),
        // fallocate(fd, mode, offset, len)
        47 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_fallocate(
            request.args[0],
            request.args[1],
            request.args[2] as i64,
            request.args[3] as i64,
        )?))),
        // faccessat(dirfd, pathname, mode)
        48 => handle_faccessat_if_proc_or_sys(request.args[0], request.args[1], request.args[2], 0),
        // fchmod(fd, mode)
        52 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_fchmod(
            request.args[0],
            request.args[1],
        )?))),
        // fchmodat(dirfd, pathname, mode)
        53 => handle_fchmodat_virtual(request.args[0], request.args[1], request.args[2], 0),
        // fchownat(dirfd, pathname, uid, gid, flags)
        54 => handle_fchownat_virtual(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // fchown(fd, uid, gid)
        55 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_fchown(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
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
        61 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_getdents64(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // lseek(fd, offset, whence)
        62 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            linux_signed_int(request.args[2]),
        )?))),
        // read(fd, buf, count)
        63 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
            None,
        )?))),
        // write(fd, buf, count)
        64 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2],
            None,
        )?))),
        // readv(fd, iov, iovcnt)
        65 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_readv(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // writev(fd, iov, iovcnt)
        66 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_writev(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // pread64(fd, buf, count, offset)
        67 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
            Some(request.args[3] as i64),
        )?))),
        // pwrite64(fd, buf, count, offset)
        68 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2],
            Some(request.args[3] as i64),
        )?))),
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
        80 if owns_fd(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        // sync()
        81 => Ok(Some(encode_result(handle_sync()?))),
        // fsync(fd) | fdatasync(fd) | syncfs(fd)
        82 | 83 | 267 => Ok(Some(encode_result(handle_fsync(request.args[0])?))),
        // utimensat(dirfd, pathname, times, flags)
        88 => handle_utimensat_virtual(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // sethostname(name, len)
        161 => Ok(Some(encode_result(handle_sethostname(
            request.args[0],
            request.args[1],
        )?))),
        // name_to_handle_at(dirfd, pathname, handle, mount_id, flags)
        264 => handle_name_to_handle_at(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        276 => handle_renameat_virtual(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // statx(dirfd, pathname, flags, mask, statxbuf)
        291 => handle_statx_if_proc_or_sys(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // openat2(dirfd, pathname, how, size)
        437 => handle_openat2_if_proc_or_sys(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // faccessat2(dirfd, pathname, mode, flags)
        439 => handle_faccessat_if_proc_or_sys(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // fchmodat2(dirfd, pathname, mode, flags)
        452 => handle_fchmodat_virtual(
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
    mnt_ns_id: u32,
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
        let mnt_ns_id = current_process_id()
            .map(super::step41_container::process_mnt_ns_id)
            .unwrap_or(INIT_MNT_NS_ID);

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
            mnt_ns_id,
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
            online_cpus: u32::from(super::super::online_cpu_count()),
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

pub(super) fn ensure_boot_initialized() {
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
    });
}

pub(super) const fn is_virtual_fstype(fstype: FilesystemType) -> bool {
    matches!(
        fstype,
        FilesystemType::Procfs
            | FilesystemType::Sysfs
            | FilesystemType::Devtmpfs
            | FilesystemType::Devpts
            | FilesystemType::Cgroup2
            | FilesystemType::Tmpfs
            | FilesystemType::Ramfs
    )
}

pub(super) const fn is_memfs_fstype(fstype: FilesystemType) -> bool {
    matches!(
        fstype,
        FilesystemType::Tmpfs
            | FilesystemType::Ramfs
            | FilesystemType::Devtmpfs
            | FilesystemType::Devpts
    )
}

pub(super) fn dev_and_mnt_id_for_fstype(fstype: FilesystemType) -> (u64, u32, u32, u32) {
    let mut found_id: Option<u32> = None;
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        state.mounts.for_each_live(|m| {
            if m.fstype() == fstype && found_id.is_none() {
                found_id = Some(m.mount_id());
            }
        });
    });
    let mnt_id = found_id.unwrap_or(match fstype {
        FilesystemType::Devtmpfs => 2,
        FilesystemType::Devpts => 3,
        FilesystemType::Procfs => 4,
        FilesystemType::Sysfs => 5,
        FilesystemType::Tmpfs => 6,
        FilesystemType::Ramfs => 7,
        _ => 1,
    });
    let (maj, min) = fstype.st_dev_pair(mnt_id);
    (fstype.st_dev(mnt_id), maj, min, mnt_id)
}

pub(super) fn clone_mount_ns(old_mnt_id: u32, new_mnt_id: u32) {
    if new_mnt_id == INIT_MNT_NS_ID || old_mnt_id == new_mnt_id {
        return;
    }
    let existing_ids: Vec<u32> =
        with_mount_state(|state| state.child_ns_mounts.iter().map(|s| s.mnt_ns_id).collect())
            .unwrap_or_default();
    let dead_ids: Vec<u32> = existing_ids
        .into_iter()
        .filter(|&id| id != old_mnt_id && !super::step41_container::is_mnt_ns_in_use(id))
        .collect();
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        for dead in &dead_ids {
            if let Some(pos) = state
                .child_ns_mounts
                .iter()
                .position(|s| s.mnt_ns_id == *dead)
            {
                let removed = state.child_ns_mounts.swap_remove(pos);
                for meta in &removed.bind_meta {
                    if meta.live && meta.backing_mount_id != 0 && meta.bind_root_ino != 0 {
                        state
                            .memfs
                            .release_fd(meta.backing_mount_id, meta.bind_root_ino);
                    }
                }
            }
        }
        if state
            .child_ns_mounts
            .iter()
            .any(|s| s.mnt_ns_id == new_mnt_id)
        {
            return;
        }
        let (cloned_mounts, cloned_meta) = {
            let (src_mounts, src_meta, _) = state.ns_view(old_mnt_id);
            (src_mounts.clone_into_child_namespace(true), *src_meta)
        };
        for meta in &cloned_meta {
            if meta.live && meta.backing_mount_id != 0 && meta.bind_root_ino != 0 {
                state
                    .memfs
                    .retain_fd(meta.backing_mount_id, meta.bind_root_ino);
            }
        }
        state.child_ns_mounts.push(Box::new(MountNsSlot {
            mnt_ns_id: new_mnt_id,
            mounts_gen: 1,
            mounts: cloned_mounts,
            bind_meta: cloned_meta,
        }));
    });
}

fn resolve_ext4_entry_backing(
    state: &Step33MountState,
    bind_meta: &[BindMountMeta; MAX_MOUNTS],
    entry: &MountEntry,
) -> Option<(u32, u32)> {
    if entry.fstype() != FilesystemType::Ext4 {
        return None;
    }
    if let Some(meta) = find_bind_meta(bind_meta, entry.mount_id())
        && meta.backing_ext4_id != 0
    {
        if state
            .ext4_mounts
            .iter()
            .any(|m| m.live && m.mount_id == meta.backing_ext4_id)
        {
            return Some((meta.backing_ext4_id, meta.bind_root_ino as u32));
        }
    }
    state
        .ext4_mounts
        .iter()
        .find(|m| m.live && &m.mount_path[..m.mount_path_len] == entry.target())
        .map(|m| (m.mount_id, 0))
}

pub(super) fn ext4_table_mount_id_for_path(
    process: ObjectId,
    abs_path: &[u8],
    ext4_slot_id: u32,
) -> (u32, bool) {
    let mnt_ns_id = super::step41_container::process_mnt_ns_id(process);
    let mut out = (ext4_slot_id, false);
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        let (mounts, _, _) = state.ns_view(mnt_ns_id);
        if !abs_path.is_empty()
            && let Ok((entry, rel)) = mounts.resolve(abs_path)
            && entry.fstype() == FilesystemType::Ext4
        {
            out = (entry.mount_id(), rel.is_empty());
            return;
        }
        if let Some(slot) = state
            .ext4_mounts
            .iter()
            .find(|m| m.live && m.mount_id == ext4_slot_id)
        {
            let mp = &slot.mount_path[..slot.mount_path_len];
            if let Ok((entry, _)) = mounts.resolve(mp) {
                out = (entry.mount_id(), false);
            }
        }
    });
    out
}

pub(super) fn fd_dir_abs_path(process: ObjectId, raw_fd: u64) -> Option<Result<Vec<u8>, Errno>> {
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(process, raw_fd) else {
        return None;
    };
    let res = with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry(state, process, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if !entry.is_dir {
            return Err(Errno::ENOTDIR);
        }
        Ok(entry.abs_path.clone())
    });
    Some(match res {
        Ok(inner) => inner,
        Err(()) => Err(Errno::EIO),
    })
}

pub(super) fn has_live_ext4_mounts() -> bool {
    HAS_LIVE_EXT4_MOUNTS.load(Ordering::Acquire)
}

pub(super) fn has_virtual_mount_prefix(process: ObjectId, abs_path: &[u8]) -> bool {
    if !abs_path.starts_with(b"/") {
        return false;
    }
    let mnt_ns_id = super::step41_container::process_mnt_ns_id(process);
    let mut result = false;
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        let (mounts, _, _) = state.ns_view(mnt_ns_id);
        let Ok((entry, _)) = mounts.resolve(abs_path) else {
            return;
        };
        if is_virtual_fstype(entry.fstype()) {
            let virt_len = entry.target().len();
            let ext4_len = if mnt_ns_id == INIT_MNT_NS_ID {
                state
                    .ext4_mounts
                    .iter()
                    .filter(|m| {
                        m.live && path_matches_prefix(abs_path, &m.mount_path[..m.mount_path_len])
                    })
                    .map(|m| m.mount_path_len)
                    .max()
                    .unwrap_or(0)
            } else {
                0
            };
            result = virt_len >= ext4_len;
        }
    });
    result
}

pub(super) fn has_ext4_descendant_under(process: ObjectId, dir_abs: &[u8]) -> bool {
    if !dir_abs.starts_with(b"/") {
        return false;
    }
    let mnt_ns_id = super::step41_container::process_mnt_ns_id(process);
    let mut found = false;
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        let (mounts, _, _) = state.ns_view(mnt_ns_id);
        mounts.for_each_live(|e| {
            if e.fstype() == FilesystemType::Ext4
                && e.target().len() > dir_abs.len()
                && path_starts_with_mount(e.target(), dir_abs)
            {
                found = true;
            }
        });
    });
    found
}

pub(super) fn resolve_ext4_mount(process: ObjectId, abs_path: &[u8]) -> Option<(u32, usize, u32)> {
    if !has_live_ext4_mounts() || !abs_path.starts_with(b"/") {
        return None;
    }
    let mnt_ns_id = super::step41_container::process_mnt_ns_id(process);
    let mut best: Option<(u32, usize, u32)> = None;
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        let (mounts, bind_meta, _) = state.ns_view(mnt_ns_id);
        if let Ok((entry, _)) = mounts.resolve(abs_path) {
            if is_virtual_fstype(entry.fstype()) {
                return;
            }
            if let Some((ext4_id, start_ino)) = resolve_ext4_entry_backing(state, bind_meta, &entry)
            {
                best = Some((ext4_id, entry.target().len(), start_ino));
                return;
            }
        }
        if mnt_ns_id == INIT_MNT_NS_ID {
            for slot in &state.ext4_mounts {
                if !slot.live {
                    continue;
                }
                let mp = &slot.mount_path[..slot.mount_path_len];
                if path_matches_prefix(abs_path, mp)
                    && best.is_none_or(|(_, blen, _)| slot.mount_path_len >= blen)
                {
                    best = Some((slot.mount_id, slot.mount_path_len, 0));
                }
            }
        }
    });
    best
}

pub(super) fn ext4_mount_at_exact(process: ObjectId, abs_path: &[u8]) -> Option<(u32, u32)> {
    if !has_live_ext4_mounts() {
        return None;
    }
    let mnt_ns_id = super::step41_container::process_mnt_ns_id(process);
    let mut found = None;
    let _ = with_mount_state(|state| {
        state.ensure_initialized();
        let (mounts, bind_meta, _) = state.ns_view(mnt_ns_id);
        if let Ok((entry, rel)) = mounts.resolve(abs_path)
            && rel.is_empty()
            && entry.fstype() == FilesystemType::Ext4
        {
            found = resolve_ext4_entry_backing(state, bind_meta, &entry);
            if found.is_some() {
                return;
            }
        }
        if mnt_ns_id == INIT_MNT_NS_ID {
            for slot in &state.ext4_mounts {
                if slot.live && &slot.mount_path[..slot.mount_path_len] == abs_path {
                    found = Some((slot.mount_id, 0));
                    break;
                }
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

fn parse_mount_mode_opt(user_data: u64) -> Option<u32> {
    if user_data == 0 {
        return None;
    }
    let mut buf = [0u8; 128];
    let len = read_user_cstr(user_data, &mut buf).ok()?;
    for opt in buf[..len].split(|&b| b == b',') {
        if let Some(val) = opt.strip_prefix(b"mode=") {
            if val.is_empty() {
                continue;
            }
            let mut acc = 0u32;
            let mut valid = true;
            for &b in val {
                if !(b'0'..=b'7').contains(&b) {
                    valid = false;
                    break;
                }
                acc = (acc << 3) | u32::from(b - b'0');
            }
            if valid {
                return Some(acc & 0o7777);
            }
        }
    }
    None
}

enum CrossHop {
    Done(Vec<u8>),
    Continue(Vec<u8>),
}

fn resolve_virtual_hop(
    owner: ObjectId,
    candidate: &[u8],
    follow_final: bool,
) -> Result<CrossHop, Errno> {
    let caller = CallerSnapshotData::capture();
    with_mount_state(|state| {
        state.ensure_initialized();
        match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            candidate,
            None,
            false,
            false,
            follow_final,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(None) => Ok(CrossHop::Done(candidate.to_vec())),
            Ok(Some(ResolvedVirtualTarget::Virtual { abs_path, .. })) => {
                Ok(CrossHop::Done(abs_path))
            }
            Ok(Some(ResolvedVirtualTarget::HostAbsolute(host))) => Ok(CrossHop::Continue(host)),
            Ok(Some(ResolvedVirtualTarget::MissingLeaf { .. })) => Err(Errno::ENOENT),
            Err(e) => Err(e),
        }
    })
    .map_err(|()| Errno::EIO)?
    .map_err(|e| e)
}

pub(super) fn resolve_virtual_host_target_once(
    owner: ObjectId,
    virt_abs: &[u8],
    follow_final: bool,
) -> Result<Option<Vec<u8>>, Errno> {
    match resolve_virtual_hop(owner, virt_abs, follow_final)? {
        CrossHop::Continue(host) => Ok(Some(host)),
        CrossHop::Done(_) => Ok(None),
    }
}

fn resolve_mount_syscall_path(
    owner: ObjectId,
    raw_path: &[u8],
    follow_final: bool,
    out: &mut [u8],
) -> Result<usize, Errno> {
    let mut cur = raw_path.to_vec();
    for _ in 0..8 {
        let mut ext4_buf = vec![0u8; LINUX_PATH_MAX];
        let ext4_len = super::step33_ext4_vfs::resolve_abs_for_current_with_follow(
            &cur,
            follow_final,
            &mut ext4_buf,
        )?;
        match resolve_virtual_hop(owner, &ext4_buf[..ext4_len], follow_final)? {
            CrossHop::Done(resolved) => {
                if resolved.len() > out.len() {
                    return Err(Errno::ENAMETOOLONG);
                }
                out[..resolved.len()].copy_from_slice(&resolved);
                return Ok(resolved.len());
            }
            CrossHop::Continue(host) => {
                cur = host;
            }
        }
    }
    Err(Errno::ELOOP)
}

fn walk_memfs_ino_from(
    memfs: &MemFs,
    mount_id: u32,
    start_ino: u64,
    parts: &[Vec<u8>],
) -> Result<u64, Errno> {
    let mut ino = if start_ino != 0 {
        memfs
            .stat_ino(mount_id, start_ino)
            .ok_or(Errno::ENOENT)?
            .ino
    } else {
        memfs.root_stat(mount_id).ok_or(Errno::ENOENT)?.ino
    };
    for seg in parts {
        let child = memfs
            .lookup_child_stat(mount_id, ino, seg)
            .ok_or(Errno::ENOENT)?;
        ino = child.ino;
    }
    Ok(ino)
}

fn apply_bind_mount_in_state(
    state: &mut Step33MountState,
    mnt_ns_id: u32,
    source_slice: &[u8],
    target_slice: &[u8],
    flags: u64,
    ext4_bind_src: Option<(u32, u32)>,
) -> Result<i64, Errno> {
    let mut norm_src_buf = [0u8; MAX_MOUNT_PATH];
    let norm_src_len = normalize_mount_path_slice(source_slice, &mut norm_src_buf)?;
    let norm_src = &norm_src_buf[..norm_src_len];
    let mut norm_tgt_buf = [0u8; MAX_MOUNT_PATH];
    let norm_tgt_len = normalize_mount_path_slice(target_slice, &mut norm_tgt_buf)?;
    let norm_tgt = &norm_tgt_buf[..norm_tgt_len];

    struct RecSub {
        sub_src: Vec<u8>,
        sub_tgt: Vec<u8>,
        fstype: FilesystemType,
        flags: u64,
        meta: BindMountMeta,
    }

    let (root_fstype, root_flags, mut root_meta, rec_subs) = {
        let (mounts, bind_meta, _) = state.ns_view(mnt_ns_id);
        let (src_entry, src_rel) = mounts.resolve(norm_src)?;
        if (src_entry.flags() & MS_UNBINDABLE) != 0 {
            return Err(Errno::EINVAL);
        }
        let src_meta = find_bind_meta(bind_meta, src_entry.mount_id()).copied();
        let base_prefix = src_meta.as_ref().map(|m| m.bind_prefix()).unwrap_or(b"");
        let full_prefix = if src_rel.is_empty() {
            base_prefix.to_vec()
        } else {
            join_rel(base_prefix, src_rel)
        };
        if full_prefix.len() > MAX_MOUNT_PATH {
            return Err(Errno::ENAMETOOLONG);
        }
        let mut meta = BindMountMeta::EMPTY;
        meta.live = true;
        meta.bind_prefix[..full_prefix.len()].copy_from_slice(&full_prefix);
        meta.bind_prefix_len = full_prefix.len();

        if src_entry.fstype() == FilesystemType::Ext4 {
            let Some((ext4_id, ino)) = ext4_bind_src else {
                return Err(Errno::ENOENT);
            };
            meta.backing_ext4_id = ext4_id;
            meta.bind_root_ino = u64::from(ino);
        } else if is_memfs_fstype(src_entry.fstype()) {
            let mem_id = src_meta
                .as_ref()
                .and_then(|m| {
                    if m.backing_mount_id != 0 {
                        Some(m.backing_mount_id)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| src_entry.mount_id());
            let start_ino = src_meta.as_ref().map_or(0, |m| m.bind_root_ino);
            let parts = split_nonempty_segments(src_rel);
            let target_ino = walk_memfs_ino_from(&state.memfs, mem_id, start_ino, &parts)?;
            meta.backing_mount_id = mem_id;
            meta.bind_root_ino = target_ino;
        } else {
            meta.backing_mount_id = src_meta
                .as_ref()
                .and_then(|m| {
                    if m.backing_mount_id != 0 {
                        Some(m.backing_mount_id)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| src_entry.mount_id());
        }

        let rflags = (src_entry.flags() & (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC))
            | MS_BIND
            | MS_SLAVE
            | (flags & MS_RDONLY);

        let mut subs: Vec<RecSub> = Vec::new();
        if (flags & MS_REC) != 0 {
            let strip_len = if norm_src == b"/" { 0 } else { norm_src.len() };
            mounts.for_each_live(|sub| {
                let stgt = sub.target();
                let is_desc = if norm_src == b"/" {
                    stgt != b"/"
                } else {
                    stgt.len() > norm_src.len()
                        && stgt.starts_with(norm_src)
                        && stgt[norm_src.len()] == b'/'
                };
                if !is_desc || path_starts_with_mount(stgt, norm_tgt) {
                    return;
                }
                let suffix = &stgt[strip_len..];
                let mut new_tgt = Vec::with_capacity(norm_tgt.len() + suffix.len());
                if norm_tgt != b"/" {
                    new_tgt.extend_from_slice(norm_tgt);
                }
                new_tgt.extend_from_slice(suffix);
                if new_tgt.is_empty() || new_tgt.len() > MAX_MOUNT_PATH {
                    return;
                }
                let mut smeta = find_bind_meta(bind_meta, sub.mount_id())
                    .copied()
                    .unwrap_or(BindMountMeta::EMPTY);
                smeta.live = true;
                smeta.mount_id = 0;
                if sub.fstype() == FilesystemType::Ext4 && smeta.backing_ext4_id == 0 {
                    if let Some((eid, eino)) = resolve_ext4_entry_backing(state, bind_meta, sub) {
                        smeta.backing_ext4_id = eid;
                        smeta.bind_root_ino = u64::from(eino);
                    }
                } else if is_memfs_fstype(sub.fstype()) && smeta.backing_mount_id == 0 {
                    smeta.backing_mount_id = sub.mount_id();
                } else if !is_memfs_fstype(sub.fstype())
                    && sub.fstype() != FilesystemType::Ext4
                    && smeta.backing_mount_id == 0
                {
                    smeta.backing_mount_id = sub.mount_id();
                }
                let sflags = (sub.flags() & (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC))
                    | MS_BIND
                    | MS_SLAVE;
                subs.push(RecSub {
                    sub_src: stgt.to_vec(),
                    sub_tgt: new_tgt,
                    fstype: sub.fstype(),
                    flags: sflags,
                    meta: smeta,
                });
            });
            subs.sort_by_key(|s| s.sub_tgt.len());
        }
        (src_entry.fstype(), rflags, meta, subs)
    };

    if root_meta.backing_mount_id != 0 && root_meta.bind_root_ino != 0 {
        state
            .memfs
            .retain_fd(root_meta.backing_mount_id, root_meta.bind_root_ino);
    }
    state.sync_next_mount_id_before(mnt_ns_id);
    let new_root_id = {
        let (mounts, bind_meta, _) = state.ns_view_mut(mnt_ns_id);
        match mounts.insert_exact_mount(norm_src, norm_tgt, root_fstype, root_flags) {
            Ok(id) => {
                root_meta.mount_id = id;
                upsert_bind_meta(bind_meta, root_meta);
                id
            }
            Err(e) => {
                if root_meta.backing_mount_id != 0 && root_meta.bind_root_ino != 0 {
                    state
                        .memfs
                        .release_fd(root_meta.backing_mount_id, root_meta.bind_root_ino);
                }
                return Err(e);
            }
        }
    };
    let _ = new_root_id;

    for mut sub in rec_subs {
        if sub.meta.backing_mount_id != 0 && sub.meta.bind_root_ino != 0 {
            state
                .memfs
                .retain_fd(sub.meta.backing_mount_id, sub.meta.bind_root_ino);
        }
        let ins_res = {
            let (mounts, bind_meta, _) = state.ns_view_mut(mnt_ns_id);
            match mounts.insert_exact_mount(&sub.sub_src, &sub.sub_tgt, sub.fstype, sub.flags) {
                Ok(id) => {
                    sub.meta.mount_id = id;
                    upsert_bind_meta(bind_meta, sub.meta);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        };
        if ins_res.is_err() && sub.meta.backing_mount_id != 0 && sub.meta.bind_root_ino != 0 {
            state
                .memfs
                .release_fd(sub.meta.backing_mount_id, sub.meta.bind_root_ino);
        }
    }
    state.sync_next_mount_id_after(mnt_ns_id);
    Ok(0)
}

fn handle_mount(
    user_source: u64,
    user_target: u64,
    user_fstype: u64,
    flags: u64,
    user_data: u64,
) -> Result<Result<i64, Errno>, ()> {
    if let Err(errno) = require_root_admin() {
        return Ok(Err(errno));
    }
    let owner = current_process_id()?;
    let mut target_buf = vec![0u8; LINUX_PATH_MAX];
    let raw_target_len = match read_user_cstr(user_target, &mut target_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut abs_target_buf = [0u8; MAX_MOUNT_PATH];
    let target_len = match resolve_mount_syscall_path(
        owner,
        &target_buf[..raw_target_len],
        true,
        &mut abs_target_buf,
    ) {
        Ok(n) => n,
        Err(errno) => return Ok(Err(errno)),
    };
    let target_slice = &abs_target_buf[..target_len];

    let mut source_buf = vec![0u8; LINUX_PATH_MAX];
    let source_len = if user_source == 0 {
        0
    } else {
        match read_user_cstr(user_source, &mut source_buf) {
            Ok(len) => len,
            Err(errno) => return Ok(Err(errno)),
        }
    };
    let mut abs_source_buf = [0u8; MAX_MOUNT_PATH];
    let abs_source_len =
        if (flags & MS_REMOUNT) == 0 && ((flags & MS_MOVE) != 0 || (flags & MS_BIND) != 0) {
            match resolve_mount_syscall_path(
                owner,
                &source_buf[..source_len],
                true,
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

    let mode_opt = if (flags & (MS_BIND | MS_MOVE)) == 0 {
        parse_mount_mode_opt(user_data)
    } else {
        None
    };

    let mut moved_pair: Option<(u32, [u8; MAX_MOUNT_PATH], usize)> = None;
    let mnt_ns_id = super::step41_container::process_mnt_ns_id(owner);
    let is_init_ns = mnt_ns_id == INIT_MNT_NS_ID;
    let ext4_bind_src = if (flags & MS_BIND) != 0 && (flags & MS_REMOUNT) == 0 {
        super::step33_ext4_vfs::resolve_ext4_bind_source(owner, &abs_source_buf[..abs_source_len])
    } else {
        None
    };
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let fstype_slice = fstype_opt.map(|n| &fstype_buf[..n]);
        let mnt_res: Result<i64, Errno> = (|| {
            if (flags & MS_REMOUNT) != 0 {
                if is_init_ns
                    && (flags & MS_BIND) == 0
                    && let Some(slot) = state
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
                let (mounts, _, _) = state.ns_view_mut(mnt_ns_id);
                return mounts
                    .mount(source_slice, target_slice, fstype_slice, flags)
                    .map(|_| 0);
            }

            if (flags & MS_MOVE) != 0 {
                if is_init_ns
                    && let Some(slot) = state
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
                let mut release_pairs: Vec<(u32, u64)> = Vec::new();
                let mut detach_ids: Vec<u32> = Vec::new();
                {
                    let (mounts, bind_meta, _) = state.ns_view(mnt_ns_id);
                    if target_slice == b"/" {
                        mounts.for_each_live(|e| {
                            let t = e.target();
                            let keep = t == source_slice || path_starts_with_mount(t, source_slice);
                            if !keep {
                                detach_ids.push(e.mount_id());
                                if let Some(meta) = find_bind_meta(bind_meta, e.mount_id())
                                    && meta.backing_mount_id != 0
                                    && meta.bind_root_ino != 0
                                {
                                    release_pairs.push((meta.backing_mount_id, meta.bind_root_ino));
                                }
                            }
                        });
                    }
                }
                let mv_res = {
                    let (mounts, bind_meta, _) = state.ns_view_mut(mnt_ns_id);
                    let r = mounts.mount(source_slice, target_slice, fstype_slice, flags);
                    if r.is_ok() {
                        for id in detach_ids {
                            if let Some(m) =
                                bind_meta.iter_mut().find(|m| m.live && m.mount_id == id)
                            {
                                *m = BindMountMeta::EMPTY;
                            }
                        }
                    }
                    r
                };
                if mv_res.is_ok() {
                    for (mid, ino) in release_pairs {
                        state.memfs.release_fd(mid, ino);
                    }
                }
                return mv_res.map(|_| 0);
            }

            if (flags & MS_BIND) != 0 {
                return apply_bind_mount_in_state(
                    state,
                    mnt_ns_id,
                    source_slice,
                    target_slice,
                    flags,
                    ext4_bind_src,
                );
            }

            let is_prop_only = (flags & MS_PROPAGATION_MASK) != 0
                && fstype_slice.is_none_or(|f| f.is_empty())
                && (source_slice.is_empty() || source_slice == b"none");

            let wants_ext4 = !is_prop_only
                && (matches!(fstype_slice, Some(b"ext4" | b"ext3" | b"ext2"))
                    || ((fstype_slice.is_none() || fstype_slice == Some(b""))
                        && source_slice.starts_with(b"/dev/vda")));
            let mut ext4_slot_id = 0u32;
            if wants_ext4 {
                if !is_init_ns {
                    return Err(Errno::EPERM);
                }
                ext4_slot_id = mount_ext4_slot(state, source_slice, target_slice, flags)?;
            }

            let eff_fstype = if wants_ext4 {
                Some(&b"ext4"[..])
            } else {
                fstype_slice
            };
            state.sync_next_mount_id_before(mnt_ns_id);
            let mnt_id = {
                let (mounts, bind_meta, _) = state.ns_view_mut(mnt_ns_id);
                let id = mounts.mount(source_slice, target_slice, eff_fstype, flags)?;
                if wants_ext4 {
                    let mut meta = BindMountMeta::EMPTY;
                    meta.live = true;
                    meta.mount_id = id;
                    meta.backing_ext4_id = ext4_slot_id;
                    upsert_bind_meta(bind_meta, meta);
                }
                id
            };
            state.sync_next_mount_id_after(mnt_ns_id);
            if !is_prop_only && !wants_ext4 {
                let perm = mode_opt;
                let fs_ty = {
                    let (mounts, _, _) = state.ns_view(mnt_ns_id);
                    mounts.entry_by_id(mnt_id).map(|e| e.fstype())
                };
                if let Some(ft) = fs_ty
                    && is_memfs_fstype(ft)
                {
                    let now = current_epoch_now_secs();
                    state.memfs.ensure_mount(mnt_id, ft, perm, now);
                }
            }
            Ok(0)
        })();
        if mnt_res.is_ok() {
            state.bump_ns_mounts_gen(mnt_ns_id);
        }
        mnt_res
    })?;
    if res.is_ok()
        && let Some((mount_id, old_mp, old_len)) = moved_pair
    {
        super::step33_ext4_vfs::on_mount_moved(mount_id, &old_mp[..old_len], target_slice);
    }
    if res.is_ok() && (flags & MS_MOVE) != 0 {
        super::step33_ext4_vfs::on_mount_moved_for_process(owner, source_slice, target_slice);
    }
    Ok(res)
}

fn handle_umount2(user_target: u64, raw_flags: u64) -> Result<Result<i64, Errno>, ()> {
    if let Err(errno) = require_root_admin() {
        return Ok(Err(errno));
    }
    let owner = current_process_id()?;
    let Ok(flags) = u32::try_from(raw_flags) else {
        return Ok(Err(Errno::EINVAL));
    };
    let mut target_buf = vec![0u8; LINUX_PATH_MAX];
    let raw_target_len = match read_user_cstr(user_target, &mut target_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut abs_target_buf = [0u8; MAX_MOUNT_PATH];
    let target_len = match resolve_mount_syscall_path(
        owner,
        &target_buf[..raw_target_len],
        (flags & UMOUNT_NOFOLLOW) == 0,
        &mut abs_target_buf,
    ) {
        Ok(n) => n,
        Err(errno) => return Ok(Err(errno)),
    };
    let target_slice = &abs_target_buf[..target_len];
    let mnt_ns_id = super::step41_container::process_mnt_ns_id(owner);
    let is_init_ns = mnt_ns_id == INIT_MNT_NS_ID;

    let mut removed_mount_id: Option<u32> = None;
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        if target_slice == b"/" {
            return Err(Errno::EBUSY);
        }
        let (target_was_bind, bind_mem_release, umount_mem_id) = {
            let (mounts, bind_meta, _) = state.ns_view(mnt_ns_id);
            let resolved = mounts.resolve(target_slice).ok();
            let was_bind = resolved
                .as_ref()
                .is_some_and(|(m, rel)| rel.is_empty() && (m.flags() & MS_BIND) != 0);
            let bind_rel = resolved.as_ref().and_then(|(m, rel)| {
                if rel.is_empty() {
                    find_bind_meta(bind_meta, m.mount_id()).and_then(|bm| {
                        if bm.backing_mount_id != 0 && bm.bind_root_ino != 0 {
                            Some((bm.backing_mount_id, bm.bind_root_ino))
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            });
            let mem_id = resolved.and_then(|(m, rel)| {
                if rel.is_empty() && (m.flags() & MS_BIND) == 0 && is_memfs_fstype(m.fstype()) {
                    Some(m.mount_id())
                } else {
                    None
                }
            });
            (was_bind, bind_rel, mem_id)
        };

        if is_init_ns && !target_was_bind {
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
        }
        let removed_tbl_id = {
            let (mounts, bind_meta, _) = state.ns_view_mut(mnt_ns_id);
            let id = mounts.umount2_returning_id(target_slice, flags)?;
            if let Some(bm) = bind_meta.iter_mut().find(|m| m.live && m.mount_id == id) {
                *bm = BindMountMeta::EMPTY;
            }
            id
        };
        let _ = removed_tbl_id;
        if let Some((mid, ino)) = bind_mem_release {
            state.memfs.release_fd(mid, ino);
        }
        if let Some(mem_id) = umount_mem_id {
            state.memfs.unmount(mem_id);
        }
        state.bump_ns_mounts_gen(mnt_ns_id);
        Ok(0)
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

    let mnt_ns_id = current_process_id()
        .map(super::step41_container::process_mnt_ns_id)
        .unwrap_or(INIT_MNT_NS_ID);
    let is_init_ns = mnt_ns_id == INIT_MNT_NS_ID;
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        {
            let (mounts, _, _) = state.ns_view_mut(mnt_ns_id);
            mounts.pivot_root(new_root, put_old)?;
        }
        if is_init_ns {
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
        }
        state.bump_ns_mounts_gen(mnt_ns_id);
        Ok(0)
    })?;
    if res.is_ok() && is_init_ns {
        super::step33_ext4_vfs::on_pivot_root(new_root, rel_put_old_slice);
    }
    Ok(res)
}

fn handle_statfs(user_path: u64, user_buf: u64) -> Result<Result<i64, Errno>, ()> {
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let owner = current_process_id()?;
    let mut path_buf = vec![0u8; LINUX_PATH_MAX];
    let raw_len = match read_user_cstr(user_path, &mut path_buf) {
        Ok(len) => len,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut abs_buf = vec![0u8; LINUX_PATH_MAX];
    let abs_len = match resolve_mount_syscall_path(owner, &path_buf[..raw_len], true, &mut abs_buf)
    {
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

    let mnt_ns_id = super::step41_container::process_mnt_ns_id(owner);
    let resolved = with_mount_state(|state| {
        state.ensure_initialized();
        let (mounts, bind_meta, _) = state.ns_view(mnt_ns_id);
        let virt = mounts.resolve(abs_slice);
        if let Ok((entry, _)) = virt {
            if entry.fstype() == FilesystemType::Ext4
                && let Some((ext4_id, _)) = resolve_ext4_entry_backing(state, bind_meta, &entry)
                && let Some(slot) = state
                    .ext4_mounts
                    .iter()
                    .find(|m| m.live && m.mount_id == ext4_id)
                && let Some(ref vol) = slot.vol
            {
                return Ok(StatfsInfo::Ext4 {
                    info: vol.statfs(),
                    flags: slot.flags | (entry.flags() & MS_RDONLY),
                    ro: vol.is_read_only() || entry.is_readonly(),
                });
            }
            if is_virtual_fstype(entry.fstype()) {
                return Ok(StatfsInfo::Virtual(entry.fstype(), entry.flags()));
            }
        }
        if mnt_ns_id == INIT_MNT_NS_ID {
            let best_ext4 = state
                .ext4_mounts
                .iter()
                .filter(|m| {
                    m.live && path_matches_prefix(abs_slice, &m.mount_path[..m.mount_path_len])
                })
                .max_by_key(|m| m.mount_path_len);
            if let Some(slot) = best_ext4
                && let Some(ref vol) = slot.vol
            {
                return Ok(StatfsInfo::Ext4 {
                    info: vol.statfs(),
                    flags: slot.flags,
                    ro: vol.is_read_only(),
                });
            }
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
        FilesystemType::Cgroup2 => 0x63u8,
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
        FilesystemType::Cgroup2 => 0x7200_0000_0000_0000u64,
        _ => 0x7100_0000_0000_0000u64,
    };
    prefix | (hash & 0x00ff_ffff_ffff_ffff).max(1)
}

enum ResolvedVirtualTarget {
    Virtual {
        mount_id: u32,
        is_mount_root: bool,
        fstype: FilesystemType,
        abs_path: Vec<u8>,
        rel_path: Vec<u8>,
        node: Option<VirtualNode>,
        mem_stat: Option<MemStat>,
    },
    MissingLeaf {
        mount_id: u32,
        fstype: FilesystemType,
        parent_ino: u64,
        parent_abs: Vec<u8>,
        parent_rel: Vec<u8>,
        leaf: Vec<u8>,
        trailing_slash: bool,
    },
    HostAbsolute(Vec<u8>),
}

enum WalkState {
    Virtual {
        table_mount_id: u32,
        mount_id: u32,
        mount_target: Vec<u8>,
        bind_prefix: Vec<u8>,
        fstype: FilesystemType,
        parts: Vec<Vec<u8>>,
        mem_ino: u64,
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

fn join_abs_from_mount(mount_target: &[u8], parts: &[Vec<u8>]) -> Vec<u8> {
    if parts.is_empty() {
        return mount_target.to_vec();
    }
    let rel = join_part_slices(parts);
    join_mount_and_rel(mount_target, &rel)
}

fn join_mount_and_rel(mount_target: &[u8], rel: &[u8]) -> Vec<u8> {
    if rel.is_empty() {
        return mount_target.to_vec();
    }
    let mut out = Vec::with_capacity(mount_target.len() + 1 + rel.len());
    out.extend_from_slice(mount_target);
    if mount_target != b"/" {
        out.push(b'/');
    }
    out.extend_from_slice(rel);
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

fn parent_abs_path(path: &[u8]) -> &[u8] {
    if path.len() <= 1 {
        return b"/";
    }
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => b"/",
        Some(idx) => &path[..idx],
    }
}

fn join_rel(prefix: &[u8], child: &[u8]) -> Vec<u8> {
    if prefix.is_empty() {
        return child.to_vec();
    }
    if child.is_empty() {
        return prefix.to_vec();
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

fn path_starts_with_mount(path: &[u8], tgt: &[u8]) -> bool {
    tgt != b"/"
        && (path == tgt
            || (path.len() > tgt.len() && path.starts_with(tgt) && path[tgt.len()] == b'/'))
}

struct VirtualMountResolved {
    table_mount_id: u32,
    backing_mount_id: u32,
    fstype: FilesystemType,
    target: Vec<u8>,
    bind_root_ino: u64,
    bind_prefix: Vec<u8>,
}

fn resolve_virtual_mount_entry(
    state: &Step33MountState,
    mnt_ns_id: u32,
    abs_path: &[u8],
) -> Option<VirtualMountResolved> {
    if !abs_path.starts_with(b"/") {
        return None;
    }
    let (mounts, bind_meta, _) = state.ns_view(mnt_ns_id);
    let Ok((entry, _)) = mounts.resolve(abs_path) else {
        return None;
    };
    if !is_virtual_fstype(entry.fstype()) {
        return None;
    }
    if mnt_ns_id == INIT_MNT_NS_ID {
        let ext4_len = state
            .ext4_mounts
            .iter()
            .filter(|m| m.live && path_matches_prefix(abs_path, &m.mount_path[..m.mount_path_len]))
            .map(|m| m.mount_path_len)
            .max()
            .unwrap_or(0);
        if ext4_len > entry.target().len() {
            return None;
        }
    }
    let meta = find_bind_meta(bind_meta, entry.mount_id());
    let backing_mount_id = meta
        .and_then(|m| {
            if m.backing_mount_id != 0 {
                Some(m.backing_mount_id)
            } else {
                None
            }
        })
        .unwrap_or_else(|| entry.mount_id());
    let bind_root_ino = meta.map_or(0, |m| m.bind_root_ino);
    let bind_prefix = meta.map(|m| m.bind_prefix().to_vec()).unwrap_or_default();
    Some(VirtualMountResolved {
        table_mount_id: entry.mount_id(),
        backing_mount_id,
        fstype: entry.fstype(),
        target: entry.target().to_vec(),
        bind_root_ino,
        bind_prefix,
    })
}

fn memfs_start_stat(memfs: &MemFs, mount_id: u32, bind_root_ino: u64) -> Result<MemStat, Errno> {
    if bind_root_ino != 0 {
        memfs.stat_ino(mount_id, bind_root_ino).ok_or(Errno::ENOENT)
    } else {
        memfs.root_stat(mount_id).ok_or(Errno::ENOENT)
    }
}

fn walk_memfs_ino(memfs: &MemFs, mount_id: u32, parts: &[Vec<u8>]) -> Result<u64, Errno> {
    let mut ino = memfs.root_stat(mount_id).ok_or(Errno::ENOENT)?.ino;
    for seg in parts {
        let child = memfs
            .lookup_child_stat(mount_id, ino, seg)
            .ok_or(Errno::ENOENT)?;
        ino = child.ino;
    }
    Ok(ino)
}

#[allow(clippy::too_many_arguments)]
fn resolve_virtual_path<const M: usize>(
    state: &Step33MountState,
    mounts: &kernal_linux_mounts::MountTable<M>,
    owner: ObjectId,
    dirfd: u64,
    user_path: u64,
    cwd_if_fdc: Option<&[u8]>,
    allow_empty: bool,
    stop_at_missing_leaf: bool,
    follow_final: bool,
    caller: &CallerSnapshotData,
    hostname: &[u8],
    boot_id_seed: [u8; 16],
) -> Result<Option<ResolvedVirtualTarget>, Errno> {
    let mut path_buf = vec![0u8; LINUX_PATH_MAX];
    let path_len = match read_user_cstr(user_path, &mut path_buf) {
        Ok(len) => len,
        Err(e) => {
            if is_proc_sys_fd(dirfd) || is_aliased_proc_sys_fd(dirfd) {
                return Err(e);
            }
            return Ok(None);
        }
    };
    resolve_virtual_bytes(
        state,
        mounts,
        owner,
        dirfd,
        &path_buf[..path_len],
        cwd_if_fdc,
        allow_empty,
        stop_at_missing_leaf,
        follow_final,
        caller,
        hostname,
        boot_id_seed,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_virtual_bytes<const M: usize>(
    state: &Step33MountState,
    _mounts: &kernal_linux_mounts::MountTable<M>,
    owner: ObjectId,
    dirfd: u64,
    raw_path: &[u8],
    cwd_if_fdc: Option<&[u8]>,
    allow_empty: bool,
    stop_at_missing_leaf: bool,
    follow_final: bool,
    caller: &CallerSnapshotData,
    hostname: &[u8],
    boot_id_seed: [u8; 16],
) -> Result<Option<ResolvedVirtualTarget>, Errno> {
    let mnt_ns_id = caller.mnt_ns_id;
    let ns_mounts = state.ns_view(mnt_ns_id).0;
    let ns_bind_meta = state.ns_view(mnt_ns_id).1;
    let mut path = raw_path;
    while path.starts_with(b"//") {
        path = &path[1..];
    }
    let trailing_slash = path.ends_with(b"/");
    let mut queue = VecDeque::new();
    let mut last_mem_stat: Option<MemStat> = None;

    let mut walk_state = if path.starts_with(b"/") {
        let Some(vm) = resolve_virtual_mount_entry(state, mnt_ns_id, path) else {
            return Ok(None);
        };
        if path.len() > vm.target.len() {
            let suffix = if vm.target == b"/" {
                &path[1..]
            } else {
                &path[vm.target.len() + 1..]
            };
            push_segments_back(&mut queue, suffix);
        }
        let mem_ino = if is_memfs_fstype(vm.fstype) {
            let root = memfs_start_stat(&state.memfs, vm.backing_mount_id, vm.bind_root_ino)?;
            if queue.is_empty() {
                last_mem_stat = Some(root);
            } else if root.kind != MemNodeKind::Dir {
                return Err(Errno::ENOTDIR);
            }
            root.ino
        } else {
            0
        };
        WalkState::Virtual {
            table_mount_id: vm.table_mount_id,
            mount_id: vm.backing_mount_id,
            mount_target: vm.target,
            bind_prefix: vm.bind_prefix,
            fstype: vm.fstype,
            parts: Vec::new(),
            mem_ino,
        }
    } else if is_proc_sys_fd(dirfd) || is_aliased_proc_sys_fd(dirfd) {
        let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, dirfd) else {
            return Err(Errno::EBADF);
        };
        let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        let (table_mount_id, mount_target, bind_prefix, init_parts) =
            if let Ok((m_ent, m_rel)) = ns_mounts.resolve(&entry.abs_path) {
                let bmeta = find_bind_meta(ns_bind_meta, m_ent.mount_id());
                let bp = bmeta.map(|m| m.bind_prefix().to_vec()).unwrap_or_default();
                (
                    m_ent.mount_id(),
                    m_ent.target().to_vec(),
                    bp,
                    split_nonempty_segments(m_rel),
                )
            } else {
                let fallback_tgt = ns_mounts
                    .entry_by_id(entry.mount_id)
                    .map(|m| m.target().to_vec())
                    .unwrap_or_else(|| match entry.fstype {
                        FilesystemType::Procfs => b"/proc".to_vec(),
                        FilesystemType::Cgroup2 => b"/sys/fs/cgroup".to_vec(),
                        FilesystemType::Devtmpfs => b"/dev".to_vec(),
                        FilesystemType::Devpts => b"/dev/pts".to_vec(),
                        _ => b"/sys".to_vec(),
                    });
                (
                    entry.mount_id,
                    fallback_tgt,
                    Vec::new(),
                    split_nonempty_segments(&entry.rel_path),
                )
            };
        if path.is_empty() {
            if allow_empty {
                let mem_stat = if entry.mem_ino != 0 {
                    state.memfs.stat_ino(entry.mount_id, entry.mem_ino)
                } else {
                    None
                };
                return Ok(Some(ResolvedVirtualTarget::Virtual {
                    mount_id: entry.mount_id,
                    is_mount_root: entry.rel_path.is_empty(),
                    fstype: entry.fstype,
                    abs_path: entry.abs_path.clone(),
                    rel_path: entry.rel_path.clone(),
                    node: None,
                    mem_stat,
                }));
            }
            return Err(Errno::ENOENT);
        }
        if !entry.is_dir {
            return Err(Errno::ENOTDIR);
        }
        push_segments_back(&mut queue, path);
        let mem_ino = if entry.mem_ino != 0 {
            entry.mem_ino
        } else if is_memfs_fstype(entry.fstype) {
            walk_memfs_ino(&state.memfs, entry.mount_id, &init_parts)?
        } else {
            0
        };
        WalkState::Virtual {
            table_mount_id,
            mount_id: entry.mount_id,
            mount_target,
            bind_prefix,
            fstype: entry.fstype,
            parts: init_parts,
            mem_ino,
        }
    } else if linux_signed_int(dirfd) == AT_FDCWD_I32 {
        let Some(cwd) = cwd_if_fdc else {
            return Ok(None);
        };
        let Some(vm) = resolve_virtual_mount_entry(state, mnt_ns_id, cwd) else {
            return Ok(None);
        };
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        let cwd_rel = if cwd.len() > vm.target.len() {
            if vm.target == b"/" {
                &cwd[1..]
            } else {
                &cwd[vm.target.len() + 1..]
            }
        } else {
            b""
        };
        let parts = split_nonempty_segments(cwd_rel);
        let mem_ino = if is_memfs_fstype(vm.fstype) {
            let start = memfs_start_stat(&state.memfs, vm.backing_mount_id, vm.bind_root_ino)?;
            walk_memfs_ino_from(&state.memfs, vm.backing_mount_id, start.ino, &parts)?
        } else {
            0
        };
        push_segments_back(&mut queue, path);
        WalkState::Virtual {
            table_mount_id: vm.table_mount_id,
            mount_id: vm.backing_mount_id,
            mount_target: vm.target,
            bind_prefix: vm.bind_prefix,
            fstype: vm.fstype,
            parts,
            mem_ino,
        }
    } else {
        return Ok(None);
    };

    let mut symlink_depth = 0usize;
    let mut last_node: Option<VirtualNode> = None;

    while let Some(seg) = queue.pop_front() {
        let is_final = queue.is_empty();
        last_node = None;
        last_mem_stat = None;
        match &mut walk_state {
            WalkState::Virtual {
                table_mount_id,
                mount_id,
                mount_target,
                bind_prefix,
                fstype,
                parts,
                mem_ino,
            } => {
                if seg == b".." {
                    if parts.pop().is_some() {
                        if is_memfs_fstype(*fstype) {
                            *mem_ino = state
                                .memfs
                                .parent_ino(*mount_id, *mem_ino)
                                .unwrap_or(*mem_ino);
                        }
                    } else {
                        let parent_abs = parent_abs_path(mount_target);
                        if let Some(pvm) = resolve_virtual_mount_entry(state, mnt_ns_id, parent_abs)
                        {
                            let p_rel = if parent_abs.len() > pvm.target.len() {
                                if pvm.target == b"/" {
                                    &parent_abs[1..]
                                } else {
                                    &parent_abs[pvm.target.len() + 1..]
                                }
                            } else {
                                b""
                            };
                            let p_parts = split_nonempty_segments(p_rel);
                            let p_mem_ino = if is_memfs_fstype(pvm.fstype) {
                                let start = memfs_start_stat(
                                    &state.memfs,
                                    pvm.backing_mount_id,
                                    pvm.bind_root_ino,
                                )?;
                                walk_memfs_ino_from(
                                    &state.memfs,
                                    pvm.backing_mount_id,
                                    start.ino,
                                    &p_parts,
                                )?
                            } else {
                                0
                            };
                            *table_mount_id = pvm.table_mount_id;
                            *mount_id = pvm.backing_mount_id;
                            *mount_target = pvm.target;
                            *bind_prefix = pvm.bind_prefix;
                            *fstype = pvm.fstype;
                            *parts = p_parts;
                            *mem_ino = p_mem_ino;
                        } else {
                            walk_state = WalkState::Host(split_nonempty_segments(parent_abs));
                        }
                    }
                    continue;
                }

                parts.push(seg.clone());
                let cand_abs = join_abs_from_mount(mount_target, parts);

                // Check crossing into a child mountpoint.
                if let Ok((c_ent, c_rel)) = ns_mounts.resolve(&cand_abs)
                    && c_rel.is_empty()
                    && c_ent.mount_id() != *table_mount_id
                    && c_ent.target().len() > mount_target.len()
                {
                    if is_virtual_fstype(c_ent.fstype()) {
                        let cmeta = find_bind_meta(ns_bind_meta, c_ent.mount_id());
                        let c_back = cmeta
                            .and_then(|m| {
                                if m.backing_mount_id != 0 {
                                    Some(m.backing_mount_id)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_else(|| c_ent.mount_id());
                        let c_ino = cmeta.map_or(0, |m| m.bind_root_ino);
                        let c_bp = cmeta.map(|m| m.bind_prefix().to_vec()).unwrap_or_default();
                        *table_mount_id = c_ent.mount_id();
                        *mount_id = c_back;
                        *mount_target = c_ent.target().to_vec();
                        *bind_prefix = c_bp;
                        *fstype = c_ent.fstype();
                        parts.clear();
                        *mem_ino = if is_memfs_fstype(*fstype) {
                            let root = memfs_start_stat(&state.memfs, c_back, c_ino)?;
                            if is_final {
                                last_mem_stat = Some(root);
                            } else if root.kind != MemNodeKind::Dir {
                                return Err(Errno::ENOTDIR);
                            }
                            root.ino
                        } else {
                            0
                        };
                        continue;
                    }
                    walk_state = WalkState::Host(split_nonempty_segments(&cand_abs));
                    continue;
                }
                if mnt_ns_id == INIT_MNT_NS_ID
                    && state
                        .ext4_mounts
                        .iter()
                        .any(|m| m.live && &m.mount_path[..m.mount_path_len] == cand_abs.as_slice())
                {
                    walk_state = WalkState::Host(split_nonempty_segments(&cand_abs));
                    continue;
                }

                if is_memfs_fstype(*fstype) {
                    let Some(child_stat) = state.memfs.lookup_child_stat(*mount_id, *mem_ino, &seg)
                    else {
                        if *fstype == FilesystemType::Devpts
                            && parts.len() == 1
                            && is_final
                            && !trailing_slash
                            && parse_u32_decimal(&seg).is_some()
                        {
                            return Ok(Some(ResolvedVirtualTarget::HostAbsolute(cand_abs)));
                        }
                        if stop_at_missing_leaf && is_final {
                            parts.pop();
                            let parent_rel = join_part_slices(parts);
                            let parent_abs = join_mount_and_rel(mount_target, &parent_rel);
                            return Ok(Some(ResolvedVirtualTarget::MissingLeaf {
                                mount_id: *mount_id,
                                fstype: *fstype,
                                parent_ino: *mem_ino,
                                parent_abs,
                                parent_rel,
                                leaf: seg,
                                trailing_slash,
                            }));
                        }
                        return Err(Errno::ENOENT);
                    };
                    match child_stat.kind {
                        MemNodeKind::Dir => {
                            *mem_ino = child_stat.ino;
                            if is_final {
                                last_mem_stat = Some(child_stat);
                            }
                        }
                        MemNodeKind::Symlink => {
                            let must_follow = !is_final || follow_final || trailing_slash;
                            if !must_follow {
                                last_mem_stat = Some(child_stat);
                                continue;
                            }
                            let target = state
                                .memfs
                                .read_symlink(*mount_id, child_stat.ino)
                                .ok_or(Errno::ENOENT)?
                                .to_vec();
                            symlink_depth += 1;
                            if symlink_depth > 40 {
                                return Err(Errno::ELOOP);
                            }
                            if target.starts_with(b"/") {
                                prepend_segments_front(&mut queue, &target[1..]);
                                walk_state = WalkState::Host(Vec::new());
                            } else {
                                parts.pop();
                                prepend_segments_front(&mut queue, &target);
                            }
                        }
                        MemNodeKind::File
                        | MemNodeKind::Socket
                        | MemNodeKind::Fifo
                        | MemNodeKind::ChrDev(_)
                        | MemNodeKind::BlkDev(_) => {
                            if !is_final || trailing_slash {
                                return Err(Errno::ENOTDIR);
                            }
                            last_mem_stat = Some(child_stat);
                        }
                    }
                    continue;
                }

                let rel_under = join_part_slices(parts);
                let rel = join_rel(bind_prefix, &rel_under);
                let node = match synthesize_virtual_node(
                    *fstype,
                    &rel,
                    ns_mounts,
                    Some(&state.fds),
                    caller,
                    hostname,
                    boot_id_seed,
                ) {
                    Ok(n) => n,
                    Err(Errno::ENOENT) if stop_at_missing_leaf && is_final => {
                        parts.pop();
                        let parent_rel = join_part_slices(parts);
                        let parent_abs = join_mount_and_rel(mount_target, &parent_rel);
                        return Ok(Some(ResolvedVirtualTarget::MissingLeaf {
                            mount_id: *mount_id,
                            fstype: *fstype,
                            parent_ino: 0,
                            parent_abs,
                            parent_rel,
                            leaf: seg,
                            trailing_slash,
                        }));
                    }
                    Err(e) => return Err(e),
                };
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
                        if symlink_depth > 40 {
                            return Err(Errno::ELOOP);
                        }
                        if target.starts_with(b"/") {
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
                    let cand_abs = host_absolute_from_parts(parts);
                    if let Some(vm) = resolve_virtual_mount_entry(state, mnt_ns_id, &cand_abs)
                        && vm.target == cand_abs.as_slice()
                    {
                        let mem_ino = if is_memfs_fstype(vm.fstype) {
                            let root = memfs_start_stat(
                                &state.memfs,
                                vm.backing_mount_id,
                                vm.bind_root_ino,
                            )?;
                            if is_final {
                                last_mem_stat = Some(root);
                            } else if root.kind != MemNodeKind::Dir {
                                return Err(Errno::ENOTDIR);
                            }
                            root.ino
                        } else {
                            0
                        };
                        walk_state = WalkState::Virtual {
                            table_mount_id: vm.table_mount_id,
                            mount_id: vm.backing_mount_id,
                            mount_target: vm.target,
                            bind_prefix: vm.bind_prefix,
                            fstype: vm.fstype,
                            parts: Vec::new(),
                            mem_ino,
                        };
                    }
                }
            }
        }
    }

    Ok(Some(match walk_state {
        WalkState::Virtual {
            table_mount_id: _,
            mount_id,
            mount_target,
            bind_prefix,
            fstype,
            parts,
            mem_ino,
        } => {
            let rel_under = join_part_slices(&parts);
            let abs_path = join_mount_and_rel(&mount_target, &rel_under);
            let rel_path = if is_memfs_fstype(fstype) {
                rel_under.clone()
            } else {
                join_rel(&bind_prefix, &rel_under)
            };
            let is_mount_root = parts.is_empty();
            if is_memfs_fstype(fstype) {
                let mem_stat = match last_mem_stat {
                    Some(st) => Some(st),
                    None => state.memfs.stat_ino(mount_id, mem_ino),
                };
                if mem_stat.is_none() {
                    return Err(Errno::ENOENT);
                }
                ResolvedVirtualTarget::Virtual {
                    mount_id,
                    is_mount_root,
                    fstype,
                    abs_path,
                    rel_path,
                    node: None,
                    mem_stat,
                }
            } else {
                let node = match last_node {
                    Some(node) => Some(node),
                    None => Some(synthesize_virtual_node(
                        fstype,
                        &rel_path,
                        ns_mounts,
                        Some(&state.fds),
                        caller,
                        hostname,
                        boot_id_seed,
                    )?),
                };
                ResolvedVirtualTarget::Virtual {
                    mount_id,
                    is_mount_root,
                    fstype,
                    abs_path,
                    rel_path,
                    node,
                    mem_stat: None,
                }
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
    let mut entries = Vec::with_capacity(16);
    push_encoded_dir_entries(
        &mut entries,
        FilesystemType::Procfs,
        rel_pid,
        b".:D|..:D|cgroup:R|cmdline:R|comm:R|cwd:L|exe:L|fd:D|fdinfo:D|mountinfo:R|mounts:R|ns:D|oom_score_adj:R|root:L|stat:R|status:R",
    );
    entries
}

fn build_proc_fd_list(
    rel_dir: &[u8],
    proc_snap: &super::runtime::ProcProcessSnapshot,
    kind: NodeKind,
) -> Vec<VirtualDirEntry> {
    let mut entries = Vec::new();
    entries.push(make_dir_entry(
        FilesystemType::Procfs,
        rel_dir,
        b".",
        NodeKind::Directory,
    ));
    entries.push(make_dir_entry(
        FilesystemType::Procfs,
        rel_dir,
        b"..",
        NodeKind::Directory,
    ));
    let mut open_fds = Vec::new();
    collect_process_fd_numbers(proc_snap.process, &mut open_fds);
    open_fds.sort_unstable();
    for fd in open_fds {
        if fd >= 0 {
            let name = format_u64_bytes(fd as u64);
            entries.push(make_dir_entry(FilesystemType::Procfs, rel_dir, &name, kind));
        }
    }
    entries
}

fn build_proc_fdinfo_bytes(
    proc_snap: &super::runtime::ProcProcessSnapshot,
    fd_num: i32,
) -> Option<Vec<u8>> {
    let mut open_fds = Vec::new();
    collect_process_fd_numbers(proc_snap.process, &mut open_fds);
    if !open_fds.contains(&fd_num) {
        return None;
    }
    let mut out = Vec::with_capacity(64);
    if let Some(target_pid) =
        super::step35_events_cgroup::pidfd_target_for_process_fd(proc_snap.process, fd_num)
    {
        out.extend_from_slice(b"pos:\t0\nflags:\t02004000\nmnt_id:\t0\nino:\t0\nPid:\t");
        out.extend_from_slice(&format_u64_bytes(u64::from(target_pid)));
        out.extend_from_slice(b"\nNSpid:\t");
        out.extend_from_slice(&format_u64_bytes(u64::from(target_pid)));
        out.push(b'\n');
    } else {
        out.extend_from_slice(b"pos:\t0\nflags:\t02000002\nmnt_id:\t0\nino:\t1\n");
    }
    Some(out)
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
    proc_sys_fds: Option<&[ProcSysFdEntry]>,
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
                make_dir_entry(
                    FilesystemType::Procfs,
                    rel,
                    b"domainname",
                    NodeKind::Regular,
                ),
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
                return Ok(VirtualNode::Directory(build_proc_fd_list(
                    rel,
                    &proc_snap,
                    NodeKind::Symlink,
                )));
            }
            b"fdinfo" => {
                return Ok(VirtualNode::Directory(build_proc_fd_list(
                    rel,
                    &proc_snap,
                    NodeKind::Regular,
                )));
            }
            b"ns" => return Ok(VirtualNode::Directory(build_proc_ns_entries(rel))),
            _ => {}
        }
        if let Some(fd_str) = subpath.strip_prefix(b"fdinfo/") {
            let fd_num = parse_u32_decimal(fd_str).ok_or(Errno::ENOENT)? as i32;
            let bytes = build_proc_fdinfo_bytes(&proc_snap, fd_num).ok_or(Errno::ENOENT)?;
            return Ok(VirtualNode::Regular(bytes));
        }
        if let Some(fd_str) = subpath.strip_prefix(b"fd/") {
            let fd_num = parse_u32_decimal(fd_str).ok_or(Errno::ENOENT)? as i32;
            let mut target_buf = vec![0u8; 512];
            let len = describe_process_fd_target_with_proc_sys(
                proc_snap.process,
                fd_num,
                proc_sys_fds,
                &mut target_buf,
            )
            .ok_or(Errno::ENOENT)?;
            return Ok(VirtualNode::Symlink(target_buf[..len].to_vec()));
        }
        if subpath == b"cgroup" {
            let mut cg_path = [0u8; 128];
            let cg_len = super::step35_events_cgroup::pid_cgroup_path(proc_snap.pid, &mut cg_path);
            let mut out = Vec::with_capacity(4 + cg_len);
            out.extend_from_slice(b"0::");
            out.extend_from_slice(&cg_path[..cg_len]);
            out.push(b'\n');
            return Ok(VirtualNode::Regular(out));
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
        FilesystemType::Cgroup2 => {
            super::step35_events_cgroup::read_cgroup_control_file(rel, node_buf)
        }
        _ => Err(Errno::ENOENT),
    }
}

fn synthesize_cgroup_node(fstype: FilesystemType, cg_rel: &[u8]) -> Result<VirtualNode, Errno> {
    if super::step35_events_cgroup::cgroup_has_dir(cg_rel) {
        let mut entries = Vec::new();
        entries.push(make_dir_entry(fstype, cg_rel, b".", NodeKind::Directory));
        entries.push(make_dir_entry(fstype, cg_rel, b"..", NodeKind::Directory));
        super::step35_events_cgroup::cgroup_list_dir(cg_rel, |name, sub_dir| {
            entries.push(make_dir_entry(
                fstype,
                cg_rel,
                name,
                if sub_dir {
                    NodeKind::Directory
                } else {
                    NodeKind::Regular
                },
            ));
        });
        return Ok(VirtualNode::Directory(entries));
    }
    let mut node_buf = vec![0u8; MAX_VIRTUAL_NODE_BYTES];
    let len = super::step35_events_cgroup::read_cgroup_control_file(cg_rel, &mut node_buf)?;
    node_buf.truncate(len);
    Ok(VirtualNode::Regular(node_buf))
}

fn read_sysfs_symlink_target(rel: &[u8]) -> Option<&'static [u8]> {
    match rel {
        b"class/tty/ttyAMA0/subsystem" | b"class/tty/console/subsystem" => {
            Some(b"../../../class/tty")
        }
        b"class/tty/ttyAMA0/device" => Some(b"../../../devices/platform/pl011"),
        b"devices/platform/pl011/tty/ttyAMA0/subsystem" => Some(b"../../../../../class/tty"),
        b"devices/platform/pl011/tty/ttyAMA0/device" => Some(b"../../../pl011"),
        b"class/block/vda/subsystem" => Some(b"../../../class/block"),
        b"devices/virtio0/block/vda/subsystem" => Some(b"../../../../class/block"),
        b"class/net/lo/subsystem" | b"class/net/eth0/subsystem" => Some(b"../../../class/net"),
        b"devices/virtio1/net/eth0/subsystem" => Some(b"../../../../class/net"),
        b"dev/char/204:64" => Some(b"../../devices/platform/pl011/tty/ttyAMA0"),
        b"dev/char/5:1" => Some(b"../../class/tty/console"),
        b"dev/block/254:0" => Some(b"../../devices/virtio0/block/vda"),
        _ => None,
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
        return synthesize_cgroup_node(FilesystemType::Sysfs, b"");
    }
    if let Some(cg_rel) = rel.strip_prefix(b"fs/cgroup/") {
        return synthesize_cgroup_node(FilesystemType::Sysfs, cg_rel);
    }
    if let Some(target) = read_sysfs_symlink_target(rel) {
        return Ok(VirtualNode::Symlink(target.to_vec()));
    }
    let mut entries = Vec::new();
    let is_dir = enumerate_sysfs_dir(rel, |name, sub_dir| {
        let mut child_buf = [0u8; MAX_MOUNT_PATH];
        let mut c = 0usize;
        if !rel.is_empty() {
            let n = rel.len().min(child_buf.len());
            child_buf[..n].copy_from_slice(&rel[..n]);
            c = n;
            if c < child_buf.len() {
                child_buf[c] = b'/';
                c += 1;
            }
        }
        let nlen = name.len().min(child_buf.len().saturating_sub(c));
        child_buf[c..c + nlen].copy_from_slice(&name[..nlen]);
        c += nlen;
        let kind = if sub_dir {
            NodeKind::Directory
        } else if read_sysfs_symlink_target(&child_buf[..c]).is_some() {
            NodeKind::Symlink
        } else {
            NodeKind::Regular
        };
        entries.push(make_dir_entry(FilesystemType::Sysfs, rel, name, kind));
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
    proc_sys_fds: Option<&[ProcSysFdEntry]>,
    caller: &CallerSnapshotData,
    hostname: &[u8],
    boot_id_seed: [u8; 16],
) -> Result<VirtualNode, Errno> {
    match fstype {
        FilesystemType::Procfs => {
            synthesize_proc_virtual_node(rel, mounts, proc_sys_fds, caller, hostname, boot_id_seed)
        }
        FilesystemType::Sysfs => {
            synthesize_sys_virtual_node(rel, mounts, caller, hostname, boot_id_seed)
        }
        FilesystemType::Cgroup2 => synthesize_cgroup_node(FilesystemType::Cgroup2, rel),
        _ => Err(Errno::ENOENT),
    }
}

fn cwd_if_at_fdcwd(owner: ObjectId, dirfd: u64) -> Option<Vec<u8>> {
    if linux_signed_int(dirfd) == AT_FDCWD_I32 {
        Some(super::step33_ext4_vfs::process_proc_cwd_root(owner).0)
    } else {
        None
    }
}

fn try_delegate_dev_open(abs_path: &[u8], flags: u64) -> Result<Option<SyscallReturn>, ()> {
    if let Some(ret) =
        super::step37_38_systemd_udev::try_open_kmsg_or_uevent_bytes(abs_path, flags)?
    {
        return Ok(Some(ret));
    }
    if !abs_path.starts_with(b"/dev/") {
        return Ok(None);
    }
    if let Some(ret) = super::step42_hardware::try_open_dev_bytes_if_block(abs_path, flags)? {
        return Ok(Some(ret));
    }
    super::step32_dev::try_open_dev_bytes(abs_path, flags)
}

fn try_delegate_dev_stat(abs_path: &[u8], user_statbuf: u64) -> Result<Option<SyscallReturn>, ()> {
    if !abs_path.starts_with(b"/dev/") {
        return Ok(None);
    }
    if let Some(ret) = super::step37_38_systemd_udev::try_stat_kmsg_bytes(abs_path, user_statbuf)? {
        return Ok(Some(ret));
    }
    if let Some(ret) = super::step42_hardware::try_stat_hw_bytes(abs_path, user_statbuf)? {
        return Ok(Some(ret));
    }
    super::step32_dev::try_stat_dev_bytes(abs_path, user_statbuf)
}

fn try_delegate_dev_statx(abs_path: &[u8], user_statx: u64) -> Result<Option<SyscallReturn>, ()> {
    if !abs_path.starts_with(b"/dev/") {
        return Ok(None);
    }
    if let Some(ret) = super::step37_38_systemd_udev::try_statx_kmsg_bytes(abs_path, user_statx)? {
        return Ok(Some(ret));
    }
    if let Some(ret) = super::step42_hardware::try_statx_hw_bytes(abs_path, user_statx)? {
        return Ok(Some(ret));
    }
    super::step32_dev::try_statx_dev_bytes(abs_path, user_statx)
}

fn delegate_host_open(
    owner: ObjectId,
    host_path: &[u8],
    flags: u64,
    mode: u64,
) -> Result<SyscallReturn, ()> {
    if let Some(ret) = try_delegate_dev_open(host_path, flags)? {
        return Ok(ret);
    }
    if let Some(ret) = super::step33_ext4_vfs::try_open_host_path(owner, host_path, flags, mode)? {
        return Ok(ret);
    }
    Ok(encode_result(super::step29_fd::openat_host_path(
        owner, host_path, flags, mode,
    )?))
}

fn is_cgroup_ctrl_writable(fstype: FilesystemType, rel: &[u8]) -> Option<&[u8]> {
    match fstype {
        FilesystemType::Cgroup2 => Some(rel),
        FilesystemType::Sysfs => rel.strip_prefix(b"fs/cgroup/"),
        _ => None,
    }
}

fn build_memfs_dir_entries(
    state: &Step33MountState,
    fstype: FilesystemType,
    mount_id: u32,
    dir_ino: u64,
) -> Result<Vec<VirtualDirEntry>, Errno> {
    let raw = state.memfs.list_dir(mount_id, dir_ino)?;
    let mut out = Vec::with_capacity(raw.len() + 4);
    for (ino, dt, name) in raw {
        let kind = match dt {
            4 => NodeKind::Directory,
            10 => NodeKind::Symlink,
            _ => NodeKind::Regular,
        };
        out.push(VirtualDirEntry { ino, kind, name });
    }
    if fstype == FilesystemType::Devpts
        && state.memfs.parent_ino(mount_id, dir_ino) == Some(dir_ino)
    {
        super::step32_dev::list_active_pts(|pts_idx| {
            let digits = format_u64_bytes(u64::from(pts_idx));
            if !out.iter().any(|e| e.name.as_slice() == digits.as_slice()) {
                out.push(VirtualDirEntry {
                    ino: (1u64 << 61) | ((136u64 << 8) | u64::from(pts_idx)),
                    kind: NodeKind::Regular,
                    name: digits,
                });
            }
        });
    }
    Ok(out)
}

const MAX_CROSS_FS_DEPTH: u8 = 16;
static CROSS_FS_DEPTH: [AtomicU8; 8] = [const { AtomicU8::new(0) }; 8];

struct CrossFsDepthGuard(usize);

impl CrossFsDepthGuard {
    fn enter() -> Result<Self, Errno> {
        let cpu = super::super::current_cpu_index().min(7);
        let cur = CROSS_FS_DEPTH[cpu].load(Ordering::Relaxed);
        if cur >= MAX_CROSS_FS_DEPTH {
            return Err(Errno::ELOOP);
        }
        CROSS_FS_DEPTH[cpu].store(cur + 1, Ordering::Relaxed);
        Ok(Self(cpu))
    }
}

impl Drop for CrossFsDepthGuard {
    fn drop(&mut self) {
        let cur = CROSS_FS_DEPTH[self.0].load(Ordering::Relaxed);
        CROSS_FS_DEPTH[self.0].store(cur.saturating_sub(1), Ordering::Relaxed);
    }
}

fn open_virtual_resolved(
    state: &mut Step33MountState,
    owner: ObjectId,
    target: ResolvedVirtualTarget,
    flags: u64,
    mode: u64,
    caller: &CallerSnapshotData,
    uid: u32,
    gid: u32,
    now: u32,
) -> Result<(Option<Vec<u8>>, Result<i64, Errno>), ()> {
    let is_path = (flags & O_PATH) != 0;
    let acc = flags & O_ACCMODE;
    if !is_path && acc == 3 {
        return Ok((None, Err(Errno::EINVAL)));
    }
    let readable = !is_path && matches!(acc, O_RDONLY | O_RDWR);
    let writable = !is_path && matches!(acc, O_WRONLY | O_RDWR);
    let close_on_exec = (flags & O_CLOEXEC) != 0;

    let (mount_id, fstype, abs_path, rel_path, mem_stat_opt, virt_node_opt, created_new) =
        match target {
            ResolvedVirtualTarget::HostAbsolute(host_path) => {
                return Ok((Some(host_path), Err(Errno::ENOENT)));
            }
            ResolvedVirtualTarget::MissingLeaf {
                mount_id,
                fstype,
                parent_ino,
                parent_abs,
                parent_rel,
                leaf,
                trailing_slash,
            } => {
                if is_path || (flags & O_CREAT) == 0 {
                    return Ok((None, Err(Errno::ENOENT)));
                }
                if !is_memfs_fstype(fstype) {
                    return Ok((None, Err(Errno::EROFS)));
                }
                if trailing_slash || (flags & O_DIRECTORY) != 0 {
                    return Ok((None, Err(Errno::EISDIR)));
                }
                let abs = join_mount_and_rel(&parent_abs, &leaf);
                let rel = join_rel(&parent_rel, &leaf);
                let stat = match state.memfs.open_or_create_file(
                    mount_id,
                    parent_ino,
                    &leaf,
                    (mode as u32) & 0o7777,
                    uid,
                    gid,
                    (flags & O_EXCL) != 0,
                    (flags & O_TRUNC) != 0,
                    now,
                ) {
                    Ok(st) => st,
                    Err(e) => return Ok((None, Err(e))),
                };
                (mount_id, fstype, abs, rel, Some(stat), None, true)
            }
            ResolvedVirtualTarget::Virtual {
                mount_id,
                is_mount_root: _,
                fstype,
                abs_path,
                rel_path,
                node,
                mem_stat,
            } => (mount_id, fstype, abs_path, rel_path, mem_stat, node, false),
        };

    if let Some(mut ms) = mem_stat_opt {
        let is_tmpfile = (flags & O_TMPFILE) == O_TMPFILE;
        if !created_new && !is_tmpfile && (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
            return Ok((None, Err(Errno::EEXIST)));
        }
        if matches!(ms.kind, MemNodeKind::ChrDev(_) | MemNodeKind::BlkDev(_)) {
            if (flags & O_DIRECTORY) != 0 {
                return Ok((None, Err(Errno::ENOTDIR)));
            }
            if !is_path {
                if abs_path.starts_with(b"/dev/") {
                    return Ok((Some(abs_path), Err(Errno::ENOENT)));
                }
                if let Some(dev_path) = super::step33_memfs::dev_path_for_rdev(ms.rdev) {
                    return Ok((Some(dev_path.to_vec()), Err(Errno::ENOENT)));
                }
            }
        }
        if ms.kind == MemNodeKind::Symlink && (flags & O_NOFOLLOW) != 0 && !is_path {
            return Ok((None, Err(Errno::ELOOP)));
        }
        let mut is_dir = ms.kind == MemNodeKind::Dir;
        if is_tmpfile {
            if !is_dir {
                return Ok((None, Err(Errno::ENOTDIR)));
            }
            if is_path || !writable {
                return Ok((None, Err(Errno::EINVAL)));
            }
            if !is_memfs_fstype(fstype) {
                return Ok((None, Err(Errno::EOPNOTSUPP)));
            }
            ms = match state.memfs.create_tmpfile(
                mount_id,
                ms.ino,
                (mode as u32) & 0o7777,
                uid,
                gid,
                now,
            ) {
                Ok(tmp) => tmp,
                Err(e) => return Ok((None, Err(e))),
            };
            is_dir = false;
        } else {
            if (flags & O_DIRECTORY) != 0 && !is_dir {
                return Ok((None, Err(Errno::ENOTDIR)));
            }
            if is_dir && writable && !is_path {
                return Ok((None, Err(Errno::EISDIR)));
            }
        }
        if !is_path && writable && (flags & O_TRUNC) != 0 && ms.kind == MemNodeKind::File {
            if let Err(e) = state.memfs.truncate(mount_id, ms.ino, 0, now) {
                return Ok((None, Err(e)));
            }
        }
        let dir_entries = if is_dir && !is_path {
            match build_memfs_dir_entries(state, fstype, mount_id, ms.ino) {
                Ok(list) => list,
                Err(e) => return Ok((None, Err(e))),
            }
        } else {
            Vec::new()
        };
        let Some((slot_idx, _)) = state.fds.iter().enumerate().find(|(_, e)| !e.live) else {
            return Ok((None, Err(Errno::EMFILE)));
        };
        state.memfs.retain_fd(mount_id, ms.ino);
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1).max(1);
        let mut owners = DirectProcessRefs::empty();
        owners.init(owner, close_on_exec);
        let cur_ns_gen = state.ns_mounts_gen(caller.mnt_ns_id);
        state.fds[slot_idx] = ProcSysFdEntry {
            live: true,
            is_dir,
            generation,
            alias_refs: 0,
            owners,
            mount_id,
            mnt_ns_id: caller.mnt_ns_id,
            fstype,
            mem_ino: ms.ino,
            readable,
            writable,
            append: !is_path && (flags & O_APPEND) != 0,
            path_only: is_path,
            abs_path,
            rel_path,
            offset: 0,
            content: Vec::new(),
            dir_entries,
            last_mount_gen: cur_ns_gen,
            last_poll_gen: cur_ns_gen,
        };
        return Ok((None, Ok(i64::from(PROC_SYS_FD_BASE + (slot_idx as i32)))));
    }

    let node = match virt_node_opt {
        Some(n) => n,
        None => {
            let ns_mounts = state.ns_view(caller.mnt_ns_id).0;
            match synthesize_virtual_node(
                fstype,
                &rel_path,
                ns_mounts,
                Some(&state.fds),
                caller,
                &state.hostname[..state.hostname_len],
                state.boot_id_seed,
            ) {
                Ok(n) => n,
                Err(e) => return Ok((None, Err(e))),
            }
        }
    };
    let is_dir = matches!(node, VirtualNode::Directory(_));
    if (flags & O_DIRECTORY) != 0 && !is_dir {
        return Ok((None, Err(Errno::ENOTDIR)));
    }
    if let VirtualNode::Symlink(_) = &node
        && (flags & O_NOFOLLOW) != 0
        && !is_path
    {
        return Ok((None, Err(Errno::ELOOP)));
    }
    if !is_path && writable {
        if fstype == FilesystemType::Sysfs
            && super::step37_38_systemd_udev::is_sysfs_uevent_trigger_rel(&rel_path)
        {
            return Ok((Some(abs_path), Err(Errno::ENOENT)));
        }
        if is_cgroup_ctrl_writable(fstype, &rel_path).is_none() || is_dir {
            return Ok((
                None,
                Err(if is_dir { Errno::EISDIR } else { Errno::EACCES }),
            ));
        }
    }

    let Some((slot_idx, _)) = state.fds.iter().enumerate().find(|(_, e)| !e.live) else {
        return Ok((None, Err(Errno::EMFILE)));
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
    let cur_ns_gen = state.ns_mounts_gen(caller.mnt_ns_id);
    state.fds[slot_idx] = ProcSysFdEntry {
        live: true,
        is_dir,
        generation,
        alias_refs: 0,
        owners,
        mount_id,
        mnt_ns_id: caller.mnt_ns_id,
        fstype,
        mem_ino: 0,
        readable,
        writable,
        append: false,
        path_only: is_path,
        abs_path,
        rel_path,
        offset: 0,
        content,
        dir_entries,
        last_mount_gen: cur_ns_gen,
        last_poll_gen: cur_ns_gen,
    };
    let fd_num = i64::from(PROC_SYS_FD_BASE + (slot_idx as i32));
    Ok((None, Ok(fd_num)))
}

fn finish_open_action(
    owner: ObjectId,
    action: (Option<Vec<u8>>, Result<i64, Errno>),
    flags: u64,
    mode: u64,
) -> Result<SyscallReturn, ()> {
    if let Some(host_path) = action.0 {
        return delegate_host_open(owner, &host_path, flags, mode);
    }
    Ok(encode_result(action.1))
}

fn handle_openat_if_proc_or_sys(
    dirfd: u64,
    user_path: u64,
    flags: u64,
    mode: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let follow = (flags & O_NOFOLLOW) == 0 && ((flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL));
    let stop_at_missing = (flags & O_CREAT) != 0 && (flags & O_PATH) == 0;
    let caller = CallerSnapshotData::capture();
    let (uid, gid) = current_uid_gid();
    let now = current_epoch_now_secs();
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let action = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            cwd.as_deref(),
            false,
            stop_at_missing,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(errno) => return Ok(Some((None, Err(errno)))),
        };
        Ok(Some(open_virtual_resolved(
            state, owner, target, flags, mode, &caller, uid, gid, now,
        )?))
    })?;
    let Some(action) = action? else {
        return Ok(None);
    };
    finish_open_action(owner, action, flags, mode).map(Some)
}

fn handle_openat2_if_proc_or_sys(
    dirfd: u64,
    user_path: u64,
    user_how: u64,
    size: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if size < 24 {
        return Ok(None);
    }
    if user_how == 0 {
        return Ok(None);
    }
    let mut raw = [0u8; 24];
    if copy_from_user(&mut raw, user_how).is_err() {
        return Ok(None);
    }
    let flags = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let mode = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let resolve = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    if (resolve & !0x3f) != 0 {
        return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
    }
    handle_openat_if_proc_or_sys(dirfd, user_path, flags, mode)
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
        let (is_dir, is_path_only, fstype, mount_id, mem_ino, cur_offset) = {
            let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
                return Err(Errno::EBADF);
            };
            (
                entry.is_dir,
                entry.path_only,
                entry.fstype,
                entry.mount_id,
                entry.mem_ino,
                entry.offset,
            )
        };
        if is_path_only {
            return Err(Errno::EBADF);
        }
        if !is_dir {
            return Err(Errno::ENOTDIR);
        }
        if mem_ino != 0 {
            let live_entries = build_memfs_dir_entries(state, fstype, mount_id, mem_ino)?;
            state.fds[idx].dir_entries = live_entries;
        }
        let entries = &state.fds[idx].dir_entries;
        let mut offset = cur_offset;
        while offset < entries.len() {
            let item = &entries[offset];
            let rec = super::step29_dirent::encode_parts_with_inode(
                item.ino,
                &item.name,
                item.kind,
                offset + 1,
            )
            .map_err(|_| Errno::EINVAL)?;
            let bytes = rec.as_bytes();
            if out.len() + bytes.len() > count {
                if out.is_empty() {
                    return Err(Errno::EINVAL);
                }
                break;
            }
            out.extend_from_slice(bytes);
            offset += 1;
        }
        state.fds[idx].offset = offset;
        Ok((out.len(), cur_offset))
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

fn is_live_mountinfo_proc_path(rel_path: &[u8]) -> bool {
    rel_path == b"mounts" || rel_path == b"mountinfo" || rel_path.ends_with(b"/mountinfo")
}

fn refresh_procfs_fd_entry(state: &mut Step33MountState, idx: usize, caller: &CallerSnapshotData) {
    let entry = &state.fds[idx];
    let cur_ns_gen = state.ns_mounts_gen(entry.mnt_ns_id);
    if entry.mem_ino != 0
        || entry.is_dir
        || entry.fstype != FilesystemType::Procfs
        || !is_live_mountinfo_proc_path(&entry.rel_path)
        || entry.last_mount_gen == cur_ns_gen
    {
        return;
    }
    let ns_mounts = state.ns_view(entry.mnt_ns_id).0;
    if let Ok(VirtualNode::Regular(bytes)) = synthesize_virtual_node(
        entry.fstype,
        &entry.rel_path,
        ns_mounts,
        Some(&state.fds),
        caller,
        &state.hostname[..state.hostname_len],
        state.boot_id_seed,
    ) {
        state.fds[idx].content = bytes;
        state.fds[idx].last_mount_gen = cur_ns_gen;
    }
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let caller = CallerSnapshotData::capture();
    with_mount_state(|state| {
        if resolve_proc_sys_entry_mut(state, owner, idx, alias_gen).is_none() {
            return Err(Errno::EBADF);
        }
        if (whence == SEEK_SET && offset == 0) || whence == SEEK_END {
            refresh_procfs_fd_entry(state, idx, &caller);
        }
        let (is_dir, is_path_only, mem_ino, mount_id, dir_len, content_len) = {
            let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
                return Err(Errno::EBADF);
            };
            (
                entry.is_dir,
                entry.path_only,
                entry.mem_ino,
                entry.mount_id,
                entry.dir_entries.len(),
                entry.content.len(),
            )
        };
        if is_path_only {
            return Err(Errno::EBADF);
        }
        let end_len = if is_dir {
            dir_len as i64
        } else if mem_ino != 0 {
            let sz = state
                .memfs
                .stat_ino(mount_id, mem_ino)
                .map_or(0, |s| s.size);
            sz as i64
        } else {
            content_len as i64
        };
        let entry = &mut state.fds[idx];
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

fn handle_read(
    raw_fd: u64,
    user_buf: u64,
    count: u64,
    explicit_offset: Option<i64>,
) -> Result<Result<i64, Errno>, ()> {
    if count == 0 {
        return Ok(Ok(0));
    }
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    if explicit_offset.is_some_and(|off| off < 0) {
        return Ok(Err(Errno::EINVAL));
    }
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let max_chunk = usize::try_from(count).unwrap_or(65536).min(65536);
    let mut temp = vec![0u8; max_chunk];
    let caller = CallerSnapshotData::capture();
    let copied = with_mount_state(|state| {
        let (read_off, old_offset, mem_ino, mount_id) = {
            let Some(entry) = resolve_proc_sys_entry_mut(state, owner, idx, alias_gen) else {
                return Err(Errno::EBADF);
            };
            if entry.path_only || !entry.readable {
                return Err(Errno::EBADF);
            }
            if entry.is_dir {
                return Err(Errno::EISDIR);
            }
            let read_off = match explicit_offset {
                Some(off) => usize::try_from(off).map_err(|_| Errno::EINVAL)?,
                None => entry.offset,
            };
            (read_off, entry.offset, entry.mem_ino, entry.mount_id)
        };
        if read_off == 0 {
            refresh_procfs_fd_entry(state, idx, &caller);
        }
        let take = if mem_ino != 0 {
            state
                .memfs
                .read_at(mount_id, mem_ino, read_off, &mut temp)?
        } else {
            let content = &state.fds[idx].content;
            if read_off >= content.len() {
                0
            } else {
                let avail = content.len() - read_off;
                let n = max_chunk.min(avail);
                temp[..n].copy_from_slice(&content[read_off..read_off + n]);
                n
            }
        };
        if explicit_offset.is_none() {
            state.fds[idx].offset += take;
        }
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
        if explicit_offset.is_none() {
            let _ = with_mount_state(|state| {
                state.fds[idx].offset = old_offset;
            });
        }
        return Ok(Err(errno));
    }
    Ok(Ok(take as i64))
}

fn handle_readv(raw_fd: u64, user_iov: u64, raw_iovcnt: u64) -> Result<Result<i64, Errno>, ()> {
    let iovcnt = linux_signed_int(raw_iovcnt);
    if !(0..=1024).contains(&iovcnt) {
        return Ok(Err(Errno::EINVAL));
    }
    let mut total = 0i64;
    for i in 0..(iovcnt as usize) {
        let (base, len) = match read_user_iovec(user_iov, i) {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        if len == 0 {
            continue;
        }
        match handle_read(raw_fd, base, len as u64, None)? {
            Ok(n) => {
                total += n;
                if (n as usize) < len {
                    break;
                }
            }
            Err(e) => return Ok(if total > 0 { Ok(total) } else { Err(e) }),
        }
    }
    Ok(Ok(total))
}

fn handle_write(
    raw_fd: u64,
    user_buf: u64,
    count: u64,
    explicit_offset: Option<i64>,
) -> Result<Result<i64, Errno>, ()> {
    if explicit_offset.is_some_and(|off| off < 0) {
        return Ok(Err(Errno::EINVAL));
    }
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let req_len = usize::try_from(count).unwrap_or(65536).min(65536);
    if req_len > 0 && user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut payload = vec![0u8; req_len];
    if req_len > 0
        && let Err(e) = copy_from_user(&mut payload, user_buf)
    {
        return Ok(Err(e));
    }
    let now = current_epoch_now_secs();
    let res = with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry_mut(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if entry.path_only || !entry.writable {
            return Err(Errno::EBADF);
        }
        if entry.is_dir {
            return Err(Errno::EISDIR);
        }
        let mount_id = entry.mount_id;
        let fstype = entry.fstype;
        let mem_ino = entry.mem_ino;
        let append = entry.append;
        let write_off = match explicit_offset {
            Some(off) => usize::try_from(off).map_err(|_| Errno::EINVAL)?,
            None => entry.offset,
        };
        if mem_ino != 0 {
            let (written, end_off) = state.memfs.write_at(
                mount_id,
                mem_ino,
                write_off,
                &payload,
                append && explicit_offset.is_none(),
                now,
            )?;
            if explicit_offset.is_none() {
                state.fds[idx].offset = end_off;
            }
            return Ok(written as i64);
        }
        if let Some(cg_rel) = is_cgroup_ctrl_writable(fstype, &entry.rel_path) {
            super::step35_events_cgroup::write_cgroup_control_file(cg_rel, &payload)?;
            return Ok(payload.len() as i64);
        }
        Err(Errno::EACCES)
    })?;
    Ok(res)
}

fn handle_writev(raw_fd: u64, user_iov: u64, raw_iovcnt: u64) -> Result<Result<i64, Errno>, ()> {
    let iovcnt = linux_signed_int(raw_iovcnt);
    if !(0..=1024).contains(&iovcnt) {
        return Ok(Err(Errno::EINVAL));
    }
    let mut total = 0i64;
    for i in 0..(iovcnt as usize) {
        let (base, len) = match read_user_iovec(user_iov, i) {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        if len == 0 {
            continue;
        }
        match handle_write(raw_fd, base, len as u64, None)? {
            Ok(n) => total += n,
            Err(e) => return Ok(if total > 0 { Ok(total) } else { Err(e) }),
        }
    }
    Ok(Ok(total))
}

fn virtual_target_stat_meta(
    mount_id: u32,
    mnt_id: u32,
    is_mount_root: bool,
    fstype: FilesystemType,
    rel_path: &[u8],
    mem_stat: Option<MemStat>,
    node: Option<&VirtualNode>,
    follow: bool,
) -> super::step_fd_util::StatMeta {
    let dev = fstype.st_dev(mount_id);
    if let Some(ms) = mem_stat {
        let mode = if !follow || ms.kind != MemNodeKind::Symlink {
            ms.mode
        } else {
            S_IFREG_RW_MODE
        };
        return super::step_fd_util::StatMeta {
            dev,
            ino: ms.ino,
            mode,
            nlink: ms.nlink,
            uid: ms.uid,
            gid: ms.gid,
            rdev: ms.rdev,
            size: ms.size,
            blksize: 4096,
            blocks: ms.size.div_ceil(512),
            atime_sec: i64::from(ms.atime),
            atime_nsec: 0,
            mtime_sec: i64::from(ms.mtime),
            mtime_nsec: 0,
            ctime_sec: i64::from(ms.ctime),
            ctime_nsec: 0,
            mnt_id,
            is_mount_root,
        };
    }
    let ino = virtual_inode(fstype, rel_path);
    let (mode, nlink, size) = match node {
        Some(n) => virtual_node_mode_nlink_size(n, follow),
        None => (S_IFDIR_RX_MODE, 2, 0),
    };
    super::step_fd_util::StatMeta {
        dev,
        ino,
        mode,
        nlink,
        uid: 0,
        gid: 0,
        rdev: 0,
        size,
        blksize: 4096,
        blocks: size.div_ceil(512),
        atime_sec: i64::from(EPOCH_BASE_SECONDS),
        atime_nsec: 0,
        mtime_sec: i64::from(EPOCH_BASE_SECONDS),
        mtime_nsec: 0,
        ctime_sec: i64::from(EPOCH_BASE_SECONDS),
        ctime_nsec: 0,
        mnt_id,
        is_mount_root,
    }
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
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let action = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            cwd.as_deref(),
            false,
            false,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return ReadlinkRes::NotOwned,
            Err(errno) => return ReadlinkRes::Handled(Err(errno)),
        };
        if (raw_bufsiz as i64) <= 0 {
            return ReadlinkRes::Handled(Err(Errno::EINVAL));
        }
        if user_buf == 0 {
            return ReadlinkRes::Handled(Err(Errno::EFAULT));
        }
        ReadlinkRes::from_resolved(state, target)
    })?;
    finish_readlink_action(owner, action, user_buf, raw_bufsiz)
}

enum ReadlinkRes {
    NotOwned,
    HostAbsolute(Vec<u8>),
    Handled(Result<Vec<u8>, Errno>),
}

impl ReadlinkRes {
    fn from_resolved(state: &Step33MountState, target: ResolvedVirtualTarget) -> Self {
        match target {
            ResolvedVirtualTarget::HostAbsolute(host) => Self::HostAbsolute(host),
            ResolvedVirtualTarget::MissingLeaf { .. } => Self::Handled(Err(Errno::ENOENT)),
            ResolvedVirtualTarget::Virtual {
                mount_id,
                mem_stat: Some(ms),
                ..
            } => {
                if ms.kind == MemNodeKind::Symlink {
                    match state.memfs.read_symlink(mount_id, ms.ino) {
                        Some(t) => Self::Handled(Ok(t.to_vec())),
                        None => Self::Handled(Err(Errno::ENOENT)),
                    }
                } else {
                    Self::Handled(Err(Errno::EINVAL))
                }
            }
            ResolvedVirtualTarget::Virtual {
                node: Some(VirtualNode::Symlink(sym_target)),
                ..
            } => Self::Handled(Ok(sym_target)),
            ResolvedVirtualTarget::Virtual { .. } => Self::Handled(Err(Errno::EINVAL)),
        }
    }
}

fn finish_readlink_action(
    owner: ObjectId,
    action: ReadlinkRes,
    user_buf: u64,
    raw_bufsiz: u64,
) -> Result<Option<SyscallReturn>, ()> {
    match action {
        ReadlinkRes::NotOwned => Ok(None),
        ReadlinkRes::HostAbsolute(host_path) => {
            if let Some(ret) =
                super::step33_ext4_vfs::try_readlink_host_path(&host_path, user_buf, raw_bufsiz)?
            {
                return Ok(Some(ret));
            }
            Ok(Some(encode_result(super::step29_fd::readlinkat_host_path(
                owner, &host_path, user_buf, raw_bufsiz,
            )?)))
        }
        ReadlinkRes::Handled(Err(errno)) => Ok(Some(SyscallReturn::error(errno))),
        ReadlinkRes::Handled(Ok(target_out)) => {
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

enum StatRes {
    NotOwned,
    DevOrHost(Vec<u8>, Option<super::step_fd_util::StatMeta>),
    Err(Errno),
    Ok(super::step_fd_util::StatMeta),
}

fn stat_res_from_resolved(
    state: &Step33MountState,
    target: ResolvedVirtualTarget,
    caller: &CallerSnapshotData,
    follow: bool,
) -> StatRes {
    match target {
        ResolvedVirtualTarget::HostAbsolute(host) => StatRes::DevOrHost(host, None),
        ResolvedVirtualTarget::MissingLeaf { .. } => StatRes::Err(Errno::ENOENT),
        ResolvedVirtualTarget::Virtual {
            mount_id,
            is_mount_root,
            fstype,
            abs_path,
            rel_path,
            node,
            mem_stat,
        } => {
            let ns_mounts = state.ns_view(caller.mnt_ns_id).0;
            let (table_mnt_id, exact_mnt) = ns_mounts
                .resolve(&abs_path)
                .map(|(e, r)| (e.mount_id(), r.is_empty()))
                .unwrap_or((mount_id, is_mount_root));
            let is_mount_root = is_mount_root || exact_mnt;
            if let Some(ms) = mem_stat {
                let meta = virtual_target_stat_meta(
                    mount_id,
                    table_mnt_id,
                    is_mount_root,
                    fstype,
                    &rel_path,
                    Some(ms),
                    None,
                    follow,
                );
                if matches!(ms.kind, MemNodeKind::ChrDev(_) | MemNodeKind::BlkDev(_))
                    && abs_path.starts_with(b"/dev/")
                {
                    return StatRes::DevOrHost(abs_path, Some(meta));
                }
                return StatRes::Ok(meta);
            }
            let node = match node {
                Some(n) => n,
                None => match synthesize_virtual_node(
                    fstype,
                    &rel_path,
                    ns_mounts,
                    Some(&state.fds),
                    caller,
                    &state.hostname[..state.hostname_len],
                    state.boot_id_seed,
                ) {
                    Ok(n) => n,
                    Err(e) => return StatRes::Err(e),
                },
            };
            StatRes::Ok(virtual_target_stat_meta(
                mount_id,
                table_mnt_id,
                is_mount_root,
                fstype,
                &rel_path,
                None,
                Some(&node),
                follow,
            ))
        }
    }
}

fn finish_stat_res(
    owner: ObjectId,
    res: StatRes,
    user_statbuf: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    match res {
        StatRes::NotOwned => Ok(None),
        StatRes::DevOrHost(host_path, fallback_meta) => {
            if let Some(ret) = try_delegate_dev_stat(&host_path, user_statbuf)? {
                return Ok(Some(ret));
            }
            if let Some(meta) = fallback_meta {
                return Ok(Some(encode_result(write_aarch64_stat_meta(
                    user_statbuf,
                    &meta,
                ))));
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
        StatRes::Err(errno) => Ok(Some(SyscallReturn::error(errno))),
        StatRes::Ok(meta) => Ok(Some(encode_result(write_aarch64_stat_meta(
            user_statbuf,
            &meta,
        )))),
    }
}

fn finish_statx_res(
    owner: ObjectId,
    res: StatRes,
    user_statx: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    match res {
        StatRes::NotOwned => Ok(None),
        StatRes::DevOrHost(host_path, fallback_meta) => {
            if let Some(ret) = try_delegate_dev_statx(&host_path, user_statx)? {
                return Ok(Some(ret));
            }
            if let Some(meta) = fallback_meta {
                return Ok(Some(encode_result(write_aarch64_statx_meta(
                    user_statx, &meta,
                ))));
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
        StatRes::Err(errno) => Ok(Some(SyscallReturn::error(errno))),
        StatRes::Ok(meta) => Ok(Some(encode_result(write_aarch64_statx_meta(
            user_statx, &meta,
        )))),
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
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            cwd.as_deref(),
            allow_empty,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return StatRes::NotOwned,
            Err(errno) => return StatRes::Err(errno),
        };
        if user_statbuf == 0 {
            return StatRes::Err(Errno::EFAULT);
        }
        stat_res_from_resolved(state, target, &caller, follow)
    })?;
    finish_stat_res(owner, res, user_statbuf, flags)
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
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            cwd.as_deref(),
            allow_empty,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return StatRes::NotOwned,
            Err(errno) => return StatRes::Err(errno),
        };
        let allowed_flags =
            AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE;
        if (flags & !allowed_flags) != 0 {
            return StatRes::Err(Errno::EINVAL);
        }
        if user_statx == 0 {
            return StatRes::Err(Errno::EFAULT);
        }
        stat_res_from_resolved(state, target, &caller, follow)
    })?;
    finish_statx_res(owner, res, user_statx, flags)
}

enum AccessRes {
    NotOwned,
    HostAbsolute(Vec<u8>),
    Handled(Result<i64, Errno>),
}

fn access_res_from_resolved(
    fstype: FilesystemType,
    rel: &[u8],
    has_mem_stat: bool,
    mode: u64,
) -> Result<i64, Errno> {
    if (mode & W_OK) == 0 || has_mem_stat {
        return Ok(0);
    }
    if fstype == FilesystemType::Cgroup2 && super::step35_events_cgroup::cgroup_has_dir(rel) {
        return Ok(0);
    }
    if fstype == FilesystemType::Sysfs
        && super::step37_38_systemd_udev::is_sysfs_uevent_trigger_rel(rel)
    {
        return Ok(0);
    }
    if is_cgroup_ctrl_writable(fstype, rel).is_some() {
        return Ok(0);
    }
    Err(Errno::EACCES)
}

fn finish_access_res(
    owner: ObjectId,
    action: AccessRes,
    mode: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    match action {
        AccessRes::NotOwned => Ok(None),
        AccessRes::HostAbsolute(host_path) => {
            if host_path.starts_with(b"/dev/")
                && super::step32_dev::try_open_dev_bytes(&host_path, O_PATH)
                    .is_ok_and(|o| o.is_some())
            {
                return Ok(Some(encode_result(Ok(0))));
            }
            if let Some(ret) =
                super::step33_ext4_vfs::try_access_host_path(owner, &host_path, mode, flags)?
            {
                return Ok(Some(ret));
            }
            Ok(Some(encode_result(super::step29_fd::faccessat_host_path(
                owner, &host_path,
            )?)))
        }
        AccessRes::Handled(res) => Ok(Some(encode_result(res))),
    }
}

fn handle_faccessat_if_proc_or_sys(
    dirfd: u64,
    user_path: u64,
    mode: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let allow_empty = (flags & AT_EMPTY_PATH) != 0;
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let action = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            cwd.as_deref(),
            allow_empty,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return AccessRes::NotOwned,
            Err(errno) => return AccessRes::Handled(Err(errno)),
        };
        if (mode & !ACCESS_MODE_MASK) != 0
            || (flags & !(AT_SYMLINK_NOFOLLOW | 0x200 | AT_EMPTY_PATH | AT_NO_AUTOMOUNT)) != 0
        {
            return AccessRes::Handled(Err(Errno::EINVAL));
        }
        match target {
            ResolvedVirtualTarget::HostAbsolute(host_path) => AccessRes::HostAbsolute(host_path),
            ResolvedVirtualTarget::MissingLeaf { .. } => AccessRes::Handled(Err(Errno::ENOENT)),
            ResolvedVirtualTarget::Virtual {
                fstype,
                rel_path,
                mem_stat,
                ..
            } => AccessRes::Handled(access_res_from_resolved(
                fstype,
                &rel_path,
                mem_stat.is_some(),
                mode,
            )),
        }
    })?;
    finish_access_res(owner, action, mode, flags)
}

fn handle_fstat(raw_fd: u64, user_statbuf: u64) -> Result<Result<i64, Errno>, ()> {
    if user_statbuf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let meta = with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        let (table_mnt_id, exact_mnt) = state
            .ns_view(entry.mnt_ns_id)
            .0
            .resolve(&entry.abs_path)
            .map(|(e, r)| (e.mount_id(), r.is_empty()))
            .unwrap_or((entry.mount_id, entry.rel_path.is_empty()));
        let is_mount_root = entry.rel_path.is_empty() || exact_mnt;
        if entry.mem_ino != 0 {
            let ms = state
                .memfs
                .stat_ino(entry.mount_id, entry.mem_ino)
                .ok_or(Errno::EBADF)?;
            return Ok(virtual_target_stat_meta(
                entry.mount_id,
                table_mnt_id,
                is_mount_root,
                entry.fstype,
                &entry.rel_path,
                Some(ms),
                None,
                false,
            ));
        }
        let dev = entry.fstype.st_dev(entry.mount_id);
        let ino = virtual_inode(entry.fstype, &entry.rel_path);
        let (mode, nlink, size) = if entry.is_dir {
            (S_IFDIR_RX_MODE, 2, 0)
        } else {
            (S_IFREG_RO_MODE, 1, entry.content.len() as u64)
        };
        Ok(super::step_fd_util::StatMeta {
            dev,
            ino,
            mode,
            nlink,
            uid: 0,
            gid: 0,
            rdev: 0,
            size,
            blksize: 4096,
            blocks: size.div_ceil(512),
            atime_sec: i64::from(EPOCH_BASE_SECONDS),
            atime_nsec: 0,
            mtime_sec: i64::from(EPOCH_BASE_SECONDS),
            mtime_nsec: 0,
            ctime_sec: i64::from(EPOCH_BASE_SECONDS),
            ctime_nsec: 0,
            mnt_id: table_mnt_id,
            is_mount_root,
        })
    })?;
    match meta {
        Ok(m) => Ok(write_aarch64_stat_meta(user_statbuf, &m)),
        Err(errno) => Ok(Err(errno)),
    }
}

fn read_user_path_vec(user_path: u64) -> Result<Vec<u8>, Errno> {
    let mut buf = vec![0u8; LINUX_PATH_MAX];
    let len = read_user_cstr(user_path, &mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

fn mkdir_resolved(
    state: &mut Step33MountState,
    target: ResolvedVirtualTarget,
    mode: u64,
    uid: u32,
    gid: u32,
    now: u32,
) -> Result<i64, Errno> {
    match target {
        ResolvedVirtualTarget::Virtual { .. } => Err(Errno::EEXIST),
        ResolvedVirtualTarget::HostAbsolute(_) => Err(Errno::EROFS),
        ResolvedVirtualTarget::MissingLeaf {
            mount_id,
            fstype,
            parent_ino,
            parent_rel,
            leaf,
            ..
        } => {
            if is_memfs_fstype(fstype) {
                state.memfs.mkdir(
                    mount_id,
                    parent_ino,
                    &leaf,
                    (mode as u32) & 0o7777,
                    uid,
                    gid,
                    now,
                )?;
                return Ok(0);
            }
            if fstype == FilesystemType::Cgroup2
                || (fstype == FilesystemType::Sysfs
                    && (parent_rel == b"fs/cgroup" || parent_rel.starts_with(b"fs/cgroup/")))
            {
                let sub_parent = parent_rel.strip_prefix(b"fs/cgroup").unwrap_or(&parent_rel);
                let sub_clean = sub_parent.strip_prefix(b"/").unwrap_or(sub_parent);
                let full_cg = join_rel(sub_clean, &leaf);
                super::step35_events_cgroup::cgroup_mkdir_strict(&full_cg)?;
                return Ok(0);
            }
            Err(Errno::EROFS)
        }
    }
}

fn handle_mkdirat_virtual(
    dirfd: u64,
    user_path: u64,
    mode: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let Ok(raw) = read_user_path_vec(user_path) else {
        return Ok(None);
    };
    let caller = CallerSnapshotData::capture();
    let (uid, gid) = current_uid_gid();
    let now = current_epoch_now_secs();
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let trimmed = if raw.len() > 1 && raw.ends_with(b"/") {
        let mut s = raw.as_slice();
        while s.len() > 1 && s.ends_with(b"/") {
            s = &s[..s.len() - 1];
        }
        s.to_vec()
    } else {
        raw
    };
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            dirfd,
            &trimmed,
            cwd.as_deref(),
            false,
            true,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        Some(mkdir_resolved(state, target, mode, uid, gid, now))
    })?;
    Ok(res.map(encode_result))
}

fn unlink_resolved(
    state: &mut Step33MountState,
    target: ResolvedVirtualTarget,
    remove_dir: bool,
) -> Result<i64, Errno> {
    match target {
        ResolvedVirtualTarget::MissingLeaf { .. } => Err(Errno::ENOENT),
        ResolvedVirtualTarget::HostAbsolute(_) => Err(Errno::EROFS),
        ResolvedVirtualTarget::Virtual {
            mount_id,
            is_mount_root,
            fstype,
            rel_path,
            mem_stat,
            ..
        } => {
            if is_mount_root {
                return Err(Errno::EBUSY);
            }
            if let Some(ms) = mem_stat {
                let parent = state
                    .memfs
                    .parent_ino(mount_id, ms.ino)
                    .ok_or(Errno::EBUSY)?;
                let leaf = match rel_path.iter().rposition(|&b| b == b'/') {
                    Some(pos) => &rel_path[pos + 1..],
                    None => &rel_path,
                };
                state.memfs.unlink(mount_id, parent, leaf, remove_dir)?;
                return Ok(0);
            }
            if remove_dir
                && (fstype == FilesystemType::Cgroup2
                    || (fstype == FilesystemType::Sysfs && rel_path.starts_with(b"fs/cgroup/")))
            {
                let cg_rel = rel_path.strip_prefix(b"fs/cgroup/").unwrap_or(&rel_path);
                super::step35_events_cgroup::cgroup_rmdir(cg_rel)?;
                return Ok(0);
            }
            Err(Errno::EPERM)
        }
    }
}

fn handle_unlinkat_virtual(
    dirfd: u64,
    user_path: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if (flags & !AT_REMOVEDIR) != 0 {
        return Ok(None);
    }
    let owner = current_process_id()?;
    let Ok(raw) = read_user_path_vec(user_path) else {
        return Ok(None);
    };
    let remove_dir = (flags & AT_REMOVEDIR) != 0;
    let trimmed = if remove_dir && raw.len() > 1 && raw.ends_with(b"/") {
        let mut s = raw.as_slice();
        while s.len() > 1 && s.ends_with(b"/") {
            s = &s[..s.len() - 1];
        }
        s.to_vec()
    } else {
        raw
    };
    let caller = CallerSnapshotData::capture();
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            dirfd,
            &trimmed,
            cwd.as_deref(),
            false,
            false,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        Some(unlink_resolved(state, target, remove_dir))
    })?;
    Ok(res.map(encode_result))
}

fn symlink_resolved(
    state: &mut Step33MountState,
    target: ResolvedVirtualTarget,
    link_target: &[u8],
    uid: u32,
    gid: u32,
    now: u32,
) -> Result<i64, Errno> {
    match target {
        ResolvedVirtualTarget::Virtual { .. } => Err(Errno::EEXIST),
        ResolvedVirtualTarget::HostAbsolute(_) => Err(Errno::EROFS),
        ResolvedVirtualTarget::MissingLeaf {
            mount_id,
            fstype,
            parent_ino,
            leaf,
            trailing_slash,
            ..
        } => {
            if trailing_slash {
                return Err(Errno::ENOENT);
            }
            if !is_memfs_fstype(fstype) {
                return Err(Errno::EROFS);
            }
            state
                .memfs
                .symlink(mount_id, parent_ino, &leaf, link_target, uid, gid, now)?;
            Ok(0)
        }
    }
}

fn parse_proc_fd_number(path: &[u8], caller_pid: u32) -> Option<u64> {
    let rest = if let Some(r) = path.strip_prefix(b"/proc/self/fd/") {
        r
    } else if let Some(r) = path.strip_prefix(b"/proc/") {
        let pid_end = r.iter().position(|&b| b == b'/')?;
        let pid_val = parse_u32_decimal(&r[..pid_end])?;
        if pid_val != caller_pid {
            return None;
        }
        r[pid_end..].strip_prefix(b"/fd/")?
    } else {
        return None;
    };
    if rest.is_empty() || rest.contains(&b'/') {
        return None;
    }
    parse_u32_decimal(rest).map(u64::from)
}

fn handle_linkat_virtual(
    olddirfd: u64,
    user_oldpath: u64,
    newdirfd: u64,
    user_newpath: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if (flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)) != 0 {
        return Ok(Some(encode_result(Err(Errno::EINVAL))));
    }
    let owner = current_process_id()?;
    let Ok(oldpath) = read_user_path_vec(user_oldpath) else {
        return Ok(None);
    };
    let Ok(newpath) = read_user_path_vec(user_newpath) else {
        return Ok(None);
    };
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let new_cwd = cwd_if_at_fdcwd(owner, newdirfd);
    let proc_fd_opt = if oldpath.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        Some(olddirfd)
    } else {
        parse_proc_fd_number(&oldpath, caller.pid)
    };
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let src_pair = if let Some(raw_fd) = proc_fd_opt {
            if !is_proc_sys_fd(raw_fd) && !is_aliased_proc_sys_fd(raw_fd) {
                return None;
            }
            let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
                return Some(Err(Errno::EBADF));
            };
            let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
                return Some(Err(Errno::EBADF));
            };
            if entry.mem_ino == 0 {
                return Some(Err(Errno::EPERM));
            }
            (entry.mount_id, entry.mem_ino)
        } else {
            return None;
        };

        let target = match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            newdirfd,
            &newpath,
            new_cwd.as_deref(),
            false,
            true,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return Some(Err(Errno::EXDEV)),
            Err(e) => return Some(Err(e)),
        };
        match target {
            ResolvedVirtualTarget::Virtual { .. } => Some(Err(Errno::EEXIST)),
            ResolvedVirtualTarget::HostAbsolute(_) => Some(Err(Errno::EXDEV)),
            ResolvedVirtualTarget::MissingLeaf {
                mount_id,
                fstype,
                parent_ino,
                leaf,
                trailing_slash,
                ..
            } => {
                if trailing_slash {
                    return Some(Err(Errno::ENOENT));
                }
                if !is_memfs_fstype(fstype) {
                    return Some(Err(Errno::EROFS));
                }
                if mount_id != src_pair.0 {
                    return Some(Err(Errno::EXDEV));
                }
                Some(
                    state
                        .memfs
                        .link_node(mount_id, src_pair.1, parent_ino, &leaf, now)
                        .map(|()| 0),
                )
            }
        }
    })?;
    Ok(res.map(encode_result))
}

fn handle_symlinkat_virtual(
    user_target: u64,
    newdirfd: u64,
    user_linkpath: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let Ok(linkpath) = read_user_path_vec(user_linkpath) else {
        return Ok(None);
    };
    let Ok(link_target) = read_user_path_vec(user_target) else {
        return Ok(None);
    };
    if link_target.is_empty() {
        return Ok(None);
    }
    let caller = CallerSnapshotData::capture();
    let (uid, gid) = current_uid_gid();
    let now = current_epoch_now_secs();
    let cwd = cwd_if_at_fdcwd(owner, newdirfd);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            newdirfd,
            &linkpath,
            cwd.as_deref(),
            false,
            true,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        Some(symlink_resolved(state, target, &link_target, uid, gid, now))
    })?;
    Ok(res.map(encode_result))
}

fn mknod_resolved(
    state: &mut Step33MountState,
    target: ResolvedVirtualTarget,
    mode: u64,
    dev: u64,
    uid: u32,
    gid: u32,
    now: u32,
) -> Result<i64, Errno> {
    match target {
        ResolvedVirtualTarget::Virtual { .. } => Err(Errno::EEXIST),
        ResolvedVirtualTarget::HostAbsolute(_) => Err(Errno::EROFS),
        ResolvedVirtualTarget::MissingLeaf {
            mount_id,
            fstype,
            parent_ino,
            leaf,
            trailing_slash,
            ..
        } => {
            if trailing_slash {
                return Err(Errno::ENOENT);
            }
            if !is_memfs_fstype(fstype) {
                return Err(Errno::EROFS);
            }
            state
                .memfs
                .mknod(mount_id, parent_ino, &leaf, mode as u32, dev, uid, gid, now)?;
            Ok(0)
        }
    }
}

fn handle_mknodat_virtual(
    dirfd: u64,
    user_path: u64,
    mode: u64,
    dev: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let Ok(raw) = read_user_path_vec(user_path) else {
        return Ok(None);
    };
    let caller = CallerSnapshotData::capture();
    let (uid, gid) = current_uid_gid();
    let now = current_epoch_now_secs();
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            dirfd,
            &raw,
            cwd.as_deref(),
            false,
            true,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        Some(mknod_resolved(state, target, mode, dev, uid, gid, now))
    })?;
    Ok(res.map(encode_result))
}

fn trim_trailing_slash(raw: &[u8]) -> &[u8] {
    let mut s = raw;
    while s.len() > 1 && s.ends_with(b"/") {
        s = &s[..s.len() - 1];
    }
    s
}

fn rename_resolved(
    state: &mut Step33MountState,
    old_t: Option<ResolvedVirtualTarget>,
    new_t: Option<ResolvedVirtualTarget>,
    noreplace: bool,
    now: u32,
) -> Option<Result<i64, Errno>> {
    match (old_t, new_t) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => Some(Err(Errno::EXDEV)),
        (Some(ot), Some(nt)) => {
            let (old_mount, old_parent, old_leaf) = match ot {
                ResolvedVirtualTarget::Virtual {
                    mount_id,
                    is_mount_root,
                    rel_path,
                    mem_stat: Some(ms),
                    ..
                } => {
                    if is_mount_root {
                        return Some(Err(Errno::EBUSY));
                    }
                    let Some(p) = state.memfs.parent_ino(mount_id, ms.ino) else {
                        return Some(Err(Errno::EBUSY));
                    };
                    let leaf = match rel_path.iter().rposition(|&b| b == b'/') {
                        Some(pos) => rel_path[pos + 1..].to_vec(),
                        None => rel_path,
                    };
                    (mount_id, p, leaf)
                }
                ResolvedVirtualTarget::MissingLeaf { .. } => return Some(Err(Errno::ENOENT)),
                _ => return Some(Err(Errno::EXDEV)),
            };
            let (new_mount, new_parent, new_leaf) = match nt {
                ResolvedVirtualTarget::Virtual {
                    mount_id,
                    is_mount_root,
                    rel_path,
                    mem_stat: Some(ms),
                    ..
                } => {
                    if is_mount_root {
                        return Some(Err(Errno::EBUSY));
                    }
                    let Some(p) = state.memfs.parent_ino(mount_id, ms.ino) else {
                        return Some(Err(Errno::EBUSY));
                    };
                    let leaf = match rel_path.iter().rposition(|&b| b == b'/') {
                        Some(pos) => rel_path[pos + 1..].to_vec(),
                        None => rel_path,
                    };
                    (mount_id, p, leaf)
                }
                ResolvedVirtualTarget::MissingLeaf {
                    mount_id,
                    fstype,
                    parent_ino,
                    leaf,
                    ..
                } => {
                    if !is_memfs_fstype(fstype) {
                        return Some(Err(Errno::EXDEV));
                    }
                    (mount_id, parent_ino, leaf)
                }
                _ => return Some(Err(Errno::EXDEV)),
            };
            if old_mount != new_mount {
                return Some(Err(Errno::EXDEV));
            }
            Some(
                state
                    .memfs
                    .rename(
                        old_mount, old_parent, &old_leaf, new_parent, &new_leaf, noreplace, now,
                    )
                    .map(|()| 0),
            )
        }
    }
}

fn handle_renameat_virtual(
    olddirfd: u64,
    user_oldpath: u64,
    newdirfd: u64,
    user_newpath: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if (flags & !RENAME_NOREPLACE) != 0 {
        return Ok(None);
    }
    let owner = current_process_id()?;
    let Ok(old_raw) = read_user_path_vec(user_oldpath) else {
        return Ok(None);
    };
    let Ok(new_raw) = read_user_path_vec(user_newpath) else {
        return Ok(None);
    };
    let noreplace = (flags & RENAME_NOREPLACE) != 0;
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let old_cwd = cwd_if_at_fdcwd(owner, olddirfd);
    let new_cwd = cwd_if_at_fdcwd(owner, newdirfd);
    let old_trimmed = trim_trailing_slash(&old_raw);
    let new_trimmed = trim_trailing_slash(&new_raw);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let old_res = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            olddirfd,
            old_trimmed,
            old_cwd.as_deref(),
            false,
            false,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        );
        let old_opt = match old_res {
            Ok(o) => o,
            Err(e) => return Some(Err(e)),
        };
        let new_res = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            newdirfd,
            new_trimmed,
            new_cwd.as_deref(),
            false,
            true,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        );
        let new_opt = match new_res {
            Ok(o) => o,
            Err(e) => {
                if old_opt.is_none() {
                    return None;
                }
                return Some(Err(e));
            }
        };
        rename_resolved(state, old_opt, new_opt, noreplace, now)
    })?;
    Ok(res.map(encode_result))
}

fn handle_truncate_virtual(user_path: u64, length: i64) -> Result<Option<SyscallReturn>, ()> {
    if length < 0 {
        return Ok(None);
    }
    let owner = current_process_id()?;
    let Ok(raw) = read_user_path_vec(user_path) else {
        return Ok(None);
    };
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let cwd = cwd_if_at_fdcwd(owner, AT_FDCWD_I32 as u64);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            &raw,
            cwd.as_deref(),
            false,
            false,
            true,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        match target {
            ResolvedVirtualTarget::Virtual {
                mount_id,
                mem_stat: Some(ms),
                ..
            } => Some(
                state
                    .memfs
                    .truncate(mount_id, ms.ino, length as usize, now)
                    .map(|()| 0),
            ),
            ResolvedVirtualTarget::Virtual { .. } => Some(Err(Errno::EACCES)),
            ResolvedVirtualTarget::MissingLeaf { .. } => Some(Err(Errno::ENOENT)),
            ResolvedVirtualTarget::HostAbsolute(_) => None,
        }
    })?;
    Ok(res.map(encode_result))
}

fn handle_ftruncate(raw_fd: u64, length: i64) -> Result<Result<i64, Errno>, ()> {
    if length < 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let now = current_epoch_now_secs();
    with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if entry.path_only || !entry.writable {
            return Err(Errno::EINVAL);
        }
        if entry.is_dir {
            return Err(Errno::EISDIR);
        }
        if entry.mem_ino != 0 {
            state
                .memfs
                .truncate(entry.mount_id, entry.mem_ino, length as usize, now)?;
            return Ok(0);
        }
        Err(Errno::EINVAL)
    })
}

/// Linux `FALLOC_FL_KEEP_SIZE`: reserve space without changing the visible file size.
pub(super) const FALLOC_FL_KEEP_SIZE: u64 = 0x01;

/// Validates `fallocate(2)` arguments shared by every backing store and returns the
/// requested end offset. Only plain allocation (`mode == 0`) and `FALLOC_FL_KEEP_SIZE` are
/// supported; hole punching / range collapsing report `EOPNOTSUPP` exactly like a filesystem
/// lacking those operations, which lets glibc `posix_fallocate` keep its documented semantics.
pub(super) fn validate_fallocate_args(raw_mode: u64, offset: i64, len: i64) -> Result<u64, Errno> {
    let mode = u64::from(linux_unsigned_int(raw_mode));
    if (mode & !FALLOC_FL_KEEP_SIZE) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if offset < 0 || len <= 0 {
        return Err(Errno::EINVAL);
    }
    let end = offset.checked_add(len).ok_or(Errno::EFBIG)?;
    Ok(end as u64)
}

fn handle_fallocate(
    raw_fd: u64,
    raw_mode: u64,
    offset: i64,
    len: i64,
) -> Result<Result<i64, Errno>, ()> {
    let end = match validate_fallocate_args(raw_mode, offset, len) {
        Ok(end) => end,
        Err(e) => return Ok(Err(e)),
    };
    let keep_size = (u64::from(linux_unsigned_int(raw_mode)) & FALLOC_FL_KEEP_SIZE) != 0;
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let now = current_epoch_now_secs();
    with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if entry.path_only || !entry.writable {
            return Err(Errno::EBADF);
        }
        if entry.is_dir {
            return Err(Errno::EISDIR);
        }
        if entry.mem_ino == 0 {
            return Err(Errno::ENODEV);
        }
        let (mount_id, ino) = (entry.mount_id, entry.mem_ino);
        let st = state.memfs.stat_ino(mount_id, ino).ok_or(Errno::EBADF)?;
        if st.kind != MemNodeKind::File {
            return Err(Errno::ENODEV);
        }
        let end = usize::try_from(end).map_err(|_| Errno::EFBIG)?;
        if !keep_size && (end as u64) > st.size {
            state.memfs.truncate(mount_id, ino, end, now)?;
        }
        Ok(0)
    })
}

fn fchmod_virtual_fd(
    owner: ObjectId,
    raw_fd: u64,
    raw_mode: u64,
    allow_path_fd: bool,
) -> Result<Result<i64, Errno>, ()> {
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let now = current_epoch_now_secs();
    with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if entry.path_only && !allow_path_fd {
            return Err(Errno::EBADF);
        }
        if entry.mem_ino != 0 {
            state
                .memfs
                .chmod(entry.mount_id, entry.mem_ino, raw_mode as u32, now)?;
            return Ok(0);
        }
        Ok(0)
    })
}

fn handle_fchmod(raw_fd: u64, raw_mode: u64) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    fchmod_virtual_fd(owner, raw_fd, raw_mode, false)
}

fn handle_fchmodat_virtual(
    dirfd: u64,
    user_path: u64,
    raw_mode: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if (flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0 {
        return Ok(None);
    }
    let owner = current_process_id()?;
    let Ok(raw) = read_user_path_vec(user_path) else {
        return Ok(None);
    };
    if raw.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        if resolve_proc_sys_slot_idx(owner, dirfd).is_ok() {
            return Ok(Some(encode_result(fchmod_virtual_fd(
                owner, dirfd, raw_mode, true,
            )?)));
        }
        return Ok(None);
    }
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            dirfd,
            &raw,
            cwd.as_deref(),
            false,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        match target {
            ResolvedVirtualTarget::Virtual {
                mount_id,
                mem_stat: Some(ms),
                ..
            } => Some(
                state
                    .memfs
                    .chmod(mount_id, ms.ino, raw_mode as u32, now)
                    .map(|()| 0),
            ),
            ResolvedVirtualTarget::Virtual { .. } => Some(Ok(0)),
            ResolvedVirtualTarget::MissingLeaf { .. } => Some(Err(Errno::ENOENT)),
            ResolvedVirtualTarget::HostAbsolute(_) => None,
        }
    })?;
    Ok(res.map(encode_result))
}

fn handle_fchown(raw_fd: u64, raw_uid: u64, raw_gid: u64) -> Result<Result<i64, Errno>, ()> {
    let owner = current_process_id()?;
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let now = current_epoch_now_secs();
    with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if entry.path_only {
            return Err(Errno::EBADF);
        }
        if entry.mem_ino != 0 {
            state.memfs.chown(
                entry.mount_id,
                entry.mem_ino,
                decode_chown_id(raw_uid),
                decode_chown_id(raw_gid),
                now,
            )?;
        }
        Ok(0)
    })
}

fn handle_fchownat_virtual(
    dirfd: u64,
    user_path: u64,
    raw_uid: u64,
    raw_gid: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let allow_empty = (flags & AT_EMPTY_PATH) != 0;
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            cwd.as_deref(),
            allow_empty,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        match target {
            ResolvedVirtualTarget::Virtual {
                mount_id,
                mem_stat: Some(ms),
                ..
            } => Some(
                state
                    .memfs
                    .chown(
                        mount_id,
                        ms.ino,
                        decode_chown_id(raw_uid),
                        decode_chown_id(raw_gid),
                        now,
                    )
                    .map(|()| 0),
            ),
            ResolvedVirtualTarget::Virtual { .. } => Some(Ok(0)),
            ResolvedVirtualTarget::MissingLeaf { .. } => Some(Err(Errno::ENOENT)),
            ResolvedVirtualTarget::HostAbsolute(_) => None,
        }
    })?;
    Ok(res.map(encode_result))
}

fn handle_utimens_on_fd(
    owner: ObjectId,
    dirfd: u64,
    user_times: u64,
    now: u32,
) -> Result<Option<SyscallReturn>, ()> {
    if !is_proc_sys_fd(dirfd) && !is_aliased_proc_sys_fd(dirfd) {
        return Ok(None);
    }
    let (atime, mtime) = match parse_utimens_pair(user_times, now) {
        Ok(v) => v,
        Err(e) => return Ok(Some(SyscallReturn::error(e))),
    };
    let Ok((idx, alias_gen)) = resolve_proc_sys_slot_idx(owner, dirfd) else {
        return Ok(Some(SyscallReturn::error(Errno::EBADF)));
    };
    let res = with_mount_state(|state| {
        let Some(entry) = resolve_proc_sys_entry(state, owner, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        if entry.mem_ino != 0 {
            state
                .memfs
                .utimens(entry.mount_id, entry.mem_ino, atime, mtime, now)?;
        }
        Ok(0)
    })?;
    Ok(Some(encode_result(res)))
}

fn handle_utimensat_virtual(
    dirfd: u64,
    user_path: u64,
    user_times: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let owner = current_process_id()?;
    let now = current_epoch_now_secs();
    if user_path == 0 {
        return handle_utimens_on_fd(owner, dirfd, user_times, now);
    }
    let Ok(raw) = read_user_path_vec(user_path) else {
        return Ok(None);
    };
    if raw.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        return handle_utimens_on_fd(owner, dirfd, user_times, now);
    }
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            dirfd,
            &raw,
            cwd.as_deref(),
            false,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        let (atime, mtime) = match parse_utimens_pair(user_times, now) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        match target {
            ResolvedVirtualTarget::Virtual {
                mount_id,
                mem_stat: Some(ms),
                ..
            } => Some(
                state
                    .memfs
                    .utimens(mount_id, ms.ino, atime, mtime, now)
                    .map(|()| 0),
            ),
            ResolvedVirtualTarget::Virtual { .. } => Some(Ok(0)),
            ResolvedVirtualTarget::MissingLeaf { .. } => Some(Err(Errno::ENOENT)),
            ResolvedVirtualTarget::HostAbsolute(_) => None,
        }
    })?;
    Ok(res.map(encode_result))
}

fn handle_name_to_handle_at(
    dirfd: u64,
    user_path: u64,
    user_handle: u64,
    user_mnt_id: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if (flags & !(AT_EMPTY_PATH | AT_SYMLINK_FOLLOW | 0x200)) != 0 {
        return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
    }
    let owner = current_process_id()?;
    let allow_empty = (flags & AT_EMPTY_PATH) != 0;
    let follow = (flags & AT_SYMLINK_FOLLOW) != 0;
    let caller = CallerSnapshotData::capture();
    let cwd = cwd_if_at_fdcwd(owner, dirfd);
    enum HandleRes {
        NotOwned,
        Host(Vec<u8>),
        Virtual(u64, u32),
        Err(Errno),
    }
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_path(
            state,
            &state.mounts,
            owner,
            dirfd,
            user_path,
            cwd.as_deref(),
            allow_empty,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return HandleRes::NotOwned,
            Err(e) => return HandleRes::Err(e),
        };
        match target {
            ResolvedVirtualTarget::HostAbsolute(h) => HandleRes::Host(h),
            ResolvedVirtualTarget::MissingLeaf { .. } => HandleRes::Err(Errno::ENOENT),
            ResolvedVirtualTarget::Virtual {
                mount_id,
                fstype,
                abs_path,
                rel_path,
                mem_stat,
                ..
            } => {
                let ino = match mem_stat {
                    Some(ms) => ms.ino,
                    None => virtual_inode(fstype, &rel_path),
                };
                let table_mnt_id = state
                    .ns_view(caller.mnt_ns_id)
                    .0
                    .resolve(&abs_path)
                    .map(|(e, _)| e.mount_id())
                    .unwrap_or(mount_id);
                HandleRes::Virtual(ino, table_mnt_id)
            }
        }
    })?;
    match res {
        HandleRes::NotOwned => Ok(None),
        HandleRes::Err(e) => Ok(Some(SyscallReturn::error(e))),
        HandleRes::Virtual(ino, mnt_id) => Ok(Some(encode_result(write_linux_file_handle(
            user_handle,
            user_mnt_id,
            ino,
            mnt_id,
        )))),
        HandleRes::Host(host_path) => {
            if let Some(ret) = super::step33_ext4_vfs::try_name_to_handle_host_path(
                owner,
                &host_path,
                user_handle,
                user_mnt_id,
                flags,
            )? {
                return Ok(Some(ret));
            }
            Ok(Some(encode_result(write_linux_file_handle(
                user_handle,
                user_mnt_id,
                virtual_inode(FilesystemType::Initramfs, &host_path),
                1,
            ))))
        }
    }
}

pub(super) fn is_virtual_dir(owner: ObjectId, abs_path: &[u8]) -> Result<bool, Errno> {
    let caller = CallerSnapshotData::capture();
    with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            true,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        match target {
            ResolvedVirtualTarget::Virtual {
                mem_stat: Some(ms), ..
            } => Ok(ms.kind == MemNodeKind::Dir),
            ResolvedVirtualTarget::Virtual { node: Some(n), .. } => {
                Ok(matches!(n, VirtualNode::Directory(_)))
            }
            ResolvedVirtualTarget::Virtual { node: None, .. } => Ok(true),
            _ => Err(Errno::ENOENT),
        }
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn try_open_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    flags: u64,
    mode: u64,
) -> Result<SyscallReturn, ()> {
    let Ok(_guard) = CrossFsDepthGuard::enter() else {
        return Ok(SyscallReturn::error(Errno::ELOOP));
    };
    let follow = (flags & O_NOFOLLOW) == 0 && ((flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL));
    let stop_at_missing = (flags & O_CREAT) != 0 && (flags & O_PATH) == 0;
    let caller = CallerSnapshotData::capture();
    let (uid, gid) = current_uid_gid();
    let now = current_epoch_now_secs();
    let action = with_mount_state(|state| {
        state.ensure_initialized();
        let target = match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            stop_at_missing,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok((Some(abs_path.to_vec()), Err(Errno::ENOENT))),
            Err(e) => return Ok((None, Err(e))),
        };
        open_virtual_resolved(state, owner, target, flags, mode, &caller, uid, gid, now)
    })?;
    finish_open_action(owner, action?, flags, mode)
}

pub(super) fn try_stat_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    flags: u64,
    user_statbuf: u64,
) -> Result<SyscallReturn, ()> {
    let Ok(_guard) = CrossFsDepthGuard::enter() else {
        return Ok(SyscallReturn::error(Errno::ELOOP));
    };
    if user_statbuf == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => stat_res_from_resolved(state, v, &caller, follow),
            Ok(None) => StatRes::DevOrHost(abs_path.to_vec(), None),
            Err(e) => StatRes::Err(e),
        }
    })?;
    Ok(finish_stat_res(owner, res, user_statbuf, flags)?
        .unwrap_or(SyscallReturn::error(Errno::ENOENT)))
}

pub(super) fn try_statx_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    flags: u64,
    user_statx: u64,
) -> Result<SyscallReturn, ()> {
    let Ok(_guard) = CrossFsDepthGuard::enter() else {
        return Ok(SyscallReturn::error(Errno::ELOOP));
    };
    if user_statx == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => stat_res_from_resolved(state, v, &caller, follow),
            Ok(None) => StatRes::DevOrHost(abs_path.to_vec(), None),
            Err(e) => StatRes::Err(e),
        }
    })?;
    Ok(finish_statx_res(owner, res, user_statx, flags)?
        .unwrap_or(SyscallReturn::error(Errno::ENOENT)))
}

pub(super) fn try_readlink_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    user_buf: u64,
    raw_bufsiz: u64,
) -> Result<SyscallReturn, ()> {
    let Ok(_guard) = CrossFsDepthGuard::enter() else {
        return Ok(SyscallReturn::error(Errno::ELOOP));
    };
    let caller = CallerSnapshotData::capture();
    let action = with_mount_state(|state| {
        state.ensure_initialized();
        match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(v)) => ReadlinkRes::from_resolved(state, v),
            Ok(None) => ReadlinkRes::Handled(Err(Errno::ENOENT)),
            Err(e) => ReadlinkRes::Handled(Err(e)),
        }
    })?;
    Ok(finish_readlink_action(owner, action, user_buf, raw_bufsiz)?
        .unwrap_or(SyscallReturn::error(Errno::ENOENT)))
}

pub(super) fn try_access_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    mode: u64,
    flags: u64,
) -> Result<SyscallReturn, ()> {
    let Ok(_guard) = CrossFsDepthGuard::enter() else {
        return Ok(SyscallReturn::error(Errno::ELOOP));
    };
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let action = with_mount_state(|state| {
        state.ensure_initialized();
        match resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        ) {
            Ok(Some(ResolvedVirtualTarget::HostAbsolute(h))) => AccessRes::HostAbsolute(h),
            Ok(Some(ResolvedVirtualTarget::MissingLeaf { .. })) | Ok(None) => {
                AccessRes::Handled(Err(Errno::ENOENT))
            }
            Ok(Some(ResolvedVirtualTarget::Virtual {
                fstype,
                rel_path,
                mem_stat,
                ..
            })) => AccessRes::Handled(access_res_from_resolved(
                fstype,
                &rel_path,
                mem_stat.is_some(),
                mode,
            )),
            Err(e) => AccessRes::Handled(Err(e)),
        }
    })?;
    Ok(finish_access_res(owner, action, mode, flags)?
        .unwrap_or(SyscallReturn::error(Errno::ENOENT)))
}

pub(super) fn try_mkdir_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    mode: u64,
) -> Result<SyscallReturn, ()> {
    let caller = CallerSnapshotData::capture();
    let (uid, gid) = current_uid_gid();
    let now = current_epoch_now_secs();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            trim_trailing_slash(abs_path),
            None,
            false,
            true,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        mkdir_resolved(state, target, mode, uid, gid, now)
    })?;
    Ok(encode_result(res))
}

pub(super) fn try_unlink_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    flags: u64,
) -> Result<SyscallReturn, ()> {
    let remove_dir = (flags & AT_REMOVEDIR) != 0;
    let path = if remove_dir {
        trim_trailing_slash(abs_path)
    } else {
        abs_path
    };
    let caller = CallerSnapshotData::capture();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            path,
            None,
            false,
            false,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        unlink_resolved(state, target, remove_dir)
    })?;
    Ok(encode_result(res))
}

pub(super) fn try_symlink_virtual_abs(
    owner: ObjectId,
    link_target: &[u8],
    abs_path: &[u8],
) -> Result<SyscallReturn, ()> {
    let caller = CallerSnapshotData::capture();
    let (uid, gid) = current_uid_gid();
    let now = current_epoch_now_secs();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            true,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        symlink_resolved(state, target, link_target, uid, gid, now)
    })?;
    Ok(encode_result(res))
}

pub(super) fn try_mknod_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    mode: u64,
    dev: u64,
) -> Result<SyscallReturn, ()> {
    let caller = CallerSnapshotData::capture();
    let (uid, gid) = current_uid_gid();
    let now = current_epoch_now_secs();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            true,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        mknod_resolved(state, target, mode, dev, uid, gid, now)
    })?;
    Ok(encode_result(res))
}

pub(super) fn try_rename_virtual_abs(
    owner: ObjectId,
    old_abs: &[u8],
    new_abs: &[u8],
    flags: u64,
) -> Result<SyscallReturn, ()> {
    if (flags & !RENAME_NOREPLACE) != 0 {
        return Ok(SyscallReturn::error(Errno::EINVAL));
    }
    let noreplace = (flags & RENAME_NOREPLACE) != 0;
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let ot = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            trim_trailing_slash(old_abs),
            None,
            false,
            false,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?;
        let nt = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            trim_trailing_slash(new_abs),
            None,
            false,
            true,
            false,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?;
        rename_resolved(state, ot, nt, noreplace, now).unwrap_or(Err(Errno::EXDEV))
    })?;
    Ok(encode_result(res))
}

pub(super) fn try_truncate_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    length: i64,
) -> Result<SyscallReturn, ()> {
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            true,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        match target {
            ResolvedVirtualTarget::Virtual {
                mount_id,
                mem_stat: Some(ms),
                ..
            } => state
                .memfs
                .truncate(mount_id, ms.ino, length as usize, now)
                .map(|()| 0),
            ResolvedVirtualTarget::Virtual { .. } => Err(Errno::EACCES),
            _ => Err(Errno::ENOENT),
        }
    })?;
    Ok(encode_result(res))
}

pub(super) fn try_chmod_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    raw_mode: u64,
    flags: u64,
) -> Result<SyscallReturn, ()> {
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        match target {
            ResolvedVirtualTarget::Virtual {
                mount_id,
                mem_stat: Some(ms),
                ..
            } => state
                .memfs
                .chmod(mount_id, ms.ino, raw_mode as u32, now)
                .map(|()| 0),
            ResolvedVirtualTarget::Virtual { .. } => Ok(0),
            _ => Err(Errno::ENOENT),
        }
    })?;
    Ok(encode_result(res))
}

pub(super) fn try_chown_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    raw_uid: u64,
    raw_gid: u64,
    flags: u64,
) -> Result<SyscallReturn, ()> {
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        match target {
            ResolvedVirtualTarget::Virtual {
                mount_id,
                mem_stat: Some(ms),
                ..
            } => state
                .memfs
                .chown(
                    mount_id,
                    ms.ino,
                    decode_chown_id(raw_uid),
                    decode_chown_id(raw_gid),
                    now,
                )
                .map(|()| 0),
            ResolvedVirtualTarget::Virtual { .. } => Ok(0),
            _ => Err(Errno::ENOENT),
        }
    })?;
    Ok(encode_result(res))
}

pub(super) fn try_utimens_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    atime: Option<u32>,
    mtime: Option<u32>,
    flags: u64,
) -> Result<SyscallReturn, ()> {
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let caller = CallerSnapshotData::capture();
    let now = current_epoch_now_secs();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        match target {
            ResolvedVirtualTarget::Virtual {
                mount_id,
                mem_stat: Some(ms),
                ..
            } => state
                .memfs
                .utimens(mount_id, ms.ino, atime, mtime, now)
                .map(|()| 0),
            ResolvedVirtualTarget::Virtual { .. } => Ok(0),
            _ => Err(Errno::ENOENT),
        }
    })?;
    Ok(encode_result(res))
}

pub(super) fn try_name_to_handle_virtual_abs(
    owner: ObjectId,
    abs_path: &[u8],
    user_handle: u64,
    user_mnt_id: u64,
    flags: u64,
) -> Result<SyscallReturn, ()> {
    let Ok(_guard) = CrossFsDepthGuard::enter() else {
        return Ok(SyscallReturn::error(Errno::ELOOP));
    };
    let follow = (flags & AT_SYMLINK_FOLLOW) != 0;
    let caller = CallerSnapshotData::capture();
    let res = with_mount_state(|state| {
        state.ensure_initialized();
        let target = resolve_virtual_bytes(
            state,
            &state.mounts,
            owner,
            AT_FDCWD_I32 as u64,
            abs_path,
            None,
            false,
            false,
            follow,
            &caller,
            &state.hostname[..state.hostname_len],
            state.boot_id_seed,
        )?
        .ok_or(Errno::ENOENT)?;
        match target {
            ResolvedVirtualTarget::Virtual {
                mount_id,
                fstype,
                rel_path,
                mem_stat,
                ..
            } => Ok((
                match mem_stat {
                    Some(ms) => ms.ino,
                    None => virtual_inode(fstype, &rel_path),
                },
                mount_id,
            )),
            _ => Err(Errno::ENOENT),
        }
    })?;
    Ok(match res {
        Ok((ino, mnt_id)) => encode_result(write_linux_file_handle(
            user_handle,
            user_mnt_id,
            ino,
            mnt_id,
        )),
        Err(e) => SyscallReturn::error(e),
    })
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
    // Virtual filesystems are backed by the bounded kernel heap (MemFs), so advertise a
    // 16 MiB capacity. Userspace sizing heuristics (e.g. journald's 10% runtime limit) then
    // stay inside what MemFs can actually store instead of failing later with ENOSPC.
    buf[16..24].copy_from_slice(&4096u64.to_le_bytes()); // f_blocks
    buf[24..32].copy_from_slice(&3072u64.to_le_bytes()); // f_bfree
    buf[32..40].copy_from_slice(&3072u64.to_le_bytes()); // f_bavail
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
