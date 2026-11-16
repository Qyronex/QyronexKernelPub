// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::ObjectId;
use kernal_linux_abi::{
    Errno, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_fd::SubsystemHandle;
use kernal_linux_mounts::{Ext4CreateAttr, Ext4InodeStat, FilesystemType};
use kernal_linux_vfs::LINUX_PATH_MAX;
use kernal_usercopy::MAX_USERCOPY_BYTES;

use super::step_fd_util::{
    DirectProcessRefs, SUBSYS_EXT4, StatMeta, copy_from_user, copy_to_user, current_epoch_now_secs,
    current_process_object, current_uid_gid, decode_chown_id, lookup_aliased_subsystem,
    lookup_aliased_subsystem_current, parse_utimens_pair, read_user_cstr, read_user_iovec,
    write_aarch64_stat_meta, write_aarch64_statx_meta, write_linux_file_handle,
};

fn current_process_id() -> Result<ObjectId, ()> {
    current_process_object().ok_or(())
}

/// Dedicated file-descriptor window for mounted real `ext4` volumes (`288..416`),
/// cleanly partitioned above Step-44 conformance descriptors (`272..280`).
pub(super) const EXT4_FD_BASE: i32 = 288;
const MAX_EXT4_FDS: usize = 128;
const MAX_PROCS: usize = super::step29_runtime::STEP29_RUNTIME_PROCESS_VIEWS;
const MAX_VFS_PATH: usize = LINUX_PATH_MAX;
const MAX_EXT4_RW_BYTES: usize = 1024 * 1024;
const MAX_SYMLINK_DEPTH: usize = 40;

const AT_FDCWD_I32: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EACCESS: u64 = 0x200;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
const RENAME_NOREPLACE: u64 = 1;

const O_ACCMODE: u64 = 0x3;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0x40;
const O_EXCL: u64 = 0x80;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;
const O_NONBLOCK: u64 = 0x800;
const O_DIRECTORY: u64 = 0x4000;
const O_NOFOLLOW: u64 = 0x8000;
const O_CLOEXEC: u64 = 0x0008_0000;
const O_PATH: u64 = 0x0020_0000;

const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

const F_GETLK: u32 = 5;
const F_SETLK: u32 = 6;
const F_SETLKW: u32 = 7;

const DT_UNKNOWN: u8 = 0;
const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_BLK: u8 = 6;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;

const S_IFLNK: u16 = 0o120_000;

#[derive(Clone, Copy)]
pub(super) struct Ext4ExecFile {
    pub mount_id: u32,
    pub ino: u32,
    pub mode: u16,
    pub size: u64,
}

#[derive(Clone)]
struct ProcessVfsState {
    live: bool,
    process: Option<ObjectId>,
    root: [u8; MAX_VFS_PATH],
    root_len: usize,
    cwd: [u8; MAX_VFS_PATH],
    cwd_len: usize,
    cwd_on_ext4: bool,
    cwd_mount_id: u32,
    cwd_ino: u32,
}

impl ProcessVfsState {
    const fn empty() -> Self {
        let mut root = [0u8; MAX_VFS_PATH];
        root[0] = b'/';
        let mut cwd = [0u8; MAX_VFS_PATH];
        cwd[0] = b'/';
        Self {
            live: false,
            process: None,
            root,
            root_len: 1,
            cwd,
            cwd_len: 1,
            cwd_on_ext4: false,
            cwd_mount_id: 0,
            cwd_ino: 0,
        }
    }

    fn reset(&mut self) {
        self.live = false;
        self.process = None;
        self.root[0] = b'/';
        self.root_len = 1;
        self.cwd[0] = b'/';
        self.cwd_len = 1;
        self.cwd_on_ext4 = false;
        self.cwd_mount_id = 0;
        self.cwd_ino = 0;
    }

    fn root_slice(&self) -> &[u8] {
        &self.root[..self.root_len]
    }

    fn cwd_slice(&self) -> &[u8] {
        &self.cwd[..self.cwd_len]
    }
}

struct Ext4FdEntry {
    live: bool,
    generation: u64,
    alias_refs: usize,
    owners: DirectProcessRefs<MAX_PROCS>,
    mount_id: u32,
    ino: u32,
    is_dir: bool,
    is_path_only: bool,
    readable: bool,
    writable: bool,
    append: bool,
    flags: u64,
    offset: u64,
    abs_path: Vec<u8>,
}

impl Ext4FdEntry {
    const EMPTY: Self = Self {
        live: false,
        generation: 0,
        alias_refs: 0,
        owners: DirectProcessRefs::empty(),
        mount_id: 0,
        ino: 0,
        is_dir: false,
        is_path_only: false,
        readable: false,
        writable: false,
        append: false,
        flags: 0,
        offset: 0,
        abs_path: Vec::new(),
    };
}

struct Ext4VfsState {
    next_generation: u64,
    procs: [ProcessVfsState; MAX_PROCS],
    fds: [Ext4FdEntry; MAX_EXT4_FDS],
}

impl Ext4VfsState {
    const fn new() -> Self {
        Self {
            next_generation: 1,
            procs: [const { ProcessVfsState::empty() }; MAX_PROCS],
            fds: [const { Ext4FdEntry::EMPTY }; MAX_EXT4_FDS],
        }
    }

    fn proc_slot(&self, process: ObjectId) -> Option<&ProcessVfsState> {
        self.procs
            .iter()
            .find(|p| p.live && p.process == Some(process))
    }

    fn ensure_proc_mut(&mut self, process: ObjectId) -> Option<&mut ProcessVfsState> {
        if let Some(pos) = self
            .procs
            .iter()
            .position(|p| p.live && p.process == Some(process))
        {
            return Some(&mut self.procs[pos]);
        }
        let slot = self.procs.iter_mut().find(|p| !p.live)?;
        slot.reset();
        slot.live = true;
        slot.process = Some(process);
        Some(slot)
    }
}

struct Ext4VfsCell {
    lock: AtomicU8,
    value: UnsafeCell<Ext4VfsState>,
}

// SAFETY: exclusive mutable access is serialized via `lock` transitions `0 -> 1 -> 0`.
unsafe impl Sync for Ext4VfsCell {}

static EXT4_VFS_STATE: Ext4VfsCell = Ext4VfsCell {
    lock: AtomicU8::new(0),
    value: UnsafeCell::new(Ext4VfsState::new()),
};

fn with_vfs_state<R>(f: impl FnOnce(&mut Ext4VfsState) -> R) -> Result<R, ()> {
    let mut spun = false;
    for _ in 0..500_000 {
        if EXT4_VFS_STATE
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            spun = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !spun {
        return Err(());
    }
    // SAFETY: state `1` grants exclusive mutable access for this synchronous scope.
    let res = f(unsafe { &mut *EXT4_VFS_STATE.value.get() });
    EXT4_VFS_STATE.lock.store(0, Ordering::Release);
    Ok(res)
}

fn encode_result(res: Result<i64, Errno>) -> SyscallReturn {
    match res {
        Ok(val) => SyscallReturn::success(val).unwrap_or(SyscallReturn::error(Errno::EINVAL)),
        Err(errno) => SyscallReturn::error(errno),
    }
}

pub(super) const fn is_ext4_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= EXT4_FD_BASE && fd < EXT4_FD_BASE + (MAX_EXT4_FDS as i32)
}

pub(super) fn is_open_ext4_fd(process: ObjectId, raw_fd: u64) -> bool {
    if !is_ext4_fd(raw_fd) {
        return false;
    }
    let idx = (linux_signed_int(raw_fd) - EXT4_FD_BASE) as usize;
    with_vfs_state(|state| {
        state
            .fds
            .get(idx)
            .is_some_and(|entry| entry_matches(entry, process, idx, None))
    })
    .unwrap_or(false)
}

fn retire_slot_if_unused(state: &mut Ext4VfsState, idx: usize) -> Option<u64> {
    let entry = state.fds.get_mut(idx)?;
    if entry.live && entry.owners.is_empty() && entry.alias_refs == 0 {
        let gen_id = entry.generation;
        *entry = Ext4FdEntry::EMPTY;
        Some(gen_id)
    } else {
        None
    }
}

fn resolve_ext4_slot_idx(process: ObjectId, raw_fd: u64) -> Option<(usize, Option<u64>)> {
    if is_ext4_fd(raw_fd) {
        let idx = (linux_signed_int(raw_fd) - EXT4_FD_BASE) as usize;
        return Some((idx, None));
    }
    let handle = lookup_aliased_subsystem(process, raw_fd)?;
    if handle.kind == SUBSYS_EXT4 {
        Some((usize::from(handle.slot), Some(handle.generation)))
    } else {
        None
    }
}

fn is_ext4_fd_or_alias_current(raw_fd: u64) -> bool {
    if is_ext4_fd(raw_fd) {
        return true;
    }
    lookup_aliased_subsystem_current(raw_fd).is_some_and(|h| h.kind == SUBSYS_EXT4)
}

fn entry_matches(entry: &Ext4FdEntry, owner: ObjectId, idx: usize, alias_gen: Option<u64>) -> bool {
    let _ = idx;
    if !entry.live {
        return false;
    }
    match alias_gen {
        Some(gen_id) => entry.generation == gen_id,
        None => entry.owners.has_owner(owner),
    }
}

pub(super) fn retain_alias_handle(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(SubsystemHandle, u64), Errno> {
    if !is_ext4_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let idx = (linux_signed_int(raw_fd) - EXT4_FD_BASE) as usize;
    with_vfs_state(|state| {
        let Some(entry) = state.fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry.live || !entry.owners.has_owner(process) {
            return Err(Errno::EBADF);
        }
        entry.alias_refs = entry.alias_refs.saturating_add(1);
        Ok((
            SubsystemHandle {
                kind: SUBSYS_EXT4,
                slot: idx as u16,
                generation: entry.generation,
            },
            entry.flags & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_PATH),
        ))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn release_alias_handle(handle: SubsystemHandle) {
    if handle.kind != SUBSYS_EXT4 {
        return;
    }
    let idx = usize::from(handle.slot);
    let mut retired = None;
    let _ = with_vfs_state(|state| {
        if let Some(entry) = state.fds.get_mut(idx)
            && entry.live
            && entry.generation == handle.generation
            && entry.alias_refs > 0
        {
            entry.alias_refs -= 1;
            retired = retire_slot_if_unused(state, idx);
        }
    });
    if let Some(ofd) = retired {
        super::step39_dpkg::on_retire_ext4_ofd(ofd);
    }
}

pub(super) fn handle_native_fcntl(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    let (idx, alias_gen) = resolve_ext4_slot_idx(process, raw_fd)?;
    if alias_gen.is_some() && !matches!(cmd, 3 | 4) {
        return None;
    }
    if matches!(cmd, F_GETLK | F_SETLK | F_SETLKW | 36 | 37 | 38) {
        return None;
    }
    let res = with_vfs_state(|state| {
        let Some(entry) = state.fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
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
            3 => Ok((entry.flags & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_PATH)) as i64),
            4 => {
                let mutable_mask = O_APPEND | O_NONBLOCK;
                entry.flags =
                    (entry.flags & !mutable_mask) | (u64::from(argi as u32) & mutable_mask);
                entry.append = (entry.flags & O_APPEND) != 0;
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    });
    Some(res.unwrap_or(Err(Errno::EIO)))
}

pub(super) fn probe_ext4_fd_readiness(
    process: ObjectId,
    raw_fd: u64,
) -> Option<Result<u32, Errno>> {
    let (idx, alias_gen) = resolve_ext4_slot_idx(process, raw_fd)?;
    let res = with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok(u32::from(kernal_linux_abi::POLLIN) | u32::from(kernal_linux_abi::POLLOUT))
    });
    Some(res.unwrap_or(Err(Errno::EIO)))
}

pub(super) fn describe_ext4_slot(
    slot: u16,
    expected_gen: Option<u64>,
    owner_filter: Option<ObjectId>,
    out: &mut [u8],
) -> Option<usize> {
    let mut written = None;
    let _ = with_vfs_state(|state| {
        let Some(entry) = state.fds.get(usize::from(slot)) else {
            return;
        };
        if !entry.live {
            return;
        }
        if let Some(gen_id) = expected_gen
            && entry.generation != gen_id
        {
            return;
        }
        if let Some(owner) = owner_filter
            && !entry.owners.has_owner(owner)
        {
            return;
        }
        let take = out.len().min(entry.abs_path.len());
        out[..take].copy_from_slice(&entry.abs_path[..take]);
        written = Some(take);
    });
    written
}

pub(super) fn append_open_ext4_fds(process: ObjectId, out: &mut Vec<i32>) {
    let _ = with_vfs_state(|state| {
        for (idx, entry) in state.fds.iter().enumerate() {
            if entry.live && entry.owners.has_owner(process) {
                out.push(EXT4_FD_BASE + (idx as i32));
            }
        }
    });
}

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    let _ = with_vfs_state(|state| {
        for entry in &mut state.fds {
            if entry.live {
                entry.owners.on_fork(parent, child);
            }
        }
        if let Some(pidx) = state
            .procs
            .iter()
            .position(|p| p.live && p.process == Some(parent))
        {
            let root = state.procs[pidx].root_slice().to_vec();
            let cwd = state.procs[pidx].cwd_slice().to_vec();
            let cwd_on_ext4 = state.procs[pidx].cwd_on_ext4;
            let cwd_mount_id = state.procs[pidx].cwd_mount_id;
            let cwd_ino = state.procs[pidx].cwd_ino;
            if let Some(cslot) = state.ensure_proc_mut(child) {
                copy_into_path_buf(&mut cslot.root, &mut cslot.root_len, &root);
                copy_into_path_buf(&mut cslot.cwd, &mut cslot.cwd_len, &cwd);
                cslot.cwd_on_ext4 = cwd_on_ext4;
                cslot.cwd_mount_id = cwd_mount_id;
                cslot.cwd_ino = cwd_ino;
            }
        }
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    let mut retired = Vec::new();
    let _ = with_vfs_state(|state| {
        for idx in 0..MAX_EXT4_FDS {
            if state.fds[idx].live {
                state.fds[idx].owners.close_cloexec_for(process);
                if let Some(ofd) = retire_slot_if_unused(state, idx) {
                    retired.push(ofd);
                }
            }
        }
    });
    for ofd in retired {
        super::step39_dpkg::on_retire_ext4_ofd(ofd);
    }
}

pub(super) fn on_process_exit(process: ObjectId) {
    let mut retired = Vec::new();
    let _ = with_vfs_state(|state| {
        for idx in 0..MAX_EXT4_FDS {
            if state.fds[idx].live {
                let _ = state.fds[idx].owners.close_owner(process);
                if let Some(ofd) = retire_slot_if_unused(state, idx) {
                    retired.push(ofd);
                }
            }
        }
        if let Some(p) = state
            .procs
            .iter_mut()
            .find(|p| p.live && p.process == Some(process))
        {
            p.reset();
        }
    });
    for ofd in retired {
        super::step39_dpkg::on_retire_ext4_ofd(ofd);
    }
}

pub(super) fn close_range_for_process(
    process: ObjectId,
    first: u32,
    last: u32,
    cloexec_only: bool,
) {
    let mut closed = Vec::new();
    let _ = with_vfs_state(|state| {
        for idx in 0..MAX_EXT4_FDS {
            let fd = EXT4_FD_BASE + (idx as i32);
            if super::step_fd_util::fd_in_close_range(fd, first, last)
                && state.fds[idx].live
                && state.fds[idx]
                    .owners
                    .apply_close_range(process, cloexec_only)
            {
                let mount_id = state.fds[idx].mount_id;
                let ino = state.fds[idx].ino;
                let retired = retire_slot_if_unused(state, idx);
                closed.push((mount_id, ino, retired));
            }
        }
    });
    for (mount_id, ino, retired) in closed {
        super::step39_dpkg::on_close_ext4_fd(mount_id, ino, retired);
    }
}

pub(super) fn on_mount_removed(mount_id: u32) {
    let _ = with_vfs_state(|state| {
        for p in &mut state.procs {
            if p.live && p.cwd_on_ext4 && p.cwd_mount_id == mount_id {
                p.cwd_on_ext4 = false;
                p.cwd_mount_id = 0;
                p.cwd_ino = 0;
            }
        }
    });
}

pub(super) fn on_mount_moved(mount_id: u32, old_mp: &[u8], new_mp: &[u8]) {
    let _ = with_vfs_state(|state| {
        for entry in &mut state.fds {
            if entry.live && entry.mount_id == mount_id {
                entry.abs_path = remap_prefix(&entry.abs_path, old_mp, new_mp);
            }
        }
        for p in &mut state.procs {
            if !p.live {
                continue;
            }
            if p.cwd_on_ext4 && p.cwd_mount_id == mount_id {
                let next = remap_prefix(p.cwd_slice(), old_mp, new_mp);
                copy_into_path_buf(&mut p.cwd, &mut p.cwd_len, &next);
            }
            if p.root_slice().starts_with(old_mp) {
                let next = remap_prefix(p.root_slice(), old_mp, new_mp);
                copy_into_path_buf(&mut p.root, &mut p.root_len, &next);
            }
        }
    });
}

pub(super) fn on_pivot_root(new_root: &[u8], put_old: &[u8]) {
    let _ = with_vfs_state(|state| {
        for entry in &mut state.fds {
            if entry.live {
                entry.abs_path = remap_pivot_slice(&entry.abs_path, new_root, put_old);
            }
        }
        for p in &mut state.procs {
            if !p.live {
                continue;
            }
            let next_cwd = remap_pivot_slice(p.cwd_slice(), new_root, put_old);
            copy_into_path_buf(&mut p.cwd, &mut p.cwd_len, &next_cwd);
            let next_root = remap_pivot_slice(p.root_slice(), new_root, put_old);
            copy_into_path_buf(&mut p.root, &mut p.root_len, &next_root);
        }
    });
}

pub(super) fn ext4_mount_id_for_fd(process: ObjectId, raw_fd: u64) -> Option<u32> {
    let (idx, alias_gen) = resolve_ext4_slot_idx(process, raw_fd)?;
    let mut found = None;
    let _ = with_vfs_state(|state| {
        if let Some(entry) = state.fds.get(idx)
            && entry_matches(entry, process, idx, alias_gen)
        {
            found = Some(entry.mount_id);
        }
    });
    found
}

/// Returns `(mount_id, ino, open_file_desc_id, current_offset, file_len)` for an open `ext4` FD
/// or alias so POSIX `fcntl` record locks and BSD `flock` share inode identity.
pub(super) fn ext4_lock_info_for_fd(
    process: ObjectId,
    raw_fd: u64,
) -> Option<(u32, u32, u64, i64, i64)> {
    let (idx, alias_gen) = resolve_ext4_slot_idx(process, raw_fd)?;
    let mut info = None;
    let _ = with_vfs_state(|state| {
        if let Some(entry) = state.fds.get(idx)
            && entry_matches(entry, process, idx, alias_gen)
        {
            info = Some((
                entry.mount_id,
                entry.ino,
                entry.generation,
                i64::try_from(entry.offset).unwrap_or(i64::MAX),
            ));
        }
    });
    let (mount_id, ino, ofd_id, offset) = info?;
    let file_len =
        super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| vol.stat_inode(dev, ino))
            .map(|st| i64::try_from(st.size).unwrap_or(i64::MAX))
            .unwrap_or(0);
    Some((mount_id, ino, ofd_id, offset, file_len))
}

pub(super) fn process_proc_cwd_root(process: ObjectId) -> (Vec<u8>, Vec<u8>) {
    let snap = get_proc_root_and_cwd(process).unwrap_or_else(|_| (vec![b'/'], vec![b'/'], false));
    let root = snap.0;
    let cwd = snap.1;
    let visible_cwd = strip_chroot_prefix(&cwd, &root);
    (visible_cwd, vec![b'/'])
}

fn remap_prefix(path: &[u8], old_mp: &[u8], new_mp: &[u8]) -> Vec<u8> {
    if path == old_mp {
        return new_mp.to_vec();
    }
    if old_mp != b"/"
        && path.len() > old_mp.len()
        && path.starts_with(old_mp)
        && path[old_mp.len()] == b'/'
    {
        let mut out = if new_mp == b"/" {
            Vec::new()
        } else {
            new_mp.to_vec()
        };
        out.extend_from_slice(&path[old_mp.len()..]);
        if out.is_empty() {
            out.push(b'/');
        }
        return out;
    }
    path.to_vec()
}

fn remap_pivot_slice(path: &[u8], new_root: &[u8], put_old: &[u8]) -> Vec<u8> {
    if path == new_root {
        return vec![b'/'];
    }
    if new_root != b"/"
        && path.len() > new_root.len()
        && path.starts_with(new_root)
        && path[new_root.len()] == b'/'
    {
        return path[new_root.len()..].to_vec();
    }
    if path == b"/" {
        return put_old.to_vec();
    }
    let mut out = put_old.to_vec();
    if out == b"/" {
        out.clear();
    }
    out.extend_from_slice(path);
    out
}

fn copy_into_path_buf(buf: &mut [u8; MAX_VFS_PATH], len: &mut usize, src: &[u8]) {
    let take = src.len().min(MAX_VFS_PATH);
    buf[..take].copy_from_slice(&src[..take]);
    *len = take.max(1);
    if take == 0 {
        buf[0] = b'/';
    }
}

fn strip_chroot_prefix(abs_path: &[u8], root: &[u8]) -> Vec<u8> {
    if root == b"/" {
        return abs_path.to_vec();
    }
    if abs_path == root {
        return vec![b'/'];
    }
    if abs_path.len() > root.len() && abs_path.starts_with(root) && abs_path[root.len()] == b'/' {
        return abs_path[root.len()..].to_vec();
    }
    vec![b'/']
}

fn get_proc_root_and_cwd(process: ObjectId) -> Result<(Vec<u8>, Vec<u8>, bool), Errno> {
    let (mut root, mut cwd, cwd_on_ext4) = with_vfs_state(|state| {
        if let Some(p) = state.proc_slot(process) {
            (
                p.root_slice().to_vec(),
                p.cwd_slice().to_vec(),
                p.cwd_on_ext4,
            )
        } else {
            (vec![b'/'], vec![b'/'], false)
        }
    })
    .map_err(|()| Errno::EIO)?;
    if !cwd_on_ext4 && root == b"/" {
        if let Ok(initramfs_cwd) = super::step29_fd::initramfs_cwd_bytes(process)
            && !initramfs_cwd.is_empty()
        {
            cwd = initramfs_cwd;
        }
    }
    if root.is_empty() {
        root.push(b'/');
    }
    if cwd.is_empty() {
        cwd.push(b'/');
    }
    Ok((root, cwd, cwd_on_ext4))
}

fn proc_uses_custom_vfs(process: ObjectId) -> bool {
    with_vfs_state(|state| {
        state
            .proc_slot(process)
            .is_some_and(|p| p.cwd_on_ext4 || p.root_slice() != b"/")
    })
    .unwrap_or(false)
}

#[derive(Clone)]
enum ResolvedPath {
    Virtual {
        abs_path: Vec<u8>,
    },
    Ext4Existing {
        mount_id: u32,
        abs_path: Vec<u8>,
        stat: Ext4InodeStat,
        parent_ino: u32,
        leaf: Vec<u8>,
    },
    Ext4MissingParent {
        mount_id: u32,
        abs_path: Vec<u8>,
        parent_ino: u32,
        leaf: Vec<u8>,
    },
    Initramfs {
        abs_path: Vec<u8>,
    },
}

fn lex_join_clamped(root: &[u8], base: &[u8], rel_or_abs: &[u8]) -> Result<Vec<u8>, Errno> {
    let mut parts: Vec<Vec<u8>> = if rel_or_abs.starts_with(b"/") {
        split_components(root)
    } else {
        split_components(base)
    };
    let root_depth = split_components(root).len();
    for comp in rel_or_abs.split(|&b| b == b'/') {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        if comp == b".." {
            if parts.len() > root_depth {
                parts.pop();
            }
            continue;
        }
        parts.push(comp.to_vec());
    }
    join_components(&parts)
}

fn split_components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&b| b == b'/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_vec())
        .collect()
}

fn join_components(parts: &[Vec<u8>]) -> Result<Vec<u8>, Errno> {
    if parts.is_empty() {
        return Ok(vec![b'/']);
    }
    let mut out = Vec::new();
    for p in parts {
        out.push(b'/');
        out.extend_from_slice(p);
    }
    if out.len() >= MAX_VFS_PATH {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(out)
}

fn starting_base_for(
    process: ObjectId,
    dirfd: i32,
    raw_path: &[u8],
    root: &[u8],
    cwd: &[u8],
) -> Result<(Vec<u8>, bool), Errno> {
    if raw_path.starts_with(b"/") {
        return Ok((root.to_vec(), false));
    }
    if dirfd == AT_FDCWD_I32 {
        return Ok((cwd.to_vec(), false));
    }
    let raw_u64 = i64::from(dirfd) as u64;
    if let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_u64) {
        let info = with_vfs_state(|state| {
            let entry = state.fds.get(idx)?;
            if !entry_matches(entry, process, idx, alias_gen) {
                return None;
            }
            Some((entry.is_dir, entry.abs_path.clone()))
        })
        .map_err(|()| Errno::EIO)?;
        let Some((is_dir, abs_path)) = info else {
            return Err(Errno::EBADF);
        };
        if !is_dir {
            return Err(Errno::ENOTDIR);
        }
        return Ok((abs_path, true));
    }
    if let Some(initramfs_dir) = super::step29_fd::resolve_initramfs_dirfd_path(process, raw_u64) {
        return Ok((initramfs_dir, false));
    }
    Err(Errno::EBADF)
}

fn is_virtual_abs(abs_path: &[u8]) -> bool {
    super::step33_mounts::has_virtual_mount_prefix(abs_path)
}

fn resolve_path(
    process: ObjectId,
    dirfd: i32,
    raw_path: &[u8],
    follow_last_symlink: bool,
) -> Result<ResolvedPath, Errno> {
    if raw_path.is_empty() {
        return Err(Errno::ENOENT);
    }
    let trailing_slash = raw_path.len() > 1 && raw_path.ends_with(b"/");
    let (root, cwd, _) = get_proc_root_and_cwd(process)?;
    let (start_abs, _) = starting_base_for(process, dirfd, raw_path, &root, &cwd)?;
    let root_parts = split_components(&root);

    let mut cur_parts = split_components(&start_abs);
    let mut queue: Vec<Vec<u8>> = raw_path
        .split(|&b| b == b'/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_vec())
        .collect();
    queue.reverse();

    let mut symlink_depth = 0usize;
    let mut cur_ext4_cache: Option<(u32, Ext4InodeStat, u32, Vec<u8>)> = None;

    // Seed initial directory if queue is empty (e.g. `"/"` or `"."`).
    while let Some(comp) = queue.pop() {
        let is_final = queue.is_empty();
        if comp == b"." {
            continue;
        }
        if comp == b".." {
            if cur_parts.len() > root_parts.len() {
                cur_parts.pop();
            }
            cur_ext4_cache = None;
            continue;
        }
        if comp.len() > 255 {
            return Err(Errno::ENAMETOOLONG);
        }

        let parent_abs = join_components(&cur_parts)?;
        let mut next_parts = cur_parts.clone();
        next_parts.push(comp.clone());
        let next_abs = join_components(&next_parts)?;

        // Crossing into a kernel virtual mount (/proc, /sys, /dev, /mnt/proc, etc.).
        if is_virtual_abs(&next_abs) {
            let mut rest_parts = next_parts;
            while let Some(rem) = queue.pop() {
                if rem == b"." {
                    continue;
                }
                if rem == b".." {
                    if rest_parts.len() > root_parts.len() {
                        rest_parts.pop();
                    }
                } else {
                    rest_parts.push(rem);
                }
            }
            let full_virt = join_components(&rest_parts)?;
            return Ok(ResolvedPath::Virtual {
                abs_path: full_virt,
            });
        }

        // Entering an exact ext4 mountpoint from any parent filesystem.
        if let Some(exact_mount_id) = super::step33_mounts::ext4_mount_at_exact(&next_abs) {
            let root_stat =
                super::step33_mounts::with_ext4_volume(exact_mount_id, |vol, dev, _| {
                    let root_ino = vol.root_ino();
                    vol.stat_inode(dev, root_ino)
                })?;
            cur_parts = next_parts;
            cur_ext4_cache = Some((exact_mount_id, root_stat, 2, Vec::new()));
            continue;
        }

        // Parent is on a mounted ext4 volume.
        if let Some((mount_id, mp_len)) = super::step33_mounts::resolve_ext4_mount(&parent_abs) {
            let parent_ino = ext4_ino_for_abs(mount_id, mp_len, &parent_abs, &cur_ext4_cache)?;
            let step = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                match vol.lookup_child(dev, parent_ino, &comp) {
                    Ok(st) => {
                        let must_follow = !is_final || follow_last_symlink || trailing_slash;
                        if st.is_symlink() && must_follow {
                            let target = vol.read_symlink(dev, st.ino)?;
                            Ok(Ok((st, Some(target))))
                        } else {
                            Ok(Ok((st, None)))
                        }
                    }
                    Err(Errno::ENOENT) => Ok(Err(())),
                    Err(e) => Err(e),
                }
            })?;

            match step {
                Err(()) => {
                    if is_final {
                        return Ok(ResolvedPath::Ext4MissingParent {
                            mount_id,
                            abs_path: next_abs,
                            parent_ino,
                            leaf: comp,
                        });
                    }
                    return Err(Errno::ENOENT);
                }
                Ok((_st, Some(target))) => {
                    symlink_depth += 1;
                    if symlink_depth > MAX_SYMLINK_DEPTH {
                        return Err(Errno::ELOOP);
                    }
                    if target.is_empty() {
                        return Err(Errno::ENOENT);
                    }
                    let mut expanded: Vec<Vec<u8>> = target
                        .split(|&b| b == b'/')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_vec())
                        .collect();
                    expanded.reverse();
                    queue.extend(expanded);
                    if target.starts_with(b"/") {
                        cur_parts = root_parts.clone();
                    }
                    cur_ext4_cache = None;
                    continue;
                }
                Ok((st, None)) => {
                    if (!is_final || trailing_slash) && !st.is_dir() {
                        return Err(Errno::ENOTDIR);
                    }
                    cur_parts = next_parts;
                    cur_ext4_cache = Some((mount_id, st, parent_ino, comp));
                    continue;
                }
            }
        }

        // Parent is on initramfs: inspect symlinks so symlinks onto ext4 work cleanly.
        if let Ok(init_path) = translate_host_path_vec(&next_abs) {
            if let Ok(Some((is_dir, Some(target)))) =
                super::step29_fd::inspect_initramfs_path(process, &init_path)
            {
                let _ = is_dir;
                let must_follow = !is_final || follow_last_symlink || trailing_slash;
                if must_follow {
                    symlink_depth += 1;
                    if symlink_depth > MAX_SYMLINK_DEPTH {
                        return Err(Errno::ELOOP);
                    }
                    let mut expanded: Vec<Vec<u8>> = target
                        .split(|&b| b == b'/')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_vec())
                        .collect();
                    expanded.reverse();
                    queue.extend(expanded);
                    if target.starts_with(b"/") {
                        cur_parts = root_parts.clone();
                    }
                    cur_ext4_cache = None;
                    continue;
                }
            }
        }

        cur_parts = next_parts;
        cur_ext4_cache = None;
    }

    let final_abs = join_components(&cur_parts)?;
    if is_virtual_abs(&final_abs) {
        return Ok(ResolvedPath::Virtual {
            abs_path: final_abs,
        });
    }
    if let Some((mount_id, mp_len, stat, parent_ino, leaf)) = if let Some((m, st, pino, leaf)) =
        cur_ext4_cache
    {
        Some((m, 0usize, st, pino, leaf))
    } else if let Some((mount_id, mp_len)) = super::step33_mounts::resolve_ext4_mount(&final_abs) {
        let (st, pino, leaf) = resolve_ext4_abs_direct(mount_id, mp_len, &final_abs, &cur_parts)?;
        Some((mount_id, mp_len, st, pino, leaf))
    } else {
        None
    } {
        let _ = mp_len;
        if trailing_slash && !stat.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        return Ok(ResolvedPath::Ext4Existing {
            mount_id,
            abs_path: final_abs,
            stat,
            parent_ino,
            leaf,
        });
    }

    Ok(ResolvedPath::Initramfs {
        abs_path: final_abs,
    })
}

fn ext4_ino_for_abs(
    mount_id: u32,
    mp_len: usize,
    abs_path: &[u8],
    cache: &Option<(u32, Ext4InodeStat, u32, Vec<u8>)>,
) -> Result<u32, Errno> {
    if let Some((cid, stat, _, _)) = cache
        && *cid == mount_id
    {
        return Ok(stat.ino);
    }
    let rel = if mp_len == 1 {
        abs_path.strip_prefix(b"/").unwrap_or(abs_path)
    } else {
        abs_path
            .get(mp_len..)
            .and_then(|s| s.strip_prefix(b"/"))
            .unwrap_or(b"")
    };
    super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
        let mut ino = vol.root_ino();
        for comp in rel.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            let st = vol.lookup_child(dev, ino, comp)?;
            ino = st.ino;
        }
        Ok(ino)
    })
}

fn resolve_ext4_abs_direct(
    mount_id: u32,
    mp_len: usize,
    abs_path: &[u8],
    parts: &[Vec<u8>],
) -> Result<(Ext4InodeStat, u32, Vec<u8>), Errno> {
    let rel = if mp_len == 1 {
        abs_path.strip_prefix(b"/").unwrap_or(abs_path)
    } else {
        abs_path
            .get(mp_len..)
            .and_then(|s| s.strip_prefix(b"/"))
            .unwrap_or(b"")
    };
    super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
        let root_ino = vol.root_ino();
        if rel.is_empty() {
            let st = vol.stat_inode(dev, root_ino)?;
            return Ok((st, root_ino, Vec::new()));
        }
        let mut ino = root_ino;
        let mut parent = root_ino;
        let mut leaf = Vec::new();
        let mut last_st = vol.stat_inode(dev, root_ino)?;
        for comp in rel.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            parent = ino;
            leaf = comp.to_vec();
            last_st = vol.lookup_child(dev, ino, comp)?;
            ino = last_st.ino;
        }
        let _ = parts;
        Ok((last_st, parent, leaf))
    })
}

pub(super) fn resolve_abs_for_current_into(
    raw_path: &[u8],
    out: &mut [u8],
) -> Result<usize, Errno> {
    let process = current_process_id().map_err(|()| Errno::EIO)?;
    let (root, cwd, _) = get_proc_root_and_cwd(process)?;
    let abs = lex_join_clamped(&root, &cwd, raw_path)?;
    if abs.len() > out.len() {
        return Err(Errno::ENAMETOOLONG);
    }
    out[..abs.len()].copy_from_slice(&abs);
    Ok(abs.len())
}

pub(super) fn resolve_abs_for_current_following(
    raw_path: &[u8],
    out: &mut [u8],
) -> Result<usize, Errno> {
    resolve_abs_for_current_with_follow(raw_path, true, out)
}

pub(super) fn resolve_abs_for_current_with_follow(
    raw_path: &[u8],
    follow_last_symlink: bool,
    out: &mut [u8],
) -> Result<usize, Errno> {
    let process = current_process_id().map_err(|()| Errno::EIO)?;
    let resolved = resolve_path(process, AT_FDCWD_I32, raw_path, follow_last_symlink)?;
    let abs = match resolved {
        ResolvedPath::Virtual { abs_path }
        | ResolvedPath::Ext4Existing { abs_path, .. }
        | ResolvedPath::Initramfs { abs_path } => abs_path,
        ResolvedPath::Ext4MissingParent { .. } => return Err(Errno::ENOENT),
    };
    if abs.len() > out.len() {
        return Err(Errno::ENAMETOOLONG);
    }
    out[..abs.len()].copy_from_slice(&abs);
    Ok(abs.len())
}

pub(super) fn try_select_ext4_exec(
    process: ObjectId,
    dirfd: i32,
    raw_path: &[u8],
    empty_path: bool,
    follow_last: bool,
) -> Result<Option<Ext4ExecFile>, Errno> {
    if empty_path {
        let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, i64::from(dirfd) as u64) else {
            return Ok(None);
        };
        let (mount_id, ino, is_dir) = with_vfs_state(|state| {
            let entry = state.fds.get(idx).ok_or(Errno::EBADF)?;
            if !entry_matches(entry, process, idx, alias_gen) {
                return Err(Errno::EBADF);
            }
            Ok((entry.mount_id, entry.ino, entry.is_dir))
        })
        .map_err(|()| Errno::EIO)??;
        if is_dir {
            return Err(Errno::EACCES);
        }
        let stat = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
            vol.stat_inode(dev, ino)
        })?;
        if !stat.is_reg() {
            return Err(Errno::EACCES);
        }
        return Ok(Some(Ext4ExecFile {
            mount_id,
            ino: stat.ino,
            mode: stat.mode,
            size: stat.size,
        }));
    }

    if !super::step33_mounts::has_live_ext4_mounts() && !proc_uses_custom_vfs(process) {
        return Ok(None);
    }

    let mut cur_dirfd = dirfd;
    let mut cur_path = raw_path.to_vec();
    for _ in 0..8 {
        match resolve_path(process, cur_dirfd, &cur_path, follow_last) {
            Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
                if stat.is_dir() || !stat.is_reg() {
                    return Err(Errno::EACCES);
                }
                return Ok(Some(Ext4ExecFile {
                    mount_id,
                    ino: stat.ino,
                    mode: stat.mode,
                    size: stat.size,
                }));
            }
            Ok(ResolvedPath::Ext4MissingParent { .. }) => return Err(Errno::ENOENT),
            Ok(ResolvedPath::Virtual { abs_path }) => {
                if let Some(host) = super::step33_mounts::resolve_virtual_host_target_once(
                    process,
                    &abs_path,
                    follow_last,
                )? {
                    cur_dirfd = -100;
                    cur_path = host;
                    continue;
                }
                return Err(Errno::EACCES);
            }
            Ok(ResolvedPath::Initramfs { .. }) => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    Err(Errno::ELOOP)
}

pub(super) fn read_ext4_file_all(mount_id: u32, ino: u32, size: u64) -> Result<Vec<u8>, Errno> {
    let total = usize::try_from(size).map_err(|_| Errno::ENOMEM)?;
    if total > 16 * 1024 * 1024 {
        return Err(Errno::ENOMEM);
    }
    let mut out = vec![0u8; total];
    if total == 0 {
        return Ok(out);
    }
    super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
        let mut off = 0usize;
        while off < total {
            let n = vol.read_file(dev, ino, off as u64, &mut out[off..])?;
            if n == 0 {
                break;
            }
            off += n;
        }
        out.truncate(off);
        Ok(out)
    })
}

pub(super) fn try_read_ext4_fd_for_mmap(
    process: ObjectId,
    raw_fd: u64,
) -> Result<Option<Vec<u8>>, Errno> {
    Ok(try_read_ext4_fd_for_mmap_with_meta(process, raw_fd, false)?.map(|(bytes, _, _)| bytes))
}

pub(super) fn try_read_ext4_fd_for_mmap_with_meta(
    process: ObjectId,
    raw_fd: u64,
    require_writable: bool,
) -> Result<Option<(Vec<u8>, u32, u32)>, Errno> {
    let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) else {
        return Ok(None);
    };
    let (mount_id, ino, is_dir, is_path_only, readable, writable) = match with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok((
            entry.mount_id,
            entry.ino,
            entry.is_dir,
            entry.is_path_only,
            entry.readable,
            entry.writable,
        ))
    }) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(()) => return Err(Errno::EIO),
    };
    if is_path_only || !readable || is_dir || (require_writable && !writable) {
        return Err(Errno::EACCES);
    }
    let stat =
        super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| vol.stat_inode(dev, ino))?;
    if !stat.is_reg() {
        return Err(Errno::EACCES);
    }
    let bytes = read_ext4_file_all(mount_id, ino, stat.size)?;
    Ok(Some((bytes, mount_id, ino)))
}

pub(super) fn write_back_ext4_mmap(mount_id: u32, ino: u32, file_offset: u64, data: &[u8]) {
    let now = current_epoch_now_secs();
    let _ = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
        let stat = vol.stat_inode(dev, ino)?;
        let take = usize::try_from(stat.size.saturating_sub(file_offset))
            .unwrap_or(0)
            .min(data.len());
        if take > 0 {
            let _ = vol.write_file(dev, ino, file_offset, &data[..take], now)?;
        }
        Ok(())
    });
}

fn stat_to_meta(mount_id: u32, stat: &Ext4InodeStat) -> StatMeta {
    StatMeta {
        dev: FilesystemType::Ext4.st_dev(mount_id),
        ino: u64::from(stat.ino),
        mode: u32::from(stat.mode),
        nlink: u32::from(stat.nlink),
        uid: stat.uid,
        gid: stat.gid,
        rdev: 0,
        size: stat.size,
        blksize: stat.blksize,
        blocks: stat.blocks_512,
        atime_sec: stat.atime,
        atime_nsec: 0,
        mtime_sec: stat.mtime,
        mtime_nsec: 0,
        ctime_sec: stat.ctime,
        ctime_nsec: 0,
        mnt_id: super::step33_mounts::ext4_table_mount_id(mount_id),
        is_mount_root: stat.ino == 2,
    }
}

fn ext4_ft_to_dt(ft: u8) -> u8 {
    match ft {
        1 => DT_REG,
        2 => DT_DIR,
        3 => DT_CHR,
        4 => DT_BLK,
        5 => DT_FIFO,
        6 => DT_SOCK,
        7 => DT_LNK,
        _ => DT_UNKNOWN,
    }
}

fn alloc_ext4_fd(
    process: ObjectId,
    mount_id: u32,
    ino: u32,
    is_dir: bool,
    flags: u64,
    abs_path: Vec<u8>,
) -> Result<i64, Errno> {
    let cloexec = (flags & O_CLOEXEC) != 0;
    let is_path = (flags & O_PATH) != 0;
    let acc = flags & O_ACCMODE;
    let readable = !is_path && acc != O_WRONLY;
    let writable = !is_path && (acc == O_WRONLY || acc == O_RDWR);
    let append = (flags & O_APPEND) != 0;

    with_vfs_state(|state| {
        let Some((idx, slot)) = state.fds.iter_mut().enumerate().find(|(_, s)| !s.live) else {
            return Err(Errno::EMFILE);
        };
        let gen_id = state.next_generation;
        state.next_generation = state.next_generation.saturating_add(1).max(1);
        *slot = Ext4FdEntry {
            live: true,
            generation: gen_id,
            alias_refs: 0,
            owners: DirectProcessRefs::empty(),
            mount_id,
            ino,
            is_dir,
            is_path_only: is_path,
            readable,
            writable,
            append,
            flags,
            offset: 0,
            abs_path,
        };
        slot.owners.init(process, cloexec);
        Ok(i64::from(EXT4_FD_BASE + (idx as i32)))
    })
    .map_err(|()| Errno::EIO)?
}

fn open_ext4_target(
    process: ObjectId,
    target: ResolvedPath,
    flags: u64,
    raw_mode: u64,
) -> Result<i64, Errno> {
    let acc = flags & O_ACCMODE;
    if acc == 3 && (flags & O_PATH) == 0 {
        return Err(Errno::EINVAL);
    }
    let is_path = (flags & O_PATH) != 0;
    let want_write = !is_path && (acc == O_WRONLY || acc == O_RDWR);
    let want_creat = !is_path && (flags & O_CREAT) != 0;
    let want_excl = want_creat && (flags & O_EXCL) != 0;
    let want_trunc = !is_path && (flags & O_TRUNC) != 0;
    let want_dir = (flags & O_DIRECTORY) != 0;
    let nofollow = (flags & O_NOFOLLOW) != 0;

    let (mount_id, ino, is_dir, abs_path) = match target {
        ResolvedPath::Ext4Existing {
            mount_id,
            abs_path,
            stat,
            ..
        } => {
            if want_excl {
                return Err(Errno::EEXIST);
            }
            if nofollow && stat.is_symlink() && !is_path {
                return Err(Errno::ELOOP);
            }
            if want_dir && !stat.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            if (want_write || want_trunc) && stat.is_dir() {
                return Err(Errno::EISDIR);
            }
            let now = current_epoch_now_secs();
            super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                if (want_write || want_trunc) && vol.is_read_only() {
                    return Err(Errno::EROFS);
                }
                if want_trunc && want_write && stat.is_reg() {
                    vol.truncate_inode(dev, stat.ino, 0, now)?;
                }
                Ok(())
            })?;
            (mount_id, stat.ino, stat.is_dir(), abs_path)
        }
        ResolvedPath::Ext4MissingParent {
            mount_id,
            abs_path,
            parent_ino,
            leaf,
        } => {
            if !want_creat {
                return Err(Errno::ENOENT);
            }
            if want_dir {
                return Err(Errno::ENOENT);
            }
            let (uid, gid) = current_uid_gid();
            let now = current_epoch_now_secs();
            let applied = super::step29_fd::apply_umask_mode(process, linux_unsigned_int(raw_mode));
            let attr = Ext4CreateAttr::new(applied, uid, gid, now);
            let created = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.create_file(dev, parent_ino, &leaf, attr)
            })?;
            (mount_id, created.ino, false, abs_path)
        }
        ResolvedPath::Virtual { .. } | ResolvedPath::Initramfs { .. } => return Err(Errno::ENOENT),
    };

    alloc_ext4_fd(process, mount_id, ino, is_dir, flags, abs_path)
}

fn translate_host_path_vec(abs_path: &[u8]) -> Result<Vec<u8>, Errno> {
    let mut out = vec![0u8; MAX_VFS_PATH];
    let len = super::step33_mounts::resolve_initramfs_host_path(abs_path, &mut out)
        .ok_or(Errno::ENOENT)?;
    out.truncate(len);
    Ok(out)
}

fn resolve_initramfs_for_dispatch(
    process: ObjectId,
    dirfd: i32,
    raw_dirfd: u64,
    raw: &[u8],
    abs_path: &[u8],
) -> Result<Option<Vec<u8>>, Errno> {
    let host = translate_host_path_vec(abs_path)?;
    if !proc_uses_custom_vfs(process)
        && (raw.starts_with(b"/")
            || dirfd == AT_FDCWD_I32
            || !is_ext4_fd_or_alias_current(raw_dirfd))
        && host.as_slice() == abs_path
    {
        return Ok(None);
    }
    Ok(Some(host))
}

pub(super) fn try_open_host_path(
    process: ObjectId,
    host_path: &[u8],
    flags: u64,
    mode: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if super::step33_mounts::resolve_ext4_mount(host_path).is_none() {
        return Ok(None);
    }
    let follow = (flags & O_NOFOLLOW) == 0 && ((flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL));
    match resolve_path(process, AT_FDCWD_I32, host_path, follow) {
        Ok(
            target @ (ResolvedPath::Ext4Existing { .. } | ResolvedPath::Ext4MissingParent { .. }),
        ) => Ok(Some(encode_result(open_ext4_target(
            process, target, flags, mode,
        )))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_open_virtual_abs(process, &abs_path, flags, mode)?,
        )),
        Ok(_) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

pub(super) fn try_readlink_host_path(
    host_path: &[u8],
    user_buf: u64,
    raw_bufsiz: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if super::step33_mounts::resolve_ext4_mount(host_path).is_none() {
        return Ok(None);
    }
    let process = current_process_id()?;
    match resolve_path(process, AT_FDCWD_I32, host_path, false) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => Ok(Some(encode_result(
            readlink_ext4_inode(mount_id, stat.ino, user_buf, raw_bufsiz),
        ))),
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            Ok(Some(super::step33_mounts::try_readlink_virtual_abs(
                process, &abs_path, user_buf, raw_bufsiz,
            )?))
        }
        Ok(_) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

pub(super) fn ext4_path_exists(raw_path: &[u8]) -> bool {
    let Ok(process) = current_process_id() else {
        return false;
    };
    matches!(
        resolve_path(process, AT_FDCWD_I32, raw_path, true),
        Ok(ResolvedPath::Ext4Existing { .. })
    )
}

pub(super) fn try_stat_host_path(
    host_path: &[u8],
    user_statbuf: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if super::step33_mounts::resolve_ext4_mount(host_path).is_none() {
        return Ok(None);
    }
    let process = current_process_id()?;
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    match resolve_path(process, AT_FDCWD_I32, host_path, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            let meta = stat_to_meta(mount_id, &stat);
            Ok(Some(encode_result(write_aarch64_stat_meta(
                user_statbuf,
                &meta,
            ))))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_stat_virtual_abs(process, &abs_path, flags, user_statbuf)?,
        )),
        Ok(_) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

pub(super) fn try_statx_host_path(
    host_path: &[u8],
    user_statx: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if super::step33_mounts::resolve_ext4_mount(host_path).is_none() {
        return Ok(None);
    }
    let process = current_process_id()?;
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    match resolve_path(process, AT_FDCWD_I32, host_path, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            let meta = stat_to_meta(mount_id, &stat);
            Ok(Some(encode_result(write_aarch64_statx_meta(
                user_statx, &meta,
            ))))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_statx_virtual_abs(process, &abs_path, flags, user_statx)?,
        )),
        Ok(_) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

pub(super) fn try_name_to_handle_host_path(
    process: ObjectId,
    host_path: &[u8],
    user_handle: u64,
    user_mnt_id: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if super::step33_mounts::resolve_ext4_mount(host_path).is_none() {
        return Ok(None);
    }
    let follow = (flags & AT_SYMLINK_FOLLOW) != 0;
    match resolve_path(process, AT_FDCWD_I32, host_path, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            Ok(Some(encode_result(write_linux_file_handle(
                user_handle,
                user_mnt_id,
                u64::from(stat.ino),
                super::step33_mounts::ext4_table_mount_id(mount_id),
            ))))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            Ok(Some(super::step33_mounts::try_name_to_handle_virtual_abs(
                process,
                &abs_path,
                user_handle,
                user_mnt_id,
                flags,
            )?))
        }
        Ok(_) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

pub(super) fn try_access_host_path(
    process: ObjectId,
    host_path: &[u8],
    mode: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if super::step33_mounts::resolve_ext4_mount(host_path).is_none() {
        return Ok(None);
    }
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    match resolve_path(process, AT_FDCWD_I32, host_path, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => Ok(Some(encode_result(
            check_ext4_access(mount_id, &stat, mode),
        ))),
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_access_virtual_abs(process, &abs_path, mode, flags)?,
        )),
        Ok(_) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn check_ext4_access(mount_id: u32, stat: &Ext4InodeStat, mode: u64) -> Result<i64, Errno> {
    if (mode & !0x7) != 0 {
        return Err(Errno::EINVAL);
    }
    let want_r = (mode & 4) != 0;
    let want_w = (mode & 2) != 0;
    let want_x = (mode & 1) != 0;
    if want_w {
        let ro =
            super::step33_mounts::with_ext4_volume(mount_id, |vol, _, _| Ok(vol.is_read_only()))?;
        if ro {
            return Err(Errno::EROFS);
        }
    }
    let (euid, egid) = current_uid_gid();
    if euid == 0 {
        if want_x && stat.is_reg() && (stat.mode & 0o111) == 0 {
            return Err(Errno::EACCES);
        }
        return Ok(0);
    }
    let perm = if euid == stat.uid {
        (stat.mode >> 6) & 0o7
    } else if egid == stat.gid || super::step30_runtime::current_in_group(stat.gid) {
        (stat.mode >> 3) & 0o7
    } else {
        stat.mode & 0o7
    };
    if (want_r && (perm & 4) == 0) || (want_w && (perm & 2) == 0) || (want_x && (perm & 1) == 0) {
        return Err(Errno::EACCES);
    }
    Ok(0)
}

fn readlink_ext4_inode(
    mount_id: u32,
    ino: u32,
    user_buf: u64,
    raw_bufsiz: u64,
) -> Result<i64, Errno> {
    let bufsiz = raw_bufsiz as i64;
    if bufsiz <= 0 {
        return Err(Errno::EINVAL);
    }
    if user_buf == 0 {
        return Err(Errno::EFAULT);
    }
    let target =
        super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| vol.read_symlink(dev, ino))?;
    let take = target.len().min(bufsiz as usize);
    if take > 0 {
        copy_to_user(user_buf, &target[..take])?;
    }
    Ok(take as i64)
}

pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        // getcwd(buf, size)
        17 => handle_getcwd(request.args[0], request.args[1]),
        // ioctl(fd, request, arg) on ext4 FD
        29 if is_ext4_fd_or_alias_current(request.args[0]) => {
            Ok(Some(SyscallReturn::error(Errno::ENOTTY)))
        }
        // mknodat(dirfd, pathname, mode, dev)
        33 => handle_mknodat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // mkdirat(dirfd, pathname, mode)
        34 => handle_mkdirat(request.args[0], request.args[1], request.args[2]),
        // unlinkat(dirfd, pathname, flags)
        35 => handle_unlinkat(request.args[0], request.args[1], request.args[2]),
        // symlinkat(target, newdirfd, linkpath)
        36 => handle_symlinkat(request.args[0], request.args[1], request.args[2]),
        // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        37 => handle_linkat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // renameat(olddirfd, oldpath, newdirfd, newpath)
        38 => handle_renameat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            0,
        ),
        // truncate(path, length)
        45 => handle_truncate(request.args[0], request.args[1] as i64),
        // ftruncate(fd, length)
        46 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(
            handle_ftruncate(request.args[0], request.args[1] as i64)?,
        ))),
        // faccessat(dirfd, pathname, mode)
        48 => handle_faccessat(request.args[0], request.args[1], request.args[2], 0),
        // chdir(path)
        49 => handle_chdir(request.args[0]),
        // fchdir(fd)
        50 => handle_fchdir(request.args[0]),
        // chroot(path)
        51 => Ok(Some(encode_result(handle_chroot(request.args[0])?))),
        // fchmod(fd, mode)
        52 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(
            handle_fchmod(request.args[0], request.args[1])?,
        ))),
        // fchmodat(dirfd, pathname, mode) -- 3-arg Linux ABI; flags added in fchmodat2 (452).
        53 => handle_fchmodat(request.args[0], request.args[1], request.args[2], 0),
        // fchownat(dirfd, pathname, owner, group, flags)
        54 => handle_fchownat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // fchown(fd, owner, group)
        55 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(
            handle_fchown(request.args[0], request.args[1], request.args[2])?,
        ))),
        // openat(dirfd, pathname, flags, mode)
        56 => handle_openat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // close(fd) for native EXT4_FD_BASE window (aliases released by step29_fd)
        57 if is_ext4_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close_native(request.args[0])?)))
        }
        // getdents64(fd, dirp, count)
        61 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(
            handle_getdents64(request.args[0], request.args[1], request.args[2])?,
        ))),
        // lseek(fd, offset, whence)
        62 if is_ext4_fd_or_alias_current(request.args[0]) => {
            Ok(Some(encode_result(handle_lseek(
                request.args[0],
                request.args[1] as i64,
                linux_signed_int(request.args[2]),
            )?)))
        }
        // read(fd, buf, count)
        63 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
            None,
        )?))),
        // write(fd, buf, count)
        64 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(
            handle_write(request.args[0], request.args[1], request.args[2], None)?,
        ))),
        // readv(fd, iov, iovcnt)
        65 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(
            handle_readv(request.args[0], request.args[1], request.args[2], None)?,
        ))),
        // writev(fd, iov, iovcnt)
        66 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(
            handle_writev(request.args[0], request.args[1], request.args[2], None)?,
        ))),
        // pread64(fd, buf, count, offset)
        67 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
            Some(request.args[3] as i64),
        )?))),
        // pwrite64(fd, buf, count, offset)
        68 if is_ext4_fd_or_alias_current(request.args[0]) => {
            Ok(Some(encode_result(handle_write(
                request.args[0],
                request.args[1],
                request.args[2],
                Some(request.args[3] as i64),
            )?)))
        }
        // sendfile(out_fd, in_fd, offset, count)
        71 if is_ext4_fd_or_alias_current(request.args[0])
            || is_ext4_fd_or_alias_current(request.args[1]) =>
        {
            Ok(Some(encode_result(handle_sendfile(
                request.args[0],
                request.args[1],
                request.args[2],
                request.args[3],
            )?)))
        }
        // readlinkat(dirfd, pathname, buf, bufsiz)
        78 => handle_readlinkat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // newfstatat(dirfd, pathname, statbuf, flags)
        79 => handle_newfstatat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // fstat(fd, statbuf)
        80 if is_ext4_fd_or_alias_current(request.args[0]) => Ok(Some(encode_result(
            handle_fstat(request.args[0], request.args[1])?,
        ))),
        // utimensat(dirfd, pathname, times, flags)
        88 => handle_utimensat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // name_to_handle_at(dirfd, pathname, handle, mount_id, flags)
        264 => handle_name_to_handle_at(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        276 => handle_renameat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
        285 if is_ext4_fd_or_alias_current(request.args[0])
            || is_ext4_fd_or_alias_current(request.args[2]) =>
        {
            Ok(Some(encode_result(handle_copy_file_range(
                request.args[0],
                request.args[1],
                request.args[2],
                request.args[3],
                request.args[4],
                request.args[5],
            )?)))
        }
        // statx(dirfd, pathname, flags, mask, statxbuf)
        291 => handle_statx(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ),
        // openat2(dirfd, pathname, how, size)
        437 => handle_openat2(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // faccessat2(dirfd, pathname, mode, flags)
        439 => handle_faccessat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        // fchmodat2(dirfd, pathname, mode, flags)
        452 => handle_fchmodat(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        _ => Ok(None),
    }
}

fn read_user_path_opt_empty(user_path: u64) -> Result<Vec<u8>, Errno> {
    let mut buf = vec![0u8; MAX_VFS_PATH];
    let len = read_user_cstr(user_path, &mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

fn copy_from_user_chunked(dst: &mut [u8], user_src: u64) -> Result<(), Errno> {
    let mut off = 0usize;
    while off < dst.len() {
        let chunk = (dst.len() - off).min(MAX_USERCOPY_BYTES);
        let addr = user_src.checked_add(off as u64).ok_or(Errno::EFAULT)?;
        copy_from_user(&mut dst[off..off + chunk], addr)?;
        off += chunk;
    }
    Ok(())
}

fn copy_to_user_chunked(user_dst: u64, src: &[u8]) -> Result<(), Errno> {
    let mut off = 0usize;
    while off < src.len() {
        let chunk = (src.len() - off).min(MAX_USERCOPY_BYTES);
        let addr = user_dst.checked_add(off as u64).ok_or(Errno::EFAULT)?;
        copy_to_user(addr, &src[off..off + chunk])?;
        off += chunk;
    }
    Ok(())
}

fn needs_ext4_path_interception(process: ObjectId, raw_dirfd: u64, raw_path: &[u8]) -> bool {
    if super::step33_mounts::has_live_ext4_mounts() {
        return true;
    }
    if proc_uses_custom_vfs(process) {
        return true;
    }
    if !raw_path.starts_with(b"/") && is_ext4_fd_or_alias_current(raw_dirfd) {
        return true;
    }
    false
}

fn handle_getcwd(user_buf: u64, raw_size: u64) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    if !proc_uses_custom_vfs(process) {
        return Ok(None);
    }
    if user_buf == 0 {
        return Ok(Some(SyscallReturn::error(Errno::EFAULT)));
    }
    let size = usize::try_from(raw_size).unwrap_or(usize::MAX);
    let (root, cwd, _) = match get_proc_root_and_cwd(process) {
        Ok(v) => v,
        Err(e) => return Ok(Some(SyscallReturn::error(e))),
    };
    let visible = strip_chroot_prefix(&cwd, &root);
    let required = visible.len() + 1;
    if size < required {
        return Ok(Some(SyscallReturn::error(Errno::ERANGE)));
    }
    let mut out = Vec::with_capacity(required);
    out.extend_from_slice(&visible);
    out.push(0);
    if let Err(e) = copy_to_user(user_buf, &out) {
        return Ok(Some(SyscallReturn::error(e)));
    }
    Ok(Some(encode_result(Ok(required as i64))))
}

fn handle_chdir(user_path: u64) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    if !super::step33_mounts::has_live_ext4_mounts() && !proc_uses_custom_vfs(process) {
        return Ok(None);
    }
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => return Ok(Some(SyscallReturn::error(e))),
    };
    match resolve_path(process, AT_FDCWD_I32, &raw, true) {
        Ok(ResolvedPath::Ext4Existing {
            mount_id,
            abs_path,
            stat,
            ..
        }) => {
            if !stat.is_dir() {
                return Ok(Some(SyscallReturn::error(Errno::ENOTDIR)));
            }
            let _ = with_vfs_state(|state| {
                if let Some(p) = state.ensure_proc_mut(process) {
                    copy_into_path_buf(&mut p.cwd, &mut p.cwd_len, &abs_path);
                    p.cwd_on_ext4 = true;
                    p.cwd_mount_id = mount_id;
                    p.cwd_ino = stat.ino;
                }
            });
            Ok(Some(encode_result(Ok(0))))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            match super::step33_mounts::is_virtual_dir(process, &abs_path) {
                Ok(true) => {
                    let _ = with_vfs_state(|state| {
                        if let Some(p) = state.ensure_proc_mut(process) {
                            copy_into_path_buf(&mut p.cwd, &mut p.cwd_len, &abs_path);
                            p.cwd_on_ext4 = true;
                            p.cwd_mount_id = 0;
                            p.cwd_ino = 0;
                        }
                    });
                    Ok(Some(encode_result(Ok(0))))
                }
                Ok(false) => Ok(Some(SyscallReturn::error(Errno::ENOTDIR))),
                Err(e) => Ok(Some(SyscallReturn::error(e))),
            }
        }
        Ok(ResolvedPath::Initramfs { abs_path }) => {
            let Ok(host_path) = translate_host_path_vec(&abs_path) else {
                return Ok(Some(SyscallReturn::error(Errno::ENOENT)));
            };
            let res = super::step29_fd::chdir_host_path(process, &host_path)?;
            if res.is_ok() {
                let _ = with_vfs_state(|state| {
                    if let Some(p) = state.ensure_proc_mut(process) {
                        copy_into_path_buf(&mut p.cwd, &mut p.cwd_len, &abs_path);
                        p.cwd_on_ext4 = false;
                        p.cwd_mount_id = 0;
                        p.cwd_ino = 0;
                    }
                });
            }
            Ok(Some(encode_result(res)))
        }
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_fchdir(raw_fd: u64) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    if let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) {
        let info = with_vfs_state(|state| {
            let entry = state.fds.get(idx).ok_or(Errno::EBADF)?;
            if !entry_matches(entry, process, idx, alias_gen) {
                return Err(Errno::EBADF);
            }
            if !entry.is_dir {
                return Err(Errno::ENOTDIR);
            }
            let mount_id = entry.mount_id;
            let ino = entry.ino;
            let abs_path = entry.abs_path.clone();
            if let Some(p) = state.ensure_proc_mut(process) {
                copy_into_path_buf(&mut p.cwd, &mut p.cwd_len, &abs_path);
                p.cwd_on_ext4 = true;
                p.cwd_mount_id = mount_id;
                p.cwd_ino = ino;
            }
            Ok(0i64)
        });
        return Ok(Some(encode_result(info.unwrap_or(Err(Errno::EIO)))));
    }
    if let Some(virt_res) = super::step33_mounts::fd_dir_abs_path(process, raw_fd) {
        return Ok(Some(encode_result(match virt_res {
            Ok(abs_path) => {
                let _ = with_vfs_state(|state| {
                    if let Some(p) = state.ensure_proc_mut(process) {
                        copy_into_path_buf(&mut p.cwd, &mut p.cwd_len, &abs_path);
                        p.cwd_on_ext4 = true;
                        p.cwd_mount_id = 0;
                        p.cwd_ino = 0;
                    }
                });
                Ok(0)
            }
            Err(e) => Err(e),
        })));
    }
    if !proc_uses_custom_vfs(process) {
        return Ok(None);
    }
    let res = super::step29_fd::fchdir_host(process, raw_fd)?;
    if res.is_ok() {
        let init_cwd =
            super::step29_fd::initramfs_cwd_bytes(process).unwrap_or_else(|_| vec![b'/']);
        let _ = with_vfs_state(|state| {
            if let Some(p) = state.ensure_proc_mut(process) {
                copy_into_path_buf(&mut p.cwd, &mut p.cwd_len, &init_cwd);
                p.cwd_on_ext4 = false;
                p.cwd_mount_id = 0;
                p.cwd_ino = 0;
            }
        });
    }
    Ok(Some(encode_result(res)))
}

fn handle_chroot(user_path: u64) -> Result<Result<i64, Errno>, ()> {
    if let Err(e) = super::step33_mounts::require_root_admin() {
        return Ok(Err(e));
    }
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => return Ok(Err(e)),
    };
    let resolved_root = match resolve_path(process, AT_FDCWD_I32, &raw, true) {
        Ok(ResolvedPath::Ext4Existing { abs_path, stat, .. }) => {
            if !stat.is_dir() {
                return Ok(Err(Errno::ENOTDIR));
            }
            abs_path
        }
        Ok(ResolvedPath::Initramfs { abs_path }) => {
            let Ok(host_path) = translate_host_path_vec(&abs_path) else {
                return Ok(Err(Errno::ENOENT));
            };
            match super::step29_fd::inspect_initramfs_path(process, &host_path) {
                Ok(Some((true, _))) => abs_path,
                Ok(Some((false, _))) => return Ok(Err(Errno::ENOTDIR)),
                Ok(None) => return Ok(Err(Errno::ENOENT)),
                Err(e) => return Ok(Err(e)),
            }
        }
        Ok(ResolvedPath::Virtual { abs_path }) => abs_path,
        Ok(ResolvedPath::Ext4MissingParent { .. }) => return Ok(Err(Errno::ENOENT)),
        Err(e) => return Ok(Err(e)),
    };
    let res = with_vfs_state(|state| {
        if let Some(p) = state.ensure_proc_mut(process) {
            copy_into_path_buf(&mut p.root, &mut p.root_len, &resolved_root);
            Ok(0)
        } else {
            Err(Errno::ENOMEM)
        }
    })?;
    Ok(res)
}

fn handle_openat(
    raw_dirfd: u64,
    user_path: u64,
    flags: u64,
    mode: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    let dirfd = linux_signed_int(raw_dirfd);
    let follow = (flags & O_NOFOLLOW) == 0 && ((flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL));
    match resolve_path(process, dirfd, &raw, follow) {
        Ok(
            target @ (ResolvedPath::Ext4Existing { .. } | ResolvedPath::Ext4MissingParent { .. }),
        ) => Ok(Some(encode_result(open_ext4_target(
            process, target, flags, mode,
        )))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            if abs_path.starts_with(b"/dev/")
                && let Some(ret) = super::step32_dev::try_open_dev_bytes(&abs_path, flags)?
            {
                return Ok(Some(ret));
            }
            if !raw.starts_with(b"/") || proc_uses_custom_vfs(process) {
                if let Some(hw) =
                    super::step42_hardware::try_open_dev_bytes_if_block(&abs_path, flags)?
                {
                    return Ok(Some(hw));
                }
            }
            Ok(Some(super::step33_mounts::try_open_virtual_abs(
                process, &abs_path, flags, mode,
            )?))
        }
        Ok(ResolvedPath::Initramfs { abs_path }) => {
            let host_path =
                match resolve_initramfs_for_dispatch(process, dirfd, raw_dirfd, &raw, &abs_path) {
                    Ok(Some(path)) => path,
                    Ok(None) => return Ok(None),
                    Err(e) => return Ok(Some(SyscallReturn::error(e))),
                };
            Ok(Some(encode_result(super::step29_fd::openat_host_path(
                process, &host_path, flags, mode,
            )?)))
        }
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_openat2(
    raw_dirfd: u64,
    user_path: u64,
    user_how: u64,
    raw_size: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let size = usize::try_from(raw_size).unwrap_or(usize::MAX);
    if size < 24 || size > 4096 {
        return Ok(None);
    }
    if user_how == 0 {
        return Ok(Some(SyscallReturn::error(Errno::EFAULT)));
    }
    let mut how_buf = [0u8; 24];
    if let Err(e) = copy_from_user(&mut how_buf, user_how) {
        return Ok(Some(SyscallReturn::error(e)));
    }
    let flags = u64::from_le_bytes(how_buf[0..8].try_into().unwrap_or([0; 8]));
    let mode = u64::from_le_bytes(how_buf[8..16].try_into().unwrap_or([0; 8]));
    let resolve = u64::from_le_bytes(how_buf[16..24].try_into().unwrap_or([0; 8]));
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    if (resolve & 0x20) != 0 && (raw.starts_with(b"/") || raw.contains(&b'.')) {
        // Simple check when RESOLVE_CACHED (0x20) is unsupported/rejected cleanly.
    }
    let follow = (flags & O_NOFOLLOW) == 0 && (resolve & 0x04) == 0;
    let dirfd = linux_signed_int(raw_dirfd);
    match resolve_path(process, dirfd, &raw, follow) {
        Ok(
            target @ (ResolvedPath::Ext4Existing { .. } | ResolvedPath::Ext4MissingParent { .. }),
        ) => Ok(Some(encode_result(open_ext4_target(
            process, target, flags, mode,
        )))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_open_virtual_abs(process, &abs_path, flags, mode)?,
        )),
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_close_native(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_id()?;
    let idx = (linux_signed_int(raw_fd) - EXT4_FD_BASE) as usize;
    let mut closed_info = None;
    let mut retired = None;
    let res = with_vfs_state(|state| {
        let Some(entry) = state.fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        let (mount_id, ino) = (entry.mount_id, entry.ino);
        if !entry.live || !entry.owners.close_owner(process) {
            return Err(Errno::EBADF);
        }
        closed_info = Some((mount_id, ino));
        retired = retire_slot_if_unused(state, idx);
        Ok(0)
    })?;
    if let Some((mount_id, ino)) = closed_info {
        super::step39_dpkg::on_close_ext4_fd(mount_id, ino, retired);
    }
    Ok(res)
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let (mount_id, ino, is_dir, is_path_only, cur_off) = match with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok((
            entry.mount_id,
            entry.ino,
            entry.is_dir,
            entry.is_path_only,
            entry.offset,
        ))
    })? {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    if is_path_only {
        return Ok(Err(Errno::EBADF));
    }
    let end_val: u64 = if whence == SEEK_END {
        if is_dir {
            match super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.readdir(dev, ino)
            }) {
                Ok(entries) => entries.len() as u64,
                Err(e) => return Ok(Err(e)),
            }
        } else {
            match super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.stat_inode(dev, ino)
            }) {
                Ok(st) => st.size,
                Err(e) => return Ok(Err(e)),
            }
        }
    } else {
        0
    };
    let next: i64 = match whence {
        SEEK_SET => offset,
        SEEK_CUR => match (cur_off as i64).checked_add(offset) {
            Some(v) => v,
            None => return Ok(Err(Errno::EINVAL)),
        },
        SEEK_END => match (end_val as i64).checked_add(offset) {
            Some(v) => v,
            None => return Ok(Err(Errno::EINVAL)),
        },
        _ => return Ok(Err(Errno::EINVAL)),
    };
    if next < 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let _ = with_vfs_state(|state| {
        if let Some(entry) = state.fds.get_mut(idx)
            && entry_matches(entry, process, idx, alias_gen)
        {
            entry.offset = next as u64;
        }
    });
    Ok(Ok(next))
}

fn handle_read(
    raw_fd: u64,
    user_buf: u64,
    raw_count: u64,
    explicit_off: Option<i64>,
) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let (mount_id, ino, is_dir, readable, cur_off) = match with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok((
            entry.mount_id,
            entry.ino,
            entry.is_dir,
            entry.readable,
            entry.offset,
        ))
    })? {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    if !readable {
        return Ok(Err(Errno::EBADF));
    }
    if is_dir {
        return Ok(Err(Errno::EISDIR));
    }
    let read_off = match explicit_off {
        Some(v) if v < 0 => return Ok(Err(Errno::EINVAL)),
        Some(v) => v as u64,
        None => cur_off,
    };
    let count = usize::try_from(raw_count)
        .unwrap_or(usize::MAX)
        .min(MAX_EXT4_RW_BYTES);
    if count == 0 {
        return Ok(Ok(0));
    }
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut kbuf = vec![0u8; count];
    let n = match super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
        vol.read_file(dev, ino, read_off, &mut kbuf)
    }) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    if n > 0
        && let Err(e) = copy_to_user_chunked(user_buf, &kbuf[..n])
    {
        return Ok(Err(e));
    }
    if explicit_off.is_none() && n > 0 {
        let _ = with_vfs_state(|state| {
            if let Some(entry) = state.fds.get_mut(idx)
                && entry_matches(entry, process, idx, alias_gen)
            {
                entry.offset = read_off.saturating_add(n as u64);
            }
        });
    }
    Ok(Ok(n as i64))
}

fn handle_readv(
    raw_fd: u64,
    user_iov: u64,
    raw_iovcnt: u64,
    explicit_off: Option<i64>,
) -> Result<Result<i64, Errno>, ()> {
    let iovcnt = linux_signed_int(raw_iovcnt);
    if iovcnt < 0 || iovcnt > 1024 {
        return Ok(Err(Errno::EINVAL));
    }
    let mut total: usize = 0;
    for i in 0..(iovcnt as usize) {
        let (base, len) = match read_user_iovec(user_iov, i) {
            Ok(pair) => pair,
            Err(e) => return Ok(if total > 0 { Ok(total as i64) } else { Err(e) }),
        };
        if len == 0 {
            continue;
        }
        let off = explicit_off.map(|o| o.saturating_add(total as i64));
        match handle_read(raw_fd, base, len as u64, off)? {
            Ok(0) => break,
            Ok(n) => {
                total += n as usize;
                if (n as usize) < len {
                    break;
                }
            }
            Err(e) => return Ok(if total > 0 { Ok(total as i64) } else { Err(e) }),
        }
    }
    Ok(Ok(total as i64))
}

fn handle_write(
    raw_fd: u64,
    user_buf: u64,
    raw_count: u64,
    explicit_off: Option<i64>,
) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let (mount_id, ino, is_dir, writable, append, cur_off) = match with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok((
            entry.mount_id,
            entry.ino,
            entry.is_dir,
            entry.writable,
            entry.append,
            entry.offset,
        ))
    })? {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    if !writable {
        return Ok(Err(Errno::EBADF));
    }
    if is_dir {
        return Ok(Err(Errno::EISDIR));
    }
    if let Some(v) = explicit_off
        && v < 0
    {
        return Ok(Err(Errno::EINVAL));
    }
    let count = usize::try_from(raw_count)
        .unwrap_or(usize::MAX)
        .min(MAX_EXT4_RW_BYTES);
    if count == 0 {
        return Ok(Ok(0));
    }
    if user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut kbuf = vec![0u8; count];
    if let Err(e) = copy_from_user_chunked(&mut kbuf, user_buf) {
        return Ok(Err(e));
    }
    let now = current_epoch_now_secs();
    let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
        let write_off = if let Some(off) = explicit_off {
            off as u64
        } else if append {
            vol.stat_inode(dev, ino)?.size
        } else {
            cur_off
        };
        let n = vol.write_file(dev, ino, write_off, &kbuf, now)?;
        Ok((n, write_off.saturating_add(n as u64)))
    });
    match res {
        Ok((n, next_off)) => {
            if explicit_off.is_none() {
                let _ = with_vfs_state(|state| {
                    if let Some(entry) = state.fds.get_mut(idx)
                        && entry_matches(entry, process, idx, alias_gen)
                    {
                        entry.offset = next_off;
                    }
                });
            }
            Ok(Ok(n as i64))
        }
        Err(e) => Ok(Err(e)),
    }
}

fn handle_writev(
    raw_fd: u64,
    user_iov: u64,
    raw_iovcnt: u64,
    explicit_off: Option<i64>,
) -> Result<Result<i64, Errno>, ()> {
    let iovcnt = linux_signed_int(raw_iovcnt);
    if iovcnt < 0 || iovcnt > 1024 {
        return Ok(Err(Errno::EINVAL));
    }
    let mut total: usize = 0;
    for i in 0..(iovcnt as usize) {
        let (base, len) = match read_user_iovec(user_iov, i) {
            Ok(pair) => pair,
            Err(e) => return Ok(if total > 0 { Ok(total as i64) } else { Err(e) }),
        };
        if len == 0 {
            continue;
        }
        let off = explicit_off.map(|o| o.saturating_add(total as i64));
        match handle_write(raw_fd, base, len as u64, off)? {
            Ok(n) => {
                total += n as usize;
                if (n as usize) < len {
                    break;
                }
            }
            Err(e) => return Ok(if total > 0 { Ok(total as i64) } else { Err(e) }),
        }
    }
    Ok(Ok(total as i64))
}

fn handle_getdents64(
    raw_fd: u64,
    user_dirp: u64,
    raw_count: u64,
) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let (mount_id, ino, is_dir, is_path_only, start_idx) = match with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok((
            entry.mount_id,
            entry.ino,
            entry.is_dir,
            entry.is_path_only,
            entry.offset as usize,
        ))
    })? {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    if is_path_only {
        return Ok(Err(Errno::EBADF));
    }
    if !is_dir {
        return Ok(Err(Errno::ENOTDIR));
    }
    let count = usize::try_from(raw_count)
        .unwrap_or(usize::MAX)
        .min(MAX_USERCOPY_BYTES);
    if count < 24 {
        return Ok(Err(Errno::EINVAL));
    }
    if user_dirp == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let entries =
        match super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| vol.readdir(dev, ino))
        {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
    let mut out = Vec::with_capacity(count.min(4096));
    let mut next_idx = start_idx;
    for (ent_i, ent) in entries.iter().enumerate().skip(start_idx) {
        let reclen = (19 + ent.name.len() + 1 + 7) & !7;
        if out.len() + reclen > count {
            if out.is_empty() {
                return Ok(Err(Errno::EINVAL));
            }
            break;
        }
        let d_off = (ent_i + 1) as i64;
        out.extend_from_slice(&u64::from(ent.ino).to_le_bytes());
        out.extend_from_slice(&d_off.to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(ext4_ft_to_dt(ent.file_type));
        out.extend_from_slice(&ent.name);
        out.push(0);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        next_idx = ent_i + 1;
    }
    if !out.is_empty()
        && let Err(e) = copy_to_user(user_dirp, &out)
    {
        return Ok(Err(e));
    }
    let _ = with_vfs_state(|state| {
        if let Some(entry) = state.fds.get_mut(idx)
            && entry_matches(entry, process, idx, alias_gen)
        {
            entry.offset = next_idx as u64;
        }
    });
    Ok(Ok(out.len() as i64))
}

fn handle_fstat(raw_fd: u64, user_stat: u64) -> Result<Result<i64, Errno>, ()> {
    if user_stat == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let process = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let (mount_id, ino) = match with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok((entry.mount_id, entry.ino))
    })? {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    let stat = match super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
        vol.stat_inode(dev, ino)
    }) {
        Ok(s) => s,
        Err(e) => return Ok(Err(e)),
    };
    let meta = stat_to_meta(mount_id, &stat);
    Ok(write_aarch64_stat_meta(user_stat, &meta))
}

fn handle_newfstatat(
    raw_dirfd: u64,
    user_path: u64,
    user_stat: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if (flags & AT_EMPTY_PATH) != 0
                && user_path == 0
                && is_ext4_fd_or_alias_current(raw_dirfd)
            {
                return Ok(Some(encode_result(handle_fstat(raw_dirfd, user_stat)?)));
            }
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if raw.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        if is_ext4_fd_or_alias_current(raw_dirfd) {
            return Ok(Some(encode_result(handle_fstat(raw_dirfd, user_stat)?)));
        }
        return Ok(None);
    }
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    if user_stat == 0 {
        return Ok(Some(SyscallReturn::error(Errno::EFAULT)));
    }
    let dirfd = linux_signed_int(raw_dirfd);
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    match resolve_path(process, dirfd, &raw, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            let meta = stat_to_meta(mount_id, &stat);
            Ok(Some(encode_result(write_aarch64_stat_meta(
                user_stat, &meta,
            ))))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            if abs_path.starts_with(b"/dev/")
                && let Some(ret) = super::step32_dev::try_stat_dev_bytes(&abs_path, user_stat)?
            {
                return Ok(Some(ret));
            }
            Ok(Some(super::step33_mounts::try_stat_virtual_abs(
                process, &abs_path, flags, user_stat,
            )?))
        }
        Ok(ResolvedPath::Initramfs { abs_path }) => {
            let host_path =
                match resolve_initramfs_for_dispatch(process, dirfd, raw_dirfd, &raw, &abs_path) {
                    Ok(Some(path)) => path,
                    Ok(None) => return Ok(None),
                    Err(e) => return Ok(Some(SyscallReturn::error(e))),
                };
            Ok(Some(encode_result(super::step29_fd::newfstatat_host_path(
                process,
                &host_path,
                user_stat,
                linux_unsigned_int(flags),
            )?)))
        }
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_statx(
    raw_dirfd: u64,
    user_path: u64,
    flags: u64,
    _mask: u64,
    user_statx: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if raw.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_dirfd) else {
            return Ok(None);
        };
        if user_statx == 0 {
            return Ok(Some(SyscallReturn::error(Errno::EFAULT)));
        }
        let (mount_id, ino) = match with_vfs_state(|state| {
            let Some(entry) = state.fds.get(idx) else {
                return Err(Errno::EBADF);
            };
            if !entry_matches(entry, process, idx, alias_gen) {
                return Err(Errno::EBADF);
            }
            Ok((entry.mount_id, entry.ino))
        })? {
            Ok(v) => v,
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        };
        let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
            vol.stat_inode(dev, ino)
        })
        .and_then(|st| write_aarch64_statx_meta(user_statx, &stat_to_meta(mount_id, &st)));
        return Ok(Some(encode_result(res)));
    }
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    if user_statx == 0 {
        return Ok(Some(SyscallReturn::error(Errno::EFAULT)));
    }
    let dirfd = linux_signed_int(raw_dirfd);
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    match resolve_path(process, dirfd, &raw, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => Ok(Some(encode_result(
            write_aarch64_statx_meta(user_statx, &stat_to_meta(mount_id, &stat)),
        ))),
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            if abs_path.starts_with(b"/dev/")
                && let Some(ret) = super::step32_dev::try_statx_dev_bytes(&abs_path, user_statx)?
            {
                return Ok(Some(ret));
            }
            Ok(Some(super::step33_mounts::try_statx_virtual_abs(
                process, &abs_path, flags, user_statx,
            )?))
        }
        Ok(ResolvedPath::Initramfs { abs_path }) => {
            let host_path =
                match resolve_initramfs_for_dispatch(process, dirfd, raw_dirfd, &raw, &abs_path) {
                    Ok(Some(path)) => path,
                    Ok(None) => return Ok(None),
                    Err(e) => return Ok(Some(SyscallReturn::error(e))),
                };
            Ok(Some(encode_result(super::step29_fd::statx_host_path(
                process,
                &host_path,
                linux_unsigned_int(flags),
                user_statx,
            )?)))
        }
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_readlinkat(
    raw_dirfd: u64,
    user_path: u64,
    user_buf: u64,
    raw_bufsiz: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if raw.is_empty()
        && let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_dirfd)
    {
        let (mount_id, ino) = match with_vfs_state(|state| {
            let Some(entry) = state.fds.get(idx) else {
                return Err(Errno::EBADF);
            };
            if !entry_matches(entry, process, idx, alias_gen) {
                return Err(Errno::EBADF);
            }
            Ok((entry.mount_id, entry.ino))
        })? {
            Ok(v) => v,
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        };
        return Ok(Some(encode_result(readlink_ext4_inode(
            mount_id, ino, user_buf, raw_bufsiz,
        ))));
    }
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    let dirfd = linux_signed_int(raw_dirfd);
    match resolve_path(process, dirfd, &raw, false) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            if !stat.is_symlink() {
                return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
            }
            Ok(Some(encode_result(readlink_ext4_inode(
                mount_id, stat.ino, user_buf, raw_bufsiz,
            ))))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            Ok(Some(super::step33_mounts::try_readlink_virtual_abs(
                process, &abs_path, user_buf, raw_bufsiz,
            )?))
        }
        Ok(ResolvedPath::Initramfs { abs_path }) => {
            let host_path =
                match resolve_initramfs_for_dispatch(process, dirfd, raw_dirfd, &raw, &abs_path) {
                    Ok(Some(path)) => path,
                    Ok(None) => return Ok(None),
                    Err(e) => return Ok(Some(SyscallReturn::error(e))),
                };
            Ok(Some(encode_result(super::step29_fd::readlinkat_host_path(
                process, &host_path, user_buf, raw_bufsiz,
            )?)))
        }
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_faccessat(
    raw_dirfd: u64,
    user_path: u64,
    mode: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if (flags & !(AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH | AT_NO_AUTOMOUNT)) != 0 {
        return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
    }
    let process = current_process_id()?;
    let empty_flag = (flags & AT_EMPTY_PATH) != 0;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if empty_flag && user_path == 0 && is_ext4_fd_or_alias_current(raw_dirfd) {
                Vec::new()
            } else if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            } else {
                return Ok(Some(SyscallReturn::error(e)));
            }
        }
    };
    if raw.is_empty() && empty_flag {
        if !is_ext4_fd_or_alias_current(raw_dirfd) {
            return Ok(None);
        }
        let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_dirfd) else {
            return Ok(Some(SyscallReturn::error(Errno::EBADF)));
        };
        let (mount_id, ino) = match with_vfs_state(|state| {
            let Some(entry) = state.fds.get(idx) else {
                return Err(Errno::EBADF);
            };
            if !entry_matches(entry, process, idx, alias_gen) {
                return Err(Errno::EBADF);
            }
            Ok((entry.mount_id, entry.ino))
        })? {
            Ok(v) => v,
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        };
        let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
            let stat = vol.stat_inode(dev, ino)?;
            check_ext4_access(mount_id, &stat, mode)
        });
        return Ok(Some(encode_result(res)));
    }
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    let dirfd = linux_signed_int(raw_dirfd);
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    match resolve_path(process, dirfd, &raw, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => Ok(Some(encode_result(
            check_ext4_access(mount_id, &stat, mode),
        ))),
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_access_virtual_abs(process, &abs_path, mode, flags)?,
        )),
        Ok(ResolvedPath::Initramfs { abs_path }) => {
            let host_path =
                match resolve_initramfs_for_dispatch(process, dirfd, raw_dirfd, &raw, &abs_path) {
                    Ok(Some(path)) => path,
                    Ok(None) => return Ok(None),
                    Err(e) => return Ok(Some(SyscallReturn::error(e))),
                };
            Ok(Some(encode_result(super::step29_fd::faccessat_host_path(
                process, &host_path,
            )?)))
        }
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_mkdirat(
    raw_dirfd: u64,
    user_path: u64,
    raw_mode: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    let trimmed: Vec<u8> = if raw.len() > 1 && raw.ends_with(b"/") {
        let mut s = raw.as_slice();
        while s.len() > 1 && s.ends_with(b"/") {
            s = &s[..s.len() - 1];
        }
        s.to_vec()
    } else {
        raw.clone()
    };
    let dirfd = linux_signed_int(raw_dirfd);
    match resolve_path(process, dirfd, &trimmed, false) {
        Ok(ResolvedPath::Ext4Existing { .. }) => Ok(Some(SyscallReturn::error(Errno::EEXIST))),
        Ok(ResolvedPath::Ext4MissingParent {
            mount_id,
            parent_ino,
            leaf,
            ..
        }) => {
            let (uid, gid) = current_uid_gid();
            let now = current_epoch_now_secs();
            let applied = super::step29_fd::apply_umask_mode(process, linux_unsigned_int(raw_mode));
            let attr = Ext4CreateAttr::new(applied, uid, gid, now);
            let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.mkdir(dev, parent_ino, &leaf, attr).map(|_| 0i64)
            });
            Ok(Some(encode_result(res)))
        }
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_mkdir_virtual_abs(process, &abs_path, raw_mode)?,
        )),
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_mknodat(
    raw_dirfd: u64,
    user_path: u64,
    raw_mode: u64,
    raw_dev: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    let dirfd = linux_signed_int(raw_dirfd);
    match resolve_path(process, dirfd, &raw, false) {
        Ok(ResolvedPath::Ext4Existing { .. }) => Ok(Some(SyscallReturn::error(Errno::EEXIST))),
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::EPERM))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_mknod_virtual_abs(process, &abs_path, raw_mode, raw_dev)?,
        )),
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_unlinkat(
    raw_dirfd: u64,
    user_path: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    if (flags & !AT_REMOVEDIR) != 0 {
        return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
    }
    let dirfd = linux_signed_int(raw_dirfd);
    let trimmed: Vec<u8> = if raw.len() > 1 && raw.ends_with(b"/") && (flags & AT_REMOVEDIR) != 0 {
        let mut s = raw.as_slice();
        while s.len() > 1 && s.ends_with(b"/") {
            s = &s[..s.len() - 1];
        }
        s.to_vec()
    } else {
        raw
    };
    match resolve_path(process, dirfd, &trimmed, false) {
        Ok(ResolvedPath::Ext4Existing {
            mount_id,
            parent_ino,
            leaf,
            stat,
            ..
        }) => {
            if leaf.is_empty() {
                return Ok(Some(SyscallReturn::error(Errno::EBUSY)));
            }
            let now = current_epoch_now_secs();
            let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                if (flags & AT_REMOVEDIR) != 0 {
                    if !stat.is_dir() {
                        return Err(Errno::ENOTDIR);
                    }
                    vol.rmdir(dev, parent_ino, &leaf, now)?;
                } else {
                    if stat.is_dir() {
                        return Err(Errno::EISDIR);
                    }
                    vol.unlink(dev, parent_ino, &leaf, now)?;
                }
                Ok(0i64)
            });
            Ok(Some(encode_result(res)))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_unlink_virtual_abs(process, &abs_path, flags)?,
        )),
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_symlinkat(
    user_target: u64,
    raw_newdirfd: u64,
    user_linkpath: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let target = match read_user_path_opt_empty(user_target) {
        Ok(t) => t,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_newdirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    let linkpath = match read_user_path_opt_empty(user_linkpath) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_newdirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_newdirfd, &linkpath) {
        return Ok(None);
    }
    if target.is_empty() {
        return Ok(Some(SyscallReturn::error(Errno::ENOENT)));
    }
    let dirfd = linux_signed_int(raw_newdirfd);
    match resolve_path(process, dirfd, &linkpath, false) {
        Ok(ResolvedPath::Ext4Existing { .. }) => Ok(Some(SyscallReturn::error(Errno::EEXIST))),
        Ok(ResolvedPath::Ext4MissingParent {
            mount_id,
            parent_ino,
            leaf,
            ..
        }) => {
            let (uid, gid) = current_uid_gid();
            let now = current_epoch_now_secs();
            let attr = Ext4CreateAttr::new(S_IFLNK | 0o777, uid, gid, now);
            let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.symlink(dev, parent_ino, &leaf, &target, attr)
                    .map(|_| 0i64)
            });
            Ok(Some(encode_result(res)))
        }
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_symlink_virtual_abs(process, &target, &abs_path)?,
        )),
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_linkat(
    raw_olddirfd: u64,
    user_oldpath: u64,
    raw_newdirfd: u64,
    user_newpath: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let oldpath = match read_user_path_opt_empty(user_oldpath) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_olddirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    let newpath = match read_user_path_opt_empty(user_newpath) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_newdirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_olddirfd, &oldpath)
        && !needs_ext4_path_interception(process, raw_newdirfd, &newpath)
    {
        return Ok(None);
    }
    if (flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)) != 0 {
        return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
    }

    let (old_mount, old_ino, old_is_dir) = if oldpath.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_olddirfd) else {
            return Ok(None);
        };
        match with_vfs_state(|state| {
            let Some(entry) = state.fds.get(idx) else {
                return Err(Errno::EBADF);
            };
            if !entry_matches(entry, process, idx, alias_gen) {
                return Err(Errno::EBADF);
            }
            Ok((entry.mount_id, entry.ino, entry.is_dir))
        })? {
            Ok(v) => v,
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        }
    } else {
        let olddirfd = linux_signed_int(raw_olddirfd);
        let follow = (flags & AT_SYMLINK_FOLLOW) != 0;
        match resolve_path(process, olddirfd, &oldpath, follow) {
            Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
                (mount_id, stat.ino, stat.is_dir())
            }
            Ok(ResolvedPath::Ext4MissingParent { .. }) => {
                return Ok(Some(SyscallReturn::error(Errno::ENOENT)));
            }
            Ok(_) => return Ok(None),
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        }
    };

    if old_is_dir {
        return Ok(Some(SyscallReturn::error(Errno::EPERM)));
    }
    let newdirfd = linux_signed_int(raw_newdirfd);
    match resolve_path(process, newdirfd, &newpath, false) {
        Ok(ResolvedPath::Ext4Existing { .. }) => Ok(Some(SyscallReturn::error(Errno::EEXIST))),
        Ok(ResolvedPath::Ext4MissingParent {
            mount_id,
            parent_ino,
            leaf,
            ..
        }) => {
            if mount_id != old_mount {
                return Ok(Some(SyscallReturn::error(Errno::EXDEV)));
            }
            let now = current_epoch_now_secs();
            let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.link(dev, old_ino, parent_ino, &leaf, now)
                    .map(|()| 0i64)
            });
            Ok(Some(encode_result(res)))
        }
        Ok(_) => Ok(Some(SyscallReturn::error(Errno::EXDEV))),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_renameat(
    raw_olddirfd: u64,
    user_oldpath: u64,
    raw_newdirfd: u64,
    user_newpath: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let oldpath = match read_user_path_opt_empty(user_oldpath) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_olddirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    let newpath = match read_user_path_opt_empty(user_newpath) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_newdirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_olddirfd, &oldpath)
        && !needs_ext4_path_interception(process, raw_newdirfd, &newpath)
    {
        return Ok(None);
    }
    if (flags & !RENAME_NOREPLACE) != 0 {
        return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
    }
    let noreplace = (flags & RENAME_NOREPLACE) != 0;
    let old_trimmed = trim_trailing_slash_if_nonempty(&oldpath);
    let new_trimmed = trim_trailing_slash_if_nonempty(&newpath);

    let old_resolved =
        match resolve_path(process, linux_signed_int(raw_olddirfd), &old_trimmed, false) {
            Ok(v) => v,
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        };
    let new_resolved =
        match resolve_path(process, linux_signed_int(raw_newdirfd), &new_trimmed, false) {
            Ok(v) => v,
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        };
    if let (
        ResolvedPath::Virtual { abs_path: old_abs },
        ResolvedPath::Virtual { abs_path: new_abs },
    ) = (&old_resolved, &new_resolved)
    {
        return Ok(Some(super::step33_mounts::try_rename_virtual_abs(
            process, old_abs, new_abs, flags,
        )?));
    }
    let (old_mount, old_parent, old_leaf) = match old_resolved {
        ResolvedPath::Ext4Existing {
            mount_id,
            parent_ino,
            leaf,
            ..
        } => {
            if leaf.is_empty() {
                return Ok(Some(SyscallReturn::error(Errno::EBUSY)));
            }
            (mount_id, parent_ino, leaf)
        }
        ResolvedPath::Ext4MissingParent { .. } => {
            return Ok(Some(SyscallReturn::error(Errno::ENOENT)));
        }
        ResolvedPath::Virtual { .. } => return Ok(Some(SyscallReturn::error(Errno::EXDEV))),
        ResolvedPath::Initramfs { .. } => return Ok(None),
    };
    let (new_mount, new_parent, new_leaf) = match new_resolved {
        ResolvedPath::Ext4Existing {
            mount_id,
            parent_ino,
            leaf,
            ..
        }
        | ResolvedPath::Ext4MissingParent {
            mount_id,
            parent_ino,
            leaf,
            ..
        } => {
            if leaf.is_empty() {
                return Ok(Some(SyscallReturn::error(Errno::EBUSY)));
            }
            (mount_id, parent_ino, leaf)
        }
        _ => return Ok(Some(SyscallReturn::error(Errno::EXDEV))),
    };

    if old_mount != new_mount {
        return Ok(Some(SyscallReturn::error(Errno::EXDEV)));
    }
    let now = current_epoch_now_secs();
    let res = super::step33_mounts::with_ext4_volume(old_mount, |vol, dev, _| {
        vol.rename(
            dev, old_parent, &old_leaf, new_parent, &new_leaf, noreplace, now,
        )
        .map(|()| 0i64)
    });
    Ok(Some(encode_result(res)))
}

fn trim_trailing_slash_if_nonempty(raw: &[u8]) -> Vec<u8> {
    let mut s = raw;
    while s.len() > 1 && s.ends_with(b"/") {
        s = &s[..s.len() - 1];
    }
    s.to_vec()
}

fn handle_truncate(user_path: u64, length: i64) -> Result<Option<SyscallReturn>, ()> {
    if length < 0 {
        return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
    }
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => return Ok(Some(SyscallReturn::error(e))),
    };
    if !needs_ext4_path_interception(process, AT_FDCWD_I32 as u64, &raw) {
        return Ok(None);
    }
    match resolve_path(process, AT_FDCWD_I32, &raw, true) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            if stat.is_dir() {
                return Ok(Some(SyscallReturn::error(Errno::EISDIR)));
            }
            let now = current_epoch_now_secs();
            let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.truncate_inode(dev, stat.ino, length as u64, now)
                    .map(|()| 0i64)
            });
            Ok(Some(encode_result(res)))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_truncate_virtual_abs(process, &abs_path, length)?,
        )),
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_ftruncate(raw_fd: u64, length: i64) -> Result<Result<i64, Errno>, ()> {
    if length < 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let process = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let (mount_id, ino, writable, is_dir) = match with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok((entry.mount_id, entry.ino, entry.writable, entry.is_dir))
    })? {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    if !writable {
        return Ok(Err(Errno::EINVAL));
    }
    if is_dir {
        return Ok(Err(Errno::EISDIR));
    }
    let now = current_epoch_now_secs();
    Ok(super::step33_mounts::with_ext4_volume(
        mount_id,
        |vol, dev, _| {
            vol.truncate_inode(dev, ino, length as u64, now)
                .map(|()| 0i64)
        },
    ))
}

fn handle_fchmod(raw_fd: u64, raw_mode: u64) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let (mount_id, ino, is_path_only) = match with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok((entry.mount_id, entry.ino, entry.is_path_only))
    })? {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    if is_path_only {
        return Ok(Err(Errno::EBADF));
    }
    let now = current_epoch_now_secs();
    let mode_bits = (raw_mode & 0o7777) as u16;
    Ok(super::step33_mounts::with_ext4_volume(
        mount_id,
        |vol, dev, _| vol.chmod(dev, ino, mode_bits, now).map(|()| 0i64),
    ))
}

fn handle_fchmodat(
    raw_dirfd: u64,
    user_path: u64,
    raw_mode: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    if (flags & !AT_SYMLINK_NOFOLLOW) != 0 {
        return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
    }
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    match resolve_path(process, linux_signed_int(raw_dirfd), &raw, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            if stat.is_symlink() {
                return Ok(Some(SyscallReturn::error(Errno::EOPNOTSUPP)));
            }
            let now = current_epoch_now_secs();
            let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.chmod(dev, stat.ino, (raw_mode & 0o7777) as u16, now)
                    .map(|()| 0i64)
            });
            Ok(Some(encode_result(res)))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => Ok(Some(
            super::step33_mounts::try_chmod_virtual_abs(process, &abs_path, raw_mode, flags)?,
        )),
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_fchown(raw_fd: u64, raw_uid: u64, raw_gid: u64) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_id()?;
    let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let (mount_id, ino, is_path_only) = match with_vfs_state(|state| {
        let Some(entry) = state.fds.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(entry, process, idx, alias_gen) {
            return Err(Errno::EBADF);
        }
        Ok((entry.mount_id, entry.ino, entry.is_path_only))
    })? {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    if is_path_only {
        return Ok(Err(Errno::EBADF));
    }
    let now = current_epoch_now_secs();
    Ok(super::step33_mounts::with_ext4_volume(
        mount_id,
        |vol, dev, _| {
            vol.chown(
                dev,
                ino,
                decode_chown_id(raw_uid),
                decode_chown_id(raw_gid),
                now,
            )
            .map(|()| 0i64)
        },
    ))
}

fn handle_fchownat(
    raw_dirfd: u64,
    user_path: u64,
    raw_uid: u64,
    raw_gid: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    if (flags & AT_EMPTY_PATH) != 0 && is_ext4_fd_or_alias_current(raw_dirfd) {
        let is_empty = if user_path == 0 {
            true
        } else {
            read_user_path_opt_empty(user_path).is_ok_and(|p| p.is_empty())
        };
        if is_empty {
            return Ok(Some(encode_result(handle_fchown(
                raw_dirfd, raw_uid, raw_gid,
            )?)));
        }
    }
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    match resolve_path(process, linux_signed_int(raw_dirfd), &raw, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            let now = current_epoch_now_secs();
            let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.chown(
                    dev,
                    stat.ino,
                    decode_chown_id(raw_uid),
                    decode_chown_id(raw_gid),
                    now,
                )
                .map(|()| 0i64)
            });
            Ok(Some(encode_result(res)))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            Ok(Some(super::step33_mounts::try_chown_virtual_abs(
                process, &abs_path, raw_uid, raw_gid, flags,
            )?))
        }
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_utimensat(
    raw_dirfd: u64,
    user_path: u64,
    user_times: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let process = current_process_id()?;
    let now = current_epoch_now_secs();
    if user_path == 0 {
        if !is_ext4_fd_or_alias_current(raw_dirfd) {
            return Ok(None);
        }
        let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_dirfd) else {
            return Ok(Some(SyscallReturn::error(Errno::EBADF)));
        };
        let (mount_id, ino) = match with_vfs_state(|state| {
            let Some(entry) = state.fds.get(idx) else {
                return Err(Errno::EBADF);
            };
            if !entry_matches(entry, process, idx, alias_gen) {
                return Err(Errno::EBADF);
            }
            Ok((entry.mount_id, entry.ino))
        })? {
            Ok(v) => v,
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        };
        let (atime, mtime) = match parse_utimens_pair(user_times, now) {
            Ok(v) => v,
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        };
        let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
            vol.utimens(dev, ino, atime, mtime, now).map(|()| 0i64)
        });
        return Ok(Some(encode_result(res)));
    }
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    match resolve_path(process, linux_signed_int(raw_dirfd), &raw, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            let (atime, mtime) = match parse_utimens_pair(user_times, now) {
                Ok(v) => v,
                Err(e) => return Ok(Some(SyscallReturn::error(e))),
            };
            let res = super::step33_mounts::with_ext4_volume(mount_id, |vol, dev, _| {
                vol.utimens(dev, stat.ino, atime, mtime, now).map(|()| 0i64)
            });
            Ok(Some(encode_result(res)))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            let (atime, mtime) = match parse_utimens_pair(user_times, now) {
                Ok(v) => v,
                Err(e) => return Ok(Some(SyscallReturn::error(e))),
            };
            Ok(Some(super::step33_mounts::try_utimens_virtual_abs(
                process, &abs_path, atime, mtime, flags,
            )?))
        }
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_name_to_handle_at(
    raw_dirfd: u64,
    user_path: u64,
    user_handle: u64,
    user_mnt_id: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if (flags & !(AT_EMPTY_PATH | AT_SYMLINK_FOLLOW | 0x200)) != 0 {
        return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
    }
    let process = current_process_id()?;
    let raw = match read_user_path_opt_empty(user_path) {
        Ok(p) => p,
        Err(e) => {
            if !needs_ext4_path_interception(process, raw_dirfd, b"") {
                return Ok(None);
            }
            return Ok(Some(SyscallReturn::error(e)));
        }
    };
    if raw.is_empty() && (flags & AT_EMPTY_PATH) != 0 && is_ext4_fd_or_alias_current(raw_dirfd) {
        let Some((idx, alias_gen)) = resolve_ext4_slot_idx(process, raw_dirfd) else {
            return Ok(Some(SyscallReturn::error(Errno::EBADF)));
        };
        let (mount_id, ino) = match with_vfs_state(|state| {
            let Some(entry) = state.fds.get(idx) else {
                return Err(Errno::EBADF);
            };
            if !entry_matches(entry, process, idx, alias_gen) {
                return Err(Errno::EBADF);
            }
            Ok((entry.mount_id, entry.ino))
        })? {
            Ok(v) => v,
            Err(e) => return Ok(Some(SyscallReturn::error(e))),
        };
        return Ok(Some(encode_result(write_linux_file_handle(
            user_handle,
            user_mnt_id,
            u64::from(ino),
            super::step33_mounts::ext4_table_mount_id(mount_id),
        ))));
    }
    if !needs_ext4_path_interception(process, raw_dirfd, &raw) {
        return Ok(None);
    }
    let follow = (flags & AT_SYMLINK_FOLLOW) != 0;
    let dirfd = linux_signed_int(raw_dirfd);
    match resolve_path(process, dirfd, &raw, follow) {
        Ok(ResolvedPath::Ext4Existing { mount_id, stat, .. }) => {
            Ok(Some(encode_result(write_linux_file_handle(
                user_handle,
                user_mnt_id,
                u64::from(stat.ino),
                super::step33_mounts::ext4_table_mount_id(mount_id),
            ))))
        }
        Ok(ResolvedPath::Ext4MissingParent { .. }) => Ok(Some(SyscallReturn::error(Errno::ENOENT))),
        Ok(ResolvedPath::Virtual { abs_path }) => {
            Ok(Some(super::step33_mounts::try_name_to_handle_virtual_abs(
                process,
                &abs_path,
                user_handle,
                user_mnt_id,
                flags,
            )?))
        }
        Ok(ResolvedPath::Initramfs { .. }) => Ok(None),
        Err(e) => Ok(Some(SyscallReturn::error(e))),
    }
}

fn handle_copy_file_range(
    raw_in: u64,
    user_off_in: u64,
    raw_out: u64,
    user_off_out: u64,
    raw_len: u64,
    flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    if flags != 0 {
        return Ok(Err(Errno::EINVAL));
    }
    if !is_ext4_fd_or_alias_current(raw_in) || !is_ext4_fd_or_alias_current(raw_out) {
        return Ok(Err(Errno::EXDEV));
    }
    let process = current_process_id()?;
    let Some((in_idx, in_gen)) = resolve_ext4_slot_idx(process, raw_in) else {
        return Ok(Err(Errno::EBADF));
    };
    let Some((out_idx, out_gen)) = resolve_ext4_slot_idx(process, raw_out) else {
        return Ok(Err(Errno::EBADF));
    };
    let in_info = with_vfs_state(|state| {
        let Some(e) = state.fds.get(in_idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(e, process, in_idx, in_gen) || !e.readable || e.is_dir {
            return Err(Errno::EBADF);
        }
        Ok((e.mount_id, e.ino, e.offset))
    })?;
    let (in_mount, in_ino, in_cur_off) = match in_info {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    let out_info = with_vfs_state(|state| {
        let Some(e) = state.fds.get(out_idx) else {
            return Err(Errno::EBADF);
        };
        if !entry_matches(e, process, out_idx, out_gen) || !e.writable || e.is_dir {
            return Err(Errno::EBADF);
        }
        Ok((e.mount_id, e.ino, e.offset, e.append))
    })?;
    let (out_mount, out_ino, out_cur_off, out_append) = match out_info {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    if in_mount != out_mount {
        return Ok(Err(Errno::EXDEV));
    }
    let in_off = match read_opt_user_off(user_off_in, in_cur_off) {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    let out_off = match read_opt_user_off(user_off_out, out_cur_off) {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    let len = usize::try_from(raw_len)
        .unwrap_or(usize::MAX)
        .min(1024 * 1024);
    let now = current_epoch_now_secs();
    let res = super::step33_mounts::with_ext4_volume(in_mount, |vol, dev, _| {
        let mut buf = vec![0u8; len.min(32768)];
        let mut copied = 0usize;
        let mut cur_in = in_off;
        let mut cur_out = if user_off_out == 0 && out_append {
            vol.stat_inode(dev, out_ino)?.size
        } else {
            out_off
        };
        while copied < len {
            let chunk = (len - copied).min(buf.len());
            let r = vol.read_file(dev, in_ino, cur_in, &mut buf[..chunk])?;
            if r == 0 {
                break;
            }
            let w = vol.write_file(dev, out_ino, cur_out, &buf[..r], now)?;
            cur_in += w as u64;
            cur_out += w as u64;
            copied += w;
            if w < r {
                break;
            }
        }
        Ok((copied, cur_in, cur_out))
    });
    match res {
        Ok((copied, next_in, next_out)) => {
            if user_off_in == 0 {
                let _ = with_vfs_state(|state| {
                    if let Some(e) = state.fds.get_mut(in_idx)
                        && entry_matches(e, process, in_idx, in_gen)
                    {
                        e.offset = next_in;
                    }
                });
            } else {
                let _ = copy_to_user(user_off_in, &(next_in as i64).to_le_bytes());
            }
            if user_off_out == 0 {
                let _ = with_vfs_state(|state| {
                    if let Some(e) = state.fds.get_mut(out_idx)
                        && entry_matches(e, process, out_idx, out_gen)
                    {
                        e.offset = next_out;
                    }
                });
            } else {
                let _ = copy_to_user(user_off_out, &(next_out as i64).to_le_bytes());
            }
            Ok(Ok(copied as i64))
        }
        Err(e) => Ok(Err(e)),
    }
}

fn handle_sendfile(
    raw_out: u64,
    raw_in: u64,
    user_off_in: u64,
    raw_count: u64,
) -> Result<Result<i64, Errno>, ()> {
    if !is_ext4_fd_or_alias_current(raw_out) || !is_ext4_fd_or_alias_current(raw_in) {
        return Ok(Err(Errno::EINVAL));
    }
    handle_copy_file_range(raw_in, user_off_in, raw_out, 0, raw_count, 0)
}

fn read_opt_user_off(ptr: u64, fallback: u64) -> Result<u64, Errno> {
    if ptr == 0 {
        return Ok(fallback);
    }
    let mut bytes = [0u8; 8];
    copy_from_user(&mut bytes, ptr)?;
    let val = i64::from_le_bytes(bytes);
    if val < 0 {
        return Err(Errno::EINVAL);
    }
    Ok(val as u64)
}
