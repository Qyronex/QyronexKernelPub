// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use alloc::vec::Vec;
use kernal_capability::ObjectId;
use kernal_linux_abi::{
    Errno, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_fd::{OpenObjectKind, SubsystemHandle};

pub(super) const ARM64_STAT_BYTES: usize = 128;
pub(super) const S_IFREG_MODE: u32 = 0o100_444;
pub(super) const S_IFCHR_MODE: u32 = 0o020_660;
pub(super) const S_IFBLK_MODE: u32 = 0o060_660;

pub(super) const SUBSYS_DEV: u8 = 1;
pub(super) const SUBSYS_PROC_SYS: u8 = 2;
pub(super) const SUBSYS_NET: u8 = 3;
pub(super) const SUBSYS_EVENT: u8 = 4;
pub(super) const SUBSYS_HW: u8 = 5;
pub(super) const SUBSYS_EXT4: u8 = 6;
pub(super) const SUBSYS_KMSG: u8 = 7;
pub(super) const SUBSYS_DESKTOP: u8 = 8;

const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const F_DUPFD_CLOEXEC: u32 = 1030;
const FD_CLOEXEC: i32 = 1;
const O_CLOEXEC_U32: u32 = 0x0008_0000;

/// Per-process native-slot reference table tracking direct (`64..192`) subsystem descriptor
/// ownership and `FD_CLOEXEC` across `fork`, `dup`, `execve`, and `exit`.
#[derive(Clone, Copy)]
pub(super) struct DirectProcessRefs<const P: usize> {
    owners: [Option<(ObjectId, bool)>; P],
}

impl<const P: usize> DirectProcessRefs<P> {
    pub(super) const fn empty() -> Self {
        Self { owners: [None; P] }
    }

    pub(super) fn init(&mut self, owner: ObjectId, cloexec: bool) {
        self.owners = [None; P];
        if P > 0 {
            self.owners[0] = Some((owner, cloexec));
        }
    }

    pub(super) fn has_owner(&self, owner: ObjectId) -> bool {
        self.owners.iter().flatten().any(|(id, _)| *id == owner)
    }

    pub(super) fn get_cloexec(&self, owner: ObjectId) -> Option<bool> {
        self.owners
            .iter()
            .flatten()
            .find(|(id, _)| *id == owner)
            .map(|(_, cloexec)| *cloexec)
    }

    pub(super) fn set_cloexec(&mut self, owner: ObjectId, cloexec: bool) -> bool {
        for (id, flag) in self.owners.iter_mut().flatten() {
            if *id == owner {
                *flag = cloexec;
                return true;
            }
        }
        false
    }

    pub(super) fn on_fork(&mut self, parent: ObjectId, child: ObjectId) {
        let Some(cloexec) = self.get_cloexec(parent) else {
            return;
        };
        if self.has_owner(child) {
            return;
        }
        if let Some(slot) = self.owners.iter_mut().find(|entry| entry.is_none()) {
            *slot = Some((child, cloexec));
        }
    }

    pub(super) fn close_owner(&mut self, owner: ObjectId) -> bool {
        let mut closed = false;
        for slot in &mut self.owners {
            if matches!(slot, Some((id, _)) if *id == owner) {
                *slot = None;
                closed = true;
            }
        }
        closed
    }

    pub(super) fn close_cloexec_for(&mut self, owner: ObjectId) {
        for slot in &mut self.owners {
            if matches!(slot, Some((id, true)) if *id == owner) {
                *slot = None;
            }
        }
    }

    pub(super) fn apply_close_range(&mut self, owner: ObjectId, cloexec_only: bool) -> bool {
        if cloexec_only {
            let _ = self.set_cloexec(owner, true);
            false
        } else {
            self.close_owner(owner)
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.owners.iter().all(Option::is_none)
    }
}

pub(super) fn fd_in_close_range(fd: i32, first: u32, last: u32) -> bool {
    u32::try_from(fd).is_ok_and(|u| u >= first && u <= last)
}

pub(super) fn current_scheduler_thread() -> Option<kernal_scheduler_smp::GlobalThreadId> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu)?;
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    unsafe { scheduler.bootstrap_current_global_thread() }.ok()
}

pub(super) fn current_process_object() -> Option<ObjectId> {
    let current = current_scheduler_thread()?;
    super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _tid) =
            state.process_parts_for_scheduler_thread(current).ok()?;
        address_space.current_owner(process).ok()?;
        Some(process.id())
    })
    .ok()
    .flatten()
}

fn write_prefixed_u64(prefix: &[u8], val: u64, suffix: &[u8], out: &mut [u8]) -> usize {
    let mut c = prefix.len().min(out.len());
    out[..c].copy_from_slice(&prefix[..c]);
    let mut digits = [0u8; 20];
    let mut v = val;
    let mut pos = digits.len();
    loop {
        pos -= 1;
        digits[pos] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let slice = &digits[pos..];
    let take_digits = out.len().saturating_sub(c).min(slice.len());
    out[c..c + take_digits].copy_from_slice(&slice[..take_digits]);
    c += take_digits;
    let take_suffix = out.len().saturating_sub(c).min(suffix.len());
    out[c..c + take_suffix].copy_from_slice(&suffix[..take_suffix]);
    c + take_suffix
}

fn describe_subsystem_handle(
    handle: SubsystemHandle,
    proc_sys_fds: Option<&[super::step33_mounts::ProcSysFdEntry]>,
    out: &mut [u8],
) -> Option<usize> {
    match handle.kind {
        SUBSYS_DEV => {
            super::step32_dev::describe_dev_slot(handle.slot, Some(handle.generation), None, out)
        }
        SUBSYS_PROC_SYS => match proc_sys_fds {
            Some(fds) => super::step33_mounts::describe_proc_sys_entry_in_slice(
                fds,
                handle.slot,
                Some(handle.generation),
                None,
                out,
            ),
            None => super::step33_mounts::describe_proc_sys_slot(
                handle.slot,
                Some(handle.generation),
                None,
                out,
            ),
        },
        SUBSYS_NET => Some(write_prefixed_u64(
            b"socket:[",
            u64::from(handle.slot),
            b"]",
            out,
        )),
        SUBSYS_EVENT => Some(write_prefixed_u64(
            b"anon_inode:[event:",
            u64::from(handle.slot),
            b"]",
            out,
        )),
        SUBSYS_HW => super::step42_hardware::describe_hw_slot(
            handle.slot,
            Some(handle.generation),
            None,
            out,
        ),
        SUBSYS_EXT4 => super::step33_ext4_vfs::describe_ext4_slot(
            handle.slot,
            Some(handle.generation),
            None,
            out,
        ),
        SUBSYS_KMSG => Some(write_prefixed_u64(
            b"kmsg:[",
            u64::from(handle.slot),
            b"]",
            out,
        )),
        SUBSYS_DESKTOP => super::step43_desktop::describe_desktop_slot(
            handle.slot,
            Some(handle.generation),
            None,
            out,
        ),
        _ => None,
    }
}

pub(super) fn collect_process_fd_numbers(process: ObjectId, out: &mut Vec<i32>) {
    let _ = super::step29_runtime::with_process(process, |runtime| {
        for fd in 0..super::step29_runtime::STEP29_RUNTIME_FDS as i32 {
            if runtime.fds().object_kind(fd).is_ok() {
                out.push(fd);
            }
        }
    });
    super::step32_dev::append_open_dev_fds(process, out);
    super::step33_mounts::append_open_proc_sys_fds(process, out);
    super::step42_hardware::append_open_hw_fds(process, out);
    super::step33_ext4_vfs::append_open_ext4_fds(process, out);
    super::step34_net::append_open_socket_fds(process, out);
    super::step35_events_cgroup::append_open_event_fds(process, out);
    super::step37_38_systemd_udev::append_open_kmsg_fds(process, out);
    super::step43_desktop::append_open_desktop_fds(process, out);
}

pub(super) fn is_live_non_tty_native_fd(process: ObjectId, raw_fd: u64) -> bool {
    super::step33_mounts::is_open_proc_sys_fd(process, raw_fd)
        || super::step34_net::is_open_socket_fd(process, raw_fd)
        || super::step35_events_cgroup::is_open_event_fd(process, raw_fd)
        || super::step37_38_systemd_udev::is_open_kmsg_fd(process, raw_fd)
        || super::step40_debian_boot::is_open_boot_fd(raw_fd)
        || super::step41_container::is_open_container_fd(raw_fd)
        || super::step42_hardware::is_open_hw_fd(process, raw_fd)
        || super::step43_desktop::is_open_desktop_fd(process, raw_fd)
        || super::step44_conformance::is_open_conformance_fd(raw_fd)
        || super::step33_ext4_vfs::is_open_ext4_fd(process, raw_fd)
}

pub(super) fn describe_process_fd_target_with_proc_sys(
    process: ObjectId,
    fd: i32,
    proc_sys_fds: Option<&[super::step33_mounts::ProcSysFdEntry]>,
    out: &mut [u8],
) -> Option<usize> {
    if (0..super::step29_runtime::STEP29_RUNTIME_FDS as i32).contains(&fd) {
        let mut kind_res = None;
        let _ = super::step29_runtime::with_process(process, |runtime| {
            if let Ok(kind) = runtime.fds().object_kind(fd) {
                kind_res = Some(kind);
            }
        });
        return match kind_res? {
            OpenObjectKind::External(_) => {
                let take = b"/dev/console".len().min(out.len());
                out[..take].copy_from_slice(&b"/dev/console"[..take]);
                Some(take)
            }
            OpenObjectKind::Pipe => Some(write_prefixed_u64(b"pipe:[", fd as u64, b"]", out)),
            OpenObjectKind::File => Some(write_prefixed_u64(b"/file:[", fd as u64, b"]", out)),
            OpenObjectKind::Directory => Some(write_prefixed_u64(b"/dir:[", fd as u64, b"]", out)),
            OpenObjectKind::Subsystem(handle) => {
                describe_subsystem_handle(handle, proc_sys_fds, out)
            }
        };
    }
    let raw_fd = fd as u64;
    if super::step32_dev::is_dev_fd(raw_fd) {
        let slot = (fd - super::step32_dev::DEV_FD_BASE) as u16;
        return super::step32_dev::describe_dev_slot(slot, None, Some(process), out);
    }
    if super::step33_mounts::is_proc_sys_fd(raw_fd) {
        let slot = (fd - super::step33_mounts::PROC_SYS_FD_BASE) as u16;
        return match proc_sys_fds {
            Some(fds) => super::step33_mounts::describe_proc_sys_entry_in_slice(
                fds,
                slot,
                None,
                Some(process),
                out,
            ),
            None => super::step33_mounts::describe_proc_sys_slot(slot, None, Some(process), out),
        };
    }
    if super::step42_hardware::is_hw_fd(raw_fd) {
        let slot = (fd - super::step42_hardware::HW_FD_BASE) as u16;
        return super::step42_hardware::describe_hw_slot(slot, None, Some(process), out);
    }
    if super::step33_ext4_vfs::is_ext4_fd(raw_fd) {
        let slot = (fd - super::step33_ext4_vfs::EXT4_FD_BASE) as u16;
        return super::step33_ext4_vfs::describe_ext4_slot(slot, None, Some(process), out);
    }
    if super::step34_net::is_socket_fd(raw_fd) {
        let slot = (fd - super::step34_net::SOCK_FD_BASE) as u16;
        return Some(write_prefixed_u64(b"socket:[", u64::from(slot), b"]", out));
    }
    if super::step37_38_systemd_udev::is_kmsg_fd(raw_fd) {
        let slot = (fd - super::step37_38_systemd_udev::KMSG_FD_BASE) as u16;
        return Some(write_prefixed_u64(b"kmsg:[", u64::from(slot), b"]", out));
    }
    if super::step43_desktop::is_desktop_fd(raw_fd) {
        let slot = (fd - super::step43_desktop::DESKTOP_FD_BASE) as u16;
        return super::step43_desktop::describe_desktop_slot(slot, None, Some(process), out);
    }
    None
}

pub(super) fn lookup_aliased_subsystem(process: ObjectId, raw_fd: u64) -> Option<SubsystemHandle> {
    let fd = linux_signed_int(raw_fd);
    if fd < 0 || fd >= super::step29_runtime::STEP29_RUNTIME_FDS as i32 {
        return None;
    }
    super::step29_runtime::with_process(process, |runtime| {
        runtime.fds().subsystem_handle(fd).ok().flatten()
    })
    .ok()
    .flatten()
}

pub(super) fn lookup_aliased_subsystem_current(raw_fd: u64) -> Option<SubsystemHandle> {
    let fd = linux_signed_int(raw_fd);
    if fd < 0 || fd >= super::step29_runtime::STEP29_RUNTIME_FDS as i32 {
        return None;
    }
    let process = current_process_object()?;
    lookup_aliased_subsystem(process, raw_fd)
}

pub(super) fn release_subsystem_handle(handle: SubsystemHandle) {
    match handle.kind {
        SUBSYS_DEV => super::step32_dev::release_alias_handle(handle),
        SUBSYS_PROC_SYS => super::step33_mounts::release_alias_handle(handle),
        SUBSYS_NET => super::step34_net::release_alias_handle(handle),
        SUBSYS_EVENT => super::step35_events_cgroup::release_alias_handle(handle),
        SUBSYS_HW => super::step42_hardware::release_alias_handle(handle),
        SUBSYS_EXT4 => super::step33_ext4_vfs::release_alias_handle(handle),
        SUBSYS_KMSG => super::step37_38_systemd_udev::release_alias_handle(handle),
        SUBSYS_DESKTOP => super::step43_desktop::release_alias_handle(handle),
        _ => {}
    }
}

pub(super) fn release_subsystem_handles(handles: &[Option<SubsystemHandle>]) {
    for handle in handles.iter().flatten().copied() {
        release_subsystem_handle(handle);
    }
}

pub(super) fn on_subsystem_process_fork(parent: ObjectId, child: ObjectId) {
    super::step32_dev::on_process_fork(parent, child);
    super::step33_mounts::on_process_fork(parent, child);
    super::step42_hardware::on_process_fork(parent, child);
    super::step33_ext4_vfs::on_process_fork(parent, child);
    super::step34_net::on_process_fork(parent, child);
    super::step35_events_cgroup::on_process_fork(parent, child);
    super::step37_38_systemd_udev::on_process_fork(parent, child);
    super::step41_container::on_process_fork(parent, child);
    super::step43_desktop::on_process_fork(parent, child);
}

pub(super) fn on_subsystem_process_exec(process: ObjectId) {
    super::step32_dev::on_process_exec(process);
    super::step33_mounts::on_process_exec(process);
    super::step42_hardware::on_process_exec(process);
    super::step33_ext4_vfs::on_process_exec(process);
    super::step34_net::on_process_exec(process);
    super::step35_events_cgroup::on_process_exec(process);
    super::step37_38_systemd_udev::on_process_exec(process);
    super::step43_desktop::on_process_exec(process);
}

pub(super) fn on_subsystem_process_exit(process: ObjectId) {
    super::step32_dev::on_process_exit(process);
    super::step33_mounts::on_process_exit(process);
    super::step42_hardware::on_process_exit(process);
    super::step33_ext4_vfs::on_process_exit(process);
    super::step34_net::on_process_exit(process);
    super::step35_events_cgroup::on_process_exit(process);
    super::step37_38_systemd_udev::on_process_exit(process);
    super::step39_dpkg::on_process_exit(process);
    super::step41_container::on_process_exit(process);
    super::step43_desktop::on_process_exit(process);
}

pub(super) fn close_range_for_all_subsystems(
    first: u32,
    last: u32,
    cloexec_only: bool,
) -> Result<(), ()> {
    let Some(process) = current_process_object() else {
        return Ok(());
    };
    let mut dropped_subsys = [None::<SubsystemHandle>; super::step29_runtime::STEP29_RUNTIME_FDS];
    let mut dropped_subsys_len = 0usize;
    #[cfg(feature = "step29-qemu-proof")]
    let mut closed_pipes = [None::<(kernal_linux_pipe::PipeId, kernal_linux_pipe::End)>;
        super::step29_runtime::STEP29_RUNTIME_FDS];
    #[cfg(feature = "step29-qemu-proof")]
    let mut closed_pipes_len = 0usize;
    let _ = super::step29_runtime::with_process(process, |runtime| {
        let (fds, pipes, overlay) = runtime.fd_pipe_overlay_parts();
        for fd in 0..super::step29_runtime::STEP29_RUNTIME_FDS as i32 {
            if !fd_in_close_range(fd, first, last) || fds.object_kind(fd).is_err() {
                continue;
            }
            if cloexec_only {
                let _ = fds.set_close_on_exec(fd, true);
                continue;
            }
            let _ = fds.close_with_release(fd, |released| match released {
                kernal_linux_fd::ReleasedObject::Pipe(ep) => {
                    pipes.close(ep).map_err(|_| Errno::EIO)?;
                    #[cfg(feature = "step29-qemu-proof")]
                    if closed_pipes_len < closed_pipes.len() {
                        closed_pipes[closed_pipes_len] = Some((ep.pipe(), ep.end()));
                        closed_pipes_len += 1;
                    }
                    Ok(())
                }
                kernal_linux_fd::ReleasedObject::RetainedDirectory(d) => {
                    overlay.release_directory(d).map_err(|_| Errno::EIO)
                }
                kernal_linux_fd::ReleasedObject::RetainedReadOnly(l) => {
                    overlay.release_open(l).map_err(|_| Errno::EIO)
                }
                kernal_linux_fd::ReleasedObject::WritableRegular(r) => {
                    overlay.release_retained_regular(r).map_err(|_| Errno::EIO)
                }
                kernal_linux_fd::ReleasedObject::Subsystem(h) => {
                    if dropped_subsys_len < dropped_subsys.len() {
                        dropped_subsys[dropped_subsys_len] = Some(h);
                        dropped_subsys_len += 1;
                    }
                    Ok(())
                }
            });
        }
    });
    release_subsystem_handles(&dropped_subsys[..dropped_subsys_len]);
    #[cfg(feature = "step29-qemu-proof")]
    for (pipe, end) in closed_pipes[..closed_pipes_len].iter().flatten() {
        super::futex::pipe_blocking::notify_after_endpoint_close(*pipe, *end).map_err(|_| ())?;
    }
    super::step32_dev::close_range_for_process(process, first, last, cloexec_only);
    super::step34_net::close_range_for_process(process, first, last, cloexec_only);
    super::step35_events_cgroup::close_range_for_process(process, first, last, cloexec_only);
    super::step37_38_systemd_udev::close_range_for_process(process, first, last, cloexec_only);
    super::step42_hardware::close_range_for_process(process, first, last, cloexec_only);
    super::step43_desktop::close_range_for_process(process, first, last, cloexec_only);
    super::step33_ext4_vfs::close_range_for_process(process, first, last, cloexec_only);
    super::step33_mounts::close_range_for_process(process, first, last, cloexec_only);
    Ok(())
}

pub(super) fn retain_existing_subsystem_handle(
    handle: SubsystemHandle,
) -> Result<(SubsystemHandle, u64), Errno> {
    match handle.kind {
        SUBSYS_DEV => super::step32_dev::retain_existing_handle(handle),
        SUBSYS_PROC_SYS => super::step33_mounts::retain_existing_handle(handle),
        SUBSYS_NET => super::step34_net::retain_existing_handle(handle),
        SUBSYS_EVENT => super::step35_events_cgroup::retain_existing_handle(handle),
        SUBSYS_HW => super::step42_hardware::retain_existing_handle(handle),
        SUBSYS_EXT4 => super::step33_ext4_vfs::retain_existing_handle(handle),
        SUBSYS_KMSG => super::step37_38_systemd_udev::retain_existing_handle(handle),
        SUBSYS_DESKTOP => super::step43_desktop::retain_existing_handle(handle),
        _ => Err(Errno::EBADF),
    }
}

pub(super) fn retain_any_subsystem_fd(
    process: ObjectId,
    raw_fd: u64,
) -> Result<Option<(SubsystemHandle, u64)>, Errno> {
    if let Some(pair) = retain_native_subsystem_fd(process, raw_fd)? {
        return Ok(Some(pair));
    }
    if let Some(handle) = lookup_aliased_subsystem(process, raw_fd) {
        return retain_existing_subsystem_handle(handle).map(Some);
    }
    Ok(None)
}

pub(super) fn install_subsystem_fd_in_process(
    process: ObjectId,
    handle: SubsystemHandle,
    cloexec: bool,
    status_flags: u64,
) -> Result<i32, Errno> {
    super::step29_runtime::with_process(process, |runtime| {
        runtime
            .fds()
            .open_subsystem_from(0, handle, cloexec, status_flags)
            .map(|tok| tok.fd())
            .map_err(|_| Errno::EMFILE)
    })
    .map_err(|_| Errno::EIO)?
}

pub(super) fn rollback_subsystem_fd_in_process(process: ObjectId, fd: i32) {
    let mut dropped: Option<SubsystemHandle> = None;
    let _ = super::step29_runtime::with_process(process, |runtime| {
        let _ = runtime.fds().close_with_release(fd, |released| {
            if let kernal_linux_fd::ReleasedObject::Subsystem(h) = released {
                dropped = Some(h);
            }
            Ok::<(), Errno>(())
        });
    });
    if let Some(h) = dropped {
        release_subsystem_handle(h);
    }
}

fn retain_native_subsystem_fd(
    process: ObjectId,
    raw_fd: u64,
) -> Result<Option<(SubsystemHandle, u64)>, Errno> {
    if super::step32_dev::is_dev_fd(raw_fd) {
        return super::step32_dev::retain_alias_handle(process, raw_fd).map(Some);
    }
    if super::step33_mounts::is_proc_sys_fd(raw_fd) {
        return super::step33_mounts::retain_alias_handle(process, raw_fd).map(Some);
    }
    if super::step34_net::is_socket_fd(raw_fd) {
        return super::step34_net::retain_alias_handle(process, raw_fd).map(Some);
    }
    if super::step35_events_cgroup::is_event_fd(raw_fd) {
        return super::step35_events_cgroup::retain_alias_handle(process, raw_fd).map(Some);
    }
    if super::step42_hardware::is_hw_fd(raw_fd) {
        return super::step42_hardware::retain_alias_handle(process, raw_fd).map(Some);
    }
    if super::step33_ext4_vfs::is_ext4_fd(raw_fd) {
        return super::step33_ext4_vfs::retain_alias_handle(process, raw_fd).map(Some);
    }
    if super::step37_38_systemd_udev::is_kmsg_fd(raw_fd) {
        return super::step37_38_systemd_udev::retain_alias_handle(process, raw_fd).map(Some);
    }
    if super::step43_desktop::is_desktop_fd(raw_fd) {
        return super::step43_desktop::retain_alias_handle(process, raw_fd).map(Some);
    }
    Ok(None)
}

fn try_native_fcntl_meta(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    if matches!(cmd, 5 | 6 | 7 | 36 | 37 | 38) {
        return None;
    }
    if super::step32_dev::is_dev_fd(raw_fd) {
        return super::step32_dev::handle_native_fcntl(process, raw_fd, cmd, argi);
    }
    if super::step33_mounts::is_proc_sys_fd(raw_fd) {
        return super::step33_mounts::handle_native_fcntl(process, raw_fd, cmd, argi);
    }
    if super::step34_net::is_socket_fd(raw_fd) {
        return super::step34_net::handle_native_fcntl(process, raw_fd, cmd, argi);
    }
    if super::step35_events_cgroup::is_event_fd(raw_fd) {
        return super::step35_events_cgroup::handle_native_fcntl(process, raw_fd, cmd, argi);
    }
    if super::step42_hardware::is_hw_fd(raw_fd) {
        return super::step42_hardware::handle_native_fcntl(process, raw_fd, cmd, argi);
    }
    if super::step33_ext4_vfs::is_ext4_fd(raw_fd) {
        return super::step33_ext4_vfs::handle_native_fcntl(process, raw_fd, cmd, argi);
    }
    if super::step37_38_systemd_udev::is_kmsg_fd(raw_fd) {
        return super::step37_38_systemd_udev::handle_native_fcntl(process, raw_fd, cmd, argi);
    }
    if super::step43_desktop::is_desktop_fd(raw_fd) {
        return super::step43_desktop::handle_native_fcntl(process, raw_fd, cmd, argi);
    }
    if matches!(cmd, F_GETFL | F_SETFL)
        && let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
    {
        return match handle.kind {
            SUBSYS_DEV => super::step32_dev::handle_native_fcntl(process, raw_fd, cmd, argi),
            SUBSYS_PROC_SYS => {
                super::step33_mounts::handle_native_fcntl(process, raw_fd, cmd, argi)
            }
            SUBSYS_NET => super::step34_net::handle_native_fcntl(process, raw_fd, cmd, argi),
            SUBSYS_EVENT => {
                super::step35_events_cgroup::handle_native_fcntl(process, raw_fd, cmd, argi)
            }
            SUBSYS_HW => super::step42_hardware::handle_native_fcntl(process, raw_fd, cmd, argi),
            SUBSYS_EXT4 => super::step33_ext4_vfs::handle_native_fcntl(process, raw_fd, cmd, argi),
            SUBSYS_KMSG => {
                super::step37_38_systemd_udev::handle_native_fcntl(process, raw_fd, cmd, argi)
            }
            SUBSYS_DESKTOP => {
                super::step43_desktop::handle_native_fcntl(process, raw_fd, cmd, argi)
            }
            _ => None,
        };
    }
    None
}

/// Intercepts `dup(2)`, `dup3(2)`, and `fcntl(2)` targeting a native subsystem descriptor window
/// (`64..192`) so callers can duplicate or redirect `/dev/*`, `/proc/*`, sockets, and event/timer/
/// signalfds onto standard or high `0..64` process descriptors cleanly.
pub(super) fn try_handle_subsystem_dup_or_fcntl(
    request: SyscallRequest,
) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        // dup(oldfd) -> lowest free 0..64 FD alias
        23 => {
            let Some(process) = current_process_object() else {
                return Err(());
            };
            let retained = match retain_native_subsystem_fd(process, request.args[0]) {
                Ok(Some(v)) => v,
                Ok(None) => return Ok(None),
                Err(errno) => return Ok(Some(SyscallReturn::error(errno))),
            };
            let res = super::step29_runtime::with_process(process, |runtime| {
                runtime
                    .fds()
                    .open_subsystem_from(0, retained.0, false, retained.1)
            });
            match res {
                Ok(Ok(token)) => Ok(Some(encode_result(Ok(i64::from(token.fd()))))),
                Ok(Err(_)) | Err(_) => {
                    release_subsystem_handle(retained.0);
                    Ok(Some(SyscallReturn::error(Errno::EMFILE)))
                }
            }
        }
        // dup3(oldfd, newfd, flags)
        24 => {
            let raw_old = request.args[0];
            let raw_new = request.args[1];
            let raw_flags = request.args[2];
            let Some(process) = current_process_object() else {
                return Err(());
            };
            let retained = match retain_native_subsystem_fd(process, raw_old) {
                Ok(Some(v)) => v,
                Ok(None) => return Ok(None),
                Err(errno) => return Ok(Some(SyscallReturn::error(errno))),
            };
            let flags = linux_signed_int(raw_flags) as u32;
            if flags & !O_CLOEXEC_U32 != 0 {
                release_subsystem_handle(retained.0);
                return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
            }
            let cloexec = flags & O_CLOEXEC_U32 != 0;
            let oldfd = linux_signed_int(raw_old);
            let newfd = linux_signed_int(raw_new);
            if oldfd == newfd {
                release_subsystem_handle(retained.0);
                return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
            }
            if newfd < 0 || newfd >= super::step29_runtime::STEP29_RUNTIME_FDS as i32 {
                release_subsystem_handle(retained.0);
                return Ok(Some(SyscallReturn::error(Errno::EBADF)));
            }
            let mut dropped_subsys: Option<SubsystemHandle> = None;
            #[cfg(feature = "step29-qemu-proof")]
            let mut closed_pipe: Option<(
                kernal_linux_pipe::PipeId,
                kernal_linux_pipe::End,
            )> = None;
            let res = super::step29_runtime::with_process(process, |runtime| {
                let (fds, pipes, overlay) = runtime.fd_pipe_overlay_parts();
                fds.bind_subsystem_exact(newfd, retained.0, cloexec, retained.1, |released| {
                    match released {
                        kernal_linux_fd::ReleasedObject::Pipe(ep) => {
                            pipes.close(ep).map_err(|_| Errno::EIO)?;
                            #[cfg(feature = "step29-qemu-proof")]
                            {
                                closed_pipe = Some((ep.pipe(), ep.end()));
                            }
                            Ok(())
                        }
                        kernal_linux_fd::ReleasedObject::RetainedDirectory(d) => {
                            overlay.release_directory(d).map_err(|_| Errno::EIO)
                        }
                        kernal_linux_fd::ReleasedObject::RetainedReadOnly(l) => {
                            overlay.release_open(l).map_err(|_| Errno::EIO)
                        }
                        kernal_linux_fd::ReleasedObject::WritableRegular(r) => {
                            overlay.release_retained_regular(r).map_err(|_| Errno::EIO)
                        }
                        kernal_linux_fd::ReleasedObject::Subsystem(h) => {
                            dropped_subsys = Some(h);
                            Ok(())
                        }
                    }
                })
            });
            if let Some(prev) = dropped_subsys {
                release_subsystem_handle(prev);
            }
            #[cfg(feature = "step29-qemu-proof")]
            if let Some((pipe, end)) = closed_pipe {
                super::futex::pipe_blocking::notify_after_endpoint_close(pipe, end)
                    .map_err(|_| ())?;
            }
            match res {
                Ok(Ok(Ok(token))) => Ok(Some(encode_result(Ok(i64::from(token.fd()))))),
                Ok(Ok(Err(errno))) => {
                    release_subsystem_handle(retained.0);
                    Ok(Some(SyscallReturn::error(errno)))
                }
                Ok(Err(_)) | Err(_) => {
                    release_subsystem_handle(retained.0);
                    Ok(Some(SyscallReturn::error(Errno::EMFILE)))
                }
            }
        }
        // fcntl(fd, cmd, arg) on native subsystem windows
        25 => {
            let raw_fd = request.args[0];
            let cmd = linux_unsigned_int(request.args[1]);
            let argi = linux_signed_int(request.args[2]);
            let Some(process) = current_process_object() else {
                return Err(());
            };
            if matches!(cmd, F_DUPFD | F_DUPFD_CLOEXEC) {
                let retained = match retain_native_subsystem_fd(process, raw_fd) {
                    Ok(Some(v)) => v,
                    Ok(None) => return Ok(None),
                    Err(errno) => return Ok(Some(SyscallReturn::error(errno))),
                };
                if argi < 0 || argi >= super::step29_runtime::STEP29_RUNTIME_FDS as i32 {
                    release_subsystem_handle(retained.0);
                    return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
                }
                let cloexec = cmd == F_DUPFD_CLOEXEC;
                let res = super::step29_runtime::with_process(process, |runtime| {
                    runtime
                        .fds()
                        .open_subsystem_from(argi, retained.0, cloexec, retained.1)
                });
                return match res {
                    Ok(Ok(token)) => Ok(Some(encode_result(Ok(i64::from(token.fd()))))),
                    Ok(Err(_)) | Err(_) => {
                        release_subsystem_handle(retained.0);
                        Ok(Some(SyscallReturn::error(Errno::EMFILE)))
                    }
                };
            }
            if matches!(cmd, F_GETFD | F_SETFD | F_GETFL | F_SETFL) {
                if let Some(res) = try_native_fcntl_meta(process, raw_fd, cmd, argi) {
                    return Ok(Some(encode_result(res)));
                }
            } else if try_native_fcntl_meta(process, raw_fd, cmd, argi).is_some() {
                return Ok(Some(SyscallReturn::error(Errno::EINVAL)));
            }
            let _ = (FD_CLOEXEC, F_GETFD, F_SETFD, F_GETFL, F_SETFL);
            Ok(None)
        }
        _ => Ok(None),
    }
}

pub(super) fn encode_result(res: Result<i64, Errno>) -> SyscallReturn {
    match res {
        Ok(val) => SyscallReturn::success(val).unwrap_or(SyscallReturn::error(Errno::EINVAL)),
        Err(errno) => SyscallReturn::error(errno),
    }
}

pub(super) fn copy_from_user(dst: &mut [u8], user_src: u64) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_from_user(dst, user_src).map_err(super::map_usercopy_errno)
}

pub(super) fn copy_to_user(user_dst: u64, src: &[u8]) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_to_user(user_dst, src).map_err(super::map_usercopy_errno)
}

pub(super) fn read_user_cstr(user_ptr: u64, out: &mut [u8]) -> Result<usize, Errno> {
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

pub(super) const ARM64_STATX_BYTES: usize = 256;
pub(super) const STATX_BASIC_STATS: u32 = 0x0000_07ff;
pub(super) const STATX_MNT_ID: u32 = 0x0000_1000;
pub(super) const STATX_ATTR_MOUNT_ROOT: u64 = 0x0000_2000;

pub(super) fn read_user_iovec(user_iov: u64, index: usize) -> Result<(u64, usize), Errno> {
    if user_iov == 0 {
        return Err(Errno::EFAULT);
    }
    let addr = (index as u64)
        .checked_mul(16)
        .and_then(|off| user_iov.checked_add(off))
        .ok_or(Errno::EFAULT)?;
    let mut raw = [0u8; 16];
    copy_from_user(&mut raw, addr)?;
    let base = u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]);
    let len = u64::from_le_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);
    let len_usize = usize::try_from(len).map_err(|_| Errno::EINVAL)?;
    Ok((base, len_usize))
}

#[derive(Clone, Copy)]
pub(super) struct StatMeta {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u32,
    pub blocks: u64,
    pub atime_sec: i64,
    pub atime_nsec: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: u64,
    pub ctime_sec: i64,
    pub ctime_nsec: u64,
    pub mnt_id: u32,
    pub is_mount_root: bool,
}

pub(super) const EPOCH_BASE_SECONDS: u32 = 1_760_000_000;

pub(super) fn current_epoch_now_secs() -> u32 {
    let mono_secs = kernal_timer_aarch64::monotonic_now_ns().map_or(0u32, |ns| {
        (ns / 1_000_000_000).min(u64::from(u32::MAX / 2)) as u32
    });
    EPOCH_BASE_SECONDS.saturating_add(mono_secs)
}

pub(super) fn current_uid_gid() -> (u32, u32) {
    let mut uid = 0u32;
    let mut gid = 0u32;
    if let Some(current) = current_scheduler_thread() {
        let _ = super::runtime::with_linux_runtime(|state| {
            let _ = state.with_current_process_credentials(current, |proc_ref, creds| {
                if let Ok(c) = creds.credentials(proc_ref) {
                    uid = c.euid();
                    gid = c.egid();
                }
            });
        });
    }
    (uid, gid)
}

const UTIME_NOW: i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;

pub(super) fn decode_chown_id(raw: u64) -> Option<u32> {
    let id = raw as u32;
    if id == u32::MAX { None } else { Some(id) }
}

pub(super) fn parse_utimens_pair(
    user_times: u64,
    now: u32,
) -> Result<(Option<u32>, Option<u32>), Errno> {
    if user_times == 0 {
        return Ok((Some(now), Some(now)));
    }
    let mut raw = [0u8; 32];
    copy_from_user(&mut raw, user_times)?;
    let asec = i64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
    let ansec = i64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
    let msec = i64::from_le_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
    let mnsec = i64::from_le_bytes(raw[24..32].try_into().unwrap_or([0; 8]));
    let decode_ts = |sec: i64, nsec: i64| -> Result<Option<u32>, Errno> {
        if nsec == UTIME_OMIT {
            return Ok(None);
        }
        if nsec == UTIME_NOW {
            return Ok(Some(now));
        }
        if !(0..1_000_000_000).contains(&nsec) {
            return Err(Errno::EINVAL);
        }
        Ok(Some(sec.clamp(0, i64::from(u32::MAX)) as u32))
    };
    Ok((decode_ts(asec, ansec)?, decode_ts(msec, mnsec)?))
}

pub(super) fn write_linux_file_handle(
    user_handle: u64,
    user_mnt_id: u64,
    ino: u64,
    mnt_id: u32,
) -> Result<i64, Errno> {
    if user_handle == 0 || user_mnt_id == 0 {
        return Err(Errno::EFAULT);
    }
    let mut hdr = [0u8; 8];
    copy_from_user(&mut hdr, user_handle)?;
    let avail = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let needed: u32 = 8;
    if avail > 128 {
        return Err(Errno::EINVAL);
    }
    copy_to_user(user_handle, &needed.to_le_bytes())?;
    if avail < needed {
        return Err(Errno::EOVERFLOW);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&needed.to_le_bytes());
    out[4..8].copy_from_slice(&1i32.to_le_bytes());
    out[8..16].copy_from_slice(&ino.to_le_bytes());
    copy_to_user(user_handle, &out)?;
    copy_to_user(user_mnt_id, &(mnt_id as i32).to_le_bytes())?;
    Ok(0)
}

pub(super) fn write_aarch64_stat_meta(user_stat: u64, meta: &StatMeta) -> Result<i64, Errno> {
    let mut buf = [0u8; ARM64_STAT_BYTES];
    buf[0..8].copy_from_slice(&meta.dev.to_le_bytes());
    buf[8..16].copy_from_slice(&meta.ino.to_le_bytes());
    buf[16..20].copy_from_slice(&meta.mode.to_le_bytes());
    buf[20..24].copy_from_slice(&meta.nlink.to_le_bytes());
    buf[24..28].copy_from_slice(&meta.uid.to_le_bytes());
    buf[28..32].copy_from_slice(&meta.gid.to_le_bytes());
    buf[32..40].copy_from_slice(&meta.rdev.to_le_bytes());
    buf[48..56].copy_from_slice(&(meta.size as i64).to_le_bytes());
    buf[56..60].copy_from_slice(&(meta.blksize as i32).to_le_bytes());
    buf[64..72].copy_from_slice(&(meta.blocks as i64).to_le_bytes());
    buf[72..80].copy_from_slice(&meta.atime_sec.to_le_bytes());
    buf[80..88].copy_from_slice(&meta.atime_nsec.to_le_bytes());
    buf[88..96].copy_from_slice(&meta.mtime_sec.to_le_bytes());
    buf[96..104].copy_from_slice(&meta.mtime_nsec.to_le_bytes());
    buf[104..112].copy_from_slice(&meta.ctime_sec.to_le_bytes());
    buf[112..120].copy_from_slice(&meta.ctime_nsec.to_le_bytes());
    copy_to_user(user_stat, &buf)?;
    Ok(0)
}

pub(super) fn write_aarch64_statx_meta(user_statx: u64, meta: &StatMeta) -> Result<i64, Errno> {
    if user_statx == 0 {
        return Err(Errno::EFAULT);
    }
    let mut buf = [0u8; ARM64_STATX_BYTES];
    let mut stx_mask = STATX_BASIC_STATS;
    if meta.mnt_id != 0 {
        stx_mask |= STATX_MNT_ID;
    }
    buf[0..4].copy_from_slice(&stx_mask.to_le_bytes());
    buf[4..8].copy_from_slice(&meta.blksize.to_le_bytes());
    if meta.is_mount_root {
        buf[8..16].copy_from_slice(&STATX_ATTR_MOUNT_ROOT.to_le_bytes());
    }
    buf[16..20].copy_from_slice(&meta.nlink.to_le_bytes());
    buf[20..24].copy_from_slice(&meta.uid.to_le_bytes());
    buf[24..28].copy_from_slice(&meta.gid.to_le_bytes());
    buf[28..30].copy_from_slice(&(meta.mode as u16).to_le_bytes());
    buf[32..40].copy_from_slice(&meta.ino.to_le_bytes());
    buf[40..48].copy_from_slice(&meta.size.to_le_bytes());
    buf[48..56].copy_from_slice(&meta.blocks.to_le_bytes());
    buf[56..64].copy_from_slice(&STATX_ATTR_MOUNT_ROOT.to_le_bytes());
    buf[64..72].copy_from_slice(&meta.atime_sec.to_le_bytes());
    buf[72..76].copy_from_slice(&(meta.atime_nsec as u32).to_le_bytes());
    buf[96..104].copy_from_slice(&meta.ctime_sec.to_le_bytes());
    buf[104..108].copy_from_slice(&(meta.ctime_nsec as u32).to_le_bytes());
    buf[112..120].copy_from_slice(&meta.mtime_sec.to_le_bytes());
    buf[120..124].copy_from_slice(&(meta.mtime_nsec as u32).to_le_bytes());
    let rdev_major = (((meta.rdev >> 8) & 0x0fff) | ((meta.rdev >> 32) & !0x0fff)) as u32;
    let rdev_minor = ((meta.rdev & 0xff) | ((meta.rdev >> 12) & !0xff)) as u32;
    buf[128..132].copy_from_slice(&rdev_major.to_le_bytes());
    buf[132..136].copy_from_slice(&rdev_minor.to_le_bytes());
    let dev_major = (((meta.dev >> 8) & 0x0fff) | ((meta.dev >> 32) & !0x0fff)) as u32;
    let dev_minor = ((meta.dev & 0xff) | ((meta.dev >> 12) & !0xff)) as u32;
    buf[136..140].copy_from_slice(&dev_major.to_le_bytes());
    buf[140..144].copy_from_slice(&dev_minor.to_le_bytes());
    buf[144..152].copy_from_slice(&u64::from(meta.mnt_id).to_le_bytes());
    copy_to_user(user_statx, &buf)?;
    Ok(0)
}

pub(super) fn write_aarch64_stat(user_stat: u64, mode: u32, size: u64) -> Result<i64, Errno> {
    let mut buf = [0u8; ARM64_STAT_BYTES];
    buf[16..20].copy_from_slice(&mode.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[48..56].copy_from_slice(&(size as i64).to_le_bytes());
    buf[56..60].copy_from_slice(&4096i32.to_le_bytes());
    copy_to_user(user_stat, &buf)?;
    Ok(0)
}

pub(super) fn seek_bounded(
    current_offset: usize,
    total: usize,
    offset: i64,
    whence: i32,
) -> Result<usize, Errno> {
    let base = match whence {
        0 => 0i64,
        1 => current_offset as i64,
        2 => total as i64,
        _ => return Err(Errno::EINVAL),
    };
    let next = base.checked_add(offset).ok_or(Errno::EINVAL)?;
    if next < 0 {
        return Err(Errno::EINVAL);
    }
    Ok(next as usize)
}
