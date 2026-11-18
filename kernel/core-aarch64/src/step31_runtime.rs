// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;
use kernal_capability::ObjectId;
use kernal_linux_aarch64_abi::classify_step31_glibc;
use kernal_linux_abi::{
    Errno, IOVEC_BYTES, IoVec, KERNEL_TERMIOS_BYTES, MAX_RW_COUNT, RLIMIT64_BYTES, Rlimit64,
    Step31GlibcCall, SyscallRequest, SyscallReturn, TCGETS, TCSETS, TCSETSF, TCSETSW, TIOCGPGRP,
    TIOCGWINSZ, TIOCSCTTY, TIOCSPGRP, TIOCSWINSZ, WINSIZE_BYTES, WinSize, decode_getrandom_flags,
    decode_iovcnt, decode_rlimit_resource, default_rlimit64, encode_default_serial_termios,
    encode_linux_aarch64_utsname, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_dev::Termios;
#[cfg(feature = "step29-qemu-proof")]
use kernal_linux_fd::{Error as FdError, ExternalObject, OpenObjectKind};
use kernal_linux_write_aarch64::{WriteError, write_from_user};
use kernal_usercopy::Error as UsercopyError;

/// Linux `getrandom(2)` single-call transfer ceiling (`32 MiB - 1`, matching Linux random driver).
const GETRANDOM_MAX_TOTAL_BYTES: usize = 0x01ff_ffff;
const GETRANDOM_CHUNK_BYTES: usize = 256;
const VEC_IO_CHUNK_BYTES: usize = 256;

#[cfg(feature = "step29-qemu-proof")]
const O_ACCMODE: u64 = 0x3;
#[cfg(feature = "step29-qemu-proof")]
const O_RDONLY: u64 = 0;
#[cfg(feature = "step29-qemu-proof")]
const O_WRONLY: u64 = 1;
#[cfg(feature = "step29-qemu-proof")]
const O_RDWR: u64 = 2;
#[cfg(feature = "step31-debian-shell")]
const O_NONBLOCK: u64 = 0x0800;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step31Error {
    Linux(Errno),
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteTargetKind {
    Serial,
    #[cfg(feature = "step29-qemu-proof")]
    Pipe {
        endpoint: kernal_linux_pipe::Endpoint,
        nonblocking: bool,
    },
    #[cfg(feature = "step29-qemu-proof")]
    WritableRegular,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadTargetKind {
    SerialStdinEof,
    #[cfg(feature = "step29-qemu-proof")]
    Pipe {
        endpoint: kernal_linux_pipe::Endpoint,
        nonblocking: bool,
    },
    #[cfg(feature = "step29-qemu-proof")]
    File,
}

/// Dispatches Step-31 dynamic glibc and coreutil startup syscalls (`ioctl`, `readv`, `writev`,
/// `uname`, `prlimit64`, `getrandom`, and `rseq`).
///
/// - `getrandom(2)` validates flags (`GRND_NONBLOCK`, `GRND_RANDOM`, `GRND_INSECURE`), generates
///   forward-secure ChaCha20 random bytes from the DTB-seeded CSPRNG owner, and copies them through
///   the audited AArch64 PAN-enforced usercopy boundary.
/// - `uname(2)`, `prlimit64(2)`, `ioctl(2)`, `readv(2)`, and `writev(2)` execute through the
///   canonical Process/LinuxIdentity/FD/VFS owners and audited usercopy.
/// - `rseq(2)` explicitly returns `-ENOSYS` per `docs/debian13/step31/glibc-oracle.json`
///   (`optional_with_enosys_fallback: ["rseq"]`, `fake_success: false`).
pub(super) fn handle(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    let Some(call) = classify_step31_glibc(request) else {
        return Ok(None);
    };

    let outcome = match call {
        Step31GlibcCall::Rseq { .. } => return Ok(Some(SyscallReturn::error(Errno::ENOSYS))),
        Step31GlibcCall::Getrandom {
            user_buffer,
            count,
            flags,
        } => handle_getrandom(user_buffer, count, flags),
        Step31GlibcCall::Uname { user_utsname } => handle_uname(user_utsname),
        Step31GlibcCall::Prlimit64 {
            pid,
            resource,
            user_new_rlim,
            user_old_rlim,
        } => handle_prlimit64(pid, resource, user_new_rlim, user_old_rlim),
        Step31GlibcCall::Ioctl { fd, request, arg } => handle_ioctl(fd, request, arg),
        Step31GlibcCall::Writev {
            fd,
            user_iov,
            iovcnt,
        } => handle_writev(fd, user_iov, iovcnt),
        Step31GlibcCall::Readv {
            fd,
            user_iov,
            iovcnt,
        } => handle_readv(fd, user_iov, iovcnt),
    };

    encode_step31_outcome(outcome)
}

/// Dispatches `readv(2)` with the trapping `ExceptionFrame` so blocking serial stdin reads can
/// yield cooperatively and resume cleanly across Stop/Continue signals.
pub(super) fn handle_blocking_readv(
    request: SyscallRequest,
    frame: &mut kernal_exceptions_aarch64::ExceptionFrame,
) -> Result<Option<SyscallReturn>, ()> {
    let Some(Step31GlibcCall::Readv {
        fd,
        user_iov,
        iovcnt,
    }) = classify_step31_glibc(request)
    else {
        return Ok(None);
    };
    encode_step31_outcome(handle_readv_inner(fd, user_iov, iovcnt, Some(frame)))
}

fn encode_step31_outcome(outcome: Result<i64, Step31Error>) -> Result<Option<SyscallReturn>, ()> {
    match outcome {
        Ok(value) => Ok(Some(SyscallReturn::success(value).ok_or(())?)),
        Err(Step31Error::Linux(errno)) => Ok(Some(SyscallReturn::error(errno))),
        Err(Step31Error::Invariant) => Err(()),
    }
}

fn handle_getrandom(user_buffer: u64, count: u64, flags: u64) -> Result<i64, Step31Error> {
    let decoded_flags = decode_getrandom_flags(flags).map_err(Step31Error::Linux)?;

    let target_len = usize::try_from(count)
        .unwrap_or(GETRANDOM_MAX_TOTAL_BYTES)
        .min(GETRANDOM_MAX_TOTAL_BYTES);
    if target_len == 0 {
        return Ok(0);
    }

    let mut chunk = [0u8; GETRANDOM_CHUNK_BYTES];
    let mut copied = 0usize;
    while copied < target_len {
        let take = (target_len - copied).min(GETRANDOM_CHUNK_BYTES);
        let dest_addr = match user_buffer.checked_add(copied as u64) {
            Some(addr) => addr,
            None => {
                chunk.fill(0);
                return if copied == 0 {
                    Err(Step31Error::Linux(Errno::EFAULT))
                } else {
                    i64::try_from(copied).map_err(|_| Step31Error::Invariant)
                };
            }
        };

        if let Err(entropy_error) = super::entropy::fill_getrandom(&mut chunk[..take]) {
            chunk.fill(0);
            return match entropy_error {
                super::entropy::Error::MissingSeed if decoded_flags.nonblock() => {
                    Err(Step31Error::Linux(Errno::EAGAIN))
                }
                _ => Err(Step31Error::Invariant),
            };
        }

        if let Err(copy_error) = kernal_usercopy_aarch64::copy_to_user(dest_addr, &chunk[..take]) {
            chunk.fill(0);
            return match map_usercopy_error(copy_error) {
                Ok(errno) => {
                    if copied == 0 {
                        Err(Step31Error::Linux(errno))
                    } else {
                        i64::try_from(copied).map_err(|_| Step31Error::Invariant)
                    }
                }
                Err(()) => Err(Step31Error::Invariant),
            };
        }

        copied += take;
    }
    chunk.fill(0);

    i64::try_from(copied).map_err(|_| Step31Error::Invariant)
}

fn handle_uname(user_utsname: u64) -> Result<i64, Step31Error> {
    let utsname = encode_linux_aarch64_utsname();
    kernal_usercopy_aarch64::copy_to_user(user_utsname, &utsname)
        .map_err(|err| map_usercopy_step31(err))?;
    Ok(0)
}

fn handle_prlimit64(
    raw_pid: u64,
    raw_resource: u64,
    user_new_rlim: u64,
    user_old_rlim: u64,
) -> Result<i64, Step31Error> {
    let pid_i32 = linux_signed_int(raw_pid);
    if pid_i32 < 0 {
        return Err(Step31Error::Linux(Errno::EINVAL));
    }
    let resource = decode_rlimit_resource(raw_resource).map_err(Step31Error::Linux)?;
    let (_process_id, caller_pid, _pgid) = current_process_identity()?;

    let is_root = super::step_fd_util::current_uid_gid().0 == 0;
    if pid_i32 != 0 && (pid_i32 as u32) != caller_pid.get() {
        let target_pid = NonZeroU32::new(pid_i32 as u32).ok_or(Step31Error::Invariant)?;
        let exists = super::runtime::with_linux_runtime(|state| {
            Ok::<bool, super::runtime::Error>(
                state
                    .signal_target_pids(None)?
                    .iter()
                    .any(|candidate| candidate == target_pid),
            )
        })
        .map_err(|_| Step31Error::Invariant)?
        .map_err(|_| Step31Error::Invariant)?;
        if !exists {
            return Err(Step31Error::Linux(Errno::ESRCH));
        }
        if !is_root {
            return Err(Step31Error::Linux(Errno::EPERM));
        }
    }

    let baseline = default_rlimit64(resource);
    if user_new_rlim != 0 {
        let mut raw_new = [0u8; RLIMIT64_BYTES];
        kernal_usercopy_aarch64::copy_from_user(&mut raw_new, user_new_rlim)
            .map_err(map_usercopy_step31)?;
        let requested = Rlimit64::from_le_bytes(raw_new)
            .validate()
            .map_err(Step31Error::Linux)?;
        if !is_root && requested.rlim_max > baseline.rlim_max {
            return Err(Step31Error::Linux(Errno::EPERM));
        }
    }

    if user_old_rlim != 0 {
        let encoded = baseline.to_le_bytes();
        kernal_usercopy_aarch64::copy_to_user(user_old_rlim, &encoded)
            .map_err(map_usercopy_step31)?;
    }

    Ok(0)
}

fn handle_ioctl(raw_fd: u64, raw_request: u64, arg: u64) -> Result<i64, Step31Error> {
    let fd = linux_signed_int(raw_fd);
    let request = linux_unsigned_int(raw_request);
    let (process_id, _pid, pgid) = current_process_identity()?;

    if super::step32_dev::is_dev_or_aliased_fd(raw_fd) {
        let ret = super::step32_dev::handle_dev_ioctl(process_id, raw_fd, raw_request, arg)
            .map_err(|()| Step31Error::Invariant)?;
        let raw = ret.raw();
        if raw < 0 {
            let errno = Errno::new(u16::try_from(-raw).map_err(|_| Step31Error::Invariant)?)
                .ok_or(Step31Error::Invariant)?;
            return Err(Step31Error::Linux(errno));
        }
        return Ok(raw);
    }

    validate_serial_tty_fd(process_id, fd)?;

    #[cfg(feature = "step31-debian-shell")]
    if matches!(
        request,
        TCGETS
            | TCSETS
            | TCSETSW
            | TCSETSF
            | TIOCGWINSZ
            | TIOCSWINSZ
            | TIOCSCTTY
            | TIOCGPGRP
            | TIOCSPGRP
    ) {
        let ret = super::step32_dev::handle_console_ioctl(raw_request, arg)
            .map_err(|()| Step31Error::Invariant)?;
        let raw = ret.raw();
        if raw < 0 {
            let errno = Errno::new(u16::try_from(-raw).map_err(|_| Step31Error::Invariant)?)
                .ok_or(Step31Error::Invariant)?;
            return Err(Step31Error::Linux(errno));
        }
        return Ok(raw);
    }

    match request {
        TCGETS => {
            let termios = encode_default_serial_termios();
            kernal_usercopy_aarch64::copy_to_user(arg, &termios).map_err(map_usercopy_step31)?;
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            let mut raw = [0u8; KERNEL_TERMIOS_BYTES];
            kernal_usercopy_aarch64::copy_from_user(&mut raw, arg).map_err(map_usercopy_step31)?;
            let _ = Termios::from_le_bytes(raw);
            Ok(0)
        }
        TIOCSCTTY => {
            if _pid != pgid {
                return Err(Step31Error::Linux(Errno::EPERM));
            }
            Ok(0)
        }
        TIOCGWINSZ => {
            let winsize = WinSize::default_serial().to_le_bytes();
            kernal_usercopy_aarch64::copy_to_user(arg, &winsize).map_err(map_usercopy_step31)?;
            Ok(0)
        }
        TIOCSWINSZ => {
            let mut raw = [0u8; WINSIZE_BYTES];
            kernal_usercopy_aarch64::copy_from_user(&mut raw, arg).map_err(map_usercopy_step31)?;
            let _ = WinSize::from_le_bytes(raw);
            Ok(0)
        }
        TIOCGPGRP => {
            let encoded = pgid.get().to_le_bytes();
            kernal_usercopy_aarch64::copy_to_user(arg, &encoded).map_err(map_usercopy_step31)?;
            Ok(0)
        }
        TIOCSPGRP => {
            let mut raw = [0u8; 4];
            kernal_usercopy_aarch64::copy_from_user(&mut raw, arg).map_err(map_usercopy_step31)?;
            let requested = i32::from_le_bytes(raw);
            if requested <= 0 {
                return Err(Step31Error::Linux(Errno::EINVAL));
            }
            if (requested as u32) != pgid.get() {
                return Err(Step31Error::Linux(Errno::EPERM));
            }
            Ok(0)
        }
        _ => Err(Step31Error::Linux(Errno::ENOTTY)),
    }
}

fn handle_writev(raw_fd: u64, user_iov: u64, raw_iovcnt: u64) -> Result<i64, Step31Error> {
    let iovcnt = decode_iovcnt(raw_iovcnt).map_err(Step31Error::Linux)?;
    let fd = linux_signed_int(raw_fd);
    let (process_id, _pid, _pgid) = current_process_identity()?;
    let target = classify_write_target(process_id, fd)?;

    if iovcnt == 0 {
        return Ok(0);
    }

    let total_requested = validate_user_iovec_table(user_iov, iovcnt)?;
    if total_requested == 0 {
        return Ok(0);
    }

    let mut total_written = 0usize;
    for index in 0..iovcnt {
        if total_written >= total_requested {
            break;
        }
        let iov = read_user_iovec_at(user_iov, index)?;
        let remaining = total_requested - total_written;
        let seg_len = usize::try_from(iov.len)
            .map_err(|_| Step31Error::Linux(Errno::EINVAL))?
            .min(remaining);
        if seg_len == 0 {
            continue;
        }

        match write_segment(process_id, fd, target, iov.base, seg_len) {
            Ok(written) => {
                total_written = total_written
                    .checked_add(written)
                    .ok_or(Step31Error::Invariant)?;
                if written < seg_len {
                    break;
                }
            }
            Err(Step31Error::Linux(errno)) => {
                if total_written == 0 {
                    return Err(Step31Error::Linux(errno));
                }
                break;
            }
            Err(Step31Error::Invariant) => return Err(Step31Error::Invariant),
        }
    }

    i64::try_from(total_written).map_err(|_| Step31Error::Invariant)
}

fn handle_readv(raw_fd: u64, user_iov: u64, raw_iovcnt: u64) -> Result<i64, Step31Error> {
    handle_readv_inner(raw_fd, user_iov, raw_iovcnt, None)
}

fn handle_readv_inner(
    raw_fd: u64,
    user_iov: u64,
    raw_iovcnt: u64,
    mut frame: Option<&mut kernal_exceptions_aarch64::ExceptionFrame>,
) -> Result<i64, Step31Error> {
    let iovcnt = decode_iovcnt(raw_iovcnt).map_err(Step31Error::Linux)?;
    let fd = linux_signed_int(raw_fd);
    let (process_id, _pid, _pgid) = current_process_identity()?;
    let target = classify_read_target(process_id, fd)?;

    if iovcnt == 0 {
        return Ok(0);
    }

    let total_requested = validate_user_iovec_table(user_iov, iovcnt)?;
    if total_requested == 0 {
        return Ok(0);
    }

    let mut total_read = 0usize;
    for index in 0..iovcnt {
        if total_read >= total_requested {
            break;
        }
        let iov = read_user_iovec_at(user_iov, index)?;
        let remaining = total_requested - total_read;
        let seg_len = usize::try_from(iov.len)
            .map_err(|_| Step31Error::Linux(Errno::EINVAL))?
            .min(remaining);
        if seg_len == 0 {
            continue;
        }

        match read_segment(
            process_id,
            fd,
            target,
            iov.base,
            seg_len,
            frame.as_deref_mut(),
        ) {
            Ok(read_bytes) => {
                total_read = total_read
                    .checked_add(read_bytes)
                    .ok_or(Step31Error::Invariant)?;
                if read_bytes < seg_len {
                    break;
                }
            }
            Err(Step31Error::Linux(errno)) => {
                if total_read == 0 {
                    return Err(Step31Error::Linux(errno));
                }
                break;
            }
            Err(Step31Error::Invariant) => return Err(Step31Error::Invariant),
        }
    }

    i64::try_from(total_read).map_err(|_| Step31Error::Invariant)
}

fn validate_user_iovec_table(user_iov: u64, iovcnt: usize) -> Result<usize, Step31Error> {
    let mut total: i64 = 0;
    for index in 0..iovcnt {
        let iov = read_user_iovec_at(user_iov, index)?;
        let seg_len = i64::try_from(iov.len).map_err(|_| Step31Error::Linux(Errno::EINVAL))?;
        total = total
            .checked_add(seg_len)
            .ok_or(Step31Error::Linux(Errno::EINVAL))?;
    }
    let total_usize = usize::try_from(total).map_err(|_| Step31Error::Linux(Errno::EINVAL))?;
    Ok(total_usize.min(MAX_RW_COUNT))
}

fn read_user_iovec_at(user_iov: u64, index: usize) -> Result<IoVec, Step31Error> {
    let byte_offset = (index as u64)
        .checked_mul(IOVEC_BYTES as u64)
        .ok_or(Step31Error::Linux(Errno::EFAULT))?;
    let entry_addr = user_iov
        .checked_add(byte_offset)
        .ok_or(Step31Error::Linux(Errno::EFAULT))?;
    let mut raw = [0u8; IOVEC_BYTES];
    kernal_usercopy_aarch64::copy_from_user(&mut raw, entry_addr).map_err(map_usercopy_step31)?;
    Ok(IoVec::from_le_bytes(raw))
}

fn current_process_identity() -> Result<(ObjectId, NonZeroU32, NonZeroU32), Step31Error> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS
        .get(current_cpu)
        .ok_or(Step31Error::Invariant)?;
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }
        .map_err(|_| Step31Error::Invariant)?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(Step31Error::Invariant);
    }

    super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _tid) = state
            .process_parts_for_scheduler_thread(current)
            .map_err(|_| Step31Error::Invariant)?;
        address_space
            .current_owner(process)
            .map_err(|_| Step31Error::Invariant)?;
        let process_id = process.id();
        let (pid, pgid) = state
            .with_current_process_identity(current, |proc_ref, identities| {
                let pid = identities
                    .bound_pid(proc_ref)
                    .map_err(|_| Step31Error::Invariant)?;
                let pgid = identities
                    .getpgid(proc_ref)
                    .map_err(|_| Step31Error::Invariant)?;
                Ok::<_, Step31Error>((pid, pgid))
            })
            .map_err(|_| Step31Error::Invariant)??;
        Ok((process_id, pid, pgid))
    })
    .map_err(|_| Step31Error::Invariant)?
}

#[cfg(feature = "step29-qemu-proof")]
fn validate_serial_tty_fd(process: ObjectId, fd: i32) -> Result<(), Step31Error> {
    if super::step_fd_util::is_live_non_tty_native_fd(process, fd as u64) {
        return Err(Step31Error::Linux(Errno::ENOTTY));
    }
    super::step29_runtime::with_process(process, |runtime| {
        match runtime.fds().object_kind(fd).map_err(map_fd_error)? {
            OpenObjectKind::External(
                ExternalObject::Stdin | ExternalObject::Stdout | ExternalObject::Stderr,
            ) => Ok(()),
            OpenObjectKind::File
            | OpenObjectKind::Directory
            | OpenObjectKind::Pipe
            | OpenObjectKind::Subsystem(_) => Err(Step31Error::Linux(Errno::ENOTTY)),
        }
    })
    .map_err(|_| Step31Error::Invariant)?
}

#[cfg(not(feature = "step29-qemu-proof"))]
fn validate_serial_tty_fd(_process: ObjectId, fd: i32) -> Result<(), Step31Error> {
    if (0..=2).contains(&fd) {
        Ok(())
    } else {
        Err(Step31Error::Linux(Errno::EBADF))
    }
}

#[cfg(feature = "step29-qemu-proof")]
fn classify_write_target(process: ObjectId, fd: i32) -> Result<WriteTargetKind, Step31Error> {
    super::step29_runtime::with_process(process, |runtime| {
        let fds = runtime.fds();
        match fds.object_kind(fd).map_err(map_fd_error)? {
            OpenObjectKind::External(ExternalObject::Stdout | ExternalObject::Stderr) => {
                Ok(WriteTargetKind::Serial)
            }
            OpenObjectKind::Pipe => {
                let status = fds.status_flags(fd).map_err(map_fd_error)?;
                if status & O_ACCMODE != O_WRONLY {
                    return Err(Step31Error::Linux(Errno::EBADF));
                }
                let endpoint = fds.pipe_endpoint(fd).map_err(|_| Step31Error::Invariant)?;
                let nonblocking = status & 0x0800 != 0;
                Ok(WriteTargetKind::Pipe {
                    endpoint,
                    nonblocking,
                })
            }
            OpenObjectKind::File => {
                let status = fds.status_flags(fd).map_err(map_fd_error)?;
                if !matches!(status & O_ACCMODE, O_WRONLY | O_RDWR)
                    || fds.writable_regular(fd).is_err()
                {
                    return Err(Step31Error::Linux(Errno::EBADF));
                }
                Ok(WriteTargetKind::WritableRegular)
            }
            OpenObjectKind::External(ExternalObject::Stdin)
            | OpenObjectKind::Directory
            | OpenObjectKind::Subsystem(_) => Err(Step31Error::Linux(Errno::EBADF)),
        }
    })
    .map_err(|_| Step31Error::Invariant)?
}

#[cfg(not(feature = "step29-qemu-proof"))]
fn classify_write_target(_process: ObjectId, fd: i32) -> Result<WriteTargetKind, Step31Error> {
    if fd == 1 || fd == 2 {
        Ok(WriteTargetKind::Serial)
    } else {
        Err(Step31Error::Linux(Errno::EBADF))
    }
}

#[cfg(feature = "step29-qemu-proof")]
fn classify_read_target(process: ObjectId, fd: i32) -> Result<ReadTargetKind, Step31Error> {
    super::step29_runtime::with_process(process, |runtime| {
        let fds = runtime.fds();
        match fds.object_kind(fd).map_err(map_fd_error)? {
            OpenObjectKind::External(ExternalObject::Stdin) => Ok(ReadTargetKind::SerialStdinEof),
            OpenObjectKind::External(ExternalObject::Stdout | ExternalObject::Stderr) => {
                Err(Step31Error::Linux(Errno::EBADF))
            }
            OpenObjectKind::Directory => Err(Step31Error::Linux(Errno::EISDIR)),
            OpenObjectKind::Pipe => {
                let status = fds.status_flags(fd).map_err(map_fd_error)?;
                if status & O_ACCMODE != O_RDONLY {
                    return Err(Step31Error::Linux(Errno::EBADF));
                }
                let endpoint = fds.pipe_endpoint(fd).map_err(|_| Step31Error::Invariant)?;
                let nonblocking = status & 0x0800 != 0;
                Ok(ReadTargetKind::Pipe {
                    endpoint,
                    nonblocking,
                })
            }
            OpenObjectKind::File => {
                let status = fds.status_flags(fd).map_err(map_fd_error)?;
                if !matches!(status & O_ACCMODE, O_RDONLY | O_RDWR) {
                    return Err(Step31Error::Linux(Errno::EBADF));
                }
                Ok(ReadTargetKind::File)
            }
            OpenObjectKind::Subsystem(_) => Err(Step31Error::Linux(Errno::EBADF)),
        }
    })
    .map_err(|_| Step31Error::Invariant)?
}

#[cfg(not(feature = "step29-qemu-proof"))]
fn classify_read_target(_process: ObjectId, fd: i32) -> Result<ReadTargetKind, Step31Error> {
    if fd == 0 {
        Ok(ReadTargetKind::SerialStdinEof)
    } else {
        Err(Step31Error::Linux(Errno::EBADF))
    }
}

fn write_segment(
    process: ObjectId,
    fd: i32,
    target: WriteTargetKind,
    user_base: u64,
    seg_len: usize,
) -> Result<usize, Step31Error> {
    let _ = (process, fd);
    match target {
        WriteTargetKind::Serial => {
            let serial = super::step15_svc_serial().ok_or(Step31Error::Invariant)?;
            match write_from_user(user_base, seg_len as u64, |bytes| {
                for byte in bytes {
                    serial.write_byte(*byte);
                }
            }) {
                Ok(written) => usize::try_from(written).map_err(|_| Step31Error::Invariant),
                Err(WriteError::Errno(errno)) => Err(Step31Error::Linux(errno)),
                Err(WriteError::UserAccessInvariant(_)) => Err(Step31Error::Invariant),
            }
        }
        #[cfg(feature = "step29-qemu-proof")]
        WriteTargetKind::Pipe {
            endpoint,
            nonblocking,
        } => {
            let written = super::step29_runtime::with_process(process, |runtime| {
                let (_fds, pipes) = runtime.fd_pipe_parts();
                super::step29_pipe_io::write(
                    pipes,
                    endpoint,
                    user_base,
                    seg_len as u64,
                    nonblocking,
                )
            })
            .map_err(|_| Step31Error::Invariant)?;
            let written = match written {
                Ok(w) => usize::try_from(w).map_err(|_| Step31Error::Invariant)?,
                Err(super::step29_pipe_io::Error::Linux(errno)) => {
                    return Err(Step31Error::Linux(errno));
                }
                Err(_) => return Err(Step31Error::Invariant),
            };
            if written != 0 {
                super::futex::pipe_blocking::notify_after_write(endpoint.pipe())
                    .map_err(|_| Step31Error::Invariant)?;
            }
            Ok(written)
        }
        #[cfg(feature = "step29-qemu-proof")]
        WriteTargetKind::WritableRegular => {
            super::step29_runtime::with_process(process, |runtime| {
                let (fds, overlay) = runtime.fd_overlay_parts();
                let mut copied = 0usize;
                let mut chunk = [0u8; VEC_IO_CHUNK_BYTES];
                while copied < seg_len {
                    let take = (seg_len - copied).min(VEC_IO_CHUNK_BYTES);
                    let src_addr = match user_base.checked_add(copied as u64) {
                        Some(addr) => addr,
                        None => {
                            return if copied == 0 {
                                Err(Step31Error::Linux(Errno::EFAULT))
                            } else {
                                Ok(copied)
                            };
                        }
                    };
                    if let Err(copy_error) =
                        kernal_usercopy_aarch64::copy_from_user(&mut chunk[..take], src_addr)
                    {
                        return match map_usercopy_error(copy_error) {
                            Ok(errno) if copied == 0 => Err(Step31Error::Linux(errno)),
                            Ok(_) => Ok(copied),
                            Err(()) => Err(Step31Error::Invariant),
                        };
                    }
                    let plan = fds.prepare_write(fd, take).map_err(map_fd_error)?;
                    let (_, _, retained, expected_offset, _, append) = plan;
                    let mutation = if append {
                        overlay.append_retained_regular(
                            retained,
                            &chunk[..take],
                            kernal_linux_vfs::MutableTimestamp::ZERO,
                        )
                    } else {
                        overlay
                            .write_retained_regular(
                                retained,
                                expected_offset,
                                &chunk[..take],
                                kernal_linux_vfs::MutableTimestamp::ZERO,
                            )
                            .map(|written| (expected_offset, written))
                    };
                    let (actual_start, written) = match mutation {
                        Ok(result) => result,
                        Err(overlay_err) => {
                            let errno = match overlay_err {
                                kernal_linux_vfs::OverlayError::FileTooLarge
                                | kernal_linux_vfs::OverlayError::TombstoneTableFull
                                | kernal_linux_vfs::OverlayError::BindingTableFull
                                | kernal_linux_vfs::OverlayError::Mutable(
                                    kernal_linux_vfs::RootedMutableError::Mutable(
                                        kernal_linux_vfs::MutableError::NodeTableFull
                                        | kernal_linux_vfs::MutableError::DirectoryEntryTableFull
                                        | kernal_linux_vfs::MutableError::FileTooLarge,
                                    ),
                                ) => Errno::ENOSPC,
                                _ => Errno::EIO,
                            };
                            return if copied == 0 {
                                Err(Step31Error::Linux(errno))
                            } else {
                                Ok(copied)
                            };
                        }
                    };
                    fds.commit_write(plan, actual_start, written)
                        .map_err(|_| Step31Error::Invariant)?;
                    copied += written;
                    if written < take {
                        break;
                    }
                }
                Ok(copied)
            })
            .map_err(|_| Step31Error::Invariant)?
        }
    }
}

fn read_segment(
    process: ObjectId,
    fd: i32,
    target: ReadTargetKind,
    user_base: u64,
    seg_len: usize,
    frame: Option<&mut kernal_exceptions_aarch64::ExceptionFrame>,
) -> Result<usize, Step31Error> {
    let _ = (process, fd, user_base, seg_len, &frame);
    match target {
        ReadTargetKind::SerialStdinEof => {
            #[cfg(feature = "step31-debian-shell")]
            {
                let nonblocking = super::step29_runtime::with_process(process, |runtime| {
                    runtime
                        .fds()
                        .status_flags(fd)
                        .map(|flags| (flags & O_NONBLOCK) != 0)
                        .map_err(map_fd_error)
                })
                .map_err(|_| Step31Error::Invariant)??;
                let ret = super::step32_dev::read_console_into_user(
                    user_base,
                    seg_len,
                    nonblocking,
                    frame,
                )
                .map_err(|()| Step31Error::Invariant)?;
                let raw = ret.raw();
                if raw < 0 {
                    let errno =
                        Errno::new(u16::try_from(-raw).map_err(|_| Step31Error::Invariant)?)
                            .ok_or(Step31Error::Invariant)?;
                    return Err(Step31Error::Linux(errno));
                }
                usize::try_from(raw).map_err(|_| Step31Error::Invariant)
            }
            #[cfg(not(feature = "step31-debian-shell"))]
            {
                Ok(0)
            }
        }
        #[cfg(feature = "step29-qemu-proof")]
        ReadTargetKind::Pipe {
            endpoint,
            nonblocking,
        } => {
            let read_bytes = super::step29_runtime::with_process(process, |runtime| {
                let (_fds, pipes) = runtime.fd_pipe_parts();
                super::step29_pipe_io::read(pipes, endpoint, user_base, seg_len as u64, nonblocking)
            })
            .map_err(|_| Step31Error::Invariant)?;
            let read = match read_bytes {
                Ok(n) => usize::try_from(n).map_err(|_| Step31Error::Invariant)?,
                Err(super::step29_pipe_io::Error::BlockingWaitRequired) => {
                    return Err(Step31Error::Linux(Errno::EAGAIN));
                }
                Err(super::step29_pipe_io::Error::Linux(errno)) => {
                    return Err(Step31Error::Linux(errno));
                }
                Err(super::step29_pipe_io::Error::Invariant) => {
                    return Err(Step31Error::Invariant);
                }
            };
            if read != 0 {
                super::futex::pipe_blocking::notify_after_read(endpoint.pipe())
                    .map_err(|_| Step31Error::Invariant)?;
            }
            Ok(read)
        }
        #[cfg(feature = "step29-qemu-proof")]
        ReadTargetKind::File => super::step29_runtime::with_process(process, |runtime| {
            let is_writable = if runtime.fds().writable_regular(fd).is_ok() {
                Some(true)
            } else if runtime.fds().retained_readonly(fd).is_ok() {
                Some(false)
            } else {
                None
            };
            if let Some(writable) = is_writable {
                if seg_len == 0 {
                    if writable {
                        runtime
                            .fds()
                            .prepare_writable_read(fd, 0)
                            .map_err(map_fd_error)?;
                    } else {
                        runtime
                            .fds()
                            .prepare_retained_read(fd, 0)
                            .map_err(map_fd_error)?;
                    }
                    return Ok(0);
                }
                let (fds, overlay) = runtime.fd_overlay_parts();
                let mut total = 0usize;
                let mut scratch = [0u8; VEC_IO_CHUNK_BYTES];
                while total < seg_len {
                    let take = (seg_len - total).min(VEC_IO_CHUNK_BYTES);
                    let Some(dst_addr) = user_base.checked_add(total as u64) else {
                        return if total == 0 {
                            Err(Step31Error::Linux(Errno::EFAULT))
                        } else {
                            Ok(total)
                        };
                    };
                    let (read, step_copied, faulted) = if writable {
                        let plan = fds.prepare_writable_read(fd, take).map_err(map_fd_error)?;
                        let read = overlay
                            .read_retained_regular(plan.2, plan.3, &mut scratch[..take])
                            .map_err(|_| Step31Error::Invariant)?;
                        let progress = match kernal_usercopy_aarch64::copy_to_user_progress(
                            dst_addr,
                            &scratch[..read],
                        ) {
                            Ok(progress) => progress,
                            Err(err) => {
                                let mapped = map_usercopy_step31(err);
                                return if total > 0 && matches!(mapped, Step31Error::Linux(_)) {
                                    Ok(total)
                                } else {
                                    Err(mapped)
                                };
                            }
                        };
                        let copied = progress.copied();
                        fds.commit_writable_read(plan, copied)
                            .map_err(map_fd_error)?;
                        (read, copied, progress.faulted())
                    } else {
                        let plan = fds.prepare_retained_read(fd, take).map_err(map_fd_error)?;
                        let read = overlay
                            .read_regular(plan.2, plan.3, &mut scratch[..take])
                            .map_err(|_| Step31Error::Invariant)?;
                        let progress = match kernal_usercopy_aarch64::copy_to_user_progress(
                            dst_addr,
                            &scratch[..read],
                        ) {
                            Ok(progress) => progress,
                            Err(err) => {
                                let mapped = map_usercopy_step31(err);
                                return if total > 0 && matches!(mapped, Step31Error::Linux(_)) {
                                    Ok(total)
                                } else {
                                    Err(mapped)
                                };
                            }
                        };
                        let copied = progress.copied();
                        fds.commit_retained_read(plan, copied)
                            .map_err(map_fd_error)?;
                        (read, copied, progress.faulted())
                    };
                    total += step_copied;
                    if faulted {
                        return if total == 0 {
                            Err(Step31Error::Linux(Errno::EFAULT))
                        } else {
                            Ok(total)
                        };
                    }
                    if read < take || step_copied < read {
                        break;
                    }
                }
                return Ok(total);
            }
            let (initrd, root_id, fds) = runtime.parts();
            let plan = fds.prepare_read(fd, seg_len).map_err(map_fd_error)?;
            let progress = initrd.with_bytes(|bytes| {
                let archive =
                    kernal_cpio::Archive::parse(bytes).map_err(|_| Step31Error::Invariant)?;
                let root = kernal_linux_vfs::InitramfsRoot::new(archive, root_id);
                let source = root
                    .read_at(plan.file(), plan.start_offset(), plan.len())
                    .map_err(|_| Step31Error::Invariant)?;
                kernal_usercopy_aarch64::copy_to_user_progress(user_base, source)
                    .map_err(map_usercopy_step31)
            })?;
            fds.commit_read(plan, progress.copied())
                .map_err(map_fd_error)?;
            if progress.copied() == 0 && progress.faulted() {
                return Err(Step31Error::Linux(Errno::EFAULT));
            }
            Ok(progress.copied())
        })
        .map_err(|_| Step31Error::Invariant)?,
    }
}

#[cfg(feature = "step29-qemu-proof")]
fn map_fd_error(error: FdError) -> Step31Error {
    match error {
        FdError::BadFd | FdError::NotFile => Step31Error::Linux(Errno::EBADF),
        FdError::NotDirectory => Step31Error::Linux(Errno::ENOTDIR),
        FdError::TableFull => Step31Error::Linux(Errno::EMFILE),
        FdError::OffsetOverflow => Step31Error::Linux(Errno::EOVERFLOW),
        FdError::InvalidSeek | FdError::InvalidPreadOffset => Step31Error::Linux(Errno::EINVAL),
        FdError::SeekOverflow => Step31Error::Linux(Errno::EOVERFLOW),
        FdError::NotSeekable => Step31Error::Linux(Errno::ESPIPE),
        FdError::StaleRead
        | FdError::InvalidReadLength
        | FdError::StaleDirectory
        | FdError::InvalidDirectoryCursor
        | FdError::StaleOpenFile
        | FdError::ReferenceOverflow
        | FdError::InvalidMinimumFd
        | FdError::InvalidTargetFd
        | FdError::SameDescriptor
        | FdError::StalePread => Step31Error::Invariant,
    }
}

fn map_usercopy_step31(error: UsercopyError) -> Step31Error {
    match map_usercopy_error(error) {
        Ok(errno) => Step31Error::Linux(errno),
        Err(()) => Step31Error::Invariant,
    }
}

fn map_usercopy_error(error: UsercopyError) -> Result<Errno, ()> {
    match error {
        UsercopyError::NullGuard
        | UsercopyError::Overflow
        | UsercopyError::OutsideUserRange
        | UsercopyError::Fault => Ok(Errno::EFAULT),
        UsercopyError::TooLarge
        | UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => Err(()),
    }
}

#[cfg(feature = "step29-qemu-proof")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum SharedMmapBacking {
    MemFs { mount_id: u32, mem_ino: u64 },
    MemFd { idx: usize, generation: u64 },
    Ext4 { mount_id: u32, ino: u32 },
    DrmDumb { handle: u32 },
}

#[cfg(feature = "step29-qemu-proof")]
const MAX_SHARED_MMAPS: usize = 64;

#[cfg(feature = "step29-qemu-proof")]
#[derive(Clone, Copy)]
struct SharedMmapEntry {
    live: bool,
    writable: bool,
    process: ObjectId,
    va_start: u64,
    len: u64,
    file_offset: u64,
    orig_prot: u64,
    rev: u64,
    backing: SharedMmapBacking,
}

#[cfg(feature = "step29-qemu-proof")]
impl SharedMmapEntry {
    const EMPTY: Self = Self {
        live: false,
        writable: false,
        process: ObjectId(0),
        va_start: 0,
        len: 0,
        file_offset: 0,
        orig_prot: 0,
        rev: 0,
        backing: SharedMmapBacking::Ext4 {
            mount_id: 0,
            ino: 0,
        },
    };
}

#[cfg(feature = "step29-qemu-proof")]
struct SharedMmapCell {
    state: core::sync::atomic::AtomicU8,
    entries: core::cell::UnsafeCell<[SharedMmapEntry; MAX_SHARED_MMAPS]>,
}

#[cfg(feature = "step29-qemu-proof")]
// SAFETY: access is synchronized by atomic CAS lock `0 -> 1 -> 0` with acquire/release ordering.
unsafe impl Sync for SharedMmapCell {}

#[cfg(feature = "step29-qemu-proof")]
static SHARED_MMAPS: SharedMmapCell = SharedMmapCell {
    state: core::sync::atomic::AtomicU8::new(0),
    entries: core::cell::UnsafeCell::new([SharedMmapEntry::EMPTY; MAX_SHARED_MMAPS]),
};

#[cfg(feature = "step29-qemu-proof")]
fn with_shared_mmaps<R>(
    f: impl FnOnce(&mut [SharedMmapEntry; MAX_SHARED_MMAPS]) -> R,
) -> Option<R> {
    use core::sync::atomic::Ordering;
    let mut spins = 0usize;
    while SHARED_MMAPS
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        spins += 1;
        if spins >= 1_000_000 {
            return None;
        }
        core::hint::spin_loop();
    }
    // SAFETY: exclusive state `1` acquired above.
    let res = f(unsafe { &mut *SHARED_MMAPS.entries.get() });
    SHARED_MMAPS.state.store(0, Ordering::Release);
    Some(res)
}

#[cfg(feature = "step29-qemu-proof")]
#[allow(clippy::too_many_arguments)]
fn record_shared_mmap(
    process: ObjectId,
    va_start: u64,
    raw_len: u64,
    file_offset: u64,
    backing: SharedMmapBacking,
    writable: bool,
    orig_prot: u64,
    rev: u64,
) {
    let page_mask = 4096u64 - 1;
    let aligned = raw_len
        .saturating_add(page_mask)
        .checked_div(4096)
        .unwrap_or(0)
        .saturating_mul(4096)
        .max(4096);
    let _ = with_shared_mmaps(|entries| {
        if let Some(slot) = entries.iter_mut().find(|e| !e.live) {
            *slot = SharedMmapEntry {
                live: true,
                writable,
                process,
                va_start,
                len: aligned,
                file_offset,
                orig_prot,
                rev,
                backing,
            };
        }
    });
}

/// Flushes dirty pages in active writable `MAP_SHARED` file mappings for `current_process_identity()`.
pub(super) fn sync_shared_mmap_range(address: u64, length: u64, unmapping: bool) {
    #[cfg(not(feature = "step29-qemu-proof"))]
    {
        let _ = (address, length, unmapping);
    }
    #[cfg(feature = "step29-qemu-proof")]
    {
        sync_shared_mmap_inner(Some((address, length)), unmapping, false);
    }
}

/// Flushes all active writable `MAP_SHARED` file mappings for the active user process.
pub(super) fn sync_shared_mmap_all_for_current(clear_entries: bool) {
    #[cfg(not(feature = "step29-qemu-proof"))]
    {
        let _ = clear_entries;
    }
    #[cfg(feature = "step29-qemu-proof")]
    {
        sync_shared_mmap_inner(None, clear_entries, false);
    }
}

/// Flushes active writable `MAP_SHARED` IPC (`memfd`/`memfs`) mappings for the current process.
pub(super) fn sync_shared_ipc_mmaps_for_current() {
    #[cfg(feature = "step29-qemu-proof")]
    {
        sync_shared_mmap_inner(None, false, true);
    }
}

/// Refreshes read-only `MAP_SHARED` `memfd` mappings in the current process if modified remotely.
pub(super) fn refresh_shared_memfd_mmaps_for_current() {
    #[cfg(feature = "step29-qemu-proof")]
    {
        refresh_shared_memfd_mmaps_inner();
    }
}

#[cfg(feature = "step29-qemu-proof")]
fn refresh_shared_memfd_mmaps_inner() {
    use kernal_linux_vm::{PROT_EXEC, PROT_WRITE};

    let Ok((process, _, _)) = current_process_identity() else {
        return;
    };
    let mut snap = [SharedMmapEntry::EMPTY; MAX_SHARED_MMAPS];
    let mut snap_n = 0usize;
    let _ = with_shared_mmaps(|entries| {
        for e in entries.iter() {
            if e.live
                && !e.writable
                && e.process == process
                && (e.orig_prot & PROT_EXEC) == 0
                && matches!(e.backing, SharedMmapBacking::MemFd { .. })
            {
                snap[snap_n] = *e;
                snap_n += 1;
            }
        }
    });
    for e in &snap[..snap_n] {
        let SharedMmapBacking::MemFd { idx, generation } = e.backing else {
            continue;
        };
        let Some((bytes, new_rev)) =
            super::step35_events_cgroup::read_memfd_if_changed(idx, generation, e.rev)
        else {
            continue;
        };
        let Ok(file_off) = usize::try_from(e.file_offset) else {
            continue;
        };
        if file_off >= bytes.len() {
            continue;
        }
        let Ok(max_bytes) = usize::try_from(e.len) else {
            continue;
        };
        let copy_len = (bytes.len() - file_off).min(max_bytes);
        if matches!(
            super::live_vm::handle_step31_mprotect(e.va_start, e.len, e.orig_prot | PROT_WRITE),
            Ok(Ok(()))
        ) {
            let mut off = 0usize;
            while off < copy_len {
                let chunk = (copy_len - off).min(4096);
                let _ = kernal_usercopy_aarch64::copy_to_user(
                    e.va_start + off as u64,
                    &bytes[file_off + off..file_off + off + chunk],
                );
                off += chunk;
            }
            let _ = super::live_vm::handle_step31_mprotect(e.va_start, e.len, e.orig_prot);
            let _ = with_shared_mmaps(|entries| {
                for slot in entries.iter_mut() {
                    if slot.live
                        && slot.process == process
                        && slot.va_start == e.va_start
                        && slot.backing == e.backing
                    {
                        slot.rev = new_rev;
                    }
                }
            });
        }
    }
}

#[cfg(feature = "step29-qemu-proof")]
fn sync_shared_mmap_inner(range_filter: Option<(u64, u64)>, remove_matched: bool, ipc_only: bool) {
    let Ok((process, _, _)) = current_process_identity() else {
        return;
    };
    let req_span = match range_filter {
        Some((addr, len)) => {
            if len == 0 {
                return;
            }
            let page_end = addr.saturating_add(len).saturating_add(4095) & !4095u64;
            let page_start = addr & !4095u64;
            if page_end <= page_start {
                return;
            }
            Some((page_start, page_end))
        }
        None => None,
    };

    let mut snap = [SharedMmapEntry::EMPTY; MAX_SHARED_MMAPS];
    let mut snap_n = 0usize;
    let _ = with_shared_mmaps(|entries| {
        for e in entries.iter_mut() {
            if !e.live || e.process != process {
                continue;
            }
            let e_end = e.va_start.saturating_add(e.len);
            let matches = match req_span {
                None => true,
                Some((s, end)) => e.va_start < end && e_end > s,
            };
            if matches {
                let should_flush = e.writable
                    && (!ipc_only
                        || matches!(
                            e.backing,
                            SharedMmapBacking::MemFd { .. } | SharedMmapBacking::MemFs { .. }
                        ));
                if should_flush {
                    snap[snap_n] = *e;
                    snap_n += 1;
                }
                if remove_matched && req_span.is_none() {
                    *e = SharedMmapEntry::EMPTY;
                }
            }
        }
    });

    let mut page_buf = [0u8; 4096];
    for e in &snap[..snap_n] {
        let e_end = e.va_start.saturating_add(e.len);
        let (ov_start, ov_end) = match req_span {
            None => (e.va_start, e_end),
            Some((s, end)) => (e.va_start.max(s), e_end.min(end)),
        };
        let mut va = ov_start;
        while va < ov_end {
            let chunk = usize::try_from(ov_end - va).unwrap_or(4096).min(4096);
            if kernal_usercopy_aarch64::copy_from_user(&mut page_buf[..chunk], va).is_ok() {
                let file_off = e.file_offset.saturating_add(va - e.va_start);
                match e.backing {
                    SharedMmapBacking::MemFs { mount_id, mem_ino } => {
                        if let Ok(off_usize) = usize::try_from(file_off) {
                            super::step33_mounts::write_back_memfs_mmap(
                                mount_id,
                                mem_ino,
                                off_usize,
                                &page_buf[..chunk],
                            );
                        }
                    }
                    SharedMmapBacking::MemFd { idx, generation } => {
                        if let Ok(off_usize) = usize::try_from(file_off) {
                            super::step35_events_cgroup::write_back_memfd_mmap(
                                idx,
                                generation,
                                off_usize,
                                &page_buf[..chunk],
                            );
                        }
                    }
                    SharedMmapBacking::Ext4 { mount_id, ino } => {
                        super::step33_ext4_vfs::write_back_ext4_mmap(
                            mount_id,
                            ino,
                            file_off,
                            &page_buf[..chunk],
                        );
                    }
                    SharedMmapBacking::DrmDumb { handle } => {
                        super::step43_desktop::write_back_drm_dumb_mmap(
                            handle,
                            file_off,
                            &page_buf[..chunk],
                        );
                    }
                }
            }
            va = va.saturating_add(chunk as u64);
        }
    }

    if remove_matched && let Some((u_start, u_end)) = req_span {
        let _ = with_shared_mmaps(|entries| {
            for e in entries.iter_mut() {
                if !e.live || e.process != process {
                    continue;
                }
                let e_end = e.va_start.saturating_add(e.len);
                if e.va_start >= u_end || e_end <= u_start {
                    continue;
                }
                if u_start <= e.va_start && u_end >= e_end {
                    *e = SharedMmapEntry::EMPTY;
                } else if u_start <= e.va_start {
                    let cut = u_end - e.va_start;
                    e.va_start = u_end;
                    e.len -= cut;
                    e.file_offset = e.file_offset.saturating_add(cut);
                } else {
                    e.len = u_start - e.va_start;
                }
            }
        });
    }
}

/// Routes Step-31 dynamic linker `mmap(2)` requests (`MAP_FIXED`, `MAP_DENYWRITE`, `PROT_NONE`,
/// `PROT_EXEC`, `MAP_SHARED`, or file-backed mappings) through the Step-31 VM transaction owner while
/// leaving standard anonymous `MAP_PRIVATE | MAP_ANONYMOUS` (`PROT_READ` / `PROT_READ | PROT_WRITE`)
/// requests to the baseline `live_vm::handle` path.
pub(super) fn try_handle_dynamic_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> Option<Result<Result<u64, kernal_linux_vm::Error>, ()>> {
    use kernal_linux_vm::{
        MAP_ANONYMOUS, MAP_PRIVATE, MmapFileBacking, PROT_READ, PROT_WRITE,
        validate_step31_mmap_spec,
    };

    if flags == (MAP_PRIVATE | MAP_ANONYMOUS)
        && (protection == PROT_READ || protection == (PROT_READ | PROT_WRITE))
    {
        return None;
    }

    // On AArch64 Linux, PROT_WRITE without PROT_EXEC implies readable+writable page permissions
    // (used e.g. by Weston's drm_fb_create_dumb mmap(PROT_WRITE, MAP_SHARED)).
    let protection =
        if (protection & PROT_WRITE) != 0 && (protection & kernal_linux_vm::PROT_EXEC) == 0 {
            protection | PROT_READ
        } else {
            protection
        };

    let Ok(spec) = validate_step31_mmap_spec(protection, flags, fd, offset) else {
        return None;
    };

    if spec.anonymous {
        return Some(super::live_vm::handle_step31_dynamic_mmap(
            address,
            length,
            protection,
            flags,
            fd,
            offset,
            MmapFileBacking::Anonymous,
        ));
    }

    #[cfg(not(feature = "step29-qemu-proof"))]
    {
        Some(Ok(Err(kernal_linux_vm::Error::Linux(Errno::EBADF))))
    }

    #[cfg(feature = "step29-qemu-proof")]
    {
        Some(handle_file_backed_mmap(
            address,
            length,
            protection,
            flags,
            fd,
            offset,
            spec.shared,
        ))
    }
}

/// Routes Step-31 `mprotect(2)` (`PROT_NONE`, `PROT_READ`, `PROT_READ | PROT_WRITE`,
/// `PROT_READ | PROT_EXEC`, `PROT_EXEC`) through the active process VM owner while preserving W^X.
pub(super) fn handle_mprotect(
    address: u64,
    length: u64,
    protection: u64,
) -> Result<Result<u64, Errno>, ()> {
    match super::live_vm::handle_step31_mprotect(address, length, protection) {
        Ok(Ok(())) => Ok(Ok(0)),
        Ok(Err(kernal_linux_vm::Error::Linux(errno))) => Ok(Err(errno)),
        Ok(Err(_)) | Err(()) => Err(()),
    }
}

#[cfg(feature = "step29-qemu-proof")]
#[allow(clippy::too_many_arguments)]
fn finish_file_backed_mmap(
    process: ObjectId,
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    raw_fd: u64,
    offset: u64,
    bytes: &[u8],
    track_shared_backing: Option<(SharedMmapBacking, bool, u64)>,
) -> Result<Result<u64, kernal_linux_vm::Error>, ()> {
    let res = super::live_vm::handle_step31_dynamic_mmap(
        address,
        length,
        protection,
        flags,
        raw_fd,
        offset,
        kernal_linux_vm::MmapFileBacking::FileSlice {
            bytes,
            file_offset: offset,
        },
    )?;
    if let Ok(mapped_va) = res
        && let Some((backing, writable, rev)) = track_shared_backing
    {
        record_shared_mmap(
            process, mapped_va, length, offset, backing, writable, protection, rev,
        );
    }
    Ok(res)
}

#[cfg(feature = "step29-qemu-proof")]
#[allow(clippy::too_many_arguments)]
fn handle_file_backed_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    raw_fd: u64,
    offset: u64,
    shared: bool,
) -> Result<Result<u64, kernal_linux_vm::Error>, ()> {
    use kernal_linux_abi::linux_signed_int;
    use kernal_linux_vfs::{InitramfsRoot, NodeKind, OverlayNodeHandle};
    use kernal_linux_vm::{Error as VmError, PROT_WRITE};

    let (process, _, _) = current_process_identity().map_err(|_| ())?;
    let need_write = shared && (protection & PROT_WRITE) != 0;
    if shared {
        sync_shared_mmap_all_for_current(false);
    }
    match super::step33_ext4_vfs::try_read_ext4_fd_for_mmap_with_meta(process, raw_fd, need_write) {
        Ok(Some((file_bytes, mount_id, ino))) => {
            return finish_file_backed_mmap(
                process,
                address,
                length,
                protection,
                flags,
                raw_fd,
                offset,
                &file_bytes,
                need_write.then_some((SharedMmapBacking::Ext4 { mount_id, ino }, true, 0)),
            );
        }
        Ok(None) => {}
        Err(errno) => return Ok(Err(VmError::Linux(errno))),
    }
    match super::step33_mounts::try_read_proc_sys_fd_for_mmap(process, raw_fd, need_write) {
        Ok(Some((file_bytes, mem_opt))) => {
            let backing = if need_write {
                mem_opt.map(|(mount_id, mem_ino)| {
                    (SharedMmapBacking::MemFs { mount_id, mem_ino }, true, 0)
                })
            } else {
                None
            };
            return finish_file_backed_mmap(
                process,
                address,
                length,
                protection,
                flags,
                raw_fd,
                offset,
                &file_bytes,
                backing,
            );
        }
        Ok(None) => {}
        Err(errno) => return Ok(Err(VmError::Linux(errno))),
    }
    match super::step35_events_cgroup::try_read_memfd_for_mmap(process, raw_fd, need_write) {
        Ok(Some((file_bytes, idx, generation, rev))) => {
            return finish_file_backed_mmap(
                process,
                address,
                length,
                protection,
                flags,
                raw_fd,
                offset,
                &file_bytes,
                shared.then_some((
                    SharedMmapBacking::MemFd { idx, generation },
                    need_write,
                    rev,
                )),
            );
        }
        Ok(None) => {}
        Err(errno) => return Ok(Err(VmError::Linux(errno))),
    }
    match super::step43_desktop::try_prepare_desktop_mmap(raw_fd, offset, length) {
        Ok(Some(handle)) => {
            let res = super::live_vm::handle_step31_dynamic_mmap(
                address,
                length,
                protection,
                flags,
                raw_fd,
                0,
                kernal_linux_vm::MmapFileBacking::FileSlice {
                    bytes: &[],
                    file_offset: 0,
                },
            )?;
            if let Ok(mapped_va) = res
                && need_write
            {
                record_shared_mmap(
                    process,
                    mapped_va,
                    length,
                    0,
                    SharedMmapBacking::DrmDumb { handle },
                    true,
                    protection,
                    0,
                );
            }
            return Ok(res);
        }
        Ok(None) => {}
        Err(errno) => return Ok(Err(VmError::Linux(errno))),
    }
    let fd = linux_signed_int(raw_fd);
    let resolved = super::step29_runtime::with_process(process, |runtime| {
        let (initrd, root_id) = {
            let (initrd, root_id, _fds) = runtime.parts();
            (initrd, root_id)
        };
        let status = match runtime.fds().status_flags(fd) {
            Ok(flags) => flags,
            Err(FdError::BadFd) => return Ok(Err(VmError::Linux(Errno::EBADF))),
            Err(_) => return Err(()),
        };
        if status & O_ACCMODE == O_WRONLY {
            return Ok(Err(VmError::Linux(Errno::EACCES)));
        }
        if let Ok(handle) = runtime.fds().retained_readonly(fd) {
            return match handle {
                OverlayNodeHandle::Immutable {
                    root,
                    kind: NodeKind::Regular,
                    file: Some(file),
                    ..
                } if root == root_id => Ok(Ok((initrd, root_id, file))),
                _ => Ok(Err(VmError::Linux(Errno::EACCES))),
            };
        }
        let (_initrd, _root_id, fds) = runtime.parts();
        match fds.prepare_read(fd, 0) {
            Ok(plan) => Ok(Ok((initrd, root_id, plan.file()))),
            Err(FdError::BadFd) => Ok(Err(VmError::Linux(Errno::EBADF))),
            Err(FdError::NotFile) => Ok(Err(VmError::Linux(Errno::EACCES))),
            Err(_) => Err(()),
        }
    })
    .map_err(|_| ())??;

    let (initrd, root_id, file) = match resolved {
        Ok(parts) => parts,
        Err(vm_err) => return Ok(Err(vm_err)),
    };
    if file.root_id() != root_id {
        return Err(());
    }
    initrd.with_bytes(|archive_bytes| {
        let archive = kernal_cpio::Archive::parse(archive_bytes).map_err(|_| ())?;
        let root = InitramfsRoot::new(archive, root_id);
        let file_bytes = root.read_at(file, 0, usize::MAX).map_err(|_| ())?;
        finish_file_backed_mmap(
            process, address, length, protection, flags, raw_fd, offset, file_bytes, None,
        )
    })
}

/// Handles Linux `mremap(2)` (`old_address`, `old_size`, `new_size`, `flags`, `new_address`),
/// supporting both tracked `MAP_SHARED` IPC/file mappings (e.g. Wayland `wl_shm_pool.resize`)
/// and anonymous `MAP_PRIVATE` allocations.
pub(super) fn try_handle_mremap(
    old_address: u64,
    old_size: u64,
    new_size: u64,
    flags: u64,
    new_address: u64,
) -> Result<Result<u64, kernal_linux_vm::Error>, ()> {
    #[cfg(not(feature = "step29-qemu-proof"))]
    {
        let _ = (old_address, old_size, new_size, flags, new_address);
        Ok(Err(kernal_linux_vm::Error::Linux(Errno::ENOSYS)))
    }
    #[cfg(feature = "step29-qemu-proof")]
    {
        try_handle_mremap_inner(old_address, old_size, new_size, flags, new_address)
    }
}

#[cfg(feature = "step29-qemu-proof")]
fn align_page_len(raw: u64) -> Option<u64> {
    if raw == 0 {
        return None;
    }
    raw.checked_add(4095).map(|v| v & !4095u64)
}

#[cfg(feature = "step29-qemu-proof")]
fn copy_user_pages_to_vec(va_start: u64, bytes_len: usize) -> Result<alloc::vec::Vec<u8>, Errno> {
    let mut out = alloc::vec![0u8; bytes_len];
    let mut off = 0usize;
    while off < bytes_len {
        let chunk = (bytes_len - off).min(4096);
        kernal_usercopy_aarch64::copy_from_user(&mut out[off..off + chunk], va_start + off as u64)
            .map_err(super::map_usercopy_errno)?;
        off += chunk;
    }
    Ok(out)
}

#[cfg(feature = "step29-qemu-proof")]
fn try_handle_mremap_inner(
    old_address: u64,
    old_size: u64,
    new_size: u64,
    flags: u64,
    new_address: u64,
) -> Result<Result<u64, kernal_linux_vm::Error>, ()> {
    use kernal_linux_abi::MinimumRuntimeCall;
    use kernal_linux_vm::{
        Error as VmError, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, MmapFileBacking,
        PROT_READ, PROT_WRITE,
    };

    const MREMAP_MAYMOVE: u64 = 1;
    const MREMAP_FIXED: u64 = 2;

    if (old_address & 0xfff) != 0 || (flags & !(MREMAP_MAYMOVE | MREMAP_FIXED)) != 0 {
        return Ok(Err(VmError::Linux(Errno::EINVAL)));
    }
    let fixed = (flags & MREMAP_FIXED) != 0;
    let maymove = (flags & MREMAP_MAYMOVE) != 0;
    if fixed && (!maymove || (new_address & 0xfff) != 0) {
        return Ok(Err(VmError::Linux(Errno::EINVAL)));
    }
    let Some(old_len) = align_page_len(old_size) else {
        return Ok(Err(VmError::Linux(Errno::EINVAL)));
    };
    let Some(new_len) = align_page_len(new_size) else {
        return Ok(Err(VmError::Linux(Errno::ENOMEM)));
    };

    let (process, _, _) = current_process_identity().map_err(|_| ())?;
    let matched = with_shared_mmaps(|entries| {
        entries
            .iter()
            .copied()
            .find(|e| e.live && e.process == process && e.va_start == old_address)
    })
    .flatten();

    if let Some(entry) = matched {
        if entry.writable {
            sync_shared_mmap_range(old_address, entry.len, false);
        }
        if new_len <= entry.len && !fixed {
            if new_len < entry.len {
                match super::live_vm::handle(MinimumRuntimeCall::Munmap {
                    address: old_address + new_len,
                    length: entry.len - new_len,
                })? {
                    Ok(_) => {}
                    Err(e) => return Ok(Err(e)),
                }
                let _ = with_shared_mmaps(|entries| {
                    for slot in entries.iter_mut() {
                        if slot.live && slot.process == process && slot.va_start == old_address {
                            slot.len = new_len;
                        }
                    }
                });
            }
            return Ok(Ok(old_address));
        }
        if !maymove {
            return Ok(Err(VmError::Linux(Errno::ENOMEM)));
        }

        let (bytes, new_rev) = match entry.backing {
            SharedMmapBacking::MemFd { idx, generation } => {
                match super::step35_events_cgroup::read_memfd_for_mremap(idx, generation) {
                    Some((b, r)) => (b, r),
                    None => return Ok(Err(VmError::Linux(Errno::EFAULT))),
                }
            }
            SharedMmapBacking::MemFs { mount_id, mem_ino } => {
                match super::step33_mounts::read_memfs_for_mremap(mount_id, mem_ino) {
                    Some(b) => (b, entry.rev),
                    None => return Ok(Err(VmError::Linux(Errno::EFAULT))),
                }
            }
            SharedMmapBacking::Ext4 { .. } | SharedMmapBacking::DrmDumb { .. } => {
                let copy_n = usize::try_from(entry.len).unwrap_or(0);
                match copy_user_pages_to_vec(old_address, copy_n) {
                    Ok(b) => (b, entry.rev),
                    Err(e) => return Ok(Err(VmError::Linux(e))),
                }
            }
        };

        let target_addr = if fixed { new_address } else { 0 };
        let map_flags = MAP_SHARED | if fixed { MAP_FIXED } else { 0 };
        let new_va = match super::live_vm::handle_step31_dynamic_mmap(
            target_addr,
            new_size,
            entry.orig_prot,
            map_flags,
            0,
            entry.file_offset,
            MmapFileBacking::FileSlice {
                bytes: &bytes,
                file_offset: entry.file_offset,
            },
        )? {
            Ok(va) => va,
            Err(e) => return Ok(Err(e)),
        };

        match super::live_vm::handle(MinimumRuntimeCall::Munmap {
            address: old_address,
            length: entry.len,
        })? {
            Ok(_) => {}
            Err(e) => return Ok(Err(e)),
        }
        let _ = with_shared_mmaps(|entries| {
            for slot in entries.iter_mut() {
                if slot.live && slot.process == process && slot.va_start == old_address {
                    slot.va_start = new_va;
                    slot.len = new_len;
                    slot.rev = new_rev;
                }
            }
        });
        return Ok(Ok(new_va));
    }

    if new_len <= old_len && !fixed {
        if let Err(e) = copy_user_pages_to_vec(old_address, 1) {
            return Ok(Err(VmError::Linux(e)));
        }
        if new_len < old_len {
            match super::live_vm::handle(MinimumRuntimeCall::Munmap {
                address: old_address + new_len,
                length: old_len - new_len,
            })? {
                Ok(_) => {}
                Err(e) => return Ok(Err(e)),
            }
        }
        return Ok(Ok(old_address));
    }
    if !maymove {
        return Ok(Err(VmError::Linux(Errno::ENOMEM)));
    }
    let Ok(copy_len) = usize::try_from(old_len.min(new_len)) else {
        return Ok(Err(VmError::Linux(Errno::ENOMEM)));
    };
    let old_bytes = match copy_user_pages_to_vec(old_address, copy_len) {
        Ok(b) => b,
        Err(e) => return Ok(Err(VmError::Linux(e))),
    };
    let target_addr = if fixed { new_address } else { 0 };
    let map_flags = MAP_PRIVATE | MAP_ANONYMOUS | if fixed { MAP_FIXED } else { 0 };
    let new_va = match super::live_vm::handle_step31_dynamic_mmap(
        target_addr,
        new_size,
        PROT_READ | PROT_WRITE,
        map_flags,
        u64::MAX,
        0,
        MmapFileBacking::Anonymous,
    )? {
        Ok(va) => va,
        Err(e) => return Ok(Err(e)),
    };
    let mut off = 0usize;
    while off < copy_len {
        let chunk = (copy_len - off).min(4096);
        if let Err(e) =
            kernal_usercopy_aarch64::copy_to_user(new_va + off as u64, &old_bytes[off..off + chunk])
        {
            return Ok(Err(VmError::Linux(super::map_usercopy_errno(e))));
        }
        off += chunk;
    }
    match super::live_vm::handle(MinimumRuntimeCall::Munmap {
        address: old_address,
        length: old_len,
    })? {
        Ok(_) => {}
        Err(e) => return Ok(Err(e)),
    }
    Ok(Ok(new_va))
}

/// Handles glibc `_Fork`/`fork` (`CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD`) and
/// `__vfork` (`CLONE_VM | CLONE_VFORK | SIGCHLD` with `child_stack == caller sp_el0`) via the
/// canonical private-fork owner transaction for unmodified Debian userspace.
#[cfg(all(
    target_arch = "aarch64",
    target_os = "none",
    feature = "step31-debian-qemu"
))]
pub(super) fn try_handle_debian_process_clone(
    request: SyscallRequest,
    frame: &mut kernal_exceptions_aarch64::ExceptionFrame,
) -> Option<bool> {
    use kernal_linux_clone::{
        CLONE_CHILD_CLEARTID, FORK_PROCESS_FLAGS, LINUX_SIGCHLD, ProcessClonePlan,
        VFORK_PROCESS_FLAGS,
    };

    const CLONE_PIDFD: u64 = 0x0000_1000;
    const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
    const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
    const CLONE_NAMESPACES_MASK: u64 = 0x7e02_0000;
    const GLIBC_FORK_FLAGS: u64 = LINUX_SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;

    if request.number != 220 {
        return None;
    }

    let flags = request.args[0];
    if (flags & CLONE_NAMESPACES_MASK) != 0 {
        // systemd uses unprivileged fallback paths (`EPERM`) when namespace isolation is denied.
        frame.x[0] = SyscallReturn::error(Errno::EPERM).as_u64_bits();
        return Some(true);
    }
    let want_pidfd = (flags & CLONE_PIDFD) != 0;
    if want_pidfd && (flags & CLONE_PARENT_SETTID) != 0 {
        frame.x[0] = SyscallReturn::error(Errno::EINVAL).as_u64_bits();
        return Some(true);
    }
    let child_stack = request.args[1];
    let parent_tid = request.args[2];
    let child_tid = request.args[4];
    if want_pidfd {
        if !parent_tid.is_multiple_of(4) {
            frame.x[0] = SyscallReturn::error(Errno::EINVAL).as_u64_bits();
            return Some(true);
        }
        if parent_tid == 0 || kernal_usercopy::UserRange::new(parent_tid, 4).is_err() {
            frame.x[0] = SyscallReturn::error(Errno::EFAULT).as_u64_bits();
            return Some(true);
        }
    }
    let base_flags = flags & !CLONE_PIDFD;

    let (child_tid_set, child_tid_clear, child_stack_override) =
        if base_flags == VFORK_PROCESS_FLAGS {
            let sp_override = if child_stack != 0 && child_stack != frame.sp_el0 {
                if !child_stack.is_multiple_of(16)
                    || child_stack
                        .checked_sub(16)
                        .is_none_or(|base| kernal_usercopy::UserRange::new(base, 16).is_err())
                {
                    frame.x[0] = SyscallReturn::error(Errno::EINVAL).as_u64_bits();
                    return Some(true);
                }
                Some(child_stack)
            } else {
                None
            };
            (None, None, sp_override)
        } else if matches!(
            base_flags,
            f if f == GLIBC_FORK_FLAGS
                || f == (LINUX_SIGCHLD | CLONE_CHILD_SETTID)
                || f == (LINUX_SIGCHLD | CLONE_CHILD_CLEARTID)
                || f == LINUX_SIGCHLD
        ) {
            let need_tid = (base_flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)) != 0;
            if child_stack != 0
                || (need_tid
                    && (!child_tid.is_multiple_of(4)
                        || kernal_usercopy::UserRange::new(child_tid, 4).is_err()))
            {
                frame.x[0] = SyscallReturn::error(Errno::EINVAL).as_u64_bits();
                return Some(true);
            }
            (
                (base_flags & CLONE_CHILD_SETTID != 0).then_some(child_tid),
                (base_flags & CLONE_CHILD_CLEARTID != 0).then_some(child_tid),
                None,
            )
        } else {
            return None;
        };

    let Ok(fork_plan) = ProcessClonePlan::validate(FORK_PROCESS_FLAGS, 0, 0, 0, 0) else {
        return Some(false);
    };
    let current_cpu = super::super::current_cpu_index();
    let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) else {
        return Some(false);
    };
    // SAFETY: lower-EL synchronous SVC owns this CPU's IRQ-masked scheduler window.
    let Ok(parent_thread) = (unsafe { scheduler.bootstrap_current_global_thread() }) else {
        return Some(false);
    };
    if usize::from(parent_thread.cpu.0) != current_cpu {
        return Some(false);
    }

    // SAFETY: same synchronous IRQ-masked SVC window and validated parent generation as Step 30 fork.
    let Ok(published) = (unsafe {
        super::live_vm::fork_process_with_tid_options(
            frame,
            parent_thread,
            fork_plan,
            scheduler,
            super::super::SMOKE_WORKER_PRIORITY,
            child_tid_set,
            child_tid_clear,
            child_stack_override,
        )
    }) else {
        frame.x[0] = SyscallReturn::error(Errno::EAGAIN).as_u64_bits();
        return Some(true);
    };
    if want_pidfd {
        let Ok((parent_process, _, _)) = current_process_identity() else {
            return Some(false);
        };
        let pidfd = match super::step35_events_cgroup::open_pidfd_for_process(
            parent_process,
            published.child_pid().get(),
        ) {
            Ok(fd) => fd,
            Err(errno) => {
                frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
                return Some(true);
            }
        };
        if let Err(err) = kernal_usercopy_aarch64::copy_to_user(parent_tid, &pidfd.to_le_bytes()) {
            let Ok(errno) = map_usercopy_error(err) else {
                return Some(false);
            };
            frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
            return Some(true);
        }
    }
    frame.x[0] = u64::from(published.child_pid().get());
    super::arm_step30_post_fork_reschedule_trace();
    if let Some(serial) = super::step15_svc_trace_serial() {
        serial.write_str("KERNAL/ARM64: Step 31 Debian fork/vfork parent result=");
        serial.write_hex_u64(frame.x[0]);
        serial.write_str("\n");
    }
    Some(true)
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "none",
    feature = "step31-debian-qemu"
))]
fn read_user_futex_word(user_address: u64) -> Result<Result<u32, Errno>, ()> {
    if !user_address.is_multiple_of(4) {
        return Ok(Err(Errno::EINVAL));
    }
    let mut raw = [0u8; 4];
    match kernal_usercopy_aarch64::copy_from_user(&mut raw, user_address) {
        Ok(()) => Ok(Ok(u32::from_le_bytes(raw))),
        Err(err) => Ok(Err(map_usercopy_error(err)?)),
    }
}

/// Normalizes unmodified Debian ARM64 futex requests (`FUTEX_WAIT[_BITSET]`, `FUTEX_WAKE[_BITSET]`,
/// with or without `FUTEX_PRIVATE_FLAG` and/or `FUTEX_CLOCK_REALTIME`) into Step-15 private futex
/// calls when untimed, and executes bounded timed waits with real deadline accounting.
#[cfg(all(
    target_arch = "aarch64",
    target_os = "none",
    feature = "step31-debian-qemu"
))]
pub(super) fn try_prepare_debian_futex(
    request: SyscallRequest,
    frame: &mut kernal_exceptions_aarch64::ExceptionFrame,
) -> Result<Option<kernal_linux_abi::MinimumRuntimeCall>, ()> {
    let user_address = request.args[0];
    let op = request.args[1];
    let value = request.args[2];
    let timeout = request.args[3];
    let user_address2 = request.args[4];
    let value3 = request.args[5];

    let (is_relative, is_realtime) =
        match kernal_linux_futex_trap_aarch64::classify_debian_futex(op, timeout, value3) {
            Ok(kernal_linux_futex_trap_aarch64::DebianFutexPlan::ForwardMinimum {
                operation,
                timeout_or_val2,
            }) => {
                return Ok(Some(kernal_linux_abi::MinimumRuntimeCall::Futex {
                    user_address,
                    operation,
                    value,
                    timeout_or_val2,
                    user_address2,
                    value3,
                }));
            }
            Ok(kernal_linux_futex_trap_aarch64::DebianFutexPlan::TimedWait {
                is_relative,
                is_realtime,
            }) => (is_relative, is_realtime),
            Err(errno) => {
                frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
                return Ok(None);
            }
        };

    let mut raw_ts = [0u8; 16];
    if let Err(err) = kernal_usercopy_aarch64::copy_from_user(&mut raw_ts, timeout) {
        let errno = map_usercopy_error(err)?;
        frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
        return Ok(None);
    }
    let tv_sec = i64::from_le_bytes(raw_ts[..8].try_into().map_err(|_| ())?);
    let tv_nsec = i64::from_le_bytes(raw_ts[8..16].try_into().map_err(|_| ())?);
    let monotonic_now_ns = if is_relative {
        kernal_timer_aarch64::monotonic_now_ns().map_err(|_| ())?
    } else {
        0
    };
    let rtc_base_seconds = if is_realtime {
        super::step42_hardware::rtc_epoch_base_seconds()
    } else {
        0
    };
    let deadline_ns = match kernal_linux_futex_trap_aarch64::compute_debian_futex_deadline_ns(
        is_relative,
        is_realtime,
        tv_sec,
        tv_nsec,
        monotonic_now_ns,
        rtc_base_seconds,
    ) {
        Ok(deadline) => deadline,
        Err(errno) => {
            frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
            return Ok(None);
        }
    };

    let current_val = match read_user_futex_word(user_address)? {
        Ok(v) => v,
        Err(errno) => {
            frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
            return Ok(None);
        }
    };
    if current_val != value as u32 {
        frame.x[0] = SyscallReturn::error(Errno::EAGAIN).as_u64_bits();
        return Ok(None);
    }

    loop {
        let now = kernal_timer_aarch64::monotonic_now_ns().map_err(|_| ())?;
        if now >= deadline_ns {
            frame.x[0] = SyscallReturn::error(Errno::ETIMEDOUT).as_u64_bits();
            return Ok(None);
        }
        if let Some(sig_ret) = super::step35_events_cgroup::blocking_wait_step(Some(frame))? {
            frame.x[0] = sig_ret.as_u64_bits();
            return Ok(None);
        }
        let latest = match read_user_futex_word(user_address)? {
            Ok(v) => v,
            Err(errno) => {
                frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
                return Ok(None);
            }
        };
        if latest != value as u32 {
            frame.x[0] = 0;
            return Ok(None);
        }
    }
}
