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
        return if exists {
            Err(Step31Error::Linux(Errno::EPERM))
        } else {
            Err(Step31Error::Linux(Errno::ESRCH))
        };
    }

    let baseline = default_rlimit64(resource);
    if user_new_rlim != 0 {
        let mut raw_new = [0u8; RLIMIT64_BYTES];
        kernal_usercopy_aarch64::copy_from_user(&mut raw_new, user_new_rlim)
            .map_err(map_usercopy_step31)?;
        let requested = Rlimit64::from_le_bytes(raw_new)
            .validate()
            .map_err(Step31Error::Linux)?;
        if requested.rlim_max > baseline.rlim_max {
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

    validate_serial_tty_fd(process_id, fd)?;

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

        match read_segment(process_id, fd, target, iov.base, seg_len) {
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
    super::step29_runtime::with_process(process, |runtime| {
        match runtime.fds().object_kind(fd).map_err(map_fd_error)? {
            OpenObjectKind::External(
                ExternalObject::Stdin | ExternalObject::Stdout | ExternalObject::Stderr,
            ) => Ok(()),
            OpenObjectKind::File | OpenObjectKind::Directory | OpenObjectKind::Pipe => {
                Err(Step31Error::Linux(Errno::ENOTTY))
            }
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
            OpenObjectKind::External(ExternalObject::Stdin) | OpenObjectKind::Directory => {
                Err(Step31Error::Linux(Errno::EBADF))
            }
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
                    let (_, _, retained, offset, _, append) = plan;
                    let write_offset = if append {
                        overlay
                            .retained_regular_size(retained)
                            .map_err(|_| Step31Error::Invariant)?
                    } else {
                        offset
                    };
                    if let Err(overlay_err) = overlay.write_retained_regular_at(
                        retained,
                        write_offset,
                        &chunk[..take],
                        kernal_linux_vfs::MutableTimestamp::ZERO,
                    ) {
                        let errno = match overlay_err {
                            kernal_linux_vfs::OverlayError::Rooted(
                                kernal_linux_vfs::RootedMutableError::Mutable(
                                    kernal_linux_vfs::MutableError::DataExhausted
                                    | kernal_linux_vfs::MutableError::InodeExhausted,
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
                    fds.commit_write(plan, write_offset, take)
                        .map_err(|_| Step31Error::Invariant)?;
                    copied += take;
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
) -> Result<usize, Step31Error> {
    let _ = (process, fd, user_base, seg_len);
    match target {
        ReadTargetKind::SerialStdinEof => Ok(0),
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
            let read_bytes = match read_bytes {
                Ok(n) => usize::try_from(n).map_err(|_| Step31Error::Invariant)?,
                Err(super::step29_pipe_io::Error::BlockingWaitRequired) => {
                    return Err(Step31Error::Linux(Errno::EAGAIN));
                }
                Err(super::step29_pipe_io::Error::Linux(errno)) => {
                    return Err(Step31Error::Linux(errno));
                }
                Err(super::step29_pipe_io::Error::Invariant) => return Err(Step31Error::Invariant),
            };
            if read_bytes != 0 {
                super::futex::pipe_blocking::notify_after_read(endpoint.pipe())
                    .map_err(|_| Step31Error::Invariant)?;
            }
            Ok(read_bytes)
        }
        #[cfg(feature = "step29-qemu-proof")]
        ReadTargetKind::File => super::step29_runtime::with_process(process, |runtime| {
            if runtime.fds().retained_readonly(fd).is_ok() {
                let (fds, overlay) = runtime.fd_overlay_parts();
                let plan = fds
                    .prepare_retained_read(fd, seg_len)
                    .map_err(map_fd_error)?;
                let (_, _, handle, start_offset, max_len) = plan;
                let slice = overlay
                    .read_open_at(handle, start_offset, max_len)
                    .map_err(|_| Step31Error::Invariant)?;
                let progress = kernal_usercopy_aarch64::copy_to_user_progress(user_base, slice)
                    .map_err(map_usercopy_step31)?;
                fds.commit_retained_read(plan, progress.copied())
                    .map_err(map_fd_error)?;
                if progress.copied() == 0 && progress.faulted() {
                    return Err(Step31Error::Linux(Errno::EFAULT));
                }
                return Ok(progress.copied());
            }
            if runtime.fds().writable_regular(fd).is_ok() {
                let (fds, overlay) = runtime.fd_overlay_parts();
                let plan = fds
                    .prepare_writable_read(fd, seg_len)
                    .map_err(map_fd_error)?;
                let (_, _, retained, start_offset, max_len) = plan;
                let slice = overlay
                    .read_retained_regular_at(retained, start_offset, max_len)
                    .map_err(|_| Step31Error::Invariant)?;
                let progress = kernal_usercopy_aarch64::copy_to_user_progress(user_base, slice)
                    .map_err(map_usercopy_step31)?;
                fds.commit_writable_read(plan, progress.copied())
                    .map_err(map_fd_error)?;
                if progress.copied() == 0 && progress.faulted() {
                    return Err(Step31Error::Linux(Errno::EFAULT));
                }
                return Ok(progress.copied());
            }
            let (initrd, root_id, fds) = runtime.parts();
            let plan = fds.prepare_read(fd, seg_len).map_err(map_fd_error)?;
            let progress = initrd
                .with_bytes(|bytes| {
                    let archive =
                        kernal_cpio::Archive::parse(bytes).map_err(|_| Step31Error::Invariant)?;
                    let root = kernal_linux_vfs::InitramfsRoot::new(archive, root_id);
                    let source = root
                        .read_at(plan.file(), plan.start_offset(), plan.len())
                        .map_err(|_| Step31Error::Invariant)?;
                    kernal_usercopy_aarch64::copy_to_user_progress(user_base, source)
                        .map_err(map_usercopy_step31)
                })
                .map_err(|_| Step31Error::Invariant)??;
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
        UsercopyError::NullPointer
        | UsercopyError::AddressOverflow
        | UsercopyError::OutsideUserRange
        | UsercopyError::PageFault => Ok(Errno::EFAULT),
        UsercopyError::LengthExceedsMaximum | UsercopyError::PrivilegeAccessNotDisabled => Err(()),
    }
}

/// Routes Step-31 dynamic linker `mmap(2)` requests (`MAP_FIXED`, `MAP_DENYWRITE`, `PROT_NONE`,
/// `PROT_EXEC`, or file-backed `MAP_PRIVATE`) through the Step-31 VM transaction owner while
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
            address, length, protection, flags, fd, offset,
        ))
    }
}

#[cfg(feature = "step29-qemu-proof")]
fn handle_file_backed_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    raw_fd: u64,
    offset: u64,
) -> Result<Result<u64, kernal_linux_vm::Error>, ()> {
    use kernal_linux_abi::linux_signed_int;
    use kernal_linux_fd::O_ACCMODE;
    use kernal_linux_fd::O_WRONLY;
    use kernal_linux_vfs::{InitramfsRoot, NodeKind, OverlayNodeHandle};
    use kernal_linux_vm::{Error as VmError, MmapFileBacking};

    let process = match current_process_id() {
        Ok(id) => id,
        Err(_) => return Err(()),
    };
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
    initrd
        .with_bytes(|archive_bytes| {
            let archive = kernal_cpio::Archive::parse(archive_bytes).map_err(|_| ())?;
            let root = InitramfsRoot::new(archive, root_id);
            let file_bytes = root.read_at(file, 0, usize::MAX).map_err(|_| ())?;
            super::live_vm::handle_step31_dynamic_mmap(
                address,
                length,
                protection,
                flags,
                raw_fd,
                offset,
                MmapFileBacking::FileSlice {
                    bytes: file_bytes,
                    file_offset: offset,
                },
            )
        })
        .map_err(|_| ())?
}
