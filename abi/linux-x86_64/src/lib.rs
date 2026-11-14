// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_linux_abi::{Step31GlibcCall, SyscallRequest};

/// Initial Linux x86_64 syscall surface. Numeric values follow the stable x86_64 Linux ABI.
pub mod nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const CLOSE: u64 = 3;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const RT_SIGACTION: u64 = 13;
    pub const RT_SIGPROCMASK: u64 = 14;
    pub const IOCTL: u64 = 16;
    pub const READV: u64 = 19;
    pub const WRITEV: u64 = 20;
    pub const SCHED_YIELD: u64 = 24;
    pub const NANOSLEEP: u64 = 35;
    pub const GETPID: u64 = 39;
    pub const SOCKET: u64 = 41;
    pub const CONNECT: u64 = 42;
    pub const ACCEPT: u64 = 43;
    pub const SENDTO: u64 = 44;
    pub const RECVFROM: u64 = 45;
    pub const BIND: u64 = 49;
    pub const LISTEN: u64 = 50;
    pub const CLONE: u64 = 56;
    pub const EXECVE: u64 = 59;
    pub const EXIT: u64 = 60;
    pub const UNAME: u64 = 63;
    pub const ARCH_PRCTL: u64 = 158;
    pub const GETTID: u64 = 186;
    pub const FUTEX: u64 = 202;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const EXIT_GROUP: u64 = 231;
    pub const EPOLL_WAIT: u64 = 232;
    pub const EPOLL_CTL: u64 = 233;
    pub const OPENAT: u64 = 257;
    pub const NEWFSTATAT: u64 = 262;
    pub const SET_ROBUST_LIST: u64 = 273;
    pub const EPOLL_PWAIT: u64 = 281;
    pub const ACCEPT4: u64 = 288;
    pub const DUP3: u64 = 292;
    pub const PIPE2: u64 = 293;
    pub const PRLIMIT64: u64 = 302;
    pub const GETRANDOM: u64 = 318;
    pub const STATX: u64 = 332;
    pub const RSEQ: u64 = 334;
    pub const CLONE3: u64 = 435;
    pub const CLOSE_RANGE: u64 = 436;
    pub const OPENAT2: u64 = 437;
    pub const EPOLL_PWAIT2: u64 = 441;
    pub const FUTEX_WAITV: u64 = 449;
}

/// Step-31 dynamic glibc and coreutil startup syscall numbers on Linux x86_64.
pub mod step31_nr {
    pub const IOCTL: u64 = super::nr::IOCTL;
    pub const READV: u64 = super::nr::READV;
    pub const WRITEV: u64 = super::nr::WRITEV;
    pub const UNAME: u64 = super::nr::UNAME;
    pub const ARCH_PRCTL: u64 = super::nr::ARCH_PRCTL;
    pub const SET_TID_ADDRESS: u64 = super::nr::SET_TID_ADDRESS;
    pub const SET_ROBUST_LIST: u64 = super::nr::SET_ROBUST_LIST;
    pub const PRLIMIT64: u64 = super::nr::PRLIMIT64;
    pub const GETRANDOM: u64 = super::nr::GETRANDOM;
    pub const RSEQ: u64 = super::nr::RSEQ;
}

/// Decoded Step-31 x86_64 dynamic glibc startup syscall (either shared [`Step31GlibcCall`] or
/// x86_64-specific `arch_prctl(2)` TLS setup).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X86_64Step31Call {
    Shared(Step31GlibcCall),
    ArchPrctl { code: u64, addr: u64 },
}

/// Classifies an x86_64 [`SyscallRequest`] into the Step-31 dynamic glibc startup surface.
pub const fn classify_step31_glibc_x86_64(request: SyscallRequest) -> Option<X86_64Step31Call> {
    match request.number {
        step31_nr::IOCTL => Some(X86_64Step31Call::Shared(Step31GlibcCall::Ioctl {
            fd: request.args[0],
            request: request.args[1],
            arg: request.args[2],
        })),
        step31_nr::READV => Some(X86_64Step31Call::Shared(Step31GlibcCall::Readv {
            fd: request.args[0],
            user_iov: request.args[1],
            iovcnt: request.args[2],
        })),
        step31_nr::WRITEV => Some(X86_64Step31Call::Shared(Step31GlibcCall::Writev {
            fd: request.args[0],
            user_iov: request.args[1],
            iovcnt: request.args[2],
        })),
        step31_nr::UNAME => Some(X86_64Step31Call::Shared(Step31GlibcCall::Uname {
            user_utsname: request.args[0],
        })),
        step31_nr::PRLIMIT64 => Some(X86_64Step31Call::Shared(Step31GlibcCall::Prlimit64 {
            pid: request.args[0],
            resource: request.args[1],
            user_new_rlim: request.args[2],
            user_old_rlim: request.args[3],
        })),
        step31_nr::GETRANDOM => Some(X86_64Step31Call::Shared(Step31GlibcCall::Getrandom {
            user_buffer: request.args[0],
            count: request.args[1],
            flags: request.args[2],
        })),
        step31_nr::RSEQ => Some(X86_64Step31Call::Shared(Step31GlibcCall::Rseq {
            rseq_abi: request.args[0],
            rseq_len: request.args[1],
            flags: request.args[2],
            sig: request.args[3],
        })),
        step31_nr::ARCH_PRCTL => Some(X86_64Step31Call::ArchPrctl {
            code: request.args[0],
            addr: request.args[1],
        }),
        _ => None,
    }
}

pub mod errno {
    pub const EPERM: i64 = 1;
    pub const ENOENT: i64 = 2;
    pub const EINTR: i64 = 4;
    pub const EIO: i64 = 5;
    pub const EBADF: i64 = 9;
    pub const EAGAIN: i64 = 11;
    pub const ENOMEM: i64 = 12;
    pub const EACCES: i64 = 13;
    pub const EFAULT: i64 = 14;
    pub const EBUSY: i64 = 16;
    pub const EEXIST: i64 = 17;
    pub const ENODEV: i64 = 19;
    pub const ENOTDIR: i64 = 20;
    pub const EISDIR: i64 = 21;
    pub const EINVAL: i64 = 22;
    pub const EMFILE: i64 = 24;
    pub const ENOSPC: i64 = 28;
    pub const EPIPE: i64 = 32;
    pub const ENOSYS: i64 = 38;
    pub const ETIMEDOUT: i64 = 110;
}

pub mod prot {
    pub const NONE: u64 = 0;
    pub const READ: u64 = 1;
    pub const WRITE: u64 = 2;
    pub const EXEC: u64 = 4;
}

pub mod map {
    pub const SHARED: u64 = 0x01;
    pub const PRIVATE: u64 = 0x02;
    pub const FIXED: u64 = 0x10;
    pub const ANONYMOUS: u64 = 0x20;
    pub const STACK: u64 = 0x20_000;
    pub const FIXED_NOREPLACE: u64 = 0x10_0000;
}

pub mod arch_prctl {
    pub const SET_GS: u64 = 0x1001;
    pub const SET_FS: u64 = 0x1002;
    pub const GET_FS: u64 = 0x1003;
    pub const GET_GS: u64 = 0x1004;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallArgs {
    pub number: u64,
    pub args: [u64; 6],
}

impl SyscallArgs {
    pub const fn new(number: u64, args: [u64; 6]) -> Self {
        Self { number, args }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialSyscall {
    Read,
    Write,
    Close,
    Mmap,
    Mprotect,
    Munmap,
    Brk,
    SchedYield,
    ArchPrctl,
    Futex,
    ClockGettime,
    Exit,
    ExitGroup,
    Getpid,
    Gettid,
    Unknown(u64),
}

pub const fn decode_initial(number: u64) -> InitialSyscall {
    match number {
        nr::READ => InitialSyscall::Read,
        nr::WRITE => InitialSyscall::Write,
        nr::CLOSE => InitialSyscall::Close,
        nr::MMAP => InitialSyscall::Mmap,
        nr::MPROTECT => InitialSyscall::Mprotect,
        nr::MUNMAP => InitialSyscall::Munmap,
        nr::BRK => InitialSyscall::Brk,
        nr::SCHED_YIELD => InitialSyscall::SchedYield,
        nr::ARCH_PRCTL => InitialSyscall::ArchPrctl,
        nr::FUTEX => InitialSyscall::Futex,
        nr::CLOCK_GETTIME => InitialSyscall::ClockGettime,
        nr::EXIT => InitialSyscall::Exit,
        nr::EXIT_GROUP => InitialSyscall::ExitGroup,
        nr::GETPID => InitialSyscall::Getpid,
        nr::GETTID => InitialSyscall::Gettid,
        other => InitialSyscall::Unknown(other),
    }
}

pub const fn return_errno(errno: i64) -> i64 {
    -errno
}

pub const fn prot_is_wx(bits: u64) -> bool {
    bits & prot::WRITE != 0 && bits & prot::EXEC != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_decoder_keeps_unknown_numbers_explicit() {
        assert_eq!(decode_initial(nr::WRITE), InitialSyscall::Write);
        assert_eq!(decode_initial(0xffff), InitialSyscall::Unknown(0xffff));
    }

    #[test]
    fn linux_errors_are_returned_negative() {
        assert_eq!(return_errno(errno::EINVAL), -22);
        assert_eq!(return_errno(errno::ENOSYS), -38);
    }

    #[test]
    fn wx_requests_are_detectable_before_mapping() {
        assert!(prot_is_wx(prot::READ | prot::WRITE | prot::EXEC));
        assert!(!prot_is_wx(prot::READ | prot::EXEC));
    }

    #[test]
    fn step31_x86_64_classifier_routes_dynamic_glibc_and_arch_prctl_calls() {
        assert_eq!(
            classify_step31_glibc_x86_64(SyscallRequest::new(
                step31_nr::ARCH_PRCTL,
                [arch_prctl::SET_FS, 0x0000_7fff_ffff_e000, 0, 0, 0, 0]
            )),
            Some(X86_64Step31Call::ArchPrctl {
                code: arch_prctl::SET_FS,
                addr: 0x0000_7fff_ffff_e000,
            })
        );
        assert_eq!(
            classify_step31_glibc_x86_64(SyscallRequest::new(
                step31_nr::GETRANDOM,
                [0x1000, 32, 1, 0, 0, 0]
            )),
            Some(X86_64Step31Call::Shared(Step31GlibcCall::Getrandom {
                user_buffer: 0x1000,
                count: 32,
                flags: 1,
            }))
        );
        assert_eq!(
            classify_step31_glibc_x86_64(SyscallRequest::new(
                step31_nr::RSEQ,
                [0x2000, 32, 0, 0x5305_3053, 0, 0]
            )),
            Some(X86_64Step31Call::Shared(Step31GlibcCall::Rseq {
                rseq_abi: 0x2000,
                rseq_len: 32,
                flags: 0,
                sig: 0x5305_3053,
            }))
        );
    }
}
