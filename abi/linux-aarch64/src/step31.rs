// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::{Step31GlibcCall, SyscallRequest};

/// Linux arm64 syscall-number anchors for the Step-31 dynamic glibc and coreutil startup surface.
pub mod nr {
    pub const IOCTL: u64 = 29;
    pub const READV: u64 = 65;
    pub const WRITEV: u64 = 66;
    pub const UNAME: u64 = 160;
    pub const PRLIMIT64: u64 = 261;
    pub const GETRANDOM: u64 = 278;
    pub const RSEQ: u64 = 293;
}

/// Classifies the Step-31 Linux arm64 dynamic glibc and coreutil startup syscall-number surface.
///
/// Raw register values are preserved without validation or dereference. `Getrandom`, `Uname`,
/// `Prlimit64`, `Ioctl`, `Readv`, and `Writev` are routed to their audited usercopy and runtime
/// owners, while `Rseq` is explicitly recognized so the runtime can enforce the Step-31
/// `glibc-oracle.json` `-ENOSYS` fallback contract without fake success.
pub fn classify_step31_glibc(request: SyscallRequest) -> Option<Step31GlibcCall> {
    let a = request.args;
    match request.number {
        nr::IOCTL => Some(Step31GlibcCall::Ioctl {
            fd: a[0],
            request: a[1],
            arg: a[2],
        }),
        nr::READV => Some(Step31GlibcCall::Readv {
            fd: a[0],
            user_iov: a[1],
            iovcnt: a[2],
        }),
        nr::WRITEV => Some(Step31GlibcCall::Writev {
            fd: a[0],
            user_iov: a[1],
            iovcnt: a[2],
        }),
        nr::UNAME => Some(Step31GlibcCall::Uname { user_utsname: a[0] }),
        nr::PRLIMIT64 => Some(Step31GlibcCall::Prlimit64 {
            pid: a[0],
            resource: a[1],
            user_new_rlim: a[2],
            user_old_rlim: a[3],
        }),
        nr::GETRANDOM => Some(Step31GlibcCall::Getrandom {
            user_buffer: a[0],
            count: a[1],
            flags: a[2],
        }),
        nr::RSEQ => Some(Step31GlibcCall::Rseq {
            rseq_abi: a[0],
            rseq_len: a[1],
            flags: a[2],
            sig: a[3],
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        classify_minimum_runtime, classify_path_fd, classify_step30_runtime, decode_registers,
        nr as base_nr, step30_nr,
    };
    use kernal_linux_abi::{Errno, SyscallReturn, unsupported};

    #[test]
    fn step31_arm64_numbers_match_linux_uapi() {
        assert_eq!(nr::IOCTL, 29);
        assert_eq!(nr::READV, 65);
        assert_eq!(nr::WRITEV, 66);
        assert_eq!(nr::UNAME, 160);
        assert_eq!(nr::PRLIMIT64, 261);
        assert_eq!(nr::GETRANDOM, 278);
        assert_eq!(nr::RSEQ, 293);
    }

    #[test]
    fn step31_classifier_preserves_register_argument_order() {
        let mut regs = [0u64; 31];
        regs[0] = 0x1000_2000;
        regs[1] = 32;
        regs[2] = 0x0001;
        regs[3] = 0x55aa_55aa;
        regs[8] = nr::GETRANDOM;
        assert_eq!(
            classify_step31_glibc(decode_registers(&regs)),
            Some(Step31GlibcCall::Getrandom {
                user_buffer: 0x1000_2000,
                count: 32,
                flags: 0x0001,
            })
        );

        regs[8] = nr::IOCTL;
        assert_eq!(
            classify_step31_glibc(decode_registers(&regs)),
            Some(Step31GlibcCall::Ioctl {
                fd: 0x1000_2000,
                request: 32,
                arg: 0x0001,
            })
        );

        regs[8] = nr::READV;
        assert_eq!(
            classify_step31_glibc(decode_registers(&regs)),
            Some(Step31GlibcCall::Readv {
                fd: 0x1000_2000,
                user_iov: 32,
                iovcnt: 0x0001,
            })
        );

        regs[8] = nr::WRITEV;
        assert_eq!(
            classify_step31_glibc(decode_registers(&regs)),
            Some(Step31GlibcCall::Writev {
                fd: 0x1000_2000,
                user_iov: 32,
                iovcnt: 0x0001,
            })
        );

        regs[8] = nr::UNAME;
        assert_eq!(
            classify_step31_glibc(decode_registers(&regs)),
            Some(Step31GlibcCall::Uname {
                user_utsname: 0x1000_2000,
            })
        );

        regs[8] = nr::PRLIMIT64;
        assert_eq!(
            classify_step31_glibc(decode_registers(&regs)),
            Some(Step31GlibcCall::Prlimit64 {
                pid: 0x1000_2000,
                resource: 32,
                user_new_rlim: 0x0001,
                user_old_rlim: 0x55aa_55aa,
            })
        );

        regs[8] = nr::RSEQ;
        let rseq_req = decode_registers(&regs);
        assert_eq!(
            classify_step31_glibc(rseq_req),
            Some(Step31GlibcCall::Rseq {
                rseq_abi: 0x1000_2000,
                rseq_len: 32,
                flags: 0x0001,
                sig: 0x55aa_55aa,
            })
        );
        assert_eq!(unsupported(rseq_req), SyscallReturn::error(Errno::ENOSYS));
    }

    #[test]
    fn step31_glibc_oracle_bootstrap_syscalls_are_anchored_and_classified() {
        let args = [1, 2, 3, 4, 5, 6];
        assert!(classify_minimum_runtime(SyscallRequest::new(base_nr::BRK, args)).is_some());
        assert!(classify_path_fd(SyscallRequest::new(base_nr::CLOSE, args)).is_some());
        assert!(classify_minimum_runtime(SyscallRequest::new(base_nr::FUTEX, args)).is_some());
        assert!(classify_step31_glibc(SyscallRequest::new(nr::GETRANDOM, args)).is_some());
        assert!(classify_step31_glibc(SyscallRequest::new(nr::IOCTL, args)).is_some());
        assert!(classify_step31_glibc(SyscallRequest::new(nr::READV, args)).is_some());
        assert!(classify_step31_glibc(SyscallRequest::new(nr::WRITEV, args)).is_some());
        assert!(classify_step31_glibc(SyscallRequest::new(nr::UNAME, args)).is_some());
        assert!(classify_step31_glibc(SyscallRequest::new(nr::PRLIMIT64, args)).is_some());
        assert!(classify_minimum_runtime(SyscallRequest::new(base_nr::MMAP, args)).is_some());
        assert!(classify_minimum_runtime(SyscallRequest::new(base_nr::MPROTECT, args)).is_some());
        assert!(classify_minimum_runtime(SyscallRequest::new(base_nr::MUNMAP, args)).is_some());
        assert!(classify_path_fd(SyscallRequest::new(base_nr::OPENAT, args)).is_some());
        assert!(classify_path_fd(SyscallRequest::new(base_nr::READ, args)).is_some());
        assert!(
            classify_step30_runtime(SyscallRequest::new(step30_nr::SET_ROBUST_LIST, args))
                .is_some()
        );
        assert!(
            classify_step30_runtime(SyscallRequest::new(step30_nr::SET_TID_ADDRESS, args))
                .is_some()
        );
        assert!(classify_step31_glibc(SyscallRequest::new(nr::RSEQ, args)).is_some());
    }
}
