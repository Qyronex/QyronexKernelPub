// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::{Step31GlibcCall, SyscallRequest};

/// Linux arm64 syscall-number anchors for the Step-31 dynamic glibc startup surface.
pub mod nr {
    pub const GETRANDOM: u64 = 278;
    pub const RSEQ: u64 = 293;
}

/// Classifies the Step-31 Linux arm64 dynamic glibc startup syscall-number surface.
///
/// Raw register values are preserved without validation or dereference. `Getrandom` is routed to
/// the audited usercopy + entropy owner, while `Rseq` is explicitly recognized so the runtime can
/// enforce the Step-31 `glibc-oracle.json` `-ENOSYS` fallback contract without fake success.
pub fn classify_step31_glibc(request: SyscallRequest) -> Option<Step31GlibcCall> {
    let a = request.args;
    match request.number {
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
