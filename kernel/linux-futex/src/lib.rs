// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_linux_abi::Errno;

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
pub const FUTEX_WAIT_PRIVATE: u32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAKE_PRIVATE: u32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAIT_BITSET: u32 = 9;
pub const FUTEX_WAKE_BITSET: u32 = 10;

/// Normalized execution plan for unmodified Debian ARM64 `futex(2)` calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebianFutexPlan {
    /// Forward an untimed (or unsupported) operation to the Step-15 minimum runtime.
    ForwardMinimum {
        operation: u64,
        timeout_or_val2: u64,
    },
    /// Execute a timed wait against either a relative timeout (`FUTEX_WAIT`) or an absolute
    /// monotonic / realtime deadline (`FUTEX_WAIT_BITSET`).
    TimedWait {
        is_relative: bool,
        is_realtime: bool,
    },
}

/// Classifies an unmodified Debian ARM64 `futex(2)` request and normalizes supported shared,
/// untimed-bitset, and timed-wait variants.
pub const fn classify_debian_futex(
    operation: u64,
    timeout_or_val2: u64,
    value3: u64,
) -> Result<DebianFutexPlan, Errno> {
    let base_op = operation & !(FUTEX_PRIVATE_FLAG as u64 | FUTEX_CLOCK_REALTIME as u64);
    let is_realtime = (operation & FUTEX_CLOCK_REALTIME as u64) != 0;

    if (base_op == FUTEX_WAKE as u64 || base_op == FUTEX_WAKE_BITSET as u64) && !is_realtime {
        if base_op == FUTEX_WAKE_BITSET as u64 && (value3 as u32) == 0 {
            return Err(Errno::EINVAL);
        }
        if base_op == FUTEX_WAKE_BITSET as u64 || operation == FUTEX_WAKE as u64 {
            return Ok(DebianFutexPlan::ForwardMinimum {
                operation: FUTEX_WAKE_PRIVATE as u64,
                timeout_or_val2: 0,
            });
        }
    }

    let is_supported_wait =
        (base_op == FUTEX_WAIT as u64 && !is_realtime) || base_op == FUTEX_WAIT_BITSET as u64;
    if !is_supported_wait {
        return Ok(DebianFutexPlan::ForwardMinimum {
            operation,
            timeout_or_val2,
        });
    }

    if base_op == FUTEX_WAIT_BITSET as u64 && (value3 as u32) == 0 {
        return Err(Errno::EINVAL);
    }

    if timeout_or_val2 == 0 {
        return Ok(DebianFutexPlan::ForwardMinimum {
            operation: FUTEX_WAIT_PRIVATE as u64,
            timeout_or_val2: 0,
        });
    }

    Ok(DebianFutexPlan::TimedWait {
        is_relative: base_op == FUTEX_WAIT as u64,
        is_realtime,
    })
}

/// Validates a Linux `timespec` pair and computes the matching monotonic deadline in nanoseconds.
pub const fn compute_debian_futex_deadline_ns(
    is_relative: bool,
    is_realtime: bool,
    tv_sec: i64,
    tv_nsec: i64,
    monotonic_now_ns: u64,
    rtc_base_seconds: u64,
) -> Result<u64, Errno> {
    if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
        return Err(Errno::EINVAL);
    }
    let spec_ns = (tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(tv_nsec as u64);
    if is_relative {
        Ok(monotonic_now_ns.saturating_add(spec_ns))
    } else if !is_realtime {
        Ok(spec_ns)
    } else {
        let base_ns = rtc_base_seconds.saturating_mul(1_000_000_000);
        Ok(spec_ns.saturating_sub(base_ns))
    }
}

/// Authority-free Step-15 subset of the Linux futex operation contract.
///
/// This type deliberately owns no usercopy, FutexTable, scheduler or wake-mailbox authority. It
/// only validates the raw Linux scalar operation needed by the unchanged musl pthread proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MinimumFutexCall {
    /// Process-private wait with no timeout. The runtime must atomically compare the futex word to
    /// `expected` immediately before `FutexTable::prepare_wait` under its external serialization.
    WaitPrivate { expected: u32 },
    /// Process-private wake of at most `maximum` matching waiters.
    WakePrivate { maximum: u32 },
}

/// Decodes the raw Linux `futex` operation/value pair into the deliberately narrow Step-15 subset.
///
/// Only `FUTEX_WAIT_PRIVATE` with a null timeout and `FUTEX_WAKE_PRIVATE` are accepted. Shared
/// futexes, timed waits, CLOCK_REALTIME, PI, requeue and bitset operations remain outside Step 15 and
/// fail with `ENOSYS` instead of silently approximating Linux semantics.
pub const fn decode_minimum(
    operation: u64,
    value: u64,
    timeout_or_value2: u64,
) -> Result<MinimumFutexCall, Errno> {
    match operation {
        op if op == FUTEX_WAIT_PRIVATE as u64 => {
            if timeout_or_value2 != 0 {
                return Err(Errno::ENOSYS);
            }
            Ok(MinimumFutexCall::WaitPrivate {
                expected: value as u32,
            })
        }
        op if op == FUTEX_WAKE_PRIVATE as u64 => {
            // Linux treats the wake count as a signed int internally. Step 15 rejects values that
            // would become negative rather than widening the contract around nonsensical counts.
            if value > i32::MAX as u64 {
                return Err(Errno::EINVAL);
            }
            Ok(MinimumFutexCall::WakePrivate {
                maximum: value as u32,
            })
        }
        _ => Err(Errno::ENOSYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_private_operation_numbers_match_uapi() {
        assert_eq!(FUTEX_WAIT, 0);
        assert_eq!(FUTEX_WAKE, 1);
        assert_eq!(FUTEX_PRIVATE_FLAG, 128);
        assert_eq!(FUTEX_CLOCK_REALTIME, 256);
        assert_eq!(FUTEX_WAIT_PRIVATE, 128);
        assert_eq!(FUTEX_WAKE_PRIVATE, 129);
    }

    #[test]
    fn private_untimed_wait_preserves_expected_u32() {
        assert_eq!(
            decode_minimum(FUTEX_WAIT_PRIVATE as u64, 0x1_7856_3412, 0),
            Ok(MinimumFutexCall::WaitPrivate {
                expected: 0x7856_3412
            })
        );
    }

    #[test]
    fn timed_wait_is_not_silently_approximated() {
        assert_eq!(
            decode_minimum(FUTEX_WAIT_PRIVATE as u64, 7, 0x1000),
            Err(Errno::ENOSYS)
        );
    }

    #[test]
    fn private_wake_accepts_nonnegative_signed_count_domain() {
        assert_eq!(
            decode_minimum(FUTEX_WAKE_PRIVATE as u64, 1, u64::MAX),
            Ok(MinimumFutexCall::WakePrivate { maximum: 1 })
        );
        assert_eq!(
            decode_minimum(FUTEX_WAKE_PRIVATE as u64, i32::MAX as u64, 0),
            Ok(MinimumFutexCall::WakePrivate {
                maximum: i32::MAX as u32
            })
        );
        assert_eq!(
            decode_minimum(FUTEX_WAKE_PRIVATE as u64, i32::MAX as u64 + 1, 0),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn shared_and_broader_futex_operations_remain_out_of_scope() {
        for operation in [
            FUTEX_WAIT as u64,
            FUTEX_WAKE as u64,
            (FUTEX_WAIT_PRIVATE | FUTEX_CLOCK_REALTIME) as u64,
            3,
            u64::MAX,
        ] {
            assert_eq!(decode_minimum(operation, 0, 0), Err(Errno::ENOSYS));
        }
    }

    #[test]
    fn debian_futex_classification_normalizes_shared_bitset_and_timed_waits() {
        assert_eq!(
            classify_debian_futex(FUTEX_WAIT as u64, 0, 0),
            Ok(DebianFutexPlan::ForwardMinimum {
                operation: FUTEX_WAIT_PRIVATE as u64,
                timeout_or_val2: 0,
            })
        );
        assert_eq!(
            classify_debian_futex(FUTEX_WAKE as u64, u64::MAX, 0),
            Ok(DebianFutexPlan::ForwardMinimum {
                operation: FUTEX_WAKE_PRIVATE as u64,
                timeout_or_val2: 0,
            })
        );
        assert_eq!(
            classify_debian_futex((FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG) as u64, 0, 0x4,),
            Ok(DebianFutexPlan::ForwardMinimum {
                operation: FUTEX_WAIT_PRIVATE as u64,
                timeout_or_val2: 0,
            })
        );
        assert_eq!(
            classify_debian_futex(FUTEX_WAKE_BITSET as u64, 0x100, 0xffff_ffff),
            Ok(DebianFutexPlan::ForwardMinimum {
                operation: FUTEX_WAKE_PRIVATE as u64,
                timeout_or_val2: 0,
            })
        );
        assert_eq!(
            classify_debian_futex(
                (FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME) as u64,
                0x2000,
                u64::from(u32::MAX),
            ),
            Ok(DebianFutexPlan::TimedWait {
                is_relative: false,
                is_realtime: true,
            })
        );
        assert_eq!(
            classify_debian_futex(FUTEX_WAIT_PRIVATE as u64, 0x2000, 0),
            Ok(DebianFutexPlan::TimedWait {
                is_relative: true,
                is_realtime: false,
            })
        );
        assert_eq!(
            classify_debian_futex(FUTEX_WAKE_PRIVATE as u64, 123, 0),
            Ok(DebianFutexPlan::ForwardMinimum {
                operation: FUTEX_WAKE_PRIVATE as u64,
                timeout_or_val2: 123,
            })
        );
        assert_eq!(
            classify_debian_futex(
                (FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME) as u64,
                0x2000,
                1u64 << 32,
            ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            classify_debian_futex(FUTEX_WAKE_BITSET as u64, 0, 0),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn debian_futex_deadline_conversion_handles_relative_monotonic_and_realtime() {
        assert_eq!(
            compute_debian_futex_deadline_ns(true, false, 1, 250_000_000, 5_000_000_000, 100),
            Ok(6_250_000_000)
        );
        assert_eq!(
            compute_debian_futex_deadline_ns(false, false, 2, 500, 999, 100),
            Ok(2_000_000_500)
        );
        assert_eq!(
            compute_debian_futex_deadline_ns(false, true, 1700, 1000, 0, 1690),
            Ok(10_000_001_000)
        );
        assert_eq!(
            compute_debian_futex_deadline_ns(false, true, 1680, 0, 0, 1690),
            Ok(0)
        );
        assert_eq!(
            compute_debian_futex_deadline_ns(true, false, -1, 0, 0, 0),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            compute_debian_futex_deadline_ns(true, false, 0, -1, 0, 0),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            compute_debian_futex_deadline_ns(true, false, 0, 1_000_000_000, 0, 0),
            Err(Errno::EINVAL)
        );
    }
}
