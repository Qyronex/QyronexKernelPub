// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::{Errno, linux_unsigned_int};

/// Linux `getrandom(2)` flag bits (`<linux/random.h>`).
pub const GRND_NONBLOCK: u32 = 0x0001;
pub const GRND_RANDOM: u32 = 0x0002;
pub const GRND_INSECURE: u32 = 0x0004;

const GRND_KNOWN_MASK: u32 = GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE;

/// Validated Linux `getrandom(2)` flags word after low-32-bit `unsigned int` decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetrandomFlags(u32);

impl GetrandomFlags {
    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn nonblock(self) -> bool {
        self.0 & GRND_NONBLOCK != 0
    }

    pub const fn random(self) -> bool {
        self.0 & GRND_RANDOM != 0
    }

    pub const fn insecure(self) -> bool {
        self.0 & GRND_INSECURE != 0
    }
}

/// Validates Linux `getrandom(2)` flags from the low 32-bit `unsigned int` syscall register.
///
/// Unknown flag bits and the mutually exclusive `GRND_INSECURE | GRND_RANDOM` combination fail
/// closed with `EINVAL` per Linux UAPI.
pub const fn decode_getrandom_flags(raw: u64) -> Result<GetrandomFlags, Errno> {
    let bits = linux_unsigned_int(raw);
    if bits & !GRND_KNOWN_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if (bits & (GRND_INSECURE | GRND_RANDOM)) == (GRND_INSECURE | GRND_RANDOM) {
        return Err(Errno::EINVAL);
    }
    Ok(GetrandomFlags(bits))
}

/// Architecture-neutral Step-31 dynamic glibc startup syscall surface.
///
/// Variants preserve raw Linux-visible scalar register values only. `Getrandom` requires audited
/// usercopy and CSPRNG authority at the runtime execution boundary; `Rseq` is classified so the
/// runtime can explicitly enforce the Step-31 `glibc-oracle.json` `-ENOSYS` fallback contract
/// without fake success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step31GlibcCall {
    Getrandom {
        user_buffer: u64,
        count: u64,
        flags: u64,
    },
    Rseq {
        rseq_abi: u64,
        rseq_len: u64,
        flags: u64,
        sig: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getrandom_flags_decode_low_32_bits_and_reject_invalid_combinations() {
        let zero = decode_getrandom_flags(0xffff_ffff_0000_0000).unwrap();
        assert_eq!(zero.bits(), 0);
        assert!(!zero.nonblock());
        assert!(!zero.random());
        assert!(!zero.insecure());

        let nonblock_random = decode_getrandom_flags((GRND_NONBLOCK | GRND_RANDOM) as u64).unwrap();
        assert!(nonblock_random.nonblock());
        assert!(nonblock_random.random());
        assert!(!nonblock_random.insecure());

        let insecure = decode_getrandom_flags((GRND_NONBLOCK | GRND_INSECURE) as u64).unwrap();
        assert!(insecure.nonblock());
        assert!(!insecure.random());
        assert!(insecure.insecure());

        assert_eq!(
            decode_getrandom_flags((GRND_RANDOM | GRND_INSECURE) as u64),
            Err(Errno::EINVAL)
        );
        assert_eq!(decode_getrandom_flags(0x0008), Err(Errno::EINVAL));
    }
}
