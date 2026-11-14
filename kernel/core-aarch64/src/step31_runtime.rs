// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_aarch64_abi::classify_step31_glibc;
use kernal_linux_abi::{
    Errno, Step31GlibcCall, SyscallRequest, SyscallReturn, decode_getrandom_flags,
};
use kernal_usercopy::Error as UsercopyError;

/// Linux `getrandom(2)` single-call transfer ceiling (`32 MiB - 1`, matching Linux random driver).
const GETRANDOM_MAX_TOTAL_BYTES: usize = 0x01ff_ffff;
const GETRANDOM_CHUNK_BYTES: usize = 256;

/// Dispatches Step-31 dynamic glibc startup syscalls (`getrandom` and `rseq`).
///
/// - `getrandom(2)` validates flags (`GRND_NONBLOCK`, `GRND_RANDOM`, `GRND_INSECURE`), generates
///   forward-secure ChaCha20 random bytes from the DTB-seeded CSPRNG owner, and copies them through
///   the audited AArch64 PAN-enforced usercopy boundary.
/// - `rseq(2)` explicitly returns `-ENOSYS` per `docs/debian13/step31/glibc-oracle.json`
///   (`optional_with_enosys_fallback: ["rseq"]`, `fake_success: false`).
pub(super) fn handle(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    let Some(call) = classify_step31_glibc(request) else {
        return Ok(None);
    };

    match call {
        Step31GlibcCall::Rseq { .. } => Ok(Some(SyscallReturn::error(Errno::ENOSYS))),
        Step31GlibcCall::Getrandom {
            user_buffer,
            count,
            flags,
        } => {
            let decoded_flags = match decode_getrandom_flags(flags) {
                Ok(decoded) => decoded,
                Err(errno) => return Ok(Some(SyscallReturn::error(errno))),
            };

            let target_len = usize::try_from(count)
                .unwrap_or(GETRANDOM_MAX_TOTAL_BYTES)
                .min(GETRANDOM_MAX_TOTAL_BYTES);
            if target_len == 0 {
                return Ok(Some(SyscallReturn::success(0).ok_or(())?));
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
                            Ok(Some(SyscallReturn::error(Errno::EFAULT)))
                        } else {
                            let written = i64::try_from(copied).map_err(|_| ())?;
                            Ok(Some(SyscallReturn::success(written).ok_or(())?))
                        };
                    }
                };

                if let Err(entropy_error) = super::entropy::fill_getrandom(&mut chunk[..take]) {
                    chunk.fill(0);
                    return match entropy_error {
                        super::entropy::Error::MissingSeed if decoded_flags.nonblock() => {
                            Ok(Some(SyscallReturn::error(Errno::EAGAIN)))
                        }
                        _ => Err(()),
                    };
                }

                if let Err(copy_error) =
                    kernal_usercopy_aarch64::copy_to_user(dest_addr, &chunk[..take])
                {
                    chunk.fill(0);
                    return match map_usercopy_error(copy_error) {
                        Ok(errno) => {
                            if copied == 0 {
                                Ok(Some(SyscallReturn::error(errno)))
                            } else {
                                let written = i64::try_from(copied).map_err(|_| ())?;
                                Ok(Some(SyscallReturn::success(written).ok_or(())?))
                            }
                        }
                        Err(()) => Err(()),
                    };
                }

                copied += take;
            }
            chunk.fill(0);

            let written = i64::try_from(copied).map_err(|_| ())?;
            Ok(Some(SyscallReturn::success(written).ok_or(())?))
        }
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
