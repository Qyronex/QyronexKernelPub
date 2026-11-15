// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::{Errno, SyscallReturn};

pub(super) const ARM64_STAT_BYTES: usize = 128;
pub(super) const S_IFREG_MODE: u32 = 0o100_444;
pub(super) const S_IFCHR_MODE: u32 = 0o020_660;
pub(super) const S_IFBLK_MODE: u32 = 0o060_660;

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
