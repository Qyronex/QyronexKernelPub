// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 39 — `dpkg`/`apt` and package-manager durability semantics:
//! - Advisory file locks: `flock(2)` (`LOCK_SH`, `LOCK_EX`, `LOCK_NB`, `LOCK_UN`) and POSIX
//!   `fcntl(2)` record locks (`F_GETLK`, `F_SETLK`, `F_SETLKW`) with range-conflict detection and
//!   bounded `ENOLCK` failure,
//! - Extended attributes (`setxattr`, `lsetxattr`, `fsetxattr`, `getxattr`, `listxattr`,
//!   `removexattr`) enforcing `ENODATA`, `ERANGE`, `EEXIST`, and namespace validation,
//! - Ownership, mode, and nanosecond timestamp preservation (`fchmod`, `fchmodat`, `fchown`,
//!   `fchownat`, `utimensat` with `UTIME_NOW` / `UTIME_OMIT`),
//! - `#!` shebang script interpreter header parser with bounded recursion depth (`ELOOP`).

use kernal_linux_abi::Errno;

/// `flock(2)` operations (`<sys/file.h>`).
pub const LOCK_SH: u32 = 1;
pub const LOCK_EX: u32 = 2;
pub const LOCK_NB: u32 = 4;
pub const LOCK_UN: u32 = 8;

/// `fcntl(2)` advisory lock commands and lock types (`<fcntl.h>`).
pub const F_GETLK: u32 = 5;
pub const F_SETLK: u32 = 6;
pub const F_SETLKW: u32 = 7;
pub const F_RDLCK: u16 = 0;
pub const F_WRLCK: u16 = 1;
pub const F_UNLCK: u16 = 2;

/// `xattr` flags (`<sys/xattr.h>`).
pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

/// `utimensat(2)` sentinel nanoseconds.
pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

/// Shebang interpreter limits (`fs/binfmt_script.c`).
pub const MAX_BINPRM_BYTES: usize = 256;
pub const MAX_SHEBANG_DEPTH: u8 = 4;

const MAX_KEY_BYTES: usize = 512;
const MAX_XATTR_NAME: usize = 64;

/// Stable key used to index advisory locks, xattrs, and metadata overrides across FDs or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetKey {
    bytes: [u8; MAX_KEY_BYTES],
    len: usize,
}

impl TargetKey {
    pub const EMPTY: Self = Self {
        bytes: [0u8; MAX_KEY_BYTES],
        len: 0,
    };

    pub fn from_path(path: &[u8]) -> Result<Self, Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        if path.len() > MAX_KEY_BYTES {
            return Err(Errno::ENAMETOOLONG);
        }
        let mut bytes = [0u8; MAX_KEY_BYTES];
        bytes[..path.len()].copy_from_slice(path);
        Ok(Self {
            bytes,
            len: path.len(),
        })
    }

    pub fn from_fd(fd: i32) -> Result<Self, Errno> {
        if fd < 0 {
            return Err(Errno::EBADF);
        }
        let mut bytes = [0u8; MAX_KEY_BYTES];
        bytes[0..3].copy_from_slice(b"fd:");
        bytes[3..7].copy_from_slice(&fd.to_le_bytes());
        Ok(Self { bytes, len: 7 })
    }

    pub fn from_ext4_inode(mount_id: u32, ino: u32) -> Self {
        let mut bytes = [0u8; MAX_KEY_BYTES];
        bytes[0..5].copy_from_slice(b"ext4:");
        bytes[5..9].copy_from_slice(&mount_id.to_le_bytes());
        bytes[9..13].copy_from_slice(&ino.to_le_bytes());
        Self { bytes, len: 13 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Decoded AArch64/Linux 64-bit `struct flock` (32 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PosixFlock {
    pub l_type: u16,
    pub l_whence: u16,
    pub l_start: i64,
    pub l_len: i64,
    pub l_pid: i32,
}

impl PosixFlock {
    pub fn from_aarch64_bytes(raw: [u8; 32]) -> Result<Self, Errno> {
        let l_type = u16::from_le_bytes([raw[0], raw[1]]);
        let l_whence = u16::from_le_bytes([raw[2], raw[3]]);
        let l_start = i64::from_le_bytes(raw[8..16].try_into().unwrap());
        let l_len = i64::from_le_bytes(raw[16..24].try_into().unwrap());
        let l_pid = i32::from_le_bytes(raw[24..28].try_into().unwrap());
        if !matches!(l_type, F_RDLCK | F_WRLCK | F_UNLCK) {
            return Err(Errno::EINVAL);
        }
        if l_whence > 2 || l_len < 0 {
            return Err(Errno::EINVAL);
        }
        Ok(Self {
            l_type,
            l_whence,
            l_start,
            l_len,
            l_pid,
        })
    }

    pub const fn to_aarch64_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let t = self.l_type.to_le_bytes();
        let w = self.l_whence.to_le_bytes();
        let s = self.l_start.to_le_bytes();
        let l = self.l_len.to_le_bytes();
        let p = self.l_pid.to_le_bytes();
        out[0] = t[0];
        out[1] = t[1];
        out[2] = w[0];
        out[3] = w[1];
        out[8] = s[0];
        out[9] = s[1];
        out[10] = s[2];
        out[11] = s[3];
        out[12] = s[4];
        out[13] = s[5];
        out[14] = s[6];
        out[15] = s[7];
        out[16] = l[0];
        out[17] = l[1];
        out[18] = l[2];
        out[19] = l[3];
        out[20] = l[4];
        out[21] = l[5];
        out[22] = l[6];
        out[23] = l[7];
        out[24] = p[0];
        out[25] = p[1];
        out[26] = p[2];
        out[27] = p[3];
        out
    }

    fn byte_range(&self, current_offset: i64, file_len: i64) -> Result<(i64, i64), Errno> {
        let base = match self.l_whence {
            0 => 0i64,
            1 => current_offset,
            2 => file_len,
            _ => return Err(Errno::EINVAL),
        };
        let start = base.checked_add(self.l_start).ok_or(Errno::EOVERFLOW)?;
        if start < 0 {
            return Err(Errno::EINVAL);
        }
        let end = if self.l_len == 0 {
            i64::MAX
        } else {
            start.checked_add(self.l_len - 1).ok_or(Errno::EOVERFLOW)?
        };
        Ok((start, end))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockKind {
    FlockShared,
    FlockExclusive,
    PosixRead,
    PosixWrite,
}

impl LockKind {
    const fn is_exclusive(self) -> bool {
        matches!(self, Self::FlockExclusive | Self::PosixWrite)
    }

    const fn is_posix(self) -> bool {
        matches!(self, Self::PosixRead | Self::PosixWrite)
    }
}

#[derive(Clone, Copy)]
struct LockEntry {
    live: bool,
    target: TargetKey,
    owner: u64,
    kind: LockKind,
    start: i64,
    end: i64,
}

impl LockEntry {
    const EMPTY: Self = Self {
        live: false,
        target: TargetKey::EMPTY,
        owner: 0,
        kind: LockKind::FlockShared,
        start: 0,
        end: 0,
    };
}

/// Bounded advisory lock manager for both `flock(2)` (BSD) and `fcntl(2)` POSIX byte-range locks.
pub struct AdvisoryLockTable<const MAX_LOCKS: usize> {
    locks: [LockEntry; MAX_LOCKS],
}

impl<const MAX_LOCKS: usize> Default for AdvisoryLockTable<MAX_LOCKS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_LOCKS: usize> AdvisoryLockTable<MAX_LOCKS> {
    pub const fn new() -> Self {
        Self {
            locks: [LockEntry::EMPTY; MAX_LOCKS],
        }
    }

    /// Executes `flock(2)` on `target` owned by `owner_ofd` (an open file description / fd id).
    pub fn flock_op(&mut self, target: TargetKey, owner_ofd: u64, op: u32) -> Result<(), Errno> {
        let mode = op & !LOCK_NB;
        if (op & !(LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN)) != 0 {
            return Err(Errno::EINVAL);
        }
        let desired = match mode {
            LOCK_UN => {
                for entry in &mut self.locks {
                    if entry.live
                        && !entry.kind.is_posix()
                        && entry.target == target
                        && entry.owner == owner_ofd
                    {
                        *entry = LockEntry::EMPTY;
                    }
                }
                return Ok(());
            }
            LOCK_SH => LockKind::FlockShared,
            LOCK_EX => LockKind::FlockExclusive,
            _ => return Err(Errno::EINVAL),
        };

        let conflict = self.locks.iter().any(|e| {
            e.live
                && !e.kind.is_posix()
                && e.target == target
                && e.owner != owner_ofd
                && (desired.is_exclusive() || e.kind.is_exclusive())
        });
        if conflict {
            return Err(Errno::EAGAIN);
        }

        if let Some(existing) = self
            .locks
            .iter_mut()
            .find(|e| e.live && !e.kind.is_posix() && e.target == target && e.owner == owner_ofd)
        {
            existing.kind = desired;
            return Ok(());
        }

        let slot = self
            .locks
            .iter_mut()
            .find(|e| !e.live)
            .ok_or(Errno::ENOLCK)?;
        *slot = LockEntry {
            live: true,
            target,
            owner: owner_ofd,
            kind: desired,
            start: 0,
            end: i64::MAX,
        };
        Ok(())
    }

    /// Releases all `flock` locks held by `owner_ofd` (e.g. on final close of open file description).
    pub fn release_flock_owner(&mut self, owner_ofd: u64) {
        for entry in &mut self.locks {
            if entry.live && !entry.kind.is_posix() && entry.owner == owner_ofd {
                *entry = LockEntry::EMPTY;
            }
        }
    }

    /// Executes `fcntl(F_GETLK)` for `target` on behalf of `caller_pid`.
    pub fn fcntl_getlk(
        &self,
        target: TargetKey,
        caller_pid: u32,
        mut req: PosixFlock,
        current_offset: i64,
        file_len: i64,
    ) -> Result<PosixFlock, Errno> {
        if req.l_type == F_UNLCK {
            return Err(Errno::EINVAL);
        }
        let (start, end) = req.byte_range(current_offset, file_len)?;
        let caller = u64::from(caller_pid);
        let want_write = req.l_type == F_WRLCK;

        if let Some(blocker) = self.locks.iter().find(|e| {
            e.live
                && e.kind.is_posix()
                && e.target == target
                && e.owner != caller
                && ranges_overlap(e.start, e.end, start, end)
                && (want_write || e.kind.is_exclusive())
        }) {
            let l_len = if blocker.end == i64::MAX {
                0
            } else {
                blocker.end.saturating_sub(blocker.start).saturating_add(1)
            };
            Ok(PosixFlock {
                l_type: if blocker.kind.is_exclusive() {
                    F_WRLCK
                } else {
                    F_RDLCK
                },
                l_whence: 0,
                l_start: blocker.start,
                l_len,
                l_pid: blocker.owner as i32,
            })
        } else {
            req.l_type = F_UNLCK;
            Ok(req)
        }
    }

    /// Executes `fcntl(F_SETLK / F_SETLKW)` for `target` on behalf of `caller_pid`.
    pub fn fcntl_setlk(
        &mut self,
        target: TargetKey,
        caller_pid: u32,
        req: PosixFlock,
        current_offset: i64,
        file_len: i64,
    ) -> Result<(), Errno> {
        let (start, end) = req.byte_range(current_offset, file_len)?;
        let caller = u64::from(caller_pid);
        if req.l_type == F_UNLCK {
            for entry in &mut self.locks {
                if entry.live
                    && entry.kind.is_posix()
                    && entry.target == target
                    && entry.owner == caller
                    && ranges_overlap(entry.start, entry.end, start, end)
                {
                    *entry = LockEntry::EMPTY;
                }
            }
            return Ok(());
        }

        let new_kind = match req.l_type {
            F_RDLCK => LockKind::PosixRead,
            F_WRLCK => LockKind::PosixWrite,
            _ => return Err(Errno::EINVAL),
        };

        let conflict = self.locks.iter().any(|e| {
            e.live
                && e.kind.is_posix()
                && e.target == target
                && e.owner != caller
                && ranges_overlap(e.start, e.end, start, end)
                && (new_kind.is_exclusive() || e.kind.is_exclusive())
        });
        if conflict {
            return Err(Errno::EAGAIN);
        }

        if let Some(existing) = self.locks.iter_mut().find(|e| {
            e.live
                && e.kind.is_posix()
                && e.target == target
                && e.owner == caller
                && e.start == start
                && e.end == end
        }) {
            existing.kind = new_kind;
            return Ok(());
        }

        let slot = self
            .locks
            .iter_mut()
            .find(|e| !e.live)
            .ok_or(Errno::ENOLCK)?;
        *slot = LockEntry {
            live: true,
            target,
            owner: caller,
            kind: new_kind,
            start,
            end,
        };
        Ok(())
    }

    /// Releases all POSIX locks owned by `caller_pid` on close/exit.
    pub fn release_posix_pid(&mut self, caller_pid: u32) {
        let caller = u64::from(caller_pid);
        for entry in &mut self.locks {
            if entry.live && entry.kind.is_posix() && entry.owner == caller {
                *entry = LockEntry::EMPTY;
            }
        }
    }

    /// Releases all POSIX locks owned by `caller_pid` on one specific inode/target (`close(2)`).
    pub fn release_posix_target_pid(&mut self, target: TargetKey, caller_pid: u32) {
        let caller = u64::from(caller_pid);
        for entry in &mut self.locks {
            if entry.live
                && entry.kind.is_posix()
                && entry.target == target
                && entry.owner == caller
            {
                *entry = LockEntry::EMPTY;
            }
        }
    }
}

const fn ranges_overlap(a_start: i64, a_end: i64, b_start: i64, b_end: i64) -> bool {
    a_start <= b_end && b_start <= a_end
}

#[derive(Clone, Copy)]
struct XattrEntry<const VAL_CAP: usize> {
    live: bool,
    target: TargetKey,
    name: [u8; MAX_XATTR_NAME],
    name_len: usize,
    value: [u8; VAL_CAP],
    val_len: usize,
}

impl<const VAL_CAP: usize> XattrEntry<VAL_CAP> {
    const EMPTY: Self = Self {
        live: false,
        target: TargetKey::EMPTY,
        name: [0u8; MAX_XATTR_NAME],
        name_len: 0,
        value: [0u8; VAL_CAP],
        val_len: 0,
    };

    fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    fn value(&self) -> &[u8] {
        &self.value[..self.val_len]
    }
}

fn validate_xattr_name(name: &[u8]) -> Result<(), Errno> {
    if name.is_empty() || name.len() > MAX_XATTR_NAME {
        return Err(if name.is_empty() {
            Errno::EINVAL
        } else {
            Errno::ERANGE
        });
    }
    let valid_ns = name.starts_with(b"user.")
        || name.starts_with(b"security.")
        || name.starts_with(b"system.")
        || name.starts_with(b"trusted.");
    if !valid_ns {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(())
}

/// Bounded extended attribute (`xattr`) store for `dpkg` / `tar` capability & ACL preservation.
pub struct XattrTable<const MAX_ATTRS: usize, const VAL_CAP: usize> {
    entries: [XattrEntry<VAL_CAP>; MAX_ATTRS],
}

impl<const MAX_ATTRS: usize, const VAL_CAP: usize> Default for XattrTable<MAX_ATTRS, VAL_CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_ATTRS: usize, const VAL_CAP: usize> XattrTable<MAX_ATTRS, VAL_CAP> {
    pub const fn new() -> Self {
        Self {
            entries: [XattrEntry::EMPTY; MAX_ATTRS],
        }
    }

    pub fn set(
        &mut self,
        target: TargetKey,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), Errno> {
        validate_xattr_name(name)?;
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
            return Err(Errno::EINVAL);
        }
        if value.len() > VAL_CAP {
            return Err(Errno::ENOSPC);
        }

        let existing_idx = self
            .entries
            .iter()
            .position(|e| e.live && e.target == target && e.name() == name);

        if (flags & XATTR_CREATE) != 0 && existing_idx.is_some() {
            return Err(Errno::EEXIST);
        }
        if (flags & XATTR_REPLACE) != 0 && existing_idx.is_none() {
            return Err(Errno::ENODATA);
        }

        let idx = match existing_idx {
            Some(i) => i,
            None => self
                .entries
                .iter()
                .position(|e| !e.live)
                .ok_or(Errno::ENOSPC)?,
        };
        let slot = &mut self.entries[idx];
        slot.live = true;
        slot.target = target;
        slot.name = [0u8; MAX_XATTR_NAME];
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.value = [0u8; VAL_CAP];
        slot.value[..value.len()].copy_from_slice(value);
        slot.val_len = value.len();
        Ok(())
    }

    pub fn get(
        &self,
        target: TargetKey,
        name: &[u8],
        out: Option<&mut [u8]>,
    ) -> Result<usize, Errno> {
        validate_xattr_name(name)?;
        let entry = self
            .entries
            .iter()
            .find(|e| e.live && e.target == target && e.name() == name)
            .ok_or(Errno::ENODATA)?;
        let val = entry.value();
        if let Some(dst) = out {
            if dst.len() < val.len() {
                return Err(Errno::ERANGE);
            }
            dst[..val.len()].copy_from_slice(val);
        }
        Ok(val.len())
    }

    pub fn list(&self, target: TargetKey, mut out: Option<&mut [u8]>) -> Result<usize, Errno> {
        let mut total = 0usize;
        for entry in &self.entries {
            if !entry.live || entry.target != target {
                continue;
            }
            let need = entry.name_len + 1;
            if let Some(dst) = out.as_deref_mut() {
                if total + need > dst.len() {
                    return Err(Errno::ERANGE);
                }
                dst[total..total + entry.name_len].copy_from_slice(entry.name());
                dst[total + entry.name_len] = 0;
            }
            total += need;
        }
        Ok(total)
    }

    pub fn remove(&mut self, target: TargetKey, name: &[u8]) -> Result<(), Errno> {
        validate_xattr_name(name)?;
        let slot = self
            .entries
            .iter_mut()
            .find(|e| e.live && e.target == target && e.name() == name)
            .ok_or(Errno::ENODATA)?;
        *slot = XattrEntry::EMPTY;
        Ok(())
    }
}

/// Preserved POSIX metadata (`mode`, `uid`, `gid`, nanosecond timestamps) per path/file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageFileMetadata {
    pub live: bool,
    pub target: TargetKey,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
}

impl PackageFileMetadata {
    const EMPTY: Self = Self {
        live: false,
        target: TargetKey::EMPTY,
        mode: 0o644,
        uid: 0,
        gid: 0,
        atime_sec: 1,
        atime_nsec: 0,
        mtime_sec: 1,
        mtime_nsec: 0,
    };
}

/// Decoded AArch64 `struct timespec` pair `[atime, mtime]` passed to `utimensat(2)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimespecPair {
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
}

impl TimespecPair {
    pub fn from_aarch64_bytes(raw: [u8; 32]) -> Result<Self, Errno> {
        let pair = Self {
            atime_sec: i64::from_le_bytes(raw[0..8].try_into().unwrap()),
            atime_nsec: i64::from_le_bytes(raw[8..16].try_into().unwrap()),
            mtime_sec: i64::from_le_bytes(raw[16..24].try_into().unwrap()),
            mtime_nsec: i64::from_le_bytes(raw[24..32].try_into().unwrap()),
        };
        validate_timespec(pair.atime_nsec)?;
        validate_timespec(pair.mtime_nsec)?;
        Ok(pair)
    }
}

const fn validate_timespec(nsec: i64) -> Result<(), Errno> {
    if nsec == UTIME_NOW || nsec == UTIME_OMIT || (nsec >= 0 && nsec < 1_000_000_000) {
        Ok(())
    } else {
        Err(Errno::EINVAL)
    }
}

/// Bounded ownership/mode/timestamp table enforcing `CAP_CHOWN`/`CAP_FOWNER` and `dpkg` extraction rules.
pub struct PackageMetadataTable<const MAX_META: usize> {
    entries: [PackageFileMetadata; MAX_META],
}

impl<const MAX_META: usize> Default for PackageMetadataTable<MAX_META> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_META: usize> PackageMetadataTable<MAX_META> {
    pub const fn new() -> Self {
        Self {
            entries: [PackageFileMetadata::EMPTY; MAX_META],
        }
    }

    fn get_or_insert_mut(&mut self, target: TargetKey) -> Result<&mut PackageFileMetadata, Errno> {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.live && e.target == target)
        {
            return Ok(&mut self.entries[pos]);
        }
        let pos = self
            .entries
            .iter()
            .position(|e| !e.live)
            .ok_or(Errno::ENOSPC)?;
        let slot = &mut self.entries[pos];
        *slot = PackageFileMetadata {
            live: true,
            target,
            ..PackageFileMetadata::EMPTY
        };
        Ok(slot)
    }

    pub fn chmod(
        &mut self,
        target: TargetKey,
        mode: u32,
        caller_euid: u32,
        has_cap_fowner: bool,
    ) -> Result<(), Errno> {
        let entry = self.get_or_insert_mut(target)?;
        if !has_cap_fowner && caller_euid != 0 && caller_euid != entry.uid {
            return Err(Errno::EPERM);
        }
        entry.mode = mode & 0o7777;
        Ok(())
    }

    pub fn chown(
        &mut self,
        target: TargetKey,
        new_uid: u32,
        new_gid: u32,
        caller_euid: u32,
        has_cap_chown: bool,
    ) -> Result<(), Errno> {
        let entry = self.get_or_insert_mut(target)?;
        let keep_uid = new_uid == u32::MAX;
        let keep_gid = new_gid == u32::MAX;
        if (!keep_uid || !keep_gid) && caller_euid != 0 && !has_cap_chown {
            return Err(Errno::EPERM);
        }
        if !keep_uid {
            entry.uid = new_uid;
        }
        if !keep_gid {
            entry.gid = new_gid;
        }
        // POSIX: chown clears S_ISUID / S_ISGID bits when changed by unprivileged callers.
        if caller_euid != 0 && !has_cap_chown {
            entry.mode &= !0o6000;
        }
        Ok(())
    }

    pub fn utimens(
        &mut self,
        target: TargetKey,
        times: Option<TimespecPair>,
        now_sec: i64,
        caller_euid: u32,
        has_cap_fowner: bool,
    ) -> Result<(), Errno> {
        let entry = self.get_or_insert_mut(target)?;
        if !has_cap_fowner && caller_euid != 0 && caller_euid != entry.uid {
            return Err(Errno::EPERM);
        }
        match times {
            None => {
                entry.atime_sec = now_sec;
                entry.atime_nsec = 0;
                entry.mtime_sec = now_sec;
                entry.mtime_nsec = 0;
            }
            Some(pair) => {
                if pair.atime_nsec == UTIME_NOW {
                    entry.atime_sec = now_sec;
                    entry.atime_nsec = 0;
                } else if pair.atime_nsec != UTIME_OMIT {
                    entry.atime_sec = pair.atime_sec;
                    entry.atime_nsec = pair.atime_nsec;
                }
                if pair.mtime_nsec == UTIME_NOW {
                    entry.mtime_sec = now_sec;
                    entry.mtime_nsec = 0;
                } else if pair.mtime_nsec != UTIME_OMIT {
                    entry.mtime_sec = pair.mtime_sec;
                    entry.mtime_nsec = pair.mtime_nsec;
                }
            }
        }
        Ok(())
    }

    pub fn get(&self, target: TargetKey) -> Option<&PackageFileMetadata> {
        self.entries.iter().find(|e| e.live && e.target == target)
    }
}

/// Parsed `#!<interpreter> [optional-arg]` script header (`binfmt_script`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShebangSpec {
    interpreter: [u8; 128],
    interpreter_len: usize,
    arg: [u8; 128],
    arg_len: usize,
    has_arg: bool,
}

impl ShebangSpec {
    pub fn interpreter(&self) -> &[u8] {
        &self.interpreter[..self.interpreter_len]
    }

    pub fn optional_arg(&self) -> Option<&[u8]> {
        if self.has_arg {
            Some(&self.arg[..self.arg_len])
        } else {
            None
        }
    }
}

/// Parses a `#!` script header according to Linux `fs/binfmt_script.c` rules.
///
/// Returns `Ok(None)` if `header` does not start with `#!`, `Err(Errno::ELOOP)` if recursion
/// `depth >= MAX_SHEBANG_DEPTH`, and `Err(Errno::ENOEXEC)` if no valid interpreter path exists.
pub fn parse_shebang(header: &[u8], depth: u8) -> Result<Option<ShebangSpec>, Errno> {
    if !header.starts_with(b"#!") {
        return Ok(None);
    }
    if depth >= MAX_SHEBANG_DEPTH {
        return Err(Errno::ELOOP);
    }
    let window = &header[2..header.len().min(MAX_BINPRM_BYTES)];
    let line = match window.iter().position(|&b| b == b'\n') {
        Some(nl) => &window[..nl],
        None => {
            if header.len() >= MAX_BINPRM_BYTES {
                return Err(Errno::ENOEXEC);
            }
            window
        }
    };
    let trimmed_end = trim_trailing_ws(line);
    let after_lead = trim_leading_ws(trimmed_end);
    if after_lead.is_empty() {
        return Err(Errno::ENOEXEC);
    }
    let interp_end = after_lead
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(after_lead.len());
    let interp = &after_lead[..interp_end];
    if interp.is_empty() || interp.len() > 128 || interp.contains(&0) {
        return Err(Errno::ENOEXEC);
    }

    let rest = trim_leading_ws(&after_lead[interp_end..]);
    if rest.len() > 128 || rest.contains(&0) {
        return Err(Errno::ENOEXEC);
    }

    let mut interpreter = [0u8; 128];
    interpreter[..interp.len()].copy_from_slice(interp);
    let mut arg = [0u8; 128];
    let has_arg = !rest.is_empty();
    if has_arg {
        arg[..rest.len()].copy_from_slice(rest);
    }
    Ok(Some(ShebangSpec {
        interpreter,
        interpreter_len: interp.len(),
        arg,
        arg_len: rest.len(),
        has_arg,
    }))
}

fn trim_leading_ws(mut s: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = s.split_first() {
        if b == b' ' || b == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn trim_trailing_ws(mut s: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = s.split_last() {
        if b == b' ' || b == b'\t' || b == b'\r' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flock_and_posix_range_locks_enforce_conflicts_release_and_nolck_cap() {
        let mut locks = AdvisoryLockTable::<2>::new();
        let dpkg_lock = TargetKey::from_path(b"/var/lib/dpkg/lock").unwrap();

        locks.flock_op(dpkg_lock, 1, LOCK_EX | LOCK_NB).unwrap();
        assert_eq!(
            locks.flock_op(dpkg_lock, 2, LOCK_EX | LOCK_NB),
            Err(Errno::EAGAIN)
        );
        locks.flock_op(dpkg_lock, 1, LOCK_UN).unwrap();
        locks.flock_op(dpkg_lock, 2, LOCK_SH | LOCK_NB).unwrap();

        let wr = PosixFlock {
            l_type: F_WRLCK,
            l_whence: 0,
            l_start: 10,
            l_len: 20,
            l_pid: 0,
        };
        locks.fcntl_setlk(dpkg_lock, 100, wr, 0, 0).unwrap();
        let seen = locks.fcntl_getlk(dpkg_lock, 200, wr, 0, 0).unwrap();
        assert_eq!(seen.l_type, F_WRLCK);
        assert_eq!(seen.l_pid, 100);

        // Table cap = 2 is now full (1 flock + 1 posix lock) -> next distinct lock returns ENOLCK!
        let apt_lock = TargetKey::from_path(b"/var/lib/apt/lists/lock").unwrap();
        assert_eq!(
            locks.fcntl_setlk(apt_lock, 200, wr, 0, 0),
            Err(Errno::ENOLCK)
        );
        locks.release_posix_pid(100);
        locks.fcntl_setlk(apt_lock, 200, wr, 0, 0).unwrap();
    }

    #[test]
    fn xattr_enforces_create_replace_enodata_and_erange() {
        let mut xattrs = XattrTable::<4, 64>::new();
        let path = TargetKey::from_path(b"/usr/bin/sudo").unwrap();

        assert_eq!(
            xattrs.get(path, b"security.capability", None),
            Err(Errno::ENODATA)
        );
        xattrs
            .set(path, b"security.capability", b"capv2", XATTR_CREATE)
            .unwrap();
        assert_eq!(
            xattrs.set(path, b"security.capability", b"new", XATTR_CREATE),
            Err(Errno::EEXIST)
        );
        assert_eq!(xattrs.get(path, b"security.capability", None), Ok(5));

        let mut small = [0u8; 2];
        assert_eq!(
            xattrs.get(path, b"security.capability", Some(&mut small)),
            Err(Errno::ERANGE)
        );
        let mut exact = [0u8; 8];
        let n = xattrs
            .get(path, b"security.capability", Some(&mut exact))
            .unwrap();
        assert_eq!(&exact[..n], b"capv2");

        let mut names = [0u8; 32];
        let l = xattrs.list(path, Some(&mut names)).unwrap();
        assert_eq!(&names[..l], b"security.capability\0");

        xattrs.remove(path, b"security.capability").unwrap();
        assert_eq!(
            xattrs.remove(path, b"security.capability"),
            Err(Errno::ENODATA)
        );
    }

    #[test]
    fn metadata_chmod_chown_utimens_preserve_dpkg_attrs() {
        let mut meta = PackageMetadataTable::<4>::new();
        let key = TargetKey::from_path(b"/var/lib/dpkg/status").unwrap();

        assert_eq!(meta.chown(key, 1000, 1000, 1000, false), Err(Errno::EPERM));
        meta.chown(key, 0, 42, 0, true).unwrap();
        meta.chmod(key, 0o2755, 0, true).unwrap();
        let ts = TimespecPair {
            atime_sec: 1_700_000_000,
            atime_nsec: 123,
            mtime_sec: 0,
            mtime_nsec: UTIME_OMIT,
        };
        meta.utimens(key, Some(ts), 1_800_000_000, 0, true).unwrap();
        let saved = meta.get(key).unwrap();
        assert_eq!(saved.mode, 0o2755);
        assert_eq!(saved.gid, 42);
        assert_eq!(saved.atime_sec, 1_700_000_000);
        assert_eq!(saved.mtime_sec, 1); // preserved because UTIME_OMIT
    }

    #[test]
    fn shebang_parser_handles_optional_arg_whitespace_and_eloop() {
        let spec = parse_shebang(b"#! /usr/bin/env -S sh -e \r\n# comment\n", 0)
            .unwrap()
            .unwrap();
        assert_eq!(spec.interpreter(), b"/usr/bin/env");
        assert_eq!(spec.optional_arg(), Some(b"-S sh -e".as_slice()));

        assert_eq!(parse_shebang(b"\x7fELF", 0), Ok(None));
        assert_eq!(parse_shebang(b"#!   \n", 0), Err(Errno::ENOEXEC));
        assert_eq!(
            parse_shebang(b"#!/bin/sh\n", MAX_SHEBANG_DEPTH),
            Err(Errno::ELOOP)
        );
    }

    #[test]
    fn ext4_inode_key_detects_cross_fd_and_cleans_on_close() {
        let mut locks = AdvisoryLockTable::<8>::new();
        let ino_a = TargetKey::from_ext4_inode(1, 42);
        let ino_b = TargetKey::from_ext4_inode(1, 43);
        assert_ne!(ino_a, ino_b);

        locks.flock_op(ino_a, 100, LOCK_EX | LOCK_NB).unwrap();
        assert_eq!(
            locks.flock_op(ino_a, 101, LOCK_EX | LOCK_NB),
            Err(Errno::EAGAIN)
        );
        locks.flock_op(ino_b, 101, LOCK_EX | LOCK_NB).unwrap();
        locks.release_flock_owner(100);
        locks.flock_op(ino_a, 101, LOCK_EX | LOCK_NB).unwrap();

        let wl = PosixFlock {
            l_type: F_WRLCK,
            l_whence: 0,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        locks.fcntl_setlk(ino_a, 10, wl, 0, 0).unwrap();
        assert_eq!(locks.fcntl_setlk(ino_a, 11, wl, 0, 0), Err(Errno::EAGAIN));
        locks.release_posix_target_pid(ino_a, 10);
        locks.fcntl_setlk(ino_a, 11, wl, 0, 0).unwrap();
    }
}
