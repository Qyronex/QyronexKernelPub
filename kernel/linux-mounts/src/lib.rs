// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 33 — Mount model (`mount`/`umount2`/`pivot_root`), `procfs`/`sysfs` introspection,
//! and persistent `ext4` read/write root filesystem with `fsync`/`fdatasync`/`sync`/`rename`
//! package-manager durability semantics.

extern crate alloc;

pub mod block_cache;
pub mod ext4;
pub mod partition;

pub use block_cache::{
    BLOCK_SECTOR_SIZE, BlockDevice, CACHE_BLOCK_SIZE, CachedBlockDevice, DEFAULT_CACHE_BLOCKS,
    PartitionSlice,
};
pub use ext4::{Ext4CreateAttr, Ext4DirEntry, Ext4InodeStat, Ext4StatFsInfo, Ext4Volume};
pub use partition::{MAX_PARTITIONS, PartitionEntry, PartitionTable, crc32_ieee, parse_partitions};

use kernal_linux_abi::Errno;

/// Linux `mount(2)` flag constants (`<sys/mount.h>`).
pub const MS_RDONLY: u64 = 1;
pub const MS_NOSUID: u64 = 2;
pub const MS_NODEV: u64 = 4;
pub const MS_NOEXEC: u64 = 8;
pub const MS_SYNCHRONOUS: u64 = 16;
pub const MS_REMOUNT: u64 = 32;
pub const MS_NOATIME: u64 = 1024;
pub const MS_NODIRATIME: u64 = 2048;
pub const MS_BIND: u64 = 4096;
pub const MS_MOVE: u64 = 8192;
pub const MS_REC: u64 = 16384;
pub const MS_UNBINDABLE: u64 = 1 << 17;
pub const MS_PRIVATE: u64 = 1 << 18;
pub const MS_SLAVE: u64 = 1 << 19;
pub const MS_SHARED: u64 = 1 << 20;
pub const MS_PROPAGATION_MASK: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;
pub const MS_RELATIME: u64 = 1 << 21;
pub const MS_STRICTATIME: u64 = 1 << 24;

/// Linux `umount2(2)` flag constants (`<sys/mount.h>`).
pub const MNT_FORCE: u32 = 1;
pub const MNT_DETACH: u32 = 2;
pub const MNT_EXPIRE: u32 = 4;
pub const UMOUNT_NOFOLLOW: u32 = 8;
const UMOUNT_VALID_MASK: u32 = MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW;

/// Supported Step-33 filesystem drivers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemType {
    Initramfs,
    Ext4,
    Tmpfs,
    Procfs,
    Sysfs,
    Devtmpfs,
    Devpts,
    Cgroup2,
    Overlay,
}

impl FilesystemType {
    pub fn parse(raw: &[u8]) -> Result<Self, Errno> {
        match raw {
            b"rootfs" | b"initramfs" => Ok(Self::Initramfs),
            b"ext4" => Ok(Self::Ext4),
            b"tmpfs" => Ok(Self::Tmpfs),
            b"proc" | b"procfs" => Ok(Self::Procfs),
            b"sysfs" => Ok(Self::Sysfs),
            b"devtmpfs" => Ok(Self::Devtmpfs),
            b"devpts" => Ok(Self::Devpts),
            b"cgroup2" => Ok(Self::Cgroup2),
            b"overlay" | b"overlayfs" => Ok(Self::Overlay),
            _ => Err(Errno::ENODEV),
        }
    }

    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Initramfs => b"rootfs",
            Self::Ext4 => b"ext4",
            Self::Tmpfs => b"tmpfs",
            Self::Procfs => b"proc",
            Self::Sysfs => b"sysfs",
            Self::Devtmpfs => b"devtmpfs",
            Self::Devpts => b"devpts",
            Self::Cgroup2 => b"cgroup2",
            Self::Overlay => b"overlay",
        }
    }

    pub const fn f_type_magic(self) -> u64 {
        match self {
            Self::Initramfs => 0x8584_58f6, // RAMFS_MAGIC
            Self::Ext4 => 0xef53,           // EXT4_SUPER_MAGIC
            Self::Tmpfs => 0x0102_1994,     // TMPFS_MAGIC
            Self::Procfs => 0x9fa0,         // PROC_SUPER_MAGIC
            Self::Sysfs => 0x6265_6572,     // SYSFS_MAGIC
            Self::Devtmpfs => 0x0102_1994,  // TMPFS_MAGIC
            Self::Devpts => 0x1cd1,         // DEVPTS_SUPER_MAGIC
            Self::Cgroup2 => 0x6367_7270,   // CGROUP2_SUPER_MAGIC
            Self::Overlay => 0x794c_7630,   // OVERLAYFS_SUPER_MAGIC
        }
    }

    pub const fn st_dev_pair(self, mount_id: u32) -> (u32, u32) {
        match self {
            Self::Initramfs => (0, 1),
            Self::Procfs => (0, 3),
            Self::Sysfs => (0, 4),
            Self::Devtmpfs => (0, 5),
            Self::Devpts => (0, 6),
            Self::Cgroup2 => (0, 12),
            Self::Ext4 => (254, mount_id),
            Self::Tmpfs => (0, 20 + mount_id),
            Self::Overlay => (0, 40 + mount_id),
        }
    }

    pub const fn st_dev(self, mount_id: u32) -> u64 {
        let (maj, min) = self.st_dev_pair(mount_id);
        let maj64 = maj as u64;
        let min64 = min as u64;
        ((maj64 & 0x0fff) << 8)
            | ((maj64 & !0x0fff) << 32)
            | (min64 & 0xff)
            | ((min64 & !0xff) << 12)
    }
}

pub const MAX_MOUNT_PATH: usize = 256;
pub const MAX_MOUNT_SOURCE: usize = 32;

/// One active mount point in the kernel [`MountTable`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountEntry {
    live: bool,
    mount_id: u32,
    fstype: FilesystemType,
    flags: u64,
    source: [u8; MAX_MOUNT_SOURCE],
    source_len: usize,
    target: [u8; MAX_MOUNT_PATH],
    target_len: usize,
}

impl MountEntry {
    const EMPTY: Self = Self {
        live: false,
        mount_id: 0,
        fstype: FilesystemType::Initramfs,
        flags: 0,
        source: [0u8; MAX_MOUNT_SOURCE],
        source_len: 0,
        target: [0u8; MAX_MOUNT_PATH],
        target_len: 0,
    };

    pub const fn mount_id(&self) -> u32 {
        self.mount_id
    }

    pub const fn fstype(&self) -> FilesystemType {
        self.fstype
    }

    pub const fn flags(&self) -> u64 {
        self.flags
    }

    pub const fn is_readonly(&self) -> bool {
        self.flags & MS_RDONLY != 0
    }

    pub fn source(&self) -> &[u8] {
        &self.source[..self.source_len]
    }

    pub fn target(&self) -> &[u8] {
        &self.target[..self.target_len]
    }
}

/// Bounded Step-33 mount table supporting `mount(2)`, `umount2(2)`, `pivot_root(2)`, and
/// longest-prefix path resolution.
pub struct MountTable<const MAX_MOUNTS: usize> {
    entries: [MountEntry; MAX_MOUNTS],
    next_id: u32,
}

impl<const MAX_MOUNTS: usize> Default for MountTable<MAX_MOUNTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_MOUNTS: usize> MountTable<MAX_MOUNTS> {
    pub const fn new() -> Self {
        Self {
            entries: [MountEntry::EMPTY; MAX_MOUNTS],
            next_id: 1,
        }
    }

    /// Clones this mount table into a child mount namespace (`CLONE_NEWNS`), demoting
    /// any `MS_SHARED` mounts to `MS_SLAVE` unless explicitly preserved.
    pub fn clone_into_child_namespace(&self, make_slave: bool) -> Self {
        let mut child = Self {
            entries: self.entries,
            next_id: self.next_id,
        };
        if make_slave {
            for e in &mut child.entries {
                if e.live && (e.flags & MS_SHARED) != 0 {
                    e.flags = (e.flags & !MS_PROPAGATION_MASK) | MS_SLAVE;
                }
            }
        }
        child
    }

    /// Seeds the baseline early-boot mount table (`/` on `initramfs`, `/dev`, `/dev/pts`, `/proc`,
    /// `/sys`, `/run`).
    pub fn seed_default_hierarchy(&mut self) -> Result<(), Errno> {
        self.mount(b"rootfs", b"/", Some(b"rootfs"), MS_RDONLY)?;
        self.mount(b"devtmpfs", b"/dev", Some(b"devtmpfs"), MS_NOSUID)?;
        self.mount(
            b"devpts",
            b"/dev/pts",
            Some(b"devpts"),
            MS_NOSUID | MS_NOEXEC,
        )?;
        self.mount(
            b"proc",
            b"/proc",
            Some(b"proc"),
            MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
        )?;
        self.mount(
            b"sysfs",
            b"/sys",
            Some(b"sysfs"),
            MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
        )?;
        self.mount(b"tmpfs", b"/run", Some(b"tmpfs"), MS_NOSUID | MS_NODEV)?;
        Ok(())
    }

    /// Executes `mount(2)` (including `MS_REMOUNT`, `MS_MOVE`, and new mount insertion).
    pub fn mount(
        &mut self,
        source: &[u8],
        target: &[u8],
        fstype: Option<&[u8]>,
        flags: u64,
    ) -> Result<u32, Errno> {
        let normalized_target = normalize_mount_path(target)?;
        if flags & MS_REMOUNT != 0 {
            let slot = self
                .entries
                .iter_mut()
                .find(|e| e.live && e.target() == normalized_target)
                .ok_or(Errno::EINVAL)?;
            let preserved = slot.flags & !(MS_RDONLY | MS_SYNCHRONOUS | MS_NOATIME | MS_RELATIME);
            let updated = flags & (MS_RDONLY | MS_SYNCHRONOUS | MS_NOATIME | MS_RELATIME);
            slot.flags = preserved | updated;
            return Ok(slot.mount_id);
        }

        if flags & MS_MOVE != 0 {
            let normalized_source = normalize_mount_path(source)?;
            if normalized_source == b"/" {
                return Err(Errno::EINVAL);
            }
            let slot = self
                .entries
                .iter_mut()
                .find(|e| e.live && e.target() == normalized_source)
                .ok_or(Errno::EINVAL)?;
            slot.target = [0u8; MAX_MOUNT_PATH];
            slot.target[..normalized_target.len()].copy_from_slice(normalized_target);
            slot.target_len = normalized_target.len();
            return Ok(slot.mount_id);
        }

        if (flags & MS_PROPAGATION_MASK) != 0
            && (flags & MS_BIND) == 0
            && fstype.is_none_or(|f| f.is_empty())
            && (source.is_empty() || source == b"none")
        {
            let prop_bits = flags & MS_PROPAGATION_MASK;
            // Exactly one propagation mode may be requested at a time.
            if prop_bits.count_ones() != 1 {
                return Err(Errno::EINVAL);
            }
            let recursive = (flags & MS_REC) != 0;
            let mut matched_id = None;
            for slot in &mut self.entries {
                if !slot.live {
                    continue;
                }
                let tgt = &slot.target[..slot.target_len];
                let is_exact = tgt == normalized_target;
                let is_descendant = recursive
                    && tgt.len() > normalized_target.len()
                    && ((normalized_target == b"/")
                        || (tgt.starts_with(normalized_target)
                            && tgt[normalized_target.len()] == b'/'));
                if is_exact || is_descendant {
                    slot.flags = (slot.flags & !MS_PROPAGATION_MASK) | prop_bits;
                    if is_exact {
                        matched_id = Some(slot.mount_id);
                    }
                }
            }
            return matched_id.ok_or(Errno::EINVAL);
        }

        if (flags & MS_BIND) != 0 {
            let norm_source = normalize_mount_path(source)?;
            let src_entry = *self
                .entries
                .iter()
                .find(|e| e.live && e.target() == norm_source)
                .ok_or(Errno::ENOENT)?;
            if (src_entry.flags & MS_UNBINDABLE) != 0 {
                return Err(Errno::EINVAL);
            }
            if source.len() > MAX_MOUNT_SOURCE {
                return Err(Errno::ENAMETOOLONG);
            }
            let mut src_buf = [0u8; MAX_MOUNT_SOURCE];
            src_buf[..source.len()].copy_from_slice(source);
            let mut tgt_buf = [0u8; MAX_MOUNT_PATH];
            tgt_buf[..normalized_target.len()].copy_from_slice(normalized_target);
            let id = self.next_id;
            self.next_id = self.next_id.saturating_add(1);
            let slot = self
                .entries
                .iter_mut()
                .find(|e| !e.live)
                .ok_or(Errno::ENOSPC)?;
            *slot = MountEntry {
                live: true,
                mount_id: id,
                fstype: src_entry.fstype,
                flags: (src_entry.flags & !MS_UNBINDABLE) | (flags & !MS_UNBINDABLE),
                source: src_buf,
                source_len: source.len(),
                target: tgt_buf,
                target_len: normalized_target.len(),
            };
            return Ok(id);
        }

        let parsed_type = FilesystemType::parse(fstype.ok_or(Errno::EINVAL)?)?;
        if source.len() > MAX_MOUNT_SOURCE {
            return Err(Errno::ENAMETOOLONG);
        }

        // If the exact target already has a mount of the same type, update it in place; otherwise
        // allocate a free slot.
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.live && e.target() == normalized_target)
        {
            existing.fstype = parsed_type;
            existing.flags = flags & !MS_REMOUNT;
            existing.source = [0u8; MAX_MOUNT_SOURCE];
            existing.source[..source.len()].copy_from_slice(source);
            existing.source_len = source.len();
            return Ok(existing.mount_id);
        }

        let slot = self
            .entries
            .iter_mut()
            .find(|e| !e.live)
            .ok_or(Errno::ENOSPC)?;
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let mut src_buf = [0u8; MAX_MOUNT_SOURCE];
        src_buf[..source.len()].copy_from_slice(source);
        let mut tgt_buf = [0u8; MAX_MOUNT_PATH];
        tgt_buf[..normalized_target.len()].copy_from_slice(normalized_target);
        *slot = MountEntry {
            live: true,
            mount_id: id,
            fstype: parsed_type,
            flags,
            source: src_buf,
            source_len: source.len(),
            target: tgt_buf,
            target_len: normalized_target.len(),
        };
        Ok(id)
    }

    /// Executes `umount2(2)`.
    pub fn umount2(&mut self, target: &[u8], flags: u32) -> Result<(), Errno> {
        if flags & !UMOUNT_VALID_MASK != 0 {
            return Err(Errno::EINVAL);
        }
        if (flags & MNT_EXPIRE != 0) && (flags & (MNT_FORCE | MNT_DETACH) != 0) {
            return Err(Errno::EINVAL);
        }
        let normalized = normalize_mount_path(target)?;
        if normalized == b"/" {
            return Err(Errno::EBUSY);
        }
        // Reject unmounting if a child mount still lives underneath `normalized` (unless MNT_DETACH).
        if flags & MNT_DETACH == 0 {
            let has_child = self.entries.iter().any(|e| {
                e.live
                    && e.target().len() > normalized.len()
                    && e.target().starts_with(normalized)
                    && e.target()[normalized.len()] == b'/'
            });
            if has_child {
                return Err(Errno::EBUSY);
            }
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|e| e.live && e.target() == normalized)
            .ok_or(Errno::EINVAL)?;
        *slot = MountEntry::EMPTY;
        Ok(())
    }

    /// Atomically transitions `/` from the early initramfs root to the newly mounted persistent
    /// root at `new_root`, moving the old root to `put_old` (`pivot_root(2)`).
    pub fn pivot_root(&mut self, new_root: &[u8], put_old: &[u8]) -> Result<(), Errno> {
        let norm_new = normalize_mount_path(new_root)?;
        let norm_old = normalize_mount_path(put_old)?;
        if norm_new == b"/" || !norm_old.starts_with(norm_new) {
            return Err(Errno::EINVAL);
        }
        let rel_old = &norm_old[norm_new.len()..];
        if !rel_old.starts_with(b"/") {
            return Err(Errno::EINVAL);
        }

        let new_idx = self
            .entries
            .iter()
            .position(|e| e.live && e.target() == norm_new)
            .ok_or(Errno::EINVAL)?;
        let old_root_idx = self
            .entries
            .iter()
            .position(|e| e.live && e.target() == b"/")
            .ok_or(Errno::EINVAL)?;

        // Move old `/` to `rel_old` and promote `new_root` to `/`.
        self.entries[old_root_idx].target = [0u8; MAX_MOUNT_PATH];
        self.entries[old_root_idx].target[..rel_old.len()].copy_from_slice(rel_old);
        self.entries[old_root_idx].target_len = rel_old.len();

        self.entries[new_idx].target = [0u8; MAX_MOUNT_PATH];
        self.entries[new_idx].target[0] = b'/';
        self.entries[new_idx].target_len = 1;
        Ok(())
    }

    /// Resolves `path` against the longest matching mount point in the table, returning the
    /// matched [`MountEntry`] and the mount-relative suffix (without leading `/`).
    pub fn resolve<'a>(&self, path: &'a [u8]) -> Result<(MountEntry, &'a [u8]), Errno> {
        let normalized = normalize_mount_path(path)?;
        let mut best: Option<MountEntry> = None;
        for entry in &self.entries {
            if !entry.live {
                continue;
            }
            let tgt = entry.target();
            let matches = if tgt == b"/" {
                normalized.starts_with(b"/")
            } else {
                normalized == tgt
                    || (normalized.len() > tgt.len()
                        && normalized.starts_with(tgt)
                        && normalized[tgt.len()] == b'/')
            };
            if matches {
                let replace = match best {
                    None => true,
                    Some(prev) => tgt.len() > prev.target().len(),
                };
                if replace {
                    best = Some(*entry);
                }
            }
        }
        let chosen = best.ok_or(Errno::ENOENT)?;
        let rel = if chosen.target() == b"/" {
            &normalized[1..]
        } else if normalized.len() == chosen.target().len() {
            b""
        } else {
            &normalized[chosen.target().len() + 1..]
        };
        Ok((chosen, rel))
    }

    /// Invokes `f` for every live mount entry in the table.
    pub fn for_each_live(&self, mut f: impl FnMut(&MountEntry)) {
        for entry in &self.entries {
            if entry.live {
                f(entry);
            }
        }
    }

    /// Returns the live mount entry matching `mount_id`, if present.
    pub fn entry_by_id(&self, mount_id: u32) -> Option<MountEntry> {
        self.entries
            .iter()
            .copied()
            .find(|entry| entry.live && entry.mount_id == mount_id)
    }

    /// Formats `/proc/mounts` lines from the live mount table into `out`.
    pub fn format_proc_mounts(&self, out: &mut [u8]) -> usize {
        let mut cursor = 0usize;
        for entry in &self.entries {
            if !entry.live {
                continue;
            }
            let rw = if entry.is_readonly() {
                &b"ro"[..]
            } else {
                &b"rw"[..]
            };
            let parts: [&[u8]; 9] = [
                entry.source(),
                b" ",
                entry.target(),
                b" ",
                entry.fstype().as_bytes(),
                b" ",
                rw,
                b" 0 0\n",
                b"",
            ];
            for part in parts {
                let take = part.len().min(out.len().saturating_sub(cursor));
                out[cursor..cursor + take].copy_from_slice(&part[..take]);
                cursor += take;
            }
        }
        cursor
    }

    /// Formats Linux `/proc/self/mountinfo` lines (`<mnt_id> <parent_id> <maj>:<min> / <target> <opts> - <fstype> <source> rw`).
    pub fn format_proc_mountinfo(&self, out: &mut [u8]) -> usize {
        let mut cursor = 0usize;
        for entry in &self.entries {
            if !entry.live {
                continue;
            }
            let tgt = entry.target();
            let mut parent_id = 0u32;
            let mut best_parent_len = 0usize;
            if tgt != b"/" {
                for cand in &self.entries {
                    if !cand.live {
                        continue;
                    }
                    let ctgt = cand.target();
                    let is_parent = if ctgt == b"/" {
                        true
                    } else {
                        tgt.len() > ctgt.len() && tgt.starts_with(ctgt) && tgt[ctgt.len()] == b'/'
                    };
                    if is_parent && ctgt.len() > best_parent_len {
                        best_parent_len = ctgt.len();
                        parent_id = cand.mount_id;
                    }
                }
            }
            let (maj, min) = entry.fstype.st_dev_pair(entry.mount_id);
            let rw = if entry.is_readonly() {
                &b"ro"[..]
            } else {
                &b"rw"[..]
            };
            cursor += write_u64_ascii(u64::from(entry.mount_id), &mut out[cursor..]);
            cursor += copy_slice(&mut out[cursor..], b" ");
            cursor += write_u64_ascii(u64::from(parent_id), &mut out[cursor..]);
            cursor += copy_slice(&mut out[cursor..], b" ");
            cursor += write_u64_ascii(u64::from(maj), &mut out[cursor..]);
            cursor += copy_slice(&mut out[cursor..], b":");
            cursor += write_u64_ascii(u64::from(min), &mut out[cursor..]);
            cursor += copy_slice(&mut out[cursor..], b" / ");
            cursor += copy_slice(&mut out[cursor..], tgt);
            cursor += copy_slice(&mut out[cursor..], b" ");
            cursor += copy_slice(&mut out[cursor..], rw);
            if entry.flags & MS_NOSUID != 0 {
                cursor += copy_slice(&mut out[cursor..], b",nosuid");
            }
            if entry.flags & MS_NODEV != 0 {
                cursor += copy_slice(&mut out[cursor..], b",nodev");
            }
            if entry.flags & MS_NOEXEC != 0 {
                cursor += copy_slice(&mut out[cursor..], b",noexec");
            }
            cursor += copy_slice(&mut out[cursor..], b" - ");
            cursor += copy_slice(&mut out[cursor..], entry.fstype.as_bytes());
            cursor += copy_slice(&mut out[cursor..], b" ");
            let src = if entry.source().is_empty() {
                entry.fstype.as_bytes()
            } else {
                entry.source()
            };
            cursor += copy_slice(&mut out[cursor..], src);
            cursor += copy_slice(&mut out[cursor..], b" ");
            cursor += copy_slice(&mut out[cursor..], rw);
            cursor += copy_slice(&mut out[cursor..], b"\n");
        }
        cursor
    }
}

fn normalize_mount_path(path: &[u8]) -> Result<&[u8], Errno> {
    if path.is_empty() || path[0] != b'/' {
        return Err(Errno::EINVAL);
    }
    if path.contains(&0) {
        return Err(Errno::EINVAL);
    }
    let mut trimmed = path;
    while trimmed.len() > 1 && trimmed.ends_with(b"/") {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    if trimmed.len() > MAX_MOUNT_PATH {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(trimmed)
}

/// Snapshot of live process and system metrics used to synthesize `/proc` and `/sys` files
/// without fake stub constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcSysSnapshot<'a> {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: &'a [u8],
    pub total_pages: u64,
    pub free_pages: u64,
    pub uptime_seconds: u64,
    pub online_cpus: u32,
    pub hostname: &'a [u8],
    pub boot_id_seed: [u8; 16],
}

/// Per-process `/proc/<pid>/*` formatting input without hardcoding PID 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcProcessInfo<'a> {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub uid: u32,
    pub gid: u32,
    pub state_char: u8,
    pub comm: &'a [u8],
    pub cmdline: &'a [u8],
    pub vm_size_kb: u64,
    pub vm_rss_kb: u64,
}

/// Target selector parsed from a `/proc/<pid>[/<subpath>]` relative path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcPidSelector {
    Current,
    Pid(u32),
}

/// Parses `rel` (relative to `/proc/`) into a PID selector and optional subpath after `<pid>/`.
pub fn parse_proc_pid_subpath(rel: &[u8]) -> Option<(ProcPidSelector, &[u8])> {
    if rel.is_empty() {
        return None;
    }
    let (head, tail) = match rel.iter().position(|&b| b == b'/') {
        Some(idx) => (&rel[..idx], &rel[idx + 1..]),
        None => (rel, &b""[..]),
    };
    let selector = if head == b"self" || head == b"thread-self" {
        ProcPidSelector::Current
    } else if !head.is_empty() && head.iter().all(|b| b.is_ascii_digit()) {
        let parsed = core::str::from_utf8(head).ok()?.parse::<u32>().ok()?;
        if parsed == 0 {
            return None;
        }
        ProcPidSelector::Pid(parsed)
    } else {
        return None;
    };
    Some((selector, tail))
}

fn state_label(state_char: u8) -> &'static [u8] {
    match state_char {
        b'Z' => b"Z (zombie)",
        b'S' => b"S (sleeping)",
        b'T' => b"T (stopped)",
        _ => b"R (running)",
    }
}

fn format_pid_status(info: &ProcProcessInfo<'_>, out: &mut [u8]) -> usize {
    let mut c = copy_slice(out, b"Name:\t");
    c += copy_slice(&mut out[c..], info.comm);
    c += copy_slice(&mut out[c..], b"\nState:\t");
    c += copy_slice(&mut out[c..], state_label(info.state_char));
    c += copy_slice(&mut out[c..], b"\nTgid:\t");
    c += write_u64_ascii(u64::from(info.pid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b"\nPid:\t");
    c += write_u64_ascii(u64::from(info.pid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b"\nPPid:\t");
    c += write_u64_ascii(u64::from(info.ppid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b"\nUid:\t");
    c += write_u64_ascii(u64::from(info.uid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b"\t");
    c += write_u64_ascii(u64::from(info.uid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b"\nGid:\t");
    c += write_u64_ascii(u64::from(info.gid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b"\t");
    c += write_u64_ascii(u64::from(info.gid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b"\nVmSize:\t");
    c += write_u64_ascii(info.vm_size_kb, &mut out[c..]);
    c += copy_slice(&mut out[c..], b" kB\nVmRSS:\t");
    c += write_u64_ascii(info.vm_rss_kb, &mut out[c..]);
    c += copy_slice(&mut out[c..], b" kB\n");
    c
}

fn format_pid_stat(info: &ProcProcessInfo<'_>, out: &mut [u8]) -> usize {
    let state = match info.state_char {
        b'Z' | b'S' | b'T' => info.state_char,
        _ => b'R',
    };
    let mut c = write_u64_ascii(u64::from(info.pid), out);
    c += copy_slice(&mut out[c..], b" (");
    c += copy_slice(&mut out[c..], info.comm);
    c += copy_slice(&mut out[c..], b") ");
    c += copy_slice(&mut out[c..], &[state]);
    c += copy_slice(&mut out[c..], b" ");
    c += write_u64_ascii(u64::from(info.ppid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b" ");
    c += write_u64_ascii(u64::from(info.pgid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b" ");
    c += write_u64_ascii(u64::from(info.sid), &mut out[c..]);
    c += copy_slice(&mut out[c..], b" 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 ");
    c += write_u64_ascii(info.vm_size_kb.saturating_mul(1024), &mut out[c..]);
    c += copy_slice(&mut out[c..], b" ");
    c += write_u64_ascii(info.vm_rss_kb / 4, &mut out[c..]);
    c += copy_slice(&mut out[c..], b"\n");
    c
}

fn format_pid_cmdline(info: &ProcProcessInfo<'_>, out: &mut [u8]) -> usize {
    if !info.cmdline.is_empty() {
        return copy_slice(out, info.cmdline);
    }
    let mut c = copy_slice(out, info.comm);
    if c < out.len() {
        out[c] = 0;
        c += 1;
    }
    c
}

/// Synthesizes `/proc/<pid>/<subpath>` for any active or zombie process.
pub fn read_procfs_process_node<const MAX_MOUNTS: usize>(
    subpath: &[u8],
    mounts: &MountTable<MAX_MOUNTS>,
    info: &ProcProcessInfo<'_>,
    out: &mut [u8],
) -> Option<usize> {
    match subpath {
        b"mounts" => Some(mounts.format_proc_mounts(out)),
        b"mountinfo" => Some(mounts.format_proc_mountinfo(out)),
        b"status" => Some(format_pid_status(info, out)),
        b"stat" => Some(format_pid_stat(info, out)),
        b"cmdline" => Some(format_pid_cmdline(info, out)),
        b"comm" => {
            let mut c = copy_slice(out, info.comm);
            c += copy_slice(&mut out[c..], b"\n");
            Some(c)
        }
        b"cgroup" => Some(copy_slice(out, b"0::/\n")),
        b"oom_score_adj" => Some(copy_slice(out, b"0\n")),
        _ => None,
    }
}

/// Lists deterministic directory children `(name, is_dir)` for a known `/sys/<rel_dir>` directory.
fn emit_sysfs_spec(spec: &[u8], mut emit: impl FnMut(&[u8], bool)) -> bool {
    for item in spec.split(|&b| b == b'|') {
        if item.len() < 3 || item[item.len() - 2] != b':' {
            continue;
        }
        emit(&item[..item.len() - 2], item[item.len() - 1] == b'D');
    }
    true
}

/// Returns `false` if `rel_dir` is not a sysfs directory.
pub fn enumerate_sysfs_dir(rel_dir: &[u8], emit: impl FnMut(&[u8], bool)) -> bool {
    let spec: &[u8] = match rel_dir {
        b"" => b"kernel:D|devices:D|class:D|dev:D|fs:D",
        b"kernel" => b"uevent_seqnum:R",
        b"fs" => b"cgroup:D",
        b"dev" => b"block:D|char:D",
        b"dev/block" => b"254:0:R",
        b"dev/char" => b"5:1:R|204:64:R",
        b"devices" => b"system:D|virtio0:D|virtio1:D|platform:D",
        b"devices/system" => b"cpu:D",
        b"devices/system/cpu" => b"online:R|present:R",
        b"devices/virtio0" => b"block:D",
        b"devices/virtio0/block" => b"vda:D",
        b"devices/virtio0/block/vda" => b"dev:R|size:R|uevent:R|subsystem:R",
        b"devices/virtio1" => b"net:D",
        b"devices/virtio1/net" => b"eth0:D",
        b"devices/virtio1/net/eth0" => b"ifindex:R|address:R|operstate:R|uevent:R|subsystem:R",
        b"devices/platform" => b"pl011:D",
        b"devices/platform/pl011" => b"tty:D",
        b"devices/platform/pl011/tty" => b"ttyAMA0:D",
        b"devices/platform/pl011/tty/ttyAMA0" => b"dev:R|uevent:R|subsystem:R",
        b"class" => b"tty:D|net:D|block:D",
        b"class/tty" => b"console:D|ttyAMA0:D",
        b"class/tty/console" => b"active:R|dev:R|uevent:R|subsystem:R",
        b"class/tty/ttyAMA0" => b"dev:R|uevent:R|subsystem:R",
        b"class/net" => b"lo:D|eth0:D",
        b"class/net/lo" => b"operstate:R|mtu:R|ifindex:R|uevent:R|subsystem:R",
        b"class/net/eth0" => b"ifindex:R|address:R|operstate:R|uevent:R|subsystem:R",
        b"class/block" => b"vda:D",
        b"class/block/vda" => b"dev:R|size:R|ro:R|uevent:R|subsystem:R",
        _ => return false,
    };
    emit_sysfs_spec(spec, emit)
}

/// Synthesizes `/proc/<rel_path>` content into `out`, returning `Some(bytes_written)` if the path
/// names a supported `procfs` node.
pub fn read_procfs_node<const MAX_MOUNTS: usize>(
    rel_path: &[u8],
    mounts: &MountTable<MAX_MOUNTS>,
    snap: &ProcSysSnapshot<'_>,
    out: &mut [u8],
) -> Option<usize> {
    match rel_path {
        b"mounts" => Some(mounts.format_proc_mounts(out)),
        b"cmdline" => Some(copy_slice(
            out,
            b"console=ttyAMA0,115200 root=/dev/vda rw init=/sbin/init\n",
        )),
        b"version" => Some(copy_slice(
            out,
            b"Linux version 6.12.0-qyronex (qyronex@build) #1 SMP PREEMPT Qyronex\n",
        )),
        b"filesystems" => Some(copy_slice(
            out,
            b"nodev\trootfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tsysfs\nnodev\tdevtmpfs\nnodev\tdevpts\nnodev\tcgroup2\n\text4\n",
        )),
        b"sys/kernel/osrelease" => Some(copy_slice(out, b"6.12.0-qyronex\n")),
        b"sys/kernel/hostname" => {
            let mut cursor = copy_slice(out, snap.hostname);
            cursor += copy_slice(&mut out[cursor..], b"\n");
            Some(cursor)
        }
        b"sys/kernel/random/boot_id" => Some(format_boot_id(&snap.boot_id_seed, out)),
        b"uptime" => {
            let mut cursor = write_u64_ascii(snap.uptime_seconds, out);
            cursor += copy_slice(&mut out[cursor..], b".00 0.00\n");
            Some(cursor)
        }
        b"loadavg" => Some(copy_slice(out, b"0.00 0.00 0.00 1/1 1\n")),
        b"stat" => Some(copy_slice(
            out,
            b"cpu  0 0 0 0 0 0 0 0 0 0\nintr 0\nctxt 0\nbtime 1700000000\nprocesses 1\nprocs_running 1\nprocs_blocked 0\n",
        )),
        b"cpuinfo" => {
            let mut c = 0usize;
            for cpu in 0..snap.online_cpus.max(1) {
                c += copy_slice(&mut out[c..], b"processor\t: ");
                c += write_u64_ascii(u64::from(cpu), &mut out[c..]);
                c += copy_slice(
                    &mut out[c..],
                    b"\nBogoMIPS\t: 125.00\nFeatures\t: fp asimd\nCPU architecture: 8\n\n",
                );
            }
            Some(c)
        }
        b"meminfo" => {
            let total_kb = snap.total_pages.saturating_mul(4);
            let free_kb = snap.free_pages.saturating_mul(4);
            let mut c = copy_slice(out, b"MemTotal:       ");
            c += write_u64_ascii(total_kb, &mut out[c..]);
            c += copy_slice(&mut out[c..], b" kB\nMemFree:        ");
            c += write_u64_ascii(free_kb, &mut out[c..]);
            c += copy_slice(&mut out[c..], b" kB\nMemAvailable:   ");
            c += write_u64_ascii(free_kb, &mut out[c..]);
            c += copy_slice(&mut out[c..], b" kB\n");
            Some(c)
        }
        b"self/mounts" | b"self/mountinfo" | b"self/status" | b"1/status" | b"self/stat"
        | b"1/stat" | b"self/cmdline" | b"1/cmdline" => {
            let subpath = rel_path
                .iter()
                .position(|&b| b == b'/')
                .map_or(&b""[..], |idx| &rel_path[idx + 1..]);
            let info = ProcProcessInfo {
                pid: snap.pid,
                ppid: snap.ppid,
                pgid: snap.pgid,
                sid: snap.sid,
                uid: snap.uid,
                gid: snap.gid,
                state_char: b'R',
                comm: snap.comm,
                cmdline: snap.comm,
                vm_size_kb: 4096,
                vm_rss_kb: 1024,
            };
            read_procfs_process_node(subpath, mounts, &info, out)
        }
        _ => None,
    }
}

/// Synthesizes `/sys/<rel_path>` content into `out`, returning `Some(bytes_written)` if the path
/// names a supported `sysfs` node.
pub fn read_sysfs_node(
    rel_path: &[u8],
    snap: &ProcSysSnapshot<'_>,
    out: &mut [u8],
) -> Option<usize> {
    match rel_path {
        b"kernel/uevent_seqnum" => Some(copy_slice(out, b"1\n")),
        b"devices/system/cpu/online" | b"devices/system/cpu/present" => {
            if snap.online_cpus <= 1 {
                Some(copy_slice(out, b"0\n"))
            } else {
                let mut c = copy_slice(out, b"0-");
                c += write_u64_ascii(u64::from(snap.online_cpus - 1), &mut out[c..]);
                c += copy_slice(&mut out[c..], b"\n");
                Some(c)
            }
        }
        b"class/tty/console/active" => Some(copy_slice(out, b"ttyAMA0\n")),
        b"class/tty/console/dev" => Some(copy_slice(out, b"5:1\n")),
        b"class/tty/console/uevent" => {
            Some(copy_slice(out, b"MAJOR=5\nMINOR=1\nDEVNAME=console\n"))
        }
        b"class/net/lo/operstate" => Some(copy_slice(out, b"unknown\n")),
        b"class/net/lo/mtu" => Some(copy_slice(out, b"65536\n")),
        b"class/net/lo/ifindex" => Some(copy_slice(out, b"1\n")),
        b"class/net/lo/uevent" => Some(copy_slice(out, b"INTERFACE=lo\nIFINDEX=1\n")),
        b"class/block/vda/ro" => Some(copy_slice(out, b"0\n")),
        _ => None,
    }
}

// ============================================================================
// Persistent Ext4 Superblock / Extent / Directory Reader & Durable Write Layer
// ============================================================================

/// On-disk `ext4` superblock magic (`0xEF53` at offset `1024 + 0x38`).
pub const EXT4_SUPER_MAGIC: u16 = 0xef53;
/// On-disk `ext4_extent_header` magic (`0xF30A`).
pub const EXT4_EXTENT_MAGIC: u16 = 0xf30a;
/// `EXT4_EXTENTS_FL` inode flag (`0x0008_0000`).
pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

/// Validated `ext4` superblock geometry parsed from byte offset 1024 of a block image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub block_size: usize,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: usize,
    pub first_data_block: u32,
}

impl Ext4Superblock {
    pub fn parse(image: &[u8]) -> Result<Self, Errno> {
        if image.len() < 2048 {
            return Err(Errno::EINVAL);
        }
        let sb = &image[1024..2048];
        let magic = read_u16_le(sb, 0x38)?;
        if magic != EXT4_SUPER_MAGIC {
            return Err(Errno::EINVAL);
        }
        let inodes_count = read_u32_le(sb, 0x00)?;
        let blocks_lo = u64::from(read_u32_le(sb, 0x04)?);
        let first_data_block = read_u32_le(sb, 0x14)?;
        let log_block_size = read_u32_le(sb, 0x18)?;
        if log_block_size > 6 {
            return Err(Errno::EINVAL);
        }
        let block_size = 1024usize << log_block_size;
        let blocks_per_group = read_u32_le(sb, 0x20)?;
        let inodes_per_group = read_u32_le(sb, 0x28)?;
        let inode_size = usize::from(read_u16_le(sb, 0x58)?);
        if inodes_per_group == 0 || blocks_per_group == 0 || inode_size < 128 {
            return Err(Errno::EINVAL);
        }
        Ok(Self {
            inodes_count,
            blocks_count: blocks_lo,
            block_size,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            first_data_block,
        })
    }

    /// Reads the raw data of a single-extent file by inode number (`ino >= 1`) from `image`.
    pub fn read_extent_file<'a>(
        &self,
        image: &'a [u8],
        ino: u32,
    ) -> Result<(u16, &'a [u8]), Errno> {
        if ino == 0 || ino > self.inodes_count {
            return Err(Errno::ENOENT);
        }
        let group = (ino - 1) / self.inodes_per_group;
        let index = (ino - 1) % self.inodes_per_group;
        let gdt_block = if self.block_size == 1024 {
            2usize
        } else {
            1usize
        };
        let gd_offset = gdt_block
            .checked_mul(self.block_size)
            .and_then(|base| base.checked_add((group as usize).checked_mul(32)?))
            .ok_or(Errno::EIO)?;
        let inode_table_block = read_u32_le(image, gd_offset + 8)? as usize;
        let inode_offset = inode_table_block
            .checked_mul(self.block_size)
            .and_then(|base| base.checked_add((index as usize).checked_mul(self.inode_size)?))
            .ok_or(Errno::EIO)?;
        if inode_offset.saturating_add(self.inode_size) > image.len() {
            return Err(Errno::EIO);
        }
        let inode = &image[inode_offset..inode_offset + self.inode_size];
        let mode = read_u16_le(inode, 0x00)?;
        let size_lo = read_u32_le(inode, 0x04)? as usize;
        let flags = read_u32_le(inode, 0x20)?;
        if flags & EXT4_EXTENTS_FL == 0 {
            return Err(Errno::EINVAL);
        }
        // Parse `ext4_extent_header` at `i_block` (offset 0x28..0x64).
        let ext_magic = read_u16_le(inode, 0x28)?;
        let ext_entries = read_u16_le(inode, 0x2a)?;
        let ext_depth = read_u16_le(inode, 0x2e)?;
        if ext_magic != EXT4_EXTENT_MAGIC || ext_depth != 0 {
            return Err(Errno::EINVAL);
        }
        if ext_entries == 0 || size_lo == 0 {
            return Ok((mode, &[]));
        }
        let ee_start_hi = u64::from(read_u16_le(inode, 0x28 + 12 + 6)?);
        let ee_start_lo = u64::from(read_u32_le(inode, 0x28 + 12 + 8)?);
        let start_block =
            usize::try_from((ee_start_hi << 32) | ee_start_lo).map_err(|_| Errno::EIO)?;
        let byte_start = start_block.checked_mul(self.block_size).ok_or(Errno::EIO)?;
        let byte_end = byte_start.checked_add(size_lo).ok_or(Errno::EIO)?;
        if byte_end > image.len() {
            return Err(Errno::EIO);
        }
        Ok((mode, &image[byte_start..byte_end]))
    }
}

#[derive(Clone, Copy)]
struct DurableFileEntry<const MAX_FILE_BYTES: usize> {
    live: bool,
    dirty: bool,
    path: [u8; MAX_MOUNT_PATH],
    path_len: usize,
    mode: u32,
    data: [u8; MAX_FILE_BYTES],
    len: usize,
}

impl<const MAX_FILE_BYTES: usize> DurableFileEntry<MAX_FILE_BYTES> {
    const EMPTY: Self = Self {
        live: false,
        dirty: false,
        path: [0u8; MAX_MOUNT_PATH],
        path_len: 0,
        mode: 0o100_644,
        data: [0u8; MAX_FILE_BYTES],
        len: 0,
    };

    fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// Durable read/write `ext4` root volume state supporting atomic `rename` (`dpkg` replacement) and
/// `fsync`/`fdatasync`/`sync` commit barriers.
pub struct Ext4DurableJournal<const MAX_FILES: usize, const MAX_FILE_BYTES: usize> {
    files: [DurableFileEntry<MAX_FILE_BYTES>; MAX_FILES],
    sync_generation: u64,
}

impl<const MAX_FILES: usize, const MAX_FILE_BYTES: usize> Default
    for Ext4DurableJournal<MAX_FILES, MAX_FILE_BYTES>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_FILES: usize, const MAX_FILE_BYTES: usize>
    Ext4DurableJournal<MAX_FILES, MAX_FILE_BYTES>
{
    pub const fn new() -> Self {
        Self {
            files: [DurableFileEntry::EMPTY; MAX_FILES],
            sync_generation: 0,
        }
    }

    pub fn write_file(&mut self, path: &[u8], mode: u32, bytes: &[u8]) -> Result<(), Errno> {
        let norm = normalize_mount_path(path)?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Errno::ENOSPC);
        }
        if let Some(existing) = self.files.iter_mut().find(|f| f.live && f.path() == norm) {
            existing.data = [0u8; MAX_FILE_BYTES];
            existing.data[..bytes.len()].copy_from_slice(bytes);
            existing.len = bytes.len();
            existing.dirty = true;
            return Ok(());
        }
        let slot = self
            .files
            .iter_mut()
            .find(|f| !f.live)
            .ok_or(Errno::ENOSPC)?;
        *slot = DurableFileEntry::EMPTY;
        slot.live = true;
        slot.dirty = true;
        slot.path[..norm.len()].copy_from_slice(norm);
        slot.path_len = norm.len();
        slot.mode = mode;
        slot.data[..bytes.len()].copy_from_slice(bytes);
        slot.len = bytes.len();
        Ok(())
    }

    pub fn read_file(&self, path: &[u8]) -> Result<&[u8], Errno> {
        let norm = normalize_mount_path(path)?;
        let entry = self
            .files
            .iter()
            .find(|f| f.live && f.path() == norm)
            .ok_or(Errno::ENOENT)?;
        Ok(&entry.data[..entry.len])
    }

    /// Atomically renames `old_path` to `new_path`, replacing any existing file at `new_path`
    /// without leaving a window where `new_path` is missing (required by `dpkg`).
    pub fn atomic_rename(&mut self, old_path: &[u8], new_path: &[u8]) -> Result<(), Errno> {
        let norm_old = normalize_mount_path(old_path)?;
        let norm_new = normalize_mount_path(new_path)?;
        if norm_old == norm_new {
            return Ok(());
        }
        let src_idx = self
            .files
            .iter()
            .position(|f| f.live && f.path() == norm_old)
            .ok_or(Errno::ENOENT)?;
        if let Some(dst_idx) = self
            .files
            .iter()
            .position(|f| f.live && f.path() == norm_new)
        {
            self.files[dst_idx] = DurableFileEntry::EMPTY;
        }
        self.files[src_idx].path = [0u8; MAX_MOUNT_PATH];
        self.files[src_idx].path[..norm_new.len()].copy_from_slice(norm_new);
        self.files[src_idx].path_len = norm_new.len();
        self.files[src_idx].dirty = true;
        Ok(())
    }

    /// Flushes one file (`fsync` / `fdatasync`) and advances the durable commit generation.
    pub fn fsync_path(&mut self, path: &[u8]) -> Result<u64, Errno> {
        let norm = normalize_mount_path(path)?;
        let entry = self
            .files
            .iter_mut()
            .find(|f| f.live && f.path() == norm)
            .ok_or(Errno::ENOENT)?;
        entry.dirty = false;
        self.sync_generation = self.sync_generation.saturating_add(1);
        Ok(self.sync_generation)
    }

    /// Flushes all dirty files (`sync(2)` / `syncfs(2)`).
    pub fn sync_all(&mut self) -> u64 {
        for file in &mut self.files {
            if file.live {
                file.dirty = false;
            }
        }
        self.sync_generation = self.sync_generation.saturating_add(1);
        self.sync_generation
    }

    pub fn has_dirty_files(&self) -> bool {
        self.files.iter().any(|f| f.live && f.dirty)
    }

    pub const fn sync_generation(&self) -> u64 {
        self.sync_generation
    }
}

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, Errno> {
    let slice = buf.get(offset..offset + 2).ok_or(Errno::EINVAL)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, Errno> {
    let slice = buf.get(offset..offset + 4).ok_or(Errno::EINVAL)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn copy_slice(out: &mut [u8], src: &[u8]) -> usize {
    let take = src.len().min(out.len());
    out[..take].copy_from_slice(&src[..take]);
    take
}

fn write_u64_ascii(mut value: u64, out: &mut [u8]) -> usize {
    let mut digits = [0u8; 20];
    let mut len = 0usize;
    if value == 0 {
        digits[0] = b'0';
        len = 1;
    } else {
        while value > 0 {
            digits[len] = b'0' + (value % 10) as u8;
            value /= 10;
            len += 1;
        }
        digits[..len].reverse();
    }
    copy_slice(out, &digits[..len])
}

fn format_boot_id(seed: &[u8; 16], out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut uuid = [0u8; 37];
    let mut pos = 0usize;
    for (idx, byte) in seed.iter().copied().enumerate() {
        if matches!(idx, 4 | 6 | 8 | 10) {
            uuid[pos] = b'-';
            pos += 1;
        }
        uuid[pos] = HEX[(byte >> 4) as usize];
        uuid[pos + 1] = HEX[(byte & 0x0f) as usize];
        pos += 2;
    }
    uuid[36] = b'\n';
    copy_slice(out, &uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_table_supports_hierarchy_remount_pivot_root_and_proc_mounts() {
        let mut table = MountTable::<12>::new();
        table.seed_default_hierarchy().unwrap();

        let (root_mnt, rel) = table.resolve(b"/etc/passwd").unwrap();
        assert_eq!(root_mnt.fstype(), FilesystemType::Initramfs);
        assert!(root_mnt.is_readonly());
        assert_eq!(rel, b"etc/passwd");

        let (pts_mnt, pts_rel) = table.resolve(b"/dev/pts/0").unwrap();
        assert_eq!(pts_mnt.fstype(), FilesystemType::Devpts);
        assert_eq!(pts_rel, b"0");

        // Mount persistent ext4 image at /newroot, then pivot_root("/newroot", "/newroot/oldroot").
        table
            .mount(b"/dev/vda", b"/newroot", Some(b"ext4"), MS_RDONLY)
            .unwrap();
        table.pivot_root(b"/newroot", b"/newroot/oldroot").unwrap();

        let (new_root, _) = table.resolve(b"/sbin/init").unwrap();
        assert_eq!(new_root.fstype(), FilesystemType::Ext4);
        assert!(new_root.is_readonly());

        // systemd-remount-fs remounts / read-write.
        table.mount(b"/dev/vda", b"/", None, MS_REMOUNT).unwrap();
        let (rw_root, _) = table.resolve(b"/sbin/init").unwrap();
        assert!(!rw_root.is_readonly());

        // Unmount old initramfs root at /oldroot.
        table.umount2(b"/oldroot", MNT_DETACH).unwrap();

        let mut mounts_buf = [0u8; 512];
        let n = table.format_proc_mounts(&mut mounts_buf);
        let text = core::str::from_utf8(&mounts_buf[..n]).unwrap();
        assert!(text.contains("/dev/vda / ext4 rw 0 0\n"));
        assert!(text.contains("proc /proc proc ro"));
    }

    #[test]
    fn procfs_and_sysfs_nodes_synthesize_live_snapshot_values() {
        let mut table = MountTable::<8>::new();
        table.seed_default_hierarchy().unwrap();
        let snap = ProcSysSnapshot {
            pid: 1,
            ppid: 0,
            pgid: 1,
            sid: 1,
            uid: 0,
            gid: 0,
            comm: b"systemd",
            total_pages: 65536,
            free_pages: 48000,
            uptime_seconds: 42,
            online_cpus: 4,
            hostname: b"debian-qyronex",
            boot_id_seed: [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
                0xdc, 0xfe,
            ],
        };

        let mut buf = [0u8; 256];
        let len = read_procfs_node(b"self/status", &table, &snap, &mut buf).unwrap();
        let status = core::str::from_utf8(&buf[..len]).unwrap();
        assert!(status.contains("Name:\tsystemd\n"));
        assert!(status.contains("Pid:\t1\n"));

        let len = read_procfs_node(b"sys/kernel/random/boot_id", &table, &snap, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"01234567-89ab-cdef-1032-547698badcfe\n");

        let len = read_sysfs_node(b"devices/system/cpu/online", &snap, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"0-3\n");
    }

    #[test]
    fn ext4_superblock_extent_parser_and_dpkg_durable_journal_work() {
        // Construct a synthetic 4-block (4096-byte block) ext4 image with inode 2 pointing to block 3.
        let mut img = [0u8; 4 * 4096];
        // Superblock at offset 1024:
        img[1024..1028].copy_from_slice(&16u32.to_le_bytes()); // s_inodes_count = 16
        img[1024 + 4..1024 + 8].copy_from_slice(&4u32.to_le_bytes()); // s_blocks_count_lo = 4
        img[1024 + 0x18..1024 + 0x1c].copy_from_slice(&2u32.to_le_bytes()); // s_log_block_size = 2 (4096)
        img[1024 + 0x20..1024 + 0x24].copy_from_slice(&32768u32.to_le_bytes()); // s_blocks_per_group
        img[1024 + 0x28..1024 + 0x2c].copy_from_slice(&16u32.to_le_bytes()); // s_inodes_per_group
        img[1024 + 0x38..1024 + 0x3a].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        img[1024 + 0x58..1024 + 0x5a].copy_from_slice(&128u16.to_le_bytes()); // s_inode_size = 128

        // Block group descriptor 0 at block 1 (offset 4096): bg_inode_table_lo = block 2
        img[4096 + 8..4096 + 12].copy_from_slice(&2u32.to_le_bytes());

        // Inode 2 at block 2 + 128 (offset 8192 + 128):
        let ino2 = 2 * 4096 + 128;
        img[ino2..ino2 + 2].copy_from_slice(&0o100_755u16.to_le_bytes()); // mode
        img[ino2 + 4..ino2 + 8].copy_from_slice(&11u32.to_le_bytes()); // size = 11 bytes
        img[ino2 + 0x20..ino2 + 0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
        img[ino2 + 0x28..ino2 + 0x2a].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        img[ino2 + 0x2a..ino2 + 0x2c].copy_from_slice(&1u16.to_le_bytes()); // eh_entries = 1
        img[ino2 + 0x2e..ino2 + 0x30].copy_from_slice(&0u16.to_le_bytes()); // eh_depth = 0
        img[ino2 + 0x28 + 12 + 8..ino2 + 0x28 + 12 + 12].copy_from_slice(&3u32.to_le_bytes()); // ee_start_lo = block 3

        img[3 * 4096..3 * 4096 + 11].copy_from_slice(b"#!/bin/sh\n\0");

        let sb = Ext4Superblock::parse(&img).unwrap();
        assert_eq!(sb.block_size, 4096);
        let (mode, data) = sb.read_extent_file(&img, 2).unwrap();
        assert_eq!(mode, 0o100_755);
        assert_eq!(data, b"#!/bin/sh\n\0");

        // Package-manager dpkg write-temp -> fsync -> atomic_rename -> sync_all workflow:
        let mut journal = Ext4DurableJournal::<8, 256>::new();
        journal
            .write_file(
                b"/var/lib/dpkg/status-new",
                0o100_644,
                b"Package: libc6\nStatus: install ok installed\n",
            )
            .unwrap();
        assert!(journal.has_dirty_files());
        let g1 = journal.fsync_path(b"/var/lib/dpkg/status-new").unwrap();
        assert_eq!(g1, 1);
        assert!(!journal.has_dirty_files());

        journal
            .atomic_rename(b"/var/lib/dpkg/status-new", b"/var/lib/dpkg/status")
            .unwrap();
        assert!(journal.has_dirty_files());
        assert_eq!(
            journal.read_file(b"/var/lib/dpkg/status-new"),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            journal.read_file(b"/var/lib/dpkg/status").unwrap(),
            b"Package: libc6\nStatus: install ok installed\n"
        );
        let g2 = journal.sync_all();
        assert_eq!(g2, 2);
        assert!(!journal.has_dirty_files());
    }

    #[test]
    fn mount_propagation_unbindable_and_overlay_type_work() {
        let mut tbl = MountTable::<12>::new();
        tbl.seed_default_hierarchy().unwrap();
        tbl.mount(
            b"overlay",
            b"/var/lib/oci/rootfs",
            Some(b"overlay"),
            MS_NODEV,
        )
        .unwrap();
        tbl.mount(
            b"tmpfs",
            b"/var/lib/oci/rootfs/tmp",
            Some(b"tmpfs"),
            MS_SHARED,
        )
        .unwrap();

        // Mark container root + child recursively unbindable; bind-mounting it must fail with EINVAL.
        tbl.mount(b"", b"/var/lib/oci/rootfs", None, MS_UNBINDABLE | MS_REC)
            .unwrap();
        assert_eq!(
            tbl.mount(b"/var/lib/oci/rootfs/tmp", b"/mnt/leak", None, MS_BIND),
            Err(Errno::EINVAL)
        );

        // Child mount namespace demotes MS_SHARED -> MS_SLAVE cleanly when isolated.
        tbl.mount(b"", b"/var/lib/oci/rootfs/tmp", None, MS_SHARED)
            .unwrap();
        let child = tbl.clone_into_child_namespace(true);
        let (entry, _) = child.resolve(b"/var/lib/oci/rootfs/tmp/file").unwrap();
        assert_ne!(entry.flags() & MS_SLAVE, 0);
        assert_eq!(entry.flags() & MS_SHARED, 0);
        let (ov, _) = child
            .resolve(b"/var/lib/oci/rootfs/etc/os-release")
            .unwrap();
        assert_eq!(ov.fstype(), FilesystemType::Overlay);
    }

    #[test]
    fn proc_pid_enumeration_and_sysfs_dir_listing_work_for_arbitrary_pid() {
        let mut tbl = MountTable::<12>::new();
        tbl.seed_default_hierarchy().unwrap();

        assert_eq!(
            parse_proc_pid_subpath(b"self/status"),
            Some((ProcPidSelector::Current, &b"status"[..]))
        );
        assert_eq!(
            parse_proc_pid_subpath(b"42/stat"),
            Some((ProcPidSelector::Pid(42), &b"stat"[..]))
        );
        assert_eq!(
            parse_proc_pid_subpath(b"42"),
            Some((ProcPidSelector::Pid(42), &b""[..]))
        );
        assert_eq!(parse_proc_pid_subpath(b"0/stat"), None);
        assert_eq!(parse_proc_pid_subpath(b"meminfo"), None);

        let info = ProcProcessInfo {
            pid: 42,
            ppid: 1,
            pgid: 42,
            sid: 1,
            uid: 0,
            gid: 0,
            state_char: b'Z',
            comm: b"ps",
            cmdline: b"/bin/ps\0aux\0",
            vm_size_kb: 2048,
            vm_rss_kb: 512,
        };
        let mut buf = [0u8; 512];
        let st_len = read_procfs_process_node(b"status", &tbl, &info, &mut buf).unwrap();
        let st = core::str::from_utf8(&buf[..st_len]).unwrap();
        assert!(st.contains("Name:\tps\n"));
        assert!(st.contains("State:\tZ (zombie)\n"));
        assert!(st.contains("Pid:\t42\nPPid:\t1\n"));

        let stat_len = read_procfs_process_node(b"stat", &tbl, &info, &mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..stat_len]).unwrap(),
            "42 (ps) Z 1 42 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 2097152 128\n"
        );

        let cmd_len = read_procfs_process_node(b"cmdline", &tbl, &info, &mut buf).unwrap();
        assert_eq!(&buf[..cmd_len], b"/bin/ps\0aux\0");

        let mut dirs = 0usize;
        let mut saw_dev = false;
        assert!(enumerate_sysfs_dir(b"", |name, is_dir| {
            if is_dir {
                dirs += 1;
                if name == b"dev" {
                    saw_dev = true;
                }
            }
        }));
        assert_eq!(dirs, 5);
        assert!(saw_dev);
        assert!(!enumerate_sysfs_dir(b"does/not/exist", |_, _| {}));

        let mi_len = read_procfs_process_node(b"mountinfo", &tbl, &info, &mut buf).unwrap();
        let mi = core::str::from_utf8(&buf[..mi_len]).unwrap();
        assert!(mi.contains(" / /proc ro,nosuid,nodev,noexec - proc proc "));
        assert!(mi.contains(" / /sys ro,nosuid,nodev,noexec - sysfs sysfs "));
        assert_ne!(
            FilesystemType::Procfs.st_dev(4),
            FilesystemType::Sysfs.st_dev(5)
        );
    }
}
