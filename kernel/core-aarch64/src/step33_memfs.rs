// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! In-memory writable virtual filesystems (`tmpfs`, `devtmpfs`, `devpts`) for Step 33+.

use alloc::vec::Vec;
use kernal_linux_abi::Errno;
use kernal_linux_mounts::FilesystemType;

const MAX_MEMFS_NODES: usize = 4096;
const MAX_MEMFS_FILE_BYTES: usize = 1024 * 1024;
const MAX_NAME_LEN: usize = 255;

const S_IFMT: u32 = 0o170_000;
const S_IFSOCK: u32 = 0o140_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFREG: u32 = 0o100_000;
const S_IFBLK: u32 = 0o060_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;

const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_BLK: u8 = 6;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;

#[inline]
const fn makedev(major: u32, minor: u32) -> u64 {
    let maj = major as u64;
    let min = minor as u64;
    ((maj & 0x0fff) << 8) | ((maj & !0x0fff) << 32) | (min & 0xff) | ((min & !0xff) << 12)
}

pub(super) const fn dev_path_for_rdev(rdev: u64) -> Option<&'static [u8]> {
    match rdev {
        x if x == makedev(1, 3) => Some(b"/dev/null"),
        x if x == makedev(1, 5) => Some(b"/dev/zero"),
        x if x == makedev(1, 7) => Some(b"/dev/full"),
        x if x == makedev(1, 8) => Some(b"/dev/random"),
        x if x == makedev(1, 9) => Some(b"/dev/urandom"),
        x if x == makedev(5, 0) => Some(b"/dev/tty"),
        x if x == makedev(5, 1) => Some(b"/dev/console"),
        x if x == makedev(5, 2) => Some(b"/dev/ptmx"),
        x if x == makedev(204, 64) => Some(b"/dev/ttyAMA0"),
        x if x == makedev(1, 11) => Some(b"/dev/kmsg"),
        x if x == makedev(254, 0) => Some(b"/dev/vda"),
        x if x == makedev(254, 1) => Some(b"/dev/vda1"),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MemNodeKind {
    Dir,
    File,
    Symlink,
    Socket,
    Fifo,
    ChrDev(u64),
    BlkDev(u64),
}

impl MemNodeKind {
    pub(super) const fn dt_type(self) -> u8 {
        match self {
            Self::Dir => DT_DIR,
            Self::File => DT_REG,
            Self::Symlink => DT_LNK,
            Self::Socket => DT_SOCK,
            Self::Fifo => DT_FIFO,
            Self::ChrDev(_) => DT_CHR,
            Self::BlkDev(_) => DT_BLK,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MemStat {
    pub mount_id: u32,
    pub ino: u64,
    pub kind: MemNodeKind,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    pub atime: u32,
    pub mtime: u32,
    pub ctime: u32,
}

#[derive(Clone)]
struct MemNode {
    mount_id: u32,
    ino: u64,
    parent_ino: u64,
    name: Vec<u8>,
    kind: MemNodeKind,
    mode: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    data: Vec<u8>,
    atime: u32,
    mtime: u32,
    ctime: u32,
    unlinked: bool,
    open_refs: u32,
}

impl MemNode {
    fn as_stat(&self, nlink: u32) -> MemStat {
        MemStat {
            mount_id: self.mount_id,
            ino: self.ino,
            kind: self.kind,
            mode: self.mode,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: self.rdev,
            size: self.data.len() as u64,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
        }
    }
}

pub(super) struct MemFs {
    nodes: Vec<MemNode>,
    next_ino: u64,
}

impl MemFs {
    pub(super) const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            next_ino: 2,
        }
    }

    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino = self.next_ino.saturating_add(1).max(2);
        ino
    }

    fn count_nlink(&self, mount_id: u32, node: &MemNode) -> u32 {
        if node.unlinked {
            return 0;
        }
        if node.kind != MemNodeKind::Dir {
            return 1;
        }
        let child_dirs = self
            .nodes
            .iter()
            .filter(|n| {
                !n.unlinked
                    && n.mount_id == mount_id
                    && n.parent_ino == node.ino
                    && n.kind == MemNodeKind::Dir
            })
            .count() as u32;
        2u32.saturating_add(child_dirs)
    }

    fn find_root_idx(&self, mount_id: u32) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| !n.unlinked && n.mount_id == mount_id && n.parent_ino == 0)
    }

    fn find_ino_idx(&self, mount_id: u32, ino: u64) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.mount_id == mount_id && n.ino == ino)
    }

    fn find_child_idx(&self, mount_id: u32, parent_ino: u64, name: &[u8]) -> Option<usize> {
        self.nodes.iter().position(|n| {
            !n.unlinked
                && n.mount_id == mount_id
                && n.parent_ino == parent_ino
                && n.name.as_slice() == name
        })
    }

    fn push_node(&mut self, node: MemNode) -> Result<u64, Errno> {
        if self.nodes.len() >= MAX_MEMFS_NODES {
            return Err(Errno::ENOSPC);
        }
        let ino = node.ino;
        self.nodes.push(node);
        Ok(ino)
    }

    fn seed_node(
        &mut self,
        mount_id: u32,
        parent_ino: u64,
        name: &[u8],
        kind: MemNodeKind,
        mode: u32,
        rdev: u64,
        data: &[u8],
        now: u32,
    ) -> Option<u64> {
        if self.find_child_idx(mount_id, parent_ino, name).is_some() {
            return None;
        }
        let ino = self.alloc_ino();
        self.push_node(MemNode {
            mount_id,
            ino,
            parent_ino,
            name: name.to_vec(),
            kind,
            mode,
            uid: 0,
            gid: 0,
            rdev,
            data: data.to_vec(),
            atime: now,
            mtime: now,
            ctime: now,
            unlinked: false,
            open_refs: 0,
        })
        .ok()
    }

    pub(super) fn ensure_mount(
        &mut self,
        mount_id: u32,
        fstype: FilesystemType,
        root_perm: Option<u32>,
        now: u32,
    ) {
        if !matches!(
            fstype,
            FilesystemType::Tmpfs
                | FilesystemType::Ramfs
                | FilesystemType::Devtmpfs
                | FilesystemType::Devpts
        ) {
            return;
        }
        if let Some(root_idx) = self.find_root_idx(mount_id) {
            if let Some(perm) = root_perm {
                self.nodes[root_idx].mode = S_IFDIR | (perm & 0o7777);
                self.nodes[root_idx].ctime = now;
            }
            return;
        }
        let ino = self.alloc_ino();
        let mode = S_IFDIR | (root_perm.unwrap_or(0o755) & 0o7777);
        if self
            .push_node(MemNode {
                mount_id,
                ino,
                parent_ino: 0,
                name: Vec::new(),
                kind: MemNodeKind::Dir,
                mode,
                uid: 0,
                gid: 0,
                rdev: 0,
                data: Vec::new(),
                atime: now,
                mtime: now,
                ctime: now,
                unlinked: false,
                open_refs: 0,
            })
            .is_err()
        {
            return;
        }
        if fstype == FilesystemType::Devtmpfs {
            self.seed_devtmpfs_root(mount_id, ino, now);
        }
    }

    fn seed_devtmpfs_root(&mut self, mount_id: u32, root_ino: u64, now: u32) {
        for dir_name in [&b"pts"[..], b"bus", b"disk", b"char", b"block"] {
            let _ = self.seed_node(
                mount_id,
                root_ino,
                dir_name,
                MemNodeKind::Dir,
                S_IFDIR | 0o755,
                0,
                b"",
                now,
            );
        }
        let _ = self.seed_node(
            mount_id,
            root_ino,
            b"shm",
            MemNodeKind::Dir,
            S_IFDIR | 0o1777,
            0,
            b"",
            now,
        );
        for (name, target) in [
            (&b"fd"[..], &b"/proc/self/fd"[..]),
            (b"stdin", b"/proc/self/fd/0"),
            (b"stdout", b"/proc/self/fd/1"),
            (b"stderr", b"/proc/self/fd/2"),
        ] {
            let _ = self.seed_node(
                mount_id,
                root_ino,
                name,
                MemNodeKind::Symlink,
                S_IFLNK | 0o777,
                0,
                target,
                now,
            );
        }
        for (name, maj, min, mode) in [
            (&b"null"[..], 1u32, 3u32, 0o666u32),
            (b"zero", 1, 5, 0o666),
            (b"full", 1, 7, 0o666),
            (b"random", 1, 8, 0o666),
            (b"urandom", 1, 9, 0o666),
            (b"tty", 5, 0, 0o666),
            (b"console", 5, 1, 0o600),
            (b"ptmx", 5, 2, 0o666),
            (b"ttyAMA0", 204, 64, 0o620),
            (b"kmsg", 1, 11, 0o644),
        ] {
            let rdev = makedev(maj, min);
            let _ = self.seed_node(
                mount_id,
                root_ino,
                name,
                MemNodeKind::ChrDev(rdev),
                S_IFCHR | mode,
                rdev,
                b"",
                now,
            );
        }
        for (name, min) in [(&b"vda"[..], 0u32), (b"vda1", 1)] {
            let rdev = makedev(254, min);
            let _ = self.seed_node(
                mount_id,
                root_ino,
                name,
                MemNodeKind::BlkDev(rdev),
                S_IFBLK | 0o660,
                rdev,
                b"",
                now,
            );
        }
    }

    pub(super) fn unmount(&mut self, mount_id: u32) {
        self.nodes
            .retain(|n| n.mount_id != mount_id || n.open_refs > 0);
        for n in &mut self.nodes {
            if n.mount_id == mount_id {
                n.unlinked = true;
                n.parent_ino = 0;
                n.name.clear();
            }
        }
    }

    pub(super) fn root_stat(&self, mount_id: u32) -> Option<MemStat> {
        let idx = self.find_root_idx(mount_id)?;
        let node = &self.nodes[idx];
        Some(node.as_stat(self.count_nlink(mount_id, node)))
    }

    pub(super) fn lookup_child_stat(
        &self,
        mount_id: u32,
        parent_ino: u64,
        name: &[u8],
    ) -> Option<MemStat> {
        let idx = self.find_child_idx(mount_id, parent_ino, name)?;
        let node = &self.nodes[idx];
        Some(node.as_stat(self.count_nlink(mount_id, node)))
    }

    pub(super) fn stat_ino(&self, mount_id: u32, ino: u64) -> Option<MemStat> {
        let idx = self.find_ino_idx(mount_id, ino)?;
        let node = &self.nodes[idx];
        Some(node.as_stat(self.count_nlink(mount_id, node)))
    }

    pub(super) fn parent_ino(&self, mount_id: u32, ino: u64) -> Option<u64> {
        let idx = self.find_ino_idx(mount_id, ino)?;
        let parent = self.nodes[idx].parent_ino;
        if parent == 0 {
            Some(self.nodes[idx].ino)
        } else {
            Some(parent)
        }
    }

    pub(super) fn read_symlink(&self, mount_id: u32, ino: u64) -> Option<&[u8]> {
        let idx = self.find_ino_idx(mount_id, ino)?;
        let node = &self.nodes[idx];
        if node.kind == MemNodeKind::Symlink {
            Some(&node.data)
        } else {
            None
        }
    }

    pub(super) fn retain_fd(&mut self, mount_id: u32, ino: u64) {
        if let Some(idx) = self.find_ino_idx(mount_id, ino) {
            self.nodes[idx].open_refs = self.nodes[idx].open_refs.saturating_add(1);
        }
    }

    pub(super) fn release_fd(&mut self, mount_id: u32, ino: u64) {
        let Some(idx) = self.find_ino_idx(mount_id, ino) else {
            return;
        };
        self.nodes[idx].open_refs = self.nodes[idx].open_refs.saturating_sub(1);
        if self.nodes[idx].unlinked && self.nodes[idx].open_refs == 0 {
            self.nodes.swap_remove(idx);
        }
    }

    pub(super) fn list_dir(
        &self,
        mount_id: u32,
        dir_ino: u64,
    ) -> Result<Vec<(u64, u8, Vec<u8>)>, Errno> {
        let idx = self.find_ino_idx(mount_id, dir_ino).ok_or(Errno::ENOENT)?;
        let dir_node = &self.nodes[idx];
        if dir_node.kind != MemNodeKind::Dir {
            return Err(Errno::ENOTDIR);
        }
        let parent_ino = if dir_node.parent_ino == 0 {
            dir_node.ino
        } else {
            dir_node.parent_ino
        };
        let mut out = Vec::new();
        out.push((dir_node.ino, DT_DIR, b".".to_vec()));
        out.push((parent_ino, DT_DIR, b"..".to_vec()));
        for node in &self.nodes {
            if !node.unlinked && node.mount_id == mount_id && node.parent_ino == dir_ino {
                out.push((node.ino, node.kind.dt_type(), node.name.clone()));
            }
        }
        Ok(out)
    }

    fn validate_new_child(&self, mount_id: u32, parent_ino: u64, name: &[u8]) -> Result<(), Errno> {
        if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
            return Err(Errno::EINVAL);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(Errno::ENAMETOOLONG);
        }
        let parent_idx = self
            .find_ino_idx(mount_id, parent_ino)
            .ok_or(Errno::ENOENT)?;
        if self.nodes[parent_idx].unlinked {
            return Err(Errno::ENOENT);
        }
        if self.nodes[parent_idx].kind != MemNodeKind::Dir {
            return Err(Errno::ENOTDIR);
        }
        Ok(())
    }

    pub(super) fn open_or_create_file(
        &mut self,
        mount_id: u32,
        parent_ino: u64,
        name: &[u8],
        mode_bits: u32,
        uid: u32,
        gid: u32,
        excl: bool,
        trunc: bool,
        now: u32,
    ) -> Result<MemStat, Errno> {
        self.validate_new_child(mount_id, parent_ino, name)?;
        if let Some(idx) = self.find_child_idx(mount_id, parent_ino, name) {
            if excl {
                return Err(Errno::EEXIST);
            }
            if self.nodes[idx].kind == MemNodeKind::Dir {
                return Err(Errno::EISDIR);
            }
            if trunc && self.nodes[idx].kind == MemNodeKind::File {
                self.nodes[idx].data.clear();
                self.nodes[idx].mtime = now;
                self.nodes[idx].ctime = now;
            }
            let nlink = self.count_nlink(mount_id, &self.nodes[idx]);
            return Ok(self.nodes[idx].as_stat(nlink));
        }
        let ino = self.alloc_ino();
        let node = MemNode {
            mount_id,
            ino,
            parent_ino,
            name: name.to_vec(),
            kind: MemNodeKind::File,
            mode: S_IFREG | (mode_bits & 0o7777),
            uid,
            gid,
            rdev: 0,
            data: Vec::new(),
            atime: now,
            mtime: now,
            ctime: now,
            unlinked: false,
            open_refs: 0,
        };
        let stat = node.as_stat(1);
        self.push_node(node)?;
        Ok(stat)
    }

    pub(super) fn create_tmpfile(
        &mut self,
        mount_id: u32,
        dir_ino: u64,
        mode_bits: u32,
        uid: u32,
        gid: u32,
        now: u32,
    ) -> Result<MemStat, Errno> {
        let dir_idx = self.find_ino_idx(mount_id, dir_ino).ok_or(Errno::ENOENT)?;
        if self.nodes[dir_idx].unlinked {
            return Err(Errno::ENOENT);
        }
        if self.nodes[dir_idx].kind != MemNodeKind::Dir {
            return Err(Errno::ENOTDIR);
        }
        let ino = self.alloc_ino();
        let node = MemNode {
            mount_id,
            ino,
            parent_ino: dir_ino,
            name: Vec::new(),
            kind: MemNodeKind::File,
            mode: S_IFREG | (mode_bits & 0o7777),
            uid,
            gid,
            rdev: 0,
            data: Vec::new(),
            atime: now,
            mtime: now,
            ctime: now,
            unlinked: true,
            open_refs: 0,
        };
        let stat = node.as_stat(0);
        self.push_node(node)?;
        Ok(stat)
    }

    pub(super) fn link_node(
        &mut self,
        mount_id: u32,
        target_ino: u64,
        new_parent_ino: u64,
        new_name: &[u8],
        now: u32,
    ) -> Result<(), Errno> {
        self.validate_new_child(mount_id, new_parent_ino, new_name)?;
        if self
            .find_child_idx(mount_id, new_parent_ino, new_name)
            .is_some()
        {
            return Err(Errno::EEXIST);
        }
        let idx = self
            .find_ino_idx(mount_id, target_ino)
            .ok_or(Errno::ENOENT)?;
        if self.nodes[idx].kind == MemNodeKind::Dir {
            return Err(Errno::EPERM);
        }
        if !self.nodes[idx].unlinked {
            return Err(Errno::EPERM);
        }
        self.nodes[idx].unlinked = false;
        self.nodes[idx].parent_ino = new_parent_ino;
        self.nodes[idx].name = new_name.to_vec();
        self.nodes[idx].ctime = now;
        Ok(())
    }

    pub(super) fn mkdir(
        &mut self,
        mount_id: u32,
        parent_ino: u64,
        name: &[u8],
        mode_bits: u32,
        uid: u32,
        gid: u32,
        now: u32,
    ) -> Result<MemStat, Errno> {
        self.validate_new_child(mount_id, parent_ino, name)?;
        if self.find_child_idx(mount_id, parent_ino, name).is_some() {
            return Err(Errno::EEXIST);
        }
        let ino = self.alloc_ino();
        let node = MemNode {
            mount_id,
            ino,
            parent_ino,
            name: name.to_vec(),
            kind: MemNodeKind::Dir,
            mode: S_IFDIR | (mode_bits & 0o7777),
            uid,
            gid,
            rdev: 0,
            data: Vec::new(),
            atime: now,
            mtime: now,
            ctime: now,
            unlinked: false,
            open_refs: 0,
        };
        let stat = node.as_stat(2);
        self.push_node(node)?;
        Ok(stat)
    }

    pub(super) fn symlink(
        &mut self,
        mount_id: u32,
        parent_ino: u64,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
        now: u32,
    ) -> Result<MemStat, Errno> {
        self.validate_new_child(mount_id, parent_ino, name)?;
        if target.is_empty() {
            return Err(Errno::ENOENT);
        }
        if self.find_child_idx(mount_id, parent_ino, name).is_some() {
            return Err(Errno::EEXIST);
        }
        let ino = self.alloc_ino();
        let node = MemNode {
            mount_id,
            ino,
            parent_ino,
            name: name.to_vec(),
            kind: MemNodeKind::Symlink,
            mode: S_IFLNK | 0o777,
            uid,
            gid,
            rdev: 0,
            data: target.to_vec(),
            atime: now,
            mtime: now,
            ctime: now,
            unlinked: false,
            open_refs: 0,
        };
        let stat = node.as_stat(1);
        self.push_node(node)?;
        Ok(stat)
    }

    pub(super) fn mknod(
        &mut self,
        mount_id: u32,
        parent_ino: u64,
        name: &[u8],
        raw_mode: u32,
        rdev: u64,
        uid: u32,
        gid: u32,
        now: u32,
    ) -> Result<MemStat, Errno> {
        self.validate_new_child(mount_id, parent_ino, name)?;
        if self.find_child_idx(mount_id, parent_ino, name).is_some() {
            return Err(Errno::EEXIST);
        }
        let fmt = raw_mode & S_IFMT;
        let kind = match fmt {
            0 | S_IFREG => MemNodeKind::File,
            S_IFCHR => MemNodeKind::ChrDev(rdev),
            S_IFBLK => MemNodeKind::BlkDev(rdev),
            S_IFIFO => MemNodeKind::Fifo,
            S_IFSOCK => MemNodeKind::Socket,
            _ => return Err(Errno::EINVAL),
        };
        let eff_fmt = if fmt == 0 { S_IFREG } else { fmt };
        let ino = self.alloc_ino();
        let node = MemNode {
            mount_id,
            ino,
            parent_ino,
            name: name.to_vec(),
            kind,
            mode: eff_fmt | (raw_mode & 0o7777),
            uid,
            gid,
            rdev: if matches!(kind, MemNodeKind::ChrDev(_) | MemNodeKind::BlkDev(_)) {
                rdev
            } else {
                0
            },
            data: Vec::new(),
            atime: now,
            mtime: now,
            ctime: now,
            unlinked: false,
            open_refs: 0,
        };
        let stat = node.as_stat(1);
        self.push_node(node)?;
        Ok(stat)
    }

    pub(super) fn unlink(
        &mut self,
        mount_id: u32,
        parent_ino: u64,
        name: &[u8],
        remove_dir: bool,
    ) -> Result<(), Errno> {
        if name.is_empty() || name == b"." || name == b".." {
            return Err(Errno::EINVAL);
        }
        let idx = self
            .find_child_idx(mount_id, parent_ino, name)
            .ok_or(Errno::ENOENT)?;
        let target_ino = self.nodes[idx].ino;
        let is_dir = self.nodes[idx].kind == MemNodeKind::Dir;
        if remove_dir {
            if !is_dir {
                return Err(Errno::ENOTDIR);
            }
            let has_child = self
                .nodes
                .iter()
                .any(|n| !n.unlinked && n.mount_id == mount_id && n.parent_ino == target_ino);
            if has_child {
                return Err(Errno::ENOTEMPTY);
            }
        } else if is_dir {
            return Err(Errno::EISDIR);
        }
        if self.nodes[idx].open_refs == 0 {
            self.nodes.swap_remove(idx);
        } else {
            self.nodes[idx].unlinked = true;
            self.nodes[idx].parent_ino = 0;
            self.nodes[idx].name.clear();
        }
        Ok(())
    }

    fn is_ancestor(&self, mount_id: u32, ancestor_ino: u64, mut node_ino: u64) -> bool {
        for _ in 0..MAX_MEMFS_NODES {
            if node_ino == ancestor_ino {
                return true;
            }
            let Some(idx) = self.find_ino_idx(mount_id, node_ino) else {
                return false;
            };
            let parent = self.nodes[idx].parent_ino;
            if parent == 0 {
                return false;
            }
            node_ino = parent;
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn rename(
        &mut self,
        mount_id: u32,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        noreplace: bool,
        now: u32,
    ) -> Result<(), Errno> {
        self.validate_new_child(mount_id, new_parent, new_name)?;
        if old_name.is_empty() || old_name == b"." || old_name == b".." {
            return Err(Errno::EINVAL);
        }
        let src_idx = self
            .find_child_idx(mount_id, old_parent, old_name)
            .ok_or(Errno::ENOENT)?;
        let src_ino = self.nodes[src_idx].ino;
        let src_is_dir = self.nodes[src_idx].kind == MemNodeKind::Dir;
        if old_parent == new_parent && old_name == new_name {
            return Ok(());
        }
        if src_is_dir && self.is_ancestor(mount_id, src_ino, new_parent) {
            return Err(Errno::EINVAL);
        }
        if let Some(dst_idx) = self.find_child_idx(mount_id, new_parent, new_name) {
            if noreplace {
                return Err(Errno::EEXIST);
            }
            let dst_is_dir = self.nodes[dst_idx].kind == MemNodeKind::Dir;
            if src_is_dir && !dst_is_dir {
                return Err(Errno::ENOTDIR);
            }
            if !src_is_dir && dst_is_dir {
                return Err(Errno::EISDIR);
            }
            self.unlink(mount_id, new_parent, new_name, dst_is_dir)?;
        }
        let src_idx = self.find_ino_idx(mount_id, src_ino).ok_or(Errno::ENOENT)?;
        self.nodes[src_idx].parent_ino = new_parent;
        self.nodes[src_idx].name = new_name.to_vec();
        self.nodes[src_idx].ctime = now;
        Ok(())
    }

    pub(super) fn read_at(
        &mut self,
        mount_id: u32,
        ino: u64,
        offset: usize,
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        let idx = self.find_ino_idx(mount_id, ino).ok_or(Errno::EBADF)?;
        let node = &mut self.nodes[idx];
        if node.kind == MemNodeKind::Dir {
            return Err(Errno::EISDIR);
        }
        if node.kind == MemNodeKind::Fifo {
            if node.data.is_empty() {
                return Err(Errno::EAGAIN);
            }
            let n = node.data.len().min(out.len());
            out[..n].copy_from_slice(&node.data[..n]);
            node.data.drain(..n);
            return Ok(n);
        }
        if offset >= node.data.len() || out.is_empty() {
            return Ok(0);
        }
        let avail = &node.data[offset..];
        let n = avail.len().min(out.len());
        out[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }

    pub(super) fn write_at(
        &mut self,
        mount_id: u32,
        ino: u64,
        offset: usize,
        src: &[u8],
        append: bool,
        now: u32,
    ) -> Result<(usize, usize), Errno> {
        let idx = self.find_ino_idx(mount_id, ino).ok_or(Errno::EBADF)?;
        let node = &mut self.nodes[idx];
        if node.kind == MemNodeKind::Dir {
            return Err(Errno::EISDIR);
        }
        if node.kind == MemNodeKind::Fifo {
            if node.data.len() + src.len() > MAX_MEMFS_FILE_BYTES {
                return Err(Errno::ENOSPC);
            }
            node.data.extend_from_slice(src);
            node.mtime = now;
            node.ctime = now;
            return Ok((src.len(), node.data.len()));
        }
        if node.kind != MemNodeKind::File {
            return Err(Errno::EINVAL);
        }
        let write_pos = if append { node.data.len() } else { offset };
        let end_pos = write_pos.checked_add(src.len()).ok_or(Errno::ENOSPC)?;
        if end_pos > MAX_MEMFS_FILE_BYTES {
            return Err(Errno::ENOSPC);
        }
        if end_pos > node.data.len() {
            node.data.resize(end_pos, 0);
        }
        if !src.is_empty() {
            node.data[write_pos..end_pos].copy_from_slice(src);
        }
        node.mtime = now;
        node.ctime = now;
        Ok((src.len(), end_pos))
    }

    pub(super) fn truncate(
        &mut self,
        mount_id: u32,
        ino: u64,
        len: usize,
        now: u32,
    ) -> Result<(), Errno> {
        let idx = self.find_ino_idx(mount_id, ino).ok_or(Errno::ENOENT)?;
        let node = &mut self.nodes[idx];
        if node.kind == MemNodeKind::Dir {
            return Err(Errno::EISDIR);
        }
        if node.kind != MemNodeKind::File {
            return Err(Errno::EINVAL);
        }
        if len > MAX_MEMFS_FILE_BYTES {
            return Err(Errno::ENOSPC);
        }
        node.data.resize(len, 0);
        node.mtime = now;
        node.ctime = now;
        Ok(())
    }

    pub(super) fn chmod(
        &mut self,
        mount_id: u32,
        ino: u64,
        mode_bits: u32,
        now: u32,
    ) -> Result<(), Errno> {
        let idx = self.find_ino_idx(mount_id, ino).ok_or(Errno::ENOENT)?;
        let node = &mut self.nodes[idx];
        if node.kind == MemNodeKind::Symlink {
            return Err(Errno::EOPNOTSUPP);
        }
        node.mode = (node.mode & S_IFMT) | (mode_bits & 0o7777);
        node.ctime = now;
        Ok(())
    }

    pub(super) fn chown(
        &mut self,
        mount_id: u32,
        ino: u64,
        uid: Option<u32>,
        gid: Option<u32>,
        now: u32,
    ) -> Result<(), Errno> {
        let idx = self.find_ino_idx(mount_id, ino).ok_or(Errno::ENOENT)?;
        let node = &mut self.nodes[idx];
        if let Some(u) = uid {
            node.uid = u;
        }
        if let Some(g) = gid {
            node.gid = g;
        }
        node.ctime = now;
        Ok(())
    }

    pub(super) fn utimens(
        &mut self,
        mount_id: u32,
        ino: u64,
        atime: Option<u32>,
        mtime: Option<u32>,
        now: u32,
    ) -> Result<(), Errno> {
        let idx = self.find_ino_idx(mount_id, ino).ok_or(Errno::ENOENT)?;
        let node = &mut self.nodes[idx];
        if let Some(a) = atime {
            node.atime = a;
        }
        if let Some(m) = mtime {
            node.mtime = m;
        }
        node.ctime = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memfs_tmpfs_and_devtmpfs_support_crud_symlinks_and_unlinked_open_fds() {
        let mut fs = MemFs::new();
        fs.ensure_mount(6, FilesystemType::Tmpfs, None, 100);
        let root = fs.root_stat(6).unwrap();
        let sub = fs.mkdir(6, root.ino, b"systemd", 0o755, 0, 0, 101).unwrap();
        let file = fs
            .open_or_create_file(6, sub.ino, b"state", 0o644, 0, 0, true, false, 102)
            .unwrap();
        fs.retain_fd(6, file.ino);
        assert_eq!(
            fs.write_at(6, file.ino, 0, b"active\n", false, 103)
                .unwrap(),
            (7, 7)
        );
        fs.unlink(6, sub.ino, b"state", false).unwrap();
        assert!(fs.lookup_child_stat(6, sub.ino, b"state").is_none());

        let mut buf = [0u8; 16];
        assert_eq!(fs.read_at(6, file.ino, 0, &mut buf).unwrap(), 7);
        assert_eq!(&buf[..7], b"active\n");
        fs.release_fd(6, file.ino);
        assert!(fs.stat_ino(6, file.ino).is_none());

        fs.ensure_mount(2, FilesystemType::Devtmpfs, None, 100);
        let dev_root = fs.root_stat(2).unwrap();
        let stdin = fs.lookup_child_stat(2, dev_root.ino, b"stdin").unwrap();
        assert_eq!(fs.read_symlink(2, stdin.ino), Some(&b"/proc/self/fd/0"[..]));
    }
}
