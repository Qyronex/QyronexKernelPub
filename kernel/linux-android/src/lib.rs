// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Android 15 / GrapheneOS kernel subsystem for Qyronex OS.
//!
//! Provides:
//! - 64-bit AArch64 **Binder IPC** (`/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`) with
//!   Project Treble domain isolation and Qyronex `Capability`-enforced transaction auditing.
//! - **Android Shared Memory** (`/dev/ashmem`) and **`dma_heap`** (`/dev/dma_heap/system`) with
//!   pin/unpin lifecycle and GrapheneOS zero-on-free sanitization.
//! - **SELinuxFS** (`/sys/fs/selinux/*`), immutable `ro.*` **Android System Properties**,
//!   **Power Wakelocks** (`/sys/power/wake_lock`), **PSI** (`/proc/pressure/*`), and
//!   **GrapheneOS Kernel Hardening** telemetry (`W^X`, TTBR1 isolation, `FEAT_PAN`, `MTE`, `PAC/BTI`).

extern crate alloc;

pub mod ebpf;
pub mod storage;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_linux_abi::Errno;

// ============================================================================
// 1. Linux AArch64 64-bit Binder IPC ABI (BINDER_CURRENT_PROTOCOL_VERSION = 8)
// ============================================================================

pub const BINDER_CURRENT_PROTOCOL_VERSION: i32 = 8;

pub const BINDER_WRITE_READ: u64 = 0xC030_6201;
pub const BINDER_SET_IDLE_TIMEOUT: u64 = 0x4008_6203;
pub const BINDER_SET_MAX_THREADS: u64 = 0x4004_6205;
pub const BINDER_SET_IDLE_PRIORITY: u64 = 0x4004_6206;
pub const BINDER_SET_CONTEXT_MGR: u64 = 0x4004_6207;
pub const BINDER_THREAD_EXIT: u64 = 0x4004_6208;
pub const BINDER_VERSION: u64 = 0xC004_6209;
pub const BINDER_SET_CONTEXT_MGR_EXT: u64 = 0x4018_620D;
/// Linux `BINDER_CTL_ADD` ioctl on `/dev/binderfs/binder-control` (`struct binderfs_device` = 264B).
pub const BINDER_CTL_ADD: u64 = 0xC108_6201;

// Binder flat object types (`flat_binder_object.hdr.type`)
pub const BINDER_TYPE_BINDER: u32 = 0x7362_2A85;
pub const BINDER_TYPE_WEAK_BINDER: u32 = 0x7762_2A85;
pub const BINDER_TYPE_HANDLE: u32 = 0x7368_2A85;
pub const BINDER_TYPE_WEAK_HANDLE: u32 = 0x7768_2A85;
pub const BINDER_TYPE_FD: u32 = 0x6664_2A85;
pub const FLAT_BINDER_OBJECT_BYTES: usize = 24;

// Android 15 ART / Bionic syscalls (`userfaultfd`, `membarrier`, `prctl`)
pub const UFFDIO_API: u64 = 0xC018_AA3F;
pub const UFFD_API_VERSION: u64 = 0xAA;
pub const MEMBARRIER_CMD_QUERY: i32 = 0;
pub const MEMBARRIER_CMD_GLOBAL: i32 = 1 << 0;
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED: i32 = 1 << 3;
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: i32 = 1 << 4;
pub const MEMBARRIER_SUPPORTED_MASK: i64 = (MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED) as i64;
pub const PR_SET_TIMERSLACK: u32 = 29;
pub const PR_GET_TIMERSLACK: u32 = 30;
pub const PR_SET_TAGGED_ADDR_CTRL: u32 = 55;
pub const PR_GET_TAGGED_ADDR_CTRL: u32 = 56;
pub const PR_SET_VMA: u32 = 0x5356_4D41;
pub const PR_SET_VMA_ANON_NAME: u64 = 0;
pub const PR_SET_PTRACER: u32 = 0x5961_6D61;

// Binder Command Protocol (userspace -> kernel)
pub const BC_TRANSACTION: u32 = 0x4040_6300;
pub const BC_REPLY: u32 = 0x4040_6301;
pub const BC_FREE_BUFFER: u32 = 0x4008_6303;
pub const BC_INCREFS: u32 = 0x4004_6304;
pub const BC_ACQUIRE: u32 = 0x4004_6305;
pub const BC_RELEASE: u32 = 0x4004_6306;
pub const BC_DECREFS: u32 = 0x4004_6307;
pub const BC_REGISTER_LOOPER: u32 = 0x0000_630B;
pub const BC_ENTER_LOOPER: u32 = 0x0000_630C;
pub const BC_EXIT_LOOPER: u32 = 0x0000_630D;
pub const BC_REQUEST_DEATH_NOTIFICATION: u32 = 0x400C_630E;
pub const BC_DEAD_BINDER_DONE: u32 = 0x4008_6310;

// Binder Return Protocol (kernel -> userspace)
pub const BR_ERROR: u32 = 0x8004_7200;
pub const BR_OK: u32 = 0x0000_7201;
pub const BR_TRANSACTION: u32 = 0x8040_7202;
pub const BR_REPLY: u32 = 0x8040_7203;
pub const BR_DEAD_REPLY: u32 = 0x0000_7205;
pub const BR_TRANSACTION_COMPLETE: u32 = 0x0000_7206;
pub const BR_INCREFS: u32 = 0x8010_7207;
pub const BR_ACQUIRE: u32 = 0x8010_7208;
pub const BR_RELEASE: u32 = 0x8010_7209;
pub const BR_DECREFS: u32 = 0x8010_720A;
pub const BR_NOOP: u32 = 0x0000_720C;
pub const BR_SPAWN_LOOPER: u32 = 0x0000_720D;
pub const BR_FAILED_REPLY: u32 = 0x0000_7211;

pub const TF_ONE_WAY: u32 = 0x01;
pub const TF_ROOT_OBJECT: u32 = 0x04;
pub const TF_STATUS_CODE: u32 = 0x08;
pub const TF_ACCEPT_FDS: u32 = 0x10;

pub const BINDER_WRITE_READ_BYTES: usize = 48;
pub const BINDER_TRANSACTION_DATA_BYTES: usize = 64;
pub const MAX_BINDER_PAYLOAD_BYTES: usize = 8192;
pub const MAX_BINDER_PROCS: usize = 32;
pub const MAX_BINDER_NODES: usize = 64;

/// Project Treble / GrapheneOS isolated Binder domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinderDomain {
    /// `/dev/binder` — Android framework IPC (`servicemanager`, `SurfaceFlinger`, apps).
    Framework,
    /// `/dev/hwbinder` — Treble HAL IPC (`hwservicemanager`, vendor HIDL/AIDL HALs).
    HardwareHal,
    /// `/dev/vndbinder` — Vendor-internal IPC (`vndservicemanager`).
    Vendor,
}

impl BinderDomain {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Framework => "binder",
            Self::HardwareHal => "hwbinder",
            Self::Vendor => "vndbinder",
        }
    }
}

/// Wire layout of 64-bit `struct binder_write_read` (48 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinderWriteRead {
    pub write_size: u64,
    pub write_consumed: u64,
    pub write_buffer: u64,
    pub read_size: u64,
    pub read_consumed: u64,
    pub read_buffer: u64,
}

impl BinderWriteRead {
    pub fn from_le_bytes(raw: &[u8; BINDER_WRITE_READ_BYTES]) -> Self {
        let r = |off: usize| -> u64 {
            u64::from_le_bytes([
                raw[off],
                raw[off + 1],
                raw[off + 2],
                raw[off + 3],
                raw[off + 4],
                raw[off + 5],
                raw[off + 6],
                raw[off + 7],
            ])
        };
        Self {
            write_size: r(0),
            write_consumed: r(8),
            write_buffer: r(16),
            read_size: r(24),
            read_consumed: r(32),
            read_buffer: r(40),
        }
    }

    pub fn to_le_bytes(self) -> [u8; BINDER_WRITE_READ_BYTES] {
        let mut out = [0u8; BINDER_WRITE_READ_BYTES];
        out[0..8].copy_from_slice(&self.write_size.to_le_bytes());
        out[8..16].copy_from_slice(&self.write_consumed.to_le_bytes());
        out[16..24].copy_from_slice(&self.write_buffer.to_le_bytes());
        out[24..32].copy_from_slice(&self.read_size.to_le_bytes());
        out[32..40].copy_from_slice(&self.read_consumed.to_le_bytes());
        out[40..48].copy_from_slice(&self.read_buffer.to_le_bytes());
        out
    }
}

/// Wire layout of 64-bit `struct binder_transaction_data` (64 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinderTransactionData {
    pub target_handle_or_ptr: u64,
    pub cookie: u64,
    pub code: u32,
    pub flags: u32,
    pub sender_pid: i32,
    pub sender_euid: u32,
    pub data_size: u64,
    pub offsets_size: u64,
    pub data_ptr: u64,
    pub offsets_ptr: u64,
}

impl BinderTransactionData {
    pub fn from_le_bytes(raw: &[u8; BINDER_TRANSACTION_DATA_BYTES]) -> Self {
        let r64 = |off: usize| -> u64 {
            u64::from_le_bytes([
                raw[off],
                raw[off + 1],
                raw[off + 2],
                raw[off + 3],
                raw[off + 4],
                raw[off + 5],
                raw[off + 6],
                raw[off + 7],
            ])
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
        };
        Self {
            target_handle_or_ptr: r64(0),
            cookie: r64(8),
            code: r32(16),
            flags: r32(20),
            sender_pid: r32(24) as i32,
            sender_euid: r32(28),
            data_size: r64(32),
            offsets_size: r64(40),
            data_ptr: r64(48),
            offsets_ptr: r64(56),
        }
    }

    pub fn to_le_bytes(self) -> [u8; BINDER_TRANSACTION_DATA_BYTES] {
        let mut out = [0u8; BINDER_TRANSACTION_DATA_BYTES];
        out[0..8].copy_from_slice(&self.target_handle_or_ptr.to_le_bytes());
        out[8..16].copy_from_slice(&self.cookie.to_le_bytes());
        out[16..20].copy_from_slice(&self.code.to_le_bytes());
        out[20..24].copy_from_slice(&self.flags.to_le_bytes());
        out[24..28].copy_from_slice(&(self.sender_pid as u32).to_le_bytes());
        out[28..32].copy_from_slice(&self.sender_euid.to_le_bytes());
        out[32..40].copy_from_slice(&self.data_size.to_le_bytes());
        out[40..48].copy_from_slice(&self.offsets_size.to_le_bytes());
        out[48..56].copy_from_slice(&self.data_ptr.to_le_bytes());
        out[56..64].copy_from_slice(&self.offsets_ptr.to_le_bytes());
        out
    }
}

/// Wire layout of 64-bit `struct flat_binder_object` (24 bytes) for object & FD passing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlatBinderObject {
    pub obj_type: u32,
    pub flags: u32,
    pub binder_or_handle: u64,
    pub cookie: u64,
}

impl FlatBinderObject {
    pub fn from_le_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < FLAT_BINDER_OBJECT_BYTES {
            return None;
        }
        let u32_at = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_le_bytes([
                raw[o],
                raw[o + 1],
                raw[o + 2],
                raw[o + 3],
                raw[o + 4],
                raw[o + 5],
                raw[o + 6],
                raw[o + 7],
            ])
        };
        Some(Self {
            obj_type: u32_at(0),
            flags: u32_at(4),
            binder_or_handle: u64_at(8),
            cookie: u64_at(16),
        })
    }

    pub fn to_le_bytes(self) -> [u8; FLAT_BINDER_OBJECT_BYTES] {
        let mut out = [0u8; FLAT_BINDER_OBJECT_BYTES];
        out[0..4].copy_from_slice(&self.obj_type.to_le_bytes());
        out[4..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..16].copy_from_slice(&self.binder_or_handle.to_le_bytes());
        out[16..24].copy_from_slice(&self.cookie.to_le_bytes());
        out
    }
}

/// Retained kernel subsystem FD in flight inside a `BINDER_TYPE_FD` transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinderTransferredFd {
    pub payload_offset: usize,
    pub subsys_kind: u8,
    pub subsys_slot: u16,
    pub subsys_generation: u64,
    pub status_flags: u64,
}

/// Queued Binder message delivered to a recipient process (`BR_TRANSACTION` or `BR_REPLY`).
#[derive(Clone, Debug)]
pub struct QueuedBinderWork {
    pub return_cmd: u32,
    pub target_ptr: u64,
    pub cookie: u64,
    pub code: u32,
    pub flags: u32,
    pub sender_pid: i32,
    pub sender_euid: u32,
    pub reply_to_client_id: Option<u32>,
    pub payload: Vec<u8>,
    pub offsets: Vec<u64>,
    pub transferred_fds: Vec<BinderTransferredFd>,
}

/// Registered Binder client endpoint belonging to one Linux/Android process.
pub struct BinderEndpoint {
    pub id: u32,
    pub owner_process: ObjectId,
    pub linux_pid: i32,
    pub linux_euid: u32,
    pub domain: BinderDomain,
    pub max_threads: u32,
    pub looper_entered: bool,
    pub capability: Capability,
    pub pending_work: VecDeque<QueuedBinderWork>,
    pub pending_reply_target: Option<u32>,
    pub mmap_base: u64,
    pub mmap_len: usize,
    pub mmap_cursor: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct BinderServiceNode {
    pub handle: u32,
    pub owner_endpoint_id: u32,
    pub ptr: u64,
    pub cookie: u64,
    pub required_rights: CapRights,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BinderAuditStats {
    pub total_transactions: u64,
    pub total_replies: u64,
    pub total_fd_transfers: u64,
    pub capability_denials: u64,
    pub active_endpoints: usize,
    pub context_managers_bound: u8,
}

/// Capability-enforced Android Binder IPC broker for one isolated domain (`binder` / `hwbinder` /
/// `vndbinder`).
pub struct BinderDomainBroker {
    domain: BinderDomain,
    next_endpoint_id: u32,
    next_handle: u32,
    context_mgr_endpoint_id: Option<u32>,
    endpoints: Vec<BinderEndpoint>,
    nodes: Vec<BinderServiceNode>,
    pub total_transactions: u64,
    pub total_replies: u64,
    pub total_fd_transfers: u64,
    pub capability_denials: u64,
}

impl BinderDomainBroker {
    pub const fn new(domain: BinderDomain) -> Self {
        Self {
            domain,
            next_endpoint_id: 1,
            next_handle: 1,
            context_mgr_endpoint_id: None,
            endpoints: Vec::new(),
            nodes: Vec::new(),
            total_transactions: 0,
            total_replies: 0,
            total_fd_transfers: 0,
            capability_denials: 0,
        }
    }

    pub fn domain(&self) -> BinderDomain {
        self.domain
    }

    pub fn open_endpoint(
        &mut self,
        owner_process: ObjectId,
        linux_pid: i32,
        linux_euid: u32,
        capability: Capability,
    ) -> Result<u32, Errno> {
        if !capability.rights.contains(CapRights::READ) {
            self.capability_denials += 1;
            return Err(Errno::EPERM);
        }
        if self.endpoints.len() >= MAX_BINDER_PROCS {
            return Err(Errno::ENOMEM);
        }
        let id = self.next_endpoint_id;
        self.next_endpoint_id = self.next_endpoint_id.wrapping_add(1).max(1);
        self.endpoints.push(BinderEndpoint {
            id,
            owner_process,
            linux_pid,
            linux_euid,
            domain: self.domain,
            max_threads: 15,
            looper_entered: false,
            capability,
            pending_work: VecDeque::new(),
            pending_reply_target: None,
            mmap_base: 0,
            mmap_len: 0,
            mmap_cursor: 0,
        });
        Ok(id)
    }

    pub fn close_endpoint(&mut self, endpoint_id: u32) {
        if self.context_mgr_endpoint_id == Some(endpoint_id) {
            self.context_mgr_endpoint_id = None;
        }
        self.nodes.retain(|n| n.owner_endpoint_id != endpoint_id);
        self.endpoints.retain(|e| e.id != endpoint_id);
    }

    pub fn endpoint(&self, endpoint_id: u32) -> Option<&BinderEndpoint> {
        self.endpoints.iter().find(|e| e.id == endpoint_id)
    }

    pub fn endpoint_mut(&mut self, endpoint_id: u32) -> Option<&mut BinderEndpoint> {
        self.endpoints.iter_mut().find(|e| e.id == endpoint_id)
    }

    pub fn set_context_manager(&mut self, endpoint_id: u32) -> Result<(), Errno> {
        let ep = self.endpoint(endpoint_id).ok_or(Errno::EBADF)?;
        if !ep.capability.rights.contains(CapRights::CONTROL) {
            self.capability_denials += 1;
            return Err(Errno::EPERM);
        }
        if self.context_mgr_endpoint_id.is_some()
            && self.context_mgr_endpoint_id != Some(endpoint_id)
        {
            return Err(Errno::EBUSY);
        }
        self.context_mgr_endpoint_id = Some(endpoint_id);
        Ok(())
    }

    pub fn set_max_threads(&mut self, endpoint_id: u32, max_threads: u32) -> Result<(), Errno> {
        let ep = self.endpoint_mut(endpoint_id).ok_or(Errno::EBADF)?;
        ep.max_threads = max_threads.clamp(1, 64);
        Ok(())
    }

    pub fn enter_looper(&mut self, endpoint_id: u32) -> Result<(), Errno> {
        let ep = self.endpoint_mut(endpoint_id).ok_or(Errno::EBADF)?;
        ep.looper_entered = true;
        Ok(())
    }

    pub fn register_mmap(
        &mut self,
        endpoint_id: u32,
        user_base: u64,
        len: usize,
    ) -> Result<(), Errno> {
        let ep = self.endpoint_mut(endpoint_id).ok_or(Errno::EBADF)?;
        ep.mmap_base = user_base;
        ep.mmap_len = len;
        ep.mmap_cursor = 0;
        Ok(())
    }

    /// Allocates a bounded user VA slice inside the target endpoint's Binder `mmap` ring.
    pub fn alloc_mmap_slice(&mut self, endpoint_id: u32, len: usize) -> Option<u64> {
        let ep = self.endpoint_mut(endpoint_id)?;
        if ep.mmap_base == 0 || ep.mmap_len == 0 || len > ep.mmap_len {
            return None;
        }
        let aligned = (len + 7) & !7;
        if ep.mmap_cursor.saturating_add(aligned) > ep.mmap_len {
            ep.mmap_cursor = 0;
        }
        let addr = ep.mmap_base.saturating_add(ep.mmap_cursor as u64);
        ep.mmap_cursor = ep.mmap_cursor.saturating_add(aligned);
        Some(addr)
    }

    /// Registers a named/pointer service node owned by `owner_endpoint_id` and returns its handle.
    pub fn register_node(
        &mut self,
        owner_endpoint_id: u32,
        ptr: u64,
        cookie: u64,
        required_rights: CapRights,
    ) -> Result<u32, Errno> {
        if self.nodes.len() >= MAX_BINDER_NODES {
            return Err(Errno::ENOSPC);
        }
        if self.endpoint(owner_endpoint_id).is_none() {
            return Err(Errno::EBADF);
        }
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        self.nodes.push(BinderServiceNode {
            handle,
            owner_endpoint_id,
            ptr,
            cookie,
            required_rights,
        });
        Ok(handle)
    }

    /// Dispatches one `BC_TRANSACTION` from `sender_id` to either `handle == 0` (context manager /
    /// `servicemanager`) or a registered service node handle, enforcing Qyronex capability rights.
    pub fn dispatch_transaction(
        &mut self,
        sender_id: u32,
        tx: BinderTransactionData,
        payload: Vec<u8>,
    ) -> Result<(), Errno> {
        self.dispatch_transaction_with_objects(sender_id, tx, payload, Vec::new(), Vec::new())
    }

    /// Dispatches one `BC_TRANSACTION` including translated `flat_binder_object` offsets and
    /// cross-process transferred kernel subsystem FDs (`BINDER_TYPE_FD`).
    pub fn dispatch_transaction_with_objects(
        &mut self,
        sender_id: u32,
        tx: BinderTransactionData,
        mut payload: Vec<u8>,
        offsets: Vec<u64>,
        transferred_fds: Vec<BinderTransferredFd>,
    ) -> Result<(), Errno> {
        if payload.len() > MAX_BINDER_PAYLOAD_BYTES {
            return Err(Errno::EINVAL);
        }
        let (sender_pid, sender_euid, sender_rights) = {
            let s = self.endpoint(sender_id).ok_or(Errno::EBADF)?;
            (s.linux_pid, s.linux_euid, s.capability.rights)
        };
        if !sender_rights.contains(CapRights::WRITE) {
            self.capability_denials += 1;
            return Err(Errno::EPERM);
        }

        // Translate `BINDER_TYPE_BINDER` objects into `BINDER_TYPE_HANDLE` for the recipient.
        for &off_u64 in &offsets {
            let off = off_u64 as usize;
            if let Some(mut obj) = payload.get(off..).and_then(FlatBinderObject::from_le_bytes)
                && (obj.obj_type == BINDER_TYPE_BINDER || obj.obj_type == BINDER_TYPE_WEAK_BINDER)
            {
                let h = self.register_node(
                    sender_id,
                    obj.binder_or_handle,
                    obj.cookie,
                    CapRights::WRITE,
                )?;
                obj.obj_type = if obj.obj_type == BINDER_TYPE_BINDER {
                    BINDER_TYPE_HANDLE
                } else {
                    BINDER_TYPE_WEAK_HANDLE
                };
                obj.binder_or_handle = u64::from(h);
                payload[off..off + FLAT_BINDER_OBJECT_BYTES].copy_from_slice(&obj.to_le_bytes());
            }
        }

        let handle = tx.target_handle_or_ptr as u32;
        let (target_ep_id, target_ptr, cookie) = if handle == 0 {
            let mgr = self.context_mgr_endpoint_id.ok_or(Errno::ENOENT)?;
            (mgr, 0u64, 0u64)
        } else {
            let node = self
                .nodes
                .iter()
                .copied()
                .find(|n| n.handle == handle)
                .ok_or(Errno::ENOENT)?;
            if !sender_rights.contains(node.required_rights) {
                self.capability_denials += 1;
                return Err(Errno::EPERM);
            }
            (node.owner_endpoint_id, node.ptr, node.cookie)
        };

        let fd_count = transferred_fds.len() as u64;
        let one_way = (tx.flags & TF_ONE_WAY) != 0;
        let work = QueuedBinderWork {
            return_cmd: BR_TRANSACTION,
            target_ptr,
            cookie,
            code: tx.code,
            flags: tx.flags,
            sender_pid,
            sender_euid,
            reply_to_client_id: if one_way { None } else { Some(sender_id) },
            payload,
            offsets,
            transferred_fds,
        };

        let target = self.endpoint_mut(target_ep_id).ok_or(Errno::EPIPE)?;
        target.pending_work.push_back(work);

        // Queue immediate BR_TRANSACTION_COMPLETE for the sender per Linux Binder protocol.
        if let Some(sender) = self.endpoint_mut(sender_id) {
            sender.pending_work.push_back(QueuedBinderWork {
                return_cmd: BR_TRANSACTION_COMPLETE,
                target_ptr: 0,
                cookie: 0,
                code: 0,
                flags: 0,
                sender_pid: 0,
                sender_euid: 0,
                reply_to_client_id: None,
                payload: Vec::new(),
                offsets: Vec::new(),
                transferred_fds: Vec::new(),
            });
        }
        self.total_transactions = self.total_transactions.saturating_add(1);
        self.total_fd_transfers = self.total_fd_transfers.saturating_add(fd_count);
        Ok(())
    }

    /// Dispatches one `BC_REPLY` from the server currently handling a synchronous transaction back
    /// to its waiting client endpoint.
    pub fn dispatch_reply(
        &mut self,
        server_id: u32,
        tx: BinderTransactionData,
        payload: Vec<u8>,
    ) -> Result<(), Errno> {
        self.dispatch_reply_with_objects(server_id, tx, payload, Vec::new(), Vec::new())
    }

    /// Dispatches one `BC_REPLY` including translated `flat_binder_object` offsets and FDs.
    pub fn dispatch_reply_with_objects(
        &mut self,
        server_id: u32,
        tx: BinderTransactionData,
        payload: Vec<u8>,
        offsets: Vec<u64>,
        transferred_fds: Vec<BinderTransferredFd>,
    ) -> Result<(), Errno> {
        if payload.len() > MAX_BINDER_PAYLOAD_BYTES {
            return Err(Errno::EINVAL);
        }
        let (server_pid, server_euid, client_id) = {
            let srv = self.endpoint_mut(server_id).ok_or(Errno::EBADF)?;
            let cid = srv.pending_reply_target.take().ok_or(Errno::EINVAL)?;
            (srv.linux_pid, srv.linux_euid, cid)
        };

        let fd_count = transferred_fds.len() as u64;
        let reply_work = QueuedBinderWork {
            return_cmd: BR_REPLY,
            target_ptr: 0,
            cookie: 0,
            code: tx.code,
            flags: tx.flags,
            sender_pid: server_pid,
            sender_euid: server_euid,
            reply_to_client_id: None,
            payload,
            offsets,
            transferred_fds,
        };

        if let Some(client) = self.endpoint_mut(client_id) {
            client.pending_work.push_back(reply_work);
        }
        if let Some(server) = self.endpoint_mut(server_id) {
            server.pending_work.push_back(QueuedBinderWork {
                return_cmd: BR_TRANSACTION_COMPLETE,
                target_ptr: 0,
                cookie: 0,
                code: 0,
                flags: 0,
                sender_pid: 0,
                sender_euid: 0,
                reply_to_client_id: None,
                payload: Vec::new(),
                offsets: Vec::new(),
                transferred_fds: Vec::new(),
            });
        }
        self.total_replies = self.total_replies.saturating_add(1);
        self.total_fd_transfers = self.total_fd_transfers.saturating_add(fd_count);
        Ok(())
    }

    /// Pops the next pending work item for `endpoint_id`, recording `pending_reply_target` when
    /// delivering a synchronous `BR_TRANSACTION`.
    pub fn pop_work(&mut self, endpoint_id: u32) -> Option<QueuedBinderWork> {
        let ep = self.endpoint_mut(endpoint_id)?;
        let work = ep.pending_work.pop_front()?;
        if work.return_cmd == BR_TRANSACTION {
            ep.pending_reply_target = work.reply_to_client_id;
        }
        Some(work)
    }

    pub fn has_pending_work(&self, endpoint_id: u32) -> bool {
        self.endpoint(endpoint_id)
            .is_some_and(|e| !e.pending_work.is_empty())
    }

    pub fn active_endpoints(&self) -> usize {
        self.endpoints.len()
    }

    pub fn has_context_manager(&self) -> bool {
        self.context_mgr_endpoint_id.is_some()
    }
}

// ============================================================================
// 2. Android Shared Memory (/dev/ashmem) & dma_heap (/dev/dma_heap/system)
// ============================================================================

pub const ASHMEM_SET_NAME: u64 = 0x4100_7701;
pub const ASHMEM_GET_NAME: u64 = 0x8100_7702;
pub const ASHMEM_SET_SIZE: u64 = 0x4008_7703;
pub const ASHMEM_GET_SIZE: u64 = 0x0000_7704;
pub const ASHMEM_SET_PROT_MASK: u64 = 0x4008_7705;
pub const ASHMEM_GET_PROT_MASK: u64 = 0x0000_7706;
pub const ASHMEM_PIN: u64 = 0x4008_7707;
pub const ASHMEM_UNPIN: u64 = 0x4008_7708;
pub const ASHMEM_GET_PIN_STATUS: u64 = 0x0000_7709;
pub const ASHMEM_PURGE_ALL_CACHES: u64 = 0x0000_770A;
pub const DMA_HEAP_IOCTL_ALLOC: u64 = 0xC018_4800;

pub const ASHMEM_NOT_PURGED: i64 = 0;
pub const ASHMEM_WAS_PURGED: i64 = 1;
pub const ASHMEM_IS_UNPINNED: i64 = 0;
pub const ASHMEM_IS_PINNED: i64 = 1;

pub const MAX_ASHMEM_SIZE: usize = 8 * 1024 * 1024; // 8 MiB per region

/// One `/dev/ashmem` or `/dev/dma_heap/system` region with GrapheneOS zero-on-free sanitization.
pub struct AshmemRegion {
    pub id: u32,
    pub name: String,
    pub size: usize,
    pub prot_mask: u64,
    pub pinned: bool,
    pub purged: bool,
    pub data: Vec<u8>,
}

impl AshmemRegion {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            name: String::from("ashmem"),
            size: 0,
            prot_mask: 0x7, // PROT_READ | PROT_WRITE | PROT_EXEC (clamped by W^X)
            pinned: true,
            purged: false,
            data: Vec::new(),
        }
    }

    pub fn set_name(&mut self, raw: &[u8]) -> Result<(), Errno> {
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let trimmed = &raw[..end.min(255)];
        self.name = String::from_utf8_lossy(trimmed).into_owned();
        Ok(())
    }

    pub fn set_size(&mut self, size: usize) -> Result<(), Errno> {
        if !self.data.is_empty() {
            return Err(Errno::EINVAL);
        }
        if size == 0 || size > MAX_ASHMEM_SIZE {
            return Err(Errno::EINVAL);
        }
        self.size = size;
        Ok(())
    }

    pub fn ensure_allocated(&mut self) -> Result<(), Errno> {
        if self.size == 0 {
            return Err(Errno::EINVAL);
        }
        if self.data.is_empty() {
            self.data = vec![0u8; self.size];
        }
        Ok(())
    }

    pub fn pin(&mut self) -> i64 {
        self.pinned = true;
        if self.purged {
            self.purged = false;
            ASHMEM_WAS_PURGED
        } else {
            ASHMEM_NOT_PURGED
        }
    }

    pub fn unpin(&mut self) -> i64 {
        self.pinned = false;
        0
    }

    /// GrapheneOS hardened sanitization: explicitly zeroes backing bytes before dropping memory.
    pub fn sanitize_zero(&mut self) {
        self.data.fill(0);
    }
}

// ============================================================================
// 3. Android Properties, SELinuxFS, Wakelocks & GrapheneOS Hardening State
// ============================================================================

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidProperty {
    pub key: String,
    pub value: String,
    pub read_only: bool,
}

/// GrapheneOS + Qyronex kernel security posture exposed to Android `init` & Auditor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrapheneOsHardeningPolicy {
    pub selinux_enforcing: bool,
    pub selinux_policy_version: u32,
    pub wx_ttbr1_isolated: bool,
    pub capability_binder_enforced: bool,
    pub zero_on_free_allocator: bool,
    pub exec_spawning_enabled: bool,
    pub ptrace_scope: u8,
    pub unprivileged_userns_clone: bool,
    pub kptr_restrict: u8,
    pub dmesg_restrict: bool,
    pub hw_pan_active: bool,
    pub hw_mte_supported: bool,
    pub hw_pac_bti_supported: bool,
    pub avb_verified_boot_green: bool,
}

impl GrapheneOsHardeningPolicy {
    pub const fn default_pixel_grapheneos() -> Self {
        Self {
            selinux_enforcing: true,
            selinux_policy_version: 33,
            wx_ttbr1_isolated: true,
            capability_binder_enforced: true,
            zero_on_free_allocator: true,
            exec_spawning_enabled: true,
            ptrace_scope: 3,
            unprivileged_userns_clone: false,
            kptr_restrict: 2,
            dmesg_restrict: true,
            hw_pan_active: true,
            hw_mte_supported: false,
            hw_pac_bti_supported: false,
            avb_verified_boot_green: true,
        }
    }
}

/// Unified Android 15 / GrapheneOS kernel runtime container.
pub struct AndroidKernelState {
    pub binder: BinderDomainBroker,
    pub hwbinder: BinderDomainBroker,
    pub vndbinder: BinderDomainBroker,
    pub properties: Vec<AndroidProperty>,
    pub wakelocks: Vec<String>,
    pub hardening: GrapheneOsHardeningPolicy,
    pub selinux_check_count: u64,
    pub ashmem_regions: Vec<AshmemRegion>,
    pub binderfs_devices: Vec<String>,
    pub ebpf: ebpf::EbpfSubsystem,
    pub dm: storage::DmControlState,
    pub fuse: storage::FuseSessionState,
    pub erofs_verified_count: u64,
    pub f2fs_verified_count: u64,
    pub super_lp_verified_count: u64,
    pub sepolicy_load_count: u64,
    pub sepolicy_bytes: usize,
    pub sepolicy_sha256: [u8; 32],
    pub bionic_vma_names_set: u64,
    pub tagged_addr_ctrl: u64,
    pub timerslack_ns: u64,
    next_ashmem_id: u32,
}

impl AndroidKernelState {
    pub fn new() -> Self {
        let mut state = Self {
            binder: BinderDomainBroker::new(BinderDomain::Framework),
            hwbinder: BinderDomainBroker::new(BinderDomain::HardwareHal),
            vndbinder: BinderDomainBroker::new(BinderDomain::Vendor),
            properties: Vec::new(),
            wakelocks: Vec::new(),
            hardening: GrapheneOsHardeningPolicy::default_pixel_grapheneos(),
            selinux_check_count: 0,
            ashmem_regions: Vec::new(),
            binderfs_devices: vec![
                String::from("binder"),
                String::from("hwbinder"),
                String::from("vndbinder"),
            ],
            ebpf: ebpf::EbpfSubsystem::new(),
            dm: storage::DmControlState::new_with_android_root(),
            fuse: storage::FuseSessionState::new(),
            erofs_verified_count: 0,
            f2fs_verified_count: 0,
            super_lp_verified_count: 0,
            sepolicy_load_count: 1,
            sepolicy_bytes: 4096,
            sepolicy_sha256: storage::sha256(b"QYRONEX_GRAPHENEOS_SEPOLICY_V33_DEFAULT"),
            bionic_vma_names_set: 0,
            tagged_addr_ctrl: 1,
            timerslack_ns: 50_000,
            next_ashmem_id: 1,
        };
        state.seed_default_properties();
        state
    }

    fn seed_default_properties(&mut self) {
        let defaults: &[(&str, &str)] = &[
            ("ro.product.brand", "Qyronex"),
            ("ro.product.manufacturer", "Google/Qyronex"),
            ("ro.product.model", "Qyronex Pixel (GrapheneOS)"),
            ("ro.product.device", "qyronex_pixel"),
            ("ro.hardware", "qyronex_pixel"),
            ("ro.build.version.release", "15"),
            ("ro.build.version.sdk", "35"),
            ("ro.build.version.security_patch", "2026-11-05"),
            ("ro.build.display.id", "AP4A.261105.001.Qyronex"),
            ("ro.build.type", "user"),
            ("ro.boot.verifiedbootstate", "green"),
            ("ro.boot.flash.locked", "1"),
            ("ro.boot.selinux", "enforcing"),
            ("ro.kernel.name", "Qyronex-Hybrid-Rust"),
            ("ro.kernel.version", "6.12.0-qyronex-android15-gki"),
            ("ro.kernel.qyronex.capability_binder", "enforced"),
            ("ro.kernel.qyronex.ttbr1_isolation", "active"),
            ("ro.grapheneos.hardened_malloc", "1"),
            ("ro.grapheneos.exec_spawning", "1"),
            ("ro.grapheneos.titan_m2", "strongbox"),
            ("ro.boot.vbmeta.hash_alg", "sha256"),
            ("ro.boot.dynamic_partitions", "true"),
            ("ro.boot.dm_verity", "enforcing"),
            ("ro.qyronex.ebpf.verifier", "enforcing"),
            ("ro.qyronex.storage.fs", "ext4,erofs,f2fs,fuse,dm-verity"),
            ("ro.qyronex.art.runtime", "qyronex-art-dalvik-v15"),
            ("persist.sys.timezone", "Europe/Berlin"),
            ("sys.boot_completed", "0"),
        ];
        for &(k, v) in defaults {
            let _ = self.set_property(k, v, true);
        }
    }

    pub fn broker_mut(&mut self, domain: BinderDomain) -> &mut BinderDomainBroker {
        match domain {
            BinderDomain::Framework => &mut self.binder,
            BinderDomain::HardwareHal => &mut self.hwbinder,
            BinderDomain::Vendor => &mut self.vndbinder,
        }
    }

    pub fn broker(&self, domain: BinderDomain) -> &BinderDomainBroker {
        match domain {
            BinderDomain::Framework => &self.binder,
            BinderDomain::HardwareHal => &self.hwbinder,
            BinderDomain::Vendor => &self.vndbinder,
        }
    }

    /// Sets an Android system property. `ro.*` properties are strictly immutable once created
    /// (unless `allow_ro_init` is set during kernel bootstrap).
    pub fn set_property(
        &mut self,
        key: &str,
        value: &str,
        allow_ro_init: bool,
    ) -> Result<(), Errno> {
        if key.is_empty() || key.len() > 92 || value.len() > 92 {
            return Err(Errno::EINVAL);
        }
        let is_ro = key.starts_with("ro.");
        if let Some(existing) = self.properties.iter_mut().find(|p| p.key == key) {
            if existing.read_only && !allow_ro_init {
                return Err(Errno::EPERM);
            }
            existing.value = String::from(value);
            return Ok(());
        }
        if is_ro && !allow_ro_init {
            return Err(Errno::EPERM);
        }
        self.properties.push(AndroidProperty {
            key: String::from(key),
            value: String::from(value),
            read_only: is_ro,
        });
        Ok(())
    }

    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.value.as_str())
    }

    pub fn acquire_wakelock(&mut self, name: &str) -> Result<(), Errno> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > 64 {
            return Err(Errno::EINVAL);
        }
        if !self.wakelocks.iter().any(|w| w == trimmed) {
            self.wakelocks.push(String::from(trimmed));
        }
        Ok(())
    }

    pub fn release_wakelock(&mut self, name: &str) -> Result<(), Errno> {
        let trimmed = name.trim();
        self.wakelocks.retain(|w| w != trimmed);
        Ok(())
    }

    pub fn create_ashmem(&mut self) -> Result<u32, Errno> {
        if self.ashmem_regions.len() >= 32 {
            return Err(Errno::ENOMEM);
        }
        let id = self.next_ashmem_id;
        self.next_ashmem_id = self.next_ashmem_id.wrapping_add(1).max(1);
        self.ashmem_regions.push(AshmemRegion::new(id));
        Ok(id)
    }

    pub fn ashmem_mut(&mut self, id: u32) -> Option<&mut AshmemRegion> {
        self.ashmem_regions.iter_mut().find(|r| r.id == id)
    }

    pub fn ashmem(&self, id: u32) -> Option<&AshmemRegion> {
        self.ashmem_regions.iter().find(|r| r.id == id)
    }

    pub fn destroy_ashmem(&mut self, id: u32) {
        if let Some(pos) = self.ashmem_regions.iter().position(|r| r.id == id) {
            if self.hardening.zero_on_free_allocator {
                self.ashmem_regions[pos].sanitize_zero();
            }
            self.ashmem_regions.swap_remove(pos);
        }
    }

    /// Provisions a dynamic named binderfs device via `BINDER_CTL_ADD`.
    pub fn add_binderfs_device(&mut self, name: &str) -> Result<(u32, u32), Errno> {
        let trimmed = name.trim_matches('\0').trim();
        if trimmed.is_empty() || trimmed.len() > 64 || trimmed.contains('/') {
            return Err(Errno::EINVAL);
        }
        if let Some(pos) = self.binderfs_devices.iter().position(|n| n == trimmed) {
            return Ok((240, pos as u32));
        }
        if self.binderfs_devices.len() >= 16 {
            return Err(Errno::ENOSPC);
        }
        let minor = self.binderfs_devices.len() as u32;
        self.binderfs_devices.push(String::from(trimmed));
        Ok((240, minor))
    }

    /// Loads an Android binary SELinux policy (`/sys/fs/selinux/load` during `init selinux_setup`).
    pub fn load_sepolicy(&mut self, data: &[u8]) -> Result<(), Errno> {
        if data.is_empty() || data.len() > 8 * 1024 * 1024 {
            return Err(Errno::EINVAL);
        }
        self.sepolicy_sha256 = storage::sha256(data);
        self.sepolicy_bytes = data.len();
        self.sepolicy_load_count = self.sepolicy_load_count.saturating_add(1);
        self.hardening.selinux_enforcing = true;
        Ok(())
    }

    /// Validates an Android SELinux context string written to `/sys/fs/selinux/context`.
    pub fn validate_selinux_context(&mut self, raw: &[u8]) -> Result<(), Errno> {
        let Ok(s) = core::str::from_utf8(raw) else {
            return Err(Errno::EINVAL);
        };
        let trimmed = s.trim_matches('\0').trim();
        if !trimmed.starts_with("u:r:") && !trimmed.starts_with("u:object_r:") {
            return Err(Errno::EINVAL);
        }
        if !trimmed.contains(":s0") {
            return Err(Errno::EINVAL);
        }
        self.selinux_check_count = self.selinux_check_count.saturating_add(1);
        Ok(())
    }

    pub fn binder_audit_stats(&self) -> BinderAuditStats {
        let mut mgrs = 0u8;
        if self.binder.has_context_manager() {
            mgrs += 1;
        }
        if self.hwbinder.has_context_manager() {
            mgrs += 1;
        }
        if self.vndbinder.has_context_manager() {
            mgrs += 1;
        }
        BinderAuditStats {
            total_transactions: self.binder.total_transactions
                + self.hwbinder.total_transactions
                + self.vndbinder.total_transactions,
            total_replies: self.binder.total_replies
                + self.hwbinder.total_replies
                + self.vndbinder.total_replies,
            total_fd_transfers: self.binder.total_fd_transfers
                + self.hwbinder.total_fd_transfers
                + self.vndbinder.total_fd_transfers,
            capability_denials: self.binder.capability_denials
                + self.hwbinder.capability_denials
                + self.vndbinder.capability_denials,
            active_endpoints: self.binder.active_endpoints()
                + self.hwbinder.active_endpoints()
                + self.vndbinder.active_endpoints(),
            context_managers_bound: mgrs,
        }
    }
}

impl Default for AndroidKernelState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_cap(id: u64) -> Capability {
        Capability {
            object: ObjectId(id),
            rights: CapRights::READ
                .union(CapRights::WRITE)
                .union(CapRights::CONTROL),
        }
    }

    fn rw_cap(id: u64) -> Capability {
        Capability {
            object: ObjectId(id),
            rights: CapRights::READ.union(CapRights::WRITE),
        }
    }

    fn ro_cap(id: u64) -> Capability {
        Capability {
            object: ObjectId(id),
            rights: CapRights::READ,
        }
    }

    #[test]
    fn binder_servicemanager_and_client_roundtrip_works() {
        let mut state = AndroidKernelState::new();
        let mgr = state
            .binder
            .open_endpoint(ObjectId(1), 10, 0, full_cap(1))
            .unwrap();
        state.binder.set_context_manager(mgr).unwrap();
        state.binder.enter_looper(mgr).unwrap();

        let cli = state
            .binder
            .open_endpoint(ObjectId(2), 20, 1000, rw_cap(2))
            .unwrap();

        let tx = BinderTransactionData {
            target_handle_or_ptr: 0,
            cookie: 0,
            code: 2, // CHECK_SERVICE_TRANSACTION
            flags: 0,
            sender_pid: 0,
            sender_euid: 0,
            data_size: 14,
            offsets_size: 0,
            data_ptr: 0,
            offsets_ptr: 0,
        };
        state
            .binder
            .dispatch_transaction(cli, tx, b"SurfaceFlinger".to_vec())
            .unwrap();

        // Client immediately gets BR_TRANSACTION_COMPLETE
        let ack = state.binder.pop_work(cli).unwrap();
        assert_eq!(ack.return_cmd, BR_TRANSACTION_COMPLETE);

        // Manager receives BR_TRANSACTION with verified kernel sender PID/EUID
        let req = state.binder.pop_work(mgr).unwrap();
        assert_eq!(req.return_cmd, BR_TRANSACTION);
        assert_eq!(req.sender_pid, 20);
        assert_eq!(req.sender_euid, 1000);
        assert_eq!(req.payload, b"SurfaceFlinger");

        // Manager replies with BC_REPLY -> client receives BR_REPLY
        state
            .binder
            .dispatch_reply(mgr, tx, b"handle=1".to_vec())
            .unwrap();
        let srv_ack = state.binder.pop_work(mgr).unwrap();
        assert_eq!(srv_ack.return_cmd, BR_TRANSACTION_COMPLETE);
        let reply = state.binder.pop_work(cli).unwrap();
        assert_eq!(reply.return_cmd, BR_REPLY);
        assert_eq!(reply.sender_pid, 10);
        assert_eq!(reply.payload, b"handle=1");

        let stats = state.binder_audit_stats();
        assert_eq!(stats.total_transactions, 1);
        assert_eq!(stats.total_replies, 1);
        assert_eq!(stats.capability_denials, 0);
        assert_eq!(stats.context_managers_bound, 1);
    }

    #[test]
    fn binder_enforces_qyronex_capabilities_fail_closed() {
        let mut state = AndroidKernelState::new();
        let unpriv = state
            .binder
            .open_endpoint(ObjectId(5), 55, 10055, ro_cap(5))
            .unwrap();
        // Cannot hijack servicemanager without CONTROL right
        assert_eq!(state.binder.set_context_manager(unpriv), Err(Errno::EPERM));

        // Cannot send transactions without WRITE right
        let tx = BinderTransactionData {
            target_handle_or_ptr: 0,
            cookie: 0,
            code: 1,
            flags: 0,
            sender_pid: 0,
            sender_euid: 0,
            data_size: 4,
            offsets_size: 0,
            data_ptr: 0,
            offsets_ptr: 0,
        };
        assert_eq!(
            state
                .binder
                .dispatch_transaction(unpriv, tx, vec![1, 2, 3, 4]),
            Err(Errno::EPERM)
        );
        assert_eq!(state.binder_audit_stats().capability_denials, 2);
    }

    #[test]
    fn ashmem_pin_unpin_and_ro_property_immutability() {
        let mut state = AndroidKernelState::new();
        assert_eq!(state.get_property("ro.build.version.release"), Some("15"));
        assert_eq!(
            state.set_property("ro.build.version.release", "99", false),
            Err(Errno::EPERM)
        );
        state
            .set_property("sys.boot_completed", "1", false)
            .unwrap();
        assert_eq!(state.get_property("sys.boot_completed"), Some("1"));

        let id = state.create_ashmem().unwrap();
        {
            let reg = state.ashmem_mut(id).unwrap();
            reg.set_name(b"surfaceflinger_fb\0").unwrap();
            reg.set_size(4096).unwrap();
            reg.ensure_allocated().unwrap();
            reg.data[0] = 0xAA;
            assert_eq!(reg.unpin(), 0);
            assert!(!reg.pinned);
            assert_eq!(reg.pin(), ASHMEM_NOT_PURGED);
            assert!(reg.pinned);
        }
        state.destroy_ashmem(id);
        assert!(state.ashmem(id).is_none());
    }

    #[test]
    fn wakelocks_acquire_and_release() {
        let mut state = AndroidKernelState::new();
        state.acquire_wakelock("SurfaceFlinger").unwrap();
        state.acquire_wakelock("PowerManagerService").unwrap();
        assert_eq!(state.wakelocks.len(), 2);
        state.release_wakelock("SurfaceFlinger").unwrap();
        assert_eq!(state.wakelocks, vec![String::from("PowerManagerService")]);
    }

    #[test]
    fn binder_v8_flat_object_and_fd_transfer() {
        let mut state = AndroidKernelState::new();
        let mgr = state
            .binder
            .open_endpoint(ObjectId(1), 10, 0, full_cap(1))
            .unwrap();
        state.binder.set_context_manager(mgr).unwrap();
        let cli = state
            .binder
            .open_endpoint(ObjectId(2), 20, 1000, full_cap(2))
            .unwrap();

        let obj_binder = FlatBinderObject {
            obj_type: BINDER_TYPE_BINDER,
            flags: 0,
            binder_or_handle: 0xDEAD_BEEF,
            cookie: 0xCAFE,
        };
        let obj_fd = FlatBinderObject {
            obj_type: BINDER_TYPE_FD,
            flags: 0,
            binder_or_handle: 7,
            cookie: 0,
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(&obj_binder.to_le_bytes());
        payload.extend_from_slice(&obj_fd.to_le_bytes());
        let offsets = vec![0u64, FLAT_BINDER_OBJECT_BYTES as u64];
        let xfer = vec![BinderTransferredFd {
            payload_offset: FLAT_BINDER_OBJECT_BYTES,
            subsys_kind: 14,
            subsys_slot: 3,
            subsys_generation: 1,
            status_flags: 2,
        }];
        let tx = BinderTransactionData {
            target_handle_or_ptr: 0,
            cookie: 0,
            code: 5,
            flags: 0,
            sender_pid: 20,
            sender_euid: 1000,
            data_size: payload.len() as u64,
            offsets_size: (offsets.len() * 8) as u64,
            data_ptr: 0,
            offsets_ptr: 0,
        };
        state
            .binder
            .dispatch_transaction_with_objects(cli, tx, payload, offsets, xfer)
            .unwrap();
        assert_eq!(state.binder.total_transactions, 1);
        assert_eq!(state.binder.total_fd_transfers, 1);

        let delivered = state.binder.pop_work(mgr).unwrap();
        assert_eq!(delivered.return_cmd, BR_TRANSACTION);
        assert_eq!(delivered.transferred_fds.len(), 1);
        assert_eq!(delivered.offsets.len(), 2);
        let translated =
            FlatBinderObject::from_le_bytes(&delivered.payload[..FLAT_BINDER_OBJECT_BYTES])
                .unwrap();
        assert_eq!(translated.obj_type, BINDER_TYPE_HANDLE);
        assert!(translated.binder_or_handle >= 1);
    }

    #[test]
    fn binderfs_dynamic_device_allocation() {
        let mut state = AndroidKernelState::new();
        assert_eq!(state.binderfs_devices.len(), 3);
        let (major, minor) = state.add_binderfs_device("my-custom-binder").unwrap();
        assert_eq!(major, 240);
        assert!(minor >= 3);
        assert_eq!(state.binderfs_devices.len(), 4);
        assert_eq!(
            state.add_binderfs_device("my-custom-binder"),
            Ok((major, minor))
        );
        assert_eq!(state.add_binderfs_device("../bad"), Err(Errno::EINVAL));
    }
}
