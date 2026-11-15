// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Architecture-neutral Linux credential owner for Roadmap Step 30.
//!
//! Linux UID/GID values are policy metadata only. This crate exposes no conversion from Linux
//! credentials to Kernal capability rights and cannot manufacture Process/Object authority.

use kernal_capability::ObjectId;
use kernal_linux_identity::{Error as IdentityError, LinuxIdentityTable};
use kernal_process::{Personality, Process, ProcessState};
use kernal_usercopy::{Error as UsercopyError, UserRange};

/// Linux `struct robust_list_head` size for the 64-bit ABI used by the active AArch64 target.
///
/// The value is an ABI contract only. This crate never dereferences the head or walks its list;
/// that remains the responsibility of the existing usercopy/futex/thread-exit integration owners.
pub const ROBUST_LIST_HEAD_BYTES: usize = 24;

/// Maximum supplementary GIDs tracked per Linux process credential record.
pub const MAX_SUPPLEMENTARY_GROUPS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity(IdentityError),
    UserRange(UsercopyError),
    Capacity,
    WrongPersonality,
    ProcessExited,
    AlreadyBound,
    ProcessNotBound,
    ChildMismatch,
    CannotClearNoNewPrivs,
    InvalidRobustListLength,
    PermissionDenied,
    InvalidArgument,
}

impl From<IdentityError> for Error {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}

impl From<UsercopyError> for Error {
    fn from(value: UsercopyError) -> Self {
        Self::UserRange(value)
    }
}

/// Validated userspace metadata published by Linux `set_robust_list`.
///
/// Linux robust-list ownership is per-thread, so this value deliberately contains no table slot,
/// PID/TID registry or lifecycle authority. The syscall integration owner stores it beside the
/// canonical exact Thread generation and hands it to the existing futex/thread-exit owner when that
/// thread exits. Keeping only a validated [`UserRange`] here prevents this Safe-Rust policy crate
/// from dereferencing user memory or inventing a second robust-futex walker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RobustListRegistration {
    head: UserRange,
}

impl RobustListRegistration {
    /// Validates the Linux-64 robust-list head pointer and exact ABI length.
    pub fn new(head_address: u64, len: usize) -> Result<Self, Error> {
        if len != ROBUST_LIST_HEAD_BYTES {
            return Err(Error::InvalidRobustListLength);
        }
        Ok(Self {
            head: UserRange::new(head_address, len)?,
        })
    }

    pub const fn head_address(self) -> u64 {
        self.head.start()
    }

    pub const fn len(self) -> usize {
        self.head.len()
    }

    pub const fn is_empty(self) -> bool {
        false
    }

    /// Returns the already-validated range for the real usercopy/futex integration owner.
    pub const fn user_range(self) -> UserRange {
        self.head
    }
}

/// Linux-visible credential scalar state.
///
/// These values deliberately do not contain or imply Kernal `CapRights`. In particular, UID 0 is
/// not a privileged capability handle; authorization remains with the existing Kernal object and
/// capability owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxCredentials {
    ruid: u32,
    euid: u32,
    suid: u32,
    fsuid: u32,
    rgid: u32,
    egid: u32,
    sgid: u32,
    fsgid: u32,
}

impl LinuxCredentials {
    pub const fn root() -> Self {
        Self::from_ids(0, 0)
    }

    pub const fn from_ids(uid: u32, gid: u32) -> Self {
        Self {
            ruid: uid,
            euid: uid,
            suid: uid,
            fsuid: uid,
            rgid: gid,
            egid: gid,
            sgid: gid,
            fsgid: gid,
        }
    }

    pub const fn ruid(self) -> u32 {
        self.ruid
    }

    pub const fn euid(self) -> u32 {
        self.euid
    }

    pub const fn suid(self) -> u32 {
        self.suid
    }

    pub const fn fsuid(self) -> u32 {
        self.fsuid
    }

    pub const fn rgid(self) -> u32 {
        self.rgid
    }

    pub const fn egid(self) -> u32 {
        self.egid
    }

    pub const fn sgid(self) -> u32 {
        self.sgid
    }

    pub const fn fsgid(self) -> u32 {
        self.fsgid
    }

    /// Returns whether these sender credentials satisfy Linux's UID-based signal permission rule
    /// for `target`, excluding capability and same-session `SIGCONT` exceptions.
    ///
    /// Linux permits a user-generated signal when either the sender's real or effective UID equals
    /// either the target's real or saved-set UID. UID 0 receives no special treatment here: CAP_KILL
    /// is deliberately outside this Step-30 credential slice and Kernal capability rights remain a
    /// separate authority domain.
    pub const fn may_signal(self, target: Self) -> bool {
        self.ruid == target.ruid
            || self.ruid == target.suid
            || self.euid == target.ruid
            || self.euid == target.suid
    }

    pub fn set_uid(&mut self, uid: u32) -> Result<(), Error> {
        let priv_root = self.euid == 0;
        apply_setid(
            priv_root,
            &mut self.ruid,
            &mut self.euid,
            &mut self.suid,
            &mut self.fsuid,
            uid,
        )
    }

    pub fn set_reuid(&mut self, ruid: Option<u32>, euid: Option<u32>) -> Result<(), Error> {
        let priv_root = self.euid == 0;
        apply_setreid(
            priv_root,
            &mut self.ruid,
            &mut self.euid,
            &mut self.suid,
            &mut self.fsuid,
            ruid,
            euid,
        )
    }

    pub fn set_resuid(
        &mut self,
        ruid: Option<u32>,
        euid: Option<u32>,
        suid: Option<u32>,
    ) -> Result<(), Error> {
        let priv_root = self.euid == 0;
        apply_setresid(
            priv_root,
            &mut self.ruid,
            &mut self.euid,
            &mut self.suid,
            &mut self.fsuid,
            ruid,
            euid,
            suid,
        )
    }

    pub fn set_fsuid(&mut self, fsuid: Option<u32>) -> u32 {
        let priv_root = self.euid == 0;
        apply_setfsid(
            priv_root,
            self.ruid,
            self.euid,
            self.suid,
            &mut self.fsuid,
            fsuid,
        )
    }

    pub fn set_gid(&mut self, gid: u32) -> Result<(), Error> {
        let priv_root = self.euid == 0;
        apply_setid(
            priv_root,
            &mut self.rgid,
            &mut self.egid,
            &mut self.sgid,
            &mut self.fsgid,
            gid,
        )
    }

    pub fn set_regid(&mut self, rgid: Option<u32>, egid: Option<u32>) -> Result<(), Error> {
        let priv_root = self.euid == 0;
        apply_setreid(
            priv_root,
            &mut self.rgid,
            &mut self.egid,
            &mut self.sgid,
            &mut self.fsgid,
            rgid,
            egid,
        )
    }

    pub fn set_resgid(
        &mut self,
        rgid: Option<u32>,
        egid: Option<u32>,
        sgid: Option<u32>,
    ) -> Result<(), Error> {
        let priv_root = self.euid == 0;
        apply_setresid(
            priv_root,
            &mut self.rgid,
            &mut self.egid,
            &mut self.sgid,
            &mut self.fsgid,
            rgid,
            egid,
            sgid,
        )
    }

    pub fn set_fsgid(&mut self, fsgid: Option<u32>) -> u32 {
        let priv_root = self.euid == 0;
        apply_setfsid(
            priv_root,
            self.rgid,
            self.egid,
            self.sgid,
            &mut self.fsgid,
            fsgid,
        )
    }
}

fn apply_setid(
    priv_root: bool,
    real: &mut u32,
    eff: &mut u32,
    saved: &mut u32,
    fs: &mut u32,
    id: u32,
) -> Result<(), Error> {
    if priv_root {
        *real = id;
        *eff = id;
        *saved = id;
        *fs = id;
        Ok(())
    } else if id == *real || id == *saved {
        *eff = id;
        *fs = id;
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}

fn apply_setreid(
    priv_root: bool,
    real: &mut u32,
    eff: &mut u32,
    saved: &mut u32,
    fs: &mut u32,
    new_real: Option<u32>,
    new_eff: Option<u32>,
) -> Result<(), Error> {
    let (old_r, old_e, old_s) = (*real, *eff, *saved);
    if let Some(r) = new_real
        && !priv_root
        && r != old_r
        && r != old_e
    {
        return Err(Error::PermissionDenied);
    }
    if let Some(e) = new_eff
        && !priv_root
        && e != old_r
        && e != old_e
        && e != old_s
    {
        return Err(Error::PermissionDenied);
    }
    if let Some(r) = new_real {
        *real = r;
    }
    if let Some(e) = new_eff {
        *eff = e;
    }
    if new_real.is_some() || new_eff.is_some_and(|e| e != old_r) {
        *saved = *eff;
    }
    *fs = *eff;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_setresid(
    priv_root: bool,
    real: &mut u32,
    eff: &mut u32,
    saved: &mut u32,
    fs: &mut u32,
    new_real: Option<u32>,
    new_eff: Option<u32>,
    new_saved: Option<u32>,
) -> Result<(), Error> {
    let (old_r, old_e, old_s) = (*real, *eff, *saved);
    let allowed = |v: u32| priv_root || v == old_r || v == old_e || v == old_s;
    if new_real.is_some_and(|v| !allowed(v))
        || new_eff.is_some_and(|v| !allowed(v))
        || new_saved.is_some_and(|v| !allowed(v))
    {
        return Err(Error::PermissionDenied);
    }
    if let Some(r) = new_real {
        *real = r;
    }
    if let Some(e) = new_eff {
        *eff = e;
    }
    if let Some(s) = new_saved {
        *saved = s;
    }
    *fs = *eff;
    Ok(())
}

fn apply_setfsid(
    priv_root: bool,
    real: u32,
    eff: u32,
    saved: u32,
    fs: &mut u32,
    new_fs: Option<u32>,
) -> u32 {
    let old_fs = *fs;
    if let Some(v) = new_fs
        && (priv_root || v == real || v == eff || v == saved || v == old_fs)
    {
        *fs = v;
    }
    old_fs
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CredentialRecord {
    process: ObjectId,
    credentials: LinuxCredentials,
    no_new_privs: bool,
    groups: [u32; MAX_SUPPLEMENTARY_GROUPS],
    groups_len: usize,
}

/// Bounded Linux credential policy keyed by exact Process generation.
///
/// The table is not a Process registry: object creation/destruction and authority remain in
/// `kernal-process`. Exact ObjectIds only prevent stale slot generations from inheriting credential
/// state accidentally.
pub struct CredentialTable<const N: usize> {
    records: [Option<CredentialRecord>; N],
}

impl<const N: usize> CredentialTable<N> {
    pub const fn new() -> Self {
        Self { records: [None; N] }
    }

    /// Binds explicit Linux credential metadata to one exact live Linux Process generation.
    ///
    /// Repeating the same binding is idempotent. Attempting to replace credentials for an already
    /// bound generation fails closed; mutation semantics such as setuid/setgid are separate policy
    /// operations and must not be smuggled through initialization.
    pub fn bind_process<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        credentials: LinuxCredentials,
    ) -> Result<(), Error> {
        validate_live_linux(process)?;
        if let Some(existing) = self.record(process.id()) {
            return if existing.credentials == credentials {
                Ok(())
            } else {
                Err(Error::AlreadyBound)
            };
        }

        let slot = self
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.records[slot] = Some(CredentialRecord {
            process: process.id(),
            credentials,
            no_new_privs: false,
            groups: [0; MAX_SUPPLEMENTARY_GROUPS],
            groups_len: 0,
        });
        Ok(())
    }

    /// Copies Linux credential metadata to an exact child relation already proven by the canonical
    /// Linux identity owner. No Kernal capability or CSpace content is copied here.
    pub fn inherit_child<
        const PROCESSES: usize,
        const THREADS: usize,
        const PARENT_CAPS: usize,
        const CHILD_CAPS: usize,
    >(
        &mut self,
        identities: &LinuxIdentityTable<PROCESSES, THREADS>,
        parent: &Process<PARENT_CAPS>,
        child: &Process<CHILD_CAPS>,
    ) -> Result<(), Error> {
        validate_live_linux(parent)?;
        validate_live_linux(child)?;
        if !identities.is_child_of(parent, child)? {
            return Err(Error::ChildMismatch);
        }

        let parent_record = self.record(parent.id()).ok_or(Error::ProcessNotBound)?;
        if let Some(existing) = self.record(child.id()) {
            return if existing.credentials == parent_record.credentials
                && existing.no_new_privs == parent_record.no_new_privs
                && existing.groups_len == parent_record.groups_len
                && existing.groups[..existing.groups_len]
                    == parent_record.groups[..parent_record.groups_len]
            {
                Ok(())
            } else {
                Err(Error::AlreadyBound)
            };
        }

        let slot = self
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.records[slot] = Some(CredentialRecord {
            process: child.id(),
            credentials: parent_record.credentials,
            no_new_privs: parent_record.no_new_privs,
            groups: parent_record.groups,
            groups_len: parent_record.groups_len,
        });
        Ok(())
    }

    pub fn credentials<const CAPS: usize>(
        &self,
        process: &Process<CAPS>,
    ) -> Result<LinuxCredentials, Error> {
        validate_live_linux(process)?;
        self.record(process.id())
            .map(|record| record.credentials)
            .ok_or(Error::ProcessNotBound)
    }

    /// Updates Linux credentials for one live Linux process using POSIX rule checks.
    pub fn update_credentials<const CAPS: usize, R>(
        &mut self,
        process: &Process<CAPS>,
        f: impl FnOnce(&mut LinuxCredentials) -> Result<R, Error>,
    ) -> Result<R, Error> {
        validate_live_linux(process)?;
        let index = self
            .record_index(process.id())
            .ok_or(Error::ProcessNotBound)?;
        let mut record = self.records[index].ok_or(Error::ProcessNotBound)?;
        let res = f(&mut record.credentials)?;
        self.records[index] = Some(record);
        Ok(res)
    }

    pub fn groups<const CAPS: usize>(&self, process: &Process<CAPS>) -> Result<&[u32], Error> {
        validate_live_linux(process)?;
        let index = self
            .record_index(process.id())
            .ok_or(Error::ProcessNotBound)?;
        let record = self.records[index].as_ref().ok_or(Error::ProcessNotBound)?;
        Ok(&record.groups[..record.groups_len])
    }

    pub fn set_groups<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        groups: &[u32],
    ) -> Result<(), Error> {
        validate_live_linux(process)?;
        let index = self
            .record_index(process.id())
            .ok_or(Error::ProcessNotBound)?;
        let mut record = self.records[index].ok_or(Error::ProcessNotBound)?;
        if record.credentials.euid != 0 {
            return Err(Error::PermissionDenied);
        }
        if groups.len() > MAX_SUPPLEMENTARY_GROUPS {
            return Err(Error::InvalidArgument);
        }
        record.groups = [0; MAX_SUPPLEMENTARY_GROUPS];
        record.groups[..groups.len()].copy_from_slice(groups);
        record.groups_len = groups.len();
        self.records[index] = Some(record);
        Ok(())
    }

    /// Implements the irreversible policy core behind `PR_SET_NO_NEW_PRIVS` / `PR_GET_NO_NEW_PRIVS`.
    ///
    /// Setting true is idempotent and inherited by exact children. Clearing after it becomes true is
    /// rejected. This flag is Linux policy metadata only; it neither grants nor revokes Kernal object
    /// capabilities by itself.
    pub fn set_no_new_privs<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        enabled: bool,
    ) -> Result<(), Error> {
        validate_live_linux(process)?;
        let index = self
            .record_index(process.id())
            .ok_or(Error::ProcessNotBound)?;
        let mut record = self.records[index].ok_or(Error::ProcessNotBound)?;
        if record.no_new_privs && !enabled {
            return Err(Error::CannotClearNoNewPrivs);
        }
        record.no_new_privs = enabled;
        self.records[index] = Some(record);
        Ok(())
    }

    pub fn no_new_privs<const CAPS: usize>(&self, process: &Process<CAPS>) -> Result<bool, Error> {
        validate_live_linux(process)?;
        self.record(process.id())
            .map(|record| record.no_new_privs)
            .ok_or(Error::ProcessNotBound)
    }

    /// Releases credential metadata only after the canonical Process owner has completed exit.
    pub fn retire_process<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
    ) -> Result<LinuxCredentials, Error> {
        if process.personality() != Personality::Linux {
            return Err(Error::WrongPersonality);
        }
        if process.state() != ProcessState::Exited {
            return Err(Error::ProcessExited);
        }
        let index = self
            .record_index(process.id())
            .ok_or(Error::ProcessNotBound)?;
        let record = self.records[index].take().ok_or(Error::ProcessNotBound)?;
        Ok(record.credentials)
    }

    fn record(&self, process: ObjectId) -> Option<CredentialRecord> {
        self.records
            .iter()
            .flatten()
            .copied()
            .find(|record| record.process == process)
    }

    fn record_index(&self, process: ObjectId) -> Option<usize> {
        self.records
            .iter()
            .position(|record| record.is_some_and(|record| record.process == process))
    }
}

impl<const N: usize> Default for CredentialTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_live_linux<const CAPS: usize>(process: &Process<CAPS>) -> Result<(), Error> {
    if process.personality() != Personality::Linux {
        return Err(Error::WrongPersonality);
    }
    if process.state() != ProcessState::Live {
        return Err(Error::ProcessExited);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_object::ObjectTable;
    use kernal_process::ThreadObjectBindings;

    #[test]
    fn robust_list_registration_requires_exact_head_size_and_user_range() {
        let registration = RobustListRegistration::new(0x1_0000, ROBUST_LIST_HEAD_BYTES).unwrap();
        assert_eq!(registration.head_address(), 0x1_0000);
        assert_eq!(registration.len(), ROBUST_LIST_HEAD_BYTES);
        assert!(!registration.is_empty());
        assert_eq!(registration.user_range().start(), 0x1_0000);
        assert_eq!(
            RobustListRegistration::new(0x1_0000, ROBUST_LIST_HEAD_BYTES - 1),
            Err(Error::InvalidRobustListLength)
        );
        assert_eq!(
            RobustListRegistration::new(0, ROBUST_LIST_HEAD_BYTES),
            Err(Error::UserRange(UsercopyError::NullGuard))
        );
    }

    #[test]
    fn signal_permission_matches_linux_uid_rule_without_uid_zero_capability() {
        let sender_real = LinuxCredentials {
            ruid: 10,
            euid: 20,
            suid: 30,
            fsuid: 40,
            rgid: 1,
            egid: 1,
            sgid: 1,
            fsgid: 1,
        };
        let sender_effective = LinuxCredentials {
            ruid: 11,
            euid: 21,
            ..sender_real
        };
        let target_real = LinuxCredentials {
            ruid: 10,
            euid: 50,
            suid: 60,
            fsuid: 70,
            ..sender_real
        };
        let target_saved = LinuxCredentials {
            ruid: 12,
            euid: 50,
            suid: 21,
            fsuid: 70,
            ..target_real
        };
        let unrelated = LinuxCredentials::from_ids(99, 99);

        assert!(sender_real.may_signal(target_real));
        assert!(sender_effective.may_signal(target_saved));
        assert!(!sender_real.may_signal(unrelated));
        assert!(!LinuxCredentials::root().may_signal(unrelated));
    }

    #[test]
    fn uid_zero_is_explicit_metadata_and_no_new_privs_is_one_way() {
        let mut objects = ObjectTable::<4>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut table = CredentialTable::<2>::new();
        table
            .bind_process(&process, LinuxCredentials::root())
            .unwrap();

        let credentials = table.credentials(&process).unwrap();
        assert_eq!(credentials.ruid(), 0);
        assert_eq!(credentials.euid(), 0);
        assert_eq!(credentials.rgid(), 0);
        assert_eq!(credentials.egid(), 0);
        assert!(!table.no_new_privs(&process).unwrap());

        table.set_no_new_privs(&process, true).unwrap();
        assert!(table.no_new_privs(&process).unwrap());
        assert_eq!(
            table.set_no_new_privs(&process, false),
            Err(Error::CannotClearNoNewPrivs)
        );
    }

    #[test]
    fn exact_child_inherits_credentials_without_accepting_pid_authority() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let unrelated = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();

        let mut table = CredentialTable::<4>::new();
        let parent_credentials = LinuxCredentials::from_ids(1000, 1000);
        table.bind_process(&parent, parent_credentials).unwrap();
        table.set_no_new_privs(&parent, true).unwrap();
        table.inherit_child(&identities, &parent, &child).unwrap();
        assert_eq!(table.credentials(&child).unwrap(), parent_credentials);
        assert!(table.no_new_privs(&child).unwrap());
        assert_eq!(
            table.inherit_child(&identities, &parent, &unrelated),
            Err(Error::Identity(IdentityError::ProcessNotBound))
        );
    }

    #[test]
    fn exited_generation_can_retire_without_affecting_replacement_process() {
        let mut objects = ObjectTable::<8>::new();
        let mut first = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let first_id = first.id();
        let mut table = CredentialTable::<2>::new();
        table
            .bind_process(&first, LinuxCredentials::from_ids(7, 9))
            .unwrap();

        let bindings = ThreadObjectBindings::<0>::new();
        first.exit(&mut objects, &bindings).unwrap();
        assert_eq!(table.retire_process(&first).unwrap().ruid(), 7);

        let replacement = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        assert_ne!(replacement.id(), first_id);
        table
            .bind_process(&replacement, LinuxCredentials::root())
            .unwrap();
        assert_eq!(table.credentials(&replacement).unwrap().euid(), 0);
    }

    #[test]
    fn root_can_drop_privileges_and_unprivileged_cannot_escalate() {
        let mut objects = ObjectTable::<8>::new();
        let root_proc = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child_proc = Process::<4>::create_fork_child(&root_proc, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&root_proc, &child_proc).unwrap();

        let mut table = CredentialTable::<4>::new();
        table
            .bind_process(&root_proc, LinuxCredentials::root())
            .unwrap();
        table.set_groups(&root_proc, &[42, 100]).unwrap();
        assert_eq!(table.groups(&root_proc).unwrap(), &[42, 100]);

        table
            .update_credentials(&root_proc, |c| c.set_resuid(None, Some(100), None))
            .unwrap();
        let tmp = table.credentials(&root_proc).unwrap();
        assert_eq!(tmp.ruid(), 0);
        assert_eq!(tmp.euid(), 100);
        assert_eq!(tmp.suid(), 0);
        assert_eq!(tmp.fsuid(), 100);
        // Temporary drop cannot call set_groups while euid != 0, but can restore euid=0 via suid.
        assert_eq!(
            table.set_groups(&root_proc, &[1]),
            Err(Error::PermissionDenied)
        );
        table
            .update_credentials(&root_proc, |c| c.set_uid(0))
            .unwrap();
        assert_eq!(table.credentials(&root_proc).unwrap().euid(), 0);

        table
            .inherit_child(&identities, &root_proc, &child_proc)
            .unwrap();
        assert_eq!(table.groups(&child_proc).unwrap(), &[42, 100]);
        table
            .update_credentials(&child_proc, |c| {
                c.set_gid(65534)?;
                c.set_uid(100)
            })
            .unwrap();
        assert_eq!(
            table.update_credentials(&child_proc, |c| c.set_uid(0)),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            table.update_credentials(&child_proc, |c| c.set_resuid(None, Some(0), None)),
            Err(Error::PermissionDenied)
        );
    }
}
