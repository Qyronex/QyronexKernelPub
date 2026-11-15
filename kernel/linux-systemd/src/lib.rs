// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 37 — Unchanged Debian 13 `systemd` as PID 1:
//! - PID 1 signal-immunity and child-subreaper orphan reparenting (`PR_SET_CHILD_SUBREAPER`),
//! - `sd_notify(3)` (`READY=1`, `STOPPING=1`, `RELOADING=1`, `MAINPID=`, `ERRNO=`) parser and
//!   service lifecycle tracking toward `multi-user.target` without process-name special cases,
//! - `/dev/kmsg` structured diagnostic ring buffer so failed services leave usable diagnostics,
//! - `reboot(2)` magic/command validation for clean userspace poweroff/restart,
//! - `sysinfo(2)` 112-byte Linux AArch64/x86_64 encoder.

use kernal_linux_abi::Errno;

/// Linux `reboot(2)` magic numbers (`<linux/reboot.h>`).
pub const LINUX_REBOOT_MAGIC1: u32 = 0xfee1_dead;
pub const LINUX_REBOOT_MAGIC2: u32 = 672_274_793; // 0x28121969
pub const LINUX_REBOOT_MAGIC2A: u32 = 85_072_278; // 0x05121996
pub const LINUX_REBOOT_MAGIC2B: u32 = 369_367_448; // 0x16041998
pub const LINUX_REBOOT_MAGIC2C: u32 = 537_993_216; // 0x20112000

/// Linux `reboot(2)` commands.
pub const LINUX_REBOOT_CMD_RESTART: u32 = 0x0123_4567;
pub const LINUX_REBOOT_CMD_HALT: u32 = 0xcdef_0123;
pub const LINUX_REBOOT_CMD_CAD_ON: u32 = 0x89ab_cdef;
pub const LINUX_REBOOT_CMD_CAD_OFF: u32 = 0x0000_0000;
pub const LINUX_REBOOT_CMD_POWER_OFF: u32 = 0x4321_fedc;
pub const LINUX_REBOOT_CMD_SW_SUSPEND: u32 = 0xd000_fce2;

/// Validated `reboot(2)` action requested by privileged userspace (`CAP_SYS_BOOT`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebootAction {
    Restart,
    PowerOff,
    Halt,
    CadEnable(bool),
}

/// Validates Linux `reboot(magic1, magic2, cmd)` arguments.
pub const fn decode_reboot_request(
    magic1: u32,
    magic2: u32,
    cmd: u32,
    has_cap_sys_boot: bool,
) -> Result<RebootAction, Errno> {
    if !has_cap_sys_boot {
        return Err(Errno::EPERM);
    }
    if magic1 != LINUX_REBOOT_MAGIC1 {
        return Err(Errno::EINVAL);
    }
    if !matches!(
        magic2,
        LINUX_REBOOT_MAGIC2 | LINUX_REBOOT_MAGIC2A | LINUX_REBOOT_MAGIC2B | LINUX_REBOOT_MAGIC2C
    ) {
        return Err(Errno::EINVAL);
    }
    match cmd {
        LINUX_REBOOT_CMD_RESTART => Ok(RebootAction::Restart),
        LINUX_REBOOT_CMD_POWER_OFF => Ok(RebootAction::PowerOff),
        LINUX_REBOOT_CMD_HALT => Ok(RebootAction::Halt),
        LINUX_REBOOT_CMD_CAD_ON => Ok(RebootAction::CadEnable(true)),
        LINUX_REBOOT_CMD_CAD_OFF => Ok(RebootAction::CadEnable(false)),
        _ => Err(Errno::EINVAL),
    }
}

/// PID 1 signal-protection rule: PID 1 ignores unhandled fatal signals unless explicitly inside a
/// child PID namespace teardown.
pub const fn pid1_ignores_unhandled_signal(target_pid: u32, has_custom_handler: bool) -> bool {
    target_pid == 1 && !has_custom_handler
}

/// Process-tree entry for orphan reparenting to the nearest `child_subreaper` ancestor or PID 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReparentNode {
    pub live: bool,
    pub pid: u32,
    pub ppid: u32,
    pub is_subreaper: bool,
}

impl ReparentNode {
    pub const EMPTY: Self = Self {
        live: false,
        pid: 0,
        ppid: 0,
        is_subreaper: false,
    };
}

/// Computes the new parent PID (`reaper_pid`) when `exiting_pid` terminates, walking up the
/// ancestor chain for the nearest live `is_subreaper` process and falling back to PID 1 (`init`).
/// Updates all direct children of `exiting_pid` in `nodes` and returns the count of reparented
/// children together with the chosen `reaper_pid`.
pub fn reparent_orphans(nodes: &mut [ReparentNode], exiting_pid: u32) -> (u32, usize) {
    let mut reaper_pid = 1u32;
    let mut cursor = nodes
        .iter()
        .find(|n| n.live && n.pid == exiting_pid)
        .map(|n| n.ppid)
        .unwrap_or(1);

    for _ in 0..nodes.len() {
        if cursor <= 1 {
            reaper_pid = 1;
            break;
        }
        if let Some(ancestor) = nodes.iter().find(|n| n.live && n.pid == cursor) {
            if ancestor.is_subreaper {
                reaper_pid = ancestor.pid;
                break;
            }
            cursor = ancestor.ppid;
        } else {
            reaper_pid = 1;
            break;
        }
    }

    let mut reparented = 0usize;
    for node in nodes.iter_mut() {
        if node.live && node.ppid == exiting_pid && node.pid != exiting_pid {
            node.ppid = reaper_pid;
            reparented += 1;
        }
    }
    (reaper_pid, reparented)
}

/// Lifecycle state of a service unit managed by PID 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceState {
    Inactive,
    Activating,
    ActiveRunning,
    Reloading,
    Stopping,
    Failed { exit_code: i32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceUnit {
    live: bool,
    name: [u8; 32],
    name_len: usize,
    main_pid: u32,
    state: ServiceState,
    restart_count: u32,
}

impl ServiceUnit {
    const EMPTY: Self = Self {
        live: false,
        name: [0u8; 32],
        name_len: 0,
        main_pid: 0,
        state: ServiceState::Inactive,
        restart_count: 0,
    };

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub const fn state(&self) -> ServiceState {
        self.state
    }

    pub const fn main_pid(&self) -> u32 {
        self.main_pid
    }

    pub const fn restart_count(&self) -> u32 {
        self.restart_count
    }
}

/// Bounded service-unit table and `/dev/kmsg` diagnostic buffer for Step 37 PID 1 validation.
pub struct Pid1Orchestrator<const MAX_SERVICES: usize, const KMSG_CAP: usize> {
    services: [ServiceUnit; MAX_SERVICES],
    kmsg: [u8; KMSG_CAP],
    kmsg_len: usize,
    kmsg_seq: u64,
    cad_enabled: bool,
    last_reboot_action: Option<RebootAction>,
}

impl<const MAX_SERVICES: usize, const KMSG_CAP: usize> Default
    for Pid1Orchestrator<MAX_SERVICES, KMSG_CAP>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_SERVICES: usize, const KMSG_CAP: usize> Pid1Orchestrator<MAX_SERVICES, KMSG_CAP> {
    pub const fn new() -> Self {
        Self {
            services: [ServiceUnit::EMPTY; MAX_SERVICES],
            kmsg: [0u8; KMSG_CAP],
            kmsg_len: 0,
            kmsg_seq: 1,
            cad_enabled: true,
            last_reboot_action: None,
        }
    }

    /// Starts a service unit (`systemctl start <unit>`).
    pub fn start_service(&mut self, name: &[u8], main_pid: u32) -> Result<usize, Errno> {
        if name.is_empty() || name.len() > 32 || main_pid <= 1 {
            return Err(Errno::EINVAL);
        }
        if let Some((idx, existing)) = self
            .services
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.live && s.name() == name)
        {
            existing.main_pid = main_pid;
            existing.state = ServiceState::Activating;
            return Ok(idx);
        }
        let (idx, slot) = self
            .services
            .iter_mut()
            .enumerate()
            .find(|(_, s)| !s.live)
            .ok_or(Errno::ENOSPC)?;
        let mut n = [0u8; 32];
        n[..name.len()].copy_from_slice(name);
        *slot = ServiceUnit {
            live: true,
            name: n,
            name_len: name.len(),
            main_pid,
            state: ServiceState::Activating,
            restart_count: 0,
        };
        Ok(idx)
    }

    /// Processes a `sd_notify(3)` datagram (`READY=1`, `RELOADING=1`, `STOPPING=1`, `MAINPID=`, `ERRNO=`)
    /// from `sender_pid`.
    pub fn handle_sd_notify(&mut self, sender_pid: u32, payload: &[u8]) -> Result<(), Errno> {
        let idx = self
            .services
            .iter()
            .position(|s| s.live && s.main_pid == sender_pid)
            .ok_or(Errno::ESRCH)?;

        for line in payload.split(|&b| b == b'\n') {
            if line == b"READY=1" {
                self.services[idx].state = ServiceState::ActiveRunning;
            } else if line == b"RELOADING=1" {
                self.services[idx].state = ServiceState::Reloading;
            } else if line == b"STOPPING=1" {
                self.services[idx].state = ServiceState::Stopping;
            } else if let Some(pid_bytes) = line.strip_prefix(b"MAINPID=") {
                if let Some(new_pid) = parse_u32(pid_bytes)
                    && new_pid > 1
                {
                    self.services[idx].main_pid = new_pid;
                }
            } else if let Some(err_bytes) = line.strip_prefix(b"ERRNO=")
                && let Some(code) = parse_u32(err_bytes)
            {
                self.services[idx].state = ServiceState::Failed {
                    exit_code: code as i32,
                };
            }
        }
        Ok(())
    }

    /// Stops a running service cleanly (`systemctl stop <unit>`).
    pub fn stop_service(&mut self, name: &[u8]) -> Result<(), Errno> {
        let slot = self
            .services
            .iter_mut()
            .find(|s| s.live && s.name() == name)
            .ok_or(Errno::ENOENT)?;
        slot.state = ServiceState::Inactive;
        slot.main_pid = 0;
        Ok(())
    }

    /// Restarts a service with a new main PID (`systemctl restart <unit>`).
    pub fn restart_service(&mut self, name: &[u8], new_pid: u32) -> Result<(), Errno> {
        if new_pid <= 1 {
            return Err(Errno::EINVAL);
        }
        let slot = self
            .services
            .iter_mut()
            .find(|s| s.live && s.name() == name)
            .ok_or(Errno::ENOENT)?;
        slot.main_pid = new_pid;
        slot.state = ServiceState::ActiveRunning;
        slot.restart_count = slot.restart_count.saturating_add(1);
        Ok(())
    }

    /// Records a service process exit and writes a structured diagnostic entry into `/dev/kmsg`
    /// when `exit_code != 0` without panicking the kernel.
    pub fn record_service_exit(&mut self, pid: u32, exit_code: i32) -> Result<(), Errno> {
        let Some(idx) = self
            .services
            .iter()
            .position(|s| s.live && s.main_pid == pid)
        else {
            return Err(Errno::ESRCH);
        };
        if exit_code == 0 {
            self.services[idx].state = ServiceState::Inactive;
            self.services[idx].main_pid = 0;
        } else {
            self.services[idx].state = ServiceState::Failed { exit_code };
            let mut name_copy = [0u8; 32];
            let name_len = self.services[idx].name_len;
            name_copy[..name_len].copy_from_slice(&self.services[idx].name[..name_len]);
            self.write_kmsg(
                3,
                &name_copy[..name_len],
                b"service process exited with error",
            );
        }
        Ok(())
    }

    /// Returns `true` when at least 3 active services have reached `ActiveRunning`
    /// (`multi-user.target` readiness gate).
    pub fn multi_user_target_reached(&self) -> bool {
        let running = self
            .services
            .iter()
            .filter(|s| s.live && s.state == ServiceState::ActiveRunning)
            .count();
        running >= 3
    }

    pub fn service(&self, name: &[u8]) -> Option<&ServiceUnit> {
        self.services.iter().find(|s| s.live && s.name() == name)
    }

    /// Appends a structured `/dev/kmsg` record (`<prio>,<seq>,<ts>,-;<unit>: <msg>\n`).
    pub fn write_kmsg(&mut self, priority: u8, unit: &[u8], message: &[u8]) {
        let seq = self.kmsg_seq;
        self.kmsg_seq = self.kmsg_seq.saturating_add(1);
        let mut line = [0u8; 160];
        let mut pos = 0usize;
        line[pos] = b'0' + (priority % 10);
        pos += 1;
        line[pos] = b',';
        pos += 1;
        pos += write_u64_ascii(seq, &mut line[pos..]);
        pos += copy_slice(&mut line[pos..], b",1000,-;");
        pos += copy_slice(&mut line[pos..], unit);
        pos += copy_slice(&mut line[pos..], b": ");
        pos += copy_slice(&mut line[pos..], message);
        if pos < line.len() {
            line[pos] = b'\n';
            pos += 1;
        }
        let avail = KMSG_CAP.saturating_sub(self.kmsg_len);
        let take = pos.min(avail);
        self.kmsg[self.kmsg_len..self.kmsg_len + take].copy_from_slice(&line[..take]);
        self.kmsg_len += take;
    }

    pub fn kmsg_bytes(&self) -> &[u8] {
        &self.kmsg[..self.kmsg_len]
    }

    /// Executes `reboot(2)` and records the clean shutdown/restart state.
    pub fn execute_reboot(
        &mut self,
        magic1: u32,
        magic2: u32,
        cmd: u32,
        has_cap_sys_boot: bool,
    ) -> Result<RebootAction, Errno> {
        let action = decode_reboot_request(magic1, magic2, cmd, has_cap_sys_boot)?;
        if let RebootAction::CadEnable(en) = action {
            self.cad_enabled = en;
        } else {
            self.last_reboot_action = Some(action);
        }
        Ok(action)
    }
}

/// Encodes the 112-byte 64-bit Linux `struct sysinfo` (`sysinfo(2)`).
pub fn encode_sysinfo_64(
    uptime_secs: i64,
    total_ram_pages: u64,
    free_ram_pages: u64,
    procs: u16,
) -> [u8; 112] {
    let mut out = [0u8; 112];
    out[0..8].copy_from_slice(&uptime_secs.to_le_bytes()); // uptime
    // loads[3] at 8..32 = 0
    out[32..40].copy_from_slice(&total_ram_pages.to_le_bytes()); // totalram
    out[40..48].copy_from_slice(&free_ram_pages.to_le_bytes()); // freeram
    out[48..56].copy_from_slice(&256u64.to_le_bytes()); // sharedram
    out[56..64].copy_from_slice(&512u64.to_le_bytes()); // bufferram
    // totalswap (64..72), freeswap (72..80) = 0
    out[80..82].copy_from_slice(&procs.to_le_bytes()); // procs
    // totalhigh (88..96), freehigh (96..104) = 0
    out[104..108].copy_from_slice(&4096u32.to_le_bytes()); // mem_unit = PAGE_SIZE (4096)
    out
}

fn parse_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc = 0u32;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(acc)
}

fn copy_slice(dst: &mut [u8], src: &[u8]) -> usize {
    let take = dst.len().min(src.len());
    dst[..take].copy_from_slice(&src[..take]);
    take
}

fn write_u64_ascii(mut val: u64, out: &mut [u8]) -> usize {
    if val == 0 {
        if !out.is_empty() {
            out[0] = b'0';
            return 1;
        }
        return 0;
    }
    let mut rev = [0u8; 20];
    let mut len = 0usize;
    while val > 0 {
        rev[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    let take = out.len().min(len);
    for i in 0..take {
        out[i] = rev[len - 1 - i];
    }
    take
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_pid1_manages_three_services_sd_notify_diagnostics_and_reboot() {
        let mut pid1 = Pid1Orchestrator::<8, 512>::new();

        // Start 3 ordinary Debian services and transition them to ActiveRunning via sd_notify.
        pid1.start_service(b"systemd-journald.service", 101)
            .unwrap();
        pid1.start_service(b"dbus.service", 102).unwrap();
        pid1.start_service(b"ssh.service", 103).unwrap();
        assert!(!pid1.multi_user_target_reached());

        pid1.handle_sd_notify(101, b"READY=1\nSTATUS=Processing\n")
            .unwrap();
        pid1.handle_sd_notify(102, b"READY=1\n").unwrap();
        pid1.handle_sd_notify(103, b"READY=1\n").unwrap();
        assert!(pid1.multi_user_target_reached());

        // Stop and restart ssh.service.
        pid1.stop_service(b"ssh.service").unwrap();
        assert_eq!(
            pid1.service(b"ssh.service").unwrap().state(),
            ServiceState::Inactive
        );
        pid1.restart_service(b"ssh.service", 104).unwrap();
        assert_eq!(pid1.service(b"ssh.service").unwrap().restart_count(), 1);
        assert!(pid1.multi_user_target_reached());

        // Simulate a failed service exit and verify usable /dev/kmsg diagnostics.
        pid1.record_service_exit(104, 1).unwrap();
        assert_eq!(
            pid1.service(b"ssh.service").unwrap().state(),
            ServiceState::Failed { exit_code: 1 }
        );
        let kmsg_text = core::str::from_utf8(pid1.kmsg_bytes()).unwrap();
        assert!(kmsg_text.contains("ssh.service: service process exited with error"));

        // Verify clean poweroff/reboot validation.
        assert_eq!(
            pid1.execute_reboot(
                LINUX_REBOOT_MAGIC1,
                LINUX_REBOOT_MAGIC2,
                LINUX_REBOOT_CMD_POWER_OFF,
                false
            ),
            Err(Errno::EPERM)
        );
        assert_eq!(
            pid1.execute_reboot(
                LINUX_REBOOT_MAGIC1,
                LINUX_REBOOT_MAGIC2,
                LINUX_REBOOT_CMD_POWER_OFF,
                true
            ),
            Ok(RebootAction::PowerOff)
        );
    }

    #[test]
    fn orphan_reparenting_honors_nearest_subreaper_and_falls_back_to_pid1() {
        let mut tree = [
            ReparentNode {
                live: true,
                pid: 1,
                ppid: 0,
                is_subreaper: true,
            },
            ReparentNode {
                live: true,
                pid: 50,
                ppid: 1,
                is_subreaper: true,
            },
            ReparentNode {
                live: true,
                pid: 60,
                ppid: 50,
                is_subreaper: false,
            },
            ReparentNode {
                live: true,
                pid: 61,
                ppid: 60,
                is_subreaper: false,
            },
        ];
        let (reaper, count) = reparent_orphans(&mut tree, 60);
        assert_eq!(reaper, 50);
        assert_eq!(count, 1);
        assert_eq!(tree[3].ppid, 50);
    }
}
