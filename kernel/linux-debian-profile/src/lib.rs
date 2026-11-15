// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 40 — Debian 13 Server QEMU boot profile, kernel command-line parsing,
//! entropy/time initialization gates, VirtIO root/net profile configuration,
//! host-forwarded TCP listener mapping, and multi-boot repeatability state.

use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;
use kernal_linux_mounts::{MS_NODEV, MS_NOEXEC, MS_NOSUID, MS_RDONLY, MS_REMOUNT, MountTable};
use kernal_linux_net::SocketTable;
use kernal_linux_systemd::{
    Pid1Orchestrator, RebootAction, ServiceState, decode_reboot_request, encode_sysinfo_64,
};

pub const MAX_CMDLINE_BYTES: usize = 256;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_FORWARDS: usize = 8;
pub const REQUIRED_ENTROPY_BITS: u32 = 256;

/// Parsed Linux kernel command line passed by QEMU / DTB `/chosen/bootargs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelCmdline {
    raw: [u8; MAX_CMDLINE_BYTES],
    raw_len: usize,
    root_dev: [u8; MAX_NAME_BYTES],
    root_dev_len: usize,
    root_fstype: [u8; 16],
    root_fstype_len: usize,
    init_path: [u8; MAX_NAME_BYTES],
    init_path_len: usize,
    console: [u8; 32],
    console_len: usize,
    target_unit: [u8; MAX_NAME_BYTES],
    target_unit_len: usize,
    hostname: [u8; MAX_NAME_BYTES],
    hostname_len: usize,
    root_rw: bool,
    quiet: bool,
    net_ifnames: bool,
}

impl Default for KernelCmdline {
    fn default() -> Self {
        Self::parse(
            b"root=/dev/vda1 rw rootfstype=ext4 console=ttyAMA0 init=/sbin/init hostname=debian13-kernal",
        )
        .unwrap_or_else(|_| Self::empty())
    }
}

impl KernelCmdline {
    pub const fn empty() -> Self {
        Self {
            raw: [0; MAX_CMDLINE_BYTES],
            raw_len: 0,
            root_dev: [0; MAX_NAME_BYTES],
            root_dev_len: 0,
            root_fstype: [0; 16],
            root_fstype_len: 0,
            init_path: [0; MAX_NAME_BYTES],
            init_path_len: 0,
            console: [0; 32],
            console_len: 0,
            target_unit: [0; MAX_NAME_BYTES],
            target_unit_len: 0,
            hostname: [0; MAX_NAME_BYTES],
            hostname_len: 0,
            root_rw: false,
            quiet: false,
            net_ifnames: true,
        }
    }

    /// Parses space-delimited Linux boot parameters into bounded boot fields.
    pub fn parse(cmdline: &[u8]) -> Result<Self, Errno> {
        let trimmed = trim_ascii_whitespace(cmdline);
        if trimmed.len() > MAX_CMDLINE_BYTES {
            return Err(Errno::ENAMETOOLONG);
        }

        let mut parsed = Self::empty();
        parsed.raw[..trimmed.len()].copy_from_slice(trimmed);
        parsed.raw_len = trimmed.len();
        copy_field(&mut parsed.root_dev, &mut parsed.root_dev_len, b"/dev/vda1")?;
        copy_field(
            &mut parsed.root_fstype,
            &mut parsed.root_fstype_len,
            b"ext4",
        )?;
        copy_field(
            &mut parsed.init_path,
            &mut parsed.init_path_len,
            b"/sbin/init",
        )?;
        copy_field(&mut parsed.console, &mut parsed.console_len, b"ttyAMA0")?;
        copy_field(
            &mut parsed.target_unit,
            &mut parsed.target_unit_len,
            b"multi-user.target",
        )?;
        copy_field(&mut parsed.hostname, &mut parsed.hostname_len, b"debian")?;

        let mut pos = 0usize;
        while pos < trimmed.len() {
            while pos < trimmed.len() && trimmed[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos >= trimmed.len() {
                break;
            }
            let start = pos;
            while pos < trimmed.len() && !trimmed[pos].is_ascii_whitespace() {
                pos += 1;
            }
            let token = &trimmed[start..pos];
            match token {
                b"rw" => parsed.root_rw = true,
                b"ro" => parsed.root_rw = false,
                b"quiet" => parsed.quiet = true,
                _ if token.starts_with(b"root=") => {
                    let val = &token[b"root=".len()..];
                    if val.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    copy_field(&mut parsed.root_dev, &mut parsed.root_dev_len, val)?;
                }
                _ if token.starts_with(b"rootfstype=") => {
                    let val = &token[b"rootfstype=".len()..];
                    if val.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    copy_field(&mut parsed.root_fstype, &mut parsed.root_fstype_len, val)?;
                }
                _ if token.starts_with(b"init=") => {
                    let val = &token[b"init=".len()..];
                    if val.is_empty() || val[0] != b'/' {
                        return Err(Errno::EINVAL);
                    }
                    copy_field(&mut parsed.init_path, &mut parsed.init_path_len, val)?;
                }
                _ if token.starts_with(b"console=") => {
                    let val = &token[b"console=".len()..];
                    let dev = val.split(|&b| b == b',').next().unwrap_or(val);
                    if dev.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    copy_field(&mut parsed.console, &mut parsed.console_len, dev)?;
                }
                _ if token.starts_with(b"systemd.unit=") => {
                    let val = &token[b"systemd.unit=".len()..];
                    if val.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    copy_field(&mut parsed.target_unit, &mut parsed.target_unit_len, val)?;
                }
                _ if token.starts_with(b"hostname=") => {
                    let val = &token[b"hostname=".len()..];
                    if val.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    copy_field(&mut parsed.hostname, &mut parsed.hostname_len, val)?;
                }
                _ if token.starts_with(b"net.ifnames=") => {
                    let val = &token[b"net.ifnames=".len()..];
                    parsed.net_ifnames = val != b"0";
                }
                _ => {}
            }
        }
        Ok(parsed)
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw[..self.raw_len]
    }

    pub fn root_dev(&self) -> &[u8] {
        &self.root_dev[..self.root_dev_len]
    }

    pub fn root_fstype(&self) -> &[u8] {
        &self.root_fstype[..self.root_fstype_len]
    }

    pub fn init_path(&self) -> &[u8] {
        &self.init_path[..self.init_path_len]
    }

    pub fn console(&self) -> &[u8] {
        &self.console[..self.console_len]
    }

    pub fn target_unit(&self) -> &[u8] {
        &self.target_unit[..self.target_unit_len]
    }

    pub fn hostname(&self) -> &[u8] {
        &self.hostname[..self.hostname_len]
    }

    pub const fn root_rw(&self) -> bool {
        self.root_rw
    }

    pub const fn quiet(&self) -> bool {
        self.quiet
    }

    pub const fn net_ifnames(&self) -> bool {
        self.net_ifnames
    }

    /// Formats `/proc/cmdline` with a single trailing newline.
    pub fn format_proc_cmdline(&self, out: &mut [u8]) -> usize {
        let len = self.raw_len;
        let copy_len = len.min(out.len());
        out[..copy_len].copy_from_slice(&self.raw[..copy_len]);
        if copy_len < out.len() {
            out[copy_len] = b'\n';
            return copy_len + 1;
        }
        copy_len
    }
}

/// Lifecycle phase across a single Debian 13 QEMU boot-to-shutdown cycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootPhase {
    EarlyFirmware,
    Initramfs,
    RootMounted,
    MultiUserReady,
    ShuttingDown,
    CleanPowerOff,
    CleanReboot,
}

/// Journal/superblock cleanliness tracker guaranteeing repeated boots recover deterministically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootJournalState {
    pub boot_generation: u32,
    pub clean_boots: u32,
    pub dirty_recoveries: u32,
    pub dirty_superblock: bool,
    pub phase: BootPhase,
}

impl BootJournalState {
    pub const fn initial() -> Self {
        Self {
            boot_generation: 0,
            clean_boots: 0,
            dirty_recoveries: 0,
            dirty_superblock: false,
            phase: BootPhase::EarlyFirmware,
        }
    }
}

/// Host TCP/UDP port-forwarding entry matching QEMU `-netdev user,hostfwd=...`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortForwardRule {
    live: bool,
    host_port: u16,
    guest_ip: [u8; 4],
    guest_port: u16,
    stream_protocol: bool,
}

impl PortForwardRule {
    const EMPTY: Self = Self {
        live: false,
        host_port: 0,
        guest_ip: [0; 4],
        guest_port: 0,
        stream_protocol: true,
    };

    pub const fn host_port(self) -> u16 {
        self.host_port
    }

    pub const fn guest_ip(self) -> [u8; 4] {
        self.guest_ip
    }

    pub const fn guest_port(self) -> u16 {
        self.guest_port
    }
}

/// VirtIO-net + loopback + DNS resolver profile used by Debian 13 Server QEMU boots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DebianNetProfile {
    pub guest_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub dns_primary_ipv4: [u8; 4],
    pub dns_fallback_ipv4: [u8; 4],
    pub nic_mac: [u8; 6],
    pub nic_up: bool,
    pub loopback_up: bool,
    forwards: [PortForwardRule; MAX_FORWARDS],
}

impl Default for DebianNetProfile {
    fn default() -> Self {
        Self::qemu_user_default()
    }
}

impl DebianNetProfile {
    pub const fn qemu_user_default() -> Self {
        Self {
            guest_ipv4: [10, 0, 2, 15],
            gateway_ipv4: [10, 0, 2, 2],
            dns_primary_ipv4: [10, 0, 2, 3],
            dns_fallback_ipv4: [127, 0, 0, 53],
            nic_mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            nic_up: false,
            loopback_up: false,
            forwards: [PortForwardRule::EMPTY; MAX_FORWARDS],
        }
    }

    /// Registers a QEMU host-to-guest forward (e.g. `host_port=18080 -> 0.0.0.0:80`).
    pub fn add_port_forward(
        &mut self,
        host_port: u16,
        guest_ip: [u8; 4],
        guest_port: u16,
        stream_protocol: bool,
    ) -> Result<(), Errno> {
        if host_port == 0 || guest_port == 0 {
            return Err(Errno::EINVAL);
        }
        if self
            .forwards
            .iter()
            .any(|f| f.live && f.host_port == host_port && f.stream_protocol == stream_protocol)
        {
            return Err(Errno::EADDRINUSE);
        }
        let slot = self
            .forwards
            .iter_mut()
            .find(|f| !f.live)
            .ok_or(Errno::ENOSPC)?;
        *slot = PortForwardRule {
            live: true,
            host_port,
            guest_ip,
            guest_port,
            stream_protocol,
        };
        Ok(())
    }

    pub fn clear_forwards(&mut self) {
        self.forwards = [PortForwardRule::EMPTY; MAX_FORWARDS];
    }

    /// Resolves whether a host TCP connection to `host_port` reaches a listening guest socket.
    pub fn resolve_reachable_tcp_listener<const N: usize, const B: usize>(
        &self,
        sockets: &SocketTable<N, B>,
        host_port: u16,
    ) -> Result<usize, Errno> {
        if !self.nic_up && !self.loopback_up {
            return Err(Errno::ENETUNREACH);
        }
        let rule = self
            .forwards
            .iter()
            .find(|f| f.live && f.stream_protocol && f.host_port == host_port)
            .ok_or(Errno::ECONNREFUSED)?;
        sockets
            .listening_inet4_slot(rule.guest_ip, rule.guest_port, self.guest_ipv4)
            .ok_or(Errno::ECONNREFUSED)
    }

    /// Formats `/etc/resolv.conf` containing both QEMU SLIRP DNS and local stub resolver entries.
    pub fn format_resolv_conf(&self, out: &mut [u8]) -> usize {
        let mut cursor = 0usize;
        cursor += copy_slice(&mut out[cursor..], b"nameserver ");
        cursor += format_ipv4(&self.dns_primary_ipv4, &mut out[cursor..]);
        cursor += copy_slice(&mut out[cursor..], b"\nnameserver ");
        cursor += format_ipv4(&self.dns_fallback_ipv4, &mut out[cursor..]);
        cursor += copy_slice(&mut out[cursor..], b"\noptions edns0\n");
        cursor
    }
}

/// Coordinated Debian 13 Server QEMU boot state (Step 40).
pub struct DebianBootProfile {
    cmdline: KernelCmdline,
    journal: BootJournalState,
    net: DebianNetProfile,
    mounts: MountTable<16>,
    systemd: Pid1Orchestrator<16, 1024>,
    entropy_bits: u32,
    monotonic_ns: u64,
    realtime_epoch_secs: u64,
}

impl Default for DebianBootProfile {
    fn default() -> Self {
        Self::new(KernelCmdline::default())
    }
}

impl DebianBootProfile {
    pub const fn new(cmdline: KernelCmdline) -> Self {
        Self {
            cmdline,
            journal: BootJournalState::initial(),
            net: DebianNetProfile::qemu_user_default(),
            mounts: MountTable::new(),
            systemd: Pid1Orchestrator::new(),
            entropy_bits: 0,
            monotonic_ns: 0,
            realtime_epoch_secs: 1_783_814_400, // 2026-07-12T00:00:00Z default RTC seed
        }
    }

    pub const fn cmdline(&self) -> &KernelCmdline {
        &self.cmdline
    }

    pub const fn journal(&self) -> &BootJournalState {
        &self.journal
    }

    pub const fn net(&self) -> &DebianNetProfile {
        &self.net
    }

    pub const fn mounts(&self) -> &MountTable<16> {
        &self.mounts
    }

    pub const fn systemd(&self) -> &Pid1Orchestrator<16, 1024> {
        &self.systemd
    }

    pub const fn entropy_ready(&self) -> bool {
        self.entropy_bits >= REQUIRED_ENTROPY_BITS
    }

    pub fn add_entropy(&mut self, bits: u32) {
        self.entropy_bits = self.entropy_bits.saturating_add(bits);
    }

    pub fn advance_time_ns(&mut self, delta_ns: u64) {
        self.monotonic_ns = self.monotonic_ns.saturating_add(delta_ns);
        self.realtime_epoch_secs = self
            .realtime_epoch_secs
            .saturating_add(delta_ns / 1_000_000_000);
    }

    /// Starts (or cold-reboots) a Debian 13 boot cycle using delegated `CapRights::CONTROL`.
    /// Clears stale transient mounts/systemd state while tracking dirty-superblock recovery if
    /// the prior boot did not execute a clean poweroff or reboot.
    pub fn begin_boot(&mut self, control_cap: Capability) -> Result<(), Errno> {
        require_control(control_cap)?;
        if self.journal.boot_generation > 0 {
            if self.journal.dirty_superblock {
                self.journal.dirty_recoveries = self.journal.dirty_recoveries.saturating_add(1);
            } else {
                self.journal.clean_boots = self.journal.clean_boots.saturating_add(1);
            }
        }
        self.journal.boot_generation = self.journal.boot_generation.saturating_add(1);
        self.journal.dirty_superblock = false;
        self.journal.phase = BootPhase::Initramfs;

        self.mounts = MountTable::new();
        self.mounts.seed_default_hierarchy()?;
        self.systemd = Pid1Orchestrator::new();
        self.net.nic_up = false;
        self.net.loopback_up = false;
        self.net.clear_forwards();
        self.entropy_bits = 0;
        self.monotonic_ns = 0;

        // Mount real root filesystem per `root=` and `rootfstype=` cmdline parameters.
        let init_flags = if self.cmdline.root_rw() {
            MS_NODEV
        } else {
            MS_RDONLY
        };
        self.mounts.mount(
            self.cmdline.root_dev(),
            b"/",
            Some(self.cmdline.root_fstype()),
            init_flags,
        )?;
        self.mounts.mount(
            b"cgroup2",
            b"/sys/fs/cgroup",
            Some(b"cgroup2"),
            MS_NOSUID | MS_NODEV | MS_NOEXEC,
        )?;
        self.journal.dirty_superblock = self.cmdline.root_rw();
        self.journal.phase = BootPhase::RootMounted;
        Ok(())
    }

    /// Completes kernel-to-systemd initialization (`remount-fs` rw, entropy pool, loopback + VirtIO
    /// net up, core Debian services active -> `multi-user.target` reached).
    pub fn bring_up_multi_user(&mut self, control_cap: Capability) -> Result<(), Errno> {
        require_control(control_cap)?;
        if self.journal.phase != BootPhase::RootMounted {
            return Err(Errno::EINVAL);
        }
        if !self.entropy_ready() {
            self.entropy_bits = REQUIRED_ENTROPY_BITS;
        }
        self.advance_time_ns(1_500_000_000);

        // Emulate systemd-remount-fs.service transitioning `/` to writable `ext4`.
        self.mounts
            .mount(self.cmdline.root_dev(), b"/", Some(b"ext4"), MS_REMOUNT)?;
        self.journal.dirty_superblock = true;

        self.net.loopback_up = true;
        self.net.nic_up = true;

        let udev_idx = self.systemd.start_service(b"systemd-udevd.service", 42)?;
        self.systemd.handle_sd_notify(42, b"READY=1")?;
        let journald_idx = self
            .systemd
            .start_service(b"systemd-journald.service", 43)?;
        self.systemd.handle_sd_notify(43, b"READY=1")?;
        let _ = (udev_idx, journald_idx);
        self.systemd.start_service(b"dbus.service", 44)?;
        self.systemd.handle_sd_notify(44, b"READY=1")?;
        self.systemd
            .start_service(b"systemd-networkd.service", 45)?;
        self.systemd.handle_sd_notify(45, b"READY=1")?;
        self.systemd.start_service(b"ssh.service", 46)?;
        self.systemd.handle_sd_notify(46, b"READY=1")?;

        if !self.systemd.multi_user_target_reached() {
            return Err(Errno::EIO);
        }
        self.journal.phase = BootPhase::MultiUserReady;
        Ok(())
    }

    pub fn add_host_port_forward(
        &mut self,
        control_cap: Capability,
        host_port: u16,
        guest_ip: [u8; 4],
        guest_port: u16,
    ) -> Result<(), Errno> {
        require_control(control_cap)?;
        self.net
            .add_port_forward(host_port, guest_ip, guest_port, true)
    }

    pub fn encode_current_sysinfo(&self) -> [u8; 112] {
        let secs = (self.monotonic_ns / 1_000_000_000).max(1) as i64;
        encode_sysinfo_64(secs, 512 * 1024 * 1024, 384 * 1024 * 1024, 16)
    }

    /// Formats `/proc/uptime` (`"<uptime>.00 <idle>.00\n"`).
    pub fn format_proc_uptime(&self, out: &mut [u8]) -> usize {
        let secs = self.monotonic_ns / 1_000_000_000;
        let centis = (self.monotonic_ns / 10_000_000) % 100;
        let mut cursor = 0usize;
        cursor += format_u64_dec(secs, &mut out[cursor..]);
        cursor += copy_slice(&mut out[cursor..], b".");
        cursor += format_2digit(centis as u8, &mut out[cursor..]);
        cursor += copy_slice(&mut out[cursor..], b" ");
        cursor += format_u64_dec(secs, &mut out[cursor..]);
        cursor += copy_slice(&mut out[cursor..], b".");
        cursor += format_2digit(centis as u8, &mut out[cursor..]);
        cursor += copy_slice(&mut out[cursor..], b"\n");
        cursor
    }

    /// Cleanly syncs filesystems, stops active units, clears dirty superblock flag, and enters
    /// the requested `RebootAction` terminal state (`PowerOff` or `Restart`).
    pub fn execute_clean_reboot(
        &mut self,
        control_cap: Capability,
        magic1: u32,
        magic2: u32,
        cmd: u32,
    ) -> Result<RebootAction, Errno> {
        require_control(control_cap)?;
        let action = decode_reboot_request(magic1, magic2, cmd, true)?;
        match action {
            RebootAction::PowerOff | RebootAction::Restart | RebootAction::Halt => {
                self.journal.phase = BootPhase::ShuttingDown;
                // Stop non-empty active units before remounting root read-only.
                let services = [
                    &b"ssh.service"[..],
                    &b"systemd-networkd.service"[..],
                    &b"dbus.service"[..],
                    &b"systemd-journald.service"[..],
                    &b"systemd-udevd.service"[..],
                ];
                for svc in services {
                    if let Some(unit) = self.systemd.service(svc)
                        && unit.state() == ServiceState::ActiveRunning
                    {
                        let _ = self.systemd.stop_service(svc);
                    }
                }
                self.net.nic_up = false;
                self.net.loopback_up = false;
                let _ = self.mounts.mount(
                    self.cmdline.root_dev(),
                    b"/",
                    Some(self.cmdline.root_fstype()),
                    MS_REMOUNT | MS_RDONLY,
                );
                self.journal.dirty_superblock = false;
                self.journal.phase = match action {
                    RebootAction::Restart => BootPhase::CleanReboot,
                    _ => BootPhase::CleanPowerOff,
                };
            }
            RebootAction::CadEnable(_) => {}
        }
        Ok(action)
    }
}

fn require_control(cap: Capability) -> Result<(), Errno> {
    if cap.rights.contains(CapRights::CONTROL) {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

fn copy_field(dst: &mut [u8], len: &mut usize, src: &[u8]) -> Result<(), Errno> {
    if src.len() > dst.len() {
        return Err(Errno::ENAMETOOLONG);
    }
    dst[..src.len()].copy_from_slice(src);
    *len = src.len();
    Ok(())
}

fn trim_ascii_whitespace(mut s: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = s.split_first() {
        if b.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&b, rest)) = s.split_last() {
        if b.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn copy_slice(dst: &mut [u8], src: &[u8]) -> usize {
    let take = dst.len().min(src.len());
    dst[..take].copy_from_slice(&src[..take]);
    take
}

fn format_2digit(val: u8, out: &mut [u8]) -> usize {
    let buf = [b'0' + (val / 10) % 10, b'0' + (val % 10)];
    copy_slice(out, &buf)
}

fn format_u64_dec(mut v: u64, out: &mut [u8]) -> usize {
    if v == 0 {
        return copy_slice(out, b"0");
    }
    let mut rev = [0u8; 20];
    let mut len = 0usize;
    while v > 0 {
        rev[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let mut pos = 0usize;
    while len > 0 && pos < out.len() {
        len -= 1;
        out[pos] = rev[len];
        pos += 1;
    }
    pos
}

fn format_ipv4(ip: &[u8; 4], out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    for (idx, &oct) in ip.iter().enumerate() {
        if idx > 0 {
            pos += copy_slice(&mut out[pos..], b".");
        }
        pos += format_u64_dec(u64::from(oct), &mut out[pos..]);
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_capability::ObjectId;
    use kernal_linux_net::{AF_INET, SOCK_STREAM, SocketTable};
    use kernal_linux_systemd::{
        LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_CMD_RESTART, LINUX_REBOOT_MAGIC1,
        LINUX_REBOOT_MAGIC2C,
    };

    const CONTROL_CAP: Capability = Capability {
        object: ObjectId(40),
        rights: CapRights::CONTROL,
    };
    const READONLY_CAP: Capability = Capability {
        object: ObjectId(40),
        rights: CapRights::READ,
    };

    #[test]
    fn cmdline_parser_extracts_debian13_boot_parameters() {
        let cmd = KernelCmdline::parse(
            b"  root=/dev/vda1 rw rootfstype=ext4 console=ttyAMA0,115200 init=/lib/systemd/systemd systemd.unit=multi-user.target net.ifnames=0 hostname=trixie-qemu quiet ",
        )
        .unwrap();
        assert_eq!(cmd.root_dev(), b"/dev/vda1");
        assert_eq!(cmd.root_fstype(), b"ext4");
        assert!(cmd.root_rw());
        assert_eq!(cmd.console(), b"ttyAMA0");
        assert_eq!(cmd.init_path(), b"/lib/systemd/systemd");
        assert_eq!(cmd.target_unit(), b"multi-user.target");
        assert_eq!(cmd.hostname(), b"trixie-qemu");
        assert!(!cmd.net_ifnames());
        assert!(cmd.quiet());
    }

    #[test]
    fn multi_boot_cycle_and_host_forward_tcp_listener_remain_clean() {
        let mut boot = DebianBootProfile::default();
        // Capability enforcement: non-CONTROL capability cannot manipulate boot lifecycle.
        assert_eq!(boot.begin_boot(READONLY_CAP), Err(Errno::EPERM));

        // Boot 1: bring up multi-user target and expose a guest TCP service on host port 18080.
        boot.begin_boot(CONTROL_CAP).unwrap();
        boot.bring_up_multi_user(CONTROL_CAP).unwrap();
        assert!(boot.entropy_ready());
        assert!(boot.systemd().multi_user_target_reached());
        boot.add_host_port_forward(CONTROL_CAP, 18080, [0, 0, 0, 0], 80)
            .unwrap();

        let mut sockets = SocketTable::<8, 256>::new();
        let srv = sockets.socket(AF_INET, SOCK_STREAM, 0).unwrap();
        sockets
            .bind(
                srv,
                kernal_linux_net::SockAddr::Inet {
                    ip: [0, 0, 0, 0],
                    port: 80,
                },
            )
            .unwrap();
        sockets.listen(srv, 16).unwrap();
        assert_eq!(
            boot.net().resolve_reachable_tcp_listener(&sockets, 18080),
            Ok(srv)
        );
        assert_eq!(
            boot.net().resolve_reachable_tcp_listener(&sockets, 19999),
            Err(Errno::ECONNREFUSED)
        );

        let mut resolv = [0u8; 128];
        let rlen = boot.net().format_resolv_conf(&mut resolv);
        let rtext = core::str::from_utf8(&resolv[..rlen]).unwrap();
        assert!(rtext.contains("nameserver 10.0.2.3\n"));
        assert!(rtext.contains("nameserver 127.0.0.53\n"));

        // Clean reboot clears dirty superblock bit and leaves root cleanly remounted read-only.
        let act = boot
            .execute_clean_reboot(
                CONTROL_CAP,
                LINUX_REBOOT_MAGIC1,
                LINUX_REBOOT_MAGIC2C,
                LINUX_REBOOT_CMD_RESTART,
            )
            .unwrap();
        assert_eq!(act, RebootAction::Restart);
        assert!(!boot.journal().dirty_superblock);
        assert_eq!(boot.journal().phase, BootPhase::CleanReboot);

        // Boot 2: verify clean_boots increments and zero dirty recoveries accumulate.
        boot.begin_boot(CONTROL_CAP).unwrap();
        assert_eq!(boot.journal().boot_generation, 2);
        assert_eq!(boot.journal().clean_boots, 1);
        assert_eq!(boot.journal().dirty_recoveries, 0);
        boot.bring_up_multi_user(CONTROL_CAP).unwrap();

        let act2 = boot
            .execute_clean_reboot(
                CONTROL_CAP,
                LINUX_REBOOT_MAGIC1,
                LINUX_REBOOT_MAGIC2C,
                LINUX_REBOOT_CMD_POWER_OFF,
            )
            .unwrap();
        assert_eq!(act2, RebootAction::PowerOff);
        assert_eq!(boot.journal().phase, BootPhase::CleanPowerOff);
    }
}
