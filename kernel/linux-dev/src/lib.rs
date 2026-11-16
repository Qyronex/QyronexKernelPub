// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::num::NonZeroU32;
use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::{
    Errno, KERNEL_TERMIOS_BYTES, POLLHUP, POLLIN, POLLOUT, WinSize, encode_default_serial_termios,
};

/// Linux `termios` `c_iflag` bit definitions (`<asm-generic/termbits.h>`).
pub const IGNCR: u32 = 0x0080;
pub const ICRNL: u32 = 0x0100;
pub const IXON: u32 = 0x0400;

/// Linux `termios` `c_oflag` bit definitions.
pub const OPOST: u32 = 0x0001;
pub const ONLCR: u32 = 0x0004;

/// Linux `termios` `c_lflag` bit definitions.
pub const ISIG: u32 = 0x0001;
pub const ICANON: u32 = 0x0002;
pub const ECHO: u32 = 0x0008;
pub const ECHOE: u32 = 0x0010;
pub const ECHOK: u32 = 0x0020;
pub const ECHONL: u32 = 0x0040;
pub const NOFLSH: u32 = 0x0080;
pub const TOSTOP: u32 = 0x0100;
pub const IEXTEN: u32 = 0x8000;

/// Linux `termios` `c_cc` control-character indices.
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const NCCS: usize = 19;

/// Step-32 `/dev`, console, TTY line-discipline, and PTY/devpts error domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NoSpace,
    WouldBlock,
    EntropyNotReady,
    AllZeroEntropy,
    PermissionDenied,
    OperationNotPermitted,
    NotControllingTty,
    NoControllingTty,
    NotTty,
    TableFull,
    BadEndpoint,
    StaleEndpoint,
    SlaveLocked,
    SlaveNotOpen,
    InputOutput,
    BrokenPipe,
    BufferFull,
    InvalidArgument,
}

impl Error {
    /// Maps a Step-32 device/TTY error to its canonical Linux [`Errno`].
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::NoSpace => Errno::ENOSPC,
            Self::WouldBlock | Self::EntropyNotReady | Self::BufferFull => Errno::EAGAIN,
            Self::AllZeroEntropy | Self::InputOutput => Errno::EIO,
            Self::PermissionDenied | Self::SlaveLocked => Errno::EACCES,
            Self::OperationNotPermitted => Errno::EPERM,
            Self::NotControllingTty | Self::NotTty => Errno::ENOTTY,
            Self::NoControllingTty | Self::SlaveNotOpen => Errno::ENXIO,
            Self::TableFull => Errno::ENFILE,
            Self::BadEndpoint | Self::StaleEndpoint => Errno::EBADF,
            Self::BrokenPipe => Errno::EPIPE,
            Self::InvalidArgument => Errno::EINVAL,
        }
    }
}

/// Encodes a Linux 64-bit `dev_t` (`makedev(major, minor)`).
pub const fn makedev(major: u32, minor: u32) -> u64 {
    let maj = (major as u64 & 0x0fff) << 8 | (major as u64 & !0x0fff) << 32;
    let min = (minor as u64 & 0x00ff) | (minor as u64 & !0x00ff) << 12;
    maj | min
}

/// Step-32 character device nodes under `/dev` and `/dev/pts`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceNodeKind {
    /// `/dev/null` (`1:3`)
    Null,
    /// `/dev/zero` (`1:5`)
    Zero,
    /// `/dev/full` (`1:7`)
    Full,
    /// `/dev/random` (`1:8`)
    Random,
    /// `/dev/urandom` (`1:9`)
    Urandom,
    /// `/dev/tty` (`5:0`, process controlling terminal)
    Tty,
    /// `/dev/console` (`5:1`)
    Console,
    /// `/dev/ptmx` (`5:2`, PTY multiplexor)
    Ptmx,
    /// `/dev/pts/<N>` (`136:<N>`, PTY slave)
    Pts(u32),
}

impl DeviceNodeKind {
    /// Returns the Linux `(major, minor)` pair for this character device node.
    pub const fn major_minor(self) -> (u32, u32) {
        match self {
            Self::Null => (1, 3),
            Self::Zero => (1, 5),
            Self::Full => (1, 7),
            Self::Random => (1, 8),
            Self::Urandom => (1, 9),
            Self::Tty => (5, 0),
            Self::Console => (5, 1),
            Self::Ptmx => (5, 2),
            Self::Pts(index) => (136, index),
        }
    }

    /// Returns the Linux `st_rdev` (`makedev`) encoding for `stat(2)` / `fstat(2)`.
    pub const fn rdev(self) -> u64 {
        let (major, minor) = self.major_minor();
        makedev(major, minor)
    }

    /// Verifies that a process holds a valid capability with the required `CapRights` before
    /// accessing this character device node.
    pub fn authorize_capability(
        self,
        capability: &Capability,
        required_rights: CapRights,
    ) -> Result<(), Error> {
        let _ = self;
        if capability.rights.contains(required_rights) {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }
}

/// Resolves a normalized `/dev/...` or `dev/...` path to a Step-32 [`DeviceNodeKind`].
pub fn classify_dev_path(path: &[u8]) -> Option<DeviceNodeKind> {
    let mut trimmed = path;
    while let Some((b'/', rest)) = trimmed.split_first() {
        trimmed = rest;
    }
    while let Some((b'/', rest)) = trimmed.split_last() {
        trimmed = rest;
    }
    let mut rest = trimmed.strip_prefix(b"dev/")?;
    while let Some((b'/', next)) = rest.split_first() {
        rest = next;
    }
    classify_dev_subpath(rest)
}

fn classify_dev_subpath(subpath: &[u8]) -> Option<DeviceNodeKind> {
    match subpath {
        b"null" => Some(DeviceNodeKind::Null),
        b"zero" => Some(DeviceNodeKind::Zero),
        b"full" => Some(DeviceNodeKind::Full),
        b"random" => Some(DeviceNodeKind::Random),
        b"urandom" => Some(DeviceNodeKind::Urandom),
        b"tty" => Some(DeviceNodeKind::Tty),
        b"console" | b"ttyAMA0" => Some(DeviceNodeKind::Console),
        b"ptmx" | b"pts/ptmx" => Some(DeviceNodeKind::Ptmx),
        _ => {
            let digits = subpath.strip_prefix(b"pts/")?;
            parse_pts_index(digits).map(DeviceNodeKind::Pts)
        }
    }
}

fn parse_pts_index(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }
    if digits.len() > 1 && digits[0] == b'0' {
        return None;
    }
    let mut value = 0u32;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

/// Explicit entropy readiness state for `/dev/random` and `/dev/urandom`.
///
/// Step 32 acceptance requires that entropy devices never claim readiness or fabricate output
/// before the explicit entropy policy permits it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyReadiness {
    Unseeded,
    Ready,
}

/// Reports whether a stateless or entropy pseudo-device is currently readable for `poll`/`select`.
pub const fn poll_pseudo_device_readable(
    node: DeviceNodeKind,
    entropy_readiness: EntropyReadiness,
) -> Option<bool> {
    match node {
        DeviceNodeKind::Null | DeviceNodeKind::Zero | DeviceNodeKind::Full => Some(true),
        DeviceNodeKind::Random | DeviceNodeKind::Urandom => {
            Some(matches!(entropy_readiness, EntropyReadiness::Ready))
        }
        DeviceNodeKind::Tty
        | DeviceNodeKind::Console
        | DeviceNodeKind::Ptmx
        | DeviceNodeKind::Pts(_) => None,
    }
}

/// Executes a read on `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, or `/dev/urandom`.
///
/// - `/dev/null` returns `Ok(0)` (EOF).
/// - `/dev/zero` and `/dev/full` fill `dest` with `0x00` and return `Ok(dest.len())`.
/// - `/dev/random` and `/dev/urandom` enforce [`EntropyReadiness`]: if [`EntropyReadiness::Unseeded`],
///   non-blocking reads fail with [`Error::WouldBlock`] (`-EAGAIN`) and blocking reads fail with
///   [`Error::EntropyNotReady`] without fabricating bytes.
pub fn read_pseudo_device<F>(
    node: DeviceNodeKind,
    dest: &mut [u8],
    nonblocking: bool,
    entropy_readiness: EntropyReadiness,
    fill_entropy: F,
) -> Result<usize, Error>
where
    F: FnOnce(&mut [u8]) -> Result<(), Error>,
{
    match node {
        DeviceNodeKind::Null => Ok(0),
        DeviceNodeKind::Zero | DeviceNodeKind::Full => {
            dest.fill(0);
            Ok(dest.len())
        }
        DeviceNodeKind::Random | DeviceNodeKind::Urandom => {
            if entropy_readiness == EntropyReadiness::Unseeded {
                return if nonblocking {
                    Err(Error::WouldBlock)
                } else {
                    Err(Error::EntropyNotReady)
                };
            }
            if dest.is_empty() {
                return Ok(0);
            }
            fill_entropy(dest)?;
            if dest.len() >= 16 && dest.iter().all(|&b| b == 0) {
                dest.fill(0);
                return Err(Error::AllZeroEntropy);
            }
            Ok(dest.len())
        }
        DeviceNodeKind::Tty
        | DeviceNodeKind::Console
        | DeviceNodeKind::Ptmx
        | DeviceNodeKind::Pts(_) => Err(Error::InvalidArgument),
    }
}

/// Executes a write on `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, or `/dev/urandom`.
///
/// - `/dev/null`, `/dev/zero`, `/dev/random`, and `/dev/urandom` consume `src.len()` bytes.
/// - `/dev/full` always fails closed with [`Error::NoSpace`] (`-ENOSPC`).
pub const fn write_pseudo_device(node: DeviceNodeKind, src: &[u8]) -> Result<usize, Error> {
    match node {
        DeviceNodeKind::Null
        | DeviceNodeKind::Zero
        | DeviceNodeKind::Random
        | DeviceNodeKind::Urandom => Ok(src.len()),
        DeviceNodeKind::Full => Err(Error::NoSpace),
        DeviceNodeKind::Tty
        | DeviceNodeKind::Console
        | DeviceNodeKind::Ptmx
        | DeviceNodeKind::Pts(_) => Err(Error::InvalidArgument),
    }
}

/// Linux `struct termios` configuration for a TTY/PTY endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
}

impl Termios {
    pub const fn default_serial() -> Self {
        let raw = encode_default_serial_termios();
        Self::from_le_bytes(raw)
    }

    pub const fn from_le_bytes(raw: [u8; KERNEL_TERMIOS_BYTES]) -> Self {
        let c_iflag = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let c_oflag = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let c_cflag = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let c_lflag = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        let c_line = raw[16];
        let mut c_cc = [0u8; NCCS];
        let mut idx = 0;
        while idx < NCCS {
            c_cc[idx] = raw[17 + idx];
            idx += 1;
        }
        Self {
            c_iflag,
            c_oflag,
            c_cflag,
            c_lflag,
            c_line,
            c_cc,
        }
    }

    pub const fn to_le_bytes(self) -> [u8; KERNEL_TERMIOS_BYTES] {
        let mut out = [0u8; KERNEL_TERMIOS_BYTES];
        let iflag = self.c_iflag.to_le_bytes();
        let oflag = self.c_oflag.to_le_bytes();
        let cflag = self.c_cflag.to_le_bytes();
        let lflag = self.c_lflag.to_le_bytes();
        out[0] = iflag[0];
        out[1] = iflag[1];
        out[2] = iflag[2];
        out[3] = iflag[3];
        out[4] = oflag[0];
        out[5] = oflag[1];
        out[6] = oflag[2];
        out[7] = oflag[3];
        out[8] = cflag[0];
        out[9] = cflag[1];
        out[10] = cflag[2];
        out[11] = cflag[3];
        out[12] = lflag[0];
        out[13] = lflag[1];
        out[14] = lflag[2];
        out[15] = lflag[3];
        out[16] = self.c_line;
        let mut idx = 0;
        while idx < NCCS {
            out[17 + idx] = self.c_cc[idx];
            idx += 1;
        }
        out
    }

    pub const fn is_canonical(&self) -> bool {
        self.c_lflag & ICANON != 0
    }

    pub const fn is_echo(&self) -> bool {
        self.c_lflag & ECHO != 0
    }

    pub const fn is_isig(&self) -> bool {
        self.c_lflag & ISIG != 0
    }

    pub const fn is_tostop(&self) -> bool {
        self.c_lflag & TOSTOP != 0
    }
}

/// Job-control signal generated by TTY line discipline or background access checks.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TtySignal {
    SigInt = 2,
    SigQuit = 3,
    SigTstp = 20,
    SigTtin = 21,
    SigTtou = 22,
}

impl TtySignal {
    pub const fn linux_signal_number(self) -> u8 {
        self as u8
    }
}

/// Controlling-session and foreground-process-group state for one TTY/PTY.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TtySessionState {
    controlling_session: Option<NonZeroU32>,
    foreground_pgid: Option<NonZeroU32>,
}

/// Outcome of a TTY foreground/background job-control check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobControlCheck {
    Allowed,
    Stop(TtySignal),
}

impl TtySessionState {
    pub const fn new() -> Self {
        Self {
            controlling_session: None,
            foreground_pgid: None,
        }
    }

    pub const fn with_session(session: NonZeroU32, foreground_pgid: NonZeroU32) -> Self {
        Self {
            controlling_session: Some(session),
            foreground_pgid: Some(foreground_pgid),
        }
    }

    pub const fn controlling_session(&self) -> Option<NonZeroU32> {
        self.controlling_session
    }

    pub const fn foreground_pgid(&self) -> Option<NonZeroU32> {
        self.foreground_pgid
    }

    /// Implements `TIOCSCTTY` (`0x540e`): attaches this TTY as the controlling terminal of a
    /// session leader (`caller_pid == caller_sid`).
    pub fn attach_controlling_session(
        &mut self,
        caller_pid: NonZeroU32,
        caller_sid: NonZeroU32,
        caller_pgid: NonZeroU32,
    ) -> Result<(), Error> {
        if caller_pid != caller_sid {
            return Err(Error::OperationNotPermitted);
        }
        if let Some(existing) = self.controlling_session {
            if existing == caller_sid {
                return Ok(());
            }
            return Err(Error::OperationNotPermitted);
        }
        self.controlling_session = Some(caller_sid);
        self.foreground_pgid = Some(caller_pgid);
        Ok(())
    }

    /// Implements `TIOCGPGRP` (`0x540f`).
    pub fn get_foreground_pgid(&self, caller_sid: NonZeroU32) -> Result<NonZeroU32, Error> {
        if self.controlling_session != Some(caller_sid) {
            return Err(Error::NotControllingTty);
        }
        self.foreground_pgid.ok_or(Error::NotControllingTty)
    }

    /// Implements `TIOCSPGRP` (`0x5410`), enforcing `SIGTTOU` when invoked from a background
    /// process group in the controlling session.
    pub fn set_foreground_pgid(
        &mut self,
        caller_sid: NonZeroU32,
        caller_pgid: NonZeroU32,
        target_pgid: NonZeroU32,
    ) -> Result<JobControlCheck, Error> {
        self.set_foreground_pgid_checked(caller_sid, caller_pgid, target_pgid, false)
    }

    /// Implements `TIOCSPGRP` (`0x5410`), allowing background callers to update the foreground
    /// process group when `SIGTTOU` is ignored or blocked per POSIX.
    pub fn set_foreground_pgid_checked(
        &mut self,
        caller_sid: NonZeroU32,
        caller_pgid: NonZeroU32,
        target_pgid: NonZeroU32,
        sigttou_ignored_or_blocked: bool,
    ) -> Result<JobControlCheck, Error> {
        if self.controlling_session != Some(caller_sid) {
            return Err(Error::NotControllingTty);
        }
        if !sigttou_ignored_or_blocked
            && let Some(fg) = self.foreground_pgid
            && fg != caller_pgid
        {
            return Ok(JobControlCheck::Stop(TtySignal::SigTtou));
        }
        self.foreground_pgid = Some(target_pgid);
        Ok(JobControlCheck::Allowed)
    }

    /// Checks whether a process in `(caller_sid, caller_pgid)` may read from this TTY or must stop
    /// with `SIGTTIN`.
    pub fn check_read_access(
        &self,
        caller_sid: NonZeroU32,
        caller_pgid: NonZeroU32,
    ) -> JobControlCheck {
        if self.controlling_session == Some(caller_sid)
            && let Some(fg) = self.foreground_pgid
            && fg != caller_pgid
        {
            return JobControlCheck::Stop(TtySignal::SigTtin);
        }
        JobControlCheck::Allowed
    }

    /// Checks whether a process in `(caller_sid, caller_pgid)` may write to this TTY or must stop
    /// with `SIGTTOU` when `TOSTOP` is enabled.
    pub fn check_write_access(
        &self,
        caller_sid: NonZeroU32,
        caller_pgid: NonZeroU32,
        tostop: bool,
    ) -> JobControlCheck {
        if tostop
            && self.controlling_session == Some(caller_sid)
            && let Some(fg) = self.foreground_pgid
            && fg != caller_pgid
        {
            return JobControlCheck::Stop(TtySignal::SigTtou);
        }
        JobControlCheck::Allowed
    }
}

impl Default for TtySessionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded `N_TTY` line discipline state for console and PTY endpoints.
pub struct LineDiscipline<const CAP: usize> {
    termios: Termios,
    winsize: WinSize,
    rx_buf: [u8; CAP],
    rx_len: usize,
    committed_len: usize,
    pending_eof: bool,
}

impl<const CAP: usize> LineDiscipline<CAP> {
    pub const fn new() -> Self {
        Self {
            termios: Termios::default_serial(),
            winsize: WinSize::default_serial(),
            rx_buf: [0u8; CAP],
            rx_len: 0,
            committed_len: 0,
            pending_eof: false,
        }
    }

    pub const fn termios(&self) -> Termios {
        self.termios
    }

    pub fn set_termios(&mut self, termios: Termios, flush_input: bool) {
        let was_canonical = self.termios.is_canonical();
        self.termios = termios;
        if flush_input {
            self.rx_len = 0;
            self.committed_len = 0;
            self.pending_eof = false;
        } else if was_canonical && !self.termios.is_canonical() {
            // Switching from canonical to raw mode makes all buffered bytes immediately readable.
            self.committed_len = self.rx_len;
        }
    }

    pub const fn winsize(&self) -> WinSize {
        self.winsize
    }

    pub fn set_winsize(&mut self, winsize: WinSize) {
        self.winsize = winsize;
    }

    pub const fn has_readable_data(&self) -> bool {
        self.committed_len > 0 || self.pending_eof
    }

    pub const fn can_accept_input(&self) -> bool {
        self.rx_len < CAP
    }

    /// Processes one incoming character from the UART RX or PTY master write path.
    ///
    /// Appends any echo bytes to `echo_out` (up to its capacity) and returns an optional
    /// [`TtySignal`] when `ISIG` matches `VINTR`, `VQUIT`, or `VSUSP`.
    pub fn receive_input_byte(
        &mut self,
        mut byte: u8,
        echo_out: &mut [u8],
    ) -> (usize, Option<TtySignal>) {
        let mut echoed = 0usize;

        if self.termios.c_iflag & IGNCR != 0 && byte == b'\r' {
            return (0, None);
        }
        if self.termios.c_iflag & ICRNL != 0 && byte == b'\r' {
            byte = b'\n';
        }

        if self.termios.is_isig() {
            let signal = if byte != 0 && byte == self.termios.c_cc[VINTR] {
                Some(TtySignal::SigInt)
            } else if byte != 0 && byte == self.termios.c_cc[VQUIT] {
                Some(TtySignal::SigQuit)
            } else if byte != 0 && byte == self.termios.c_cc[VSUSP] {
                Some(TtySignal::SigTstp)
            } else {
                None
            };
            if let Some(sig) = signal {
                if self.termios.c_lflag & NOFLSH == 0 {
                    self.rx_len = self.committed_len;
                }
                return (0, Some(sig));
            }
        }

        if self.termios.is_canonical() {
            let verase = self.termios.c_cc[VERASE];
            let vkill = self.termios.c_cc[VKILL];
            let veof = self.termios.c_cc[VEOF];
            let veol = self.termios.c_cc[VEOL];

            if verase != 0 && byte == verase {
                if self.rx_len > self.committed_len {
                    self.rx_len -= 1;
                    if self.termios.is_echo() && (self.termios.c_lflag & ECHOE != 0) {
                        echoed += push_echo_bytes(echo_out, echoed, b"\x08 \x08");
                    }
                }
                return (echoed, None);
            }

            if vkill != 0 && byte == vkill {
                if self.rx_len > self.committed_len {
                    self.rx_len = self.committed_len;
                    if self.termios.is_echo() && (self.termios.c_lflag & ECHOK != 0) {
                        echoed += self.echo_char(b'\n', echo_out, echoed);
                    }
                }
                return (echoed, None);
            }

            if veof != 0 && byte == veof {
                if self.rx_len == self.committed_len {
                    self.pending_eof = true;
                } else {
                    self.committed_len = self.rx_len;
                }
                return (0, None);
            }

            if self.rx_len < CAP {
                self.rx_buf[self.rx_len] = byte;
                self.rx_len += 1;
                if self.termios.is_echo() || (byte == b'\n' && self.termios.c_lflag & ECHONL != 0) {
                    echoed += self.echo_char(byte, echo_out, echoed);
                }
                if byte == b'\n' || (veol != 0 && byte == veol) {
                    self.committed_len = self.rx_len;
                }
            }
            (echoed, None)
        } else {
            if self.rx_len < CAP {
                self.rx_buf[self.rx_len] = byte;
                self.rx_len += 1;
                self.committed_len = self.rx_len;
                if self.termios.is_echo() {
                    echoed += self.echo_char(byte, echo_out, echoed);
                }
            }
            (echoed, None)
        }
    }

    /// Reads committed bytes from the TTY input buffer.
    ///
    /// In canonical mode (`ICANON`), at most one line (up to and including `\n` or `VEOL`) is
    /// returned per `read(2)` call, matching POSIX/Linux `N_TTY` semantics.
    pub fn read_committed(&mut self, out: &mut [u8], _nonblocking: bool) -> Result<usize, Error> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.committed_len == 0 {
            if self.pending_eof {
                self.pending_eof = false;
                return Ok(0);
            }
            return Err(Error::WouldBlock);
        }

        let mut take = self.committed_len.min(out.len());
        if self.termios.is_canonical() {
            let veol = self.termios.c_cc[VEOL];
            for idx in 0..take {
                let b = self.rx_buf[idx];
                if b == b'\n' || (veol != 0 && b == veol) {
                    take = idx + 1;
                    break;
                }
            }
        }

        out[..take].copy_from_slice(&self.rx_buf[..take]);
        self.rx_buf.copy_within(take..self.rx_len, 0);
        self.rx_len -= take;
        self.committed_len -= take;
        Ok(take)
    }

    /// Formats one output byte according to `c_oflag` (`OPOST` / `ONLCR`).
    pub const fn format_output_byte(&self, byte: u8) -> ([u8; 2], usize) {
        if (self.termios.c_oflag & OPOST != 0)
            && (self.termios.c_oflag & ONLCR != 0)
            && byte == b'\n'
        {
            (*b"\r\n", 2)
        } else {
            ([byte, 0], 1)
        }
    }

    fn echo_char(&self, byte: u8, echo_out: &mut [u8], offset: usize) -> usize {
        let (formatted, len) = self.format_output_byte(byte);
        push_echo_bytes(echo_out, offset, &formatted[..len])
    }
}

impl<const CAP: usize> Default for LineDiscipline<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

fn push_echo_bytes(dest: &mut [u8], offset: usize, src: &[u8]) -> usize {
    let available = dest.len().saturating_sub(offset);
    let take = available.min(src.len());
    dest[offset..offset + take].copy_from_slice(&src[..take]);
    take
}

/// Generation-safe identity of one allocated PTY pair in [`PtyTable`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtyId {
    index: u32,
    generation: u64,
}

impl PtyId {
    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Generation-bound handle to the master side (`/dev/ptmx`) of a PTY pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtyMasterEndpoint {
    pty: PtyId,
}

impl PtyMasterEndpoint {
    pub const fn pty(self) -> PtyId {
        self.pty
    }
}

/// Generation-bound handle to the slave side (`/dev/pts/<N>`) of a PTY pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtySlaveEndpoint {
    pty: PtyId,
}

impl PtySlaveEndpoint {
    pub const fn pty(self) -> PtyId {
        self.pty
    }
}

/// Result of writing bytes to a PTY master endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtyMasterWriteResult {
    pub written: usize,
    pub signal: Option<(TtySignal, Option<NonZeroU32>)>,
}

/// Result of a slave-side PTY read or write after job-control evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtySlaveIoResult {
    Transferred(usize),
    JobControlStop(TtySignal),
}

struct PtySlot<const BUF_CAP: usize> {
    generation: u64,
    allocated: bool,
    master_open: bool,
    slave_open_count: usize,
    slave_ever_opened: bool,
    slave_locked: bool,
    ldisc: LineDiscipline<BUF_CAP>,
    session: TtySessionState,
    master_rx_buf: [u8; BUF_CAP],
    master_rx_len: usize,
}

impl<const BUF_CAP: usize> PtySlot<BUF_CAP> {
    const fn new() -> Self {
        Self {
            generation: 0,
            allocated: false,
            master_open: false,
            slave_open_count: 0,
            slave_ever_opened: false,
            slave_locked: true,
            ldisc: LineDiscipline::new(),
            session: TtySessionState::new(),
            master_rx_buf: [0u8; BUF_CAP],
            master_rx_len: 0,
        }
    }

    fn push_master_rx(&mut self, bytes: &[u8]) -> usize {
        let available = BUF_CAP.saturating_sub(self.master_rx_len);
        let take = available.min(bytes.len());
        self.master_rx_buf[self.master_rx_len..self.master_rx_len + take]
            .copy_from_slice(&bytes[..take]);
        self.master_rx_len += take;
        take
    }
}

/// Bounded `/dev/ptmx` + `/dev/pts/<N>` pseudo-terminal table.
pub struct PtyTable<const MAX_PTYS: usize, const BUF_CAP: usize> {
    slots: [PtySlot<BUF_CAP>; MAX_PTYS],
}

impl<const MAX_PTYS: usize, const BUF_CAP: usize> PtyTable<MAX_PTYS, BUF_CAP> {
    pub const fn new() -> Self {
        Self {
            slots: [const { PtySlot::new() }; MAX_PTYS],
        }
    }

    /// Allocates a new PTY pair when `/dev/ptmx` is opened.
    ///
    /// The slave node `/dev/pts/<N>` starts locked (`slave_locked = true`) until unlocked via
    /// [`Self::set_slave_lock`] (`TIOCSPTLCK`).
    pub fn allocate_ptmx(&mut self) -> Result<PtyMasterEndpoint, Error> {
        if MAX_PTYS == 0 || BUF_CAP == 0 {
            return Err(Error::TableFull);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.allocated)
            .ok_or(Error::TableFull)?;
        let index_u32 = u32::try_from(index).map_err(|_| Error::TableFull)?;
        let slot = &mut self.slots[index];
        let next_gen = slot.generation.checked_add(1).ok_or(Error::TableFull)?;
        slot.generation = next_gen;
        slot.allocated = true;
        slot.master_open = true;
        slot.slave_open_count = 0;
        slot.slave_ever_opened = false;
        slot.slave_locked = true;
        slot.ldisc = LineDiscipline::new();
        slot.session = TtySessionState::new();
        slot.master_rx_len = 0;
        Ok(PtyMasterEndpoint {
            pty: PtyId {
                index: index_u32,
                generation: next_gen,
            },
        })
    }

    /// Returns the `/dev/pts/<N>` slave number (`TIOCGPTN`).
    pub fn pts_number(&self, master: PtyMasterEndpoint) -> Result<u32, Error> {
        let _ = self.master_slot(master)?;
        Ok(master.pty.index)
    }

    /// Locks or unlocks the `/dev/pts/<N>` slave node (`TIOCSPTLCK`).
    pub fn set_slave_lock(&mut self, master: PtyMasterEndpoint, locked: bool) -> Result<(), Error> {
        let slot = self.master_slot_mut(master)?;
        slot.slave_locked = locked;
        Ok(())
    }

    /// Opens the slave `/dev/pts/<N>` node for an unlocked, live PTY pair.
    pub fn open_slave(&mut self, pts_index: u32) -> Result<PtySlaveEndpoint, Error> {
        let idx = usize::try_from(pts_index).map_err(|_| Error::SlaveNotOpen)?;
        let slot = self.slots.get_mut(idx).ok_or(Error::SlaveNotOpen)?;
        if !slot.allocated || !slot.master_open {
            return Err(Error::SlaveNotOpen);
        }
        if slot.slave_locked {
            return Err(Error::SlaveLocked);
        }
        slot.slave_open_count = slot
            .slave_open_count
            .checked_add(1)
            .ok_or(Error::TableFull)?;
        slot.slave_ever_opened = true;
        Ok(PtySlaveEndpoint {
            pty: PtyId {
                index: pts_index,
                generation: slot.generation,
            },
        })
    }

    /// Closes a master endpoint; frees the PTY slot once both master and all slave opens are closed.
    pub fn close_master(&mut self, master: PtyMasterEndpoint) -> Result<(), Error> {
        let slot = self.master_slot_mut(master)?;
        slot.master_open = false;
        if slot.slave_open_count == 0 {
            slot.allocated = false;
        }
        Ok(())
    }

    /// Closes one slave endpoint open reference; frees the PTY slot if master is also closed.
    pub fn close_slave(&mut self, slave: PtySlaveEndpoint) -> Result<(), Error> {
        let slot = self.slave_slot_mut(slave)?;
        slot.slave_open_count = slot.slave_open_count.saturating_sub(1);
        if !slot.master_open && slot.slave_open_count == 0 {
            slot.allocated = false;
        }
        Ok(())
    }

    /// Writes input bytes from the PTY master into the slave line discipline.
    pub fn master_write(
        &mut self,
        master: PtyMasterEndpoint,
        input: &[u8],
    ) -> Result<PtyMasterWriteResult, Error> {
        let slot = self.master_slot_mut(master)?;
        if input.is_empty() {
            return Ok(PtyMasterWriteResult {
                written: 0,
                signal: None,
            });
        }
        let mut echo_scratch = [0u8; 8];
        let mut last_signal = None;
        for &byte in input {
            let (echoed, sig) = slot.ldisc.receive_input_byte(byte, &mut echo_scratch);
            if echoed > 0 {
                let _ = slot.push_master_rx(&echo_scratch[..echoed]);
            }
            if let Some(s) = sig {
                last_signal = Some((s, slot.session.foreground_pgid()));
            }
        }
        Ok(PtyMasterWriteResult {
            written: input.len(),
            signal: last_signal,
        })
    }

    /// Reads slave output (and echoed input) from the PTY master.
    ///
    /// Per Linux PTY semantics, once the slave has been opened and all slave descriptors have been
    /// closed, draining the remaining output returns [`Error::InputOutput`] (`-EIO`).
    pub fn master_read(
        &mut self,
        master: PtyMasterEndpoint,
        out: &mut [u8],
        _nonblocking: bool,
    ) -> Result<usize, Error> {
        let slot = self.master_slot_mut(master)?;
        if out.is_empty() {
            return Ok(0);
        }
        if slot.master_rx_len == 0 {
            if slot.slave_ever_opened && slot.slave_open_count == 0 {
                return Err(Error::InputOutput);
            }
            return Err(Error::WouldBlock);
        }
        let take = slot.master_rx_len.min(out.len());
        out[..take].copy_from_slice(&slot.master_rx_buf[..take]);
        slot.master_rx_buf.copy_within(take..slot.master_rx_len, 0);
        slot.master_rx_len -= take;
        Ok(take)
    }

    /// Reads committed line-discipline bytes from the PTY slave, enforcing `SIGTTIN` on background
    /// process groups in the controlling session.
    pub fn slave_read(
        &mut self,
        slave: PtySlaveEndpoint,
        caller_sid: NonZeroU32,
        caller_pgid: NonZeroU32,
        out: &mut [u8],
        nonblocking: bool,
    ) -> Result<PtySlaveIoResult, Error> {
        let slot = self.slave_slot_mut(slave)?;
        if let JobControlCheck::Stop(sig) = slot.session.check_read_access(caller_sid, caller_pgid)
        {
            return Ok(PtySlaveIoResult::JobControlStop(sig));
        }
        if !slot.ldisc.has_readable_data() && !slot.master_open {
            return Ok(PtySlaveIoResult::Transferred(0));
        }
        let n = slot.ldisc.read_committed(out, nonblocking)?;
        Ok(PtySlaveIoResult::Transferred(n))
    }

    /// Writes bytes from the PTY slave to the PTY master, enforcing `SIGTTOU` when `TOSTOP` is
    /// enabled and applying `OPOST`/`ONLCR` output processing.
    pub fn slave_write(
        &mut self,
        slave: PtySlaveEndpoint,
        caller_sid: NonZeroU32,
        caller_pgid: NonZeroU32,
        input: &[u8],
    ) -> Result<PtySlaveIoResult, Error> {
        self.slave_write_checked(slave, caller_sid, caller_pgid, input, false)
    }

    /// Writes bytes from the PTY slave to the PTY master, bypassing background `SIGTTOU` stop when
    /// `sigttou_ignored_or_blocked` is `true`.
    pub fn slave_write_checked(
        &mut self,
        slave: PtySlaveEndpoint,
        caller_sid: NonZeroU32,
        caller_pgid: NonZeroU32,
        input: &[u8],
        sigttou_ignored_or_blocked: bool,
    ) -> Result<PtySlaveIoResult, Error> {
        let slot = self.slave_slot_mut(slave)?;
        if !slot.master_open {
            return Err(Error::BrokenPipe);
        }
        if let JobControlCheck::Stop(sig) = slot.session.check_write_access(
            caller_sid,
            caller_pgid,
            slot.ldisc.termios().is_tostop() && !sigttou_ignored_or_blocked,
        ) {
            return Ok(PtySlaveIoResult::JobControlStop(sig));
        }
        let mut consumed = 0usize;
        for &byte in input {
            let (formatted, flen) = slot.ldisc.format_output_byte(byte);
            if slot.master_rx_len + flen > BUF_CAP {
                break;
            }
            let _ = slot.push_master_rx(&formatted[..flen]);
            consumed += 1;
        }
        if consumed == 0 && !input.is_empty() {
            return Err(Error::BufferFull);
        }
        Ok(PtySlaveIoResult::Transferred(consumed))
    }

    pub fn slave_session_mut(
        &mut self,
        slave: PtySlaveEndpoint,
    ) -> Result<&mut TtySessionState, Error> {
        Ok(&mut self.slave_slot_mut(slave)?.session)
    }

    pub fn slave_ldisc_mut(
        &mut self,
        slave: PtySlaveEndpoint,
    ) -> Result<&mut LineDiscipline<BUF_CAP>, Error> {
        Ok(&mut self.slave_slot_mut(slave)?.ldisc)
    }

    /// Returns a mutable reference to the shared PTY line discipline via a master endpoint.
    pub fn master_ldisc_mut(
        &mut self,
        master: PtyMasterEndpoint,
    ) -> Result<&mut LineDiscipline<BUF_CAP>, Error> {
        Ok(&mut self.master_slot_mut(master)?.ldisc)
    }

    /// Returns the Linux `POLL*` readiness bitmask for a PTY master endpoint.
    pub fn master_readiness(&self, master: PtyMasterEndpoint) -> Result<u32, Error> {
        let slot = self.master_slot(master)?;
        let mut mask = 0u32;
        if slot.master_rx_len > 0 {
            mask |= u32::from(POLLIN);
        }
        if slot.ldisc.can_accept_input() {
            mask |= u32::from(POLLOUT);
        }
        if slot.slave_ever_opened && slot.slave_open_count == 0 {
            mask |= u32::from(POLLHUP);
        }
        Ok(mask)
    }

    /// Returns the Linux `POLL*` readiness bitmask for a PTY slave endpoint.
    pub fn slave_readiness(&self, slave: PtySlaveEndpoint) -> Result<u32, Error> {
        let slot = self.slave_slot(slave)?;
        let mut mask = 0u32;
        if slot.ldisc.has_readable_data() {
            mask |= u32::from(POLLIN);
        }
        if slot.master_open && slot.master_rx_len < BUF_CAP {
            mask |= u32::from(POLLOUT);
        }
        if !slot.master_open {
            mask |= u32::from(POLLHUP);
        }
        Ok(mask)
    }

    fn master_slot(&self, master: PtyMasterEndpoint) -> Result<&PtySlot<BUF_CAP>, Error> {
        let idx = usize::try_from(master.pty.index).map_err(|_| Error::BadEndpoint)?;
        let slot = self.slots.get(idx).ok_or(Error::BadEndpoint)?;
        if !slot.allocated || !slot.master_open || slot.generation != master.pty.generation {
            return Err(Error::StaleEndpoint);
        }
        Ok(slot)
    }

    fn master_slot_mut(
        &mut self,
        master: PtyMasterEndpoint,
    ) -> Result<&mut PtySlot<BUF_CAP>, Error> {
        let idx = usize::try_from(master.pty.index).map_err(|_| Error::BadEndpoint)?;
        let slot = self.slots.get_mut(idx).ok_or(Error::BadEndpoint)?;
        if !slot.allocated || !slot.master_open || slot.generation != master.pty.generation {
            return Err(Error::StaleEndpoint);
        }
        Ok(slot)
    }

    fn slave_slot(&self, slave: PtySlaveEndpoint) -> Result<&PtySlot<BUF_CAP>, Error> {
        let idx = usize::try_from(slave.pty.index).map_err(|_| Error::BadEndpoint)?;
        let slot = self.slots.get(idx).ok_or(Error::BadEndpoint)?;
        if !slot.allocated || slot.slave_open_count == 0 || slot.generation != slave.pty.generation
        {
            return Err(Error::StaleEndpoint);
        }
        Ok(slot)
    }

    fn slave_slot_mut(&mut self, slave: PtySlaveEndpoint) -> Result<&mut PtySlot<BUF_CAP>, Error> {
        let idx = usize::try_from(slave.pty.index).map_err(|_| Error::BadEndpoint)?;
        let slot = self.slots.get_mut(idx).ok_or(Error::BadEndpoint)?;
        if !slot.allocated || slot.slave_open_count == 0 || slot.generation != slave.pty.generation
        {
            return Err(Error::StaleEndpoint);
        }
        Ok(slot)
    }
}

impl<const MAX_PTYS: usize, const BUF_CAP: usize> Default for PtyTable<MAX_PTYS, BUF_CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_capability::{CapRights, Capability, ObjectId};

    #[test]
    fn dev_path_classification_and_major_minor_match_linux_devices() {
        assert_eq!(classify_dev_path(b"/dev/null"), Some(DeviceNodeKind::Null));
        assert_eq!(classify_dev_path(b"dev/zero"), Some(DeviceNodeKind::Zero));
        assert_eq!(classify_dev_path(b"/dev/full"), Some(DeviceNodeKind::Full));
        assert_eq!(
            classify_dev_path(b"/dev/random"),
            Some(DeviceNodeKind::Random)
        );
        assert_eq!(
            classify_dev_path(b"/dev/urandom"),
            Some(DeviceNodeKind::Urandom)
        );
        assert_eq!(classify_dev_path(b"/dev/tty"), Some(DeviceNodeKind::Tty));
        assert_eq!(
            classify_dev_path(b"/dev/console"),
            Some(DeviceNodeKind::Console)
        );
        assert_eq!(
            classify_dev_path(b"/dev/ttyAMA0"),
            Some(DeviceNodeKind::Console)
        );
        assert_eq!(classify_dev_path(b"/dev/ptmx"), Some(DeviceNodeKind::Ptmx));
        assert_eq!(
            classify_dev_path(b"/dev/pts/0"),
            Some(DeviceNodeKind::Pts(0))
        );
        assert_eq!(
            classify_dev_path(b"/dev/pts/12"),
            Some(DeviceNodeKind::Pts(12))
        );
        assert_eq!(classify_dev_path(b"/dev/pts/01"), None);
        assert_eq!(classify_dev_path(b"/etc/passwd"), None);

        assert_eq!(DeviceNodeKind::Null.major_minor(), (1, 3));
        assert_eq!(DeviceNodeKind::Zero.major_minor(), (1, 5));
        assert_eq!(DeviceNodeKind::Full.major_minor(), (1, 7));
        assert_eq!(DeviceNodeKind::Random.major_minor(), (1, 8));
        assert_eq!(DeviceNodeKind::Urandom.major_minor(), (1, 9));
        assert_eq!(DeviceNodeKind::Tty.major_minor(), (5, 0));
        assert_eq!(DeviceNodeKind::Console.major_minor(), (5, 1));
        assert_eq!(DeviceNodeKind::Ptmx.major_minor(), (5, 2));
        assert_eq!(DeviceNodeKind::Pts(3).major_minor(), (136, 3));

        let read_only_cap = Capability {
            object: ObjectId(10),
            rights: CapRights::READ,
        };
        assert_eq!(
            DeviceNodeKind::Null.authorize_capability(&read_only_cap, CapRights::READ),
            Ok(())
        );
        assert_eq!(
            DeviceNodeKind::Null.authorize_capability(&read_only_cap, CapRights::WRITE),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn pseudo_devices_enforce_null_zero_full_and_entropy_readiness_policy() {
        let mut buf = [0xffu8; 32];
        assert_eq!(
            read_pseudo_device(
                DeviceNodeKind::Null,
                &mut buf,
                false,
                EntropyReadiness::Ready,
                |_| unreachable!()
            ),
            Ok(0)
        );
        assert_eq!(write_pseudo_device(DeviceNodeKind::Null, &buf), Ok(32));

        assert_eq!(
            read_pseudo_device(
                DeviceNodeKind::Zero,
                &mut buf,
                false,
                EntropyReadiness::Ready,
                |_| unreachable!()
            ),
            Ok(32)
        );
        assert!(buf.iter().all(|&b| b == 0));

        assert_eq!(
            write_pseudo_device(DeviceNodeKind::Full, &buf),
            Err(Error::NoSpace)
        );
        assert_eq!(Error::NoSpace.to_errno(), Errno::ENOSPC);

        // Unseeded entropy devices must never claim readiness or fabricate bytes.
        assert_eq!(
            poll_pseudo_device_readable(DeviceNodeKind::Random, EntropyReadiness::Unseeded),
            Some(false)
        );
        assert_eq!(
            poll_pseudo_device_readable(DeviceNodeKind::Urandom, EntropyReadiness::Unseeded),
            Some(false)
        );
        assert_eq!(
            read_pseudo_device(
                DeviceNodeKind::Random,
                &mut buf,
                true,
                EntropyReadiness::Unseeded,
                |_| unreachable!()
            ),
            Err(Error::WouldBlock)
        );
        assert_eq!(
            read_pseudo_device(
                DeviceNodeKind::Urandom,
                &mut buf,
                false,
                EntropyReadiness::Unseeded,
                |_| unreachable!()
            ),
            Err(Error::EntropyNotReady)
        );

        // Once seeded, entropy reads succeed and reject all-zero CSPRNG failures.
        assert_eq!(
            poll_pseudo_device_readable(DeviceNodeKind::Random, EntropyReadiness::Ready),
            Some(true)
        );
        assert_eq!(
            read_pseudo_device(
                DeviceNodeKind::Random,
                &mut buf,
                false,
                EntropyReadiness::Ready,
                |out| {
                    out.fill(0);
                    Ok(())
                }
            ),
            Err(Error::AllZeroEntropy)
        );
        assert_eq!(
            read_pseudo_device(
                DeviceNodeKind::Urandom,
                &mut buf,
                false,
                EntropyReadiness::Ready,
                |out| {
                    for (i, b) in out.iter_mut().enumerate() {
                        *b = (i as u8).wrapping_add(1);
                    }
                    Ok(())
                }
            ),
            Ok(32)
        );
    }

    #[test]
    fn line_discipline_supports_canonical_editing_eof_and_isig_signals() {
        let mut ldisc = LineDiscipline::<128>::new();
        let mut echo = [0u8; 64];

        // Type "ab", backspace (DEL=127), "c\r" -> ICRNL turns '\r' into '\n' and commits "ac\n".
        for &ch in b"ab\x7fc\r" {
            let (_, sig) = ldisc.receive_input_byte(ch, &mut echo);
            assert!(sig.is_none());
        }
        assert!(ldisc.has_readable_data());
        let mut read_buf = [0u8; 16];
        let n = ldisc.read_committed(&mut read_buf, false).unwrap();
        assert_eq!(&read_buf[..n], b"ac\n");

        // Type ^C (0x03) -> generates SIGINT and flushes uncommitted line.
        let _ = ldisc.receive_input_byte(b'x', &mut echo);
        let (_, sig) = ldisc.receive_input_byte(0x03, &mut echo);
        assert_eq!(sig, Some(TtySignal::SigInt));
        assert!(!ldisc.has_readable_data());

        // Type ^D (0x04) on empty buffer -> commits immediate 0-byte EOF.
        let (_, sig) = ldisc.receive_input_byte(0x04, &mut echo);
        assert!(sig.is_none());
        assert_eq!(ldisc.read_committed(&mut read_buf, false), Ok(0));
    }

    #[test]
    fn pty_table_and_job_control_run_interactive_shell_exchange() {
        let mut ptys = PtyTable::<4, 256>::new();
        let master = ptys.allocate_ptmx().unwrap();
        let pts_num = ptys.pts_number(master).unwrap();
        assert_eq!(pts_num, 0);

        // Slave cannot be opened while locked.
        assert_eq!(ptys.open_slave(pts_num), Err(Error::SlaveLocked));

        // Unlock via TIOCSPTLCK and open slave.
        ptys.set_slave_lock(master, false).unwrap();
        let slave = ptys.open_slave(pts_num).unwrap();

        let sid = NonZeroU32::new(100).unwrap();
        let shell_pgid = NonZeroU32::new(100).unwrap();
        let child_pgid = NonZeroU32::new(200).unwrap();

        // Attach controlling terminal to session leader (PID=100, SID=100) and move foreground to child_pgid.
        ptys.slave_session_mut(slave)
            .unwrap()
            .attach_controlling_session(sid, sid, shell_pgid)
            .unwrap();
        assert_eq!(
            ptys.slave_session_mut(slave)
                .unwrap()
                .set_foreground_pgid(sid, shell_pgid, child_pgid),
            Ok(JobControlCheck::Allowed)
        );

        // Background shell reading while child_pgid is foreground receives SIGTTIN.
        let mut buf = [0u8; 64];
        assert_eq!(
            ptys.slave_read(slave, sid, shell_pgid, &mut buf, false),
            Ok(PtySlaveIoResult::JobControlStop(TtySignal::SigTtin))
        );

        // Master sends "echo hi\r" -> echoed as "echo hi\r\n" to master, committed as "echo hi\n" to foreground slave.
        let write_res = ptys.master_write(master, b"echo hi\r").unwrap();
        assert_eq!(write_res.written, 8);
        assert!(write_res.signal.is_none());

        let echoed = ptys.master_read(master, &mut buf, true).unwrap();
        assert_eq!(&buf[..echoed], b"echo hi\r\n");

        let slave_in = ptys
            .slave_read(slave, sid, child_pgid, &mut buf, false)
            .unwrap();
        assert_eq!(slave_in, PtySlaveIoResult::Transferred(8));
        assert_eq!(&buf[..8], b"echo hi\n");

        // Foreground slave writes "hi\n" -> ONLCR translates to "hi\r\n" on master read.
        assert_eq!(
            ptys.slave_write(slave, sid, child_pgid, b"hi\n"),
            Ok(PtySlaveIoResult::Transferred(3))
        );
        let master_out = ptys.master_read(master, &mut buf, true).unwrap();
        assert_eq!(&buf[..master_out], b"hi\r\n");

        // Master sends ^Z (0x1a) -> generates SIGTSTP targeting foreground process group (200).
        let ctrl_z = ptys.master_write(master, &[0x1a]).unwrap();
        assert_eq!(ctrl_z.signal, Some((TtySignal::SigTstp, Some(child_pgid))));

        // Closing slave causes subsequent master read on empty buffer to return -EIO.
        ptys.close_slave(slave).unwrap();
        assert_eq!(
            ptys.master_read(master, &mut buf, true),
            Err(Error::InputOutput)
        );
        ptys.close_master(master).unwrap();
    }

    #[test]
    fn pty_readiness_tracks_rx_tx_and_hangup_states() {
        let mut ptys = PtyTable::<4, 64>::new();
        let master = ptys.allocate_ptmx().unwrap();
        let idx = ptys.pts_number(master).unwrap();
        ptys.set_slave_lock(master, false).unwrap();
        let slave = ptys.open_slave(idx).unwrap();

        assert_eq!(ptys.master_readiness(master), Ok(u32::from(POLLOUT)));
        assert_eq!(ptys.slave_readiness(slave), Ok(u32::from(POLLOUT)));

        ptys.master_write(master, b"hi\n").unwrap();
        assert_eq!(
            ptys.master_readiness(master),
            Ok(u32::from(POLLIN | POLLOUT))
        );
        assert_eq!(ptys.slave_readiness(slave), Ok(u32::from(POLLIN | POLLOUT)));

        ptys.close_slave(slave).unwrap();
        assert_eq!(
            ptys.master_readiness(master),
            Ok(u32::from(POLLIN | POLLOUT | POLLHUP))
        );

        let slave2 = ptys.open_slave(idx).unwrap();
        ptys.close_master(master).unwrap();
        assert_eq!(
            ptys.slave_readiness(slave2),
            Ok(u32::from(POLLIN | POLLHUP))
        );
        ptys.close_slave(slave2).unwrap();
    }
}
