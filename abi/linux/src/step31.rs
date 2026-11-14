// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::{Errno, linux_signed_int, linux_unsigned_int};

/// Linux `getrandom(2)` flag bits (`<linux/random.h>`).
pub const GRND_NONBLOCK: u32 = 0x0001;
pub const GRND_RANDOM: u32 = 0x0002;
pub const GRND_INSECURE: u32 = 0x0004;

const GRND_KNOWN_MASK: u32 = GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE;

/// Linux `struct iovec` byte length on 64-bit targets (`iov_base: u64`, `iov_len: u64`).
pub const IOVEC_BYTES: usize = 16;
/// Linux `UIO_MAXIOV` upper bound on `iovcnt` for `readv(2)` / `writev(2)`.
pub const UIO_MAXIOV: usize = 1024;
/// Linux `MAX_RW_COUNT` single-call transfer ceiling (`0x7ffff000`).
pub const MAX_RW_COUNT: usize = 0x7fff_f000;

/// Linux `struct new_utsname` field and total byte sizes (`<linux/utsname.h>`).
pub const UTSNAME_FIELD_BYTES: usize = 65;
pub const UTSNAME_BYTES: usize = UTSNAME_FIELD_BYTES * 6;

/// Linux `struct rlimit64` byte size (`rlim_cur: u64`, `rlim_max: u64`) and infinity sentinel.
pub const RLIMIT64_BYTES: usize = 16;
pub const RLIM64_INFINITY: u64 = u64::MAX;
pub const RLIM_NLIMITS: u32 = 16;

/// Linux TTY/console `ioctl(2)` request numbers observed during Debian 13 glibc/busybox/systemd
/// startup (`<asm-generic/ioctls.h>`).
pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSW: u32 = 0x5403;
pub const TCSETSF: u32 = 0x5404;
pub const TIOCSCTTY: u32 = 0x540e;
pub const TIOCGPGRP: u32 = 0x540f;
pub const TIOCSPGRP: u32 = 0x5410;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
pub const TIOCGPTN: u32 = 0x8004_5430;
pub const TIOCSPTLCK: u32 = 0x4004_5431;

/// Linux `struct winsize` byte size (`ws_row`, `ws_col`, `ws_xpixel`, `ws_ypixel`).
pub const WINSIZE_BYTES: usize = 8;
/// Linux `struct termios` byte size for `TCGETS` (`4 * u32 + u8 + [u8; 19] = 36` bytes).
pub const KERNEL_TERMIOS_BYTES: usize = 36;

/// Validated Linux `getrandom(2)` flags word after low-32-bit `unsigned int` decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetrandomFlags(u32);

impl GetrandomFlags {
    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn nonblock(self) -> bool {
        self.0 & GRND_NONBLOCK != 0
    }

    pub const fn random(self) -> bool {
        self.0 & GRND_RANDOM != 0
    }

    pub const fn insecure(self) -> bool {
        self.0 & GRND_INSECURE != 0
    }
}

/// Validates Linux `getrandom(2)` flags from the low 32-bit `unsigned int` syscall register.
///
/// Unknown flag bits and the mutually exclusive `GRND_INSECURE | GRND_RANDOM` combination fail
/// closed with `EINVAL` per Linux UAPI.
pub const fn decode_getrandom_flags(raw: u64) -> Result<GetrandomFlags, Errno> {
    let bits = linux_unsigned_int(raw);
    if bits & !GRND_KNOWN_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if (bits & (GRND_INSECURE | GRND_RANDOM)) == (GRND_INSECURE | GRND_RANDOM) {
        return Err(Errno::EINVAL);
    }
    Ok(GetrandomFlags(bits))
}

/// 64-bit Linux `struct iovec` element (`iov_base`, `iov_len`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoVec {
    pub base: u64,
    pub len: u64,
}

impl IoVec {
    pub const fn new(base: u64, len: u64) -> Self {
        Self { base, len }
    }

    pub const fn from_le_bytes(raw: [u8; IOVEC_BYTES]) -> Self {
        let base = u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]);
        let len = u64::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        Self { base, len }
    }

    pub const fn to_le_bytes(self) -> [u8; IOVEC_BYTES] {
        let b = self.base.to_le_bytes();
        let l = self.len.to_le_bytes();
        [
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], l[0], l[1], l[2], l[3], l[4], l[5],
            l[6], l[7],
        ]
    }
}

/// Decodes the signed 32-bit `int iovcnt` argument of `readv(2)` / `writev(2)`.
pub const fn decode_iovcnt(raw: u64) -> Result<usize, Errno> {
    let signed = linux_signed_int(raw);
    if signed < 0 || (signed as usize) > UIO_MAXIOV {
        return Err(Errno::EINVAL);
    }
    Ok(signed as usize)
}

/// Validates a slice of `IoVec` descriptors against Linux `ssize_t` (`i64::MAX`) overflow.
///
/// Returns the total requested byte count capped to [`MAX_RW_COUNT`].
pub fn validate_iovec_slice(iovecs: &[IoVec]) -> Result<usize, Errno> {
    let mut total: i64 = 0;
    for iov in iovecs {
        let seg_len = i64::try_from(iov.len).map_err(|_| Errno::EINVAL)?;
        total = total.checked_add(seg_len).ok_or(Errno::EINVAL)?;
    }
    let total_usize = usize::try_from(total).map_err(|_| Errno::EINVAL)?;
    Ok(total_usize.min(MAX_RW_COUNT))
}

const fn write_uts_field(buf: &mut [u8; UTSNAME_BYTES], field_index: usize, text: &[u8]) {
    let base = field_index * UTSNAME_FIELD_BYTES;
    let max_copy = if text.len() < UTSNAME_FIELD_BYTES - 1 {
        text.len()
    } else {
        UTSNAME_FIELD_BYTES - 1
    };
    let mut i = 0;
    while i < max_copy {
        buf[base + i] = text[i];
        i += 1;
    }
}

/// Encodes the deterministic 390-byte `struct new_utsname` for `uname(2)` on AArch64.
///
/// Reports `sysname = "Linux"`, `release = "6.12.0-qyronex"`, and `machine = "aarch64"` so
/// Debian 13 (Trixie) glibc `DL_SYSDEP_OSCHECK` and `systemd` kernel-version checks pass
/// deterministically.
pub const fn encode_linux_aarch64_utsname() -> [u8; UTSNAME_BYTES] {
    let mut buf = [0u8; UTSNAME_BYTES];
    write_uts_field(&mut buf, 0, b"Linux");
    write_uts_field(&mut buf, 1, b"qyronex");
    write_uts_field(&mut buf, 2, b"6.12.0-qyronex");
    write_uts_field(&mut buf, 3, b"#1 SMP PREEMPT Qyronex");
    write_uts_field(&mut buf, 4, b"aarch64");
    write_uts_field(&mut buf, 5, b"(none)");
    buf
}

/// Encodes the deterministic 390-byte `struct new_utsname` for `uname(2)` on x86_64.
pub const fn encode_linux_x86_64_utsname() -> [u8; UTSNAME_BYTES] {
    let mut buf = [0u8; UTSNAME_BYTES];
    write_uts_field(&mut buf, 0, b"Linux");
    write_uts_field(&mut buf, 1, b"qyronex");
    write_uts_field(&mut buf, 2, b"6.12.0-qyronex");
    write_uts_field(&mut buf, 3, b"#1 SMP PREEMPT Qyronex");
    write_uts_field(&mut buf, 4, b"x86_64");
    write_uts_field(&mut buf, 5, b"(none)");
    buf
}

/// Linux x86_64 `arch_prctl(2)` subfunction codes (`<asm/prctl.h>`).
pub const ARCH_SET_GS: u32 = 0x1001;
pub const ARCH_SET_FS: u32 = 0x1002;
pub const ARCH_GET_FS: u32 = 0x1003;
pub const ARCH_GET_GS: u32 = 0x1004;

/// 48-bit canonical lower-half user address ceiling on x86_64 (`0x0000_8000_0000_0000`).
pub const X86_64_CANONICAL_USER_LIMIT: u64 = 0x0000_8000_0000_0000;

/// Validated x86_64 `arch_prctl(2)` TLS/GS base operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchPrctlOp {
    SetGs(u64),
    SetFs(u64),
    GetFs(u64),
    GetGs(u64),
}

/// Decodes and validates an x86_64 `arch_prctl(int code, unsigned long addr)` request.
///
/// `ARCH_SET_FS` and `ARCH_SET_GS` reject non-canonical or upper-half addresses (`>= 1 << 47`)
/// with `EPERM` per Linux x86_64 `do_arch_prctl_64`.
pub const fn decode_arch_prctl(raw_code: u64, addr: u64) -> Result<ArchPrctlOp, Errno> {
    match linux_unsigned_int(raw_code) {
        ARCH_SET_GS => {
            if addr >= X86_64_CANONICAL_USER_LIMIT {
                return Err(Errno::EPERM);
            }
            Ok(ArchPrctlOp::SetGs(addr))
        }
        ARCH_SET_FS => {
            if addr >= X86_64_CANONICAL_USER_LIMIT {
                return Err(Errno::EPERM);
            }
            Ok(ArchPrctlOp::SetFs(addr))
        }
        ARCH_GET_FS => Ok(ArchPrctlOp::GetFs(addr)),
        ARCH_GET_GS => Ok(ArchPrctlOp::GetGs(addr)),
        _ => Err(Errno::EINVAL),
    }
}

/// Linux `prlimit64(2)` resource selector (`0..16`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RlimitResource {
    Cpu = 0,
    Fsize = 1,
    Data = 2,
    Stack = 3,
    Core = 4,
    Rss = 5,
    Nproc = 6,
    Nofile = 7,
    Memlock = 8,
    As = 9,
    Locks = 10,
    Sigpending = 11,
    Msgqueue = 12,
    Nice = 13,
    Rtprio = 14,
    Rttime = 15,
}

/// Decodes the low 32-bit `unsigned int resource` argument of `prlimit64(2)`.
pub const fn decode_rlimit_resource(raw: u64) -> Result<RlimitResource, Errno> {
    match linux_unsigned_int(raw) {
        0 => Ok(RlimitResource::Cpu),
        1 => Ok(RlimitResource::Fsize),
        2 => Ok(RlimitResource::Data),
        3 => Ok(RlimitResource::Stack),
        4 => Ok(RlimitResource::Core),
        5 => Ok(RlimitResource::Rss),
        6 => Ok(RlimitResource::Nproc),
        7 => Ok(RlimitResource::Nofile),
        8 => Ok(RlimitResource::Memlock),
        9 => Ok(RlimitResource::As),
        10 => Ok(RlimitResource::Locks),
        11 => Ok(RlimitResource::Sigpending),
        12 => Ok(RlimitResource::Msgqueue),
        13 => Ok(RlimitResource::Nice),
        14 => Ok(RlimitResource::Rtprio),
        15 => Ok(RlimitResource::Rttime),
        _ => Err(Errno::EINVAL),
    }
}

/// Linux `struct rlimit64` (`rlim_cur`, `rlim_max`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rlimit64 {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

impl Rlimit64 {
    pub const fn new(rlim_cur: u64, rlim_max: u64) -> Self {
        Self { rlim_cur, rlim_max }
    }

    pub const fn validate(self) -> Result<Self, Errno> {
        if self.rlim_cur > self.rlim_max {
            return Err(Errno::EINVAL);
        }
        Ok(self)
    }

    pub const fn from_le_bytes(raw: [u8; RLIMIT64_BYTES]) -> Self {
        let rlim_cur = u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]);
        let rlim_max = u64::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        Self { rlim_cur, rlim_max }
    }

    pub const fn to_le_bytes(self) -> [u8; RLIMIT64_BYTES] {
        let cur = self.rlim_cur.to_le_bytes();
        let max = self.rlim_max.to_le_bytes();
        [
            cur[0], cur[1], cur[2], cur[3], cur[4], cur[5], cur[6], cur[7], max[0], max[1], max[2],
            max[3], max[4], max[5], max[6], max[7],
        ]
    }
}

/// Returns the deterministic baseline `struct rlimit64` for a given [`RlimitResource`].
pub const fn default_rlimit64(resource: RlimitResource) -> Rlimit64 {
    match resource {
        RlimitResource::Stack => Rlimit64::new(8 * 1024 * 1024, RLIM64_INFINITY),
        RlimitResource::Core => Rlimit64::new(0, RLIM64_INFINITY),
        RlimitResource::Nproc => Rlimit64::new(4, 4),
        RlimitResource::Nofile => Rlimit64::new(32, 32),
        RlimitResource::Memlock => Rlimit64::new(64 * 1024, 64 * 1024),
        RlimitResource::Sigpending => Rlimit64::new(64, 64),
        RlimitResource::Msgqueue => Rlimit64::new(819_200, 819_200),
        RlimitResource::Nice | RlimitResource::Rtprio => Rlimit64::new(0, 0),
        RlimitResource::Cpu
        | RlimitResource::Fsize
        | RlimitResource::Data
        | RlimitResource::Rss
        | RlimitResource::As
        | RlimitResource::Locks
        | RlimitResource::Rttime => Rlimit64::new(RLIM64_INFINITY, RLIM64_INFINITY),
    }
}

/// Linux `struct winsize` (`TIOCGWINSZ` / `TIOCSWINSZ`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WinSize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

impl WinSize {
    pub const fn default_serial() -> Self {
        Self {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }

    pub const fn from_le_bytes(raw: [u8; WINSIZE_BYTES]) -> Self {
        Self {
            ws_row: u16::from_le_bytes([raw[0], raw[1]]),
            ws_col: u16::from_le_bytes([raw[2], raw[3]]),
            ws_xpixel: u16::from_le_bytes([raw[4], raw[5]]),
            ws_ypixel: u16::from_le_bytes([raw[6], raw[7]]),
        }
    }

    pub const fn to_le_bytes(self) -> [u8; WINSIZE_BYTES] {
        let r = self.ws_row.to_le_bytes();
        let c = self.ws_col.to_le_bytes();
        let x = self.ws_xpixel.to_le_bytes();
        let y = self.ws_ypixel.to_le_bytes();
        [r[0], r[1], c[0], c[1], x[0], x[1], y[0], y[1]]
    }
}

/// Encodes the deterministic 36-byte Linux `struct termios` returned by `ioctl(fd, TCGETS, arg)`
/// on the serial console TTY (`isatty(3)` / `tcgetattr(3)`).
pub const fn encode_default_serial_termios() -> [u8; KERNEL_TERMIOS_BYTES] {
    // c_iflag: ICRNL (0x0100) | IXON (0x0400) = 0x0500
    // c_oflag: OPOST (0x0001) | ONLCR (0x0004) = 0x0005
    // c_cflag: B38400 (0x000f) | CS8 (0x0030) | CREAD (0x0080) | HUPCL (0x0400) = 0x04bf
    // c_lflag: ISIG (0x0001) | ICANON (0x0002) | ECHO (0x0008) | ECHOE (0x0010)
    //          | ECHOK (0x0020) | IEXTEN (0x8000) = 0x803b
    let mut out = [0u8; KERNEL_TERMIOS_BYTES];
    let iflag = 0x0000_0500u32.to_le_bytes();
    let oflag = 0x0000_0005u32.to_le_bytes();
    let cflag = 0x0000_04bfu32.to_le_bytes();
    let lflag = 0x0000_803bu32.to_le_bytes();
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
    out[16] = 0; // c_line = N_TTY (0)
    // Standard control characters: VINTR=3 (^C), VQUIT=28 (^\), VERASE=127 (DEL),
    // VKILL=21 (^U), VEOF=4 (^D), VTIME=0, VMIN=1, VSTART=17 (^Q), VSTOP=19 (^S), VSUSP=26 (^Z).
    out[17] = 3;
    out[18] = 28;
    out[19] = 127;
    out[20] = 21;
    out[21] = 4;
    out[22] = 0;
    out[23] = 1;
    out[25] = 17;
    out[26] = 19;
    out[27] = 26;
    out
}

/// Architecture-neutral Step-31 dynamic glibc and coreutil startup syscall surface.
///
/// Variants preserve raw Linux-visible scalar register values only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step31GlibcCall {
    Ioctl {
        fd: u64,
        request: u64,
        arg: u64,
    },
    Readv {
        fd: u64,
        user_iov: u64,
        iovcnt: u64,
    },
    Writev {
        fd: u64,
        user_iov: u64,
        iovcnt: u64,
    },
    Uname {
        user_utsname: u64,
    },
    Prlimit64 {
        pid: u64,
        resource: u64,
        user_new_rlim: u64,
        user_old_rlim: u64,
    },
    Getrandom {
        user_buffer: u64,
        count: u64,
        flags: u64,
    },
    Rseq {
        rseq_abi: u64,
        rseq_len: u64,
        flags: u64,
        sig: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getrandom_flags_decode_low_32_bits_and_reject_invalid_combinations() {
        let zero = decode_getrandom_flags(0xffff_ffff_0000_0000).unwrap();
        assert_eq!(zero.bits(), 0);
        assert!(!zero.nonblock());
        assert!(!zero.random());
        assert!(!zero.insecure());

        let nonblock_random = decode_getrandom_flags((GRND_NONBLOCK | GRND_RANDOM) as u64).unwrap();
        assert!(nonblock_random.nonblock());
        assert!(nonblock_random.random());
        assert!(!nonblock_random.insecure());

        let insecure = decode_getrandom_flags((GRND_NONBLOCK | GRND_INSECURE) as u64).unwrap();
        assert!(insecure.nonblock());
        assert!(!insecure.random());
        assert!(insecure.insecure());

        assert_eq!(
            decode_getrandom_flags((GRND_RANDOM | GRND_INSECURE) as u64),
            Err(Errno::EINVAL)
        );
        assert_eq!(decode_getrandom_flags(0x0008), Err(Errno::EINVAL));
    }

    #[test]
    fn iovec_and_iovcnt_validation_enforce_uio_maxiov_and_ssize_overflow() {
        assert_eq!(decode_iovcnt(0), Ok(0));
        assert_eq!(decode_iovcnt(UIO_MAXIOV as u64), Ok(UIO_MAXIOV));
        assert_eq!(decode_iovcnt((UIO_MAXIOV + 1) as u64), Err(Errno::EINVAL));
        assert_eq!(decode_iovcnt(u64::MAX), Err(Errno::EINVAL));

        let iov = IoVec::new(0x1000_2000, 128);
        assert_eq!(IoVec::from_le_bytes(iov.to_le_bytes()), iov);

        let valid = [IoVec::new(0x1000, 64), IoVec::new(0x2000, 192)];
        assert_eq!(validate_iovec_slice(&valid), Ok(256));

        let overflow = [IoVec::new(0x1000, i64::MAX as u64), IoVec::new(0x2000, 1)];
        assert_eq!(validate_iovec_slice(&overflow), Err(Errno::EINVAL));
    }

    #[test]
    fn utsname_and_rlimit64_encodings_match_linux_uapi() {
        let uts = encode_linux_aarch64_utsname();
        assert_eq!(uts.len(), 390);
        assert_eq!(&uts[0..6], b"Linux\0");
        assert_eq!(&uts[65..73], b"qyronex\0");
        assert_eq!(&uts[130..145], b"6.12.0-qyronex\0");
        assert_eq!(&uts[260..268], b"aarch64\0");

        let x86_uts = encode_linux_x86_64_utsname();
        assert_eq!(&x86_uts[260..267], b"x86_64\0");

        assert_eq!(
            decode_arch_prctl(ARCH_SET_FS as u64, 0x0000_7fff_ffff_e000),
            Ok(ArchPrctlOp::SetFs(0x0000_7fff_ffff_e000))
        );
        assert_eq!(
            decode_arch_prctl(ARCH_SET_FS as u64, X86_64_CANONICAL_USER_LIMIT),
            Err(Errno::EPERM)
        );
        assert_eq!(decode_arch_prctl(0x9999, 0), Err(Errno::EINVAL));

        assert_eq!(decode_rlimit_resource(3), Ok(RlimitResource::Stack));
        assert_eq!(decode_rlimit_resource(7), Ok(RlimitResource::Nofile));
        assert_eq!(decode_rlimit_resource(16), Err(Errno::EINVAL));

        let stack_limit = default_rlimit64(RlimitResource::Stack);
        assert_eq!(
            Rlimit64::from_le_bytes(stack_limit.to_le_bytes()).validate(),
            Ok(stack_limit)
        );
        assert_eq!(Rlimit64::new(64, 32).validate(), Err(Errno::EINVAL));
    }

    #[test]
    fn winsize_and_termios_encodings_preserve_serial_console_defaults() {
        let ws = WinSize::default_serial();
        assert_eq!(ws.ws_row, 24);
        assert_eq!(ws.ws_col, 80);
        assert_eq!(WinSize::from_le_bytes(ws.to_le_bytes()), ws);

        let termios = encode_default_serial_termios();
        assert_eq!(termios.len(), KERNEL_TERMIOS_BYTES);
        assert_eq!(
            u32::from_le_bytes([termios[0], termios[1], termios[2], termios[3]]),
            0x0500
        );
        assert_eq!(
            u32::from_le_bytes([termios[12], termios[13], termios[14], termios[15]]),
            0x803b
        );
    }
}
