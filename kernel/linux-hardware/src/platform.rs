// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;
use kernal_linux_systemd::RebootAction;

/// Linux `<linux/rtc.h>` ioctl numbers (AArch64 little-endian ABI).
pub const RTC_AIE_ON: u64 = 0x7001;
pub const RTC_AIE_OFF: u64 = 0x7002;
pub const RTC_ALM_SET: u64 = 0x4024_7007;
pub const RTC_ALM_READ: u64 = 0x8024_7008;
pub const RTC_RD_TIME: u64 = 0x8024_7009;
pub const RTC_SET_TIME: u64 = 0x4024_700a;

/// Linux `<linux/watchdog.h>` ioctl numbers.
pub const WDIOC_GETSUPPORT: u64 = 0x8028_5700;
pub const WDIOC_KEEPALIVE: u64 = 0x8004_5705;
pub const WDIOC_SETTIMEOUT: u64 = 0xc004_5706;
pub const WDIOC_GETTIMEOUT: u64 = 0x8004_5707;
pub const WDIOC_GETTIMELEFT: u64 = 0x8004_570a;

pub const RTC_TIME_BYTES: usize = 36;

/// Linux `struct rtc_time` (`int` x 9 = 36 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtcTime {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,  // 0..=11
    pub year: i32, // years since 1900
    pub wday: i32,
    pub yday: i32,
    pub isdst: i32,
}

impl RtcTime {
    pub fn validate(self) -> Result<(), Errno> {
        if !(0..=59).contains(&self.sec)
            || !(0..=59).contains(&self.min)
            || !(0..=23).contains(&self.hour)
            || !(0..=11).contains(&self.mon)
            || self.year < 70
        {
            return Err(Errno::EINVAL);
        }
        let full_year = self.year + 1900;
        let max_day = days_in_month(full_year, self.mon as u8) as i32;
        if !(1..=max_day).contains(&self.mday) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    pub fn to_epoch_seconds(self) -> Result<u64, Errno> {
        self.validate()?;
        let full_year = self.year + 1900;
        let mut days = 0i64;
        for y in 1970..full_year {
            days += if is_leap_year(y) { 366 } else { 365 };
        }
        for m in 0..(self.mon as u8) {
            days += i64::from(days_in_month(full_year, m));
        }
        days += i64::from(self.mday - 1);
        let secs = days * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.min) * 60
            + i64::from(self.sec);
        u64::try_from(secs).map_err(|_| Errno::EINVAL)
    }

    pub fn from_epoch_seconds(epoch: u64) -> Self {
        let mut days = (epoch / 86_400) as i64;
        let rem = (epoch % 86_400) as i32;
        let wday = ((days + 4).rem_euclid(7)) as i32; // 1970-01-01 was Thursday (4).
        let hour = rem / 3_600;
        let min = (rem % 3_600) / 60;
        let sec = rem % 60;

        let mut year = 1970i32;
        loop {
            let ydays = if is_leap_year(year) { 366 } else { 365 };
            if days < ydays {
                break;
            }
            days -= ydays;
            year += 1;
        }
        let yday = days as i32;
        let mut mon = 0u8;
        while mon < 11 {
            let mdays = i64::from(days_in_month(year, mon));
            if days < mdays {
                break;
            }
            days -= mdays;
            mon += 1;
        }
        Self {
            sec,
            min,
            hour,
            mday: (days + 1) as i32,
            mon: i32::from(mon),
            year: year - 1900,
            wday,
            yday,
            isdst: 0,
        }
    }

    pub fn encode(self) -> [u8; RTC_TIME_BYTES] {
        let mut out = [0u8; RTC_TIME_BYTES];
        let vals = [
            self.sec, self.min, self.hour, self.mday, self.mon, self.year, self.wday, self.yday,
            self.isdst,
        ];
        for (idx, val) in vals.into_iter().enumerate() {
            out[idx * 4..(idx + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Errno> {
        if raw.len() != RTC_TIME_BYTES {
            return Err(Errno::EINVAL);
        }
        let mut vals = [0i32; 9];
        for (idx, slot) in vals.iter_mut().enumerate() {
            *slot = i32::from_le_bytes([
                raw[idx * 4],
                raw[idx * 4 + 1],
                raw[idx * 4 + 2],
                raw[idx * 4 + 3],
            ]);
        }
        let t = Self {
            sec: vals[0],
            min: vals[1],
            hour: vals[2],
            mday: vals[3],
            mon: vals[4],
            year: vals[5],
            wday: vals[6],
            yday: vals[7],
            isdst: vals[8],
        };
        t.validate()?;
        Ok(t)
    }
}

const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

const fn days_in_month(year: i32, mon: u8) -> u8 {
    match mon {
        0 | 2 | 4 | 6 | 7 | 9 | 11 => 31,
        3 | 5 | 8 | 10 => 30,
        1 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// ARM PrimeCell PL031 Real-Time Clock register/alarm state (`DR`, `MR`, `LR`, `CR`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtcPl031 {
    pub dr_seconds: u64,
    pub mr_alarm_seconds: u64,
    pub alarm_enabled: bool,
    pub enabled: bool,
}

impl Default for RtcPl031 {
    fn default() -> Self {
        Self::new(1_784_000_000) // ~2026 baseline epoch matching Debian 13 snapshot timeline
    }
}

impl RtcPl031 {
    pub const fn new(initial_epoch_seconds: u64) -> Self {
        Self {
            dr_seconds: initial_epoch_seconds,
            mr_alarm_seconds: 0,
            alarm_enabled: false,
            enabled: true,
        }
    }

    pub fn tick_seconds(&mut self, delta: u64) -> bool {
        if !self.enabled {
            return false;
        }
        self.dr_seconds = self.dr_seconds.saturating_add(delta);
        self.alarm_enabled && self.dr_seconds >= self.mr_alarm_seconds
    }

    pub fn read_time(&self) -> RtcTime {
        RtcTime::from_epoch_seconds(self.dr_seconds)
    }

    pub fn set_time(&mut self, cap: Capability, time: RtcTime) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EACCES);
        }
        self.dr_seconds = time.to_epoch_seconds()?;
        Ok(())
    }

    pub fn set_alarm(&mut self, cap: Capability, time: RtcTime) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EACCES);
        }
        self.mr_alarm_seconds = time.to_epoch_seconds()?;
        Ok(())
    }
}

/// Hardware watchdog device (`/dev/watchdog`) enforcing magic-close semantics & reset action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogDevice {
    pub active: bool,
    pub timeout_secs: u32,
    pub remaining_secs: u32,
    pub nowayout: bool,
    pub magic_close_armed: bool,
    pub triggered_resets: u32,
}

impl Default for WatchdogDevice {
    fn default() -> Self {
        Self::new(60, false)
    }
}

impl WatchdogDevice {
    pub const fn new(timeout_secs: u32, nowayout: bool) -> Self {
        let clamped = if timeout_secs == 0 { 1 } else { timeout_secs };
        Self {
            active: false,
            timeout_secs: clamped,
            remaining_secs: clamped,
            nowayout,
            magic_close_armed: false,
            triggered_resets: 0,
        }
    }

    pub fn start(&mut self, cap: Capability) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(Errno::EACCES);
        }
        self.active = true;
        self.remaining_secs = self.timeout_secs;
        self.magic_close_armed = false;
        Ok(())
    }

    pub fn keepalive(&mut self, cap: Capability) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(Errno::EACCES);
        }
        if !self.active {
            return Err(Errno::EINVAL);
        }
        self.remaining_secs = self.timeout_secs;
        Ok(())
    }

    pub fn set_timeout(&mut self, cap: Capability, secs: u32) -> Result<u32, Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EACCES);
        }
        if !(1..=65_535).contains(&secs) {
            return Err(Errno::EINVAL);
        }
        self.timeout_secs = secs;
        self.remaining_secs = secs;
        Ok(secs)
    }

    pub fn write_ping(&mut self, cap: Capability, data: &[u8]) -> Result<(), Errno> {
        self.keepalive(cap)?;
        self.magic_close_armed = data.contains(&b'V');
        Ok(())
    }

    pub fn release(&mut self) -> Result<(), Errno> {
        if !self.active {
            return Ok(());
        }
        if !self.nowayout && self.magic_close_armed {
            self.active = false;
            self.magic_close_armed = false;
            return Ok(());
        }
        // Keep running when closed without magic `'V'` (or when `nowayout` is enabled).
        self.magic_close_armed = false;
        Ok(())
    }

    pub fn tick_seconds(&mut self, elapsed: u32) -> Option<RebootAction> {
        if !self.active {
            return None;
        }
        if elapsed >= self.remaining_secs {
            self.remaining_secs = 0;
            self.triggered_resets = self.triggered_resets.saturating_add(1);
            return Some(RebootAction::Restart);
        }
        self.remaining_secs -= elapsed;
        None
    }
}

/// CPU topology and thermal zone telemetry exposed via Linux sysfs nodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformTelemetry {
    pub online_cpus: u8,
    pub max_cpus: u8,
    pub thermal_millicelsius: i32,
    pub critical_millicelsius: i32,
    pub ac_online: bool,
}

impl Default for PlatformTelemetry {
    fn default() -> Self {
        Self {
            online_cpus: 1,
            max_cpus: 4,
            thermal_millicelsius: 42_000,
            critical_millicelsius: 105_000,
            ac_online: true,
        }
    }
}

impl PlatformTelemetry {
    pub const fn thermal_throttled(&self) -> bool {
        self.thermal_millicelsius >= self.critical_millicelsius - 10_000
    }
}

/// Cryptographic ARX-permutation entropy pool requiring >= 256 bits of non-zero seed before use.
#[derive(Clone, Debug)]
pub struct HardwareEntropyPool {
    state: [u32; 16],
    seeded: bool,
    entropy_bits: u32,
    reseed_counter: u64,
}

impl Default for HardwareEntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareEntropyPool {
    pub const fn new() -> Self {
        // ChaCha-style constants in words 0..4; remains unusable until 256-bit seed arrives.
        let mut state = [0u32; 16];
        state[0] = 0x6170_7865;
        state[1] = 0x3320_646e;
        state[2] = 0x7962_2d32;
        state[3] = 0x6b20_6574;
        Self {
            state,
            seeded: false,
            entropy_bits: 0,
            reseed_counter: 0,
        }
    }

    pub const fn is_seeded(&self) -> bool {
        self.seeded
    }

    pub const fn entropy_bits(&self) -> u32 {
        self.entropy_bits
    }

    pub const fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// Mixes hardware/DTB entropy bytes and transitions to `seeded = true` once >= 256 bits arrive.
    pub fn mix_seed(&mut self, seed: &[u8]) -> Result<(), Errno> {
        if seed.is_empty() || seed.iter().all(|b| *b == 0) {
            return Err(Errno::EINVAL);
        }
        for (i, chunk) in seed.chunks(4).enumerate() {
            let mut word_bytes = [0u8; 4];
            word_bytes[..chunk.len()].copy_from_slice(chunk);
            let slot = 4 + (i % 8);
            self.state[slot] ^= u32::from_le_bytes(word_bytes);
            self.permute();
        }
        let added_bits = u32::try_from(seed.len().saturating_mul(8)).unwrap_or(u32::MAX);
        self.entropy_bits = self.entropy_bits.saturating_add(added_bits);
        if self.entropy_bits >= 256 {
            self.seeded = true;
            self.reseed_counter = self.reseed_counter.saturating_add(1);
        }
        Ok(())
    }

    /// Fills `out` with forward-secure random bytes, failing closed with `EAGAIN` if unseeded.
    pub fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Errno> {
        if !self.seeded {
            return Err(Errno::EAGAIN);
        }
        let mut offset = 0usize;
        while offset < out.len() {
            let block = self.block_bytes();
            let take = core::cmp::min(out.len() - offset, block.len());
            out[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }
        // Backtracking resistance: erase key words with newly derived state.
        let ratcheted = self.block_bytes();
        for i in 0..8 {
            self.state[4 + i] ^= u32::from_le_bytes([
                ratcheted[i * 4],
                ratcheted[i * 4 + 1],
                ratcheted[i * 4 + 2],
                ratcheted[i * 4 + 3],
            ]);
        }
        self.permute();
        Ok(())
    }

    fn permute(&mut self) {
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
        for _ in 0..10 {
            Self::quarter_round(&mut self.state, 0, 4, 8, 12);
            Self::quarter_round(&mut self.state, 1, 5, 9, 13);
            Self::quarter_round(&mut self.state, 2, 6, 10, 14);
            Self::quarter_round(&mut self.state, 3, 7, 11, 15);
            Self::quarter_round(&mut self.state, 0, 5, 10, 15);
            Self::quarter_round(&mut self.state, 1, 6, 11, 12);
            Self::quarter_round(&mut self.state, 2, 7, 8, 13);
            Self::quarter_round(&mut self.state, 3, 4, 9, 14);
        }
    }

    fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    }

    fn block_bytes(&mut self) -> [u8; 64] {
        let initial = self.state;
        self.permute();
        let mut out = [0u8; 64];
        for (i, word) in self.state.iter().enumerate() {
            let mixed = word.wrapping_add(initial[i]);
            out[i * 4..(i + 1) * 4].copy_from_slice(&mixed.to_le_bytes());
        }
        out
    }
}
