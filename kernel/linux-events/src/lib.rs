// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 35 — Linux event, notification, and modern descriptor APIs:
//! `epoll` (`epoll_create1`, `epoll_ctl`, `epoll_pwait`), `eventfd2`, `timerfd`
//! (`timerfd_create`, `timerfd_settime`, `timerfd_gettime`), `signalfd4`, `inotify`
//! (`inotify_init1`, `inotify_add_watch`, `inotify_rm_watch`), `memfd_create` with
//! `F_ADD_SEALS`/`F_GET_SEALS`, `pidfd_open`, and `close_range`.

use kernal_linux_abi::Errno;

pub const O_NONBLOCK: u32 = 0o000_4000; // 0x800
pub const O_CLOEXEC: u32 = 0o200_0000; // 0x80000

/// `epoll` constants (`<sys/epoll.h>`).
pub const EPOLL_CLOEXEC: u32 = O_CLOEXEC;
pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;

/// `eventfd2` flags (`<sys/eventfd.h>`).
pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_NONBLOCK: u32 = O_NONBLOCK;
pub const EFD_CLOEXEC: u32 = O_CLOEXEC;

/// `timerfd` constants (`<sys/timerfd.h>`).
pub const CLOCK_REALTIME: u32 = 0;
pub const CLOCK_MONOTONIC: u32 = 1;
pub const CLOCK_BOOTTIME: u32 = 7;
pub const TFD_TIMER_ABSTIME: u32 = 1;
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 2;
pub const TFD_NONBLOCK: u32 = O_NONBLOCK;
pub const TFD_CLOEXEC: u32 = O_CLOEXEC;

/// `signalfd4` flags (`<sys/signalfd.h>`).
pub const SFD_NONBLOCK: u32 = O_NONBLOCK;
pub const SFD_CLOEXEC: u32 = O_CLOEXEC;
pub const SIGNALFD_SIGINFO_BYTES: usize = 128;

/// `inotify` constants (`<sys/inotify.h>`).
pub const IN_NONBLOCK: u32 = O_NONBLOCK;
pub const IN_CLOEXEC: u32 = O_CLOEXEC;
pub const IN_MODIFY: u32 = 0x0000_0002;
pub const IN_ATTRIB: u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE: u32 = 0x0000_0200;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_MOVE_SELF: u32 = 0x0000_0800;
pub const IN_ALL_EVENTS: u32 = 0x0000_0fff;
pub const INOTIFY_PATH_CAP: usize = 256;
pub const MAX_INOTIFY_WATCHES: usize = 64;

/// `memfd_create` and sealing constants (`<linux/memfd.h>`, `<linux/fcntl.h>`).
pub const MFD_CLOEXEC: u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;
pub const MFD_NOEXEC_SEAL: u32 = 0x0008;
pub const MFD_EXEC: u32 = 0x0010;

pub const F_ADD_SEALS: u32 = 1033;
pub const F_GET_SEALS: u32 = 1034;
pub const F_SEAL_SEAL: u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW: u32 = 0x0004;
pub const F_SEAL_WRITE: u32 = 0x0008;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
const VALID_SEALS_MASK: u32 =
    F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;

/// `close_range(2)` flags (`<linux/close_range.h>`).
pub const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

/// One ready `epoll_event` (`events: u32`, `data: u64`).
/// On AArch64, `struct epoll_event` is 16 bytes (4-byte `events`, 4-byte pad, 8-byte `data`);
/// on x86_64 (`__attribute__((packed))`), it is 12 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

impl EpollEvent {
    pub const fn to_aarch64_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        let e = self.events.to_le_bytes();
        let d = self.data.to_le_bytes();
        out[0] = e[0];
        out[1] = e[1];
        out[2] = e[2];
        out[3] = e[3];
        out[8] = d[0];
        out[9] = d[1];
        out[10] = d[2];
        out[11] = d[3];
        out[12] = d[4];
        out[13] = d[5];
        out[14] = d[6];
        out[15] = d[7];
        out
    }

    pub const fn from_aarch64_bytes(raw: [u8; 16]) -> Self {
        let events = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let data = u64::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        Self { events, data }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpollWatch {
    live: bool,
    target_fd: i32,
    events: u32,
    data: u64,
    armed: bool,
    last_edge_mask: u32,
}

impl EpollWatch {
    const EMPTY: Self = Self {
        live: false,
        target_fd: -1,
        events: 0,
        data: 0,
        armed: false,
        last_edge_mask: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InotifyWatch {
    live: bool,
    wd: i32,
    mask: u32,
    path: [u8; INOTIFY_PATH_CAP],
    path_len: usize,
}

impl InotifyWatch {
    const EMPTY: Self = Self {
        live: false,
        wd: 0,
        mask: 0,
        path: [0u8; INOTIFY_PATH_CAP],
        path_len: 0,
    };
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy)]
pub enum EventObject<const MEMFD_CAP: usize> {
    Empty,
    Epoll {
        cloexec: bool,
        watches: [EpollWatch; 32],
    },
    EventFd {
        counter: u64,
        semaphore: bool,
        nonblocking: bool,
        cloexec: bool,
    },
    TimerFd {
        clock_id: u32,
        nonblocking: bool,
        cloexec: bool,
        interval_ns: u64,
        value_ns: u64,
        expirations: u64,
        deadline_ns: Option<u64>,
    },
    SignalFd {
        mask: u64,
        nonblocking: bool,
        cloexec: bool,
        pending_mask: u64,
        last_sender_pid: u32,
        last_sender_uid: u32,
    },
    Inotify {
        nonblocking: bool,
        cloexec: bool,
        next_wd: i32,
        watches: [InotifyWatch; MAX_INOTIFY_WATCHES],
        queue: [u8; 1024],
        queue_len: usize,
    },
    MemFd {
        cloexec: bool,
        allow_sealing: bool,
        seals: u32,
        offset: usize,
        len: usize,
        data: [u8; MEMFD_CAP],
    },
    PidFd {
        target_pid: u32,
        nonblocking: bool,
        cloexec: bool,
        exited: bool,
    },
}

/// Bounded table of Step-35 event, notification, memfd, and pidfd descriptors.
pub struct EventTable<const MAX_FDS: usize, const MEMFD_CAP: usize> {
    slots: [EventObject<MEMFD_CAP>; MAX_FDS],
}

impl<const MAX_FDS: usize, const MEMFD_CAP: usize> Default for EventTable<MAX_FDS, MEMFD_CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_FDS: usize, const MEMFD_CAP: usize> EventTable<MAX_FDS, MEMFD_CAP> {
    pub const fn new() -> Self {
        Self {
            slots: [EventObject::Empty; MAX_FDS],
        }
    }

    fn alloc_slot(&mut self, obj: EventObject<MEMFD_CAP>) -> Result<usize, Errno> {
        let (idx, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| matches!(s, EventObject::Empty))
            .ok_or(Errno::EMFILE)?;
        *slot = obj;
        Ok(idx)
    }

    pub fn close(&mut self, id: usize) -> Result<(), Errno> {
        let slot = self.slots.get_mut(id).ok_or(Errno::EBADF)?;
        if matches!(slot, EventObject::Empty) {
            return Err(Errno::EBADF);
        }
        *slot = EventObject::Empty;
        Ok(())
    }

    /// Creates an `epoll` instance (`epoll_create1(2)`).
    pub fn epoll_create1(&mut self, flags: u32) -> Result<usize, Errno> {
        if flags & !EPOLL_CLOEXEC != 0 {
            return Err(Errno::EINVAL);
        }
        self.alloc_slot(EventObject::Epoll {
            cloexec: (flags & EPOLL_CLOEXEC) != 0,
            watches: [EpollWatch::EMPTY; 32],
        })
    }

    pub fn epoll_watch_targets(&self, epfd_idx: usize) -> [Option<(i32, u32)>; 32] {
        let mut out = [None; 32];
        if let Some(EventObject::Epoll { watches, .. }) = self.slots.get(epfd_idx) {
            for (i, w) in watches.iter().enumerate() {
                if w.live && w.armed {
                    out[i] = Some((w.target_fd, w.events));
                }
            }
        }
        out
    }

    /// Adds, modifies, or deletes an interest in an `epoll` instance (`epoll_ctl(2)`).
    pub fn epoll_ctl(
        &mut self,
        epfd_idx: usize,
        op: u32,
        target_fd: i32,
        event: Option<EpollEvent>,
    ) -> Result<(), Errno> {
        if target_fd < 0 {
            return Err(Errno::EBADF);
        }
        let slot = self.slots.get_mut(epfd_idx).ok_or(Errno::EBADF)?;
        let EventObject::Epoll { watches, .. } = slot else {
            return Err(Errno::EINVAL);
        };
        match op {
            EPOLL_CTL_ADD => {
                let ev = event.ok_or(Errno::EFAULT)?;
                if watches.iter().any(|w| w.live && w.target_fd == target_fd) {
                    return Err(Errno::EEXIST);
                }
                let free = watches.iter_mut().find(|w| !w.live).ok_or(Errno::ENOSPC)?;
                *free = EpollWatch {
                    live: true,
                    target_fd,
                    events: ev.events,
                    data: ev.data,
                    armed: true,
                    last_edge_mask: 0,
                };
                Ok(())
            }
            EPOLL_CTL_MOD => {
                let ev = event.ok_or(Errno::EFAULT)?;
                let existing = watches
                    .iter_mut()
                    .find(|w| w.live && w.target_fd == target_fd)
                    .ok_or(Errno::ENOENT)?;
                existing.events = ev.events;
                existing.data = ev.data;
                existing.armed = true;
                existing.last_edge_mask = 0;
                Ok(())
            }
            EPOLL_CTL_DEL => {
                let existing = watches
                    .iter_mut()
                    .find(|w| w.live && w.target_fd == target_fd)
                    .ok_or(Errno::ENOENT)?;
                *existing = EpollWatch::EMPTY;
                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    fn collect_external_fds_inner(
        &self,
        epfd_idx: usize,
        fd_base: i32,
        depth: usize,
        visited_mask: &mut u64,
        out: &mut [i32],
        out_len: &mut usize,
    ) {
        if depth >= 4 || epfd_idx >= MAX_FDS {
            return;
        }
        if epfd_idx < 64 {
            let bit = 1u64 << epfd_idx;
            if (*visited_mask & bit) != 0 {
                return;
            }
            *visited_mask |= bit;
        }
        let Some(EventObject::Epoll { watches, .. }) = self.slots.get(epfd_idx) else {
            return;
        };
        for w in watches {
            if !w.live || !w.armed {
                continue;
            }
            let fd = w.target_fd;
            if fd >= fd_base && (fd - fd_base) < (MAX_FDS as i32) {
                let target_idx = (fd - fd_base) as usize;
                if matches!(self.slots.get(target_idx), Some(EventObject::Epoll { .. })) {
                    self.collect_external_fds_inner(
                        target_idx,
                        fd_base,
                        depth + 1,
                        visited_mask,
                        out,
                        out_len,
                    );
                }
            } else if !out[..*out_len].contains(&fd) && *out_len < out.len() {
                out[*out_len] = fd;
                *out_len += 1;
            }
        }
    }

    /// Collects all unique external (non-event-table) target FDs watched by `epfd_idx`
    /// and any nested `epoll` instances up to depth 4, enabling external readiness probing
    /// without holding the event table lock.
    pub fn collect_epoll_external_fds(
        &self,
        epfd_idx: usize,
        fd_base: i32,
        out: &mut [i32],
    ) -> usize {
        let mut visited_mask = 0u64;
        let mut count = 0usize;
        self.collect_external_fds_inner(epfd_idx, fd_base, 0, &mut visited_mask, out, &mut count);
        count
    }

    fn eval_watch_match<F>(
        &self,
        w: &EpollWatch,
        fd_base: i32,
        depth: usize,
        external_readiness: &F,
    ) -> (u32, bool)
    where
        F: Fn(i32) -> u32,
    {
        let ready_mask = if w.target_fd >= fd_base && (w.target_fd - fd_base) < (MAX_FDS as i32) {
            let target_idx = (w.target_fd - fd_base) as usize;
            self.slot_readiness_with(target_idx, fd_base, depth, external_readiness)
        } else {
            external_readiness(w.target_fd)
        };
        let interest = (w.events & !(EPOLLET | EPOLLONESHOT)) | EPOLLERR | EPOLLHUP;
        let matched = ready_mask & interest;
        let trigger = if (w.events & EPOLLET) != 0 {
            (matched & !w.last_edge_mask) != 0
        } else {
            matched != 0
        };
        (matched, trigger)
    }

    fn slot_readiness_with<F>(
        &self,
        idx: usize,
        fd_base: i32,
        depth: usize,
        external_readiness: &F,
    ) -> u32
    where
        F: Fn(i32) -> u32,
    {
        match self.slots.get(idx) {
            Some(EventObject::Epoll { watches, .. }) => {
                if depth >= 4 {
                    return 0;
                }
                for w in watches {
                    if !w.live || !w.armed {
                        continue;
                    }
                    let (_, triggered) =
                        self.eval_watch_match(w, fd_base, depth + 1, external_readiness);
                    if triggered {
                        return EPOLLIN;
                    }
                }
                0
            }
            _ => self.internal_readiness(idx),
        }
    }

    /// Polls an `epoll` instance (`epoll_pwait(2)`), evaluating readiness across internal
    /// event descriptors (including nested `epoll` instances) and an external readiness predicate.
    pub fn epoll_wait<F>(
        &mut self,
        epfd_idx: usize,
        fd_base: i32,
        external_readiness: F,
        out: &mut [EpollEvent],
    ) -> Result<usize, Errno>
    where
        F: Fn(i32) -> u32,
    {
        self.epoll_wait_with_fds(epfd_idx, fd_base, external_readiness, out, &mut [])
    }

    /// Polls `epfd_idx`, writing matched events to `out` and (when non-empty) target FDs to `out_fds`.
    pub fn epoll_wait_with_fds<F>(
        &mut self,
        epfd_idx: usize,
        fd_base: i32,
        external_readiness: F,
        out: &mut [EpollEvent],
        out_fds: &mut [i32],
    ) -> Result<usize, Errno>
    where
        F: Fn(i32) -> u32,
    {
        if out.is_empty() {
            return Err(Errno::EINVAL);
        }
        // Snapshot the watch list from `epfd_idx`.
        let mut watches = match self.slots.get(epfd_idx).ok_or(Errno::EBADF)? {
            EventObject::Epoll { watches, .. } => *watches,
            _ => return Err(Errno::EINVAL),
        };

        let mut count = 0usize;
        for w in &mut watches {
            if !w.live || !w.armed || count >= out.len() {
                continue;
            }
            let (matched, trigger) = self.eval_watch_match(w, fd_base, 0, &external_readiness);
            if (w.events & EPOLLET) != 0 {
                w.last_edge_mask = matched;
            }
            if trigger {
                out[count] = EpollEvent {
                    events: matched,
                    data: w.data,
                };
                if count < out_fds.len() {
                    out_fds[count] = w.target_fd;
                }
                count += 1;
                if (w.events & EPOLLONESHOT) != 0 {
                    w.armed = false;
                }
            }
        }

        if let Some(EventObject::Epoll {
            watches: stored, ..
        }) = self.slots.get_mut(epfd_idx)
        {
            *stored = watches;
        }
        Ok(count)
    }

    /// Clears specific edge-detection bits in `epfd_idx` for `target_fd` after a one-shot
    /// readiness change (such as `/proc/self/mountinfo` generation bump) has been consumed.
    pub fn clear_watch_edge_bits(&mut self, epfd_idx: usize, target_fd: i32, bits: u32) {
        if let Some(EventObject::Epoll { watches, .. }) = self.slots.get_mut(epfd_idx) {
            for w in watches {
                if w.live && w.target_fd == target_fd {
                    w.last_edge_mask &= !bits;
                }
            }
        }
    }

    /// Returns the Linux `POLL*`/`EPOLL*` readiness bitmask for an internal slot, supporting
    /// nested `epoll` instances via `external_readiness`.
    pub fn poll_readiness_with<F>(
        &self,
        idx: usize,
        fd_base: i32,
        external_readiness: F,
    ) -> Result<u32, Errno>
    where
        F: Fn(i32) -> u32,
    {
        let slot = self.slots.get(idx).ok_or(Errno::EBADF)?;
        if matches!(slot, EventObject::Empty) {
            return Err(Errno::EBADF);
        }
        Ok(self.slot_readiness_with(idx, fd_base, 0, &external_readiness))
    }

    /// Returns the Linux `POLL*`/`EPOLL*` readiness bitmask for an event/timer/signal/inotify/memfd/pidfd slot.
    pub fn poll_readiness(&self, idx: usize) -> Result<u32, Errno> {
        self.poll_readiness_with(idx, 0, |_| 0)
    }

    fn internal_readiness(&self, idx: usize) -> u32 {
        match self.slots.get(idx) {
            Some(EventObject::EventFd { counter, .. }) => {
                let mut mask = 0;
                if *counter > 0 {
                    mask |= EPOLLIN;
                }
                if *counter < u64::MAX - 1 {
                    mask |= EPOLLOUT;
                }
                mask
            }
            Some(EventObject::TimerFd { expirations, .. }) if *expirations > 0 => EPOLLIN,
            Some(EventObject::SignalFd {
                mask, pending_mask, ..
            }) if (*mask & *pending_mask) != 0 => EPOLLIN,
            Some(EventObject::Inotify { queue_len, .. }) if *queue_len > 0 => EPOLLIN,
            Some(EventObject::MemFd { .. }) => EPOLLIN | EPOLLOUT,
            Some(EventObject::PidFd { exited, .. }) if *exited => EPOLLIN,
            _ => 0,
        }
    }

    /// Creates an `eventfd2(2)` descriptor.
    pub fn eventfd2(&mut self, initval: u32, flags: u32) -> Result<usize, Errno> {
        let valid = EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC;
        if flags & !valid != 0 {
            return Err(Errno::EINVAL);
        }
        self.alloc_slot(EventObject::EventFd {
            counter: u64::from(initval),
            semaphore: (flags & EFD_SEMAPHORE) != 0,
            nonblocking: (flags & EFD_NONBLOCK) != 0,
            cloexec: (flags & EFD_CLOEXEC) != 0,
        })
    }

    /// Creates a `timerfd_create(2)` descriptor.
    pub fn timerfd_create(&mut self, clock_id: u32, flags: u32) -> Result<usize, Errno> {
        if !matches!(clock_id, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME) {
            return Err(Errno::EINVAL);
        }
        if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
            return Err(Errno::EINVAL);
        }
        self.alloc_slot(EventObject::TimerFd {
            clock_id,
            nonblocking: (flags & TFD_NONBLOCK) != 0,
            cloexec: (flags & TFD_CLOEXEC) != 0,
            interval_ns: 0,
            value_ns: 0,
            expirations: 0,
            deadline_ns: None,
        })
    }

    fn clock_now_for(clock_id: u32, now_mono_ns: u64, now_real_ns: u64) -> u64 {
        if clock_id == CLOCK_REALTIME {
            now_real_ns
        } else {
            now_mono_ns
        }
    }

    fn advance_timer(
        interval_ns: u64,
        expirations: &mut u64,
        deadline_ns: &mut Option<u64>,
        now_ns: u64,
    ) {
        let Some(dl) = *deadline_ns else {
            return;
        };
        if now_ns < dl {
            return;
        }
        let elapsed = now_ns - dl;
        if let Some(extra) = elapsed.checked_div(interval_ns) {
            *expirations = expirations.saturating_add(1).saturating_add(extra);
            *deadline_ns = Some(dl.saturating_add((extra + 1).saturating_mul(interval_ns)));
        } else {
            *expirations = expirations.saturating_add(1);
            *deadline_ns = None;
        }
    }

    /// Refreshes all armed timers against the current monotonic and realtime clocks.
    pub fn refresh_timers(&mut self, now_mono_ns: u64, now_real_ns: u64) {
        for slot in &mut self.slots {
            if let EventObject::TimerFd {
                clock_id,
                interval_ns,
                expirations,
                deadline_ns,
                ..
            } = slot
            {
                let now = Self::clock_now_for(*clock_id, now_mono_ns, now_real_ns);
                Self::advance_timer(*interval_ns, expirations, deadline_ns, now);
            }
        }
    }

    /// Arms or disarms a `timerfd` (`timerfd_settime(2)`), returning `(old_interval_ns, old_value_ns)`.
    pub fn timerfd_settime(
        &mut self,
        idx: usize,
        flags: u32,
        new_interval_ns: u64,
        new_value_ns: u64,
    ) -> Result<(u64, u64), Errno> {
        self.timerfd_settime_inner(idx, flags, new_interval_ns, new_value_ns, None)
    }

    /// Arms or disarms a `timerfd` against live monotonic/realtime clocks.
    pub fn timerfd_settime_clocks(
        &mut self,
        idx: usize,
        flags: u32,
        new_interval_ns: u64,
        new_value_ns: u64,
        now_mono_ns: u64,
        now_real_ns: u64,
    ) -> Result<(u64, u64), Errno> {
        self.timerfd_settime_inner(
            idx,
            flags,
            new_interval_ns,
            new_value_ns,
            Some((now_mono_ns, now_real_ns)),
        )
    }

    fn timerfd_settime_inner(
        &mut self,
        idx: usize,
        flags: u32,
        new_interval_ns: u64,
        new_value_ns: u64,
        now_clocks: Option<(u64, u64)>,
    ) -> Result<(u64, u64), Errno> {
        if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
            return Err(Errno::EINVAL);
        }
        let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
        let EventObject::TimerFd {
            clock_id,
            interval_ns,
            value_ns,
            expirations,
            deadline_ns,
            ..
        } = slot
        else {
            return Err(Errno::EINVAL);
        };
        if (flags & TFD_TIMER_CANCEL_ON_SET) != 0 && (flags & TFD_TIMER_ABSTIME) == 0 {
            return Err(Errno::EINVAL);
        }
        let old = if let Some((mono, real)) = now_clocks {
            let now = Self::clock_now_for(*clock_id, mono, real);
            Self::advance_timer(*interval_ns, expirations, deadline_ns, now);
            let rem = deadline_ns.map_or(0, |dl| dl.saturating_sub(now));
            (*interval_ns, rem)
        } else {
            (*interval_ns, *value_ns)
        };
        *interval_ns = new_interval_ns;
        *value_ns = new_value_ns;
        if let Some((mono, real)) = now_clocks {
            let now = Self::clock_now_for(*clock_id, mono, real);
            *expirations = 0;
            if new_value_ns == 0 {
                *deadline_ns = None;
            } else {
                let dl = if (flags & TFD_TIMER_ABSTIME) != 0 {
                    new_value_ns
                } else {
                    now.saturating_add(new_value_ns)
                };
                *deadline_ns = Some(dl);
                Self::advance_timer(new_interval_ns, expirations, deadline_ns, now);
            }
        } else {
            *deadline_ns = None;
            *expirations = u64::from(new_value_ns > 0);
        }
        Ok(old)
    }

    pub fn timerfd_gettime(&self, idx: usize) -> Result<(u64, u64), Errno> {
        self.timerfd_gettime_clocks(idx, 0, 0, false)
    }

    pub fn timerfd_gettime_live(
        &self,
        idx: usize,
        now_mono_ns: u64,
        now_real_ns: u64,
    ) -> Result<(u64, u64), Errno> {
        self.timerfd_gettime_clocks(idx, now_mono_ns, now_real_ns, true)
    }

    fn timerfd_gettime_clocks(
        &self,
        idx: usize,
        now_mono_ns: u64,
        now_real_ns: u64,
        use_live_clocks: bool,
    ) -> Result<(u64, u64), Errno> {
        let slot = self.slots.get(idx).ok_or(Errno::EBADF)?;
        let EventObject::TimerFd {
            clock_id,
            interval_ns,
            value_ns,
            deadline_ns,
            ..
        } = slot
        else {
            return Err(Errno::EINVAL);
        };
        let rem = if use_live_clocks {
            let now = Self::clock_now_for(*clock_id, now_mono_ns, now_real_ns);
            deadline_ns.map_or(0, |dl| dl.saturating_sub(now))
        } else {
            *value_ns
        };
        Ok((*interval_ns, rem))
    }

    /// Creates or updates a `signalfd4(2)` descriptor (`fd == -1` creates a new one).
    pub fn signalfd4(
        &mut self,
        existing_idx: Option<usize>,
        mask: u64,
        flags: u32,
    ) -> Result<usize, Errno> {
        if flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
            return Err(Errno::EINVAL);
        }
        if let Some(idx) = existing_idx {
            let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
            let EventObject::SignalFd {
                mask: stored_mask, ..
            } = slot
            else {
                return Err(Errno::EINVAL);
            };
            *stored_mask = mask;
            return Ok(idx);
        }
        self.alloc_slot(EventObject::SignalFd {
            mask,
            nonblocking: (flags & SFD_NONBLOCK) != 0,
            cloexec: (flags & SFD_CLOEXEC) != 0,
            pending_mask: 0,
            last_sender_pid: 1,
            last_sender_uid: 0,
        })
    }

    /// Queues a signal bit (`1..=64`) into all matching `SignalFd` descriptors.
    pub fn notify_signal(&mut self, signo: u32, sender_pid: u32, sender_uid: u32) {
        for idx in 0..self.slots.len() {
            self.notify_signal_slot(idx, signo, sender_pid, sender_uid);
        }
    }

    pub fn notify_signal_slot(&mut self, idx: usize, signo: u32, sender_pid: u32, sender_uid: u32) {
        if !(1..=64).contains(&signo) {
            return;
        }
        let bit = 1u64 << (signo - 1);
        if let Some(EventObject::SignalFd {
            mask,
            pending_mask,
            last_sender_pid,
            last_sender_uid,
            ..
        }) = self.slots.get_mut(idx)
            && (*mask & bit) != 0
        {
            *pending_mask |= bit;
            *last_sender_pid = sender_pid;
            *last_sender_uid = sender_uid;
        }
    }

    /// Creates an `inotify_init1(2)` instance.
    pub fn inotify_init1(&mut self, flags: u32) -> Result<usize, Errno> {
        if flags & !(IN_NONBLOCK | IN_CLOEXEC) != 0 {
            return Err(Errno::EINVAL);
        }
        self.alloc_slot(EventObject::Inotify {
            nonblocking: (flags & IN_NONBLOCK) != 0,
            cloexec: (flags & IN_CLOEXEC) != 0,
            next_wd: 1,
            watches: [InotifyWatch::EMPTY; MAX_INOTIFY_WATCHES],
            queue: [0u8; 1024],
            queue_len: 0,
        })
    }

    /// Adds or updates a path watch on an `inotify` descriptor (`inotify_add_watch(2)`).
    pub fn inotify_add_watch(&mut self, idx: usize, path: &[u8], mask: u32) -> Result<i32, Errno> {
        if path.is_empty() || (mask & IN_ALL_EVENTS) == 0 {
            return Err(Errno::EINVAL);
        }
        if path.len() > INOTIFY_PATH_CAP {
            return Err(Errno::ENAMETOOLONG);
        }
        let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
        let EventObject::Inotify {
            next_wd, watches, ..
        } = slot
        else {
            return Err(Errno::EINVAL);
        };
        if let Some(existing) = watches
            .iter_mut()
            .find(|w| w.live && &w.path[..w.path_len] == path)
        {
            existing.mask = mask;
            return Ok(existing.wd);
        }
        let free = watches.iter_mut().find(|w| !w.live).ok_or(Errno::ENOSPC)?;
        let wd = *next_wd;
        *next_wd = next_wd.saturating_add(1);
        let mut p = [0u8; INOTIFY_PATH_CAP];
        p[..path.len()].copy_from_slice(path);
        *free = InotifyWatch {
            live: true,
            wd,
            mask,
            path: p,
            path_len: path.len(),
        };
        Ok(wd)
    }

    /// Removes a watch descriptor (`inotify_rm_watch(2)`).
    pub fn inotify_rm_watch(&mut self, idx: usize, wd: i32) -> Result<(), Errno> {
        let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
        let EventObject::Inotify { watches, .. } = slot else {
            return Err(Errno::EINVAL);
        };
        let target = watches
            .iter_mut()
            .find(|w| w.live && w.wd == wd)
            .ok_or(Errno::EINVAL)?;
        *target = InotifyWatch::EMPTY;
        Ok(())
    }

    /// Publishes a filesystem event (`IN_CREATE`, `IN_DELETE`, `IN_MOVED_TO`, etc.) to any
    /// matching `inotify` watches.
    pub fn notify_fs_event(&mut self, dir_path: &[u8], name: &[u8], event_mask: u32, cookie: u32) {
        let padded_name_len = if name.is_empty() {
            0
        } else {
            (name.len() + 1 + 3) & !3
        };
        let record_len = 16 + padded_name_len;

        for slot in &mut self.slots {
            let EventObject::Inotify {
                watches,
                queue,
                queue_len,
                ..
            } = slot
            else {
                continue;
            };
            for w in watches.iter() {
                if !w.live || (w.mask & event_mask) == 0 {
                    continue;
                }
                if &w.path[..w.path_len] != dir_path {
                    continue;
                }
                if *queue_len + record_len <= queue.len() {
                    let base = *queue_len;
                    queue[base..base + 4].copy_from_slice(&w.wd.to_le_bytes());
                    queue[base + 4..base + 8].copy_from_slice(&(event_mask & w.mask).to_le_bytes());
                    queue[base + 8..base + 12].copy_from_slice(&cookie.to_le_bytes());
                    queue[base + 12..base + 16]
                        .copy_from_slice(&(padded_name_len as u32).to_le_bytes());
                    if padded_name_len > 0 {
                        for b in &mut queue[base + 16..base + record_len] {
                            *b = 0;
                        }
                        queue[base + 16..base + 16 + name.len()].copy_from_slice(name);
                    }
                    *queue_len += record_len;
                }
            }
        }
    }

    /// Creates an anonymous in-memory file (`memfd_create(2)`).
    pub fn memfd_create(&mut self, name: &[u8], flags: u32) -> Result<usize, Errno> {
        if name.is_empty() || name.len() > 249 {
            return Err(Errno::EINVAL);
        }
        let valid = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL | MFD_EXEC;
        if flags & !valid != 0 {
            return Err(Errno::EINVAL);
        }
        if (flags & MFD_NOEXEC_SEAL != 0) && (flags & MFD_EXEC != 0) {
            return Err(Errno::EINVAL);
        }
        let allow_sealing = (flags & (MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)) != 0;
        self.alloc_slot(EventObject::MemFd {
            cloexec: (flags & (MFD_CLOEXEC | MFD_NOEXEC_SEAL)) != 0,
            allow_sealing,
            seals: if allow_sealing { 0 } else { F_SEAL_SEAL },
            offset: 0,
            len: 0,
            data: [0u8; MEMFD_CAP],
        })
    }

    /// Adds seals to a `memfd` (`fcntl(fd, F_ADD_SEALS, seals)`).
    pub fn memfd_add_seals(&mut self, idx: usize, seals: u32) -> Result<(), Errno> {
        if seals & !VALID_SEALS_MASK != 0 {
            return Err(Errno::EINVAL);
        }
        let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
        let EventObject::MemFd {
            allow_sealing,
            seals: current_seals,
            ..
        } = slot
        else {
            return Err(Errno::EINVAL);
        };
        if !*allow_sealing || (*current_seals & F_SEAL_SEAL) != 0 {
            return Err(Errno::EPERM);
        }
        *current_seals |= seals;
        Ok(())
    }

    /// Queries seals on a `memfd` (`fcntl(fd, F_GET_SEALS)`).
    pub fn memfd_get_seals(&self, idx: usize) -> Result<u32, Errno> {
        let slot = self.slots.get(idx).ok_or(Errno::EBADF)?;
        let EventObject::MemFd { seals, .. } = slot else {
            return Err(Errno::EINVAL);
        };
        Ok(*seals)
    }

    /// Returns the current byte length of a `memfd`, or `0` for non-memfd descriptors.
    pub fn memfd_len(&self, idx: usize) -> usize {
        match self.slots.get(idx) {
            Some(EventObject::MemFd { len, .. }) => *len,
            _ => 0,
        }
    }

    /// Returns a read-only view of a `memfd`'s contents and active seals (`F_SEAL_*`).
    pub fn memfd_snapshot(&self, idx: usize) -> Result<(&[u8], u32), Errno> {
        let slot = self.slots.get(idx).ok_or(Errno::EBADF)?;
        let EventObject::MemFd {
            seals, len, data, ..
        } = slot
        else {
            return Err(Errno::EINVAL);
        };
        Ok((&data[..*len], *seals))
    }

    /// Writes `input` into an existing `memfd` at explicit `file_offset` without mutating its cursor.
    pub fn memfd_write_at(
        &mut self,
        idx: usize,
        file_offset: usize,
        input: &[u8],
    ) -> Result<usize, Errno> {
        let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
        let EventObject::MemFd {
            seals, len, data, ..
        } = slot
        else {
            return Err(Errno::EINVAL);
        };
        if (*seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) != 0 {
            return Err(Errno::EPERM);
        }
        if file_offset >= *len || input.is_empty() {
            return Ok(0);
        }
        let take = (*len - file_offset).min(input.len());
        data[file_offset..file_offset + take].copy_from_slice(&input[..take]);
        Ok(take)
    }

    /// Truncates or extends a `memfd` (`ftruncate(2)`), enforcing `F_SEAL_SHRINK` and `F_SEAL_GROW`.
    pub fn memfd_truncate(&mut self, idx: usize, new_len: usize) -> Result<(), Errno> {
        if new_len > MEMFD_CAP {
            return Err(Errno::ENOSPC);
        }
        let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
        let EventObject::MemFd {
            seals, len, data, ..
        } = slot
        else {
            return Err(Errno::EINVAL);
        };
        if new_len < *len && (*seals & F_SEAL_SHRINK) != 0 {
            return Err(Errno::EPERM);
        }
        if new_len > *len && (*seals & F_SEAL_GROW) != 0 {
            return Err(Errno::EPERM);
        }
        if new_len > *len {
            for b in &mut data[*len..new_len] {
                *b = 0;
            }
        }
        *len = new_len;
        Ok(())
    }

    /// Creates a `pidfd_open(2)` descriptor.
    pub fn pidfd_open(&mut self, pid: u32, flags: u32) -> Result<usize, Errno> {
        if pid == 0 {
            return Err(Errno::EINVAL);
        }
        if flags & !O_NONBLOCK != 0 {
            return Err(Errno::EINVAL);
        }
        self.alloc_slot(EventObject::PidFd {
            target_pid: pid,
            nonblocking: (flags & O_NONBLOCK) != 0,
            cloexec: true,
            exited: false,
        })
    }

    pub fn pidfd_target(&self, idx: usize) -> Result<u32, Errno> {
        let slot = self.slots.get(idx).ok_or(Errno::EBADF)?;
        let EventObject::PidFd { target_pid, .. } = slot else {
            return Err(Errno::EBADF);
        };
        Ok(*target_pid)
    }

    pub fn mark_slot_pidfd_exited(&mut self, idx: usize) {
        if let Some(EventObject::PidFd { exited, .. }) = self.slots.get_mut(idx) {
            *exited = true;
        }
    }

    pub fn mark_pidfd_exited(&mut self, pid: u32) {
        for slot in &mut self.slots {
            if let EventObject::PidFd {
                target_pid, exited, ..
            } = slot
                && *target_pid == pid
            {
                *exited = true;
            }
        }
    }

    /// Reads from an `eventfd`, `timerfd`, `signalfd`, `inotify`, or `memfd` descriptor.
    pub fn read(&mut self, idx: usize, out: &mut [u8]) -> Result<usize, Errno> {
        let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
        match slot {
            EventObject::EventFd {
                counter, semaphore, ..
            } => {
                if out.len() < 8 {
                    return Err(Errno::EINVAL);
                }
                if *counter == 0 {
                    return Err(Errno::EAGAIN);
                }
                let val = if *semaphore {
                    *counter -= 1;
                    1
                } else {
                    let v = *counter;
                    *counter = 0;
                    v
                };
                out[..8].copy_from_slice(&val.to_le_bytes());
                Ok(8)
            }
            EventObject::TimerFd { expirations, .. } => {
                if out.len() < 8 {
                    return Err(Errno::EINVAL);
                }
                if *expirations == 0 {
                    return Err(Errno::EAGAIN);
                }
                let v = *expirations;
                *expirations = 0;
                out[..8].copy_from_slice(&v.to_le_bytes());
                Ok(8)
            }
            EventObject::SignalFd {
                mask,
                pending_mask,
                last_sender_pid,
                last_sender_uid,
                ..
            } => {
                if out.len() < SIGNALFD_SIGINFO_BYTES {
                    return Err(Errno::EINVAL);
                }
                let ready = *mask & *pending_mask;
                if ready == 0 {
                    return Err(Errno::EAGAIN);
                }
                let signo = ready.trailing_zeros() + 1;
                *pending_mask &= !(1u64 << (signo - 1));
                for b in &mut out[..SIGNALFD_SIGINFO_BYTES] {
                    *b = 0;
                }
                out[0..4].copy_from_slice(&signo.to_le_bytes()); // ssi_signo
                out[12..16].copy_from_slice(&last_sender_pid.to_le_bytes()); // ssi_pid
                out[16..20].copy_from_slice(&last_sender_uid.to_le_bytes()); // ssi_uid
                Ok(SIGNALFD_SIGINFO_BYTES)
            }
            EventObject::Inotify {
                queue, queue_len, ..
            } => {
                if *queue_len == 0 {
                    return Err(Errno::EAGAIN);
                }
                if out.len() < 16 {
                    return Err(Errno::EINVAL);
                }
                let take = out.len().min(*queue_len);
                out[..take].copy_from_slice(&queue[..take]);
                let rem = *queue_len - take;
                if rem > 0 {
                    queue.copy_within(take..*queue_len, 0);
                }
                *queue_len = rem;
                Ok(take)
            }
            EventObject::MemFd {
                offset, len, data, ..
            } => {
                if *offset >= *len {
                    return Ok(0);
                }
                let avail = *len - *offset;
                let take = out.len().min(avail);
                out[..take].copy_from_slice(&data[*offset..*offset + take]);
                *offset += take;
                Ok(take)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// Writes to an `eventfd` or `memfd` descriptor.
    pub fn write(&mut self, idx: usize, input: &[u8]) -> Result<usize, Errno> {
        let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
        match slot {
            EventObject::EventFd { counter, .. } => {
                if input.len() < 8 {
                    return Err(Errno::EINVAL);
                }
                let add = u64::from_le_bytes(input[0..8].try_into().unwrap());
                if add == u64::MAX {
                    return Err(Errno::EINVAL);
                }
                let next = counter.checked_add(add).ok_or(Errno::EAGAIN)?;
                if next == u64::MAX {
                    return Err(Errno::EAGAIN);
                }
                *counter = next;
                Ok(8)
            }
            EventObject::MemFd {
                seals,
                offset,
                len,
                data,
                ..
            } => {
                if (*seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) != 0 {
                    return Err(Errno::EPERM);
                }
                let end = offset.checked_add(input.len()).ok_or(Errno::EINVAL)?;
                if end > *len && (*seals & F_SEAL_GROW) != 0 {
                    return Err(Errno::EPERM);
                }
                if end > MEMFD_CAP {
                    return Err(Errno::ENOSPC);
                }
                data[*offset..end].copy_from_slice(input);
                *offset = end;
                if end > *len {
                    *len = end;
                }
                Ok(input.len())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    pub fn lseek(&mut self, idx: usize, offset: i64, whence: i32) -> Result<i64, Errno> {
        let slot = self.slots.get_mut(idx).ok_or(Errno::EBADF)?;
        let EventObject::MemFd {
            offset: cur, len, ..
        } = slot
        else {
            return Err(Errno::ESPIPE);
        };
        let base: i64 = match whence {
            0 => 0,
            1 => *cur as i64,
            2 => *len as i64,
            _ => return Err(Errno::EINVAL),
        };
        let next = base.checked_add(offset).ok_or(Errno::EINVAL)?;
        if next < 0 {
            return Err(Errno::EINVAL);
        }
        *cur = usize::try_from(next).map_err(|_| Errno::EINVAL)?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_epoll_eventfd_timerfd_signalfd_test_passes() {
        let mut table = EventTable::<16, 256>::new();
        let base = 160i32;

        let ep = table.epoll_create1(EPOLL_CLOEXEC).unwrap();
        let efd = table.eventfd2(0, EFD_NONBLOCK | EFD_CLOEXEC).unwrap();
        let tfd = table
            .timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)
            .unwrap();
        let sfd = table
            .signalfd4(None, 1 << (15 - 1), SFD_NONBLOCK | SFD_CLOEXEC)
            .unwrap();

        table
            .epoll_ctl(
                ep,
                EPOLL_CTL_ADD,
                base + (efd as i32),
                Some(EpollEvent {
                    events: EPOLLIN,
                    data: 101,
                }),
            )
            .unwrap();
        table
            .epoll_ctl(
                ep,
                EPOLL_CTL_ADD,
                base + (tfd as i32),
                Some(EpollEvent {
                    events: EPOLLIN,
                    data: 102,
                }),
            )
            .unwrap();
        table
            .epoll_ctl(
                ep,
                EPOLL_CTL_ADD,
                base + (sfd as i32),
                Some(EpollEvent {
                    events: EPOLLIN,
                    data: 103,
                }),
            )
            .unwrap();

        // Trigger eventfd, timerfd, and signalfd (SIGTERM = 15).
        table.write(efd, &3u64.to_le_bytes()).unwrap();
        table.timerfd_settime(tfd, 0, 0, 1_000_000).unwrap();
        table.notify_signal(15, 1, 0);

        let mut events = [EpollEvent { events: 0, data: 0 }; 4];
        let ready = table.epoll_wait(ep, base, |_| 0, &mut events).unwrap();
        assert_eq!(ready, 3);
        assert_eq!(events[0].data, 101);
        assert_eq!(events[1].data, 102);
        assert_eq!(events[2].data, 103);

        // Drain eventfd and signalfd.
        let mut buf8 = [0u8; 8];
        table.read(efd, &mut buf8).unwrap();
        assert_eq!(u64::from_le_bytes(buf8), 3);

        let mut siginfo = [0u8; 128];
        table.read(sfd, &mut siginfo).unwrap();
        assert_eq!(u32::from_le_bytes(siginfo[0..4].try_into().unwrap()), 15);
    }

    #[test]
    fn inotify_create_rename_delete_and_memfd_sealing_work() {
        let mut table = EventTable::<8, 256>::new();
        let ino = table.inotify_init1(IN_NONBLOCK | IN_CLOEXEC).unwrap();
        let wd = table
            .inotify_add_watch(
                ino,
                b"/etc",
                IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO,
            )
            .unwrap();
        assert_eq!(wd, 1);

        table.notify_fs_event(b"/etc", b"hosts.new", IN_CREATE, 0);
        table.notify_fs_event(b"/etc", b"hosts", IN_MOVED_TO, 77);
        table.notify_fs_event(b"/etc", b"hosts.old", IN_DELETE, 0);

        let mut ev_buf = [0u8; 256];
        let n = table.read(ino, &mut ev_buf).unwrap();
        assert!(n >= 48);
        assert_eq!(i32::from_le_bytes(ev_buf[0..4].try_into().unwrap()), wd);
        assert_eq!(
            u32::from_le_bytes(ev_buf[4..8].try_into().unwrap()),
            IN_CREATE
        );

        // Test memfd_create + sealing enforcement.
        let mfd = table
            .memfd_create(b"systemd-state", MFD_CLOEXEC | MFD_ALLOW_SEALING)
            .unwrap();
        table.write(mfd, b"ACTIVE=1\n").unwrap();
        table
            .memfd_add_seals(
                mfd,
                F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL,
            )
            .unwrap();
        assert_eq!(
            table.memfd_get_seals(mfd).unwrap(),
            F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL
        );
        // Further writes, truncates, or seal changes must fail with EPERM!
        assert_eq!(table.write(mfd, b"X"), Err(Errno::EPERM));
        assert_eq!(table.memfd_truncate(mfd, 0), Err(Errno::EPERM));
        assert_eq!(table.memfd_add_seals(mfd, F_SEAL_WRITE), Err(Errno::EPERM));

        table.lseek(mfd, 0, 0).unwrap();
        let mut read_back = [0u8; 16];
        let r = table.read(mfd, &mut read_back).unwrap();
        assert_eq!(&read_back[..r], b"ACTIVE=1\n");
    }

    #[test]
    fn poll_readiness_reflects_event_timer_memfd_and_closed_slots() {
        let mut table = EventTable::<8, 64>::new();
        let efd = table.eventfd2(0, 0).unwrap();
        assert_eq!(table.poll_readiness(efd), Ok(EPOLLOUT));
        table.write(efd, &1u64.to_le_bytes()).unwrap();
        assert_eq!(table.poll_readiness(efd), Ok(EPOLLIN | EPOLLOUT));

        let mfd = table.memfd_create(b"x", 0).unwrap();
        assert_eq!(table.poll_readiness(mfd), Ok(EPOLLIN | EPOLLOUT));

        table.close(efd).unwrap();
        assert_eq!(table.poll_readiness(efd), Err(Errno::EBADF));
    }

    #[test]
    fn nested_epoll_surfaces_epollet_epollpri_without_consuming_inner_edge() {
        let mut table = EventTable::<8, 64>::new();
        let outer = table.epoll_create1(0).unwrap();
        let inner = table.epoll_create1(0).unwrap();
        let fd_base = 160;
        let mountinfo_fd = 416;

        table
            .epoll_ctl(
                inner,
                EPOLL_CTL_ADD,
                mountinfo_fd,
                Some(EpollEvent {
                    events: EPOLLPRI | EPOLLET,
                    data: 11,
                }),
            )
            .unwrap();
        table
            .epoll_ctl(
                outer,
                EPOLL_CTL_ADD,
                fd_base + (inner as i32),
                Some(EpollEvent {
                    events: EPOLLIN,
                    data: 22,
                }),
            )
            .unwrap();

        let mut ext = [0i32; 8];
        let ext_n = table.collect_epoll_external_fds(outer, fd_base, &mut ext);
        assert_eq!(&ext[..ext_n], &[mountinfo_fd]);

        // Initial check: no change -> neither outer nor inner is ready.
        let mut evs = [EpollEvent { events: 0, data: 0 }; 4];
        let mut fds = [0i32; 4];
        assert_eq!(
            table
                .epoll_wait_with_fds(outer, fd_base, |_| 0, &mut evs, &mut fds)
                .unwrap(),
            0
        );

        // Mount table changes -> mountinfo_fd raises POLLPRI | POLLERR.
        assert_eq!(
            table
                .epoll_wait_with_fds(outer, fd_base, |_| EPOLLPRI | EPOLLERR, &mut evs, &mut fds)
                .unwrap(),
            1
        );
        assert_eq!(evs[0].data, 22);
        assert_eq!(evs[0].events, EPOLLIN);

        // Inner epoll still fires when libmount calls epoll_wait(inner) because outer peek didn't consume edge.
        assert_eq!(
            table
                .epoll_wait_with_fds(inner, fd_base, |_| EPOLLPRI | EPOLLERR, &mut evs, &mut fds)
                .unwrap(),
            1
        );
        assert_eq!(evs[0].data, 11);
        assert_eq!(fds[0], mountinfo_fd);
    }
}
