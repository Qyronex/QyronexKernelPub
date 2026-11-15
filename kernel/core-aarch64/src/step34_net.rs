// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::ObjectId;
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_abi::{
    Errno, POLLIN, POLLOUT, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_fd::SubsystemHandle;
use kernal_linux_net::stack::{NetStack, TcpConnState};
use kernal_linux_net::{
    AF_INET, AF_INET6, AF_NETLINK, AF_UNSPEC, IPPROTO_IPV6, IPPROTO_TCP, IPV6_V6ONLY,
    MAX_SCM_RIGHTS_FDS, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, NETLINK_ROUTE, NetInterfaceConfig,
    SCM_RIGHTS, SHUT_RD, SHUT_RDWR, SHUT_WR, SO_DOMAIN, SO_ERROR, SO_PROTOCOL, SO_RCVBUF,
    SO_RCVTIMEO_NEW, SO_RCVTIMEO_OLD, SO_SNDBUF, SO_SNDTIMEO_NEW, SO_SNDTIMEO_OLD, SO_TYPE,
    SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, SockAddr, SocketTable, Ucred,
    handle_netlink_route_request_with_cfg,
};

use super::step_fd_util::{
    DirectProcessRefs, SUBSYS_NET, current_process_object, lookup_aliased_subsystem,
    lookup_aliased_subsystem_current, read_user_iovec,
};

/// Dedicated file-descriptor base for Step-34 sockets (`128..160`), partitioned cleanly above
/// `STEP29_RUNTIME_FDS` (`0..64`), `DEV_FD_BASE` (`64..96`), and `PROC_SYS_FD_BASE` (`96..128`).
pub(super) const SOCK_FD_BASE: i32 = 128;
const MAX_SOCKETS: usize = 32;
const SOCK_BUF_CAP: usize = 512;
const MAX_IOV_BYTES: usize = 65_536;
const MAX_SOCKADDR_BYTES: usize = 110;
const ARM64_STAT_BYTES: usize = 128;
const S_IFSOCK_MODE: u32 = 0o140_777;
const SOCK_CLOEXEC_FLAG: u32 = 0x0008_0000;
const SOCK_NONBLOCK_FLAG: u32 = 0x0000_0800;
const O_RDWR_U64: u64 = 2;

const FIONREAD: u64 = 0x541B;
const FIONBIO: u64 = 0x5421;
const SIOCGIFCONF: u64 = 0x8912;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCGIFADDR: u64 = 0x8915;
const SIOCGIFNETMASK: u64 = 0x891B;
const SIOCGIFMTU: u64 = 0x8921;
const SIOCGIFHWADDR: u64 = 0x8927;
const SIOCGIFINDEX: u64 = 0x8933;

#[inline]
fn net_now_ns() -> u64 {
    #[cfg(not(test))]
    {
        kernal_timer_aarch64::monotonic_now_ns().unwrap_or(0)
    }
    #[cfg(test)]
    {
        0
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HardwareSockKind {
    None,
    Udp {
        handle: u32,
        is_v6: bool,
    },
    Tcp {
        handle: u32,
        is_v6: bool,
    },
    TcpListener {
        handle: u32,
        is_v6: bool,
        also_loopback: bool,
    },
}

#[derive(Clone, Copy)]
struct SocketMeta {
    live: bool,
    generation: u64,
    owners: DirectProcessRefs<16>,
    alias_refs: usize,
    nonblocking: bool,
    domain: u16,
    sock_type: u32,
    proto: u32,
    ipv6_v6only: bool,
    bound_local: Option<SockAddr>,
    rcv_timeout_ns: Option<u64>,
    snd_timeout_ns: Option<u64>,
    hw: HardwareSockKind,
}

impl SocketMeta {
    const EMPTY: Self = Self {
        live: false,
        generation: 0,
        owners: DirectProcessRefs::empty(),
        alias_refs: 0,
        nonblocking: false,
        domain: 0,
        sock_type: 0,
        proto: 0,
        ipv6_v6only: false,
        bound_local: None,
        rcv_timeout_ns: None,
        snd_timeout_ns: None,
        hw: HardwareSockKind::None,
    };
}

struct Step34NetState {
    next_generation: u64,
    table: SocketTable<MAX_SOCKETS, SOCK_BUF_CAP>,
    meta: [SocketMeta; MAX_SOCKETS],
    hw_net: Option<NetStack>,
    netlink_rx: Vec<VecDeque<Vec<u8>>>,
}

impl Step34NetState {
    const fn new() -> Self {
        Self {
            next_generation: 1,
            table: SocketTable::new(),
            meta: [SocketMeta::EMPTY; MAX_SOCKETS],
            hw_net: None,
            netlink_rx: Vec::new(),
        }
    }

    fn ensure_netlink_vec(&mut self) {
        if self.netlink_rx.len() < MAX_SOCKETS {
            self.netlink_rx.resize_with(MAX_SOCKETS, VecDeque::new);
        }
    }

    fn init_slot(
        &mut self,
        idx: usize,
        owner: ObjectId,
        domain: u16,
        sock_type: u32,
        proto: u32,
        cloexec: bool,
        nonblocking: bool,
    ) {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        let mut owners = DirectProcessRefs::empty();
        owners.init(owner, cloexec);
        self.meta[idx] = SocketMeta {
            live: true,
            generation,
            owners,
            alias_refs: 0,
            nonblocking,
            domain,
            sock_type: sock_type & 0x0f,
            proto,
            ipv6_v6only: false,
            bound_local: None,
            rcv_timeout_ns: None,
            snd_timeout_ns: None,
            hw: HardwareSockKind::None,
        };
        if let Some(q) = self.netlink_rx.get_mut(idx) {
            q.clear();
        }
    }

    fn check_slot(
        &self,
        process: ObjectId,
        idx: usize,
        alias_gen: Option<u64>,
    ) -> Result<(), Errno> {
        let Some(m) = self.meta.get(idx) else {
            return Err(Errno::EBADF);
        };
        if !m.live {
            return Err(Errno::EBADF);
        }
        match alias_gen {
            Some(expected_gen) if m.generation == expected_gen && m.alias_refs > 0 => Ok(()),
            Some(_) => Err(Errno::EBADF),
            None if m.owners.has_owner(process) => Ok(()),
            None => Err(Errno::EBADF),
        }
    }

    fn retire_if_unused(&mut self, idx: usize, now_ns: u64) {
        let Some(m) = self.meta.get_mut(idx) else {
            return;
        };
        if !m.live || !m.owners.is_empty() || m.alias_refs > 0 {
            return;
        }
        let hw = m.hw;
        *m = SocketMeta::EMPTY;
        if let Some(q) = self.netlink_rx.get_mut(idx) {
            q.clear();
        }
        if let Some(ref mut stack) = self.hw_net {
            match hw {
                HardwareSockKind::Udp { handle, .. } => stack.udp_close(handle),
                HardwareSockKind::Tcp { handle, .. }
                | HardwareSockKind::TcpListener { handle, .. } => stack.tcp_close(handle, now_ns),
                HardwareSockKind::None => {}
            }
        }
        let _ = self.table.close(idx);
    }

    fn iface_config(&self) -> NetInterfaceConfig {
        let Some(ref stack) = self.hw_net else {
            return NetInterfaceConfig::LOOPBACK_ONLY;
        };
        NetInterfaceConfig {
            has_eth0: true,
            link_up: stack.link_up(),
            ip: stack.cfg.ip,
            netmask: stack.cfg.netmask,
            prefix_len: stack.cfg.prefix_len,
            gateway: stack.cfg.gateway,
            mac: stack.mac(),
            mtu: u32::from(stack.mtu()),
        }
    }
}

struct Step34NetCell {
    state: AtomicU8,
    value: UnsafeCell<Step34NetState>,
}

// SAFETY: Step-34 socket table accesses happen under synchronous EL0 trap dispatch serialized by
// an explicit atomic lock (`0 -> 1 -> 0`).
unsafe impl Sync for Step34NetCell {}

static NET_STATE: Step34NetCell = Step34NetCell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step34NetState::new()),
};

fn with_net_full<R>(f: impl FnOnce(&mut Step34NetState) -> R) -> Result<R, ()> {
    if NET_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state transition `0 -> 1` grants exclusive mutable access for this synchronous scope.
    let result = f(unsafe { &mut *NET_STATE.value.get() });
    NET_STATE.state.store(0, Ordering::Release);
    Ok(result)
}

fn drain_tx_frames() {
    if !super::step42_hardware::has_hardware_net() {
        return;
    }
    let mut tx_frames = Vec::new();
    let _ = with_net_full(|state| {
        let Some(ref mut stack) = state.hw_net else {
            return;
        };
        while tx_frames.len() < 32 {
            let Some(frame) = stack.pop_tx_frame() else {
                break;
            };
            tx_frames.push(frame);
        }
    });
    for frame in &tx_frames {
        let _ = super::step42_hardware::net_send_frame(frame);
    }
}

/// Pumps incoming Ethernet frames from VirtIO-Net, advances DHCP/ARP/TCP timers, flushes outbound
/// frames, and updates Step-40 `/etc/resolv.conf` metadata once DHCP completes.
pub(super) fn pump_hardware_net() {
    if !super::step42_hardware::has_hardware_net() {
        return;
    }
    let mut rx_frames: Vec<Vec<u8>> = Vec::new();
    let mut rx_scratch = [0u8; 2048];
    for _ in 0..16 {
        match super::step42_hardware::net_recv_frame(&mut rx_scratch) {
            Ok(Some(len)) => rx_frames.push(rx_scratch[..len].to_vec()),
            _ => break,
        }
    }

    let now = net_now_ns();
    let mut tx_frames: Vec<Vec<u8>> = Vec::new();
    let mut newly_bound = None;
    let _ = with_net_full(|state| {
        let Some(ref mut stack) = state.hw_net else {
            return;
        };
        let was_bound = stack.dhcp_bound();
        for frame in &rx_frames {
            stack.ingest_frame(frame, now);
        }
        stack.tick(now);
        if !was_bound && stack.dhcp_bound() {
            newly_bound = Some((stack.cfg, stack.mac()));
        }
        while tx_frames.len() < 32 {
            let Some(f) = stack.pop_tx_frame() else {
                break;
            };
            tx_frames.push(f);
        }
    });
    for frame in &tx_frames {
        let _ = super::step42_hardware::net_send_frame(frame);
    }
    if let Some((cfg, mac)) = newly_bound {
        super::step40_debian_boot::update_network_config(cfg.ip, cfg.gateway, cfg.dns, mac);
    }
}

/// Initializes the real `NetStack` over an attached `virtio-net` MMIO device and kicks off DHCPv4.
pub(super) fn init_hardware_net() -> Option<[u8; 4]> {
    let mac = super::step42_hardware::hardware_net_mac()?;
    let mtu = super::step42_hardware::hardware_net_mtu().unwrap_or(1500);
    let link_up = super::step42_hardware::hardware_net_link_up();
    let now = net_now_ns();
    let _ = with_net_full(|state| {
        let mut stack = NetStack::new(mac, mtu, link_up);
        stack.start_dhcp(now);
        state.hw_net = Some(stack);
    });
    pump_hardware_net();
    for _ in 0..1000 {
        for _ in 0..5000 {
            core::hint::spin_loop();
        }
        pump_hardware_net();
        let bound_ip = with_net_full(|state| {
            state
                .hw_net
                .as_ref()
                .filter(|s| s.dhcp_bound())
                .map(|s| s.cfg.ip)
        })
        .ok()
        .flatten();
        if bound_ip.is_some() {
            return bound_ip;
        }
    }
    None
}

fn socket_status_flags(nonblocking: bool) -> u64 {
    if nonblocking {
        O_RDWR_U64 | u64::from(SOCK_NONBLOCK_FLAG)
    } else {
        O_RDWR_U64
    }
}

fn is_aliased_socket_fd(raw_fd: u64) -> bool {
    lookup_aliased_subsystem_current(raw_fd).is_some_and(|h| h.kind == SUBSYS_NET)
}

fn resolve_socket_target(raw_fd: u64) -> Result<(usize, Option<u64>), Errno> {
    let fd = linux_signed_int(raw_fd);
    if fd < 0 {
        return Err(Errno::EBADF);
    }
    if is_socket_fd(raw_fd) {
        return Ok(((fd - SOCK_FD_BASE) as usize, None));
    }
    if let Some(handle) = lookup_aliased_subsystem_current(raw_fd)
        && handle.kind == SUBSYS_NET
    {
        return Ok((handle.slot as usize, Some(handle.generation)));
    }
    Err(Errno::ENOTSOCK)
}

pub(super) fn append_open_socket_fds(process: ObjectId, out: &mut Vec<i32>) {
    let _ = with_net_full(|state| {
        for (idx, m) in state.meta.iter().enumerate() {
            if m.live && m.owners.has_owner(process) {
                out.push(SOCK_FD_BASE + (idx as i32));
            }
        }
    });
}

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    let _ = with_net_full(|state| {
        for m in &mut state.meta {
            if m.live {
                m.owners.on_fork(parent, child);
            }
        }
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    let now = net_now_ns();
    let _ = with_net_full(|state| {
        for idx in 0..MAX_SOCKETS {
            if state.meta[idx].live {
                state.meta[idx].owners.close_cloexec_for(process);
                state.retire_if_unused(idx, now);
            }
        }
    });
    drain_tx_frames();
}

pub(super) fn on_process_exit(process: ObjectId) {
    let now = net_now_ns();
    let _ = with_net_full(|state| {
        for idx in 0..MAX_SOCKETS {
            if state.meta[idx].live {
                let _ = state.meta[idx].owners.close_owner(process);
                state.retire_if_unused(idx, now);
            }
        }
    });
    drain_tx_frames();
}

pub(super) fn retain_alias_handle(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(SubsystemHandle, u64), Errno> {
    if !is_socket_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let idx = (linux_signed_int(raw_fd) - SOCK_FD_BASE) as usize;
    with_net_full(|state| {
        let Some(m) = state.meta.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !m.live || !m.owners.has_owner(process) {
            return Err(Errno::EBADF);
        }
        m.alias_refs += 1;
        Ok((
            SubsystemHandle {
                kind: SUBSYS_NET,
                slot: idx as u16,
                generation: m.generation,
            },
            socket_status_flags(m.nonblocking),
        ))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn release_alias_handle(handle: SubsystemHandle) {
    if handle.kind != SUBSYS_NET {
        return;
    }
    let idx = handle.slot as usize;
    let now = net_now_ns();
    let _ = with_net_full(|state| {
        let Some(m) = state.meta.get_mut(idx) else {
            return;
        };
        if m.live && m.generation == handle.generation && m.alias_refs > 0 {
            m.alias_refs -= 1;
            state.retire_if_unused(idx, now);
        }
    });
    drain_tx_frames();
}

pub(super) fn handle_native_fcntl(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    let (idx, alias_gen) = if is_socket_fd(raw_fd) {
        ((linux_signed_int(raw_fd) - SOCK_FD_BASE) as usize, None)
    } else if let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
        && handle.kind == SUBSYS_NET
        && matches!(cmd, 3 | 4)
    {
        (handle.slot as usize, Some(handle.generation))
    } else {
        return None;
    };
    let res = with_net_full(|state| {
        state.check_slot(process, idx, alias_gen)?;
        let Some(m) = state.meta.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        match cmd {
            1 => Ok(i64::from(i32::from(
                m.owners.get_cloexec(process).unwrap_or(false),
            ))),
            2 => {
                let _ = m.owners.set_cloexec(process, (argi & 1) != 0);
                Ok(0)
            }
            3 => Ok(socket_status_flags(m.nonblocking) as i64),
            4 => {
                m.nonblocking = ((argi as u32) & SOCK_NONBLOCK_FLAG) != 0;
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    });
    Some(match res {
        Ok(inner) => inner,
        Err(()) => Err(Errno::EIO),
    })
}

/// Returns `true` if `raw_fd` lies in the Step-34 socket descriptor window (`128..160`).
pub(super) const fn is_socket_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= SOCK_FD_BASE && fd < SOCK_FD_BASE + (MAX_SOCKETS as i32)
}

/// Probes `POLL*` readiness for a Step-34 socket FD or aliased `SUBSYS_NET` FD owned by `process`.
pub(super) fn probe_socket_readiness(process: ObjectId, raw_fd: u64) -> Option<Result<u32, Errno>> {
    let (slot_idx, alias_gen) = if is_socket_fd(raw_fd) {
        let idx = usize::try_from(linux_signed_int(raw_fd) - SOCK_FD_BASE).ok()?;
        (idx, None)
    } else {
        let handle = lookup_aliased_subsystem(process, raw_fd)?;
        if handle.kind != SUBSYS_NET {
            return None;
        }
        (usize::from(handle.slot), Some(handle.generation))
    };
    pump_hardware_net();
    let res = match with_net_full(|state| {
        state.check_slot(process, slot_idx, alias_gen)?;
        let m = state.meta[slot_idx];
        if m.domain == AF_NETLINK && m.proto == NETLINK_ROUTE {
            let has_rx = state
                .netlink_rx
                .get(slot_idx)
                .is_some_and(|q| !q.is_empty());
            let mut ev = u32::from(POLLOUT);
            if has_rx {
                ev |= u32::from(POLLIN);
            }
            return Ok(ev);
        }
        match m.hw {
            HardwareSockKind::Udp { handle, .. } => {
                let Some(ref stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                Ok(u32::from(stack.udp_poll_events(handle)))
            }
            HardwareSockKind::Tcp { handle, .. } => {
                let Some(ref stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                Ok(u32::from(stack.tcp_poll_events(handle)))
            }
            HardwareSockKind::TcpListener {
                handle,
                also_loopback,
                ..
            } => {
                let mut ev = state
                    .hw_net
                    .as_ref()
                    .map(|s| u32::from(s.tcp_poll_events(handle)))
                    .unwrap_or(0);
                if also_loopback {
                    ev |= state.table.poll_readiness(slot_idx).unwrap_or(0);
                }
                Ok(ev)
            }
            HardwareSockKind::None => state.table.poll_readiness(slot_idx),
        }
    }) {
        Ok(res) => res,
        Err(()) => Err(Errno::EIO),
    };
    Some(res)
}

/// Dispatches Step-34 socket syscalls and socket file-descriptor operations.
pub(super) fn try_handle_syscall(
    request: SyscallRequest,
    mut frame: Option<&mut ExceptionFrame>,
) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        // ioctl(fd, request, arg)
        29 if is_socket_fd(request.args[0]) || is_aliased_socket_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_socket_ioctl(
                request.args[0],
                request.args[1],
                request.args[2],
            )?)))
        }
        // close(fd)
        57 if is_socket_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        // read(fd, buf, count)
        63 if is_socket_fd(request.args[0]) || is_aliased_socket_fd(request.args[0]) => {
            Ok(Some(handle_recvfrom_blocking(
                frame.as_deref_mut(),
                request.args[0],
                request.args[1],
                request.args[2],
                0,
                0,
                0,
            )?))
        }
        // write(fd, buf, count)
        64 if is_socket_fd(request.args[0]) || is_aliased_socket_fd(request.args[0]) => {
            Ok(Some(handle_sendto_blocking(
                frame.as_deref_mut(),
                request.args[0],
                request.args[1],
                request.args[2],
                0,
                0,
                0,
            )?))
        }
        // readv(fd, iov, iovcnt)
        65 if is_socket_fd(request.args[0]) || is_aliased_socket_fd(request.args[0]) => {
            Ok(Some(handle_readv_blocking(
                frame.as_deref_mut(),
                request.args[0],
                request.args[1],
                request.args[2],
            )?))
        }
        // writev(fd, iov, iovcnt)
        66 if is_socket_fd(request.args[0]) || is_aliased_socket_fd(request.args[0]) => {
            Ok(Some(handle_writev_blocking(
                frame.as_deref_mut(),
                request.args[0],
                request.args[1],
                request.args[2],
            )?))
        }
        // fstat(fd, statbuf)
        80 if is_socket_fd(request.args[0]) || is_aliased_socket_fd(request.args[0]) => Ok(Some(
            encode_result(handle_fstat(request.args[0], request.args[1])?),
        )),
        // socket(domain, type, protocol)
        198 => Ok(Some(encode_result(handle_socket(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // socketpair(domain, type, protocol, sv)
        199 => Ok(Some(encode_result(handle_socketpair(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        // bind(sockfd, addr, addrlen)
        200 => Ok(Some(encode_result(handle_bind(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // listen(sockfd, backlog)
        201 => Ok(Some(encode_result(handle_listen(
            request.args[0],
            request.args[1],
        )?))),
        // accept(sockfd, addr, addrlen)
        202 => Ok(Some(handle_accept4_blocking(
            frame.as_deref_mut(),
            request.args[0],
            request.args[1],
            request.args[2],
            0,
        )?)),
        // connect(sockfd, addr, addrlen)
        203 => Ok(Some(handle_connect_blocking(
            frame.as_deref_mut(),
            request.args[0],
            request.args[1],
            request.args[2],
        )?)),
        // getsockname(sockfd, addr, addrlen)
        204 => Ok(Some(encode_result(handle_getsockname(
            request.args[0],
            request.args[1],
            request.args[2],
            false,
        )?))),
        // getpeername(sockfd, addr, addrlen)
        205 => Ok(Some(encode_result(handle_getsockname(
            request.args[0],
            request.args[1],
            request.args[2],
            true,
        )?))),
        // sendto(sockfd, buf, len, flags, dest_addr, addrlen)
        206 => Ok(Some(handle_sendto_blocking(
            frame.as_deref_mut(),
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
            request.args[5],
        )?)),
        // recvfrom(sockfd, buf, len, flags, src_addr, addrlen)
        207 => Ok(Some(handle_recvfrom_blocking(
            frame.as_deref_mut(),
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
            request.args[5],
        )?)),
        // setsockopt(sockfd, level, optname, optval, optlen)
        208 => Ok(Some(encode_result(handle_setsockopt(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        )?))),
        // getsockopt(sockfd, level, optname, optval, optlen)
        209 => Ok(Some(encode_result(handle_getsockopt(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        )?))),
        // shutdown(sockfd, how)
        210 => Ok(Some(encode_result(handle_shutdown(
            request.args[0],
            request.args[1],
        )?))),
        // sendmsg(sockfd, msg, flags)
        211 => Ok(Some(handle_sendmsg_blocking(
            frame.as_deref_mut(),
            request.args[0],
            request.args[1],
            request.args[2],
        )?)),
        // recvmsg(sockfd, msg, flags)
        212 => Ok(Some(handle_recvmsg_blocking(
            frame.as_deref_mut(),
            request.args[0],
            request.args[1],
            request.args[2],
        )?)),
        // accept4(sockfd, addr, addrlen, flags)
        242 => Ok(Some(handle_accept4_blocking(
            frame,
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?)),
        _ => Ok(None),
    }
}

fn encode_result(res: Result<i64, Errno>) -> SyscallReturn {
    match res {
        Ok(val) => SyscallReturn::success(val).unwrap_or(SyscallReturn::error(Errno::EINVAL)),
        Err(errno) => SyscallReturn::error(errno),
    }
}

fn current_ucred() -> Ucred {
    let pid = super::step30_runtime::current_linux_tid()
        .map(|tid| tid.get())
        .unwrap_or(1);
    let (uid, gid) = super::step30_runtime::current_uid_gid().unwrap_or((0, 0));
    Ucred { pid, uid, gid }
}

fn extract_ipv4(addr: &SockAddr, domain: u16, ipv6_v6only: bool) -> Option<([u8; 4], u16)> {
    match *addr {
        SockAddr::Inet { ip, port } if domain == AF_INET => Some((ip, port)),
        SockAddr::Inet6 { ip, port } if domain == AF_INET6 && !ipv6_v6only => {
            if ip == [0u8; 16] {
                Some(([0, 0, 0, 0], port))
            } else if ip[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                Some(([ip[12], ip[13], ip[14], ip[15]], port))
            } else if ip == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
                Some(([127, 0, 0, 1], port))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_loopback_ipv4(ip: [u8; 4]) -> bool {
    ip[0] == 127 || ip == [0, 0, 0, 0]
}

fn encode_sockaddr_for_domain(domain: u16, ip: [u8; 4], port: u16) -> SockAddr {
    if domain == AF_INET6 {
        SockAddr::Inet6 {
            ip: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ip[0], ip[1], ip[2], ip[3],
            ],
            port,
        }
    } else {
        SockAddr::Inet { ip, port }
    }
}

fn handle_socket(raw_domain: u64, raw_type: u64, raw_proto: u64) -> Result<Result<i64, Errno>, ()> {
    let Ok(domain) = u16::try_from(linux_unsigned_int(raw_domain)) else {
        return Ok(Err(Errno::EAFNOSUPPORT));
    };
    let sock_type = linux_unsigned_int(raw_type);
    let proto = linux_unsigned_int(raw_proto);
    let process = current_process_object().unwrap_or(ObjectId(1));
    with_net_full(|state| {
        let idx = state.table.socket(domain, sock_type, proto)?;
        state.init_slot(
            idx,
            process,
            domain,
            sock_type,
            proto,
            (sock_type & SOCK_CLOEXEC_FLAG) != 0,
            (sock_type & SOCK_NONBLOCK_FLAG) != 0,
        );
        Ok(i64::from(SOCK_FD_BASE + (idx as i32)))
    })
}

fn handle_socketpair(
    raw_domain: u64,
    raw_type: u64,
    raw_proto: u64,
    user_sv: u64,
) -> Result<Result<i64, Errno>, ()> {
    if user_sv == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let Ok(domain) = u16::try_from(linux_unsigned_int(raw_domain)) else {
        return Ok(Err(Errno::EAFNOSUPPORT));
    };
    let sock_type = linux_unsigned_int(raw_type);
    let proto = linux_unsigned_int(raw_proto);
    let cloexec = (sock_type & SOCK_CLOEXEC_FLAG) != 0;
    let nonblocking = (sock_type & SOCK_NONBLOCK_FLAG) != 0;
    let cred = current_ucred();
    let process = current_process_object().unwrap_or(ObjectId(1));
    let pair = with_net_full(|state| {
        let (a, b) = state.table.socketpair(domain, sock_type, proto, cred)?;
        state.init_slot(a, process, domain, sock_type, proto, cloexec, nonblocking);
        state.init_slot(b, process, domain, sock_type, proto, cloexec, nonblocking);
        Ok((a, b))
    })?;
    let (a, b) = match pair {
        Ok(p) => p,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut sv_bytes = [0u8; 8];
    sv_bytes[0..4].copy_from_slice(&(SOCK_FD_BASE + (a as i32)).to_le_bytes());
    sv_bytes[4..8].copy_from_slice(&(SOCK_FD_BASE + (b as i32)).to_le_bytes());
    if let Err(errno) = copy_to_user(user_sv, &sv_bytes) {
        let now = net_now_ns();
        with_net_full(|state| {
            let _ = state.meta[a].owners.close_owner(process);
            let _ = state.meta[b].owners.close_owner(process);
            state.retire_if_unused(a, now);
            state.retire_if_unused(b, now);
        })?;
        return Ok(Err(errno));
    }
    Ok(Ok(0))
}

fn handle_bind(raw_fd: u64, user_addr: u64, addrlen: u64) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let addr = match read_user_sockaddr(user_addr, addrlen) {
        Ok(a) => a,
        Err(e) => return Ok(Err(e)),
    };
    let process = current_process_object().unwrap_or(ObjectId(1));
    with_net_full(|state| {
        state.check_slot(process, idx, alias_gen)?;
        let m = state.meta[idx];
        if let Some((ip, port)) = extract_ipv4(&addr, m.domain, m.ipv6_v6only) {
            let is_v6 = m.domain == AF_INET6;
            if m.sock_type == SOCK_DGRAM && state.hw_net.is_some() && !is_loopback_ipv4(ip) {
                let Some(ref mut stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                if ip != [0, 0, 0, 0] && stack.cfg.configured && ip != stack.cfg.ip {
                    return Err(Errno::EADDRNOTAVAIL);
                }
                let handle = stack.udp_open(ip, port)?;
                let (bound_ip, bound_port) = stack.udp_local_addr(handle)?;
                state.meta[idx].hw = HardwareSockKind::Udp { handle, is_v6 };
                state.meta[idx].bound_local =
                    Some(encode_sockaddr_for_domain(m.domain, bound_ip, bound_port));
                return Ok(0);
            }
            if !is_loopback_ipv4(ip) {
                let Some(ref stack) = state.hw_net else {
                    return Err(Errno::EADDRNOTAVAIL);
                };
                if stack.cfg.configured && ip != stack.cfg.ip {
                    return Err(Errno::EADDRNOTAVAIL);
                }
                state.meta[idx].bound_local = Some(addr);
                return Ok(0);
            }
            if m.sock_type == SOCK_DGRAM && state.hw_net.is_some() && ip == [0, 0, 0, 0] {
                let Some(ref mut stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                let handle = stack.udp_open([0, 0, 0, 0], port)?;
                let (_, assigned_port) = stack.udp_local_addr(handle)?;
                state.meta[idx].hw = HardwareSockKind::Udp { handle, is_v6 };
                let normalized = encode_sockaddr_for_domain(m.domain, [0, 0, 0, 0], assigned_port);
                state.meta[idx].bound_local = Some(normalized);
                let _ = state.table.bind(
                    idx,
                    SockAddr::Inet {
                        ip: [0, 0, 0, 0],
                        port: assigned_port,
                    },
                );
                return Ok(0);
            }
        }
        let eff_addr = if let SockAddr::Netlink { pid, groups } = addr {
            let assigned = assign_netlink_portid(state, idx, pid, current_ucred().pid);
            SockAddr::Netlink {
                pid: assigned,
                groups,
            }
        } else {
            addr
        };
        state.table.bind(idx, eff_addr)?;
        state.meta[idx].bound_local = state.table.getsockname(idx).ok();
        Ok(0)
    })
}

fn assign_netlink_portid(
    state: &Step34NetState,
    self_idx: usize,
    requested_pid: u32,
    preferred_pid: u32,
) -> u32 {
    if requested_pid != 0 {
        return requested_pid;
    }
    let candidate = preferred_pid.max(1);
    let in_use = |pid: u32| {
        state.meta.iter().enumerate().any(|(i, slot)| {
            i != self_idx
                && slot.live
                && matches!(slot.bound_local, Some(SockAddr::Netlink { pid: p, .. }) if p == pid)
        })
    };
    if !in_use(candidate) {
        return candidate;
    }
    let mut seq = 0x4000_0000u32.saturating_add(self_idx as u32 + 1);
    while in_use(seq) {
        seq = seq.wrapping_add(1).max(0x4000_0001);
    }
    seq
}

fn handle_listen(raw_fd: u64, raw_backlog: u64) -> Result<Result<i64, Errno>, ()> {
    let backlog = linux_signed_int(raw_backlog);
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let process = current_process_object().unwrap_or(ObjectId(1));
    let now = net_now_ns();
    with_net_full(|state| {
        state.check_slot(process, idx, alias_gen)?;
        let m = state.meta[idx];
        if (m.domain == AF_INET || m.domain == AF_INET6) && m.sock_type == SOCK_STREAM {
            if let Some(bound) = m.bound_local
                && let Some((ip, port)) = extract_ipv4(&bound, m.domain, m.ipv6_v6only)
                && ip != [127, 0, 0, 1]
                && state.hw_net.is_some()
            {
                let is_v6 = m.domain == AF_INET6;
                let also_loopback = ip == [0, 0, 0, 0];
                if also_loopback {
                    state.table.listen(idx, backlog)?;
                }
                let Some(ref mut stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                let handle = stack.tcp_listen(ip, port, backlog.max(1) as usize, now)?;
                state.meta[idx].hw = HardwareSockKind::TcpListener {
                    handle,
                    is_v6,
                    also_loopback,
                };
                return Ok(0);
            }
        }
        state.table.listen(idx, backlog).map(|()| 0)
    })
}

fn handle_accept4_blocking(
    mut frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    user_addr: u64,
    user_addrlen: u64,
    raw_flags: u64,
) -> Result<SyscallReturn, ()> {
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(SyscallReturn::error(e)),
    };
    let flags = linux_unsigned_int(raw_flags);
    let cloexec = (flags & SOCK_CLOEXEC_FLAG) != 0;
    let nonblocking_child = (flags & SOCK_NONBLOCK_FLAG) != 0;
    let process = current_process_object().unwrap_or(ObjectId(1));

    loop {
        pump_hardware_net();
        let mut listener_nonblock = false;
        let mut rcv_timeout_ns = None;
        let step = with_net_full(|state| {
            state.check_slot(process, idx, alias_gen)?;
            let m = state.meta[idx];
            listener_nonblock = m.nonblocking;
            rcv_timeout_ns = m.rcv_timeout_ns;
            match m.hw {
                HardwareSockKind::TcpListener {
                    handle,
                    is_v6,
                    also_loopback,
                } => {
                    let child_hw = state
                        .hw_net
                        .as_mut()
                        .and_then(|s| s.tcp_accept(handle).ok().flatten());
                    if let Some(child_handle) = child_hw {
                        let dom = if is_v6 { AF_INET6 } else { AF_INET };
                        let new_idx = state.table.socket(dom, SOCK_STREAM, 0)?;
                        state.init_slot(
                            new_idx,
                            process,
                            dom,
                            SOCK_STREAM,
                            IPPROTO_TCP,
                            cloexec,
                            nonblocking_child,
                        );
                        state.meta[new_idx].hw = HardwareSockKind::Tcp {
                            handle: child_handle,
                            is_v6,
                        };
                        let peer_addr = state
                            .hw_net
                            .as_ref()
                            .and_then(|s| s.tcp_addrs(child_handle))
                            .map(|a| encode_sockaddr_for_domain(dom, a.remote_ip, a.remote_port));
                        return Ok((new_idx, peer_addr));
                    }
                    if also_loopback {
                        match state.table.accept4(idx, flags) {
                            Ok((new_idx, peer_addr)) => {
                                state.init_slot(
                                    new_idx,
                                    process,
                                    m.domain,
                                    m.sock_type,
                                    m.proto,
                                    cloexec,
                                    nonblocking_child,
                                );
                                return Ok((new_idx, peer_addr));
                            }
                            Err(Errno::EAGAIN) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    Err(Errno::EAGAIN)
                }
                _ => {
                    let (new_idx, peer_addr) = state.table.accept4(idx, flags)?;
                    state.init_slot(
                        new_idx,
                        process,
                        m.domain,
                        m.sock_type,
                        m.proto,
                        cloexec,
                        nonblocking_child,
                    );
                    Ok((new_idx, peer_addr))
                }
            }
        })?;

        match step {
            Ok((new_idx, peer_addr)) => {
                if user_addr != 0
                    && let Some(addr) = peer_addr
                    && let Err(e) = write_user_sockaddr(user_addr, user_addrlen, &addr)
                {
                    return Ok(SyscallReturn::error(e));
                }
                return Ok(encode_result(Ok(i64::from(
                    SOCK_FD_BASE + (new_idx as i32),
                ))));
            }
            Err(Errno::EAGAIN) if !listener_nonblock => {
                if let Some(ret) =
                    super::step35_events_cgroup::blocking_wait_step(frame.as_deref_mut())?
                {
                    return Ok(ret);
                }
            }
            Err(e) => return Ok(SyscallReturn::error(e)),
        }
    }
}

fn handle_connect_blocking(
    mut frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    user_addr: u64,
    addrlen: u64,
) -> Result<SyscallReturn, ()> {
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(SyscallReturn::error(e)),
    };
    let addr = match read_user_sockaddr(user_addr, addrlen) {
        Ok(a) => a,
        Err(e) => return Ok(SyscallReturn::error(e)),
    };
    let cred = current_ucred();
    let process = current_process_object().unwrap_or(ObjectId(1));
    let start_ns = net_now_ns();

    enum ConnectAction {
        Done,
        InProgress {
            handle: u32,
            timeout_ns: Option<u64>,
        },
    }

    let init_res = with_net_full(|state| {
        state.check_slot(process, idx, alias_gen)?;
        let m = state.meta[idx];

        // Non-blocking connect() status re-check
        if let HardwareSockKind::Tcp { handle, .. } = m.hw {
            let Some(ref mut stack) = state.hw_net else {
                return Err(Errno::ENETUNREACH);
            };
            return match stack.tcp_state(handle) {
                Some(TcpConnState::SynSent) => Err(Errno::EALREADY),
                Some(TcpConnState::Established | TcpConnState::CloseWait) => Err(Errno::EISCONN),
                Some(TcpConnState::Reset | TcpConnState::Closed) => {
                    Err(stack.tcp_take_error(handle).unwrap_or(Errno::ECONNREFUSED))
                }
                _ => Err(Errno::EALREADY),
            };
        }

        if let Some((ip, port)) = extract_ipv4(&addr, m.domain, m.ipv6_v6only) {
            let ext_ip = if ip == [0, 0, 0, 0] {
                [127, 0, 0, 1]
            } else {
                ip
            };
            if ext_ip[0] != 127 {
                let is_v6 = m.domain == AF_INET6;
                let bound = m
                    .bound_local
                    .and_then(|b| extract_ipv4(&b, m.domain, m.ipv6_v6only));
                let Some(ref mut stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                if m.sock_type == SOCK_DGRAM {
                    let handle = match m.hw {
                        HardwareSockKind::Udp { handle, .. } => handle,
                        HardwareSockKind::None => {
                            let (bip, bp) = bound.unwrap_or(([0; 4], 0));
                            let h = stack.udp_open(bip, bp)?;
                            state.meta[idx].hw = HardwareSockKind::Udp { handle: h, is_v6 };
                            h
                        }
                        _ => return Err(Errno::EOPNOTSUPP),
                    };
                    stack.udp_connect(handle, ext_ip, port)?;
                    return Ok(ConnectAction::Done);
                } else if m.sock_type == SOCK_STREAM {
                    let bip = bound.map(|(bip, _)| bip);
                    let bp = bound.map(|(_, bp)| bp);
                    let handle = stack.tcp_connect(bip, bp, ext_ip, port, start_ns)?;
                    state.meta[idx].hw = HardwareSockKind::Tcp { handle, is_v6 };
                    if m.nonblocking {
                        return Err(Errno::EINPROGRESS);
                    }
                    return Ok(ConnectAction::InProgress {
                        handle,
                        timeout_ns: m.snd_timeout_ns,
                    });
                }
            }
        }

        // Loopback or AF_UNIX (translate ::ffff:127.x.x.x -> SockAddr::Inet for loopback SocketTable)
        let target_addr = match extract_ipv4(&addr, m.domain, m.ipv6_v6only) {
            Some((ip, port)) => SockAddr::Inet { ip, port },
            None => addr,
        };
        state.table.connect(idx, target_addr, cred)?;
        Ok(ConnectAction::Done)
    })?;

    drain_tx_frames();

    match init_res {
        Ok(ConnectAction::Done) => Ok(encode_result(Ok(0))),
        Err(e) => Ok(SyscallReturn::error(e)),
        Ok(ConnectAction::InProgress { handle, timeout_ns }) => loop {
            pump_hardware_net();
            let poll = with_net_full(|state| {
                let Some(ref mut stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                match stack.tcp_state(handle) {
                    Some(TcpConnState::Established | TcpConnState::CloseWait) => Ok(true),
                    Some(TcpConnState::SynSent) => Ok(false),
                    Some(TcpConnState::Reset | TcpConnState::Closed) => {
                        Err(stack.tcp_take_error(handle).unwrap_or(Errno::ECONNREFUSED))
                    }
                    _ => Err(Errno::ECONNRESET),
                }
            })?;
            match poll {
                Ok(true) => return Ok(encode_result(Ok(0))),
                Err(e) => return Ok(SyscallReturn::error(e)),
                Ok(false) => {
                    if let Some(tmo) = timeout_ns
                        && net_now_ns().saturating_sub(start_ns) >= tmo
                    {
                        return Ok(SyscallReturn::error(Errno::EINPROGRESS));
                    }
                    if let Some(ret) =
                        super::step35_events_cgroup::blocking_wait_step(frame.as_deref_mut())?
                    {
                        return Ok(ret);
                    }
                }
            }
        },
    }
}

fn handle_getsockname(
    raw_fd: u64,
    user_addr: u64,
    user_addrlen: u64,
    peer: bool,
) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_object().unwrap_or(ObjectId(1));
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let res = with_net_full(|state| {
        state.check_slot(process, idx, alias_gen)?;
        let m = state.meta[idx];
        match m.hw {
            HardwareSockKind::Udp { handle, .. } => {
                let Some(ref stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                if peer {
                    let (ip, port) = stack.udp_peer_addr(handle)?.ok_or(Errno::ENOTCONN)?;
                    Ok(encode_sockaddr_for_domain(m.domain, ip, port))
                } else {
                    let (ip, port) = stack.udp_local_addr(handle)?;
                    Ok(encode_sockaddr_for_domain(m.domain, ip, port))
                }
            }
            HardwareSockKind::Tcp { handle, .. } | HardwareSockKind::TcpListener { handle, .. } => {
                let Some(ref stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                let addrs = stack.tcp_addrs(handle).ok_or(Errno::EBADF)?;
                if peer {
                    if addrs.remote_port == 0 {
                        return Err(Errno::ENOTCONN);
                    }
                    Ok(encode_sockaddr_for_domain(
                        m.domain,
                        addrs.remote_ip,
                        addrs.remote_port,
                    ))
                } else {
                    Ok(encode_sockaddr_for_domain(
                        m.domain,
                        addrs.local_ip,
                        addrs.local_port,
                    ))
                }
            }
            HardwareSockKind::None => {
                if !peer && let Some(bound) = m.bound_local {
                    return Ok(bound);
                }
                if peer {
                    state.table.getpeername(idx)
                } else {
                    state.table.getsockname(idx)
                }
            }
        }
    })?;
    let addr = match res {
        Ok(a) => a,
        Err(e) => return Ok(Err(e)),
    };
    if let Err(e) = write_user_sockaddr(user_addr, user_addrlen, &addr) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn send_payload_blocking(
    mut frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    payload: &[u8],
    flags: u32,
    dest: Option<SockAddr>,
    rights: &[i32],
) -> Result<SyscallReturn, ()> {
    let process = current_process_object().unwrap_or(ObjectId(1));
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(SyscallReturn::error(e)),
    };
    let allowed_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
    if (flags & !allowed_flags) != 0 {
        // Ignore unknown benign flags? Allow MSG_MORE/0 if needed, or reject invalid only if huge.
        let _ = flags;
    }
    let dontwait = (flags & MSG_DONTWAIT) != 0;
    let start_ns = net_now_ns();
    let mut offset = 0usize;

    loop {
        pump_hardware_net();
        let now = net_now_ns();
        let mut is_nonblock = dontwait;
        let mut snd_timeout_ns = None;
        let mut used_hw_net = false;

        let step: Result<Option<usize>, Errno> = with_net_full(|state| {
            state.check_slot(process, idx, alias_gen)?;
            let m = state.meta[idx];
            is_nonblock |= m.nonblocking;
            snd_timeout_ns = m.snd_timeout_ns;

            if m.domain == AF_NETLINK && m.proto == NETLINK_ROUTE {
                let bound_pid = match state.meta[idx].bound_local {
                    Some(SockAddr::Netlink { pid, .. }) => pid,
                    _ => {
                        let assigned = assign_netlink_portid(state, idx, 0, current_ucred().pid);
                        let nl_addr = SockAddr::Netlink {
                            pid: assigned,
                            groups: 0,
                        };
                        let _ = state.table.bind(idx, nl_addr);
                        state.meta[idx].bound_local = Some(nl_addr);
                        assigned
                    }
                };
                let iface = state.iface_config();
                state.ensure_netlink_vec();
                let mut reply = vec![0u8; 1024];
                let n =
                    handle_netlink_route_request_with_cfg(payload, &mut reply, bound_pid, &iface)?;
                reply.truncate(n);
                state.netlink_rx[idx].push_back(reply);
                return Ok(Some(payload.len()));
            }

            if let Some(daddr) = dest
                && let Some((ip, port)) = extract_ipv4(&daddr, m.domain, m.ipv6_v6only)
                && !is_loopback_ipv4(ip)
                && m.sock_type == SOCK_DGRAM
            {
                let bound = m
                    .bound_local
                    .and_then(|b| extract_ipv4(&b, m.domain, m.ipv6_v6only));
                let is_v6 = m.domain == AF_INET6;
                let Some(ref mut stack) = state.hw_net else {
                    return Err(Errno::ENETUNREACH);
                };
                let handle = match m.hw {
                    HardwareSockKind::Udp { handle, .. } => handle,
                    HardwareSockKind::None => {
                        let (bip, bp) = bound.unwrap_or(([0; 4], 0));
                        let h = stack.udp_open(bip, bp)?;
                        state.meta[idx].hw = HardwareSockKind::Udp { handle: h, is_v6 };
                        h
                    }
                    _ => return Err(Errno::EOPNOTSUPP),
                };
                used_hw_net = true;
                let n = stack.udp_send_to(handle, Some((ip, port)), payload, now)?;
                return Ok(Some(n));
            }

            match m.hw {
                HardwareSockKind::Udp { handle, .. } => {
                    used_hw_net = true;
                    let dst = dest.and_then(|d| extract_ipv4(&d, m.domain, m.ipv6_v6only));
                    let Some(ref mut stack) = state.hw_net else {
                        return Err(Errno::ENETUNREACH);
                    };
                    let n = stack.udp_send_to(handle, dst, payload, now)?;
                    Ok(Some(n))
                }
                HardwareSockKind::Tcp { handle, .. } => {
                    used_hw_net = true;
                    let Some(ref mut stack) = state.hw_net else {
                        return Err(Errno::ENETUNREACH);
                    };
                    let n = stack.tcp_send(handle, &payload[offset..], now)?;
                    Ok(Some(n))
                }
                HardwareSockKind::None => {
                    let n = state.table.send(idx, &payload[offset..], dest, rights)?;
                    Ok(Some(n))
                }
                HardwareSockKind::TcpListener { .. } => Err(Errno::ENOTCONN),
            }
        })?;

        if used_hw_net {
            drain_tx_frames();
        }

        match step {
            Ok(Some(n)) => {
                if !used_hw_net || matches!(n, _ if n == payload.len() - offset) {
                    return Ok(encode_result(Ok((offset + n) as i64)));
                }
                offset += n;
                if offset >= payload.len() || is_nonblock {
                    return Ok(encode_result(Ok(offset as i64)));
                }
                // Wait for TCP TX window space to open up before continuing stream send.
                if let Some(tmo) = snd_timeout_ns
                    && net_now_ns().saturating_sub(start_ns) >= tmo
                {
                    return Ok(encode_result(Ok(offset as i64)));
                }
                if let Some(ret) =
                    super::step35_events_cgroup::blocking_wait_step(frame.as_deref_mut())?
                {
                    if offset > 0 {
                        return Ok(encode_result(Ok(offset as i64)));
                    }
                    return Ok(ret);
                }
            }
            Ok(None) | Err(Errno::EAGAIN) => {
                if offset > 0 {
                    return Ok(encode_result(Ok(offset as i64)));
                }
                if is_nonblock {
                    return Ok(SyscallReturn::error(Errno::EAGAIN));
                }
                if let Some(tmo) = snd_timeout_ns
                    && net_now_ns().saturating_sub(start_ns) >= tmo
                {
                    return Ok(SyscallReturn::error(Errno::EAGAIN));
                }
                if let Some(ret) =
                    super::step35_events_cgroup::blocking_wait_step(frame.as_deref_mut())?
                {
                    return Ok(ret);
                }
            }
            Err(e) => {
                if offset > 0 {
                    return Ok(encode_result(Ok(offset as i64)));
                }
                return Ok(SyscallReturn::error(e));
            }
        }
    }
}

fn recv_payload_blocking(
    mut frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    max_len: usize,
    flags: u32,
) -> Result<Result<(Vec<u8>, Option<SockAddr>, [i32; MAX_SCM_RIGHTS_FDS], usize), SyscallReturn>, ()>
{
    let process = current_process_object().unwrap_or(ObjectId(1));
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(SyscallReturn::error(e))),
    };
    let peek = (flags & MSG_PEEK) != 0;
    let dontwait = (flags & MSG_DONTWAIT) != 0;
    let start_ns = net_now_ns();
    let take = max_len.min(MAX_IOV_BYTES);

    loop {
        pump_hardware_net();
        let now = net_now_ns();
        let mut is_nonblock = dontwait;
        let mut rcv_timeout_ns = None;
        let mut used_hw_net = false;

        let res = with_net_full(|state| {
            state.check_slot(process, idx, alias_gen)?;
            let m = state.meta[idx];
            is_nonblock |= m.nonblocking;
            rcv_timeout_ns = m.rcv_timeout_ns;

            if m.domain == AF_NETLINK && m.proto == NETLINK_ROUTE {
                state.ensure_netlink_vec();
                let q = &mut state.netlink_rx[idx];
                let msg = if peek {
                    q.front().cloned()
                } else {
                    q.pop_front()
                };
                let Some(msg) = msg else {
                    return Err(Errno::EAGAIN);
                };
                let copy_len = take.min(msg.len());
                let out = msg[..copy_len].to_vec();
                return Ok((
                    out,
                    Some(SockAddr::Netlink { pid: 0, groups: 0 }),
                    [-1; MAX_SCM_RIGHTS_FDS],
                    0,
                ));
            }

            let mut buf = vec![0u8; take];
            match m.hw {
                HardwareSockKind::Udp { handle, .. } => {
                    used_hw_net = true;
                    let Some(ref mut stack) = state.hw_net else {
                        return Err(Errno::ENETUNREACH);
                    };
                    let (n, src_ip, src_port) = stack.udp_recv_from(handle, &mut buf, peek)?;
                    buf.truncate(n);
                    let peer = encode_sockaddr_for_domain(m.domain, src_ip, src_port);
                    Ok((buf, Some(peer), [-1; MAX_SCM_RIGHTS_FDS], 0))
                }
                HardwareSockKind::Tcp { handle, .. } => {
                    used_hw_net = true;
                    let Some(ref mut stack) = state.hw_net else {
                        return Err(Errno::ENETUNREACH);
                    };
                    let n = stack.tcp_recv(handle, &mut buf, peek, now)?;
                    buf.truncate(n);
                    let peer = stack
                        .tcp_addrs(handle)
                        .map(|a| encode_sockaddr_for_domain(m.domain, a.remote_ip, a.remote_port));
                    Ok((buf, peer, [-1; MAX_SCM_RIGHTS_FDS], 0))
                }
                HardwareSockKind::None => {
                    let (n, peer, rights, rcount) =
                        state.table.recv_with_peek(idx, &mut buf, peek)?;
                    buf.truncate(n);
                    Ok((buf, peer, rights, rcount))
                }
                HardwareSockKind::TcpListener { .. } => Err(Errno::ENOTCONN),
            }
        })?;

        if used_hw_net {
            drain_tx_frames();
        }

        match res {
            Ok(tuple) => return Ok(Ok(tuple)),
            Err(Errno::EAGAIN) if !is_nonblock => {
                if let Some(tmo) = rcv_timeout_ns
                    && net_now_ns().saturating_sub(start_ns) >= tmo
                {
                    return Ok(Err(SyscallReturn::error(Errno::EAGAIN)));
                }
                if let Some(ret) =
                    super::step35_events_cgroup::blocking_wait_step(frame.as_deref_mut())?
                {
                    return Ok(Err(ret));
                }
            }
            Err(e) => return Ok(Err(SyscallReturn::error(e))),
        }
    }
}

fn handle_sendto_blocking(
    frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    user_buf: u64,
    len: u64,
    raw_flags: u64,
    user_dest: u64,
    addrlen: u64,
) -> Result<SyscallReturn, ()> {
    if let Err(e) = resolve_socket_target(raw_fd) {
        return Ok(SyscallReturn::error(e));
    }
    let dest = if user_dest != 0 {
        match read_user_sockaddr(user_dest, addrlen) {
            Ok(a) => Some(a),
            Err(e) => return Ok(SyscallReturn::error(e)),
        }
    } else {
        None
    };
    let take = usize::try_from(len)
        .unwrap_or(MAX_IOV_BYTES)
        .min(MAX_IOV_BYTES);
    let mut buf = vec![0u8; take];
    if take > 0
        && let Err(e) = copy_from_user(&mut buf, user_buf)
    {
        return Ok(SyscallReturn::error(e));
    }
    send_payload_blocking(
        frame,
        raw_fd,
        &buf,
        linux_unsigned_int(raw_flags),
        dest,
        &[],
    )
}

fn handle_recvfrom_blocking(
    frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    user_buf: u64,
    len: u64,
    raw_flags: u64,
    user_src: u64,
    user_addrlen: u64,
) -> Result<SyscallReturn, ()> {
    if let Err(e) = resolve_socket_target(raw_fd) {
        return Ok(SyscallReturn::error(e));
    }
    let take = usize::try_from(len)
        .unwrap_or(MAX_IOV_BYTES)
        .min(MAX_IOV_BYTES);
    if take > 0 && user_buf == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }
    let (data, peer_addr, _, _) =
        match recv_payload_blocking(frame, raw_fd, take, linux_unsigned_int(raw_flags))? {
            Ok(t) => t,
            Err(ret) => return Ok(ret),
        };
    if !data.is_empty()
        && let Err(e) = copy_to_user(user_buf, &data)
    {
        return Ok(SyscallReturn::error(e));
    }
    if user_src != 0
        && let Some(addr) = peer_addr
        && let Err(e) = write_user_sockaddr(user_src, user_addrlen, &addr)
    {
        return Ok(SyscallReturn::error(e));
    }
    Ok(encode_result(Ok(data.len() as i64)))
}

fn handle_writev_blocking(
    frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    user_iov: u64,
    iovcnt: u64,
) -> Result<SyscallReturn, ()> {
    if let Err(e) = resolve_socket_target(raw_fd) {
        return Ok(SyscallReturn::error(e));
    }
    let count = usize::try_from(iovcnt).unwrap_or(usize::MAX);
    if count > 1024 {
        return Ok(SyscallReturn::error(Errno::EINVAL));
    }
    let mut payload = Vec::new();
    for i in 0..count {
        let Ok((base, len)) = read_user_iovec(user_iov, i) else {
            return Ok(SyscallReturn::error(Errno::EFAULT));
        };
        if len == 0 {
            continue;
        }
        let room = MAX_IOV_BYTES.saturating_sub(payload.len());
        let take = len.min(room);
        if take > 0 {
            let start = payload.len();
            payload.resize(start + take, 0);
            if let Err(e) = copy_from_user(&mut payload[start..], base) {
                return Ok(SyscallReturn::error(e));
            }
        }
        if payload.len() >= MAX_IOV_BYTES {
            break;
        }
    }
    send_payload_blocking(frame, raw_fd, &payload, 0, None, &[])
}

fn handle_readv_blocking(
    frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    user_iov: u64,
    iovcnt: u64,
) -> Result<SyscallReturn, ()> {
    if let Err(e) = resolve_socket_target(raw_fd) {
        return Ok(SyscallReturn::error(e));
    }
    let count = usize::try_from(iovcnt).unwrap_or(usize::MAX);
    if count > 1024 {
        return Ok(SyscallReturn::error(Errno::EINVAL));
    }
    let mut iovs = Vec::with_capacity(count.min(64));
    let mut total = 0usize;
    for i in 0..count {
        let Ok((base, len)) = read_user_iovec(user_iov, i) else {
            return Ok(SyscallReturn::error(Errno::EFAULT));
        };
        let room = MAX_IOV_BYTES.saturating_sub(total);
        let take = len.min(room);
        iovs.push((base, take));
        total += take;
        if total >= MAX_IOV_BYTES {
            break;
        }
    }
    let (data, _, _, _) = match recv_payload_blocking(frame, raw_fd, total, 0)? {
        Ok(t) => t,
        Err(ret) => return Ok(ret),
    };
    let mut off = 0usize;
    for (base, take) in iovs {
        if off >= data.len() {
            break;
        }
        let chunk = take.min(data.len() - off);
        if chunk > 0 {
            if let Err(e) = copy_to_user(base, &data[off..off + chunk]) {
                return Ok(SyscallReturn::error(e));
            }
            off += chunk;
        }
    }
    Ok(encode_result(Ok(off as i64)))
}

fn handle_setsockopt(
    raw_fd: u64,
    raw_level: u64,
    raw_optname: u64,
    user_optval: u64,
    optlen: u64,
) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_object().unwrap_or(ObjectId(1));
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    if user_optval == 0 || optlen < 4 {
        return Ok(Err(Errno::EINVAL));
    }
    let level = linux_unsigned_int(raw_level);
    let optname = linux_unsigned_int(raw_optname);

    if level == SOL_SOCKET
        && matches!(
            optname,
            SO_RCVTIMEO_OLD | SO_SNDTIMEO_OLD | SO_RCVTIMEO_NEW | SO_SNDTIMEO_NEW
        )
    {
        if optlen < 16 {
            return Ok(Err(Errno::EINVAL));
        }
        let mut tv = [0u8; 16];
        if let Err(e) = copy_from_user(&mut tv, user_optval) {
            return Ok(Err(e));
        }
        let sec = i64::from_le_bytes(tv[0..8].try_into().unwrap());
        let usec = i64::from_le_bytes(tv[8..16].try_into().unwrap());
        if sec < 0 || !(0..1_000_000).contains(&usec) {
            return Ok(Err(Errno::EINVAL));
        }
        let ns = (sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add((usec as u64).saturating_mul(1000));
        let tmo = if ns == 0 { None } else { Some(ns) };
        return with_net_full(|state| {
            state.check_slot(process, idx, alias_gen)?;
            if optname == SO_RCVTIMEO_OLD || optname == SO_RCVTIMEO_NEW {
                state.meta[idx].rcv_timeout_ns = tmo;
            } else {
                state.meta[idx].snd_timeout_ns = tmo;
            }
            Ok(0)
        });
    }

    let mut raw_val = [0u8; 4];
    if let Err(e) = copy_from_user(&mut raw_val, user_optval) {
        return Ok(Err(e));
    }
    let val = u32::from_le_bytes(raw_val);
    with_net_full(|state| {
        state.check_slot(process, idx, alias_gen)?;
        if level == IPPROTO_IPV6 && optname == IPV6_V6ONLY {
            state.meta[idx].ipv6_v6only = val != 0;
        }
        match state.table.setsockopt(idx, level, optname, val) {
            Ok(()) => Ok(0),
            Err(Errno::ENOPROTOOPT)
                if level == IPPROTO_TCP || level == IPPROTO_IPV6 || level == SOL_SOCKET =>
            {
                Ok(0)
            }
            Err(e) => Err(e),
        }
    })
}

fn handle_getsockopt(
    raw_fd: u64,
    raw_level: u64,
    raw_optname: u64,
    user_optval: u64,
    user_optlen: u64,
) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_object().unwrap_or(ObjectId(1));
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    if user_optval == 0 || user_optlen == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut len_bytes = [0u8; 4];
    if let Err(e) = copy_from_user(&mut len_bytes, user_optlen) {
        return Ok(Err(e));
    }
    let max_len = (u32::from_le_bytes(len_bytes) as usize).min(32);
    let mut out = [0u8; 32];
    let level = linux_unsigned_int(raw_level);
    let optname = linux_unsigned_int(raw_optname);

    let res = with_net_full(|state| {
        state.check_slot(process, idx, alias_gen)?;
        let m = state.meta[idx];
        if level == SOL_SOCKET && optname == SO_ERROR {
            if max_len < 4 {
                return Err(Errno::EINVAL);
            }
            let err_val = match m.hw {
                HardwareSockKind::Tcp { handle, .. } => state
                    .hw_net
                    .as_mut()
                    .and_then(|s| s.tcp_take_error(handle))
                    .map(|e| u32::from(e.get()))
                    .unwrap_or(0),
                _ => 0,
            };
            out[0..4].copy_from_slice(&err_val.to_le_bytes());
            return Ok(4usize);
        }
        if level == SOL_SOCKET && optname == SO_PROTOCOL {
            if max_len < 4 {
                return Err(Errno::EINVAL);
            }
            let p = if m.proto != 0 {
                m.proto
            } else if m.domain == AF_INET || m.domain == AF_INET6 {
                if m.sock_type == SOCK_STREAM { 6 } else { 17 }
            } else {
                0
            };
            out[0..4].copy_from_slice(&p.to_le_bytes());
            return Ok(4usize);
        }
        if level == SOL_SOCKET && (optname == SO_RCVBUF || optname == SO_SNDBUF) {
            if max_len < 4 {
                return Err(Errno::EINVAL);
            }
            out[0..4].copy_from_slice(&(131_072u32).to_le_bytes());
            return Ok(4usize);
        }
        if level == SOL_SOCKET && optname == SO_TYPE {
            if max_len < 4 {
                return Err(Errno::EINVAL);
            }
            out[0..4].copy_from_slice(&m.sock_type.to_le_bytes());
            return Ok(4usize);
        }
        if level == SOL_SOCKET && optname == SO_DOMAIN {
            if max_len < 4 {
                return Err(Errno::EINVAL);
            }
            out[0..4].copy_from_slice(&u32::from(m.domain).to_le_bytes());
            return Ok(4usize);
        }
        state
            .table
            .getsockopt(idx, level, optname, &mut out[..max_len])
    })?;
    let written = match res {
        Ok(w) => w,
        Err(e) => return Ok(Err(e)),
    };
    if let Err(e) = copy_to_user(user_optval, &out[..written]) {
        return Ok(Err(e));
    }
    if let Err(e) = copy_to_user(user_optlen, &(written as u32).to_le_bytes()) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn handle_shutdown(raw_fd: u64, raw_how: u64) -> Result<Result<i64, Errno>, ()> {
    let how = linux_unsigned_int(raw_how);
    if !matches!(how, SHUT_RD | SHUT_WR | SHUT_RDWR) {
        return Ok(Err(Errno::EINVAL));
    }
    let process = current_process_object().unwrap_or(ObjectId(1));
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    let now = net_now_ns();
    let res = with_net_full(|state| {
        state.check_slot(process, idx, alias_gen)?;
        match state.meta[idx].hw {
            HardwareSockKind::Tcp { handle, .. } => {
                let Some(ref mut stack) = state.hw_net else {
                    return Err(Errno::ENOTCONN);
                };
                let rd = how == SHUT_RD || how == SHUT_RDWR;
                let wr = how == SHUT_WR || how == SHUT_RDWR;
                stack.tcp_shutdown(handle, rd, wr, now)?;
                Ok(0)
            }
            HardwareSockKind::Udp { .. } => Ok(0),
            HardwareSockKind::None | HardwareSockKind::TcpListener { .. } => {
                state.table.shutdown(idx, how).map(|()| 0)
            }
        }
    });
    drain_tx_frames();
    res
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = (linux_signed_int(raw_fd) - SOCK_FD_BASE) as usize;
    let process = current_process_object().unwrap_or(ObjectId(1));
    let now = net_now_ns();
    let res = with_net_full(|state| {
        state.check_slot(process, idx, None)?;
        let _ = state.meta[idx].owners.close_owner(process);
        state.retire_if_unused(idx, now);
        Ok(0)
    });
    drain_tx_frames();
    res
}

fn handle_fstat(raw_fd: u64, user_statbuf: u64) -> Result<Result<i64, Errno>, ()> {
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    if user_statbuf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let process = current_process_object().unwrap_or(ObjectId(1));
    with_net_full(|state| {
        state.check_slot(process, idx, alias_gen)?;
        let mut buf = [0u8; ARM64_STAT_BYTES];
        buf[16..20].copy_from_slice(&S_IFSOCK_MODE.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[56..60].copy_from_slice(&(SOCK_BUF_CAP as i32).to_le_bytes());
        copy_to_user(user_statbuf, &buf)?;
        Ok(0)
    })
}

fn handle_sendmsg_blocking(
    frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    user_msghdr: u64,
    raw_flags: u64,
) -> Result<SyscallReturn, ()> {
    if let Err(e) = resolve_socket_target(raw_fd) {
        return Ok(SyscallReturn::error(e));
    }
    if user_msghdr == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }
    let mut hdr = [0u8; 56];
    if let Err(e) = copy_from_user(&mut hdr, user_msghdr) {
        return Ok(SyscallReturn::error(e));
    }
    let msg_name = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
    let msg_namelen = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as u64;
    let msg_iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    let msg_iovlen = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    let msg_control = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
    let msg_controllen = u64::from_le_bytes(hdr[40..48].try_into().unwrap());

    if msg_iovlen > 64 {
        return Ok(SyscallReturn::error(Errno::EMSGSIZE));
    }
    let dest = if msg_name != 0 && msg_namelen > 0 {
        match read_user_sockaddr(msg_name, msg_namelen) {
            Ok(a) => Some(a),
            Err(e) => return Ok(SyscallReturn::error(e)),
        }
    } else {
        None
    };

    let mut payload = Vec::new();
    for i in 0..(msg_iovlen as usize) {
        let Ok((base, len)) = read_user_iovec(msg_iov, i) else {
            return Ok(SyscallReturn::error(Errno::EFAULT));
        };
        let room = MAX_IOV_BYTES.saturating_sub(payload.len());
        let take = len.min(room);
        if take > 0 {
            let start = payload.len();
            payload.resize(start + take, 0);
            if let Err(e) = copy_from_user(&mut payload[start..], base) {
                return Ok(SyscallReturn::error(e));
            }
        }
        if payload.len() >= MAX_IOV_BYTES {
            break;
        }
    }

    let mut rights = [0i32; MAX_SCM_RIGHTS_FDS];
    let mut rights_count = 0usize;
    if msg_control != 0 && msg_controllen >= 16 {
        let mut cmsg = [0u8; 16 + MAX_SCM_RIGHTS_FDS * 4];
        let copy_len = (msg_controllen as usize).min(cmsg.len());
        if let Err(e) = copy_from_user(&mut cmsg[..copy_len], msg_control) {
            return Ok(SyscallReturn::error(e));
        }
        let cmsg_len = u64::from_le_bytes(cmsg[0..8].try_into().unwrap()) as usize;
        let cmsg_level = i32::from_le_bytes(cmsg[8..12].try_into().unwrap());
        let cmsg_type = i32::from_le_bytes(cmsg[12..16].try_into().unwrap());
        if cmsg_level == (SOL_SOCKET as i32) && cmsg_type == SCM_RIGHTS && cmsg_len >= 16 {
            let data_bytes = cmsg_len.min(copy_len) - 16;
            rights_count = (data_bytes / 4).min(MAX_SCM_RIGHTS_FDS);
            for (r_idx, slot) in rights.iter_mut().enumerate().take(rights_count) {
                let off = 16 + r_idx * 4;
                *slot = i32::from_le_bytes(cmsg[off..off + 4].try_into().unwrap());
            }
        }
    }

    send_payload_blocking(
        frame,
        raw_fd,
        &payload,
        linux_unsigned_int(raw_flags),
        dest,
        &rights[..rights_count],
    )
}

fn handle_recvmsg_blocking(
    frame: Option<&mut ExceptionFrame>,
    raw_fd: u64,
    user_msghdr: u64,
    raw_flags: u64,
) -> Result<SyscallReturn, ()> {
    if let Err(e) = resolve_socket_target(raw_fd) {
        return Ok(SyscallReturn::error(e));
    }
    if user_msghdr == 0 {
        return Ok(SyscallReturn::error(Errno::EFAULT));
    }
    let mut hdr = [0u8; 56];
    if let Err(e) = copy_from_user(&mut hdr, user_msghdr) {
        return Ok(SyscallReturn::error(e));
    }
    let msg_name = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
    let msg_namelen = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    let msg_iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    let msg_iovlen = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    let msg_control = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
    let msg_controllen = u64::from_le_bytes(hdr[40..48].try_into().unwrap()) as usize;

    if msg_iovlen > 64 {
        return Ok(SyscallReturn::error(Errno::EMSGSIZE));
    }
    let mut iovs = Vec::with_capacity((msg_iovlen as usize).min(64));
    let mut total_iov = 0usize;
    for i in 0..(msg_iovlen as usize) {
        let Ok((base, len)) = read_user_iovec(msg_iov, i) else {
            return Ok(SyscallReturn::error(Errno::EFAULT));
        };
        let room = MAX_IOV_BYTES.saturating_sub(total_iov);
        let take = len.min(room);
        iovs.push((base, take));
        total_iov += take;
        if total_iov >= MAX_IOV_BYTES {
            break;
        }
    }

    let (data, peer, rights, rights_count) =
        match recv_payload_blocking(frame, raw_fd, total_iov, linux_unsigned_int(raw_flags))? {
            Ok(t) => t,
            Err(ret) => return Ok(ret),
        };

    let mut off = 0usize;
    for (base, take) in iovs {
        if off >= data.len() {
            break;
        }
        let chunk = take.min(data.len() - off);
        if chunk > 0 {
            if let Err(e) = copy_to_user(base, &data[off..off + chunk]) {
                return Ok(SyscallReturn::error(e));
            }
            off += chunk;
        }
    }

    if msg_name != 0
        && msg_namelen > 0
        && let Some(ref addr) = peer
    {
        let mut encoded = [0u8; MAX_SOCKADDR_BYTES];
        let actual = addr.encode(&mut encoded);
        let cp = actual.min(msg_namelen as usize);
        if cp > 0
            && let Err(e) = copy_to_user(msg_name, &encoded[..cp])
        {
            return Ok(SyscallReturn::error(e));
        }
        hdr[8..12].copy_from_slice(&(actual as u32).to_le_bytes());
    }

    let mut out_cmsg_len = 0usize;
    if rights_count > 0 && msg_control != 0 && msg_controllen >= 16 + rights_count * 4 {
        let cmsg_len = 16 + rights_count * 4;
        let mut cmsg = [0u8; 16 + MAX_SCM_RIGHTS_FDS * 4];
        cmsg[0..8].copy_from_slice(&(cmsg_len as u64).to_le_bytes());
        cmsg[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_le_bytes());
        cmsg[12..16].copy_from_slice(&SCM_RIGHTS.to_le_bytes());
        for (i, &fd) in rights.iter().enumerate().take(rights_count) {
            let off = 16 + i * 4;
            cmsg[off..off + 4].copy_from_slice(&fd.to_le_bytes());
        }
        if let Err(e) = copy_to_user(msg_control, &cmsg[..cmsg_len]) {
            return Ok(SyscallReturn::error(e));
        }
        out_cmsg_len = cmsg_len;
    }
    hdr[40..48].copy_from_slice(&(out_cmsg_len as u64).to_le_bytes());
    hdr[48..52].copy_from_slice(&0i32.to_le_bytes()); // msg_flags
    if let Err(e) = copy_to_user(user_msghdr, &hdr) {
        return Ok(SyscallReturn::error(e));
    }
    Ok(encode_result(Ok(off as i64)))
}

fn encode_ipv4_sockaddr_in(ip: [u8; 4], out: &mut [u8]) {
    out[0..16].fill(0);
    out[0..2].copy_from_slice(&AF_INET.to_le_bytes());
    out[4..8].copy_from_slice(&ip);
}

fn handle_socket_ioctl(raw_fd: u64, req: u64, arg: u64) -> Result<Result<i64, Errno>, ()> {
    let process = current_process_object().unwrap_or(ObjectId(1));
    let (idx, alias_gen) = match resolve_socket_target(raw_fd) {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    if arg == 0 {
        return Ok(Err(Errno::EFAULT));
    }

    match req {
        FIONREAD => {
            pump_hardware_net();
            with_net_full(|state| {
                state.check_slot(process, idx, alias_gen)?;
                let m = state.meta[idx];
                let unread: usize = if m.domain == AF_NETLINK && m.proto == NETLINK_ROUTE {
                    state
                        .netlink_rx
                        .get(idx)
                        .and_then(|q| q.front())
                        .map(|v| v.len())
                        .unwrap_or(0)
                } else {
                    match m.hw {
                        HardwareSockKind::Udp { handle, .. } => state
                            .hw_net
                            .as_ref()
                            .map(|s| s.udp_unread_bytes(handle))
                            .unwrap_or(0),
                        HardwareSockKind::Tcp { handle, .. } => state
                            .hw_net
                            .as_ref()
                            .map(|s| s.tcp_unread_bytes(handle))
                            .unwrap_or(0),
                        _ => state.table.rx_available(idx),
                    }
                };
                copy_to_user(arg, &(unread as i32).to_le_bytes())?;
                Ok(0)
            })
        }
        FIONBIO => {
            let mut val_bytes = [0u8; 4];
            if let Err(e) = copy_from_user(&mut val_bytes, arg) {
                return Ok(Err(e));
            }
            let nb = i32::from_le_bytes(val_bytes) != 0;
            with_net_full(|state| {
                state.check_slot(process, idx, alias_gen)?;
                state.meta[idx].nonblocking = nb;
                Ok(0)
            })
        }
        SIOCGIFCONF => {
            // struct ifconf { int ifc_len; u32 pad; u64 ifc_buf; } (16 bytes on aarch64)
            let mut ifc = [0u8; 16];
            if let Err(e) = copy_from_user(&mut ifc, arg) {
                return Ok(Err(e));
            }
            let buf_cap = i32::from_le_bytes(ifc[0..4].try_into().unwrap()).max(0) as usize;
            let buf_ptr = u64::from_le_bytes(ifc[8..16].try_into().unwrap());
            let iface = with_net_full(|state| {
                state.check_slot(process, idx, alias_gen)?;
                Ok(state.iface_config())
            })?;
            let iface = match iface {
                Ok(c) => c,
                Err(e) => return Ok(Err(e)),
            };
            let mut entries = Vec::new();
            let mut lo_req = [0u8; 40];
            lo_req[0..3].copy_from_slice(b"lo\0");
            encode_ipv4_sockaddr_in([127, 0, 0, 1], &mut lo_req[16..32]);
            entries.extend_from_slice(&lo_req);
            if iface.has_eth0 && iface.ip != [0, 0, 0, 0] {
                let mut eth_req = [0u8; 40];
                eth_req[0..5].copy_from_slice(b"eth0\0");
                encode_ipv4_sockaddr_in(iface.ip, &mut eth_req[16..32]);
                entries.extend_from_slice(&eth_req);
            }
            let write_len = entries.len().min(buf_cap);
            if buf_ptr != 0 && write_len > 0 {
                if let Err(e) = copy_to_user(buf_ptr, &entries[..write_len]) {
                    return Ok(Err(e));
                }
            } else if buf_ptr == 0 {
                // NULL ifc_buf returns required size.
                ifc[0..4].copy_from_slice(&(entries.len() as i32).to_le_bytes());
                if let Err(e) = copy_to_user(arg, &ifc) {
                    return Ok(Err(e));
                }
                return Ok(Ok(0));
            }
            ifc[0..4].copy_from_slice(&(write_len as i32).to_le_bytes());
            if let Err(e) = copy_to_user(arg, &ifc) {
                return Ok(Err(e));
            }
            Ok(Ok(0))
        }
        SIOCGIFFLAGS | SIOCGIFADDR | SIOCGIFNETMASK | SIOCGIFMTU | SIOCGIFHWADDR | SIOCGIFINDEX => {
            let mut ifreq = [0u8; 40];
            if let Err(e) = copy_from_user(&mut ifreq, arg) {
                return Ok(Err(e));
            }
            let name_len = ifreq[..16].iter().position(|&b| b == 0).unwrap_or(16);
            let name = &ifreq[..name_len];
            let iface = with_net_full(|state| {
                state.check_slot(process, idx, alias_gen)?;
                Ok(state.iface_config())
            })?;
            let iface = match iface {
                Ok(c) => c,
                Err(e) => return Ok(Err(e)),
            };
            if name == b"lo" {
                match req {
                    SIOCGIFINDEX => ifreq[16..20].copy_from_slice(&1i32.to_le_bytes()),
                    SIOCGIFFLAGS => ifreq[16..18].copy_from_slice(&0x0049i16.to_le_bytes()),
                    SIOCGIFADDR => encode_ipv4_sockaddr_in([127, 0, 0, 1], &mut ifreq[16..32]),
                    SIOCGIFNETMASK => encode_ipv4_sockaddr_in([255, 0, 0, 0], &mut ifreq[16..32]),
                    SIOCGIFMTU => ifreq[16..20].copy_from_slice(&65536i32.to_le_bytes()),
                    SIOCGIFHWADDR => {
                        ifreq[16..18].copy_from_slice(&772u16.to_le_bytes()); // ARPHRD_LOOPBACK
                        ifreq[18..24].fill(0);
                    }
                    _ => return Ok(Err(Errno::EINVAL)),
                }
            } else if name == b"eth0" && iface.has_eth0 {
                match req {
                    SIOCGIFINDEX => ifreq[16..20].copy_from_slice(&2i32.to_le_bytes()),
                    SIOCGIFFLAGS => {
                        let fl: i16 = if iface.link_up { 0x1043 } else { 0x1002 };
                        ifreq[16..18].copy_from_slice(&fl.to_le_bytes());
                    }
                    SIOCGIFADDR => encode_ipv4_sockaddr_in(iface.ip, &mut ifreq[16..32]),
                    SIOCGIFNETMASK => encode_ipv4_sockaddr_in(iface.netmask, &mut ifreq[16..32]),
                    SIOCGIFMTU => ifreq[16..20].copy_from_slice(&(iface.mtu as i32).to_le_bytes()),
                    SIOCGIFHWADDR => {
                        ifreq[16..18].copy_from_slice(&1u16.to_le_bytes()); // ARPHRD_ETHER
                        ifreq[18..24].copy_from_slice(&iface.mac);
                    }
                    _ => return Ok(Err(Errno::EINVAL)),
                }
            } else {
                return Ok(Err(Errno::ENODEV));
            }
            if let Err(e) = copy_to_user(arg, &ifreq) {
                return Ok(Err(e));
            }
            Ok(Ok(0))
        }
        _ => Ok(Err(Errno::ENOTTY)),
    }
}

fn read_user_sockaddr(user_addr: u64, addrlen: u64) -> Result<SockAddr, Errno> {
    if user_addr == 0 {
        return Err(Errno::EFAULT);
    }
    let len = usize::try_from(addrlen).map_err(|_| Errno::EINVAL)?;
    if !(2..=MAX_SOCKADDR_BYTES).contains(&len) {
        return Err(Errno::EINVAL);
    }
    let mut raw = [0u8; MAX_SOCKADDR_BYTES];
    copy_from_user(&mut raw[..len], user_addr)?;
    if len >= 2 && u16::from_le_bytes([raw[0], raw[1]]) == AF_UNSPEC {
        return Ok(SockAddr::Inet {
            ip: [0, 0, 0, 0],
            port: 0,
        });
    }
    SockAddr::parse(&raw[..len])
}

fn write_user_sockaddr(user_addr: u64, user_addrlen: u64, addr: &SockAddr) -> Result<(), Errno> {
    if user_addr == 0 || user_addrlen == 0 {
        return Err(Errno::EFAULT);
    }
    let mut len_bytes = [0u8; 4];
    copy_from_user(&mut len_bytes, user_addrlen)?;
    let max_len = (u32::from_le_bytes(len_bytes) as usize).min(MAX_SOCKADDR_BYTES);
    let mut encoded = [0u8; MAX_SOCKADDR_BYTES];
    let actual_len = addr.encode(&mut encoded);
    let copy_len = max_len.min(actual_len);
    if copy_len > 0 {
        copy_to_user(user_addr, &encoded[..copy_len])?;
    }
    copy_to_user(user_addrlen, &(actual_len as u32).to_le_bytes())
}

fn copy_from_user(dst: &mut [u8], user_src: u64) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_from_user(dst, user_src).map_err(super::map_usercopy_errno)
}

fn copy_to_user(user_dst: u64, src: &[u8]) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_to_user(user_dst, src).map_err(super::map_usercopy_errno)
}

/// Broadcasts a kernel kobject uevent payload to all bound `NETLINK_KOBJECT_UEVENT` sockets.
pub(super) fn broadcast_netlink_uevent(msg: &[u8]) -> Result<usize, ()> {
    with_net_full(|state| state.table.broadcast_netlink_uevent(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_fd_window_is_disjoint_from_earlier_subsystems() {
        assert!(!is_socket_fd(0));
        assert!(!is_socket_fd(64));
        assert!(!is_socket_fd(96));
        assert!(is_socket_fd(SOCK_FD_BASE as u64));
        assert!(is_socket_fd(
            (SOCK_FD_BASE + (MAX_SOCKETS as i32) - 1) as u64
        ));
        assert!(!is_socket_fd((SOCK_FD_BASE + (MAX_SOCKETS as i32)) as u64));
    }
}
