// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 34 — Debian networking: `AF_UNIX` (`SOCK_STREAM`, `SOCK_DGRAM`, `SOCK_SEQPACKET`,
//! `SCM_RIGHTS`, `SO_PEERCRED`), IPv4/IPv6 loopback TCP & UDP socket state machines,
//! bounded `NETLINK_ROUTE` (`AF_NETLINK`) link/address/route dumps, and DNS resolver packet codec.

use kernal_linux_abi::Errno;

/// Linux address families (`<sys/socket.h>`).
pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_NETLINK: u16 = 16;

/// Linux socket types and creation flags (`<sys/socket.h>`).
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_SEQPACKET: u32 = 5;
pub const SOCK_TYPE_MASK: u32 = 0x0f;
pub const SOCK_NONBLOCK: u32 = 0o000_4000; // 0x800
pub const SOCK_CLOEXEC: u32 = 0o200_0000; // 0x80000

/// Linux `shutdown(2)` modes.
pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
pub const SHUT_RDWR: u32 = 2;

/// Linux socket option levels and option names.
pub const SOL_SOCKET: u32 = 1;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_IPV6: u32 = 41;

pub const SO_REUSEADDR: u32 = 2;
pub const SO_TYPE: u32 = 3;
pub const SO_ERROR: u32 = 4;
pub const SO_SNDBUF: u32 = 7;
pub const SO_RCVBUF: u32 = 8;
pub const SO_KEEPALIVE: u32 = 9;
pub const SO_REUSEPORT: u32 = 15;
pub const SO_PASSCRED: u32 = 16;
pub const SO_PEERCRED: u32 = 17;
pub const SO_DOMAIN: u32 = 39;
pub const TCP_NODELAY: u32 = 1;
pub const IPV6_V6ONLY: u32 = 26;

/// `SCM_RIGHTS` ancillary control message type (`SOL_SOCKET = 1`, `SCM_RIGHTS = 1`).
pub const SCM_RIGHTS: i32 = 1;
pub const MAX_SCM_RIGHTS_FDS: usize = 4;
pub const MAX_UNIX_PATH: usize = 64;

/// Netlink constants (`<linux/netlink.h>`, `<linux/rtnetlink.h>`).
pub const NETLINK_ROUTE: u32 = 0;
pub const NETLINK_KOBJECT_UEVENT: u32 = 15;
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_GETROUTE: u16 = 26;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    Unix,
    Inet,
    Inet6,
    Netlink,
}

impl AddressFamily {
    pub const fn from_raw(raw: u16) -> Result<Self, Errno> {
        match raw {
            AF_UNIX => Ok(Self::Unix),
            AF_INET => Ok(Self::Inet),
            AF_INET6 => Ok(Self::Inet6),
            AF_NETLINK => Ok(Self::Netlink),
            _ => Err(Errno::EAFNOSUPPORT),
        }
    }

    pub const fn as_raw(self) -> u16 {
        match self {
            Self::Unix => AF_UNIX,
            Self::Inet => AF_INET,
            Self::Inet6 => AF_INET6,
            Self::Netlink => AF_NETLINK,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketKind {
    Stream,
    Dgram,
    SeqPacket,
    Raw,
}

impl SocketKind {
    pub const fn decode(raw_type: u32) -> Result<(Self, bool, bool), Errno> {
        let allowed_flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
        if (raw_type & !SOCK_TYPE_MASK) & !allowed_flags != 0 {
            return Err(Errno::EINVAL);
        }
        let kind = match raw_type & SOCK_TYPE_MASK {
            SOCK_STREAM => Self::Stream,
            SOCK_DGRAM => Self::Dgram,
            SOCK_SEQPACKET => Self::SeqPacket,
            SOCK_RAW => Self::Raw,
            _ => return Err(Errno::EINVAL),
        };
        let nonblocking = (raw_type & SOCK_NONBLOCK) != 0;
        let cloexec = (raw_type & SOCK_CLOEXEC) != 0;
        Ok((kind, nonblocking, cloexec))
    }

    pub const fn as_raw(self) -> u32 {
        match self {
            Self::Stream => SOCK_STREAM,
            Self::Dgram => SOCK_DGRAM,
            Self::SeqPacket => SOCK_SEQPACKET,
            Self::Raw => SOCK_RAW,
        }
    }
}

/// Credentials reported by `getsockopt(..., SOL_SOCKET, SO_PEERCRED)` (`struct ucred`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ucred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Ucred {
    pub const ROOT_INIT: Self = Self {
        pid: 1,
        uid: 0,
        gid: 0,
    };

    pub const fn to_le_bytes(self) -> [u8; 12] {
        let mut out = [0u8; 12];
        let p = self.pid.to_le_bytes();
        let u = self.uid.to_le_bytes();
        let g = self.gid.to_le_bytes();
        out[0] = p[0];
        out[1] = p[1];
        out[2] = p[2];
        out[3] = p[3];
        out[4] = u[0];
        out[5] = u[1];
        out[6] = u[2];
        out[7] = u[3];
        out[8] = g[0];
        out[9] = g[1];
        out[10] = g[2];
        out[11] = g[3];
        out
    }
}

/// Parsed socket address (`sockaddr_un`, `sockaddr_in`, `sockaddr_in6`, `sockaddr_nl`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SockAddr {
    Unix {
        abstract_ns: bool,
        path: [u8; MAX_UNIX_PATH],
        len: usize,
    },
    Inet {
        ip: [u8; 4],
        port: u16,
    },
    Inet6 {
        ip: [u8; 16],
        port: u16,
    },
    Netlink {
        pid: u32,
        groups: u32,
    },
}

impl SockAddr {
    pub fn parse(raw: &[u8]) -> Result<Self, Errno> {
        if raw.len() < 2 {
            return Err(Errno::EINVAL);
        }
        let family = u16::from_le_bytes([raw[0], raw[1]]);
        match family {
            AF_UNIX => {
                let sun_path = &raw[2..];
                if sun_path.is_empty() {
                    return Ok(Self::Unix {
                        abstract_ns: false,
                        path: [0u8; MAX_UNIX_PATH],
                        len: 0,
                    });
                }
                let abstract_ns = sun_path[0] == 0;
                let payload = if abstract_ns {
                    &sun_path[1..]
                } else {
                    let end = sun_path
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(sun_path.len());
                    &sun_path[..end]
                };
                if payload.len() > MAX_UNIX_PATH {
                    return Err(Errno::ENAMETOOLONG);
                }
                let mut path = [0u8; MAX_UNIX_PATH];
                path[..payload.len()].copy_from_slice(payload);
                Ok(Self::Unix {
                    abstract_ns,
                    path,
                    len: payload.len(),
                })
            }
            AF_INET => {
                if raw.len() < 8 {
                    return Err(Errno::EINVAL);
                }
                let port = u16::from_be_bytes([raw[2], raw[3]]);
                let ip = [raw[4], raw[5], raw[6], raw[7]];
                Ok(Self::Inet { ip, port })
            }
            AF_INET6 => {
                if raw.len() < 24 {
                    return Err(Errno::EINVAL);
                }
                let port = u16::from_be_bytes([raw[2], raw[3]]);
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&raw[8..24]);
                Ok(Self::Inet6 { ip, port })
            }
            AF_NETLINK => {
                if raw.len() < 12 {
                    return Err(Errno::EINVAL);
                }
                let pid = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
                let groups = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
                Ok(Self::Netlink { pid, groups })
            }
            _ => Err(Errno::EAFNOSUPPORT),
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> usize {
        match *self {
            Self::Unix {
                abstract_ns,
                ref path,
                len,
            } => {
                let mut raw = [0u8; 2 + 1 + MAX_UNIX_PATH + 1];
                raw[0..2].copy_from_slice(&AF_UNIX.to_le_bytes());
                let total = if len == 0 {
                    2
                } else if abstract_ns {
                    raw[2] = 0;
                    raw[3..3 + len].copy_from_slice(&path[..len]);
                    3 + len
                } else {
                    raw[2..2 + len].copy_from_slice(&path[..len]);
                    raw[2 + len] = 0;
                    3 + len
                };
                let take = out.len().min(total);
                out[..take].copy_from_slice(&raw[..take]);
                total
            }
            Self::Inet { ip, port } => {
                let mut raw = [0u8; 16];
                raw[0..2].copy_from_slice(&AF_INET.to_le_bytes());
                raw[2..4].copy_from_slice(&port.to_be_bytes());
                raw[4..8].copy_from_slice(&ip);
                let take = out.len().min(16);
                out[..take].copy_from_slice(&raw[..take]);
                16
            }
            Self::Inet6 { ip, port } => {
                let mut raw = [0u8; 28];
                raw[0..2].copy_from_slice(&AF_INET6.to_le_bytes());
                raw[2..4].copy_from_slice(&port.to_be_bytes());
                raw[8..24].copy_from_slice(&ip);
                let take = out.len().min(28);
                out[..take].copy_from_slice(&raw[..take]);
                28
            }
            Self::Netlink { pid, groups } => {
                let mut raw = [0u8; 12];
                raw[0..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
                raw[4..8].copy_from_slice(&pid.to_le_bytes());
                raw[8..12].copy_from_slice(&groups.to_le_bytes());
                let take = out.len().min(12);
                out[..take].copy_from_slice(&raw[..take]);
                12
            }
        }
    }

    pub const fn is_loopback_or_unspecified(&self) -> bool {
        match *self {
            Self::Unix { .. } | Self::Netlink { .. } => true,
            Self::Inet { ip, .. } => {
                ip[0] == 127 || (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0)
            }
            Self::Inet6 { ip, .. } => {
                let mut prefix_zero = true;
                let mut i = 0usize;
                while i < 15 {
                    if ip[i] != 0 {
                        prefix_zero = false;
                        break;
                    }
                    i += 1;
                }
                prefix_zero && (ip[15] == 0 || ip[15] == 1)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketState {
    Unbound,
    Bound,
    Listening,
    Connected,
    Closed,
}

#[derive(Clone, Copy)]
struct AncillaryRights {
    fds: [i32; MAX_SCM_RIGHTS_FDS],
    count: usize,
}

impl AncillaryRights {
    const EMPTY: Self = Self {
        fds: [-1; MAX_SCM_RIGHTS_FDS],
        count: 0,
    };
}

#[derive(Clone, Copy)]
struct SocketSlot<const BUF_CAP: usize> {
    live: bool,
    family: AddressFamily,
    kind: SocketKind,
    netlink_protocol: u32,
    state: SocketState,
    nonblocking: bool,
    cloexec: bool,
    reuseaddr: bool,
    passcred: bool,
    tcp_nodelay: bool,
    ipv6_v6only: bool,
    shut_rd: bool,
    shut_wr: bool,
    local_addr: Option<SockAddr>,
    peer_addr: Option<SockAddr>,
    peer_slot: Option<usize>,
    pending_accept: [Option<usize>; 4],
    pending_count: usize,
    rx_buf: [u8; BUF_CAP],
    rx_len: usize,
    rx_ancillary: AncillaryRights,
    peer_cred: Ucred,
}

impl<const BUF_CAP: usize> SocketSlot<BUF_CAP> {
    const EMPTY: Self = Self {
        live: false,
        family: AddressFamily::Unix,
        kind: SocketKind::Stream,
        netlink_protocol: 0,
        state: SocketState::Unbound,
        nonblocking: false,
        cloexec: false,
        reuseaddr: false,
        passcred: false,
        tcp_nodelay: false,
        ipv6_v6only: false,
        shut_rd: false,
        shut_wr: false,
        local_addr: None,
        peer_addr: None,
        peer_slot: None,
        pending_accept: [None; 4],
        pending_count: 0,
        rx_buf: [0u8; BUF_CAP],
        rx_len: 0,
        rx_ancillary: AncillaryRights::EMPTY,
        peer_cred: Ucred::ROOT_INIT,
    };
}

/// Bounded in-kernel socket table supporting `AF_UNIX`, `AF_INET`, `AF_INET6`, and `AF_NETLINK`.
pub struct SocketTable<const MAX_SOCKETS: usize, const BUF_CAP: usize> {
    slots: [SocketSlot<BUF_CAP>; MAX_SOCKETS],
    next_ephemeral_port: u16,
}

impl<const MAX_SOCKETS: usize, const BUF_CAP: usize> Default for SocketTable<MAX_SOCKETS, BUF_CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_SOCKETS: usize, const BUF_CAP: usize> SocketTable<MAX_SOCKETS, BUF_CAP> {
    pub const fn new() -> Self {
        Self {
            slots: [SocketSlot::EMPTY; MAX_SOCKETS],
            next_ephemeral_port: 49152,
        }
    }

    /// Creates a new socket (`socket(2)`).
    pub fn socket(
        &mut self,
        raw_domain: u16,
        raw_type: u32,
        protocol: u32,
    ) -> Result<usize, Errno> {
        let family = AddressFamily::from_raw(raw_domain)?;
        let (kind, nonblocking, cloexec) = SocketKind::decode(raw_type)?;
        match (family, kind) {
            (
                AddressFamily::Unix,
                SocketKind::Stream | SocketKind::Dgram | SocketKind::SeqPacket,
            ) => {
                if protocol != 0 {
                    return Err(Errno::EPROTONOSUPPORT);
                }
            }
            (AddressFamily::Inet | AddressFamily::Inet6, SocketKind::Stream) => {
                if protocol != 0 && protocol != IPPROTO_TCP {
                    return Err(Errno::EPROTONOSUPPORT);
                }
            }
            (AddressFamily::Inet | AddressFamily::Inet6, SocketKind::Dgram) => {
                if protocol != 0 && protocol != 17 {
                    return Err(Errno::EPROTONOSUPPORT);
                }
            }
            (AddressFamily::Netlink, SocketKind::Raw | SocketKind::Dgram) => {
                if protocol != NETLINK_ROUTE && protocol != NETLINK_KOBJECT_UEVENT {
                    return Err(Errno::EPROTONOSUPPORT);
                }
            }
            _ => return Err(Errno::EPROTONOSUPPORT),
        }

        let (idx, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| !s.live)
            .ok_or(Errno::EMFILE)?;
        *slot = SocketSlot {
            live: true,
            family,
            kind,
            netlink_protocol: if family == AddressFamily::Netlink {
                protocol
            } else {
                0
            },
            state: SocketState::Unbound,
            nonblocking,
            cloexec,
            ..SocketSlot::EMPTY
        };
        Ok(idx)
    }

    /// Creates a connected pair of `AF_UNIX` sockets (`socketpair(2)`).
    pub fn socketpair(
        &mut self,
        raw_domain: u16,
        raw_type: u32,
        protocol: u32,
        cred: Ucred,
    ) -> Result<(usize, usize), Errno> {
        if raw_domain != AF_UNIX {
            return Err(Errno::EOPNOTSUPP);
        }
        let a = self.socket(raw_domain, raw_type, protocol)?;
        let b = match self.socket(raw_domain, raw_type, protocol) {
            Ok(b) => b,
            Err(e) => {
                self.slots[a] = SocketSlot::EMPTY;
                return Err(e);
            }
        };
        self.slots[a].state = SocketState::Connected;
        self.slots[a].peer_slot = Some(b);
        self.slots[a].peer_cred = cred;
        self.slots[b].state = SocketState::Connected;
        self.slots[b].peer_slot = Some(a);
        self.slots[b].peer_cred = cred;
        Ok((a, b))
    }

    /// Binds a socket to `addr` (`bind(2)`).
    pub fn bind(&mut self, id: usize, mut addr: SockAddr) -> Result<(), Errno> {
        let slot = self.slot(id)?;
        if slot.state != SocketState::Unbound {
            return Err(Errno::EINVAL);
        }
        if !addr.is_loopback_or_unspecified() {
            return Err(Errno::EADDRNOTAVAIL);
        }
        match (slot.family, &mut addr) {
            (AddressFamily::Unix, SockAddr::Unix { .. }) => {}
            (AddressFamily::Inet, SockAddr::Inet { port, .. }) => {
                if *port == 0 {
                    *port = self.alloc_ephemeral_port();
                }
            }
            (AddressFamily::Inet6, SockAddr::Inet6 { port, .. }) => {
                if *port == 0 {
                    *port = self.alloc_ephemeral_port();
                }
            }
            (AddressFamily::Netlink, SockAddr::Netlink { .. }) => {}
            _ => return Err(Errno::EAFNOSUPPORT),
        }

        let reuse = self.slots[id].reuseaddr;
        let conflict =
            self.slots.iter().enumerate().any(|(other_id, s)| {
                other_id != id && s.live && s.local_addr == Some(addr) && !reuse
            });
        if conflict && !matches!(addr, SockAddr::Netlink { .. }) {
            return Err(Errno::EADDRINUSE);
        }
        self.slots[id].local_addr = Some(addr);
        self.slots[id].state = SocketState::Bound;
        Ok(())
    }

    /// Marks a bound stream/seqpacket socket as listening (`listen(2)`).
    pub fn listen(&mut self, id: usize, _backlog: i32) -> Result<(), Errno> {
        let slot = self.slot_mut(id)?;
        if !matches!(slot.kind, SocketKind::Stream | SocketKind::SeqPacket) {
            return Err(Errno::EOPNOTSUPP);
        }
        if slot.state != SocketState::Bound && slot.state != SocketState::Listening {
            return Err(Errno::EINVAL);
        }
        slot.state = SocketState::Listening;
        Ok(())
    }

    /// Connects socket `id` to `target` (`connect(2)`).
    pub fn connect(&mut self, id: usize, target: SockAddr, cred: Ucred) -> Result<(), Errno> {
        let (family, kind, state) = {
            let s = self.slot(id)?;
            (s.family, s.kind, s.state)
        };
        if state == SocketState::Connected
            && matches!(kind, SocketKind::Stream | SocketKind::SeqPacket)
        {
            return Err(Errno::EISCONN);
        }
        if !target.is_loopback_or_unspecified() {
            return Err(Errno::ENETUNREACH);
        }

        if kind == SocketKind::Dgram {
            // Find bound datagram peer.
            let peer_idx = self
                .slots
                .iter()
                .enumerate()
                .find(|&(idx, s)| idx != id && s.live && s.local_addr == Some(target))
                .map(|(idx, _)| idx);
            self.slots[id].peer_addr = Some(target);
            self.slots[id].peer_slot = peer_idx;
            self.slots[id].state = SocketState::Connected;
            return Ok(());
        }

        // Stream / SeqPacket: locate listening server socket matching `target`.
        let listener_idx = self
            .slots
            .iter()
            .enumerate()
            .find(|&(idx, s)| {
                idx != id
                    && s.live
                    && s.family == family
                    && s.state == SocketState::Listening
                    && addresses_match_loopback(s.local_addr, target)
            })
            .map(|(idx, _)| idx)
            .ok_or(Errno::ECONNREFUSED)?;

        if self.slots[listener_idx].pending_count >= 4 {
            return Err(Errno::EAGAIN);
        }

        // Allocate the server-side accepted socket slot and pair it with `id`.
        let server_peer = self
            .slots
            .iter()
            .position(|s| !s.live)
            .ok_or(Errno::EMFILE)?;
        let listener_local = self.slots[listener_idx].local_addr;
        let client_local = self.slots[id].local_addr.unwrap_or_else(|| match family {
            AddressFamily::Inet => SockAddr::Inet {
                ip: [127, 0, 0, 1],
                port: self.alloc_ephemeral_port(),
            },
            AddressFamily::Inet6 => {
                let mut ip = [0u8; 16];
                ip[15] = 1;
                SockAddr::Inet6 {
                    ip,
                    port: self.alloc_ephemeral_port(),
                }
            }
            AddressFamily::Unix => SockAddr::Unix {
                abstract_ns: false,
                path: [0u8; MAX_UNIX_PATH],
                len: 0,
            },
            AddressFamily::Netlink => SockAddr::Netlink { pid: 0, groups: 0 },
        });

        self.slots[server_peer] = SocketSlot {
            live: true,
            family,
            kind,
            state: SocketState::Connected,
            local_addr: listener_local,
            peer_addr: Some(client_local),
            peer_slot: Some(id),
            peer_cred: cred,
            ..SocketSlot::EMPTY
        };

        self.slots[id].local_addr = Some(client_local);
        self.slots[id].peer_addr = listener_local;
        self.slots[id].peer_slot = Some(server_peer);
        self.slots[id].peer_cred = self.slots[listener_idx].peer_cred;
        self.slots[id].state = SocketState::Connected;

        let q_idx = self.slots[listener_idx].pending_count;
        self.slots[listener_idx].pending_accept[q_idx] = Some(server_peer);
        self.slots[listener_idx].pending_count += 1;
        Ok(())
    }

    /// Dequeues a pending connected socket from a listening socket (`accept4(2)`).
    pub fn accept4(
        &mut self,
        listener_id: usize,
        flags: u32,
    ) -> Result<(usize, Option<SockAddr>), Errno> {
        if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
            return Err(Errno::EINVAL);
        }
        let listener = self.slot_mut(listener_id)?;
        if listener.state != SocketState::Listening {
            return Err(Errno::EINVAL);
        }
        if listener.pending_count == 0 {
            return Err(Errno::EAGAIN);
        }
        let accepted_id = listener.pending_accept[0].ok_or(Errno::EAGAIN)?;
        for i in 0..3 {
            listener.pending_accept[i] = listener.pending_accept[i + 1];
        }
        listener.pending_accept[3] = None;
        listener.pending_count -= 1;

        let accepted = self.slot_mut(accepted_id)?;
        accepted.nonblocking = (flags & SOCK_NONBLOCK) != 0;
        accepted.cloexec = (flags & SOCK_CLOEXEC) != 0;
        let peer_addr = accepted.peer_addr;
        Ok((accepted_id, peer_addr))
    }

    /// Sends payload (and optional `SCM_RIGHTS` fds for `AF_UNIX`) on socket `id`.
    pub fn send(
        &mut self,
        id: usize,
        payload: &[u8],
        dest: Option<SockAddr>,
        rights: &[i32],
    ) -> Result<usize, Errno> {
        if rights.len() > MAX_SCM_RIGHTS_FDS {
            return Err(Errno::EINVAL);
        }
        let (family, kind, shut_wr, peer_slot) = {
            let s = self.slot(id)?;
            (s.family, s.kind, s.shut_wr, s.peer_slot)
        };
        if shut_wr {
            return Err(Errno::EPIPE);
        }
        if !rights.is_empty() && family != AddressFamily::Unix {
            return Err(Errno::EINVAL);
        }

        if family == AddressFamily::Netlink {
            let slot = self.slot_mut(id)?;
            if slot.netlink_protocol != NETLINK_ROUTE {
                return Err(Errno::EOPNOTSUPP);
            }
            let n = handle_netlink_route_request(payload, &mut slot.rx_buf)?;
            slot.rx_len = n;
            return Ok(payload.len());
        }

        let target_peer = if let Some(peer) = peer_slot {
            peer
        } else if let Some(addr) = dest {
            if !addr.is_loopback_or_unspecified() {
                return Err(Errno::ENETUNREACH);
            }
            // If UDP packet is directed to loopback port 53 (DNS), synthesize the DNS response directly!
            if matches!(
                addr,
                SockAddr::Inet { port: 53, .. } | SockAddr::Inet6 { port: 53, .. }
            ) && kind == SocketKind::Dgram
            {
                let slot = self.slot_mut(id)?;
                let resp_len = build_dns_loopback_response(payload, &mut slot.rx_buf)?;
                slot.rx_len = resp_len;
                slot.peer_addr = Some(addr);
                return Ok(payload.len());
            }
            self.slots
                .iter()
                .enumerate()
                .find(|&(idx, s)| {
                    idx != id && s.live && addresses_match_loopback(s.local_addr, addr)
                })
                .map(|(idx, _)| idx)
                .ok_or(Errno::ECONNREFUSED)?
        } else {
            return Err(Errno::ENOTCONN);
        };

        let sender_local = self.slots[id].local_addr;
        let peer = self.slots.get_mut(target_peer).ok_or(Errno::EPIPE)?;
        if !peer.live || peer.shut_rd {
            return Err(Errno::EPIPE);
        }
        let avail = BUF_CAP.saturating_sub(peer.rx_len);
        if avail == 0 && !payload.is_empty() {
            return Err(Errno::EAGAIN);
        }
        let take = payload.len().min(avail);
        peer.rx_buf[peer.rx_len..peer.rx_len + take].copy_from_slice(&payload[..take]);
        peer.rx_len += take;
        if peer.peer_addr.is_none() {
            peer.peer_addr = sender_local;
        }
        if !rights.is_empty() {
            let mut fds = [-1i32; MAX_SCM_RIGHTS_FDS];
            fds[..rights.len()].copy_from_slice(rights);
            peer.rx_ancillary = AncillaryRights {
                fds,
                count: rights.len(),
            };
        }
        Ok(take)
    }

    /// Receives data (and optional `SCM_RIGHTS` fds) from socket `id`.
    pub fn recv(
        &mut self,
        id: usize,
        out: &mut [u8],
    ) -> Result<(usize, Option<SockAddr>, [i32; MAX_SCM_RIGHTS_FDS], usize), Errno> {
        let (peer_slot, rx_len, shut_rd) = {
            let s = self.slot(id)?;
            (s.peer_slot, s.rx_len, s.shut_rd)
        };
        if rx_len == 0 {
            if shut_rd {
                return Ok((0, None, [-1; MAX_SCM_RIGHTS_FDS], 0));
            }
            if let Some(peer_id) = peer_slot
                && (!self.slots[peer_id].live || self.slots[peer_id].shut_wr)
            {
                return Ok((0, None, [-1; MAX_SCM_RIGHTS_FDS], 0));
            }
            return Err(Errno::EAGAIN);
        }

        let slot = self.slot_mut(id)?;
        let take = out.len().min(slot.rx_len);
        out[..take].copy_from_slice(&slot.rx_buf[..take]);
        let remaining = slot.rx_len - take;
        if remaining > 0 {
            slot.rx_buf.copy_within(take..slot.rx_len, 0);
        }
        slot.rx_len = remaining;
        let peer_addr = slot.peer_addr;
        let rights = slot.rx_ancillary;
        slot.rx_ancillary = AncillaryRights::EMPTY;
        Ok((take, peer_addr, rights.fds, rights.count))
    }

    /// Shuts down part or all of a full-duplex connection (`shutdown(2)`).
    pub fn shutdown(&mut self, id: usize, how: u32) -> Result<(), Errno> {
        let slot = self.slot_mut(id)?;
        match how {
            SHUT_RD => slot.shut_rd = true,
            SHUT_WR => slot.shut_wr = true,
            SHUT_RDWR => {
                slot.shut_rd = true;
                slot.shut_wr = true;
            }
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    /// Broadcasts a kernel kobject uevent payload to bound `NETLINK_KOBJECT_UEVENT` sockets.
    pub fn broadcast_netlink_uevent(&mut self, msg: &[u8]) -> usize {
        if msg.is_empty() {
            return 0;
        }
        let mut delivered = 0usize;
        for slot in &mut self.slots {
            if !slot.live
                || slot.shut_rd
                || slot.family != AddressFamily::Netlink
                || slot.netlink_protocol != NETLINK_KOBJECT_UEVENT
            {
                continue;
            }
            let subscribed = matches!(
                slot.local_addr,
                Some(SockAddr::Netlink { groups, .. }) if groups == 0 || (groups & 1) != 0
            );
            if !subscribed {
                continue;
            }
            let avail = BUF_CAP.saturating_sub(slot.rx_len);
            if avail < msg.len() {
                continue;
            }
            slot.rx_buf[slot.rx_len..slot.rx_len + msg.len()].copy_from_slice(msg);
            slot.rx_len += msg.len();
            slot.peer_addr = Some(SockAddr::Netlink { pid: 0, groups: 1 });
            delivered += 1;
        }
        delivered
    }

    /// Closes socket `id`.
    pub fn close(&mut self, id: usize) -> Result<(), Errno> {
        let slot = self.slot_mut(id)?;
        slot.live = false;
        slot.state = SocketState::Closed;
        slot.shut_rd = true;
        slot.shut_wr = true;
        Ok(())
    }

    pub fn getsockname(&self, id: usize) -> Result<SockAddr, Errno> {
        let s = self.slot(id)?;
        Ok(s.local_addr.unwrap_or(match s.family {
            AddressFamily::Unix => SockAddr::Unix {
                abstract_ns: false,
                path: [0u8; MAX_UNIX_PATH],
                len: 0,
            },
            AddressFamily::Inet => SockAddr::Inet {
                ip: [127, 0, 0, 1],
                port: 0,
            },
            AddressFamily::Inet6 => SockAddr::Inet6 {
                ip: [0u8; 16],
                port: 0,
            },
            AddressFamily::Netlink => SockAddr::Netlink { pid: 0, groups: 0 },
        }))
    }

    pub fn getpeername(&self, id: usize) -> Result<SockAddr, Errno> {
        let s = self.slot(id)?;
        s.peer_addr.ok_or(Errno::ENOTCONN)
    }

    pub fn setsockopt(
        &mut self,
        id: usize,
        level: u32,
        optname: u32,
        val: u32,
    ) -> Result<(), Errno> {
        let s = self.slot_mut(id)?;
        let enabled = val != 0;
        match (level, optname) {
            (SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT) => s.reuseaddr = enabled,
            (SOL_SOCKET, SO_PASSCRED) => s.passcred = enabled,
            (SOL_SOCKET, SO_KEEPALIVE | SO_SNDBUF | SO_RCVBUF) => {}
            (IPPROTO_TCP, TCP_NODELAY) => s.tcp_nodelay = enabled,
            (IPPROTO_IPV6, IPV6_V6ONLY) => s.ipv6_v6only = enabled,
            _ => return Err(Errno::ENOPROTOOPT),
        }
        Ok(())
    }

    pub fn getsockopt(
        &self,
        id: usize,
        level: u32,
        optname: u32,
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        let s = self.slot(id)?;
        match (level, optname) {
            (SOL_SOCKET, SO_ERROR) => write_u32_opt(0, out),
            (SOL_SOCKET, SO_TYPE) => write_u32_opt(s.kind.as_raw(), out),
            (SOL_SOCKET, SO_DOMAIN) => write_u32_opt(u32::from(s.family.as_raw()), out),
            (SOL_SOCKET, SO_REUSEADDR) => write_u32_opt(u32::from(s.reuseaddr), out),
            (SOL_SOCKET, SO_PASSCRED) => write_u32_opt(u32::from(s.passcred), out),
            (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => write_u32_opt(BUF_CAP as u32, out),
            (SOL_SOCKET, SO_PEERCRED) => {
                if out.len() < 12 {
                    return Err(Errno::EINVAL);
                }
                let bytes = s.peer_cred.to_le_bytes();
                out[..12].copy_from_slice(&bytes);
                Ok(12)
            }
            (IPPROTO_TCP, TCP_NODELAY) => write_u32_opt(u32::from(s.tcp_nodelay), out),
            (IPPROTO_IPV6, IPV6_V6ONLY) => write_u32_opt(u32::from(s.ipv6_v6only), out),
            _ => Err(Errno::ENOPROTOOPT),
        }
    }

    pub fn has_readable_data(&self, id: usize) -> bool {
        if let Ok(s) = self.slot(id) {
            s.rx_len > 0 || s.pending_count > 0
        } else {
            false
        }
    }

    /// Finds a listening `SOCK_STREAM` IPv4 slot bound to `guest_port` on wildcard (`0.0.0.0`),
    /// `target_ip`, `fallback_ip`, or loopback (`127.0.0.1`).
    pub fn listening_inet4_slot(
        &self,
        target_ip: [u8; 4],
        guest_port: u16,
        fallback_ip: [u8; 4],
    ) -> Option<usize> {
        for (idx, s) in self.slots.iter().enumerate() {
            if !s.live || s.kind != SocketKind::Stream || !matches!(s.state, SocketState::Listening)
            {
                continue;
            }
            if let Some(SockAddr::Inet { ip, port }) = s.local_addr
                && port == guest_port
                && (ip == [0, 0, 0, 0]
                    || ip == target_ip
                    || ip == fallback_ip
                    || ip == [127, 0, 0, 1])
            {
                return Some(idx);
            }
        }
        None
    }

    fn slot(&self, id: usize) -> Result<&SocketSlot<BUF_CAP>, Errno> {
        let s = self.slots.get(id).ok_or(Errno::EBADF)?;
        if !s.live {
            return Err(Errno::EBADF);
        }
        Ok(s)
    }

    fn slot_mut(&mut self, id: usize) -> Result<&mut SocketSlot<BUF_CAP>, Errno> {
        let s = self.slots.get_mut(id).ok_or(Errno::EBADF)?;
        if !s.live {
            return Err(Errno::EBADF);
        }
        Ok(s)
    }

    fn alloc_ephemeral_port(&mut self) -> u16 {
        let port = self.next_ephemeral_port;
        self.next_ephemeral_port = if port >= 60999 { 49152 } else { port + 1 };
        port
    }
}

fn write_u32_opt(val: u32, out: &mut [u8]) -> Result<usize, Errno> {
    if out.len() < 4 {
        return Err(Errno::EINVAL);
    }
    out[..4].copy_from_slice(&val.to_le_bytes());
    Ok(4)
}

fn addresses_match_loopback(bound: Option<SockAddr>, target: SockAddr) -> bool {
    let Some(bound) = bound else {
        return false;
    };
    match (bound, target) {
        (
            SockAddr::Unix {
                abstract_ns: a1,
                path: p1,
                len: l1,
            },
            SockAddr::Unix {
                abstract_ns: a2,
                path: p2,
                len: l2,
            },
        ) => a1 == a2 && l1 == l2 && p1[..l1] == p2[..l2],
        (
            SockAddr::Inet {
                ip: bip,
                port: bport,
            },
            SockAddr::Inet {
                ip: tip,
                port: tport,
            },
        ) => bport == tport && (bip == tip || bip == [0, 0, 0, 0]),
        (SockAddr::Inet6 { port: bport, .. }, SockAddr::Inet6 { port: tport, .. }) => {
            bport == tport
        }
        _ => false,
    }
}

/// Validates and responds to `NETLINK_ROUTE` (`RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`)
/// requests with strict `NLMSG_OK` bounds checking. Malformed messages fail closed with `EINVAL`.
pub fn handle_netlink_route_request(request: &[u8], out: &mut [u8]) -> Result<usize, Errno> {
    if request.len() < 16 {
        return Err(Errno::EINVAL);
    }
    let nlmsg_len = u32::from_le_bytes([request[0], request[1], request[2], request[3]]) as usize;
    let nlmsg_type = u16::from_le_bytes([request[4], request[5]]);
    let nlmsg_flags = u16::from_le_bytes([request[6], request[7]]);
    let nlmsg_seq = u32::from_le_bytes([request[8], request[9], request[10], request[11]]);
    let nlmsg_pid = u32::from_le_bytes([request[12], request[13], request[14], request[15]]);

    // Strict NLMSG_OK check: declared length must be >= 16 and <= actual payload slice.
    if nlmsg_len < 16 || nlmsg_len > request.len() || (nlmsg_flags & NLM_F_REQUEST) == 0 {
        return Err(Errno::EINVAL);
    }

    match nlmsg_type {
        RTM_GETLINK => {
            // Emit RTM_NEWLINK for loopback ("lo", ifindex=1, IFF_UP | IFF_LOOPBACK | IFF_RUNNING)
            // followed by NLMSG_DONE.
            // ifinfomsg is 16 bytes + RTA "lo\0" (8 bytes aligned) = 24 bytes payload -> 40 bytes total.
            if out.len() < 60 {
                return Err(Errno::ENOBUFS);
            }
            write_nlmsghdr(
                &mut out[0..16],
                40,
                RTM_NEWLINK,
                NLM_F_MULTI,
                nlmsg_seq,
                nlmsg_pid,
            );
            // struct ifinfomsg: family(u8)=0, pad(u8)=0, type(u16)=772(ARPHRD_LOOPBACK), index(i32)=1,
            // flags(u32)=0x10049(UP|LOOPBACK|RUNNING|LOWER_UP), change(u32)=0
            out[16..20].copy_from_slice(&[0, 0, 0x04, 0x03]);
            out[20..24].copy_from_slice(&1i32.to_le_bytes());
            out[24..28].copy_from_slice(&0x0001_0049u32.to_le_bytes());
            out[28..32].copy_from_slice(&0u32.to_le_bytes());
            // rtattr IFLA_IFNAME (type=3, len=7: "lo\0", padded to 8)
            out[32..34].copy_from_slice(&7u16.to_le_bytes());
            out[34..36].copy_from_slice(&3u16.to_le_bytes());
            out[36..40].copy_from_slice(b"lo\0\0");

            // NLMSG_DONE (20 bytes: 16-byte header + 4-byte i32 0)
            write_nlmsghdr(
                &mut out[40..56],
                20,
                NLMSG_DONE,
                NLM_F_MULTI,
                nlmsg_seq,
                nlmsg_pid,
            );
            out[56..60].copy_from_slice(&0i32.to_le_bytes());
            Ok(60)
        }
        RTM_GETADDR => {
            // Emit RTM_NEWADDR for 127.0.0.1/8 on ifindex 1 followed by NLMSG_DONE.
            // 16 (nlmsghdr) + 8 (ifaddrmsg) + 8 (IFA_LOCAL 127.0.0.1) + 8 (IFA_ADDRESS 127.0.0.1) = 40 bytes.
            if out.len() < 60 {
                return Err(Errno::ENOBUFS);
            }
            write_nlmsghdr(
                &mut out[0..16],
                40,
                RTM_NEWADDR,
                NLM_F_MULTI,
                nlmsg_seq,
                nlmsg_pid,
            );
            // struct ifaddrmsg: family=AF_INET(2), prefixlen=8, flags=0x80(PERMANENT), scope=254(HOST), index=1
            out[16] = AF_INET as u8;
            out[17] = 8;
            out[18] = 0x80;
            out[19] = 254;
            out[20..24].copy_from_slice(&1u32.to_le_bytes());
            // IFA_ADDRESS (type=1, len=8: 127.0.0.1)
            out[24..26].copy_from_slice(&8u16.to_le_bytes());
            out[26..28].copy_from_slice(&1u16.to_le_bytes());
            out[28..32].copy_from_slice(&[127, 0, 0, 1]);
            // IFA_LOCAL (type=2, len=8: 127.0.0.1)
            out[32..34].copy_from_slice(&8u16.to_le_bytes());
            out[34..36].copy_from_slice(&2u16.to_le_bytes());
            out[36..40].copy_from_slice(&[127, 0, 0, 1]);

            write_nlmsghdr(
                &mut out[40..56],
                20,
                NLMSG_DONE,
                NLM_F_MULTI,
                nlmsg_seq,
                nlmsg_pid,
            );
            out[56..60].copy_from_slice(&0i32.to_le_bytes());
            Ok(60)
        }
        RTM_GETROUTE => {
            if out.len() < 20 {
                return Err(Errno::ENOBUFS);
            }
            write_nlmsghdr(
                &mut out[0..16],
                20,
                NLMSG_DONE,
                NLM_F_MULTI,
                nlmsg_seq,
                nlmsg_pid,
            );
            out[16..20].copy_from_slice(&0i32.to_le_bytes());
            Ok(20)
        }
        _ => Err(Errno::EOPNOTSUPP),
    }
}

fn write_nlmsghdr(out: &mut [u8], len: u32, msg_type: u16, flags: u16, seq: u32, pid: u32) {
    out[0..4].copy_from_slice(&len.to_le_bytes());
    out[4..6].copy_from_slice(&msg_type.to_le_bytes());
    out[6..8].copy_from_slice(&flags.to_le_bytes());
    out[8..12].copy_from_slice(&seq.to_le_bytes());
    out[12..16].copy_from_slice(&pid.to_le_bytes());
}

/// Synthesizes a RFC-1035 DNS A (`127.0.0.1`) or AAAA (`::1`) response for local/test queries on
/// loopback port 53 so glibc `getaddrinfo(3)` resolver probes complete deterministically.
pub fn build_dns_loopback_response(query: &[u8], out: &mut [u8]) -> Result<usize, Errno> {
    // DNS header is 12 bytes + question section (at least 5 bytes).
    if query.len() < 17 || query.len() > 256 {
        return Err(Errno::EINVAL);
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        return Err(Errno::EINVAL);
    }
    // Walk QNAME labels strictly within `query[12..]`.
    let mut pos = 12usize;
    while pos < query.len() {
        let label_len = query[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        if label_len > 63 || pos + label_len > query.len() {
            return Err(Errno::EINVAL);
        }
        pos += label_len;
    }
    if pos + 4 > query.len() {
        return Err(Errno::EINVAL);
    }
    let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
    let qclass = u16::from_be_bytes([query[pos + 2], query[pos + 3]]);
    if qclass != 1 {
        return Err(Errno::EINVAL);
    }
    let q_end = pos + 4;
    let rdata: &[u8] = match qtype {
        1 => &[127, 0, 0, 1], // A record -> 127.0.0.1
        28 => &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], // AAAA -> ::1
        _ => &[],
    };
    let total = q_end
        + if rdata.is_empty() {
            0
        } else {
            12 + rdata.len()
        };
    if out.len() < total {
        return Err(Errno::ENOBUFS);
    }
    out[..q_end].copy_from_slice(&query[..q_end]);
    // QR=1, RD=1, RA=1 -> 0x8180
    out[2] = 0x81;
    out[3] = 0x80;
    // ANCOUNT = 1 if A or AAAA else 0
    let ancount: u16 = if rdata.is_empty() { 0 } else { 1 };
    out[6..8].copy_from_slice(&ancount.to_be_bytes());
    out[8..12].copy_from_slice(&[0, 0, 0, 0]);
    if !rdata.is_empty() {
        // Name pointer to offset 12 (0xc00c), TYPE, CLASS=IN(1), TTL=60s, RDLENGTH
        out[q_end..q_end + 2].copy_from_slice(&[0xc0, 0x0c]);
        out[q_end + 2..q_end + 4].copy_from_slice(&qtype.to_be_bytes());
        out[q_end + 4..q_end + 6].copy_from_slice(&1u16.to_be_bytes());
        out[q_end + 6..q_end + 10].copy_from_slice(&60u32.to_be_bytes());
        out[q_end + 10..q_end + 12].copy_from_slice(&(rdata.len() as u16).to_be_bytes());
        out[q_end + 12..total].copy_from_slice(rdata);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn af_unix_socketpair_and_scm_rights_and_peercred_work() {
        let mut table = SocketTable::<8, 256>::new();
        let cred = Ucred {
            pid: 42,
            uid: 1000,
            gid: 1000,
        };
        let (a, b) = table
            .socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, cred)
            .unwrap();

        let sent = table.send(a, b"dbus-hello", None, &[5, 6]).unwrap();
        assert_eq!(sent, 10);

        let mut rx = [0u8; 32];
        let (n, _addr, fds, fd_count) = table.recv(b, &mut rx).unwrap();
        assert_eq!(&rx[..n], b"dbus-hello");
        assert_eq!(fd_count, 2);
        assert_eq!(&fds[..2], &[5, 6]);

        let mut ucred_buf = [0u8; 12];
        let opt_len = table
            .getsockopt(b, SOL_SOCKET, SO_PEERCRED, &mut ucred_buf)
            .unwrap();
        assert_eq!(opt_len, 12);
        assert_eq!(u32::from_le_bytes(ucred_buf[0..4].try_into().unwrap()), 42);
    }

    #[test]
    fn ipv4_loopback_tcp_bind_listen_connect_accept_and_exchange() {
        let mut table = SocketTable::<8, 256>::new();
        let srv = table.socket(AF_INET, SOCK_STREAM, 0).unwrap();
        table.setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, 1).unwrap();
        let bind_addr = SockAddr::Inet {
            ip: [127, 0, 0, 1],
            port: 8080,
        };
        table.bind(srv, bind_addr).unwrap();
        table.listen(srv, 4).unwrap();

        let cli = table.socket(AF_INET, SOCK_STREAM, 0).unwrap();
        table.connect(cli, bind_addr, Ucred::ROOT_INIT).unwrap();

        let (accepted, peer) = table.accept4(srv, SOCK_CLOEXEC).unwrap();
        assert!(peer.is_some());

        table
            .send(cli, b"GET / HTTP/1.1\r\n\r\n", None, &[])
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, _, _, _) = table.recv(accepted, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"GET / HTTP/1.1\r\n\r\n");

        table.shutdown(cli, SHUT_WR).unwrap();
        let (eof, _, _, _) = table.recv(accepted, &mut buf).unwrap();
        assert_eq!(eof, 0);
    }

    #[test]
    fn netlink_route_getlink_getaddr_and_malformed_bounds_check() {
        let mut table = SocketTable::<4, 256>::new();
        let nl = table.socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE).unwrap();

        // Malformed netlink message (declared length 64 > actual 16 bytes) must fail with EINVAL.
        let mut bad_req = [0u8; 16];
        bad_req[0..4].copy_from_slice(&64u32.to_le_bytes());
        bad_req[4..6].copy_from_slice(&RTM_GETLINK.to_le_bytes());
        bad_req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_le_bytes());
        assert_eq!(table.send(nl, &bad_req, None, &[]), Err(Errno::EINVAL));

        // Valid RTM_GETLINK request.
        let mut good_req = [0u8; 16];
        good_req[0..4].copy_from_slice(&16u32.to_le_bytes());
        good_req[4..6].copy_from_slice(&RTM_GETLINK.to_le_bytes());
        good_req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_le_bytes());
        good_req[8..12].copy_from_slice(&1u32.to_le_bytes());
        table.send(nl, &good_req, None, &[]).unwrap();

        let mut resp = [0u8; 128];
        let (n, _, _, _) = table.recv(nl, &mut resp).unwrap();
        assert_eq!(n, 60);
        let first_type = u16::from_le_bytes([resp[4], resp[5]]);
        let done_type = u16::from_le_bytes([resp[44], resp[45]]);
        assert_eq!(first_type, RTM_NEWLINK);
        assert_eq!(done_type, NLMSG_DONE);
    }

    #[test]
    fn dns_loopback_resolver_synthesizes_valid_a_record_reply() {
        let mut table = SocketTable::<4, 256>::new();
        let udp = table.socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        // Minimal DNS query for "localhost" A record (txid=0x1234).
        let query: [u8; 27] = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 9, b'l', b'o',
            b'c', b'a', b'l', b'h', b'o', b's', b't', 0, 0x00, 0x01, 0x00, 0x01,
        ];
        let dns_addr = SockAddr::Inet {
            ip: [127, 0, 0, 1],
            port: 53,
        };
        table.send(udp, &query, Some(dns_addr), &[]).unwrap();
        let mut resp = [0u8; 64];
        let (n, from, _, _) = table.recv(udp, &mut resp).unwrap();
        assert_eq!(from, Some(dns_addr));
        assert_eq!(&resp[0..2], &[0x12, 0x34]);
        assert_eq!(&resp[n - 4..n], &[127, 0, 0, 1]);
    }

    #[test]
    fn netlink_kobject_uevent_delivers_broadcast_to_bound_sockets() {
        let mut table = SocketTable::<4, 256>::new();
        let udev_sock = table
            .socket(
                AF_NETLINK,
                SOCK_DGRAM | SOCK_CLOEXEC,
                NETLINK_KOBJECT_UEVENT,
            )
            .unwrap();
        table
            .bind(
                udev_sock,
                SockAddr::Netlink {
                    pid: 100,
                    groups: 1,
                },
            )
            .unwrap();

        let payload = b"add@/devices/virtio0/block/vda\0ACTION=add\0SUBSYSTEM=block\0DEVNAME=vda\0";
        assert_eq!(table.broadcast_netlink_uevent(payload), 1);

        let mut rx = [0u8; 128];
        let (n, from, _, _) = table.recv(udev_sock, &mut rx).unwrap();
        assert_eq!(&rx[..n], payload);
        assert_eq!(from, Some(SockAddr::Netlink { pid: 0, groups: 1 }));
    }
}
