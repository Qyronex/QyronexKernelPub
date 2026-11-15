// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Pure-Rust `#![no_std]` + `alloc` IPv4/ARP/ICMP/UDP/DHCPv4/TCP network stack for `virtio-net`.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cmp::min;
use kernal_linux_abi::{Errno, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP};

use crate::proto::{
    ARP_OP_REPLY, ARP_OP_REQUEST, BROADCAST_MAC, DEFAULT_TCP_MSS, DHCP_CLIENT_PORT,
    DHCP_SERVER_PORT, DhcpMessageType, ETHERTYPE_ARP, ETHERTYPE_IPV4, ICMP_ECHO_REQUEST,
    IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, ZERO_MAC,
    build_arp_frame, build_dhcp_discover, build_dhcp_request, build_ethernet_frame,
    build_icmp_echo_reply_ip, build_tcp_ip, build_udp_ip, parse_arp, parse_dhcp_reply,
    parse_ethernet, parse_icmp, parse_ipv4, parse_tcp, parse_udp,
};

const ARP_CACHE_MAX: usize = 32;
const PENDING_ARP_MAX: usize = 64;
const UDP_RX_QUEUE_MAX: usize = 64;
const TCP_RX_BUF_CAP: usize = 131_072;
const TCP_TX_BUF_CAP: usize = 131_072;
const TCP_MAX_INFLIGHT_BYTES: u32 = 32 * 1460;
const TCP_OOO_MAX: usize = 8;
const TCP_RTO_BASE_NS: u64 = 250_000_000;
const TCP_MAX_RETRANSMITS: u8 = 10;
const DHCP_RETRY_NS: u64 = 250_000_000;
const ARP_RETRY_NS: u64 = 150_000_000;

#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[inline]
fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

fn netmask_to_prefix(mask: [u8; 4]) -> u8 {
    u32::from_be_bytes(mask).leading_ones() as u8
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetConfig {
    pub configured: bool,
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub prefix_len: u8,
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
}

impl NetConfig {
    pub const fn unconfigured() -> Self {
        Self {
            configured: false,
            ip: [0; 4],
            netmask: [255, 255, 255, 0],
            prefix_len: 24,
            gateway: [0; 4],
            dns: [0; 4],
        }
    }

    pub fn same_subnet(&self, other: [u8; 4]) -> bool {
        if !self.configured {
            return false;
        }
        let m = u32::from_be_bytes(self.netmask);
        (u32::from_be_bytes(self.ip) & m) == (u32::from_be_bytes(other) & m)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DhcpClientState {
    Idle,
    DiscoverSent {
        xid: u32,
        last_sent_ns: u64,
        attempts: u8,
    },
    RequestSent {
        xid: u32,
        offered_ip: [u8; 4],
        server_id: [u8; 4],
        subnet: [u8; 4],
        gateway: [u8; 4],
        dns: [u8; 4],
        last_sent_ns: u64,
        attempts: u8,
    },
    Bound,
}

#[derive(Clone, Copy, Debug)]
struct ArpEntry {
    ip: [u8; 4],
    mac: [u8; 6],
}

#[derive(Clone)]
struct PendingArpPacket {
    next_hop: [u8; 4],
    ipv4_pkt: Vec<u8>,
    last_req_ns: u64,
    attempts: u8,
}

#[derive(Clone)]
pub struct UdpRxDatagram {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub payload: Vec<u8>,
}

struct UdpEntry {
    local_ip: [u8; 4],
    local_port: u16,
    peer: Option<([u8; 4], u16)>,
    rx_queue: VecDeque<UdpRxDatagram>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpConnState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Reset,
}

struct UnackedSegment {
    seq: u32,
    end_seq: u32,
    flags: u8,
    mss: Option<u16>,
    data: Vec<u8>,
    sent_ns: u64,
    retransmits: u8,
}

struct OooChunk {
    seq: u32,
    data: Vec<u8>,
}

struct TcpEntry {
    state: TcpConnState,
    local_ip: [u8; 4],
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    irs: u32,
    rcv_nxt: u32,
    peer_mss: u16,
    rx_buf: VecDeque<u8>,
    tx_buf: VecDeque<u8>,
    unacked: VecDeque<UnackedSegment>,
    ooo: Vec<OooChunk>,
    accept_queue: VecDeque<u32>,
    backlog: usize,
    parent_listener: Option<u32>,
    dup_acks: u8,
    peer_fin_received: bool,
    local_fin_seq: Option<u32>,
    shutdown_rd: bool,
    shutdown_wr: bool,
    close_after_tx: bool,
    closed_by_user: bool,
    pending_error: Option<Errno>,
    last_activity_ns: u64,
    time_wait_deadline_ns: u64,
}

impl TcpEntry {
    fn rcv_window(&self) -> u16 {
        let avail = TCP_RX_BUF_CAP.saturating_sub(self.rx_buf.len());
        min(avail, 65535) as u16
    }

    fn inflight_bytes(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpEndpointAddrs {
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
}

struct OutboundTcpSeg {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    payload: Vec<u8>,
}

pub struct NetStack {
    mac: [u8; 6],
    mtu: u16,
    link_up: bool,
    pub cfg: NetConfig,
    dhcp: DhcpClientState,
    arp_cache: Vec<ArpEntry>,
    pending_arp: VecDeque<PendingArpPacket>,
    tx_frames: VecDeque<Vec<u8>>,
    udp: Vec<Option<UdpEntry>>,
    tcp: Vec<Option<TcpEntry>>,
    next_ephemeral: u16,
    next_ip_id: u16,
    isn_nonce: u32,
}

impl NetStack {
    pub fn new(mac: [u8; 6], mtu: u16, link_up: bool) -> Self {
        Self {
            mac,
            mtu: if mtu == 0 { 1500 } else { mtu },
            link_up,
            cfg: NetConfig::unconfigured(),
            dhcp: DhcpClientState::Idle,
            arp_cache: Vec::new(),
            pending_arp: VecDeque::new(),
            tx_frames: VecDeque::new(),
            udp: Vec::new(),
            tcp: Vec::new(),
            next_ephemeral: 32768,
            next_ip_id: 1,
            isn_nonce: 0x1357_2468,
        }
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn link_up(&self) -> bool {
        self.link_up
    }

    pub fn dhcp_bound(&self) -> bool {
        self.cfg.configured && matches!(self.dhcp, DhcpClientState::Bound)
    }

    pub fn configure_static(
        &mut self,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
        dns: [u8; 4],
    ) {
        self.cfg = NetConfig {
            configured: true,
            ip,
            netmask,
            prefix_len: netmask_to_prefix(netmask),
            gateway,
            dns,
        };
        self.dhcp = DhcpClientState::Bound;
    }

    pub fn start_dhcp(&mut self, now_ns: u64) {
        let xid = 0x4b52_4e01u32
            ^ u32::from_be_bytes([self.mac[2], self.mac[3], self.mac[4], self.mac[5]]);
        self.dhcp = DhcpClientState::DiscoverSent {
            xid,
            last_sent_ns: now_ns,
            attempts: 1,
        };
        self.emit_dhcp_discover(xid);
    }

    fn alloc_ip_id(&mut self) -> u16 {
        let id = self.next_ip_id;
        self.next_ip_id = self.next_ip_id.wrapping_add(1).max(1);
        id
    }

    fn alloc_ephemeral_port(&mut self) -> Result<u16, Errno> {
        for _ in 0..(61000 - 32768) {
            let candidate = self.next_ephemeral;
            self.next_ephemeral = if self.next_ephemeral >= 60999 {
                32768
            } else {
                self.next_ephemeral + 1
            };
            if candidate == DHCP_SERVER_PORT || candidate == DHCP_CLIENT_PORT {
                continue;
            }
            if !self.is_port_in_use(candidate) {
                return Ok(candidate);
            }
        }
        Err(Errno::EADDRNOTAVAIL)
    }

    fn is_port_in_use(&self, port: u16) -> bool {
        self.udp.iter().flatten().any(|u| u.local_port == port)
            || self
                .tcp
                .iter()
                .flatten()
                .any(|t| t.local_port == port && t.state != TcpConnState::Closed)
    }

    pub fn pop_tx_frame(&mut self) -> Option<Vec<u8>> {
        self.tx_frames.pop_front()
    }

    fn emit_dhcp_discover(&mut self, xid: u32) {
        let bootp = build_dhcp_discover(self.mac, xid);
        let id = self.alloc_ip_id();
        let ip_pkt = build_udp_ip(
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            id,
            &bootp,
        );
        self.tx_frames.push_back(build_ethernet_frame(
            self.mac,
            BROADCAST_MAC,
            ETHERTYPE_IPV4,
            &ip_pkt,
        ));
    }

    fn emit_dhcp_request(&mut self, xid: u32, offered_ip: [u8; 4], server_id: [u8; 4]) {
        let bootp = build_dhcp_request(self.mac, xid, offered_ip, server_id);
        let id = self.alloc_ip_id();
        let ip_pkt = build_udp_ip(
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            id,
            &bootp,
        );
        self.tx_frames.push_back(build_ethernet_frame(
            self.mac,
            BROADCAST_MAC,
            ETHERTYPE_IPV4,
            &ip_pkt,
        ));
    }

    fn lookup_arp(&self, ip: [u8; 4]) -> Option<[u8; 6]> {
        self.arp_cache.iter().find(|e| e.ip == ip).map(|e| e.mac)
    }

    fn insert_arp(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        if ip == [0, 0, 0, 0] || mac == ZERO_MAC || mac == BROADCAST_MAC {
            return;
        }
        if let Some(existing) = self.arp_cache.iter_mut().find(|e| e.ip == ip) {
            existing.mac = mac;
        } else {
            if self.arp_cache.len() >= ARP_CACHE_MAX {
                self.arp_cache.remove(0);
            }
            self.arp_cache.push(ArpEntry { ip, mac });
        }
        // Flush any queued packets awaiting this next_hop MAC.
        let mut remaining = VecDeque::new();
        while let Some(pending) = self.pending_arp.pop_front() {
            if pending.next_hop == ip {
                self.tx_frames.push_back(build_ethernet_frame(
                    self.mac,
                    mac,
                    ETHERTYPE_IPV4,
                    &pending.ipv4_pkt,
                ));
            } else {
                remaining.push_back(pending);
            }
        }
        self.pending_arp = remaining;
    }

    fn send_arp_request(&mut self, target_ip: [u8; 4]) {
        let spa = if self.cfg.configured {
            self.cfg.ip
        } else {
            [0, 0, 0, 0]
        };
        let frame = build_arp_frame(
            self.mac,
            BROADCAST_MAC,
            ARP_OP_REQUEST,
            self.mac,
            spa,
            ZERO_MAC,
            target_ip,
        );
        self.tx_frames.push_back(frame);
    }

    fn send_ipv4_packet(
        &mut self,
        dst_ip: [u8; 4],
        ipv4_pkt: Vec<u8>,
        now_ns: u64,
    ) -> Result<(), Errno> {
        if dst_ip == [255, 255, 255, 255] {
            self.tx_frames.push_back(build_ethernet_frame(
                self.mac,
                BROADCAST_MAC,
                ETHERTYPE_IPV4,
                &ipv4_pkt,
            ));
            return Ok(());
        }
        if !self.cfg.configured {
            return Err(Errno::ENETUNREACH);
        }
        let next_hop = if self.cfg.same_subnet(dst_ip) {
            dst_ip
        } else if self.cfg.gateway != [0, 0, 0, 0] {
            self.cfg.gateway
        } else {
            return Err(Errno::ENETUNREACH);
        };

        if let Some(dst_mac) = self.lookup_arp(next_hop) {
            self.tx_frames.push_back(build_ethernet_frame(
                self.mac,
                dst_mac,
                ETHERTYPE_IPV4,
                &ipv4_pkt,
            ));
            return Ok(());
        }

        let recently_asked = self
            .pending_arp
            .iter()
            .any(|p| p.next_hop == next_hop && now_ns.saturating_sub(p.last_req_ns) < ARP_RETRY_NS);
        if self.pending_arp.len() >= PENDING_ARP_MAX {
            let _ = self.pending_arp.pop_front();
        }
        self.pending_arp.push_back(PendingArpPacket {
            next_hop,
            ipv4_pkt,
            last_req_ns: now_ns,
            attempts: 1,
        });
        if !recently_asked {
            self.send_arp_request(next_hop);
        }
        Ok(())
    }

    pub fn ingest_frame(&mut self, frame: &[u8], now_ns: u64) {
        let Some(eth) = parse_ethernet(frame) else {
            return;
        };
        if eth.dst_mac != self.mac && eth.dst_mac != BROADCAST_MAC {
            return;
        }
        match eth.ethertype {
            ETHERTYPE_ARP => self.handle_arp(eth.payload),
            ETHERTYPE_IPV4 => self.handle_ipv4(eth.src_mac, eth.payload, now_ns),
            _ => {}
        }
    }

    fn handle_arp(&mut self, payload: &[u8]) {
        let Some(arp) = parse_arp(payload) else {
            return;
        };
        self.insert_arp(arp.spa, arp.sha);
        if arp.oper == ARP_OP_REQUEST && self.cfg.configured && arp.tpa == self.cfg.ip {
            let reply = build_arp_frame(
                self.mac,
                arp.sha,
                ARP_OP_REPLY,
                self.mac,
                self.cfg.ip,
                arp.sha,
                arp.spa,
            );
            self.tx_frames.push_back(reply);
        }
    }

    fn handle_ipv4(&mut self, src_mac: [u8; 6], payload: &[u8], now_ns: u64) {
        let Some(ip) = parse_ipv4(payload) else {
            return;
        };
        let is_broadcast = ip.dst == [255, 255, 255, 255];
        let for_us = if self.cfg.configured {
            ip.dst == self.cfg.ip || is_broadcast
        } else {
            // Allow DHCP replies before IP is bound.
            ip.proto == IPPROTO_UDP
        };
        if !for_us {
            return;
        }
        if self.cfg.configured && self.cfg.same_subnet(ip.src) {
            self.insert_arp(ip.src, src_mac);
        }

        match ip.proto {
            IPPROTO_ICMP => self.handle_icmp(src_mac, &ip),
            IPPROTO_UDP => self.handle_udp(&ip, now_ns),
            IPPROTO_TCP => self.handle_tcp(&ip, now_ns),
            _ => {}
        }
    }

    fn handle_icmp(&mut self, src_mac: [u8; 6], ip: &crate::proto::Ipv4Packet<'_>) {
        if !self.cfg.configured || ip.dst != self.cfg.ip {
            return;
        }
        let Some(icmp) = parse_icmp(ip.payload) else {
            return;
        };
        if icmp.msg_type == ICMP_ECHO_REQUEST && icmp.code == 0 {
            let id = self.alloc_ip_id();
            let reply_ip =
                build_icmp_echo_reply_ip(self.cfg.ip, ip.src, id, icmp.id, icmp.seq, icmp.data);
            self.tx_frames.push_back(build_ethernet_frame(
                self.mac,
                src_mac,
                ETHERTYPE_IPV4,
                &reply_ip,
            ));
        }
    }

    fn handle_udp(&mut self, ip: &crate::proto::Ipv4Packet<'_>, now_ns: u64) {
        let Some(udp) = parse_udp(ip.src, ip.dst, ip.payload) else {
            return;
        };
        if udp.dst_port == DHCP_CLIENT_PORT && udp.src_port == DHCP_SERVER_PORT {
            self.handle_dhcp_udp(udp.payload, ip.src, now_ns);
            return;
        }
        if !self.cfg.configured || ip.dst != self.cfg.ip {
            return;
        }
        for slot in self.udp.iter_mut().flatten() {
            if slot.local_port != udp.dst_port {
                continue;
            }
            if slot.local_ip != [0, 0, 0, 0] && slot.local_ip != ip.dst {
                continue;
            }
            if let Some((peer_ip, peer_port)) = slot.peer
                && (peer_ip != ip.src || (peer_port != 0 && peer_port != udp.src_port))
            {
                continue;
            }
            if slot.rx_queue.len() >= UDP_RX_QUEUE_MAX {
                let _ = slot.rx_queue.pop_front();
            }
            slot.rx_queue.push_back(UdpRxDatagram {
                src_ip: ip.src,
                src_port: udp.src_port,
                payload: udp.payload.to_vec(),
            });
            return;
        }
    }

    fn handle_dhcp_udp(&mut self, data: &[u8], src_ip: [u8; 4], now_ns: u64) {
        match self.dhcp {
            DhcpClientState::DiscoverSent { xid, .. } => {
                let Some(reply) = parse_dhcp_reply(data, self.mac, xid) else {
                    return;
                };
                if reply.msg_type != DhcpMessageType::Offer || reply.yiaddr == [0, 0, 0, 0] {
                    return;
                }
                let server_id = reply.server_id.unwrap_or(src_ip);
                let subnet = reply.subnet_mask.unwrap_or([255, 255, 255, 0]);
                let gateway = reply.router.unwrap_or(server_id);
                let dns = reply.dns.unwrap_or(gateway);
                self.dhcp = DhcpClientState::RequestSent {
                    xid,
                    offered_ip: reply.yiaddr,
                    server_id,
                    subnet,
                    gateway,
                    dns,
                    last_sent_ns: now_ns,
                    attempts: 1,
                };
                self.emit_dhcp_request(xid, reply.yiaddr, server_id);
            }
            DhcpClientState::RequestSent {
                xid,
                offered_ip,
                subnet,
                gateway,
                dns,
                ..
            } => {
                let Some(reply) = parse_dhcp_reply(data, self.mac, xid) else {
                    return;
                };
                match reply.msg_type {
                    DhcpMessageType::Ack => {
                        let ip = if reply.yiaddr != [0, 0, 0, 0] {
                            reply.yiaddr
                        } else {
                            offered_ip
                        };
                        let netmask = reply.subnet_mask.unwrap_or(subnet);
                        let gw = reply.router.unwrap_or(gateway);
                        let dns_ip = reply.dns.unwrap_or(dns);
                        self.cfg = NetConfig {
                            configured: true,
                            ip,
                            netmask,
                            prefix_len: netmask_to_prefix(netmask),
                            gateway: gw,
                            dns: dns_ip,
                        };
                        self.dhcp = DhcpClientState::Bound;
                    }
                    DhcpMessageType::Nak => {
                        self.dhcp = DhcpClientState::DiscoverSent {
                            xid: xid.wrapping_add(1),
                            last_sent_ns: 0,
                            attempts: 1,
                        };
                    }
                    DhcpMessageType::Offer => {}
                }
            }
            DhcpClientState::Idle | DhcpClientState::Bound => {}
        }
    }

    pub fn tick(&mut self, now_ns: u64) {
        // 1. DHCP timers
        match self.dhcp {
            DhcpClientState::DiscoverSent {
                xid,
                last_sent_ns,
                attempts,
            } => {
                if (last_sent_ns == 0 || now_ns.saturating_sub(last_sent_ns) >= DHCP_RETRY_NS)
                    && attempts < 12
                {
                    self.dhcp = DhcpClientState::DiscoverSent {
                        xid,
                        last_sent_ns: now_ns,
                        attempts: attempts + 1,
                    };
                    self.emit_dhcp_discover(xid);
                }
            }
            DhcpClientState::RequestSent {
                xid,
                offered_ip,
                server_id,
                subnet,
                gateway,
                dns,
                last_sent_ns,
                attempts,
            } => {
                if last_sent_ns == 0 || now_ns.saturating_sub(last_sent_ns) >= DHCP_RETRY_NS {
                    if attempts < 12 {
                        self.dhcp = DhcpClientState::RequestSent {
                            xid,
                            offered_ip,
                            server_id,
                            subnet,
                            gateway,
                            dns,
                            last_sent_ns: now_ns,
                            attempts: attempts + 1,
                        };
                        self.emit_dhcp_request(xid, offered_ip, server_id);
                    } else {
                        self.start_dhcp(now_ns);
                    }
                }
            }
            DhcpClientState::Idle | DhcpClientState::Bound => {}
        }

        // 2. ARP re-requests and expiration
        let mut resend_arp_for: Vec<[u8; 4]> = Vec::new();
        let mut kept = VecDeque::with_capacity(self.pending_arp.len());
        while let Some(mut p) = self.pending_arp.pop_front() {
            if let Some(mac) = self.lookup_arp(p.next_hop) {
                self.tx_frames.push_back(build_ethernet_frame(
                    self.mac,
                    mac,
                    ETHERTYPE_IPV4,
                    &p.ipv4_pkt,
                ));
                continue;
            }
            if now_ns.saturating_sub(p.last_req_ns) >= ARP_RETRY_NS {
                if p.attempts >= 12 {
                    continue;
                }
                p.last_req_ns = now_ns;
                p.attempts += 1;
                if !resend_arp_for.contains(&p.next_hop) {
                    resend_arp_for.push(p.next_hop);
                }
            }
            kept.push_back(p);
        }
        self.pending_arp = kept;
        for ip in resend_arp_for {
            self.send_arp_request(ip);
        }

        // 3. TCP retransmission and TIME_WAIT / closed socket cleanup
        let tcp_count = self.tcp.len();
        for idx in 0..tcp_count {
            let mut timed_out = false;
            let mut reclaim = false;
            let mut retransmit_spec: Option<OutboundTcpSeg> = None;

            if let Some(ref mut t) = self.tcp[idx] {
                if t.closed_by_user
                    && (matches!(t.state, TcpConnState::Closed | TcpConnState::Reset)
                        || (t.state == TcpConnState::TimeWait && now_ns >= t.time_wait_deadline_ns)
                        || now_ns.saturating_sub(t.last_activity_ns) >= 3_000_000_000)
                {
                    reclaim = true;
                } else if t.state == TcpConnState::TimeWait && now_ns >= t.time_wait_deadline_ns {
                    t.state = TcpConnState::Closed;
                    if t.closed_by_user {
                        reclaim = true;
                    }
                } else if !t.unacked.is_empty() {
                    let rcv_nxt = t.rcv_nxt;
                    let win = t.rcv_window();
                    let (lip, rip, lp, rp) = (t.local_ip, t.remote_ip, t.local_port, t.remote_port);
                    if let Some(front) = t.unacked.front_mut() {
                        let rto = TCP_RTO_BASE_NS << min(front.retransmits, 4);
                        if now_ns.saturating_sub(front.sent_ns) >= rto {
                            if front.retransmits >= TCP_MAX_RETRANSMITS {
                                timed_out = true;
                            } else {
                                front.retransmits += 1;
                                front.sent_ns = now_ns;
                                retransmit_spec = Some(OutboundTcpSeg {
                                    src_ip: lip,
                                    dst_ip: rip,
                                    src_port: lp,
                                    dst_port: rp,
                                    seq: front.seq,
                                    ack: if (front.flags & TCP_ACK) != 0 {
                                        rcv_nxt
                                    } else {
                                        0
                                    },
                                    flags: front.flags,
                                    window: win,
                                    mss: front.mss,
                                    payload: front.data.clone(),
                                });
                            }
                        }
                    }
                }
            }

            if timed_out {
                if let Some(ref mut t) = self.tcp[idx] {
                    t.pending_error = Some(Errno::ETIMEDOUT);
                    t.state = TcpConnState::Reset;
                    t.unacked.clear();
                    t.tx_buf.clear();
                    if t.closed_by_user {
                        reclaim = true;
                    }
                }
            } else if let Some(seg) = retransmit_spec {
                self.emit_tcp_segment(
                    seg.src_ip,
                    seg.dst_ip,
                    seg.src_port,
                    seg.dst_port,
                    seg.seq,
                    seg.ack,
                    seg.flags,
                    seg.window,
                    seg.mss,
                    &seg.payload,
                    now_ns,
                );
            }

            if reclaim {
                self.tcp[idx] = None;
            }
        }
    }

    // ------------------------------------------------------------------------
    // UDP Public API
    // ------------------------------------------------------------------------

    pub fn udp_open(&mut self, local_ip: [u8; 4], local_port: u16) -> Result<u32, Errno> {
        let port = if local_port == 0 {
            self.alloc_ephemeral_port()?
        } else {
            if self
                .udp
                .iter()
                .flatten()
                .any(|u| u.local_port == local_port)
            {
                return Err(Errno::EADDRINUSE);
            }
            local_port
        };
        let entry = UdpEntry {
            local_ip,
            local_port: port,
            peer: None,
            rx_queue: VecDeque::new(),
        };
        self.insert_udp_entry(entry)
    }

    fn insert_udp_entry(&mut self, entry: UdpEntry) -> Result<u32, Errno> {
        for (i, slot) in self.udp.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                return Ok(i as u32);
            }
        }
        let id = u32::try_from(self.udp.len()).map_err(|_| Errno::ENOBUFS)?;
        self.udp.push(Some(entry));
        Ok(id)
    }

    pub fn udp_connect(
        &mut self,
        id: u32,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> Result<(), Errno> {
        let Some(Some(entry)) = self.udp.get_mut(id as usize) else {
            return Err(Errno::EBADF);
        };
        entry.peer = Some((remote_ip, remote_port));
        Ok(())
    }

    pub fn udp_local_addr(&self, id: u32) -> Result<([u8; 4], u16), Errno> {
        let Some(Some(entry)) = self.udp.get(id as usize) else {
            return Err(Errno::EBADF);
        };
        let ip = if entry.local_ip == [0, 0, 0, 0] && self.cfg.configured {
            self.cfg.ip
        } else {
            entry.local_ip
        };
        Ok((ip, entry.local_port))
    }

    pub fn udp_peer_addr(&self, id: u32) -> Result<Option<([u8; 4], u16)>, Errno> {
        let Some(Some(entry)) = self.udp.get(id as usize) else {
            return Err(Errno::EBADF);
        };
        Ok(entry.peer)
    }

    pub fn udp_send_to(
        &mut self,
        id: u32,
        dst: Option<([u8; 4], u16)>,
        payload: &[u8],
        now_ns: u64,
    ) -> Result<usize, Errno> {
        if !self.cfg.configured {
            return Err(Errno::ENETUNREACH);
        }
        if payload.len() > 1472 {
            return Err(Errno::EMSGSIZE);
        }
        let Some(Some(entry)) = self.udp.get(id as usize) else {
            return Err(Errno::EBADF);
        };
        let (dst_ip, dst_port) = dst.or(entry.peer).ok_or(Errno::EDESTADDRREQ)?;
        if dst_port == 0 {
            return Err(Errno::EINVAL);
        }
        let src_port = entry.local_port;
        let src_ip = if entry.local_ip == [0, 0, 0, 0] {
            self.cfg.ip
        } else {
            entry.local_ip
        };
        let ip_id = self.alloc_ip_id();
        let pkt = build_udp_ip(src_ip, dst_ip, src_port, dst_port, ip_id, payload);
        self.send_ipv4_packet(dst_ip, pkt, now_ns)?;
        Ok(payload.len())
    }

    pub fn udp_recv_from(
        &mut self,
        id: u32,
        out: &mut [u8],
        peek: bool,
    ) -> Result<(usize, [u8; 4], u16), Errno> {
        let Some(Some(entry)) = self.udp.get_mut(id as usize) else {
            return Err(Errno::EBADF);
        };
        let dg = if peek {
            entry.rx_queue.front().cloned()
        } else {
            entry.rx_queue.pop_front()
        };
        let Some(dg) = dg else {
            return Err(Errno::EAGAIN);
        };
        let copy_len = min(out.len(), dg.payload.len());
        out[..copy_len].copy_from_slice(&dg.payload[..copy_len]);
        Ok((copy_len, dg.src_ip, dg.src_port))
    }

    pub fn udp_unread_bytes(&self, id: u32) -> usize {
        self.udp
            .get(id as usize)
            .and_then(|s| s.as_ref())
            .and_then(|e| e.rx_queue.front())
            .map(|d| d.payload.len())
            .unwrap_or(0)
    }

    pub fn udp_poll_events(&self, id: u32) -> u16 {
        let Some(Some(entry)) = self.udp.get(id as usize) else {
            return POLLERR;
        };
        let mut ev = 0u16;
        if !entry.rx_queue.is_empty() {
            ev |= POLLIN;
        }
        if self.cfg.configured {
            ev |= POLLOUT;
        }
        ev
    }

    pub fn udp_close(&mut self, id: u32) {
        if let Some(slot) = self.udp.get_mut(id as usize) {
            *slot = None;
        }
    }

    // ------------------------------------------------------------------------
    // TCP Public API & Engine
    // ------------------------------------------------------------------------

    fn next_isn(&mut self, now_ns: u64) -> u32 {
        self.isn_nonce = self.isn_nonce.wrapping_add(0x0101_0001);
        (now_ns as u32).wrapping_add(self.isn_nonce)
    }

    fn alloc_tcp_slot(&mut self, entry: TcpEntry) -> Result<u32, Errno> {
        for (i, slot) in self.tcp.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                return Ok(i as u32);
            }
        }
        let id = u32::try_from(self.tcp.len()).map_err(|_| Errno::ENOBUFS)?;
        self.tcp.push(Some(entry));
        Ok(id)
    }

    pub fn tcp_listen(
        &mut self,
        local_ip: [u8; 4],
        local_port: u16,
        backlog: usize,
        now_ns: u64,
    ) -> Result<u32, Errno> {
        let port = if local_port == 0 {
            self.alloc_ephemeral_port()?
        } else {
            if self
                .tcp
                .iter()
                .flatten()
                .any(|t| t.local_port == local_port && t.state == TcpConnState::Listen)
            {
                return Err(Errno::EADDRINUSE);
            }
            local_port
        };
        let entry = TcpEntry {
            state: TcpConnState::Listen,
            local_ip,
            local_port: port,
            remote_ip: [0; 4],
            remote_port: 0,
            iss: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            irs: 0,
            rcv_nxt: 0,
            peer_mss: DEFAULT_TCP_MSS,
            rx_buf: VecDeque::new(),
            tx_buf: VecDeque::new(),
            unacked: VecDeque::new(),
            ooo: Vec::new(),
            accept_queue: VecDeque::new(),
            backlog: backlog.clamp(1, 32),
            parent_listener: None,
            dup_acks: 0,
            peer_fin_received: false,
            local_fin_seq: None,
            shutdown_rd: false,
            shutdown_wr: false,
            close_after_tx: false,
            closed_by_user: false,
            pending_error: None,
            last_activity_ns: now_ns,
            time_wait_deadline_ns: 0,
        };
        self.alloc_tcp_slot(entry)
    }

    pub fn tcp_accept(&mut self, listener_id: u32) -> Result<Option<u32>, Errno> {
        let Some(Some(listener)) = self.tcp.get_mut(listener_id as usize) else {
            return Err(Errno::EBADF);
        };
        if listener.state != TcpConnState::Listen {
            return Err(Errno::EINVAL);
        }
        Ok(listener.accept_queue.pop_front())
    }

    pub fn tcp_connect(
        &mut self,
        bound_ip: Option<[u8; 4]>,
        bound_port: Option<u16>,
        remote_ip: [u8; 4],
        remote_port: u16,
        now_ns: u64,
    ) -> Result<u32, Errno> {
        if !self.cfg.configured {
            return Err(Errno::ENETUNREACH);
        }
        if remote_port == 0 {
            return Err(Errno::ECONNREFUSED);
        }
        let local_ip = match bound_ip {
            Some(ip) if ip != [0, 0, 0, 0] => ip,
            _ => self.cfg.ip,
        };
        let local_port = match bound_port {
            Some(p) if p != 0 => p,
            _ => self.alloc_ephemeral_port()?,
        };
        let iss = self.next_isn(now_ns);
        let snd_nxt = iss.wrapping_add(1);
        let mut unacked = VecDeque::new();
        unacked.push_back(UnackedSegment {
            seq: iss,
            end_seq: snd_nxt,
            flags: TCP_SYN,
            mss: Some(DEFAULT_TCP_MSS),
            data: Vec::new(),
            sent_ns: now_ns,
            retransmits: 0,
        });
        let entry = TcpEntry {
            state: TcpConnState::SynSent,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            iss,
            snd_una: iss,
            snd_nxt,
            snd_wnd: 65535,
            irs: 0,
            rcv_nxt: 0,
            peer_mss: DEFAULT_TCP_MSS,
            rx_buf: VecDeque::new(),
            tx_buf: VecDeque::new(),
            unacked,
            ooo: Vec::new(),
            accept_queue: VecDeque::new(),
            backlog: 0,
            parent_listener: None,
            dup_acks: 0,
            peer_fin_received: false,
            local_fin_seq: None,
            shutdown_rd: false,
            shutdown_wr: false,
            close_after_tx: false,
            closed_by_user: false,
            pending_error: None,
            last_activity_ns: now_ns,
            time_wait_deadline_ns: 0,
        };
        let win = entry.rcv_window();
        let id = self.alloc_tcp_slot(entry)?;
        self.emit_tcp_segment(
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            iss,
            0,
            TCP_SYN,
            win,
            Some(DEFAULT_TCP_MSS),
            &[],
            now_ns,
        );
        Ok(id)
    }

    pub fn tcp_send(&mut self, id: u32, data: &[u8], now_ns: u64) -> Result<usize, Errno> {
        let Some(Some(entry)) = self.tcp.get_mut(id as usize) else {
            return Err(Errno::EBADF);
        };
        if let Some(err) = entry.pending_error.take() {
            return Err(err);
        }
        if entry.shutdown_wr
            || matches!(
                entry.state,
                TcpConnState::Closed
                    | TcpConnState::Reset
                    | TcpConnState::FinWait1
                    | TcpConnState::FinWait2
                    | TcpConnState::Closing
                    | TcpConnState::LastAck
                    | TcpConnState::TimeWait
            )
        {
            return Err(Errno::EPIPE);
        }
        if !matches!(
            entry.state,
            TcpConnState::Established | TcpConnState::CloseWait
        ) {
            return Err(Errno::EAGAIN);
        }
        let room = TCP_TX_BUF_CAP.saturating_sub(entry.tx_buf.len());
        if room == 0 {
            return Err(Errno::EAGAIN);
        }
        let take = min(room, data.len());
        entry.tx_buf.extend(&data[..take]);
        entry.last_activity_ns = now_ns;
        self.flush_tcp_tx(id, now_ns);
        Ok(take)
    }

    pub fn tcp_recv(
        &mut self,
        id: u32,
        out: &mut [u8],
        peek: bool,
        now_ns: u64,
    ) -> Result<usize, Errno> {
        let mut send_win_update = None;
        let result = {
            let Some(Some(entry)) = self.tcp.get_mut(id as usize) else {
                return Err(Errno::EBADF);
            };
            if entry.shutdown_rd {
                return Ok(0);
            }
            if !entry.rx_buf.is_empty() {
                let prev_win = entry.rcv_window();
                let take = min(out.len(), entry.rx_buf.len());
                if peek {
                    for (dst, src) in out[..take].iter_mut().zip(entry.rx_buf.iter()) {
                        *dst = *src;
                    }
                } else {
                    for dst in out[..take].iter_mut() {
                        *dst = entry.rx_buf.pop_front().unwrap_or(0);
                    }
                    let new_win = entry.rcv_window();
                    if prev_win < entry.peer_mss * 2 && new_win >= entry.peer_mss * 4 {
                        send_win_update = Some((
                            entry.local_ip,
                            entry.remote_ip,
                            entry.local_port,
                            entry.remote_port,
                            entry.snd_nxt,
                            entry.rcv_nxt,
                            new_win,
                        ));
                    }
                }
                entry.last_activity_ns = now_ns;
                Ok(take)
            } else if let Some(err) = entry.pending_error.take() {
                Err(err)
            } else if entry.peer_fin_received
                || matches!(
                    entry.state,
                    TcpConnState::CloseWait
                        | TcpConnState::Closing
                        | TcpConnState::LastAck
                        | TcpConnState::TimeWait
                        | TcpConnState::Closed
                        | TcpConnState::Reset
                )
            {
                Ok(0)
            } else {
                Err(Errno::EAGAIN)
            }
        };

        if let Some((src_ip, dst_ip, sp, dp, seq, ack, win)) = send_win_update {
            self.emit_tcp_segment(
                src_ip,
                dst_ip,
                sp,
                dp,
                seq,
                ack,
                TCP_ACK,
                win,
                None,
                &[],
                now_ns,
            );
        }
        result
    }

    pub fn tcp_shutdown(&mut self, id: u32, rd: bool, wr: bool, now_ns: u64) -> Result<(), Errno> {
        let Some(Some(entry)) = self.tcp.get_mut(id as usize) else {
            return Err(Errno::EBADF);
        };
        if rd {
            entry.shutdown_rd = true;
        }
        if wr {
            entry.shutdown_wr = true;
            entry.close_after_tx = true;
            self.flush_tcp_tx(id, now_ns);
        }
        Ok(())
    }

    pub fn tcp_close(&mut self, id: u32, now_ns: u64) {
        let mut children_to_close = Vec::new();
        let Some(Some(entry)) = self.tcp.get_mut(id as usize) else {
            return;
        };
        if entry.state == TcpConnState::Listen {
            while let Some(child) = entry.accept_queue.pop_front() {
                children_to_close.push(child);
            }
            self.tcp[id as usize] = None;
            for child in children_to_close {
                self.tcp_close(child, now_ns);
            }
            return;
        }

        entry.closed_by_user = true;
        entry.shutdown_rd = true;
        entry.shutdown_wr = true;
        entry.last_activity_ns = now_ns;
        match entry.state {
            TcpConnState::Closed
            | TcpConnState::Reset
            | TcpConnState::SynSent
            | TcpConnState::TimeWait => {
                self.tcp[id as usize] = None;
            }
            _ => {
                entry.close_after_tx = true;
                self.flush_tcp_tx(id, now_ns);
            }
        }
    }

    pub fn tcp_state(&self, id: u32) -> Option<TcpConnState> {
        self.tcp
            .get(id as usize)
            .and_then(|s| s.as_ref())
            .map(|t| t.state)
    }

    pub fn tcp_addrs(&self, id: u32) -> Option<TcpEndpointAddrs> {
        self.tcp
            .get(id as usize)
            .and_then(|s| s.as_ref())
            .map(|t| TcpEndpointAddrs {
                local_ip: t.local_ip,
                local_port: t.local_port,
                remote_ip: t.remote_ip,
                remote_port: t.remote_port,
            })
    }

    pub fn tcp_unread_bytes(&self, id: u32) -> usize {
        self.tcp
            .get(id as usize)
            .and_then(|s| s.as_ref())
            .map(|t| t.rx_buf.len())
            .unwrap_or(0)
    }

    pub fn tcp_take_error(&mut self, id: u32) -> Option<Errno> {
        let Some(Some(entry)) = self.tcp.get_mut(id as usize) else {
            return Some(Errno::EBADF);
        };
        entry.pending_error.take()
    }

    pub fn tcp_poll_events(&self, id: u32) -> u16 {
        let Some(Some(entry)) = self.tcp.get(id as usize) else {
            return POLLERR;
        };
        let mut ev = 0u16;
        match entry.state {
            TcpConnState::Listen => {
                if !entry.accept_queue.is_empty() {
                    ev |= POLLIN;
                }
            }
            TcpConnState::SynSent | TcpConnState::SynReceived => {}
            TcpConnState::Established | TcpConnState::FinWait1 | TcpConnState::FinWait2 => {
                if !entry.rx_buf.is_empty() || entry.peer_fin_received {
                    ev |= POLLIN;
                }
                if entry.peer_fin_received {
                    ev |= POLLRDHUP;
                }
                if matches!(entry.state, TcpConnState::Established)
                    && !entry.shutdown_wr
                    && entry.tx_buf.len() < TCP_TX_BUF_CAP
                {
                    ev |= POLLOUT;
                }
            }
            TcpConnState::CloseWait => {
                ev |= POLLIN | POLLRDHUP;
                if !entry.shutdown_wr && entry.tx_buf.len() < TCP_TX_BUF_CAP {
                    ev |= POLLOUT;
                }
            }
            TcpConnState::Closing
            | TcpConnState::LastAck
            | TcpConnState::TimeWait
            | TcpConnState::Closed => {
                ev |= POLLIN | POLLHUP | POLLRDHUP;
            }
            TcpConnState::Reset => {
                ev |= POLLERR | POLLHUP | POLLIN;
            }
        }
        if entry.pending_error.is_some() {
            ev |= POLLERR | POLLOUT | POLLIN;
        }
        ev
    }

    fn flush_tcp_tx(&mut self, id: u32, now_ns: u64) {
        let mut to_send: Vec<OutboundTcpSeg> = Vec::new();
        {
            let Some(Some(entry)) = self.tcp.get_mut(id as usize) else {
                return;
            };
            if !matches!(
                entry.state,
                TcpConnState::Established | TcpConnState::CloseWait
            ) {
                return;
            }

            let effective_wnd = min(
                entry.snd_wnd.max(u32::from(entry.peer_mss)),
                TCP_MAX_INFLIGHT_BYTES,
            );
            while !entry.tx_buf.is_empty() {
                let inflight = entry.inflight_bytes();
                if inflight >= effective_wnd {
                    break;
                }
                let avail_wnd = (effective_wnd - inflight) as usize;
                let chunk_len = min(
                    min(usize::from(entry.peer_mss), avail_wnd),
                    entry.tx_buf.len(),
                );
                if chunk_len == 0 {
                    break;
                }
                let mut payload = Vec::with_capacity(chunk_len);
                for _ in 0..chunk_len {
                    payload.push(entry.tx_buf.pop_front().unwrap_or(0));
                }
                let seq = entry.snd_nxt;
                let end_seq = seq.wrapping_add(chunk_len as u32);
                entry.snd_nxt = end_seq;
                let flags = TCP_ACK | TCP_PSH;
                entry.unacked.push_back(UnackedSegment {
                    seq,
                    end_seq,
                    flags,
                    mss: None,
                    data: payload.clone(),
                    sent_ns: now_ns,
                    retransmits: 0,
                });
                to_send.push(OutboundTcpSeg {
                    src_ip: entry.local_ip,
                    dst_ip: entry.remote_ip,
                    src_port: entry.local_port,
                    dst_port: entry.remote_port,
                    seq,
                    ack: entry.rcv_nxt,
                    flags,
                    window: entry.rcv_window(),
                    mss: None,
                    payload,
                });
            }

            if entry.close_after_tx && entry.tx_buf.is_empty() && entry.local_fin_seq.is_none() {
                let seq = entry.snd_nxt;
                let end_seq = seq.wrapping_add(1);
                entry.snd_nxt = end_seq;
                entry.local_fin_seq = Some(end_seq);
                let flags = TCP_ACK | TCP_FIN;
                entry.unacked.push_back(UnackedSegment {
                    seq,
                    end_seq,
                    flags,
                    mss: None,
                    data: Vec::new(),
                    sent_ns: now_ns,
                    retransmits: 0,
                });
                entry.state = match entry.state {
                    TcpConnState::Established => TcpConnState::FinWait1,
                    TcpConnState::CloseWait => TcpConnState::LastAck,
                    other => other,
                };
                to_send.push(OutboundTcpSeg {
                    src_ip: entry.local_ip,
                    dst_ip: entry.remote_ip,
                    src_port: entry.local_port,
                    dst_port: entry.remote_port,
                    seq,
                    ack: entry.rcv_nxt,
                    flags,
                    window: entry.rcv_window(),
                    mss: None,
                    payload: Vec::new(),
                });
            }
        }

        for seg in to_send {
            self.emit_tcp_segment(
                seg.src_ip,
                seg.dst_ip,
                seg.src_port,
                seg.dst_port,
                seg.seq,
                seg.ack,
                seg.flags,
                seg.window,
                seg.mss,
                &seg.payload,
                now_ns,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_tcp_segment(
        &mut self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        mss: Option<u16>,
        payload: &[u8],
        now_ns: u64,
    ) {
        let ip_id = self.alloc_ip_id();
        let pkt = build_tcp_ip(
            src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window, mss, ip_id, payload,
        );
        let _ = self.send_ipv4_packet(dst_ip, pkt, now_ns);
    }

    fn handle_tcp(&mut self, ip: &crate::proto::Ipv4Packet<'_>, now_ns: u64) {
        if !self.cfg.configured || ip.dst != self.cfg.ip {
            return;
        }
        let Some(seg) = parse_tcp(ip.src, ip.dst, ip.payload) else {
            return;
        };

        // 1. Find existing non-listening connection matching 4-tuple.
        let conn_idx = self.tcp.iter().position(|slot| {
            let Some(t) = slot else {
                return false;
            };
            t.state != TcpConnState::Listen
                && t.state != TcpConnState::Closed
                && t.local_port == seg.dst_port
                && t.remote_ip == ip.src
                && t.remote_port == seg.src_port
        });

        if let Some(id) = conn_idx {
            self.handle_tcp_conn_segment(id as u32, ip.src, &seg, now_ns);
            return;
        }

        // 2. Otherwise check listening sockets on `dst_port`.
        let listener_idx = self.tcp.iter().position(|slot| {
            let Some(t) = slot else {
                return false;
            };
            t.state == TcpConnState::Listen
                && t.local_port == seg.dst_port
                && (t.local_ip == [0, 0, 0, 0] || t.local_ip == ip.dst)
        });

        if let Some(lid) = listener_idx
            && (seg.flags & TCP_SYN) != 0
            && (seg.flags & TCP_ACK) == 0
            && (seg.flags & TCP_RST) == 0
        {
            self.handle_tcp_listen_syn(lid as u32, ip.dst, ip.src, &seg, now_ns);
            return;
        }

        // 3. Unknown port/connection: send RST unless incoming itself had RST.
        if (seg.flags & TCP_RST) == 0 {
            if (seg.flags & TCP_ACK) != 0 {
                self.emit_tcp_segment(
                    ip.dst,
                    ip.src,
                    seg.dst_port,
                    seg.src_port,
                    seg.ack,
                    0,
                    TCP_RST,
                    0,
                    None,
                    &[],
                    now_ns,
                );
            } else {
                let ack = seg
                    .seq
                    .wrapping_add(seg.payload.len() as u32)
                    .wrapping_add(u32::from((seg.flags & (TCP_SYN | TCP_FIN)) != 0));
                self.emit_tcp_segment(
                    ip.dst,
                    ip.src,
                    seg.dst_port,
                    seg.src_port,
                    0,
                    ack,
                    TCP_RST | TCP_ACK,
                    0,
                    None,
                    &[],
                    now_ns,
                );
            }
        }
    }

    fn handle_tcp_listen_syn(
        &mut self,
        listener_id: u32,
        dst_ip: [u8; 4],
        src_ip: [u8; 4],
        seg: &crate::proto::TcpPacket<'_>,
        now_ns: u64,
    ) {
        let Some(Some(listener)) = self.tcp.get(listener_id as usize) else {
            return;
        };
        if listener.accept_queue.len() >= listener.backlog {
            return;
        }
        let local_port = listener.local_port;
        let iss = self.next_isn(now_ns);
        let irs = seg.seq;
        let rcv_nxt = irs.wrapping_add(1);
        let snd_nxt = iss.wrapping_add(1);
        let mut unacked = VecDeque::new();
        unacked.push_back(UnackedSegment {
            seq: iss,
            end_seq: snd_nxt,
            flags: TCP_SYN | TCP_ACK,
            mss: Some(DEFAULT_TCP_MSS),
            data: Vec::new(),
            sent_ns: now_ns,
            retransmits: 0,
        });
        let child = TcpEntry {
            state: TcpConnState::SynReceived,
            local_ip: dst_ip,
            local_port,
            remote_ip: src_ip,
            remote_port: seg.src_port,
            iss,
            snd_una: iss,
            snd_nxt,
            snd_wnd: u32::from(seg.window.max(1)),
            irs,
            rcv_nxt,
            peer_mss: seg
                .mss
                .unwrap_or(DEFAULT_TCP_MSS)
                .clamp(536, DEFAULT_TCP_MSS),
            rx_buf: VecDeque::new(),
            tx_buf: VecDeque::new(),
            unacked,
            ooo: Vec::new(),
            accept_queue: VecDeque::new(),
            backlog: 0,
            parent_listener: Some(listener_id),
            dup_acks: 0,
            peer_fin_received: false,
            local_fin_seq: None,
            shutdown_rd: false,
            shutdown_wr: false,
            close_after_tx: false,
            closed_by_user: false,
            pending_error: None,
            last_activity_ns: now_ns,
            time_wait_deadline_ns: 0,
        };
        let win = child.rcv_window();
        if self.alloc_tcp_slot(child).is_ok() {
            self.emit_tcp_segment(
                dst_ip,
                src_ip,
                local_port,
                seg.src_port,
                iss,
                rcv_nxt,
                TCP_SYN | TCP_ACK,
                win,
                Some(DEFAULT_TCP_MSS),
                &[],
                now_ns,
            );
        }
    }

    fn handle_tcp_conn_segment(
        &mut self,
        id: u32,
        src_ip: [u8; 4],
        seg: &crate::proto::TcpPacket<'_>,
        now_ns: u64,
    ) {
        let mut send_ack = false;
        let mut send_rst = None;
        let mut retransmit_synack = None;
        let mut fast_retransmit = None;
        let mut promote_parent = None;
        let mut ack_tuple = None;
        let mut need_flush = false;

        {
            let Some(Some(entry)) = self.tcp.get_mut(id as usize) else {
                return;
            };
            entry.last_activity_ns = now_ns;

            if entry.state == TcpConnState::SynSent {
                if (seg.flags & TCP_RST) != 0 {
                    if (seg.flags & TCP_ACK) == 0 || seg.ack == entry.snd_nxt {
                        entry.pending_error = Some(Errno::ECONNREFUSED);
                        entry.state = TcpConnState::Reset;
                        entry.unacked.clear();
                    }
                    return;
                }
                if (seg.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)
                    && seg.ack == entry.snd_nxt
                {
                    entry.irs = seg.seq;
                    entry.rcv_nxt = seg.seq.wrapping_add(1);
                    entry.snd_una = seg.ack;
                    entry.snd_wnd = u32::from(seg.window.max(1));
                    if let Some(m) = seg.mss {
                        entry.peer_mss = m.clamp(536, DEFAULT_TCP_MSS);
                    }
                    entry.unacked.clear();
                    entry.state = TcpConnState::Established;
                    send_ack = true;
                    ack_tuple = Some((
                        entry.local_ip,
                        src_ip,
                        entry.local_port,
                        entry.remote_port,
                        entry.snd_nxt,
                        entry.rcv_nxt,
                        entry.rcv_window(),
                    ));
                    need_flush = true;
                } else {
                    return;
                }
            } else {
                if (seg.flags & TCP_RST) != 0 {
                    let in_wnd = seq_ge(seg.seq, entry.rcv_nxt)
                        && seq_le(
                            seg.seq,
                            entry
                                .rcv_nxt
                                .wrapping_add(u32::from(entry.rcv_window()).max(1)),
                        );
                    if in_wnd {
                        entry.pending_error = Some(Errno::ECONNRESET);
                        entry.state = TcpConnState::Reset;
                        entry.unacked.clear();
                        entry.tx_buf.clear();
                    }
                    return;
                }

                // Re-send SYN|ACK if peer retransmits SYN in SynReceived.
                if entry.state == TcpConnState::SynReceived
                    && (seg.flags & TCP_SYN) != 0
                    && (seg.flags & TCP_ACK) == 0
                {
                    retransmit_synack = Some((
                        entry.local_ip,
                        src_ip,
                        entry.local_port,
                        entry.remote_port,
                        entry.iss,
                        entry.rcv_nxt,
                        entry.rcv_window(),
                    ));
                } else {
                    // Process ACK field
                    if (seg.flags & TCP_ACK) != 0 {
                        entry.snd_wnd = u32::from(seg.window);
                        if entry.state == TcpConnState::SynReceived && seg.ack == entry.snd_nxt {
                            entry.snd_una = seg.ack;
                            entry.unacked.clear();
                            entry.state = TcpConnState::Established;
                            promote_parent = entry.parent_listener.take();
                        } else if seq_gt(seg.ack, entry.snd_una) && seq_le(seg.ack, entry.snd_nxt) {
                            entry.snd_una = seg.ack;
                            entry.dup_acks = 0;
                            while let Some(front) = entry.unacked.front() {
                                if seq_le(front.end_seq, seg.ack) {
                                    let _ = entry.unacked.pop_front();
                                } else {
                                    break;
                                }
                            }
                            if let Some(fin_end) = entry.local_fin_seq
                                && seq_ge(seg.ack, fin_end)
                            {
                                entry.state = match entry.state {
                                    TcpConnState::FinWait1 => TcpConnState::FinWait2,
                                    TcpConnState::Closing => {
                                        entry.time_wait_deadline_ns = now_ns + 500_000_000;
                                        TcpConnState::TimeWait
                                    }
                                    TcpConnState::LastAck => TcpConnState::Closed,
                                    other => other,
                                };
                            }
                            need_flush = true;
                        } else if seg.ack == entry.snd_una
                            && !entry.unacked.is_empty()
                            && seg.payload.is_empty()
                            && (seg.flags & (TCP_SYN | TCP_FIN)) == 0
                        {
                            entry.dup_acks = entry.dup_acks.saturating_add(1);
                            if entry.dup_acks == 3
                                && let Some(front) = entry.unacked.front()
                            {
                                fast_retransmit = Some((
                                    entry.local_ip,
                                    entry.remote_ip,
                                    entry.local_port,
                                    entry.remote_port,
                                    front.seq,
                                    entry.rcv_nxt,
                                    front.flags,
                                    entry.rcv_window(),
                                    front.mss,
                                    front.data.clone(),
                                ));
                            }
                        }
                    }

                    // Process incoming payload & FIN
                    if matches!(
                        entry.state,
                        TcpConnState::Established
                            | TcpConnState::FinWait1
                            | TcpConnState::FinWait2
                            | TcpConnState::TimeWait
                    ) && (!seg.payload.is_empty() || (seg.flags & TCP_FIN) != 0)
                    {
                        if entry.state == TcpConnState::TimeWait {
                            send_ack = true;
                        } else if seq_le(seg.seq, entry.rcv_nxt) {
                            let overlap = entry.rcv_nxt.wrapping_sub(seg.seq) as usize;
                            let mut accepted_all_payload = true;
                            if overlap < seg.payload.len() {
                                let fresh = &seg.payload[overlap..];
                                let space = TCP_RX_BUF_CAP.saturating_sub(entry.rx_buf.len());
                                let take = min(space, fresh.len());
                                if take < fresh.len() {
                                    accepted_all_payload = false;
                                }
                                if entry.shutdown_rd {
                                    send_rst = Some((
                                        entry.local_ip,
                                        entry.remote_ip,
                                        entry.local_port,
                                        entry.remote_port,
                                        entry.snd_nxt,
                                    ));
                                    entry.state = TcpConnState::Reset;
                                } else {
                                    entry.rx_buf.extend(&fresh[..take]);
                                    entry.rcv_nxt = entry.rcv_nxt.wrapping_add(take as u32);
                                }
                            } else if !seg.payload.is_empty() {
                                // Duplicate packet: acknowledge current rcv_nxt
                                send_ack = true;
                            }

                            // Drain matching OOO chunks
                            loop {
                                let mut progress = false;
                                let mut i = 0;
                                while i < entry.ooo.len() {
                                    if seq_le(entry.ooo[i].seq, entry.rcv_nxt) {
                                        let chunk = entry.ooo.remove(i);
                                        let ov = entry.rcv_nxt.wrapping_sub(chunk.seq) as usize;
                                        if ov < chunk.data.len() {
                                            let rem = &chunk.data[ov..];
                                            let space =
                                                TCP_RX_BUF_CAP.saturating_sub(entry.rx_buf.len());
                                            let take = min(space, rem.len());
                                            entry.rx_buf.extend(&rem[..take]);
                                            entry.rcv_nxt = entry.rcv_nxt.wrapping_add(take as u32);
                                            if take > 0 {
                                                progress = true;
                                            }
                                        }
                                        break;
                                    }
                                    i += 1;
                                }
                                if !progress {
                                    break;
                                }
                            }

                            if !seg.payload.is_empty() {
                                send_ack = true;
                            }

                            let seg_end_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
                            if accepted_all_payload
                                && (seg.flags & TCP_FIN) != 0
                                && !entry.peer_fin_received
                                && seq_le(seg_end_seq, entry.rcv_nxt)
                            {
                                entry.rcv_nxt = entry.rcv_nxt.wrapping_add(1);
                                entry.peer_fin_received = true;
                                send_ack = true;
                                entry.state = match entry.state {
                                    TcpConnState::Established => TcpConnState::CloseWait,
                                    TcpConnState::FinWait1 => TcpConnState::Closing,
                                    TcpConnState::FinWait2 => {
                                        entry.time_wait_deadline_ns = now_ns + 500_000_000;
                                        TcpConnState::TimeWait
                                    }
                                    other => other,
                                };
                            }
                        } else if !seg.payload.is_empty()
                            && seg.seq.wrapping_sub(entry.rcv_nxt) < TCP_RX_BUF_CAP as u32
                        {
                            if entry.ooo.len() < TCP_OOO_MAX
                                && !entry.ooo.iter().any(|c| c.seq == seg.seq)
                            {
                                entry.ooo.push(OooChunk {
                                    seq: seg.seq,
                                    data: seg.payload.to_vec(),
                                });
                            }
                            send_ack = true;
                        } else {
                            send_ack = true;
                        }
                    }

                    if send_ack {
                        ack_tuple = Some((
                            entry.local_ip,
                            src_ip,
                            entry.local_port,
                            entry.remote_port,
                            entry.snd_nxt,
                            entry.rcv_nxt,
                            entry.rcv_window(),
                        ));
                    }
                }
            }
        }

        if let Some((lip, rip, lp, rp, iss, rcv, win)) = retransmit_synack {
            self.emit_tcp_segment(
                lip,
                rip,
                lp,
                rp,
                iss,
                rcv,
                TCP_SYN | TCP_ACK,
                win,
                Some(DEFAULT_TCP_MSS),
                &[],
                now_ns,
            );
            return;
        }

        if let Some(lid) = promote_parent
            && let Some(Some(listener)) = self.tcp.get_mut(lid as usize)
            && listener.state == TcpConnState::Listen
            && listener.accept_queue.len() < listener.backlog
        {
            listener.accept_queue.push_back(id);
        }

        if let Some((lip, rip, lp, rp, seq)) = send_rst {
            self.emit_tcp_segment(lip, rip, lp, rp, seq, 0, TCP_RST, 0, None, &[], now_ns);
            return;
        }

        if let Some((lip, rip, lp, rp, seq, ack, flags, win, mss, data)) = fast_retransmit {
            self.emit_tcp_segment(lip, rip, lp, rp, seq, ack, flags, win, mss, &data, now_ns);
        }

        if send_ack && let Some((lip, rip, lp, rp, seq, ack, win)) = ack_tuple {
            self.emit_tcp_segment(lip, rip, lp, rp, seq, ack, TCP_ACK, win, None, &[], now_ns);
        }

        if need_flush {
            self.flush_tcp_tx(id, now_ns);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_mock_dhcp_reply(
        mac: [u8; 6],
        xid: u32,
        msg_type: u8,
        yiaddr: [u8; 4],
        server_id: [u8; 4],
    ) -> Vec<u8> {
        let mut bootp = vec![0u8; 300];
        bootp[0] = 2; // BOOTREPLY
        bootp[1] = 1;
        bootp[2] = 6;
        bootp[4..8].copy_from_slice(&xid.to_be_bytes());
        bootp[16..20].copy_from_slice(&yiaddr);
        bootp[28..34].copy_from_slice(&mac);
        bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
        let opts: &[u8] = &[
            53,
            1,
            msg_type,
            54,
            4,
            server_id[0],
            server_id[1],
            server_id[2],
            server_id[3],
            1,
            4,
            255,
            255,
            255,
            0,
            3,
            4,
            10,
            0,
            2,
            2,
            6,
            4,
            10,
            0,
            2,
            3,
            255,
        ];
        bootp[240..240 + opts.len()].copy_from_slice(opts);
        let ip = build_udp_ip(server_id, [255, 255, 255, 255], 67, 68, 1, &bootp);
        build_ethernet_frame(
            [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02],
            mac,
            ETHERTYPE_IPV4,
            &ip,
        )
    }

    #[test]
    fn dhcp_arp_udp_and_tcp_roundtrip() {
        let guest_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let gw_mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let mut stack = NetStack::new(guest_mac, 1500, true);
        stack.start_dhcp(1_000_000);

        let disc_frame = stack.pop_tx_frame().expect("DHCPDISCOVER");
        let eth = parse_ethernet(&disc_frame).unwrap();
        let ip = parse_ipv4(eth.payload).unwrap();
        let udp = parse_udp(ip.src, ip.dst, ip.payload).unwrap();
        assert_eq!(udp.dst_port, 67);
        let xid = u32::from_be_bytes(udp.payload[4..8].try_into().unwrap());

        let offer = build_mock_dhcp_reply(guest_mac, xid, 2, [10, 0, 2, 15], [10, 0, 2, 2]);
        stack.ingest_frame(&offer, 2_000_000);
        let req_frame = stack.pop_tx_frame().expect("DHCPREQUEST");
        let _ = req_frame;

        let ack = build_mock_dhcp_reply(guest_mac, xid, 5, [10, 0, 2, 15], [10, 0, 2, 2]);
        stack.ingest_frame(&ack, 3_000_000);
        assert!(stack.dhcp_bound());
        assert_eq!(stack.cfg.ip, [10, 0, 2, 15]);
        assert_eq!(stack.cfg.gateway, [10, 0, 2, 2]);
        assert_eq!(stack.cfg.dns, [10, 0, 2, 3]);

        // UDP send triggers ARP request, then flushes buffered UDP packet on ARP reply.
        let udp_id = stack.udp_open([0; 4], 0).unwrap();
        stack
            .udp_send_to(udp_id, Some(([10, 0, 2, 3], 53)), b"dnsq", 4_000_000)
            .unwrap();
        let arp_req = stack.pop_tx_frame().expect("ARP request");
        let arp = parse_arp(parse_ethernet(&arp_req).unwrap().payload).unwrap();
        assert_eq!(arp.tpa, [10, 0, 2, 3]);
        assert!(stack.pop_tx_frame().is_none());

        let dns_mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x03];
        let arp_rep = build_arp_frame(
            dns_mac,
            guest_mac,
            ARP_OP_REPLY,
            dns_mac,
            [10, 0, 2, 3],
            guest_mac,
            [10, 0, 2, 15],
        );
        stack.ingest_frame(&arp_rep, 5_000_000);
        let flushed_udp = stack.pop_tx_frame().expect("flushed UDP");
        let udp_rx_ip = parse_ipv4(parse_ethernet(&flushed_udp).unwrap().payload).unwrap();
        assert_eq!(udp_rx_ip.dst, [10, 0, 2, 3]);

        // Seed gateway ARP and verify TCP 3-way handshake + data RX/TX + FIN.
        let gw_arp = build_arp_frame(
            gw_mac,
            guest_mac,
            ARP_OP_REPLY,
            gw_mac,
            [10, 0, 2, 2],
            guest_mac,
            [10, 0, 2, 15],
        );
        stack.ingest_frame(&gw_arp, 6_000_000);

        let sock = stack
            .tcp_connect(None, None, [93, 184, 216, 34], 80, 7_000_000)
            .unwrap();
        assert_eq!(stack.tcp_state(sock), Some(TcpConnState::SynSent));
        let syn_frame = stack.pop_tx_frame().expect("SYN frame");
        let syn_ip = parse_ipv4(parse_ethernet(&syn_frame).unwrap().payload).unwrap();
        let syn_tcp = parse_tcp(syn_ip.src, syn_ip.dst, syn_ip.payload).unwrap();
        assert_eq!(syn_tcp.flags, TCP_SYN);

        let synack_ip = build_tcp_ip(
            [93, 184, 216, 34],
            [10, 0, 2, 15],
            80,
            syn_tcp.src_port,
            9000,
            syn_tcp.seq.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            65535,
            Some(1460),
            10,
            &[],
        );
        stack.ingest_frame(
            &build_ethernet_frame(gw_mac, guest_mac, ETHERTYPE_IPV4, &synack_ip),
            8_000_000,
        );
        assert_eq!(stack.tcp_state(sock), Some(TcpConnState::Established));
        let _ack_frame = stack.pop_tx_frame().expect("handshake ACK");

        assert_eq!(
            stack.tcp_send(sock, b"GET / HTTP/1.0\r\n\r\n", 9_000_000),
            Ok(18)
        );
        let data_tx = stack.pop_tx_frame().expect("TCP data TX");
        let data_ip = parse_ipv4(parse_ethernet(&data_tx).unwrap().payload).unwrap();
        let data_tcp = parse_tcp(data_ip.src, data_ip.dst, data_ip.payload).unwrap();
        assert_eq!(data_tcp.payload, b"GET / HTTP/1.0\r\n\r\n");

        let srv_reply = build_tcp_ip(
            [93, 184, 216, 34],
            [10, 0, 2, 15],
            80,
            syn_tcp.src_port,
            9001,
            data_tcp.seq.wrapping_add(18),
            TCP_ACK | TCP_FIN,
            65535,
            None,
            11,
            b"HTTP/1.0 200 OK\r\n\r\n",
        );
        stack.ingest_frame(
            &build_ethernet_frame(gw_mac, guest_mac, ETHERTYPE_IPV4, &srv_reply),
            10_000_000,
        );
        let mut buf = [0u8; 64];
        assert_eq!(stack.tcp_recv(sock, &mut buf, false, 11_000_000), Ok(19));
        assert_eq!(&buf[..19], b"HTTP/1.0 200 OK\r\n\r\n");
        assert_eq!(stack.tcp_recv(sock, &mut buf, false, 11_000_000), Ok(0));
        assert_eq!(stack.tcp_state(sock), Some(TcpConnState::CloseWait));
    }
}
