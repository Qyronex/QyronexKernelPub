// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Pure-Rust wire-format codecs and RFC 1071 checksums for Ethernet II, ARP, IPv4, ICMP,
//! UDP, TCP, and DHCPv4.

use alloc::vec;
use alloc::vec::Vec;

pub const ETH_HDR_LEN: usize = 14;
pub const IPV4_HDR_LEN: usize = 20;
pub const UDP_HDR_LEN: usize = 8;
pub const TCP_BASE_HDR_LEN: usize = 20;
pub const DEFAULT_TCP_MSS: u16 = 1460;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

pub const ARP_HTYPE_ETHERNET: u16 = 1;
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];
pub const ZERO_MAC: [u8; 6] = [0x00; 6];

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetFrame<'a> {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpPacket {
    pub oper: u16,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Packet<'a> {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    pub id: u16,
    pub ttl: u8,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpPacket<'a> {
    pub msg_type: u8,
    pub code: u8,
    pub id: u16,
    pub seq: u16,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPacket<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpPacket<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhcpMessageType {
    Offer = 2,
    Ack = 5,
    Nak = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DhcpReply {
    pub xid: u32,
    pub msg_type: DhcpMessageType,
    pub yiaddr: [u8; 4],
    pub server_id: Option<[u8; 4]>,
    pub subnet_mask: Option<[u8; 4]>,
    pub router: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
    pub lease_secs: Option<u32>,
}

pub fn checksum_accumulate(mut sum: u32, data: &[u8]) -> u32 {
    let mut i = 0usize;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    sum
}

pub fn checksum_finalize(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn ones_complement_checksum(data: &[u8]) -> u16 {
    checksum_finalize(checksum_accumulate(0, data))
}

pub fn ipv4_pseudo_checksum(src: [u8; 4], dst: [u8; 4], proto: u8, l4_bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum_accumulate(sum, &src);
    sum = checksum_accumulate(sum, &dst);
    sum += u32::from(proto);
    sum += u32::try_from(l4_bytes.len()).unwrap_or(0xffff);
    sum = checksum_accumulate(sum, l4_bytes);
    checksum_finalize(sum)
}

pub fn parse_ethernet(frame: &[u8]) -> Option<EthernetFrame<'_>> {
    if frame.len() < ETH_HDR_LEN {
        return None;
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&frame[0..6]);
    src_mac.copy_from_slice(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    Some(EthernetFrame {
        dst_mac,
        src_mac,
        ethertype,
        payload: &frame[ETH_HDR_LEN..],
    })
}

pub fn parse_arp(data: &[u8]) -> Option<ArpPacket> {
    if data.len() < 28 {
        return None;
    }
    let htype = u16::from_be_bytes([data[0], data[1]]);
    let ptype = u16::from_be_bytes([data[2], data[3]]);
    let hlen = data[4];
    let plen = data[5];
    if htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 || hlen != 6 || plen != 4 {
        return None;
    }
    let oper = u16::from_be_bytes([data[6], data[7]]);
    let mut sha = [0u8; 6];
    let mut spa = [0u8; 4];
    let mut tha = [0u8; 6];
    let mut tpa = [0u8; 4];
    sha.copy_from_slice(&data[8..14]);
    spa.copy_from_slice(&data[14..18]);
    tha.copy_from_slice(&data[18..24]);
    tpa.copy_from_slice(&data[24..28]);
    Some(ArpPacket {
        oper,
        sha,
        spa,
        tha,
        tpa,
    })
}

pub fn parse_ipv4(data: &[u8]) -> Option<Ipv4Packet<'_>> {
    if data.len() < IPV4_HDR_LEN {
        return None;
    }
    let ver_ihl = data[0];
    if (ver_ihl >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(ver_ihl & 0x0f) * 4;
    if ihl < IPV4_HDR_LEN || data.len() < ihl {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if total_len < ihl || total_len > data.len() {
        return None;
    }
    if ones_complement_checksum(&data[..ihl]) != 0 {
        return None;
    }
    let frag = u16::from_be_bytes([data[6], data[7]]);
    // Drop non-initial fragments or fragmented datagrams (MF=0x2000, offset != 0).
    if (frag & 0x3fff) != 0 {
        return None;
    }
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&data[12..16]);
    dst.copy_from_slice(&data[16..20]);
    Some(Ipv4Packet {
        src,
        dst,
        proto: data[9],
        id: u16::from_be_bytes([data[4], data[5]]),
        ttl: data[8],
        payload: &data[ihl..total_len],
    })
}

pub fn parse_icmp(data: &[u8]) -> Option<IcmpPacket<'_>> {
    if data.len() < 8 || ones_complement_checksum(data) != 0 {
        return None;
    }
    Some(IcmpPacket {
        msg_type: data[0],
        code: data[1],
        id: u16::from_be_bytes([data[4], data[5]]),
        seq: u16::from_be_bytes([data[6], data[7]]),
        data: &data[8..],
    })
}

pub fn parse_udp(src_ip: [u8; 4], dst_ip: [u8; 4], data: &[u8]) -> Option<UdpPacket<'_>> {
    if data.len() < UDP_HDR_LEN {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([data[4], data[5]]));
    if udp_len < UDP_HDR_LEN || udp_len > data.len() {
        return None;
    }
    let slice = &data[..udp_len];
    let csum = u16::from_be_bytes([slice[6], slice[7]]);
    if csum != 0 && ipv4_pseudo_checksum(src_ip, dst_ip, IPPROTO_UDP, slice) != 0 {
        return None;
    }
    Some(UdpPacket {
        src_port: u16::from_be_bytes([slice[0], slice[1]]),
        dst_port: u16::from_be_bytes([slice[2], slice[3]]),
        payload: &slice[UDP_HDR_LEN..],
    })
}

pub fn parse_tcp(src_ip: [u8; 4], dst_ip: [u8; 4], data: &[u8]) -> Option<TcpPacket<'_>> {
    if data.len() < TCP_BASE_HDR_LEN {
        return None;
    }
    let data_offset = usize::from(data[12] >> 4) * 4;
    if data_offset < TCP_BASE_HDR_LEN || data_offset > data.len() {
        return None;
    }
    if ipv4_pseudo_checksum(src_ip, dst_ip, IPPROTO_TCP, data) != 0 {
        return None;
    }
    let mut mss = None;
    let opts = &data[TCP_BASE_HDR_LEN..data_offset];
    let mut i = 0usize;
    while i < opts.len() {
        let kind = opts[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        if i + 1 >= opts.len() {
            break;
        }
        let len = usize::from(opts[i + 1]);
        if len < 2 || i + len > opts.len() {
            break;
        }
        if kind == 2 && len == 4 {
            mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
        }
        i += len;
    }
    Some(TcpPacket {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        flags: data[13],
        window: u16::from_be_bytes([data[14], data[15]]),
        mss,
        payload: &data[data_offset..],
    })
}

pub fn build_ethernet_frame(
    eth_src: [u8; 6],
    eth_dst: [u8; 6],
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = vec![0u8; ETH_HDR_LEN + payload.len()];
    frame[0..6].copy_from_slice(&eth_dst);
    frame[6..12].copy_from_slice(&eth_src);
    frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
    frame[ETH_HDR_LEN..].copy_from_slice(payload);
    frame
}

#[allow(clippy::too_many_arguments)]
pub fn build_arp_frame(
    eth_src: [u8; 6],
    eth_dst: [u8; 6],
    oper: u16,
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
) -> Vec<u8> {
    let mut arp = [0u8; 28];
    arp[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    arp[2..4].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&oper.to_be_bytes());
    arp[8..14].copy_from_slice(&sha);
    arp[14..18].copy_from_slice(&spa);
    arp[18..24].copy_from_slice(&tha);
    arp[24..28].copy_from_slice(&tpa);
    build_ethernet_frame(eth_src, eth_dst, ETHERTYPE_ARP, &arp)
}

#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    proto: u8,
    ip_id: u16,
    l4_bytes: &[u8],
) -> Vec<u8> {
    let total_len = IPV4_HDR_LEN + l4_bytes.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());
    // DF=0x4000
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = proto;
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);
    let csum = ones_complement_checksum(&pkt[..IPV4_HDR_LEN]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    pkt[IPV4_HDR_LEN..].copy_from_slice(l4_bytes);
    pkt
}

pub fn build_icmp_echo_reply_ip(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    ip_id: u16,
    id: u16,
    seq: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut icmp = vec![0u8; 8 + data.len()];
    icmp[0] = ICMP_ECHO_REPLY;
    icmp[1] = 0;
    icmp[4..6].copy_from_slice(&id.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    icmp[8..].copy_from_slice(data);
    let csum = ones_complement_checksum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());
    build_ipv4_packet(src_ip, dst_ip, IPPROTO_ICMP, ip_id, &icmp)
}

#[allow(clippy::too_many_arguments)]
pub fn build_udp_ip(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    ip_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = UDP_HDR_LEN + payload.len();
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[UDP_HDR_LEN..].copy_from_slice(payload);
    let mut csum = ipv4_pseudo_checksum(src_ip, dst_ip, IPPROTO_UDP, &udp);
    if csum == 0 {
        csum = 0xffff;
    }
    udp[6..8].copy_from_slice(&csum.to_be_bytes());
    build_ipv4_packet(src_ip, dst_ip, IPPROTO_UDP, ip_id, &udp)
}

#[allow(clippy::too_many_arguments)]
pub fn build_tcp_ip(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    ip_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let hdr_len = if mss.is_some() {
        TCP_BASE_HDR_LEN + 4
    } else {
        TCP_BASE_HDR_LEN
    };
    let mut tcp = vec![0u8; hdr_len + payload.len()];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = ((hdr_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    if let Some(mss_val) = mss {
        tcp[20] = 2;
        tcp[21] = 4;
        tcp[22..24].copy_from_slice(&mss_val.to_be_bytes());
    }
    tcp[hdr_len..].copy_from_slice(payload);
    let csum = ipv4_pseudo_checksum(src_ip, dst_ip, IPPROTO_TCP, &tcp);
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());
    build_ipv4_packet(src_ip, dst_ip, IPPROTO_TCP, ip_id, &tcp)
}

pub fn build_dhcp_discover(mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut bootp = vec![0u8; 300];
    bootp[0] = 1; // BOOTREQUEST
    bootp[1] = 1; // Ethernet
    bootp[2] = 6; // HLEN
    bootp[4..8].copy_from_slice(&xid.to_be_bytes());
    bootp[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // Broadcast flag
    bootp[28..34].copy_from_slice(&mac);
    bootp[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    let mut idx = 240;
    // Option 53: DHCP Discover (1)
    bootp[idx..idx + 3].copy_from_slice(&[53, 1, 1]);
    idx += 3;
    // Option 55: Parameter Request List (1=Mask, 3=Router, 6=DNS)
    bootp[idx..idx + 5].copy_from_slice(&[55, 3, 1, 3, 6]);
    idx += 5;
    bootp[idx] = 255; // End
    bootp
}

pub fn build_dhcp_request(
    mac: [u8; 6],
    xid: u32,
    requested_ip: [u8; 4],
    server_id: [u8; 4],
) -> Vec<u8> {
    let mut bootp = vec![0u8; 312];
    bootp[0] = 1;
    bootp[1] = 1;
    bootp[2] = 6;
    bootp[4..8].copy_from_slice(&xid.to_be_bytes());
    bootp[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    bootp[28..34].copy_from_slice(&mac);
    bootp[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    let mut idx = 240;
    bootp[idx..idx + 3].copy_from_slice(&[53, 1, 3]); // DHCP Request
    idx += 3;
    bootp[idx] = 50;
    bootp[idx + 1] = 4;
    bootp[idx + 2..idx + 6].copy_from_slice(&requested_ip);
    idx += 6;
    bootp[idx] = 54;
    bootp[idx + 1] = 4;
    bootp[idx + 2..idx + 6].copy_from_slice(&server_id);
    idx += 6;
    bootp[idx..idx + 5].copy_from_slice(&[55, 3, 1, 3, 6]);
    idx += 5;
    bootp[idx] = 255;
    bootp
}

pub fn parse_dhcp_reply(
    data: &[u8],
    expected_mac: [u8; 6],
    expected_xid: u32,
) -> Option<DhcpReply> {
    if data.len() < 240 || data[0] != 2 || data[1] != 1 || data[2] != 6 {
        return None;
    }
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if xid != expected_xid || data[28..34] != expected_mac {
        return None;
    }
    if data[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }
    let mut yiaddr = [0u8; 4];
    yiaddr.copy_from_slice(&data[16..20]);

    let mut msg_type = None;
    let mut server_id = None;
    let mut subnet_mask = None;
    let mut router = None;
    let mut dns = None;
    let mut lease_secs = None;

    let opts = &data[240..];
    let mut i = 0usize;
    while i < opts.len() {
        let code = opts[i];
        if code == 0 {
            i += 1;
            continue;
        }
        if code == 255 {
            break;
        }
        if i + 1 >= opts.len() {
            break;
        }
        let len = usize::from(opts[i + 1]);
        if i + 2 + len > opts.len() {
            break;
        }
        let val = &opts[i + 2..i + 2 + len];
        match code {
            53 if len == 1 => {
                msg_type = match val[0] {
                    2 => Some(DhcpMessageType::Offer),
                    5 => Some(DhcpMessageType::Ack),
                    6 => Some(DhcpMessageType::Nak),
                    _ => None,
                };
            }
            1 if len == 4 => subnet_mask = Some([val[0], val[1], val[2], val[3]]),
            3 if len >= 4 => router = Some([val[0], val[1], val[2], val[3]]),
            6 if len >= 4 => dns = Some([val[0], val[1], val[2], val[3]]),
            51 if len == 4 => {
                lease_secs = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]))
            }
            54 if len == 4 => server_id = Some([val[0], val[1], val[2], val[3]]),
            _ => {}
        }
        i += 2 + len;
    }

    Some(DhcpReply {
        xid,
        msg_type: msg_type?,
        yiaddr,
        server_id,
        subnet_mask,
        router,
        dns,
        lease_secs,
    })
}
