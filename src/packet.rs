//! Header-only parsing. The caller's capture buffer is never retained.
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketEvent {
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    Malformed,
    Unsupported,
    Fragmented,
}

fn be16(b: &[u8], at: usize) -> Result<u16, Skip> {
    let s = b.get(at..at + 2).ok_or(Skip::Malformed)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

pub fn supported_link(link: i32) -> bool {
    matches!(link, 0 | 1 | 12 | 101 | 108 | 113 | 228 | 229 | 276)
}

/// `wire_len` is pcap's original frame length, not the snaplen-truncated length.
pub fn parse(frame: &[u8], wire_len: u32, link: i32) -> Result<PacketEvent, Skip> {
    let (mut offset, mut ethertype) = match link {
        1 => (14, be16(frame, 12)?),
        113 => (16, be16(frame, 14)?),
        276 => (20, be16(frame, 0)?),
        0 | 108 => (4, 0), // BSD loopback: IP version determines the family.
        12 | 101 | 228 | 229 => (0, 0),
        _ => return Err(Skip::Unsupported),
    };
    if matches!(link, 1 | 113 | 276) {
        for _ in 0..4 {
            if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
                break;
            }
            ethertype = be16(frame, offset + 2)?;
            offset += 4;
        }
        if !matches!(ethertype, 0x0800 | 0x86dd) {
            return Err(Skip::Unsupported);
        }
    }
    let ip = frame.get(offset..).ok_or(Skip::Malformed)?;
    let version = ip.first().ok_or(Skip::Malformed)? >> 4;
    if (ethertype == 0x0800 && version != 4)
        || (ethertype == 0x86dd && version != 6)
        || (link == 228 && version != 4)
        || (link == 229 && version != 6)
    {
        return Err(Skip::Malformed);
    }
    let (src_ip, dst_ip, mut next, mut pos, total) = match version {
        4 => {
            if ip.len() < 20 {
                return Err(Skip::Malformed);
            }
            let ihl = ((ip[0] & 15) as usize) * 4;
            let total = be16(ip, 2)? as usize;
            if ihl < 20 || total < ihl || ip.len() < ihl {
                return Err(Skip::Malformed);
            }
            if be16(ip, 6)? & 0x3fff != 0 {
                return Err(Skip::Fragmented);
            }
            (
                IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
                IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
                ip[9],
                ihl,
                total,
            )
        }
        6 => {
            if ip.len() < 40 {
                return Err(Skip::Malformed);
            }
            let payload = be16(ip, 4)? as usize;
            if payload == 0 {
                return Err(Skip::Unsupported);
            } // No jumbograms in v0.1.
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap())),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap())),
                ip[6],
                40,
                payload + 40,
            )
        }
        _ => return Err(Skip::Unsupported),
    };
    if (wire_len as usize) < offset + total {
        return Err(Skip::Malformed);
    }
    let ip = &ip[..ip.len().min(total)];
    if version == 6 {
        let mut count = 0;
        while matches!(next, 0 | 43 | 44 | 51 | 60) {
            if next == 44 {
                return Err(Skip::Fragmented);
            }
            count += 1;
            if count > 8 {
                return Err(Skip::Unsupported);
            }
            let header = ip.get(pos..pos + 2).ok_or(Skip::Malformed)?;
            let len = if next == 51 {
                (header[1] as usize + 2) * 4
            } else {
                (header[1] as usize + 1) * 8
            };
            if next == 51 && len < 12 {
                return Err(Skip::Malformed);
            }
            next = header[0];
            pos += len;
            if pos > ip.len() {
                return Err(Skip::Malformed);
            }
        }
    }
    let transport = ip.get(pos..).ok_or(Skip::Malformed)?;
    let protocol = match next {
        6 => {
            if transport.len() < 20 {
                return Err(Skip::Malformed);
            }
            let header_len = (transport[12] >> 4) as usize * 4;
            if header_len < 20 || transport.len() < header_len {
                return Err(Skip::Malformed);
            }
            Protocol::Tcp
        }
        17 => {
            if transport.len() < 8 {
                return Err(Skip::Malformed);
            }
            let udp_len = be16(transport, 4)? as usize;
            if udp_len < 8 || udp_len != total - pos {
                return Err(Skip::Malformed);
            }
            Protocol::Udp
        }
        _ => return Err(Skip::Unsupported),
    };
    Ok(PacketEvent {
        protocol,
        src_ip,
        dst_ip,
        src_port: be16(transport, 0)?,
        dst_port: be16(transport, 2)?,
        ip_length: total as u32,
    })
}
