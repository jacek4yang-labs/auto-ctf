//! PCAP parsing (P1): classic libpcap global header, packet records,
//! Ethernet/IPv4/UDP/TCP walk, TCP stream reassembly, and USB HID keyboard
//! decode.
//!
//! Capability coverage: domain 8 (packet parse), domain 9 (net forensics),
//! domain 10 (USB/HID), domain 11 (file forensics pcap variant).

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy)]
pub struct PcapHeader {
    pub endian: Endian,
    pub nanosecond: bool,
    pub link_type: u32,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub ts_sec: u32,
    pub ts_frac: u32,
    pub data: Vec<u8>,
}

pub fn parse_header(data: &[u8]) -> Result<PcapHeader> {
    if data.len() < 24 {
        return Err(invalid("pcap shorter than global header"));
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let (endian, nanosecond) = match magic {
        0xa1b2_c3d4 | 0xa1b2_3c4d | 0xa1b2_cd34 => (Endian::Little, magic == 0xa1b2_3c4d),
        0xd4c3_b2a1 | 0x4d3c_b2a1 => (Endian::Big, magic == 0x4d3c_b2a1),
        other => return Err(invalid(&format!("bad pcap magic {other:#x}"))),
    };
    let rd_u32 = |b: &[u8]| -> u32 {
        if endian == Endian::Little {
            u32::from_le_bytes(b.try_into().unwrap())
        } else {
            u32::from_be_bytes(b.try_into().unwrap())
        }
    };
    Ok(PcapHeader { endian, nanosecond, link_type: rd_u32(&data[20..24]) })
}

pub fn parse_packets(data: &[u8]) -> Result<Vec<Packet>> {
    let header = parse_header(data)?;
    let rd_u32 = |b: &[u8]| -> u32 {
        if header.endian == Endian::Little {
            u32::from_le_bytes(b.try_into().unwrap())
        } else {
            u32::from_be_bytes(b.try_into().unwrap())
        }
    };
    let mut pos = 24usize;
    let mut packets = Vec::new();
    while pos + 16 <= data.len() {
        let ts_sec = rd_u32(&data[pos..pos + 4]);
        let ts_frac = rd_u32(&data[pos + 4..pos + 8]);
        let incl = rd_u32(&data[pos + 8..pos + 12]) as usize;
        pos += 16;
        if pos + incl > data.len() {
            break;
        }
        packets.push(Packet { ts_sec, ts_frac, data: data[pos..pos + incl].to_vec() });
        pos += incl;
    }
    Ok(packets)
}

pub fn parse_frame(pkt: &[u8]) -> Option<(String, String, u16, u16, Vec<u8>)> {
    if pkt.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes(pkt[12..14].try_into().unwrap());
    if ethertype != 0x0800 {
        return None;
    }
    let ip = &pkt[14..];
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ip.len() < ihl {
        return None;
    }
    let proto = ip[9];
    let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    let l4 = &ip[ihl..];
    if l4.len() < 4 {
        return None;
    }
    match proto {
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let sport = u16::from_be_bytes(l4[0..2].try_into().unwrap());
            let dport = u16::from_be_bytes(l4[2..4].try_into().unwrap());
            let doff = (l4[12] >> 4) as usize * 4;
            if l4.len() < doff {
                return None;
            }
            Some((src, dst, sport, dport, l4[doff..].to_vec()))
        }
        17 => {
            let sport = u16::from_be_bytes(l4[0..2].try_into().unwrap());
            let dport = u16::from_be_bytes(l4[2..4].try_into().unwrap());
            Some((src, dst, sport, dport, l4[8..].to_vec()))
        }
        _ => None,
    }
}

pub fn tcp_stream(packets: &[Packet], src: &str, sport: u16, dst: &str, dport: u16) -> Vec<u8> {
    let mut out = Vec::new();
    for p in packets {
        if let Some((s, d, sp, dp, payload)) = parse_frame(&p.data) {
            if s == src && sp == sport && d == dst && dp == dport {
                out.extend_from_slice(&payload);
            }
        }
    }
    out
}

/// Parse pcapng SHB/IDB/EPB blocks.
pub fn parse_pcapng(data: &[u8]) -> Result<Vec<Packet>> {
    if data.len() < 12 || data[0..4] != [0x0a, 0x0d, 0x0d, 0x0a] {
        return Err(invalid("not pcapng"));
    }
    let bom = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let le = bom == 0x1a2b_3c4d;
    let rd_u32 = |b: &[u8], p: usize| -> u32 {
        if le {
            u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
        } else {
            u32::from_be_bytes(b[p..p + 4].try_into().unwrap())
        }
    };
    let mut pos = 0usize;
    let mut packets = Vec::new();
    while pos + 12 <= data.len() {
        let block_type = rd_u32(data, pos);
        let block_len = rd_u32(data, pos + 4) as usize;
        if block_len < 12 || pos + block_len > data.len() {
            break;
        }
        if block_type == 0x0000_0006 && block_len >= 32 {
            let captured = rd_u32(data, pos + 20) as usize;
            let ts_high = rd_u32(data, pos + 12);
            let ts_low = rd_u32(data, pos + 16);
            let data_start = pos + 28;
            if data_start + captured <= data.len() {
                packets.push(Packet {
                    ts_sec: ts_high,
                    ts_frac: ts_low,
                    data: data[data_start..data_start + captured].to_vec(),
                });
            }
        }
        pos += block_len;
    }
    Ok(packets)
}

/// Dispatch on magic: classic pcap or pcapng.
pub fn parse_any(data: &[u8]) -> Result<Vec<Packet>> {
    if data.len() >= 4 && data[0..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
        parse_pcapng(data)
    } else {
        parse_packets(data)
    }
}

/// USB HID keyboard decode: parse USBPcap headers, extract HID reports
/// from interrupt transfers, track key transitions, decode printable text.
pub fn usb_keyboard_decode(packets: &[Packet]) -> String {
    let mut out = String::new();
    let mut prev_keys: [u8; 6] = [0; 6];
    for p in packets {
        let d = &p.data;
        if d.len() < 27 {
            continue;
        }
        let hdr_len = u16::from_le_bytes(d[0..2].try_into().unwrap()) as usize;
        let transfer = d[22];
        let data_len = u32::from_le_bytes(d[23..27].try_into().unwrap()) as usize;
        if transfer != 1 || data_len < 8 || hdr_len + 8 > d.len() {
            continue;
        }
        let report = &d[hdr_len..hdr_len + 8];
        let keys = &report[2..8];
        let modifier = report[0];
        for &k in keys {
            if k != 0 && !prev_keys.contains(&k) && (0x04..=0x1d).contains(&k) {
                let ch = b'a' + (k - 0x04);
                if let Some(c) = char::from_u32(ch as u32) {
                    if modifier & 0x22 != 0 {
                        if let Some(up) = c.to_uppercase().next() {
                            out.push(up);
                        }
                    } else {
                        out.push(c);
                    }
                }
            }
        }
        prev_keys.copy_from_slice(keys);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pcap(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        for (i, p) in packets.iter().enumerate() {
            v.extend_from_slice(&(1000 + i as u32).to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&(p.len() as u32).to_le_bytes());
            v.extend_from_slice(&(p.len() as u32).to_le_bytes());
            v.extend_from_slice(p);
        }
        v
    }

    fn tcp_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x00;
        let total = (20 + 20 + payload.len()) as u16;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&4444u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 5 << 4;
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn pcap_roundtrip_tcp() {
        let payload = b"GET /flag HTTP/1.1\r\nHost: x\r\n\r\n";
        let data = build_pcap(&[tcp_frame(payload), tcp_frame(b"second")]);
        let header = parse_header(&data).unwrap();
        assert_eq!(header.link_type, 1);
        let packets = parse_packets(&data).unwrap();
        assert_eq!(packets.len(), 2);
        let (src, dst, sport, dport, pl) = parse_frame(&packets[0].data).unwrap();
        assert_eq!(src, "10.0.0.1");
        assert_eq!((sport, dport), (4444, 80));
        assert_eq!(pl, payload.to_vec());
        let stream = tcp_stream(&packets, "10.0.0.1", 4444, "10.0.0.2", 80);
        assert!(stream.starts_with(b"GET"));
    }

    #[test]
    fn bad_magic_rejected() {
        assert!(parse_header(b"not a pcap at all........").is_err());
    }

    #[test]
    fn usb_keyboard_decodes_letters() {
        let make = |key: u8| {
            let mut pkt = vec![0u8; 35];
            pkt[0..2].copy_from_slice(&27u16.to_le_bytes());
            pkt[22] = 1;
            pkt[23..27].copy_from_slice(&8u32.to_le_bytes());
            pkt[29] = key;
            pkt
        };
        let packets: Vec<Packet> = vec![
            make(0x0b),
            make(0x00),
            make(0x08),
            make(0x00),
        ]
        .into_iter()
        .map(|data| Packet { ts_sec: 0, ts_frac: 0, data })
        .collect();
        let out = usb_keyboard_decode(&packets);
        assert_eq!(out, "he");
    }
}
