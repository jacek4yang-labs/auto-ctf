//! Network protocol helpers on top of the pcap packet stream:
//! HTTP request/response splitting and DNS message parsing.
//!
//! Traffic-misc challenges hide flags in HTTP bodies, DNS TXT records, or
//! covert channels in the transaction ID — these helpers turn raw TCP
//! streams / UDP payloads into structured views.
//!
//! Capability coverage: domain 9 (net forensics).

/// parsed HTTP message (request or response — unified view)
#[derive(Debug, Clone, Default)]
pub struct HttpMessage {
    pub is_response: bool,
    /// request: "GET /x HTTP/1.1"; response: "HTTP/1.1 200 OK"
    pub start_line: String,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpMessage {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// parse one HTTP message from the head of `data`; returns (message, consumed)
pub fn parse_http(data: &[u8]) -> Option<(HttpMessage, usize)> {
    let sep = find_subslice(data, b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&data[..sep]).into_owned();
    let mut lines = head.split("\r\n");
    let start = lines.next()?.to_string();
    let mut msg = HttpMessage::default();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    if start.starts_with("HTTP/") {
        msg.is_response = true;
        msg.status = start.split_whitespace().nth(1)?.parse().ok();
    } else {
        let mut it = start.split_whitespace();
        msg.method = it.next()?.to_string();
        msg.path = it.next()?.to_string();
    }
    msg.start_line = start;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().ok();
            }
            if k.eq_ignore_ascii_case("transfer-encoding") && v.to_lowercase().contains("chunked") {
                chunked = true;
            }
            msg.headers.push((k, v));
        }
    }
    let mut pos = sep + 4;
    if chunked {
        // chunked body: [size hex]\r\n[data]\r\n ... 0\r\n[\r\n]
        let mut body = Vec::new();
        loop {
            let line_end = find_subslice(&data[pos..], b"\r\n")? + pos;
            let size_str = String::from_utf8_lossy(&data[pos..line_end]);
            let size = usize::from_str_radix(size_str.trim().split(';').next()?.trim(), 16).ok()?;
            pos = line_end + 2;
            if size == 0 {
                break;
            }
            body.extend_from_slice(data.get(pos..pos + size)?);
            pos += size + 2; // skip chunk data + trailing CRLF
        }
        msg.body = body;
        pos += 2; // final CRLF
    } else {
        let len = content_length.unwrap_or(data.len().saturating_sub(pos));
        let end = (pos + len).min(data.len());
        msg.body = data[pos..end].to_vec();
        pos = end;
    }
    Some((msg, pos))
}

/// split a TCP stream into consecutive HTTP messages
pub fn parse_http_stream(data: &[u8]) -> Vec<HttpMessage> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        match parse_http(&data[pos..]) {
            Some((m, used)) if used > 0 => {
                out.push(m);
                pos += used;
            }
            _ => break,
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, Default)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub is_response: bool,
    pub questions: Vec<String>,
    pub answers: Vec<DnsRecord>,
}

fn dns_read_name(d: &[u8], mut pos: usize, depth: u32) -> Option<(String, usize)> {
    if depth > 16 {
        return None;
    }
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_pos = pos;
    loop {
        let len = *d.get(pos)?;
        if len & 0xC0 == 0xC0 {
            // compression pointer
            let ptr = ((len & 0x3F) as usize) << 8 | *d.get(pos + 1)? as usize;
            if !jumped {
                end_pos = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }
        let label = String::from_utf8_lossy(d.get(pos + 1..pos + 1 + len as usize)?).into_owned();
        labels.push(label);
        pos += 1 + len as usize;
    }
    Some((labels.join("."), end_pos))
}

/// parse a DNS message from a UDP payload (without the UDP header)
pub fn parse_dns(data: &[u8]) -> Option<DnsMessage> {
    if data.len() < 12 {
        return None;
    }
    let mut msg = DnsMessage {
        transaction_id: u16::from_be_bytes(data[0..2].try_into().unwrap()),
        is_response: data[2] & 0x80 != 0,
        ..Default::default()
    };
    let qd = u16::from_be_bytes(data[4..6].try_into().unwrap());
    let an = u16::from_be_bytes(data[6..8].try_into().unwrap()) as usize;
    let mut pos = 12usize;
    for _ in 0..qd {
        let (name, used) = dns_read_name(data, pos, 0)?;
        msg.questions.push(name);
        pos = used + 4; // qtype + qclass
    }
    for _ in 0..an {
        let (name, used) = dns_read_name(data, pos, 0)?;
        pos = used;
        let rtype = u16::from_be_bytes(data.get(pos..pos + 2)?.try_into().unwrap());
        let ttl = u32::from_be_bytes(data.get(pos + 4..pos + 8)?.try_into().unwrap());
        let rdlen = u16::from_be_bytes(data.get(pos + 8..pos + 10)?.try_into().unwrap()) as usize;
        let rdata = data.get(pos + 10..pos + 10 + rdlen)?;
        let data_str = match rtype {
            1 => rdata.chunks_exact(4).map(|b| b.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".")).collect::<Vec<_>>().join(","),
            28 => rdata.chunks_exact(16).map(|b| b.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(":")).collect::<Vec<_>>().join(","),
            2 | 5 | 12 => dns_read_name(data, pos + 10, 0).map(|(n, _)| n).unwrap_or_default(),
            16 => {
                // TXT: len-prefixed strings
                let mut parts = Vec::new();
                let mut p = 0usize;
                while p < rdata.len() {
                    let l = rdata[p] as usize;
                    if p + 1 + l > rdata.len() {
                        break;
                    }
                    parts.push(String::from_utf8_lossy(&rdata[p + 1..p + 1 + l]).into_owned());
                    p += 1 + l;
                }
                parts.join("|")
            }
            _ => rdata.iter().map(|b| format!("{:02x}", b)).collect(),
        };
        msg.answers.push(DnsRecord { name, rtype, ttl, data: data_str });
        pos += 10 + rdlen;
    }
    Some(msg)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_with_body() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let (m, used) = parse_http(raw).unwrap();
        assert_eq!(m.method, "POST");
        assert_eq!(m.path, "/upload");
        assert_eq!(m.body, b"hello");
        assert_eq!(used, raw.len() - 5);
        assert_eq!(m.header("host"), Some("x"));
    }

    #[test]
    fn http_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nflag\r\n0\r\n\r\n";
        let (m, _) = parse_http(raw).unwrap();
        assert!(m.is_response);
        assert_eq!(m.status, Some(200));
        assert_eq!(m.body, b"flag");
    }

    #[test]
    fn http_stream_splits_messages() {
        let r1 = b"GET /a HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let r2 = b"GET /b HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let msgs = parse_http_stream(&[r1.as_slice(), r2.as_slice()].concat());
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[1].path, "/b");
    }

    #[test]
    fn dns_query_and_txt_answer() {
        // hand-built query: id 0x1234, rd=1, 1 question example.com A
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend(b"\x07example\x03com\x00");
        q.extend([0, 1, 0, 1]); // A, IN
        let m = parse_dns(&q).unwrap();
        assert_eq!(m.transaction_id, 0x1234);
        assert!(!m.is_response);
        assert_eq!(m.questions[0], "example.com");

        // response with TXT answer carrying a flag
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.extend(b"\x07example\x03com\x00");
        r.extend([0, 16, 0, 1]); // TXT, IN
        r.extend([0xC0, 0x0C]); // name pointer
        r.extend([0, 16, 0, 1]); // type TXT, class IN
        r.extend([0, 0, 0, 60]); // ttl
        let txt = b"flag{dns_exfil}";
        r.extend(((txt.len() + 1) as u16).to_be_bytes()); // rdlen
        r.extend([txt.len() as u8]); // TXT string length prefix
        r.extend(txt);
        let m = parse_dns(&r).unwrap();
        assert!(m.is_response);
        assert_eq!(m.answers.len(), 1);
        assert_eq!(m.answers[0].data, "flag{dns_exfil}");
    }
}
