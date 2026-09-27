//! ctf-tube — pwntools-shaped Tube API over rnc's IO/encoding core.
//!
//! Reuses `rnc::encoding` (utf-8 / gbk / gb18030 / raw) for the text layer;
//! sockets are std::net with per-op timeouts (Windows-safe, no Unix-only
//! calls). Upstream provenance and the pwntools gap table live in
//! docs/UPSTREAM.md.
//!
//! Coverage: remote()/listen() TCP tubes and process() tubes, with
//! send/sendline/recv/recvuntil/recvn/recvall/clean and timeout control.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rnc::encoding::Mode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TubeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("tube closed by peer")]
    Closed,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TubeError>;

/// Byte-level IO abstraction shared by remote and process tubes.
pub trait TubeIo: Send {
    fn read_once(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write_all(&mut self, buf: &[u8]) -> Result<()>;
}

struct RemoteIo {
    stream: TcpStream,
}

impl TubeIo for RemoteIo {
    fn read_once(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.stream.read(buf)?)
    }
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.stream.write_all(buf)?;
        self.stream.flush()?;
        Ok(())
    }
}

struct ProcessIo {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
}

impl TubeIo for ProcessIo {
    fn read_once(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.stdout.read(buf)?)
    }
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.stdin.write_all(buf)?;
        self.stdin.flush()?;
        Ok(())
    }
}

impl Drop for ProcessIo {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Encoding selection reusing rnc's console-conversion core.
#[derive(Clone, Copy, Debug)]
pub enum TubeEncoding {
    Raw,
    Utf8,
    Gbk,
    Gb18030,
}

impl TubeEncoding {
    fn mode(self) -> Option<Mode> {
        match self {
            TubeEncoding::Raw => None,
            TubeEncoding::Utf8 => Some(Mode::Utf8),
            TubeEncoding::Gbk => Some(Mode::Gbk),
            TubeEncoding::Gb18030 => Some(Mode::Gb18030),
        }
    }

    /// Map to the shared rnc encoding mode (vocabulary reuse).
    fn rnc_mode(self) -> Option<rnc::encoding::Mode> {
        self.mode()
    }

    /// Decode received bytes to text (encoding_rs; same codec rnc uses).
    fn decode(&self, data: &[u8]) -> String {
        match self.mode() {
            None => String::from_utf8_lossy(data).into_owned(),
            Some(mode) => {
                let label = match mode {
                    Mode::Utf8 => "utf-8",
                    Mode::Gbk => "gbk",
                    Mode::Gb18030 => "gb18030",
                    Mode::Auto => "utf-8",
                };
                let enc = encoding_rs::Encoding::for_label(label.as_bytes())
                    .unwrap_or(encoding_rs::UTF_8);
                let (cow, _, _) = enc.decode(data);
                cow.into_owned()
            }
        }
    }
}

/// A connection tube: remote (TCP), listen (TCP), or process.
pub struct Tube {
    io: Box<dyn TubeIo + Send>,
    pub encoding: TubeEncoding,
    pub timeout: Duration,
    buffer: Vec<u8>,
}

impl Tube {
    fn wrap(io: Box<dyn TubeIo>, encoding: TubeEncoding, timeout: Duration) -> Self {
        Self { io, encoding, timeout, buffer: Vec::new() }
    }

    /// TCP connect to host:port (pwntools `remote`).
    pub fn remote(host: &str, port: u16) -> Result<Self> {
        let stream = TcpStream::connect((host, port))?;
        stream.set_nodelay(true).ok();
        Ok(Self::wrap(
            Box::new(RemoteIo { stream }),
            TubeEncoding::Raw,
            Duration::from_secs(10),
        ))
    }

    /// Accept one TCP connection on a listening port (pwntools `listen`).
    pub fn listen(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port))?;
        let (stream, _) = listener.accept()?;
        Ok(Self::wrap(
            Box::new(RemoteIo { stream }),
            TubeEncoding::Raw,
            Duration::from_secs(10),
        ))
    }

    /// Spawn a local process with piped stdio (pwntools `process`).
    pub fn process(program: &str, args: &[String]) -> Result<Self> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| TubeError::Other("no stdin".into()))?;
        let stdout = child.stdout.take().ok_or_else(|| TubeError::Other("no stdout".into()))?;
        Ok(Self::wrap(
            Box::new(ProcessIo { child, stdin, stdout }),
            TubeEncoding::Raw,
            Duration::from_secs(10),
        ))
    }

    pub fn set_encoding(&mut self, enc: TubeEncoding) {
        self.encoding = enc;
    }

    pub fn set_timeout(&mut self, d: Duration) {
        self.timeout = d;
    }

    /// Read more bytes into the internal buffer (one underlying read).
    fn pump(&mut self) -> Result<usize> {
        let mut chunk = [0u8; 65536];
        match self.io.read_once(&mut chunk) {
            Ok(0) => Err(TubeError::Closed),
            Ok(n) => {
                self.buffer.extend_from_slice(&chunk[..n]);
                Ok(n)
            }
            Err(TubeError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err(TubeError::Timeout(self.timeout))
            }
            Err(e) => Err(e),
        }
    }

    /// Send raw bytes.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        self.io.write_all(data)
    }

    /// Send text using the selected encoding (Raw falls back to UTF-8 bytes).
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        let bytes = match self.encoding.mode() {
            None | Some(Mode::Utf8) => text.as_bytes().to_vec(),
            Some(mode) => {
                let label = match mode {
                    Mode::Gbk => "gbk",
                    Mode::Gb18030 => "gb18030",
                    _ => "utf-8",
                };
                let enc = encoding_rs::Encoding::for_label(label.as_bytes())
                    .unwrap_or(encoding_rs::UTF_8);
                let (cow, _, _) = enc.encode(text);
                cow.into_owned()
            }
        };
        self.send(&bytes)
    }

    /// send + b"\n"
    pub fn sendline(&mut self, data: &[u8]) -> Result<()> {
        self.send(data)?;
        self.send(b"\n")
    }

    /// Receive everything currently available, waiting up to `timeout`.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let deadline = Instant::now() + self.timeout;
        loop {
            if !self.buffer.is_empty() {
                return Ok(std::mem::take(&mut self.buffer));
            }
            if Instant::now() >= deadline {
                return Err(TubeError::Timeout(self.timeout));
            }
            // poll with a short sleep; per-op timeouts live on the socket layer
            match self.pump() {
                Ok(_) => {}
                Err(TubeError::Timeout(_)) | Err(TubeError::Closed) => {
                    if self.buffer.is_empty() {
                        return Err(TubeError::Timeout(self.timeout));
                    }
                    return Ok(std::mem::take(&mut self.buffer));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Receive exactly `n` bytes.
    pub fn recvn(&mut self, n: usize) -> Result<Vec<u8>> {
        let deadline = Instant::now() + self.timeout;
        while self.buffer.len() < n {
            if Instant::now() >= deadline {
                return Err(TubeError::Timeout(self.timeout));
            }
            self.pump()?;
        }
        Ok(self.buffer.drain(..n).collect())
    }

    /// Receive until `delim` appears (delimiter included).
    pub fn recvuntil(&mut self, delim: &[u8]) -> Result<Vec<u8>> {
        if delim.is_empty() {
            return Err(TubeError::Other("empty delimiter".into()));
        }
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Some(pos) = find_subsequence(&self.buffer, delim) {
                return Ok(self.buffer.drain(..pos + delim.len()).collect());
            }
            if Instant::now() >= deadline {
                return Err(TubeError::Timeout(self.timeout));
            }
            self.pump()?;
        }
    }

    /// Receive until the peer closes (bounded by timeout).
    pub fn recvall(&mut self) -> Result<Vec<u8>> {
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.pump() {
                Ok(_) => {}
                Err(TubeError::Closed) => return Ok(std::mem::take(&mut self.buffer)),
                Err(TubeError::Timeout(_)) => return Ok(std::mem::take(&mut self.buffer)),
                Err(e) => return Err(e),
            }
            if Instant::now() >= deadline {
                return Ok(std::mem::take(&mut self.buffer));
            }
        }
    }

    /// Drop buffered bytes (pwntools `clean`).
    pub fn clean(&mut self) {
        self.buffer.clear();
    }

    /// Receive decoded text (respecting the tube encoding).
    pub fn recv_text(&mut self) -> Result<String> {
        let data = self.recv()?;
        Ok(self.encoding.decode(&data))
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn echo_server(port: u16, sentinel: &'static str) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
            for conn in listener.incoming() {
                let mut conn = conn.unwrap();
                let mut buf = [0u8; 4096];
                let n = conn.read(&mut buf).unwrap_or(0);
                let _ = conn.write_all(&buf[..n]);
                let _ = conn.write_all(sentinel.as_bytes());
                break;
            }
        })
    }

    #[test]
    fn remote_send_recvuntil() {
        echo_server(39701, "END>");
        thread::sleep(Duration::from_millis(150));
        let mut tube = Tube::remote("127.0.0.1", 39701).unwrap();
        tube.sendline(b"hello-tube").unwrap();
        let got = tube.recvuntil(b"END>").unwrap();
        assert_eq!(got, b"hello-tube\nEND>");
    }

    #[test]
    fn recvn_exact() {
        echo_server(39702, "ABCDEFGH");
        thread::sleep(Duration::from_millis(150));
        let mut tube = Tube::remote("127.0.0.1", 39702).unwrap();
        tube.send(b"x").unwrap();
        let got = tube.recvn(9).unwrap();
        assert_eq!(got, b"xABCDEFGH");
    }

    #[test]
    fn listen_accepts_connection() {
        let server = thread::spawn(|| {
            let listener = TcpListener::bind(("127.0.0.1", 39703)).unwrap();
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(b"welcome").unwrap();
        });
        // give the listener a moment, then connect from another thread
        thread::sleep(Duration::from_millis(150));
        let client = thread::spawn(|| {
            let mut t = Tube::remote("127.0.0.1", 39703).unwrap();
            t.set_timeout(Duration::from_secs(3));
            t.recv().unwrap()
        });
        server.join().unwrap();
        let got = client.join().unwrap();
        assert_eq!(got, b"welcome");
    }

    #[test]
    fn process_tube_roundtrip() {
        // cmd.exe exists on every Windows host we target
        let mut tube = Tube::process("cmd", &["/C".into(), "echo tube-smoke".into()]).unwrap();
        tube.set_timeout(Duration::from_secs(5));
        let got = tube.recvall().unwrap();
        let text = String::from_utf8_lossy(&got);
        assert!(text.contains("tube-smoke"), "got: {text}");
    }

    #[test]
    fn recv_times_out_on_silent_peer() {
        let listener = TcpListener::bind(("127.0.0.1", 39704)).unwrap();
        thread::spawn(move || {
            let _conn = listener.accept().unwrap();
            thread::sleep(Duration::from_secs(2));
        });
        thread::sleep(Duration::from_millis(150));
        let mut tube = Tube::remote("127.0.0.1", 39704).unwrap();
        tube.set_timeout(Duration::from_millis(300));
        assert!(matches!(tube.recv(), Err(TubeError::Timeout(_))));
    }

    #[test]
    fn encoding_decode_gbk() {
        // "中文" in GBK bytes: d6 d0 ce c4
        let enc = TubeEncoding::Gbk;
        let decoded = enc.decode(&[0xd6, 0xd0, 0xce, 0xc4]);
        assert_eq!(decoded, "中文");
    }
}
