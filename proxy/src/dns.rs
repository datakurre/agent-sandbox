use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub const SOCKET_ENV: &str = "AGENT_SANDBOX_DNS_SOCKET";
pub const SOCKET_NAME: &str = "host-resolver.sock";
const MAX_FRAME_SIZE: usize = 4096;
pub const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize, Serialize)]
pub struct ResolveRequest {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResolveResponse {
    pub addresses: Vec<SocketAddr>,
    pub error: Option<String>,
}

pub fn read_frame<R: Read, T: DeserializeOwned>(reader: R) -> io::Result<T> {
    let mut frame = Vec::new();
    let mut reader = BufReader::new(reader.take((MAX_FRAME_SIZE + 1) as u64));
    let read = reader.read_until(b'\n', &mut frame)?;
    if read == 0 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "empty DNS relay frame",
        ));
    }
    if frame.len() > MAX_FRAME_SIZE || frame.last() != Some(&b'\n') {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid DNS relay frame length",
        ));
    }
    serde_json::from_slice(&frame[..frame.len() - 1])
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
}

pub fn read_frame_with_timeout<T: DeserializeOwned>(
    stream: &mut UnixStream,
    timeout: Duration,
) -> io::Result<T> {
    let mut reader = DeadlineReader {
        stream,
        deadline: Instant::now() + timeout,
    };
    read_frame(&mut reader)
}

pub fn write_frame<W: Write, T: Serialize>(mut writer: W, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    writer.write_all(b"\n")
}

struct DeadlineReader<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "DNS relay frame deadline expired",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buf)
    }
}

pub fn resolve_via_host(socket_path: &Path, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    resolve_via_host_with_timeout(socket_path, host, port, SOCKET_TIMEOUT)
}

pub fn resolve_via_host_with_timeout(
    socket_path: &Path,
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<Vec<SocketAddr>> {
    if timeout.is_zero() {
        return Err(io::Error::new(
            ErrorKind::TimedOut,
            "host resolver deadline expired",
        ));
    }
    let deadline = Instant::now() + timeout;
    let mut stream = UnixStream::connect(socket_path)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            ErrorKind::TimedOut,
            "host resolver deadline expired",
        ));
    }
    stream.set_write_timeout(Some(remaining))?;
    write_frame(
        &mut stream,
        &ResolveRequest {
            host: host.to_string(),
            port,
        },
    )?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let response: ResolveResponse = read_frame_with_timeout(&mut stream, remaining)?;
    match response.error {
        Some(error) => Err(io::Error::other(error)),
        None if response.addresses.is_empty() => Err(io::Error::new(
            ErrorKind::NotFound,
            "host resolver returned no addresses",
        )),
        None => Ok(response.addresses),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_round_trip() {
        let expected = ResolveRequest {
            host: "example.com".to_string(),
            port: 443,
        };
        let mut frame = Vec::new();
        write_frame(&mut frame, &expected).unwrap();
        let actual: ResolveRequest = read_frame(Cursor::new(frame)).unwrap();
        assert_eq!(actual.host, expected.host);
        assert_eq!(actual.port, expected.port);
    }

    #[test]
    fn rejects_frames_without_a_terminating_newline() {
        let error = read_frame::<_, ResolveRequest>(Cursor::new(b"{\"host\":\"example.com\"}"))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_oversized_frames() {
        let frame = vec![b'a'; MAX_FRAME_SIZE + 1];
        let error = read_frame::<_, ResolveRequest>(Cursor::new(frame)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn resolver_timeout_bounds_a_slow_host_response() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host-resolver.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _: ResolveRequest = read_frame(&mut stream).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let response = ResolveResponse {
                addresses: vec!["93.184.216.34:443".parse().unwrap()],
                error: None,
            };
            let _ = write_frame(&mut stream, &response);
        });

        let error =
            resolve_via_host_with_timeout(&path, "example.com", 443, Duration::from_millis(10))
                .unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::TimedOut | ErrorKind::WouldBlock
        ));
        server.join().unwrap();
    }

    #[test]
    fn frame_read_timeout_is_total_not_reset_for_each_byte() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            client.write_all(b"{").unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let _ = client.write_all(b"}\n");
        });

        let error =
            read_frame_with_timeout::<ResolveRequest>(&mut server, Duration::from_millis(10))
                .unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::TimedOut | ErrorKind::WouldBlock
        ));
        sender.join().unwrap();
    }
}
