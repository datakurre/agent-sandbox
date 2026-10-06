//! The `--host-loopback-port` bridge: a TCP port on the sandbox's loopback
//! that reaches a TCP port on the host's, carried over a unix socket in a
//! directory the launcher mounts at `/run/agent-sandbox-host`.
//!
//! The sandbox owns the socket and the host dials it -- not the other way
//! round. On an enforcing SELinux host a `container_t` process may not
//! `connectto` a socket a host process listens on, and no relabel changes
//! that: the check is between the two processes' domains, not the file's
//! label. A host process connecting to a socket the container listens on is
//! the direction the default policy allows.
//!
//! Because the side that sees a new TCP client (the sandbox) is not the side
//! that can open a connection (the host), the host keeps a few idle
//! connections parked on the socket. The sandbox pairs each new client with
//! one of them and writes [`GO`]; only then does the host dial its own
//! loopback, so a service that speaks first (ssh, MySQL) is not handed a
//! connection nobody asked for.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// The byte the sandbox writes on a parked connection once a client is
/// waiting on the far end of it.
const GO: u8 = 1;

/// Idle connections the host keeps parked per mapping: how many clients can
/// arrive at once without waiting on the host to dial another.
const POOL: usize = 4;

/// How long a sandbox client waits for a parked connection before it is
/// dropped. Only reached when the launcher is gone or wedged.
const PAIR_TIMEOUT: Duration = Duration::from_secs(10);

/// The socket for sandbox port `port` inside `dir`.
pub fn socket_path(dir: &Path, port: u16) -> PathBuf {
    dir.join(format!("{}.sock", port))
}

/// Created next to a socket once the host has parked its first connection on
/// it, so a caller inside can wait for the bridge to be live rather than
/// guess. Absent means the host has not reached the socket.
pub fn ready_marker(dir: &Path, port: u16) -> PathBuf {
    dir.join(format!("{}.up", port))
}

/// What the sandbox-side bridge process says about each port on its stdout,
/// one line apiece, so the entrypoint can report failures before it execs the
/// command rather than let them surface later inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// The port is listening on both sides.
    Up(u16),
    /// The port could not be served, and why.
    Down(u16, String),
    /// Every port has been reported.  A terminator rather than EOF, because the
    /// bridge keeps running -- and keeps its stdout -- after it has spoken.
    Done,
}

impl Report {
    /// The line for one port's outcome.
    pub fn for_port(port: u16, outcome: &io::Result<()>) -> Report {
        match outcome {
            Ok(()) => Report::Up(port),
            Err(e) => Report::Down(port, e.to_string()),
        }
    }

    pub fn to_line(&self) -> String {
        match self {
            Report::Up(port) => format!("ok {}", port),
            Report::Down(port, why) => format!("err {} {}", port, why.replace('\n', " ")),
            Report::Done => "done".to_string(),
        }
    }

    pub fn parse(line: &str) -> Option<Report> {
        let mut words = line.trim_end().splitn(3, ' ');
        match (words.next()?, words.next(), words.next()) {
            ("done", None, None) => Some(Report::Done),
            ("ok", Some(port), None) => port.parse().ok().map(Report::Up),
            ("err", Some(port), why) => port
                .parse()
                .ok()
                .map(|port| Report::Down(port, why.unwrap_or_default().to_string())),
            _ => None,
        }
    }
}

/// Sandbox side, for one port: listen on `127.0.0.1:port` and on its socket in
/// `dir`, and serve both until the process exits.  Errors only if either
/// listener cannot be bound; the serving itself is on spawned threads.
pub fn bind_and_serve(dir: &Path, port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    serve_sandbox(dir, port, listener)
}

/// Copies both directions until each side closes, shutting the other's write
/// half as its own read side ends. Two threads, because CDP is long-lived and
/// full duplex and neither direction may wait on the other.
fn splice<A, B>(a: A, b: B)
where
    A: Read + Write + Send + 'static + TryCloneShutdown,
    B: Read + Write + Send + 'static + TryCloneShutdown,
{
    let (Ok(mut a_read), Ok(mut b_write)) = (a.try_clone_box(), b.try_clone_box()) else {
        return;
    };
    let forward = thread::spawn(move || {
        let _ = io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown_write();
    });
    let (mut b_read, mut a_write) = (b, a);
    let _ = io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown_write();
    let _ = forward.join();
}

trait TryCloneShutdown: Sized {
    fn try_clone_box(&self) -> io::Result<Self>;
    fn shutdown_write(&self) -> io::Result<()>;
}

impl TryCloneShutdown for TcpStream {
    fn try_clone_box(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

impl TryCloneShutdown for UnixStream {
    fn try_clone_box(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

/// Host side: keep [`POOL`] connections parked on `socket` for the life of
/// the process, and splice each one the sandbox claims to `127.0.0.1:host_port`.
///
/// The socket does not exist until the sandbox's entrypoint creates it, and
/// disappears if the sandbox goes away, so a failed connect is retried rather
/// than reported: it is the normal state before the container starts.
pub fn serve_host(socket: PathBuf, host_port: u16) {
    let (slot_tx, slot_rx) = mpsc::channel::<()>();
    for _ in 0..POOL {
        let _ = slot_tx.send(());
    }
    thread::spawn(move || {
        let mut reported_denial = false;
        for () in slot_rx.iter() {
            let parked = loop {
                match UnixStream::connect(&socket) {
                    Ok(stream) => break stream,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::PermissionDenied && !reported_denial {
                            reported_denial = true;
                            eprintln!(
                                "agent-sandbox: could not reach the sandbox's bridge for host port {}: {}",
                                host_port, e
                            );
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            };
            let slot_tx = slot_tx.clone();
            thread::spawn(move || {
                let mut parked = parked;
                let mut go = [0u8; 1];
                let claimed = matches!(parked.read(&mut go), Ok(1) if go[0] == GO);
                // Claimed or dead, this slot is free again: dial the next one.
                let _ = slot_tx.send(());
                if !claimed {
                    return;
                }
                match TcpStream::connect(("127.0.0.1", host_port)) {
                    Ok(upstream) => splice(parked, upstream),
                    Err(e) => eprintln!(
                        "agent-sandbox: host port {} is not answering: {}",
                        host_port, e
                    ),
                }
            });
        }
    });
}

/// Sandbox side: listen on `socket` for the host's parked connections and on
/// `listener` for clients, and pair them. Returns once both are being served;
/// the work happens on spawned threads.
pub fn serve_sandbox(dir: &Path, port: u16, listener: TcpListener) -> io::Result<()> {
    let socket = socket_path(dir, port);
    let _ = fs::remove_file(&socket);
    let parked_listener = UnixListener::bind(&socket)?;
    let marker = ready_marker(dir, port);

    let (parked_tx, parked_rx) = mpsc::channel::<UnixStream>();
    thread::spawn(move || {
        let mut marked = false;
        for stream in parked_listener.incoming().flatten() {
            if !marked {
                marked = true;
                let _ = fs::write(&marker, "");
            }
            if parked_tx.send(stream).is_err() {
                return;
            }
        }
    });

    thread::spawn(move || {
        // Said once: this process's stderr is the agent's terminal by now, and
        // a dead launcher would otherwise repeat it for every client.
        let mut reported = false;
        for client in listener.incoming().flatten() {
            // A parked connection whose host end has gone (the launcher was
            // restarted, or the pool turned over) fails the GO write; take
            // the next one.
            let paired = loop {
                match parked_rx.recv_timeout(PAIR_TIMEOUT) {
                    Ok(mut parked) => {
                        if parked.write_all(&[GO]).is_ok() {
                            break Some(parked);
                        }
                    }
                    Err(_) => break None,
                }
            };
            match paired {
                Some(parked) => {
                    thread::spawn(move || splice(client, parked));
                }
                None if !reported => {
                    reported = true;
                    eprintln!(
                        "agent-sandbox: no host connection for 127.0.0.1:{}; is the launcher still running?",
                        port
                    );
                }
                None => {}
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_server() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut write = stream.try_clone().unwrap();
                    let mut read = stream;
                    let _ = io::copy(&mut read, &mut write);
                });
            }
        });
        port
    }

    fn roundtrip(port: u16, message: &[u8]) -> Vec<u8> {
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.write_all(message).unwrap();
        let mut got = vec![0u8; message.len()];
        client.read_exact(&mut got).unwrap();
        got
    }

    #[test]
    fn a_report_survives_its_line() {
        for report in [
            Report::Up(9222),
            Report::Down(7419, "Address already in use (os error 98)".to_string()),
            Report::Done,
        ] {
            assert_eq!(Report::parse(&report.to_line()), Some(report));
        }
        assert_eq!(
            Report::parse(&Report::Down(1, "two\nlines".into()).to_line()),
            Some(Report::Down(1, "two lines".into()))
        );
        assert_eq!(Report::parse("err 5"), Some(Report::Down(5, String::new())));
        for garbage in ["", "ok", "ok x", "ok 1 2", "done 1", "hello 1"] {
            assert_eq!(Report::parse(garbage), None, "{:?}", garbage);
        }
    }

    #[test]
    fn a_port_already_taken_is_reported_not_hung_on() {
        let dir = tempfile::tempdir().unwrap();
        let taken = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = taken.local_addr().unwrap().port();

        let outcome = bind_and_serve(dir.path(), port);
        assert!(
            matches!(Report::for_port(port, &outcome), Report::Down(p, _) if p == port),
            "{:?}",
            outcome
        );
        assert!(!socket_path(dir.path(), port).exists(), "no socket for a dead port");
    }

    #[test]
    fn the_host_dials_in_and_carries_concurrent_clients() {
        let dir = tempfile::tempdir().unwrap();
        let host_port = echo_server();
        let sandbox_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let sandbox_port = sandbox_listener.local_addr().unwrap().port();

        // Host first, as in a real launch: it must wait for the socket.
        serve_host(socket_path(dir.path(), sandbox_port), host_port);
        thread::sleep(Duration::from_millis(150));
        serve_sandbox(dir.path(), sandbox_port, sandbox_listener).unwrap();

        // More clients than the pool holds, all at once.
        let clients: Vec<_> = (0..POOL * 3)
            .map(|i| {
                thread::spawn(move || {
                    let message = format!("hello {}", i).into_bytes();
                    assert_eq!(roundtrip(sandbox_port, &message), message);
                })
            })
            .collect();
        for client in clients {
            client.join().unwrap();
        }
        assert!(ready_marker(dir.path(), sandbox_port).exists());
    }

    #[test]
    fn a_server_that_speaks_first_is_not_dialled_before_a_client_arrives() {
        let dir = tempfile::tempdir().unwrap();
        let upstream = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let host_port = upstream.local_addr().unwrap().port();
        upstream.set_nonblocking(true).unwrap();
        let sandbox_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let sandbox_port = sandbox_listener.local_addr().unwrap().port();

        serve_sandbox(dir.path(), sandbox_port, sandbox_listener).unwrap();
        serve_host(socket_path(dir.path(), sandbox_port), host_port);
        let marker = ready_marker(dir.path(), sandbox_port);
        for _ in 0..50 {
            if marker.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(marker.exists(), "the host never parked a connection");
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            upstream.accept().map_err(|e| e.kind()).err(),
            Some(io::ErrorKind::WouldBlock),
            "parked connections must not reach the host service"
        );

        // A banner-first server: the client reads before it writes.
        let mut client = TcpStream::connect(("127.0.0.1", sandbox_port)).unwrap();
        upstream.set_nonblocking(false).unwrap();
        let (mut server, _) = upstream.accept().unwrap();
        server.write_all(b"SSH-2.0-test\r\n").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut banner = [0u8; 14];
        client.read_exact(&mut banner).unwrap();
        assert_eq!(&banner, b"SSH-2.0-test\r\n");
    }
}
