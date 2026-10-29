use agent_sandbox_proxy::dns::{self, ResolveRequest, ResolveResponse};
use std::fs;
use std::io::{self, ErrorKind};
use std::net::ToSocketAddrs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const RESOLVER_WORKERS: usize = 16;
const REQUEST_QUEUE_CAPACITY: usize = 32;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct HostDnsRelay {
    socket_path: PathBuf,
    stopping: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl HostDnsRelay {
    pub fn start(socket_path: &Path) -> io::Result<Self> {
        let listener = UnixListener::bind(socket_path)?;
        if let Err(error) = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(socket_path);
            return Err(error);
        }
        if let Err(error) = listener.set_nonblocking(true) {
            let _ = fs::remove_file(socket_path);
            return Err(error);
        }

        let stopping = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker in 0..RESOLVER_WORKERS {
            let receiver = Arc::clone(&receiver);
            let worker_stopping = Arc::clone(&stopping);
            if let Err(error) = thread::Builder::new()
                .name(format!("agent-sandbox-dns-worker-{}", worker))
                .spawn(move || {
                    while !worker_stopping.load(Ordering::SeqCst) {
                        let request = match receiver
                            .lock()
                            .map(|receiver| receiver.recv_timeout(Duration::from_millis(100)))
                        {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(mpsc::RecvTimeoutError::Timeout)) => continue,
                            Ok(Err(mpsc::RecvTimeoutError::Disconnected)) | Err(_) => break,
                        };
                        handle_request(request);
                    }
                })
            {
                stopping.store(true, Ordering::SeqCst);
                let _ = fs::remove_file(socket_path);
                return Err(error);
            }
        }

        let thread_stopping = Arc::clone(&stopping);
        let accept_thread = match thread::Builder::new()
            .name("agent-sandbox-host-dns".to_string())
            .spawn(move || serve(listener, sender, thread_stopping))
        {
            Ok(thread) => thread,
            Err(error) => {
                stopping.store(true, Ordering::SeqCst);
                let _ = fs::remove_file(socket_path);
                return Err(error);
            }
        };

        Ok(Self {
            socket_path: socket_path.to_path_buf(),
            stopping,
            accept_thread: Some(accept_thread),
        })
    }
}

impl Drop for HostDnsRelay {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket_path);
    }
}

fn serve(listener: UnixListener, sender: mpsc::SyncSender<UnixStream>, stopping: Arc<AtomicBool>) {
    while !stopping.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut stream = stream;
                loop {
                    if stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    match sender.try_send(stream) {
                        Ok(()) => break,
                        Err(mpsc::TrySendError::Full(returned)) => {
                            stream = returned;
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(mpsc::TrySendError::Disconnected(_)) => return,
                    }
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                eprintln!("agent-sandbox: host DNS relay accept failed: {}", error);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn handle_request(mut stream: UnixStream) {
    if stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err() {
        return;
    }
    let request: ResolveRequest = match dns::read_frame_with_timeout(&mut stream, READ_TIMEOUT) {
        Ok(request) => request,
        Err(_) => return,
    };
    let response = resolve(request);
    let _ = dns::write_frame(&mut stream, &response);
}

fn resolve(request: ResolveRequest) -> ResolveResponse {
    if request.host.is_empty()
        || request.host.len() > 253
        || request
            .host
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return ResolveResponse {
            addresses: Vec::new(),
            error: Some("invalid hostname".to_string()),
        };
    }

    match (request.host.as_str(), request.port).to_socket_addrs() {
        Ok(addresses) => {
            let mut addresses = addresses.collect::<Vec<_>>();
            addresses.dedup();
            if addresses.is_empty() {
                ResolveResponse {
                    addresses,
                    error: Some("host resolver returned no addresses".to_string()),
                }
            } else {
                ResolveResponse {
                    addresses,
                    error: None,
                }
            }
        }
        Err(error) => ResolveResponse {
            addresses: Vec::new(),
            error: Some(error.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_sandbox_proxy::dns::resolve_via_host;
    use tempfile::tempdir;

    #[test]
    fn resolves_using_the_host_resolver_and_releases_the_socket() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("host-resolver.sock");
        let relay = HostDnsRelay::start(&path).unwrap();

        let addresses = resolve_via_host(&path, "localhost", 443).unwrap();
        assert!(addresses.iter().any(|address| address.ip().is_loopback()));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        drop(relay);
        assert!(!path.exists());
    }

    #[test]
    fn sends_resolution_errors_back_to_the_client() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("host-resolver.sock");
        let relay = HostDnsRelay::start(&path).unwrap();
        let error = resolve_via_host(&path, "invalid hostname", 443).unwrap_err();
        assert!(error.to_string().contains("invalid hostname"));
        drop(relay);
    }

    #[test]
    fn rejects_invalid_hostnames_without_querying_the_resolver() {
        let invalid = vec![
            "".to_string(),
            "has whitespace".to_string(),
            "x".repeat(254),
        ];
        for host in invalid {
            let response = resolve(ResolveRequest { host, port: 443 });
            assert!(response.addresses.is_empty());
            assert_eq!(response.error.as_deref(), Some("invalid hostname"));
        }
    }
}
