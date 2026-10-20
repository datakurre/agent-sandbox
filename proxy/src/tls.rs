use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::Mutex;

const LEAF_CACHE_MAX: usize = 256;
const HTTP1_ALPN: &[u8] = b"http/1.1";

#[derive(Clone, Debug)]
pub struct IssuedLeaf {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

#[derive(Debug)]
struct LeafCache {
    by_host: HashMap<String, IssuedLeaf>,
    order: VecDeque<String>,
}

pub struct SessionCa {
    cert: Certificate,
    key_pair: KeyPair,
    leaves: Mutex<LeafCache>,
}

impl SessionCa {
    pub fn generate() -> Result<Self, String> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "agent-sandbox session proxy CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let key_pair = KeyPair::generate().map_err(|e| format!("key generation failed: {}", e))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("CA self-sign failed: {}", e))?;

        Ok(Self {
            cert,
            key_pair,
            leaves: Mutex::new(LeafCache {
                by_host: HashMap::new(),
                order: VecDeque::new(),
            }),
        })
    }

    pub fn public_cert_pem(&self) -> String {
        self.cert.pem()
    }

    pub fn write_public_cert_pem(&self, path: &str) -> Result<(), String> {
        fs::write(path, self.public_cert_pem()).map_err(|e| format!("cannot write {}: {}", path, e))
    }

    pub fn issue_leaf(&self, host: &str) -> Result<IssuedLeaf, String> {
        {
            let cache = self.leaves.lock().map_err(|_| "leaf cache lock poisoned")?;
            if let Some(existing) = cache.by_host.get(host) {
                return Ok(existing.clone());
            }
        }

        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("invalid SAN {:?}: {}", host, e))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let key_pair = KeyPair::generate().map_err(|e| format!("key generation failed: {}", e))?;
        let cert = params
            .signed_by(&key_pair, &self.cert, &self.key_pair)
            .map_err(|e| format!("leaf signing failed for {:?}: {}", host, e))?;

        let issued = IssuedLeaf {
            cert_der: cert.der().to_vec(),
            key_der: key_pair.serialize_der(),
        };

        let mut cache = self.leaves.lock().map_err(|_| "leaf cache lock poisoned")?;
        if !cache.by_host.contains_key(host) {
            if cache.by_host.len() >= LEAF_CACHE_MAX {
                if let Some(oldest) = cache.order.pop_front() {
                    cache.by_host.remove(&oldest);
                }
            }
            cache.order.push_back(host.to_string());
            cache.by_host.insert(host.to_string(), issued.clone());
        }
        Ok(issued)
    }
}

pub fn terminate<S>(
    stream: S,
    leaf: &IssuedLeaf,
) -> Result<StreamOwned<ServerConnection, S>, String>
where
    S: Read + Write,
{
    let certs = vec![CertificateDer::from(leaf.cert_der.clone())];
    let key = PrivateKeyDer::try_from(leaf.key_der.clone())
        .map_err(|e| format!("leaf key is not valid DER: {}", e))?;
    // The sandbox's own clients all speak 1.3; only the upstream leg needs the
    // `tls12` feature, so this side stays as narrow as it was without it.
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("leaf cert config failed: {}", e))?;
    config.alpn_protocols = vec![HTTP1_ALPN.to_vec()];
    let conn = ServerConnection::new(Arc::new(config))
        .map_err(|e| format!("TLS acceptor init failed: {}", e))?;
    Ok(StreamOwned::new(conn, stream))
}

pub fn originate(
    stream: std::net::TcpStream,
    host: &str,
) -> Result<StreamOwned<ClientConnection, std::net::TcpStream>, String> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid upstream TLS server name {:?}", host))?;
    let conn = ClientConnection::new(Arc::new(upstream_config(roots)), server_name)
        .map_err(|e| format!("TLS client init failed: {}", e))?;
    Ok(StreamOwned::new(conn, stream))
}

/// The upstream leg offers TLS 1.3 and 1.2: the origin, not the sandbox
/// client, decides what this side can speak, and registry.npmjs.org answers a
/// 1.3-only ClientHello with a `protocol_version` alert. This relies on the
/// rustls `tls12` feature, which `default-features = false` leaves out.
fn upstream_config(roots: RootCertStore) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![HTTP1_ALPN.to_vec()];
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ca_certificate_is_pem_encoded() {
        let ca = SessionCa::generate().expect("generate");
        let pem = ca.public_cert_pem();
        assert!(pem.contains("BEGIN CERTIFICATE"), "{pem}");
    }

    #[test]
    fn leaf_issue_is_cached_by_host() {
        let ca = SessionCa::generate().expect("generate");
        let first = ca.issue_leaf("api.example.com").expect("first");
        let second = ca.issue_leaf("api.example.com").expect("second");
        assert_eq!(first.cert_der, second.cert_der);
        assert_eq!(first.key_der, second.key_der);
    }

    #[test]
    fn cache_is_bounded() {
        let ca = SessionCa::generate().expect("generate");
        let mut seen = HashSet::new();
        for i in 0..(LEAF_CACHE_MAX + 8) {
            let host = format!("{}.example.com", i);
            let leaf = ca.issue_leaf(&host).expect("issue");
            seen.insert(leaf.cert_der);
        }
        assert!(seen.len() >= LEAF_CACHE_MAX);
    }

    fn handshake_with_upstream_limited_to(
        version: &'static rustls::SupportedProtocolVersion,
    ) -> Result<rustls::ProtocolVersion, String> {
        let ca = SessionCa::generate().expect("generate");
        let leaf = ca.issue_leaf("upstream.test").expect("leaf");
        let server_config = ServerConfig::builder_with_protocol_versions(&[version])
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.cert_der.clone())],
                PrivateKeyDer::try_from(leaf.key_der.clone()).expect("key"),
            )
            .expect("server config");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accept");
            let conn = ServerConnection::new(Arc::new(server_config)).expect("server conn");
            let mut tls = StreamOwned::new(conn, sock);
            // The client side reports the outcome; this only has to answer.
            let _ = tls.conn.complete_io(&mut tls.sock);
        });

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.cert.der().to_vec()))
            .expect("root");
        let sock = std::net::TcpStream::connect(addr).expect("connect");
        let conn = ClientConnection::new(
            Arc::new(upstream_config(roots)),
            ServerName::try_from("upstream.test").unwrap(),
        )
        .expect("client conn");
        let mut tls = StreamOwned::new(conn, sock);
        let result = tls
            .conn
            .complete_io(&mut tls.sock)
            .map_err(|e| e.to_string())
            .map(|_| tls.conn.protocol_version().expect("negotiated version"));
        drop(tls);
        server.join().expect("server thread");
        result
    }

    #[test]
    fn upstream_handshake_falls_back_to_tls12() {
        let version = handshake_with_upstream_limited_to(&rustls::version::TLS12)
            .expect("a TLS 1.2-only origin must be reachable");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn upstream_handshake_prefers_tls13() {
        let version = handshake_with_upstream_limited_to(&rustls::version::TLS13)
            .expect("a TLS 1.3 origin must be reachable");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
    }
}
