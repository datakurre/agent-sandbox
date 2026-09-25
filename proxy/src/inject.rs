use std::io::{self, ErrorKind, Read, Write};

const HEAD_MAX: usize = 64 * 1024;

fn read_head<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return if buf.is_empty() { Ok(None) } else { Ok(Some(buf)) },
            Ok(1) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    return Ok(Some(buf));
                }
                if buf.len() >= HEAD_MAX {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "request head exceeds limit",
                    ));
                }
            }
            Ok(_) => unreachable!("single-byte buffer"),
            Err(ref e) if e.kind() == ErrorKind::Interrupted || e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => continue,
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => {
                return if buf.is_empty() { Ok(None) } else { Ok(Some(buf)) };
            }
            Err(e) => return Err(e),
        }
    }
}

fn read_line_crlf<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return if line.is_empty() {
                    Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "unexpected EOF while reading line",
                    ))
                } else {
                    Ok(line)
                };
            }
            Ok(1) => {
                line.push(byte[0]);
                if line.ends_with(b"\r\n") {
                    return Ok(line);
                }
            }
            Ok(_) => unreachable!("single-byte buffer"),
            Err(ref e) if e.kind() == ErrorKind::Interrupted || e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => continue,
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => {
                return if line.is_empty() {
                    Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "unexpected EOF while reading line",
                    ))
                } else {
                    Ok(line)
                };
            }
            Err(e) => return Err(e),
        }
    }
}

/// RFC 9110 §5.6.2 `tchar`: the bytes a header field name may contain.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Validate the header block of a request or response head.
///
/// RFC 9112 §5.1 requires a server to reject whitespace between a header
/// field name and its colon, because a lenient recipient that instead
/// strips it can be made to see a header -- `Transfer-Encoding`, most
/// dangerously -- that this proxy's own line-oriented lookups
/// (`content_length`, `is_chunked`, ...) do not, letting a request smuggle a
/// second one past the L7 check in what this proxy treats as a body. This
/// walks the header block on the wire's own terms -- strictly `\r\n`
/// delimited, so a bare CR or LF inside a line (which would let the two
/// sides disagree about where a line ends) is caught rather than silently
/// accepted the way `str::lines` would -- and rejects anything RFC 9112
/// does not allow: an empty or non-`tchar` name (whitespace before the
/// colon included), obsolete line folding, or a line with no colon.
fn validate_head_lines(head: &str) -> io::Result<()> {
    let bad = |msg: &str| io::Error::new(ErrorKind::InvalidData, msg.to_string());
    let start = head
        .find("\r\n")
        .ok_or_else(|| bad("head is missing its request/status line terminator"))?;
    // `find` only locates the first true `\r\n`; a bare `\r` or `\n` earlier
    // in what should be the request/status line would otherwise sit inside
    // `head[..start]` unchecked, while `content_length`/`is_chunked`
    // (`str::lines()`-based) would still split on it as a line of its own --
    // the same disagreement between this validator and the framing logic
    // that a malformed header name further down is meant to close.
    if head[..start].contains('\r') || head[..start].contains('\n') {
        return Err(bad("stray CR or LF inside the request/status line"));
    }
    let mut rest = &head[start + 2..];
    loop {
        let idx = rest
            .find("\r\n")
            .ok_or_else(|| bad("head is missing the blank line terminating it"))?;
        let line = &rest[..idx];
        rest = &rest[idx + 2..];
        if line.is_empty() {
            return Ok(());
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(bad("obsolete header line folding is not allowed"));
        }
        if line.contains('\r') || line.contains('\n') {
            return Err(bad("stray CR or LF inside a header line"));
        }
        let Some((name, _value)) = line.split_once(':') else {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("header line has no colon: {:?}", line),
            ));
        };
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid header field name: {:?}", name),
            ));
        }
    }
}

fn content_length(head: &str) -> io::Result<Option<usize>> {
    let mut found: Option<usize> = None;
    for line in head.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value.trim().parse::<usize>().map_err(|_| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid Content-Length: {:?}", value.trim()),
                )
            })?;
            if let Some(prev) = found {
                if prev != parsed {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "conflicting Content-Length headers",
                    ));
                }
            }
            found = Some(parsed);
        }
    }
    Ok(found)
}

fn is_chunked(head: &str) -> bool {
    head.lines().skip(1).any(|line| {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            return false;
        }
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    })
}

/// The request target as an *origin server* must see it.
///
/// A client talking to a proxy sends absolute-form -- `GET http://h:8000/a
/// HTTP/1.1` -- and RFC 9112 §3.2.1 is explicit that the proxy converts it to
/// origin-form (`GET /a HTTP/1.1`) before forwarding, because absolute-form is
/// addressed to the proxy, not to the server.  Most servers tolerate being
/// handed the proxy's copy anyway, which is why this went unnoticed;
/// `python3 -m http.server` does not, and looks for a file literally named
/// `http:/h:8000/a`, which is a 404 nobody can explain.
///
/// `*` (OPTIONS), origin-form and CONNECT's authority-form are already what the
/// far end expects and are returned unchanged.
pub fn origin_form(target: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    if target == "*" || target.starts_with('/') {
        return Cow::Borrowed(target);
    }
    let Some(idx) = target.find("://") else {
        return Cow::Borrowed(target);
    };
    let rest = &target[idx + 3..];
    match rest.find(['/', '?', '#']) {
        // The common case: the path starts right there, so no copy is needed.
        Some(i) if rest.as_bytes()[i] == b'/' => Cow::Borrowed(&rest[i..]),
        // `http://h?q` has no path segment; origin-form still needs one.
        Some(i) => Cow::Owned(format!("/{}", &rest[i..])),
        None => Cow::Borrowed("/"),
    }
}

/// Rewrite a request head's target to origin-form, or `None` when it already is
/// one and the bytes can go out untouched.
///
/// Only the second token of the first line is replaced; every header, the
/// method and the version stay byte-identical, and the target's path and query
/// are copied across verbatim rather than taken from the normalized path the
/// L7 check uses -- that normalization exists to stop `/a/../b` reaching a rule
/// it does not match, and forwarding it would change what the origin serves.
/// A first line that is not exactly three space-separated tokens is left alone:
/// the request-smuggling checks own that case.
pub fn rewrite_request_target(head: &[u8]) -> Option<Vec<u8>> {
    let end = head.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&head[..end]).ok()?;
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || method == "CONNECT" {
        return None;
    }
    let origin = origin_form(target);
    if origin == target {
        return None;
    }
    let mut out = Vec::with_capacity(head.len());
    out.extend_from_slice(format!("{} {} {}", method, origin, version).as_bytes());
    out.extend_from_slice(&head[end..]);
    Some(out)
}

fn request_method(head: &str) -> io::Result<&str> {
    let request_line = head
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "request head is missing request line"))?;
    request_line
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "malformed request line"))
}

/// The request path as the L7/secret-route matcher must see it.
///
/// Percent-encoding is decoded (including `%2F`, since scoped npm package
/// names and GitLab-style project ids legitimately encode a `/` inside a
/// path segment), and matching runs against that decoded path. What is
/// rejected outright, rather than normalised the way an origin might, is any
/// path where normalising would matter: a `.` or `..` segment, an empty
/// (`//`) segment, a backslash, or a control byte. An origin server is free
/// to interpret `/admin//../public/x` differently than this proxy would
/// after normalising it, and matching a normalised copy against
/// `allow_route`/`secret_route` while forwarding the raw bytes
/// (`rewrite_request_target` copies the target verbatim) would let a request
/// scoped to one route land on another. Fail closed instead: an ambiguous
/// path never reaches the matcher or the origin.
fn request_path(head: &str) -> io::Result<String> {
    let request_line = head
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "request head is missing request line"))?;
    let mut parts = request_line.split_whitespace();
    parts.next(); // skip method
    let target = parts
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "request target is missing"))?;

    // Target could be absolute URI (http://host/path) or absolute path (/path)
    let path = if let Some(idx) = target.find("://") {
        let after_scheme = &target[idx + 3..];
        if let Some(path_idx) = after_scheme.find('/') {
            &after_scheme[path_idx..]
        } else {
            "/"
        }
    } else {
        target
    };
    // Strip query string and fragment: neither is inspected for ambiguity.
    let path = path.split('?').next().unwrap_or(path);
    let path = path.split('#').next().unwrap_or(path);

    // `%2F` is decoded like any other percent-encoding, not refused: origins
    // that route on the decoded path are common (an npm scoped package name
    // like `/@scope%2fname`, a GitLab-style project id like
    // `/api/v4/projects/group%2Fproject`), and the ambiguity that matters --
    // a path segment that resolves differently depending on whether `.`/`..`
    // are read before or after decoding -- is caught below regardless, since
    // the segment check runs on the fully decoded path. A backslash, whether
    // written literally or as `%5C`, decodes to the same byte either way, so
    // one check below catches both spellings.
    let decoded_bytes = percent_decode_bytes(path)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("invalid percent encoding: {}", e)))?;
    if decoded_bytes.iter().any(|&b| b < 0x20 || b == b'\\') {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "path contains a control byte or backslash",
        ));
    }
    let decoded = String::from_utf8(decoded_bytes)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "path is not valid UTF-8 after decoding"))?;

    let segments: Vec<&str> = decoded.split('/').collect();
    let last = segments.len().saturating_sub(1);
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            // A leading or trailing slash produces an empty segment too; only
            // an empty segment strictly between two others is an actual `//`.
            if i == 0 || i == last {
                continue;
            }
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "path contains an empty segment",
            ));
        }
        if *seg == "." || *seg == ".." {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "path contains a '.' or '..' segment",
            ));
        }
    }

    Ok(if decoded.is_empty() { "/".to_string() } else { decoded })
}

fn percent_decode_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| "invalid hex")?;
                let byte = u8::from_str_radix(hex, 16).map_err(|_| "invalid hex")?;
                out.push(byte);
                i += 3;
            } else {
                return Err("truncated percent encoding");
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn authority_host_port(authority: &str, default_port: u16) -> io::Result<(String, u16)> {
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    if authority.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidData, "authority is empty"));
    }

    let (host, port_text) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, rest)) = rest.split_once(']') else {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "malformed bracketed IPv6 authority",
            ));
        };
        let port = match rest.strip_prefix(':') {
            Some(port) if !port.is_empty() => Some(port),
            Some(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "authority port is empty",
                ))
            }
            None if rest.is_empty() => None,
            None => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "malformed bracketed authority",
                ))
            }
        };
        (host, port)
    } else if authority.matches(':').count() == 1 {
        let (host, port) = authority.rsplit_once(':').expect("one colon");
        if host.is_empty() || port.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "malformed authority",
            ));
        }
        (host, Some(port))
    } else {
        (authority, None)
    };

    let port = match port_text {
        Some(text) => text.parse::<u16>().map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid authority port: {:?}", text),
            )
        })?,
        None => default_port,
    };
    Ok((host.trim_end_matches('.').to_ascii_lowercase(), port))
}

fn request_target_authority(request_target: &str, default_port: u16) -> io::Result<Option<(String, u16)>> {
    let Some((scheme, rest)) = request_target.split_once("://") else {
        return Ok(None);
    };
    let scheme = scheme.to_ascii_lowercase();
    let scheme_default = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => default_port,
    };
    let authority = rest.split('/').next().unwrap_or("");
    authority_host_port(authority, scheme_default).map(Some)
}

fn host_header_authority(head: &str, default_port: u16) -> io::Result<Option<(String, u16)>> {
    let mut found: Option<(String, u16)> = None;
    for line in head.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            let parsed = authority_host_port(value.trim(), default_port)?;
            if let Some(prev) = &found {
                if prev != &parsed {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "conflicting Host headers",
                    ));
                }
            }
            found = Some(parsed);
        }
    }
    Ok(found)
}

fn validate_request_authority(
    head: &str,
    expected_host: &str,
    expected_port: u16,
) -> io::Result<()> {
    let request_line = head
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "request head is missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let _method = parts
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "malformed request line"))?;
    let target = parts
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "request target is missing"))?;

    let expected = (expected_host.trim_end_matches('.').to_ascii_lowercase(), expected_port);
    let target_authority = request_target_authority(target, expected_port)?;
    let host_authority = host_header_authority(head, expected_port)?;

    if let (Some(target), Some(host)) = (&target_authority, &host_authority) {
        if target != host {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "request target authority does not match Host",
            ));
        }
    }

    let effective = target_authority.or(host_authority).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "request is missing Host/authority for secret injection",
        )
    })?;

    if effective != expected {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "request authority {:?}:{} does not match secret target {:?}:{}",
                effective.0, effective.1, expected.0, expected.1
            ),
        ));
    }
    Ok(())
}

fn response_status_code(head: &str) -> io::Result<u16> {
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "response head is missing status line"))?;
    let mut parts = status_line.split_whitespace();
    let _http = parts
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "malformed status line"))?;
    let status = parts
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "status code is missing"))?;
    status.parse::<u16>().map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid status code: {:?}", status),
        )
    })
}

fn rewrite_head(head: &[u8], header_name: &str, header_value: &str) -> io::Result<Vec<u8>> {
    let head_str = std::str::from_utf8(head)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "request head is not valid UTF-8"))?;

    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidData, "request head is missing request line")
    })?;
    if request_line.split_whitespace().count() < 3 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "malformed HTTP request line",
        ));
    }

    let mut out = String::new();
    out.push_str(request_line);
    out.push_str("\r\n");
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, _value)) = line.split_once(':') else {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("malformed header line: {:?}", line),
            ));
        };
        if name.eq_ignore_ascii_case(header_name) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str(header_name);
    out.push_str(": ");
    out.push_str(header_value);
    out.push_str("\r\n\r\n");
    Ok(out.into_bytes())
}

fn copy_exact<R: Read, W: Write>(reader: &mut R, writer: &mut W, len: usize) -> io::Result<u64> {
    let mut left = len;
    let mut buf = [0u8; 16 * 1024];
    let mut copied = 0u64;
    while left > 0 {
        let chunk = left.min(buf.len());
        let mut chunk_left = chunk;
        let mut chunk_pos = 0;
        while chunk_left > 0 {
            match reader.read(&mut buf[chunk_pos..chunk_pos + chunk_left]) {
                Ok(0) => return Err(io::Error::new(ErrorKind::UnexpectedEof, "unexpected EOF in copy_exact")),
                Ok(n) => {
                    chunk_left -= n;
                    chunk_pos += n;
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted || e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => continue,
                Err(e) => return Err(e),
            }
        }
        writer.write_all(&buf[..chunk])?;
        left -= chunk;
        copied += chunk as u64;
    }
    Ok(copied)
}

fn copy_chunked_body<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> io::Result<u64> {
    let mut copied = 0u64;
    loop {
        let line = read_line_crlf(reader)?;
        copied += line.len() as u64;
        writer.write_all(&line)?;
        let line_text = std::str::from_utf8(&line)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "chunk size line is not UTF-8"))?;
        let line_text = line_text.trim_end_matches("\r\n");
        let size_text = line_text.split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_text, 16).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid chunk size: {:?}", size_text),
            )
        })?;
        if size == 0 {
            loop {
                let trailer = read_line_crlf(reader)?;
                copied += trailer.len() as u64;
                writer.write_all(&trailer)?;
                if trailer == b"\r\n" {
                    return Ok(copied);
                }
            }
        }
        copied += copy_exact(reader, writer, size + 2)?;
    }
}

fn copy_to_eof<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> io::Result<u64> {
    let mut buf = [0u8; 16 * 1024];
    let mut copied = 0u64;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(copied),
            Ok(n) => {
                writer.write_all(&buf[..n])?;
                copied += n as u64;
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted || e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => continue,
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(copied),
            Err(e) => return Err(e),
        }
    }
}

fn response_has_no_body(request_method: &str, status_code: u16) -> bool {
    request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || status_code == 204
        || status_code == 304
}

#[derive(Debug)]
pub struct HttpExchangeOutcome {
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub secret_missing: bool,
    /// The last response was `101 Switching Protocols`.  What follows on the
    /// connection (WebSocket frames, most commonly) is not HTTP, so this
    /// function stopped rather than trying to parse another request head out
    /// of it; the caller owns the two streams and should splice them
    /// byte-for-byte from here on.
    pub upgraded: bool,
}

#[derive(Debug)]
pub enum ProxyHttpError {
    L7Denied {
        method: String,
        path: String,
        reason: String,
    },
    Io {
        method: Option<String>,
        path: Option<String>,
        status: Option<u16>,
        secret_missing: bool,
        error: io::Error,
    },
}

impl std::fmt::Display for ProxyHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyHttpError::L7Denied { reason, .. } => write!(f, "L7 denied: {}", reason),
            ProxyHttpError::Io { error, .. } => write!(f, "{}", error),
        }
    }
}
impl std::error::Error for ProxyHttpError {}

/// Forward HTTP/1.1 request/response exchanges, evaluating L7 policy on each
/// request and injecting the secret the operator authorized *for that request*
/// -- host, method and path -- so it appears exactly once.
///
/// The per-request resolution is the point.  A keep-alive connection carries
/// many requests; resolving the binding once when the connection opened meant
/// a token authorized for `GET /user/repos` was also injected into every other
/// request the policy happened to allow on that host.
///
/// Returns `HttpExchangeOutcome` on successful parsing (up to EOF), or `ProxyHttpError`.
pub fn proxy_http1_with_injection<C: Read + Write, U: Read + Write>(
    client: &mut C,
    upstream: &mut U,
    expected_host: &str,
    expected_port: u16,
    shared: &std::sync::Arc<crate::Shared>,
) -> Result<HttpExchangeOutcome, ProxyHttpError> {
    let mut secret_missing = false;
    let mut up_bytes = 0u64;
    let mut down_bytes = 0u64;
    let mut last_method: Option<String> = None;
    let mut last_path: Option<String> = None;
    let mut last_status: Option<u16> = None;

    let mut io_loop = || -> io::Result<bool> {
        loop {
            let Some(request_head) = read_head(client)? else {
                return Ok(false);
            };
            let request_text = std::str::from_utf8(&request_head).map_err(|_| {
                io::Error::new(ErrorKind::InvalidData, "request head is not valid UTF-8")
            })?;
            if let Err(e) = validate_head_lines(request_text) {
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                return Err(e);
            }
            validate_request_authority(request_text, expected_host, expected_port)?;
            
            let has_cl = content_length(request_text)?.is_some();
            let has_te = is_chunked(request_text);
            if has_cl && has_te {
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                return Err(io::Error::new(ErrorKind::InvalidData, "request has both Content-Length and Transfer-Encoding"));
            }
            
            // Also check if Transfer-Encoding is something other than "chunked"
            if has_te {
                let te_valid = request_text.lines().skip(1).filter_map(|line| {
                    let line = line.trim_end_matches('\r');
                    if line.is_empty() { return None; }
                    line.split_once(':')
                }).any(|(name, value)| {
                    name.eq_ignore_ascii_case("transfer-encoding") && value.trim().eq_ignore_ascii_case("chunked")
                });
                if !te_valid {
                    let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                    return Err(io::Error::new(ErrorKind::InvalidData, "invalid Transfer-Encoding"));
                }
            }

            let method = request_method(request_text)?.to_string();
            let path = match request_path(request_text) {
                Ok(path) => path,
                Err(e) => {
                    let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                    return Err(e);
                }
            };
            last_method = Some(method.clone());
            last_path = Some(path.clone());

            let (allowed, reason) = shared.l7_check(expected_host, &method, &path);
            if !allowed {
                let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
                let msg = reason.unwrap_or_else(|| "L7 denied".to_string());
                return Err(io::Error::new(ErrorKind::PermissionDenied, msg));
            }

            // Resolved here, against the *normalized* path the L7 check just
            // used, so `/user/repos/../../zen` cannot carry the token to
            // `/zen`.
            let out_head = match shared.secret_for_request(expected_host, &method, &path) {
                Some(binding) => {
                    rewrite_head(&request_head, &binding.header, binding.value.as_str())?
                }
                None => {
                    // Authorized route, no provider behind it: worth reporting,
                    // since the request goes out unauthenticated.
                    if shared.config().is_secret_route(expected_host, &method, &path) {
                        secret_missing = true;
                    }
                    request_head.clone()
                }
            };

            // Last thing before the wire: what leaves here is addressed to the
            // origin, not to this proxy.
            let out_head = rewrite_request_target(&out_head).unwrap_or(out_head);
            upstream.write_all(&out_head)?;
            up_bytes += out_head.len() as u64;

            if let Some(len) = content_length(request_text)? {
                up_bytes += copy_exact(client, upstream, len)?;
            } else if is_chunked(request_text) {
                up_bytes += copy_chunked_body(client, upstream)?;
            }

            // Read response heads until the *final* one. A 1xx (other than
            // 101) is an interim response: RFC 9110 §15.2 says it has no
            // body and the origin still owes this same request a final
            // response on the same stream, so looping back to the top to
            // read the *next request* here would leave that final response
            // (100 Continue's is the common case: curl sends
            // `Expect: 100-continue` for larger bodies) sitting unread and
            // pair it with whatever the client sends next instead.
            let (status, response_text) = loop {
                let response_head = read_head(upstream)?.ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "upstream closed before sending an HTTP response",
                    )
                })?;
                let response_text = std::str::from_utf8(&response_head)
                    .map_err(|_| {
                        io::Error::new(ErrorKind::InvalidData, "response head is not valid UTF-8")
                    })?
                    .to_string();
                // Validated before it is relayed: a desynced upstream is not
                // forwarded to the client as though it were well-formed.
                validate_head_lines(&response_text)?;

                client.write_all(&response_head)?;
                down_bytes += response_head.len() as u64;

                let status = response_status_code(&response_text)?;

                if status == 101 {
                    // Switching Protocols: the exchange that got us here is
                    // the last HTTP-shaped thing on this connection. Reading
                    // another request head out of what comes next (WebSocket
                    // frames, most commonly) would desync the parser, so
                    // stop instead of looping.
                    last_status = Some(status);
                    return Ok(true);
                }

                if (100..200).contains(&status) {
                    continue;
                }

                break (status, response_text);
            };
            let response_text = response_text.as_str();
            last_status = Some(status);

            if response_has_no_body(&method, status) {
                continue;
            }

            if let Some(len) = content_length(response_text)? {
                down_bytes += copy_exact(upstream, client, len)?;
                continue;
            }
            if is_chunked(response_text) {
                down_bytes += copy_chunked_body(upstream, client)?;
                continue;
            }

            // Close-delimited response body: once this drains, the exchange ends.
            down_bytes += copy_to_eof(upstream, client)?;
            return Ok(false);
        }
    };

    match io_loop() {
        Ok(upgraded) => Ok(HttpExchangeOutcome {
            up_bytes,
            down_bytes,
            method: last_method,
            path: last_path,
            status: last_status,
            secret_missing,
            upgraded,
        }),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            Err(ProxyHttpError::L7Denied {
                method: last_method.unwrap_or_default(),
                path: last_path.unwrap_or_default(),
                reason: e.into_inner().map(|i| i.to_string()).unwrap_or_else(|| "L7 denied".to_string()),
            })
        }
        Err(e) => {
            Err(ProxyHttpError::Io {
                method: last_method,
                path: last_path,
                status: last_status,
                secret_missing,
                error: e,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Default)]
    struct FixtureIo {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
        eof_as_unexpected_eof: bool,
    }

    impl FixtureIo {
        fn with_read(data: &[u8]) -> Self {
            Self {
                read: Cursor::new(data.to_vec()),
                written: Vec::new(),
                eof_as_unexpected_eof: false,
            }
        }

        fn with_read_eof_error(data: &[u8]) -> Self {
            Self {
                read: Cursor::new(data.to_vec()),
                written: Vec::new(),
                eof_as_unexpected_eof: true,
            }
        }
    }

    impl Read for FixtureIo {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.read.read(buf)?;
            if n == 0 && self.eof_as_unexpected_eof {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "peer closed connection without sending TLS close_notify",
                ));
            }
            Ok(n)
        }
    }

    impl Write for FixtureIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A `Shared` whose policy allows everything on `example.com` and marks
    /// `route` secret-bearing, with a provider binding behind it.
    fn shared_injecting(route: &str, header: &str, value: &str) -> std::sync::Arc<crate::Shared> {
        std::sync::Arc::new(crate::shared_with_secrets(
            &format!("allow_host example.com\nsecret_route\t{route}\n"),
            &format!("{route}\t{header}\t{value}\n"),
        ))
    }

    #[test]
    fn rewrites_two_keep_alive_requests() {
        let client_in = b"GET /one HTTP/1.1\r\nHost: example.com\r\nAuthorization: old\r\n\r\n\
                          GET /two HTTP/1.1\r\nHost: example.com\r\nauthorization: old2\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none\
                            HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &shared_injecting("example.com\t*\t/**", "Authorization", "Bearer injected-secret"),
        )
        .expect("proxy");
        let rendered = String::from_utf8(upstream.written).expect("utf8 output");
        assert_eq!(rendered.matches("Authorization: Bearer injected-secret").count(), 2);
        assert!(!rendered.contains("Authorization: old"));
        assert!(!rendered.contains("authorization: old2"));
    }

    #[test]
    fn a_second_absolute_form_request_on_the_same_connection_is_also_rewritten() {
        // The reported failure: a browser configured with this proxy sends
        // absolute-form requests for as long as a connection stays open, not
        // just for the first one. A caller that only rewrites the first
        // request line and then splices the rest raw (as the un-intercepted
        // fast path used to) leaves later requests addressed to the proxy
        // itself, which most origins -- Vite's dev server among them --
        // cannot resolve and answer with their SPA-fallback document instead
        // of the asset that was actually asked for.
        let client_in = b"GET http://example.com/assets/app.js HTTP/1.1\r\nHost: example.com\r\n\r\n\
                          GET http://example.com/assets/app.css HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\njs\
                            HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ncss";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &crate::dummy_shared(),
        )
        .expect("proxy");
        let rendered = String::from_utf8(upstream.written).expect("utf8 output");
        assert!(rendered.contains("GET /assets/app.js HTTP/1.1"));
        assert!(rendered.contains("GET /assets/app.css HTTP/1.1"));
        assert!(!rendered.contains("http://example.com"));
    }

    #[test]
    fn a_101_response_stops_the_loop_instead_of_parsing_websocket_frames_as_http() {
        let client_in = b"GET /socket HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let upstream_in = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let outcome = proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &crate::dummy_shared(),
        )
        .expect("proxy");
        assert!(outcome.upgraded);
        assert_eq!(outcome.status, Some(101));
    }

    #[test]
    fn keeps_request_body_for_content_length() {
        let client_in = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &shared_injecting("example.com\tPOST\t/submit", "X-Api-Key", "value"),
        )
        .expect("proxy");
        let rendered = String::from_utf8(upstream.written).expect("utf8 output");
        assert!(rendered.ends_with("hello"));
        assert!(rendered.contains("X-Api-Key: value\r\n\r\n"));
    }

    #[test]
    fn keeps_chunked_body() {
        let client_in = b"POST /chunk HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n\
                          4\r\ntest\r\n0\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &shared_injecting("example.com\tPOST\t/chunk", "X-Test", "yes"),
        )
        .expect("proxy");
        let rendered = String::from_utf8(upstream.written).expect("utf8 output");
        assert!(rendered.contains("X-Test: yes\r\n\r\n"));
        assert!(rendered.ends_with("4\r\ntest\r\n0\r\n\r\n"));
    }

    #[test]
    fn a_secret_route_with_no_provider_binding_is_reported_missing_on_success() {
        // Authorized for injection by policy, but no provider ever bound a
        // value to the route: the request still goes out (unauthenticated),
        // and the caller (main.rs) needs to know that happened so it can
        // surface it, rather than the exchange silently looking like any
        // other successful one.
        let client_in = b"GET /user HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let shared = std::sync::Arc::new(crate::shared_with_secrets(
            "allow_host api.example.com\nsecret_route\tapi.example.com\tGET\t/user\n",
            "",
        ));

        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let outcome =
            proxy_http1_with_injection(&mut client, &mut upstream, "api.example.com", 80, &shared)
                .expect("proxy");

        assert!(outcome.secret_missing);
    }

    #[test]
    fn a_second_request_on_one_connection_outside_the_route_gets_no_secret() {
        // The leak, end to end.  Both requests are allowed by L7 -- the repo's
        // AGENTS.md said so -- but only /user/repos is a route the operator
        // authorized the token for.  Resolving the binding once per connection
        // put the token on both.
        let client_in = b"GET /user/repos HTTP/1.1\r\nHost: api.example.com\r\n\r\n\
                          GET /zen HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none\
                            HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo";
        let shared = std::sync::Arc::new(crate::shared_with_secrets(
            "allow_host api.example.com\n\
             allow_route\tapi.example.com\t*\t/**\n\
             secret_route\tapi.example.com\tGET\t/user/repos\n",
            "api.example.com\tGET\t/user/repos\tAuthorization\tBearer tok\n",
        ));

        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        proxy_http1_with_injection(&mut client, &mut upstream, "api.example.com", 80, &shared)
            .expect("proxy");

        let rendered = String::from_utf8(upstream.written).expect("utf8");
        let (first, second) = rendered.split_once("GET /zen").expect("both requests forwarded");
        assert!(first.contains("Authorization: Bearer tok"), "{rendered}");
        assert!(!second.contains("Bearer tok"), "the token leaked onto /zen: {rendered}");
    }

    #[test]
    fn hundred_continue_relays_final_response() {
        let client_in = b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nhi";
        let upstream_in = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let out = proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &crate::dummy_shared(),
        )
        .expect("proxy");
        let got = String::from_utf8_lossy(&client.written);
        assert!(got.starts_with("HTTP/1.1 100 Continue\r\n\r\n"), "{got}");
        assert!(got.ends_with("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), "{got}");
        assert_eq!(out.status, Some(200));
    }

    #[test]
    fn early_hints_relays_final_response() {
        let client_in = b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let out = proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &crate::dummy_shared(),
        )
        .expect("proxy");
        let got = String::from_utf8_lossy(&client.written);
        assert!(got.contains("103 Early Hints"), "{got}");
        assert!(got.ends_with("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), "{got}");
        assert_eq!(out.status, Some(200));
    }

    #[test]
    fn interim_responses_do_not_shift_keep_alive_pairing() {
        let client_in = b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n\
                          GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none\
                            HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &crate::dummy_shared(),
        )
        .expect("proxy");
        let got = String::from_utf8_lossy(&client.written);
        assert_eq!(got.matches("HTTP/1.1 200 OK").count(), 2, "{got}");
        assert!(got.contains("100 Continue"), "{got}");
        assert!(got.ends_with("two"), "{got}");
        let upstream_rendered = String::from_utf8_lossy(&upstream.written);
        assert_eq!(upstream_rendered.matches("GET /").count(), 2, "{upstream_rendered}");
    }

    #[test]
    fn header_lines_with_whitespace_before_the_colon_are_rejected() {
        let shared = std::sync::Arc::new(crate::shared_with_secrets("allow_host example.com\n", ""));
        let bad_heads: &[&[u8]] = &[
            b"GET /ok HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding : chunked\r\nContent-Length: 5\r\n\r\nhello",
            b"GET /ok HTTP/1.1\r\nHost: example.com\r\nContent-Length : 5\r\n\r\nhello",
            b"GET /ok HTTP/1.1\r\nHost : evil.com\r\n\r\n",
            b"GET /ok HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding\t: chunked\r\n\r\n0\r\n\r\n",
            b"GET /ok HTTP/1.1\r\nHost: example.com\r\nX-Multi: a\r\n chunked\r\n\r\n",
            b"GET /ok HTTP/1.1\r\nHost: example.com\r\nno-colon-here\r\n\r\n",
            // A bare LF inside what should be the request line: this
            // validator's own line-splitting (strict on "\r\n") would
            // otherwise treat "GET /ok HTTP/1.1\nTransfer-Encoding: chunked"
            // as one unchecked chunk, while content_length/is_chunked
            // (str::lines()-based) split on the bare "\n" and would see
            // Transfer-Encoding as a header of its own.
            b"GET /ok HTTP/1.1\nTransfer-Encoding: chunked\r\nHost: example.com\r\n\r\n",
        ];
        for head in bad_heads {
            let mut client = FixtureIo::with_read(head);
            let mut upstream = FixtureIo::with_read(b"");
            proxy_http1_with_injection(&mut client, &mut upstream, "example.com", 80, &shared)
                .unwrap_err();
            assert!(
                upstream.written.is_empty(),
                "nothing should reach upstream for {:?}",
                String::from_utf8_lossy(head)
            );
            assert!(
                String::from_utf8_lossy(&client.written).starts_with("HTTP/1.1 400"),
                "expected a 400 for {:?}, got {:?}",
                String::from_utf8_lossy(head),
                String::from_utf8_lossy(&client.written)
            );
        }
    }

    #[test]
    fn a_well_formed_header_block_still_passes_validation() {
        let client_in = b"GET /ok HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let shared = std::sync::Arc::new(crate::shared_with_secrets("allow_host example.com\n", ""));
        proxy_http1_with_injection(&mut client, &mut upstream, "example.com", 80, &shared)
            .expect("proxy");
    }

    #[test]
    fn a_dot_segment_path_is_rejected_rather_than_normalized_onto_another_route() {
        // Normalizing /user/repos/../../zen to /zen and matching that would
        // still leave the raw target -- which the origin sees -- ambiguous
        // relative to what the origin does with ".." itself. Fail closed
        // instead: the request never reaches the matcher or the wire.
        let client_in =
            b"GET /user/repos/../../zen HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let shared = std::sync::Arc::new(crate::shared_with_secrets(
            "allow_host api.example.com\n\
             allow_route\tapi.example.com\t*\t/**\n\
             secret_route\tapi.example.com\tGET\t/user/**\n",
            "api.example.com\tGET\t/user/**\tAuthorization\tBearer tok\n",
        ));

        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let err = proxy_http1_with_injection(&mut client, &mut upstream, "api.example.com", 80, &shared)
            .unwrap_err();

        assert!(err.to_string().contains("'.' or '..' segment"), "{err}");
        assert!(upstream.written.is_empty(), "nothing should reach the origin");
    }

    #[test]
    fn ambiguous_paths_are_refused_with_a_400_and_nothing_forwarded() {
        let shared = std::sync::Arc::new(crate::shared_with_secrets(
            "allow_host x\nallow_route\tx\t*\t/public/**\n",
            "",
        ));
        for target in [
            "/admin//../public/x",
            "/admin/..%2Fpublic/x",
            "/a/%2e%2e/b",
            "/a/.%2E/b",
            "/a/%2E/b",
            "/a\\b",
        ] {
            let client_in = format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n");
            let mut client = FixtureIo::with_read(client_in.as_bytes());
            let mut upstream = FixtureIo::with_read(b"");
            let err = proxy_http1_with_injection(&mut client, &mut upstream, "x", 80, &shared)
                .unwrap_err();
            assert!(upstream.written.is_empty(), "{target}: {err}");
            assert!(
                String::from_utf8_lossy(&client.written).starts_with("HTTP/1.1 400"),
                "{target}: {}",
                String::from_utf8_lossy(&client.written)
            );
        }
    }

    #[test]
    fn ordinary_paths_still_work() {
        for target in [
            "/",
            "/a/b",
            "/a/b/",
            "/a%20b",
            // A percent-encoded slash inside a segment is decoded and
            // matched like a literal one, not refused: both are real paths
            // origins route on.
            "/@scope%2fname",
            "/api/v4/projects/group%2Fproject/issues",
        ] {
            let client_in = format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n");
            let mut client = FixtureIo::with_read(client_in.as_bytes());
            let mut upstream = FixtureIo::with_read(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            let shared = std::sync::Arc::new(crate::shared_with_secrets("allow_host x\n", ""));
            proxy_http1_with_injection(&mut client, &mut upstream, "x", 80, &shared)
                .unwrap_or_else(|e| panic!("{target} should be allowed: {e}"));
        }
        // The query string is never inspected for dot-segments.
        let client_in = b"GET /a?x=../y HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let shared = std::sync::Arc::new(crate::shared_with_secrets("allow_host x\n", ""));
        proxy_http1_with_injection(&mut client, &mut upstream, "x", 80, &shared).expect("proxy");
    }

    #[test]
    fn a_percent_encoded_slash_decodes_before_route_matching_and_secret_injection() {
        // The regression: refusing %2F outright broke real traffic (a
        // private npm registry's scoped package names, a GitLab-style
        // project id) that legitimately encodes a `/` inside one path
        // segment. Matching -- and injection -- has to run against the
        // decoded path, the same one an origin that decodes %2F sees.
        let client_in =
            b"GET /@scope%2fname HTTP/1.1\r\nHost: registry.example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let shared = std::sync::Arc::new(crate::shared_with_secrets(
            "allow_host registry.example.com\n\
             secret_route\tregistry.example.com\tGET\t/@scope/*\n",
            "registry.example.com\tGET\t/@scope/*\tAuthorization\tBearer tok\n",
        ));

        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        proxy_http1_with_injection(&mut client, &mut upstream, "registry.example.com", 80, &shared)
            .expect("proxy");

        let rendered = String::from_utf8(upstream.written).expect("utf8");
        assert!(rendered.contains("Authorization: Bearer tok"), "{rendered}");
    }

    #[test]
    fn proxies_two_request_response_exchanges() {
        let client_in = b"GET /one HTTP/1.1\r\nHost: example.com\r\nAuthorization: old\r\n\r\n\
                          GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none\
                            HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo";

        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let outcome =
            proxy_http1_with_injection(
                &mut client,
                &mut upstream,
                "example.com",
                80,
                &shared_injecting("example.com\t*\t/**", "Authorization", "Bearer v"),
            )
            .expect("proxy");

        assert_eq!(outcome.up_bytes as usize, upstream.written.len());
        assert_eq!(outcome.down_bytes as usize, client.written.len());
        let upstream_rendered = String::from_utf8(upstream.written).expect("utf8");
        assert_eq!(upstream_rendered.matches("Authorization: Bearer v").count(), 2);
        assert!(!upstream_rendered.contains("Authorization: old"));

        let client_rendered = String::from_utf8(client.written).expect("utf8");
        assert!(client_rendered.contains("HTTP/1.1 200 OK"));
        assert!(client_rendered.contains("\r\n\r\none"));
        assert!(client_rendered.ends_with("two"));
    }

    #[test]
    fn rejects_host_mismatch_before_injection() {
        let client_in = b"GET /one HTTP/1.1\r\nHost: attacker.example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let err = proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "api.example.com",
            80,
            &shared_injecting("api.example.com\t*\t/**", "Authorization", "Bearer v"),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("does not match secret target"),
            "{err}"
        );
        assert!(upstream.written.is_empty());
    }

    #[test]
    fn rejects_absolute_form_and_host_mismatch() {
        let client_in =
            b"GET http://api.example.com/one HTTP/1.1\r\nHost: attacker.example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let err = proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "api.example.com",
            80,
            &shared_injecting("api.example.com\t*\t/**", "Authorization", "Bearer v"),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("request target authority does not match Host"),
            "{err}"
        );
        assert!(upstream.written.is_empty());
    }

    #[test]
    fn copy_to_eof_treats_unexpected_eof_as_clean_close() {
        struct EofReader {
            data: Vec<u8>,
            pos: usize,
        }
        impl Read for EofReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "peer closed connection without sending TLS close_notify",
                    ));
                }
                let n = (self.data.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        let mut reader = EofReader {
            data: b"hello world".to_vec(),
            pos: 0,
        };
        let mut output = Vec::new();
        let copied = copy_to_eof(&mut reader, &mut output).expect("copy should succeed");
        assert_eq!(copied, 11);
        assert_eq!(output, b"hello world");
    }

    #[test]
    fn proxies_one_request_and_treats_client_unexpected_eof_as_clean_close() {
        let client_in = b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

        let mut client = FixtureIo::with_read_eof_error(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        let outcome = proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &crate::dummy_shared(),
        )
        .expect("proxy should succeed");

        assert!(outcome.up_bytes > 0);
        assert!(outcome.down_bytes > 0);
        let client_rendered = String::from_utf8(client.written).expect("utf8");
        assert!(client_rendered.contains("HTTP/1.1 200 OK"));
        assert!(client_rendered.ends_with("ok"));
    }

    #[test]
    fn an_absolute_target_becomes_the_path_the_origin_expects() {
        assert_eq!(origin_form("http://127.0.0.1:8000/index.html"), "/index.html");
        assert_eq!(origin_form("http://h/a?b=c"), "/a?b=c");
        assert_eq!(origin_form("HTTP://Example.com/x"), "/x");
        assert_eq!(origin_form("http://[::1]:8000/x"), "/x");
    }

    #[test]
    fn a_target_with_no_path_still_gets_one() {
        assert_eq!(origin_form("http://127.0.0.1:8000"), "/");
        assert_eq!(origin_form("http://h?q=1"), "/?q=1");
    }

    #[test]
    fn what_is_already_addressed_to_the_origin_is_left_alone() {
        assert_eq!(origin_form("/index.html"), "/index.html");
        assert_eq!(origin_form("*"), "*");
        // Authority-form, which is CONNECT's and never an origin request.
        assert_eq!(origin_form("example.com:443"), "example.com:443");
        assert!(rewrite_request_target(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n").is_none());
        assert!(rewrite_request_target(b"CONNECT h:443 HTTP/1.1\r\n\r\n").is_none());
        // Not three tokens: the smuggling checks own this, not the rewriter.
        assert!(rewrite_request_target(b"GET  http://h/a HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn rewriting_the_target_touches_nothing_else_in_the_head() {
        let head = b"GET http://127.0.0.1:8000/a?b HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nAccept: */*\r\n\r\n";
        let out = rewrite_request_target(head).expect("rewritten");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "GET /a?b HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nAccept: */*\r\n\r\n"
        );
    }

    #[test]
    fn the_forwarded_request_is_the_one_the_origin_would_have_received() {
        // The reported failure: a proxied `python3 -m http.server` 404s because
        // it resolves the absolute target as a path under its document root.
        let client_in = b"GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let upstream_in = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut client = FixtureIo::with_read(client_in);
        let mut upstream = FixtureIo::with_read(upstream_in);
        proxy_http1_with_injection(
            &mut client,
            &mut upstream,
            "example.com",
            80,
            &shared_injecting("example.com\tPOST\t/nothing", "X-Api-Key", "value"),
        )
        .expect("proxy");
        let rendered = String::from_utf8(upstream.written).expect("utf8 output");
        assert!(
            rendered.starts_with("GET /index.html HTTP/1.1\r\n"),
            "forwarded head was {:?}",
            rendered
        );
    }
}
