use std::fmt;
use std::fs::File;
use std::io::Read;

#[derive(Clone, Eq, PartialEq)]
pub struct Secret(String);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Clone, Debug)]
pub struct SecretBinding {
    pub domain: String,
    pub header: String,
    pub value: Secret,
}

#[derive(Clone, Default, Debug)]
pub struct SecretBindings {
    entries: Vec<SecretBinding>,
}

impl SecretBindings {
    pub fn from_fd(fd: Option<i32>) -> Result<Self, String> {
        let Some(fd) = fd else {
            return Ok(Self::default());
        };
        if fd < 0 {
            return Err(format!("fd {} is negative", fd));
        }
        let mut body = String::new();
        File::open(format!("/proc/self/fd/{fd}"))
            .map_err(|e| format!("cannot open fd {}: {}", fd, e))?
            .read_to_string(&mut body)
            .map_err(|e| format!("cannot read fd {}: {}", fd, e))?;
        Self::parse(&body)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries: Vec<SecretBinding> = Vec::new();
        for (i, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim_end_matches('\r');
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let lineno = i + 1;
            let mut parts = line.splitn(3, '\t');
            let domain = parts
                .next()
                .map(str::trim)
                .ok_or_else(|| format!("{lineno}: missing domain"))?;
            let header = parts
                .next()
                .map(str::trim)
                .ok_or_else(|| format!("{lineno}: expected DOMAIN<TAB>HEADER<TAB>VALUE"))?;
            let value = parts
                .next()
                .ok_or_else(|| format!("{lineno}: expected DOMAIN<TAB>HEADER<TAB>VALUE"))?;

            if domain.is_empty() {
                return Err(format!("{lineno}: domain is empty"));
            }
            if header.is_empty() {
                return Err(format!("{lineno}: header is empty"));
            }
            if value.is_empty() {
                return Err(format!("{lineno}: value is empty"));
            }

            let domain = domain.to_ascii_lowercase();
            validate_domain(&domain)
                .map_err(|e| format!("{lineno}: invalid domain {:?}: {}", domain, e))?;
            validate_header(header)
                .map_err(|e| format!("{lineno}: invalid header {:?}: {}", header, e))?;

            if let Some(existing) = entries
                .iter()
                .find(|entry| patterns_overlap(&entry.domain, &domain))
            {
                return Err(format!(
                    "{lineno}: domain {:?} overlaps with {:?}",
                    domain, existing.domain
                ));
            }

            entries.push(SecretBinding {
                domain,
                header: header.to_string(),
                value: Secret(value.to_string()),
            });
        }

        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[SecretBinding] {
        &self.entries
    }

    pub fn binding_for_host(&self, host: &str) -> Option<&SecretBinding> {
        let host = host.to_ascii_lowercase();
        let mut best: Option<&SecretBinding> = None;
        let mut best_len: usize = 0;
        for entry in &self.entries {
            if domain_match(&host, &entry.domain) && entry.domain.len() > best_len {
                best = Some(entry);
                best_len = entry.domain.len();
            }
        }
        best
    }
}

fn validate_domain(domain: &str) -> Result<(), &'static str> {
    let bare = domain.strip_prefix("*.").unwrap_or(domain);
    if bare.is_empty() {
        return Err("empty domain");
    }
    if bare.starts_with('.') || bare.ends_with('.') || bare.contains("..") {
        return Err("malformed dot placement");
    }
    if !bare
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Err("contains invalid characters");
    }
    if !bare
        .chars()
        .next()
        .expect("non-empty")
        .is_ascii_alphanumeric()
        || !bare
            .chars()
            .last()
            .expect("non-empty")
            .is_ascii_alphanumeric()
    {
        return Err("must begin and end with an alphanumeric character");
    }
    Ok(())
}

fn is_header_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

fn validate_header(header: &str) -> Result<(), &'static str> {
    if !header.chars().all(is_header_char) {
        return Err("contains non-token characters");
    }
    let lower = header.to_ascii_lowercase();
    if lower == "host"
        || lower == "connection"
        || lower == "content-length"
        || lower == "transfer-encoding"
        || lower.starts_with("proxy-")
    {
        return Err("reserved header name");
    }
    Ok(())
}

fn domain_match(domain: &str, pattern: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(base) => domain == base || domain.ends_with(&pattern[1..]),
        None => domain == pattern,
    }
}

fn overlap_samples(pattern: &str) -> [String; 2] {
    match pattern.strip_prefix("*.") {
        Some(base) => [base.to_string(), format!("sample.{}", base)],
        None => [pattern.to_string(), pattern.to_string()],
    }
}

fn patterns_overlap(a: &str, b: &str) -> bool {
    let [a0, a1] = overlap_samples(a);
    let [b0, b1] = overlap_samples(b);
    domain_match(&a0, b) || domain_match(&a1, b) || domain_match(&b0, a) || domain_match(&b1, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let binding =
            SecretBindings::parse("api.example.com\tAuthorization\tBearer super-secret\n")
                .expect("parse");
        let dbg = format!("{:?}", binding);
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(!dbg.contains("super-secret"), "{dbg}");
    }

    #[test]
    fn parser_reads_tab_delimited_entries() {
        let parsed = SecretBindings::parse(
            "api.example.com\tAuthorization\tBearer abc\n\
             *.example.org\tX-Api-Key\txyz\n",
        )
        .expect("parse");
        assert_eq!(parsed.len(), 2);
        let binding = parsed
            .binding_for_host("api.example.com")
            .expect("binding for api.example.com");
        assert_eq!(binding.header, "Authorization");
        assert_eq!(binding.value.as_str(), "Bearer abc");
    }

    #[test]
    fn parser_rejects_reserved_header_names() {
        let err = SecretBindings::parse("api.example.com\tHost\tvalue\n").unwrap_err();
        assert!(err.contains("reserved header name"), "{err}");
    }

    #[test]
    fn parser_rejects_overlapping_patterns() {
        let err = SecretBindings::parse(
            "*.example.com\tAuthorization\tone\n\
             api.example.com\tAuthorization\ttwo\n",
        )
        .unwrap_err();
        assert!(err.contains("overlaps"), "{err}");
    }

    #[test]
    fn host_lookup_prefers_more_specific_pattern() {
        let parsed = SecretBindings::parse(
            "*.example.com\tAuthorization\twild\n\
             api.example.com\tAuthorization\texact\n",
        );
        assert!(parsed.is_err(), "overlap must be rejected");

        let parsed =
            SecretBindings::parse("*.example.com\tAuthorization\twild\n").expect("parse wildcard");
        let binding = parsed
            .binding_for_host("api.example.com")
            .expect("binding for api.example.com");
        assert_eq!(binding.value.as_str(), "wild");
    }
}
