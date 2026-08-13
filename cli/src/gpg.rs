#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GpgScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
pub enum GpgScanStatus {
    Safe,
    Unsafe(Vec<PathBuf>),
}

pub fn scan_gnupg_home(gnupg_home: &Path) -> Result<GpgScanStatus, GpgScanError> {
    if !gnupg_home.is_dir() {
        return Ok(GpgScanStatus::Safe);
    }

    let mut offenders = Vec::new();

    let private_dir = gnupg_home.join("private-keys-v1.d");
    if private_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&private_dir) {
            let mut paths: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
                .map(|e| e.path())
                .collect();
            paths.sort();

            for path in paths {
                let mut buf = [0; 256];
                use std::io::Read;
                let mut is_unsafe = true; // Default to unsafe
                if let Ok(mut f) = fs::File::open(&path) {
                    let bytes_read = f.read(&mut buf).unwrap_or(0);
                    let content = &buf[..bytes_read];
                    
                    let mut header = String::with_capacity(bytes_read);
                    for &b in content {
                        if b != 0 {
                            header.push(b as char);
                        }
                    }
                    
                    // Equivalent to `tr -s ' \t\n' ' '`
                    let mut squeezed = String::with_capacity(header.len());
                    let mut last_was_space = false;
                    for c in header.chars() {
                        if c == ' ' || c == '\t' || c == '\n' {
                            if !last_was_space {
                                squeezed.push(' ');
                                last_was_space = true;
                            }
                        } else {
                            squeezed.push(c);
                            last_was_space = false;
                        }
                    }

                    if squeezed.contains("(protected-private-key") {
                        is_unsafe = true;
                    } else if squeezed.contains("(shadowed-private-key") {
                        is_unsafe = false;
                    } else if squeezed.contains("(private-key") {
                        is_unsafe = true;
                    } else {
                        is_unsafe = true; // Anything unrecognised counts as unsafe
                    }
                }
                
                if is_unsafe {
                    offenders.push(path);
                }
            }
        }
    }

    let legacy_secring = gnupg_home.join("secring.gpg");
    if let Ok(metadata) = fs::metadata(&legacy_secring) {
        if metadata.is_file() && metadata.len() > 0 {
            offenders.push(legacy_secring);
        }
    }

    if offenders.is_empty() {
        Ok(GpgScanStatus::Safe)
    } else {
        Ok(GpgScanStatus::Unsafe(offenders))
    }
}
