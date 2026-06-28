//! Tamper-evident audit log (DESIGN §7).
//!
//! Each proxied request appends one JSON line recording *what categories* were
//! detected — counts and types only, never values. Records are hash-chained:
//! `hash = SHA-256(prev_hash || record-without-hash)`, so deleting, reordering,
//! or editing any line breaks verification from that point on.
//!
//! Verify with `scrub audit-verify <path>` or [`verify`].

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One audit record. Field order is significant: the hash is computed over the
/// JSON of this struct with `hash` blanked, so serialization must be stable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub seq: u64,
    /// Unix seconds.
    pub ts: u64,
    pub route: String,
    pub tenant: Option<String>,
    pub mode: String,
    pub detected: usize,
    pub types: BTreeMap<String, usize>,
    /// Hex SHA-256 of the previous record (empty for the first).
    pub prev: String,
    /// Hex SHA-256 of this record (chain link).
    pub hash: String,
}

impl Record {
    /// Recompute the chain hash for this record given `prev`.
    fn compute_hash(&self, prev: &str) -> String {
        let mut core = self.clone();
        core.prev = prev.to_string();
        core.hash = String::new();
        let json = serde_json::to_string(&core).expect("record serializes");
        let mut h = Sha256::new();
        h.update(prev.as_bytes());
        h.update(json.as_bytes());
        hex(&h.finalize())
    }
}

/// Append-only, hash-chained audit writer.
pub struct AuditLog {
    inner: Mutex<Inner>,
}

struct Inner {
    writer: BufWriter<File>,
    seq: u64,
    prev: String,
}

impl AuditLog {
    /// Open (creating if needed) the audit log at `path`, continuing the chain
    /// from any existing records.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<std::sync::Arc<Self>> {
        let path = path.as_ref();
        let (seq, prev) = match verify(path) {
            Ok(report) => (report.count, report.last_hash),
            // Missing file -> fresh chain; other read issues -> also start fresh.
            Err(_) => (0, String::new()),
        };
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(Inner {
                writer: BufWriter::new(file),
                seq,
                prev,
            }),
        }))
    }

    /// Append one record. Counts/types only — callers must never pass values.
    pub fn record(
        &self,
        route: &str,
        tenant: Option<&str>,
        mode: &str,
        detected: usize,
        types: &BTreeMap<String, usize>,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut inner = self.inner.lock().unwrap();
        let mut rec = Record {
            seq: inner.seq,
            ts,
            route: route.to_string(),
            tenant: tenant.map(str::to_string),
            mode: mode.to_string(),
            detected,
            types: types.clone(),
            prev: inner.prev.clone(),
            hash: String::new(),
        };
        rec.hash = rec.compute_hash(&inner.prev);
        if let Ok(line) = serde_json::to_string(&rec) {
            // Best-effort: a failed audit write must not take down the proxy, but
            // it is logged loudly.
            if writeln!(inner.writer, "{line}")
                .and_then(|_| inner.writer.flush())
                .is_err()
            {
                tracing::error!("audit write failed");
                return;
            }
        }
        inner.seq += 1;
        inner.prev = rec.hash;
    }
}

/// Result of verifying an audit file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Number of records verified up to the first break (or total if intact).
    pub count: u64,
    /// Hash of the last verified record (chain head).
    pub last_hash: String,
    /// `Some(seq)` of the first record whose chain is broken, else `None`.
    pub broken_at: Option<u64>,
}

impl VerifyReport {
    pub fn is_intact(&self) -> bool {
        self.broken_at.is_none()
    }
}

/// Verify the hash chain of an audit file. Errors only on I/O (e.g. missing
/// file); a tampered-but-readable file returns `Ok` with `broken_at` set.
pub fn verify(path: impl AsRef<Path>) -> std::io::Result<VerifyReport> {
    let content = std::fs::read_to_string(path)?;
    let mut prev = String::new();
    let mut count = 0u64;
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let rec: Record = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => return Ok(broken(count, prev, i as u64)),
        };
        // Chain linkage + recomputed hash must both hold, and seq must be ordered.
        if rec.prev != prev || rec.seq != count || rec.compute_hash(&prev) != rec.hash {
            return Ok(broken(count, prev, rec.seq));
        }
        prev = rec.hash;
        count += 1;
    }
    Ok(VerifyReport {
        count,
        last_hash: prev,
        broken_at: None,
    })
}

fn broken(count: u64, last_hash: String, seq: u64) -> VerifyReport {
    VerifyReport {
        count,
        last_hash,
        broken_at: Some(seq),
    }
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("scrub-audit-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn types(pairs: &[(&str, usize)]) -> BTreeMap<String, usize> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn chain_verifies_and_survives_reopen() {
        let path = tmp("chain");
        {
            let log = AuditLog::open(&path).unwrap();
            log.record(
                "/openai",
                Some("acme"),
                "enforce",
                2,
                &types(&[("EMAIL", 2)]),
            );
            log.record("/openai", None, "dry-run", 1, &types(&[("SECRET", 1)]));
        }
        // Reopen continues the chain.
        {
            let log = AuditLog::open(&path).unwrap();
            log.record("/x", None, "enforce", 0, &types(&[]));
        }
        let report = verify(&path).unwrap();
        assert!(report.is_intact());
        assert_eq!(report.count, 3);
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let path = tmp("tamper");
        {
            let log = AuditLog::open(&path).unwrap();
            log.record("/openai", None, "enforce", 2, &types(&[("EMAIL", 2)]));
            log.record("/openai", None, "enforce", 5, &types(&[("EMAIL", 5)]));
        }
        // Tamper: bump a detection count on the first line without fixing hashes.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        lines[0] = lines[0].replace("\"detected\":2", "\"detected\":9");
        std::fs::write(&path, lines.join("\n")).unwrap();

        let report = verify(&path).unwrap();
        assert!(!report.is_intact());
        assert_eq!(report.broken_at, Some(0));
    }

    #[test]
    fn deleting_a_record_breaks_the_chain() {
        let path = tmp("delete");
        {
            let log = AuditLog::open(&path).unwrap();
            log.record("/a", None, "enforce", 1, &types(&[("EMAIL", 1)]));
            log.record("/b", None, "enforce", 1, &types(&[("EMAIL", 1)]));
            log.record("/c", None, "enforce", 1, &types(&[("EMAIL", 1)]));
        }
        // Remove the middle record.
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();

        let report = verify(&path).unwrap();
        assert_eq!(report.count, 1); // only the first record verifies
        assert_eq!(report.broken_at, Some(2)); // the seq-2 record no longer links
    }
}
