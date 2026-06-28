//! Full request/response transaction log (DESIGN §7).
//!
//! One JSON line per proxied request, recording the **provider-facing** exchange:
//! the masked request body sent upstream and the masked response received. In
//! enforce mode both are secret-free (only sentinels), so the log is fully
//! auditable without re-introducing the exposure SCRUB exists to prevent. In
//! dry-run mode nothing is masked, so records reflect the original content.
//!
//! Each request gets an id, also returned to the client as `x-scrub-request-id`.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Append-only transaction writer.
pub struct TransactionLog {
    writer: Mutex<BufWriter<File>>,
}

impl TransactionLog {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Arc<Self>> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Arc::new(Self {
            writer: Mutex::new(BufWriter::new(file)),
        }))
    }

    fn write(&self, record: &Record) {
        if let Ok(line) = serde_json::to_string(record) {
            let mut w = self.writer.lock().unwrap();
            if writeln!(w, "{line}").and_then(|_| w.flush()).is_err() {
                tracing::error!("transaction write failed");
            }
        }
    }
}

/// One transaction record (counts/types plus the masked bodies).
#[derive(Debug, Serialize)]
pub struct Record {
    pub id: String,
    pub ts: u64,
    pub route: String,
    pub tenant: Option<String>,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub mode: String,
    pub detected: usize,
    pub types: BTreeMap<String, usize>,
    /// Masked request body sent upstream (truncated to `max_body_bytes`).
    pub request: String,
    pub request_truncated: bool,
    /// Masked response body received from upstream (truncated).
    pub response: String,
    pub response_truncated: bool,
}

/// Immutable metadata captured before the response streams.
pub struct Meta {
    pub id: String,
    pub route: String,
    pub tenant: Option<String>,
    pub method: String,
    pub path: String,
    pub mode: String,
    pub detected: usize,
    pub types: BTreeMap<String, usize>,
}

/// Accumulates a transaction across the streamed response and writes it on EOF.
pub struct Recorder {
    log: Arc<TransactionLog>,
    meta: Meta,
    status: u16,
    request: Vec<u8>,
    request_truncated: bool,
    response: Vec<u8>,
    response_truncated: bool,
    max: usize,
}

impl Recorder {
    /// Create a recorder, capturing the (bounded) provider-facing request body.
    pub fn new(
        log: Arc<TransactionLog>,
        meta: Meta,
        status: u16,
        request_body: &[u8],
        max: usize,
    ) -> Self {
        let request_truncated = request_body.len() > max;
        let request = request_body[..request_body.len().min(max)].to_vec();
        Self {
            log,
            meta,
            status,
            request,
            request_truncated,
            response: Vec::new(),
            response_truncated: false,
            max,
        }
    }

    /// Accumulate an upstream response chunk (bounded).
    pub fn push_response(&mut self, chunk: &[u8]) {
        if self.response.len() >= self.max {
            self.response_truncated = true;
            return;
        }
        let room = self.max - self.response.len();
        if chunk.len() > room {
            self.response.extend_from_slice(&chunk[..room]);
            self.response_truncated = true;
        } else {
            self.response.extend_from_slice(chunk);
        }
    }

    /// Write the record (call once at stream end).
    pub fn finish(self) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let record = Record {
            id: self.meta.id,
            ts,
            route: self.meta.route,
            tenant: self.meta.tenant,
            method: self.meta.method,
            path: self.meta.path,
            status: self.status,
            mode: self.meta.mode,
            detected: self.meta.detected,
            types: self.meta.types,
            request: String::from_utf8_lossy(&self.request).into_owned(),
            request_truncated: self.request_truncated,
            response: String::from_utf8_lossy(&self.response).into_owned(),
            response_truncated: self.response_truncated,
        };
        self.log.write(&record);
    }
}

/// A random hex request id.
pub fn request_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    let mut s = String::with_capacity(16);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_capture_is_bounded() {
        let mut path = std::env::temp_dir();
        path.push(format!("scrub-tx-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let log = TransactionLog::open(&path).unwrap();

        let meta = Meta {
            id: "abc".into(),
            route: "/x".into(),
            tenant: None,
            method: "POST".into(),
            path: "/v1".into(),
            mode: "enforce".into(),
            detected: 1,
            types: BTreeMap::new(),
        };
        let mut rec = Recorder::new(log, meta, 200, b"req", 8);
        rec.push_response(b"1234567");
        rec.push_response(b"89ABCDEF"); // exceeds max(8)
        assert!(rec.response_truncated);
        rec.finish();

        let body = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(v["id"], "abc");
        assert_eq!(v["response"], "12345678");
        assert_eq!(v["response_truncated"], true);
    }
}
