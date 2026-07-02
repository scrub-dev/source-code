//! Streaming rehydration state machine (DESIGN §3 ingress, §9).
//!
//! Feed response chunks via [`Rehydrator::push`]; it emits rehydrated bytes
//! immediately and holds back only the minimum tail that *could* be the start of
//! a sentinel split across chunk boundaries (bounded by [`MAX_SENTINEL_LEN`]).
//! Call [`Rehydrator::finish`] at end-of-stream to flush any remainder verbatim.
//!
//! Guarantees (the reversibility contract):
//! - A complete `⟦S…⟧` whose id is known is replaced by its original.
//! - An id we never issued is emitted verbatim — never guessed, never an error
//!   (handles model-invented lookalikes).
//! - A sentinel straddling two chunks rehydrates correctly.
//! - At EOS, anything unterminated is emitted verbatim (lossless).

use memchr::memmem;

use crate::sentinel::{self, MAX_SENTINEL_LEN, PREFIX};
use crate::vault::MappingStore;

/// How a rehydrated original is encoded when spliced back into the stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Encoding {
    /// Emit original bytes unchanged.
    #[default]
    Raw,
    /// Escape the original as JSON string content (no surrounding quotes), so an
    /// original containing `"`, `\`, or control chars cannot break the JSON/SSE
    /// frame it is spliced into. A no-op for ordinary text.
    JsonString,
}

/// Incremental, allocation-light rehydrator over a byte stream.
pub struct Rehydrator {
    /// Carry: bytes not yet safe to emit (possible partial/incomplete sentinel).
    buf: Vec<u8>,
    finder: memmem::Finder<'static>,
    encoding: Encoding,
}

impl Default for Rehydrator {
    fn default() -> Self {
        Self::new()
    }
}

impl Rehydrator {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            finder: memmem::Finder::new(PREFIX.as_bytes()),
            encoding: Encoding::Raw,
        }
    }

    /// Build a rehydrator that escapes originals for the given output context.
    pub fn with_encoding(encoding: Encoding) -> Self {
        Self {
            encoding,
            ..Self::new()
        }
    }

    /// Process one chunk, returning rehydrated bytes ready to forward downstream.
    pub fn push(&mut self, chunk: &[u8], store: &dyn MappingStore) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(self.buf.len());
        let carry_start = self.drain(store, &mut out);
        self.buf.drain(..carry_start);
        out
    }

    /// Flush any buffered remainder verbatim. Call once at end-of-stream; the
    /// rehydrator is left empty and safe to drop.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Emit everything currently decidable; return the offset at which the
    /// undecided carry begins (everything before it has been written to `out`).
    fn drain(&self, store: &dyn MappingStore, out: &mut Vec<u8>) -> usize {
        let buf = &self.buf;
        let mut i = 0;
        loop {
            let Some(rel) = self.finder.find(&buf[i..]) else {
                // No full prefix ahead. Flush all but a possible dangling partial
                // prefix at the very end (e.g. chunk ends mid-`⟦`).
                let keep = sentinel::dangling_prefix_len(&buf[i..]);
                let flush_end = buf.len() - keep;
                out.extend_from_slice(&buf[i..flush_end]);
                return flush_end;
            };

            let p = i + rel;
            out.extend_from_slice(&buf[i..p]); // literal bytes before the prefix

            match sentinel::parse(&buf[p..]) {
                Some((id, tag, len)) => {
                    match store.resolve(id, tag) {
                        // Only a sentinel with a valid tag resolves; a forged/echoed
                        // or unknown one is emitted verbatim (never guessed).
                        Some(original) => emit_original(out, &original, self.encoding),
                        None => out.extend_from_slice(&buf[p..p + len]),
                    }
                    i = p + len;
                }
                None => {
                    let remaining = buf.len() - p;
                    if remaining >= MAX_SENTINEL_LEN {
                        // No terminator within the bound -> not a sentinel. Emit
                        // one byte of the would-be prefix literally and re-scan;
                        // the rest flushes as literals.
                        out.extend_from_slice(&buf[p..p + 1]);
                        i = p + 1;
                    } else {
                        // Might complete in a later chunk: hold back from p.
                        return p;
                    }
                }
            }
        }
    }
}

/// Emit `original`, escaped per `encoding`, into `out`.
fn emit_original(out: &mut Vec<u8>, original: &[u8], encoding: Encoding) {
    match encoding {
        Encoding::Raw => out.extend_from_slice(original),
        Encoding::JsonString => json_escape_into(out, original),
    }
}

/// Append `bytes` to `out`, escaped as JSON string content (RFC 8259), without
/// surrounding quotes. Splicing this into an existing JSON string stays valid.
pub fn json_escape_into(out: &mut Vec<u8>, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            c if c < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(c >> 4) as usize]);
                out.push(HEX[(c & 0xf) as usize]);
            }
            c => out.push(c),
        }
    }
}

/// Convenience one-shot rehydration (push the whole buffer, then finish).
pub fn rehydrate_all(input: &[u8], store: &dyn MappingStore) -> Vec<u8> {
    let mut r = Rehydrator::new();
    let mut out = r.push(input, store);
    out.extend_from_slice(&r.finish());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::detect::Detector;
    use crate::mask::{mask, MaskStyle};
    use crate::vault::Vault;

    fn detector() -> Detector {
        let cfg: Config = Config::from_yaml(
            r#"
glossary:
  - { term: "Project Hufflepuff", type: CODENAME, priority: 100 }
rules:
  - { name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }
"#,
        )
        .unwrap();
        Detector::from_config(&cfg).unwrap()
    }

    /// Full round trip with the model echoing the masked text back verbatim.
    #[test]
    fn round_trip_whole() {
        let det = detector();
        let v = Vault::new();
        let original = b"contact john@acme.com re Project Hufflepuff".to_vec();
        let masked = mask(&original, &det, &v, MaskStyle::TypedSentinel);
        assert_ne!(masked, original);
        let restored = rehydrate_all(&masked, &v);
        assert_eq!(restored, original);
    }

    /// The hard case: rehydrate correctly no matter where chunk boundaries fall,
    /// including straight through the middle of a multi-byte sentinel.
    #[test]
    fn round_trip_every_split() {
        let det = detector();
        let v = Vault::new();
        let original = b"a john@acme.com b Project Hufflepuff c jane@x.io".to_vec();
        let masked = mask(&original, &det, &v, MaskStyle::TypedSentinel);

        for split in 0..=masked.len() {
            let mut r = Rehydrator::new();
            let mut out = r.push(&masked[..split], &v);
            out.extend_from_slice(&r.push(&masked[split..], &v));
            out.extend_from_slice(&r.finish());
            assert_eq!(out, original, "failed at split {split}");
        }
    }

    /// Byte-at-a-time streaming must also reconstruct exactly.
    #[test]
    fn round_trip_byte_by_byte() {
        let det = detector();
        let v = Vault::new();
        let original = b"x john@acme.com y".to_vec();
        let masked = mask(&original, &det, &v, MaskStyle::TypedSentinel);

        let mut r = Rehydrator::new();
        let mut out = Vec::new();
        for b in &masked {
            out.extend_from_slice(&r.push(std::slice::from_ref(b), &v));
        }
        out.extend_from_slice(&r.finish());
        assert_eq!(out, original);
    }

    /// A sentinel-shaped token with an id we never issued passes through verbatim.
    #[test]
    fn unknown_id_passes_through() {
        let v = Vault::new(); // empty store
        let input = b"before \xE2\x9F\xA6S:EMAIL\xC2\xB7zz\xE2\x9F\xA7 after";
        let out = rehydrate_all(input, &v);
        assert_eq!(out, input);
    }

    /// Plain text with no sentinels is untouched.
    #[test]
    fn passthrough_plain_text() {
        let v = Vault::new();
        let input = b"the quick brown fox";
        assert_eq!(rehydrate_all(input, &v), input);
    }

    /// JsonString encoding escapes an original that would otherwise break the
    /// JSON frame it is spliced into, keeping the surrounding document valid.
    #[test]
    fn json_encoding_keeps_frame_valid() {
        // Original secret contains a quote, a backslash and a newline.
        let v = Vault::new();
        let id = v.intern(b"a\"b\\c\nd", Some("SECRET"));
        let mut masked = Vec::new();
        sentinel::encode(&mut masked, Some("SECRET"), id, v.tag(id));
        // Splice the sentinel inside a JSON content string, as a model would echo it.
        let frame = format!(r#"{{"content":"{}"}}"#, String::from_utf8(masked).unwrap());

        let mut r = Rehydrator::with_encoding(Encoding::JsonString);
        let mut out = r.push(frame.as_bytes(), &v);
        out.extend_from_slice(&r.finish());

        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["content"], "a\"b\\c\nd");
    }
}
