//! The sentinel grammar (DESIGN §2).
//!
//! ```text
//! sentinel := PREFIX [ ":" TYPE ] SEP ID SUFFIX
//! PREFIX   := "⟦S"
//! SUFFIX   := "⟧"
//! SEP      := "·"
//! TYPE     := [A-Z]+
//! ID       := base62(u32)        // index into the request reverse table
//! ```
//!
//! The prefix is rare and self-delimiting, so the return-path scan is a single
//! `memmem` for `PREFIX` followed by a bounded parse to `SUFFIX`. The id is an
//! *index*, never the data — the secret stays in SCRUB's memory.

/// Visible prefix that opens every sentinel. Chosen to be rare in real payloads.
pub const PREFIX: &str = "⟦S";
/// Closes every sentinel.
pub const SUFFIX: &str = "⟧";
/// Separates the optional type from the id.
pub const SEP: &str = "·";
/// Separates the `S` marker from the type.
pub const TYPE_SEP: &str = ":";

/// Upper bound on a well-formed sentinel's byte length. The rehydrator never
/// buffers more than this waiting for a `SUFFIX`, which bounds memory and makes
/// "prefix present but no terminator" decidable. `u32` base62 is <= 6 chars, the
/// type is short; 64 bytes is comfortable headroom.
pub const MAX_SENTINEL_LEN: usize = 64;

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Append `⟦S[:TYPE]·ID⟧` to `out` for the given reverse-table index.
pub fn encode(out: &mut Vec<u8>, ty: Option<&str>, id: u32) {
    out.extend_from_slice(PREFIX.as_bytes());
    if let Some(t) = ty {
        out.extend_from_slice(TYPE_SEP.as_bytes());
        out.extend_from_slice(t.as_bytes());
    }
    out.extend_from_slice(SEP.as_bytes());
    encode_base62(out, id);
    out.extend_from_slice(SUFFIX.as_bytes());
}

/// Encode `n` as base62 (most-significant first). `0` encodes as `"0"`.
pub fn encode_base62(out: &mut Vec<u8>, mut n: u32) {
    if n == 0 {
        out.push(BASE62[0]);
        return;
    }
    let start = out.len();
    while n > 0 {
        out.push(BASE62[(n % 62) as usize]);
        n /= 62;
    }
    out[start..].reverse();
}

/// Decode a base62 id. Returns `None` on empty input, a non-base62 byte, or
/// `u32` overflow (any of which means "not a sentinel we issued").
pub fn decode_base62(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut n: u32 = 0;
    for &b in bytes {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'A'..=b'Z' => b - b'A' + 10,
            b'a'..=b'z' => b - b'a' + 36,
            _ => return None,
        } as u32;
        n = n.checked_mul(62)?.checked_add(d)?;
    }
    Some(n)
}

/// Given a slice that begins exactly at `PREFIX`, try to parse one complete
/// sentinel. Returns `(id, total_byte_len)` on success.
///
/// `None` means: not enough bytes yet, no terminator within `MAX_SENTINEL_LEN`,
/// or a malformed body. Callers distinguish "incomplete, wait for more" from
/// "malformed, emit literally" using whether `buf` already holds the bound.
pub fn parse(buf: &[u8]) -> Option<(u32, usize)> {
    debug_assert!(buf.starts_with(PREFIX.as_bytes()));
    let window = &buf[..buf.len().min(MAX_SENTINEL_LEN)];
    let suffix_at = memchr::memmem::find(window, SUFFIX.as_bytes())?;
    let body = &buf[PREFIX.len()..suffix_at];
    // The id is whatever follows the last SEP (type, if present, has no SEP).
    let sep_at = memchr::memmem::rfind(body, SEP.as_bytes())?;
    let id_bytes = &body[sep_at + SEP.len()..];
    let id = decode_base62(id_bytes)?;
    Some((id, suffix_at + SUFFIX.len()))
}

/// Length of the longest suffix of `buf` that is a proper prefix of `PREFIX`.
/// Used to decide how few trailing bytes to hold back when no full prefix is
/// present but the chunk might end mid-prefix (e.g. ends with `⟦`).
pub fn dangling_prefix_len(buf: &[u8]) -> usize {
    let p = PREFIX.as_bytes();
    let max = p.len().min(buf.len());
    for k in (1..=max).rev() {
        if buf[buf.len() - k..] == p[..k] {
            return k;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base62_roundtrips() {
        for n in [0u32, 1, 61, 62, 1000, u32::MAX] {
            let mut b = Vec::new();
            encode_base62(&mut b, n);
            assert_eq!(decode_base62(&b), Some(n), "n={n}");
        }
    }

    #[test]
    fn encode_parse_roundtrips() {
        let mut b = Vec::new();
        encode(&mut b, Some("EMAIL"), 0x7f3a);
        assert!(b.starts_with(PREFIX.as_bytes()));
        let (id, len) = parse(&b).unwrap();
        assert_eq!(id, 0x7f3a);
        assert_eq!(len, b.len());
    }

    #[test]
    fn parse_untyped() {
        let mut b = Vec::new();
        encode(&mut b, None, 42);
        let (id, len) = parse(&b).unwrap();
        assert_eq!(id, 42);
        assert_eq!(len, b.len());
    }

    #[test]
    fn parse_incomplete_is_none() {
        let mut b = Vec::new();
        encode(&mut b, Some("EMAIL"), 7);
        b.truncate(b.len() - SUFFIX.len()); // drop terminator
        assert!(parse(&b).is_none());
    }

    #[test]
    fn dangling_prefix_detection() {
        assert_eq!(dangling_prefix_len(b"hello"), 0);
        // ends with the first byte(s) of "⟦"
        let p = PREFIX.as_bytes();
        let mut s = b"hello".to_vec();
        s.extend_from_slice(&p[..2]);
        assert_eq!(dangling_prefix_len(&s), 2);
    }
}
