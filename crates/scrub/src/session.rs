//! Session-scoped mapping registry (DESIGN §2 determinism boundary).
//!
//! When a route uses `scope: session`, all requests carrying the same session
//! key share one [`Vault`], so a given original keeps a stable pseudonym across
//! a multi-turn conversation. Entries are evicted after `ttl` of inactivity; the
//! dropped `Vault` zeroizes its secrets.
//!
//! Time/TTL handling lives here (runtime concern), keeping `scrub-core` free of
//! clocks and background threads.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use scrub_core::vault::{IdSpace, Vault};

use crate::crypto::Cipher;

/// Pluggable storage for session vaults (DESIGN §8 v3). The proxy acquires a
/// working [`Vault`] for a session, masks/rehydrates with it, then commits any
/// new entries back. The in-memory backend shares one `Vault` per key; the
/// KV/Redis backend load-modify-stores so sessions span nodes.
#[async_trait]
pub trait SessionBackend: Send + Sync {
    /// Obtain the working vault for `key` (preloaded with existing entries).
    async fn acquire(&self, key: &str) -> Arc<Vault>;
    /// Persist the vault's entries for `key` (no-op when already shared).
    async fn commit(&self, key: &str, vault: &Vault);
    /// Evict idle sessions if this backend manages TTL locally; else 0.
    fn sweep(&self) -> usize {
        0
    }
}

/// In-memory backend: one shared `Vault` per session key (single-node fast path).
pub struct MemoryBackend {
    registry: Arc<SessionRegistry>,
}

impl MemoryBackend {
    pub fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            registry: SessionRegistry::new(ttl),
        })
    }
}

#[async_trait]
impl SessionBackend for MemoryBackend {
    async fn acquire(&self, key: &str) -> Arc<Vault> {
        self.registry.get_or_create(key)
    }
    async fn commit(&self, _key: &str, _vault: &Vault) {
        // The Arc is already shared; nothing to persist.
    }
    fn sweep(&self) -> usize {
        self.registry.sweep()
    }
}

/// A simple key/value store (e.g. Redis) holding serialized session vaults.
#[async_trait]
pub trait KvStore: Send + Sync {
    /// All `(field, value)` pairs of the hash at `key`.
    async fn hgetall(&self, key: &str) -> Vec<(String, Vec<u8>)>;
    /// Set the given hash fields and (re)set the key's TTL. Concurrent calls that
    /// touch disjoint fields must not clobber each other (atomic per field).
    async fn hset_with_ttl(&self, key: &str, fields: &[(String, Vec<u8>)], ttl: Duration);
}

/// Bits of the id reserved for the node; the rest is the per-node counter.
const NODE_BITS: u32 = 12; // up to 4096 nodes
const COUNTER_BITS: u32 = u32::BITS - NODE_BITS; // ~1M ids per session per node

/// The disjoint id space owned by `node_id` (DESIGN §8 v3).
pub fn id_space_for_node(node_id: u16) -> IdSpace {
    let base = (node_id as u32 & ((1 << NODE_BITS) - 1)) << COUNTER_BITS;
    let end = base.saturating_add(1 << COUNTER_BITS);
    IdSpace { base, end }
}

/// Cross-node session backend over a [`KvStore`]. Each session is a hash whose
/// fields are `id -> original`; a node only ever writes ids from its own
/// [`IdSpace`], so concurrent commits from different nodes merge (no entry loss)
/// and ids never collide. With a [`Cipher`], each field value is sealed so the
/// store only holds ciphertext (DESIGN §7, §8 v3).
pub struct KvSessionBackend {
    kv: Arc<dyn KvStore>,
    ttl: Duration,
    cipher: Option<Cipher>,
    space: IdSpace,
}

impl KvSessionBackend {
    /// Plaintext backend for `node_id`.
    pub fn new(kv: Arc<dyn KvStore>, ttl: Duration, node_id: u16) -> Arc<Self> {
        Arc::new(Self {
            kv,
            ttl,
            cipher: None,
            space: id_space_for_node(node_id),
        })
    }

    /// Backend for `node_id` that seals stored field values with `cipher`.
    pub fn encrypted(
        kv: Arc<dyn KvStore>,
        ttl: Duration,
        cipher: Cipher,
        node_id: u16,
    ) -> Arc<Self> {
        Arc::new(Self {
            kv,
            ttl,
            cipher: Some(cipher),
            space: id_space_for_node(node_id),
        })
    }
}

#[async_trait]
impl SessionBackend for KvSessionBackend {
    async fn acquire(&self, key: &str) -> Arc<Vault> {
        let mut entries = Vec::new();
        for (field, value) in self.kv.hgetall(key).await {
            let Ok(id) = field.parse::<u32>() else {
                continue;
            };
            let original = match &self.cipher {
                Some(c) => match c.open(&value) {
                    Some(o) => o,
                    None => continue, // tampered / wrong key -> skip
                },
                None => value,
            };
            entries.push((id, original));
        }
        Arc::new(Vault::from_entries_in(entries, self.space))
    }

    async fn commit(&self, key: &str, vault: &Vault) {
        // Only this node's own ids — never overwrite another node's fields.
        let fields: Vec<(String, Vec<u8>)> = vault
            .entries_in_space()
            .into_iter()
            .map(|(id, original)| {
                let value = match &self.cipher {
                    Some(c) => c.seal(&original),
                    None => original,
                };
                (id.to_string(), value)
            })
            .collect();
        if !fields.is_empty() {
            self.kv.hset_with_ttl(key, &fields, self.ttl).await;
        }
    }
}

struct Entry {
    vault: Arc<Vault>,
    last_access: Instant,
}

/// A keyed set of session vaults with inactivity-based eviction.
pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, Entry>>,
    ttl: Duration,
}

impl SessionRegistry {
    pub fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            ttl,
        })
    }

    /// Return the vault for `key`, creating it on first use, and mark it active.
    pub fn get_or_create(&self, key: &str) -> Arc<Vault> {
        let mut sessions = self.sessions.lock().unwrap();
        let entry = sessions.entry(key.to_string()).or_insert_with(|| Entry {
            vault: Arc::new(Vault::new()),
            last_access: Instant::now(),
        });
        entry.last_access = Instant::now();
        entry.vault.clone()
    }

    /// Evict entries idle for longer than `ttl`. Returns the number removed.
    pub fn sweep(&self) -> usize {
        let mut sessions = self.sessions.lock().unwrap();
        let before = sessions.len();
        let ttl = self.ttl;
        sessions.retain(|_, e| e.last_access.elapsed() < ttl);
        before - sessions.len()
    }

    /// Current number of live sessions.
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse a simple duration string: a bare number is seconds, or a suffixed
/// `s`/`m`/`h`/`d` value (e.g. `30m`, `1h`, `45s`). Falls back to `default` on
/// an empty or unparseable input.
pub fn parse_duration(s: Option<&str>, default: Duration) -> Duration {
    let Some(s) = s.map(str::trim).filter(|s| !s.is_empty()) else {
        return default;
    };
    let (num, unit): (&str, u64) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return default,
    };
    match num.trim().parse::<u64>() {
        Ok(n) => Duration::from_secs(n * unit),
        Err(_) => default,
    }
}

/// In-memory hash [`KvStore`] for tests: simulates a shared external store (e.g.
/// one Redis) so multiple `AppState`s can model multi-node session sharing.
/// Per-field semantics match Redis hashes; TTL is ignored.
#[derive(Default)]
pub struct InMemoryKv {
    map: Mutex<HashMap<String, HashMap<String, Vec<u8>>>>,
}

#[async_trait]
impl KvStore for InMemoryKv {
    async fn hgetall(&self, key: &str) -> Vec<(String, Vec<u8>)> {
        self.map
            .lock()
            .unwrap()
            .get(key)
            .map(|h| h.iter().map(|(f, v)| (f.clone(), v.clone())).collect())
            .unwrap_or_default()
    }
    async fn hset_with_ttl(&self, key: &str, fields: &[(String, Vec<u8>)], _ttl: Duration) {
        let mut map = self.map.lock().unwrap();
        let hash = map.entry(key.to_string()).or_default();
        for (f, v) in fields {
            hash.insert(f.clone(), v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrub_core::vault::MappingStore;

    const TTL: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn kv_backend_load_modify_store() {
        let kv = Arc::new(InMemoryKv::default());
        let backend = KvSessionBackend::new(kv.clone(), TTL, 0);

        // Node 1: intern an original and commit.
        let v1 = backend.acquire("s").await;
        let id = v1.intern(b"secret-value", Some("SECRET"));
        backend.commit("s", &v1).await;

        // Node 2 (fresh backend over the SAME kv): sees the committed entry.
        let backend2 = KvSessionBackend::new(kv, TTL, 0);
        let v2 = backend2.acquire("s").await;
        assert_eq!(v2.resolve(id), Some(b"secret-value".to_vec()));
        // and dedups the same original to the same id
        assert_eq!(v2.intern(b"secret-value", Some("SECRET")), id);
    }

    #[tokio::test]
    async fn encrypted_backend_stores_ciphertext_and_roundtrips() {
        let kv = Arc::new(InMemoryKv::default());
        let cipher = crate::crypto::Cipher::from_passphrase("a-strong-shared-key");
        let backend = KvSessionBackend::encrypted(kv.clone(), TTL, cipher, 0);

        let v = backend.acquire("s").await;
        let id = v.intern(b"top-secret-value", Some("SECRET"));
        backend.commit("s", &v).await;

        // Every stored field value is ciphertext — the plaintext must not appear.
        for (_field, value) in kv.hgetall("s").await {
            assert!(
                !value.windows(16).any(|w| w == b"top-secret-value"),
                "secret leaked to store in plaintext"
            );
        }

        // A second node with the SAME key rehydrates correctly.
        let cipher2 = crate::crypto::Cipher::from_passphrase("a-strong-shared-key");
        let backend2 = KvSessionBackend::encrypted(kv, TTL, cipher2, 0);
        let v2 = backend2.acquire("s").await;
        assert_eq!(v2.resolve(id), Some(b"top-secret-value".to_vec()));
    }

    /// The correctness fix: two nodes interning *different* originals from the
    /// same pre-commit view must not lose either entry, and ids must not collide.
    #[tokio::test]
    async fn concurrent_nodes_dont_lose_or_collide() {
        let kv = Arc::new(InMemoryKv::default());
        let node_a = KvSessionBackend::new(kv.clone(), TTL, 0);
        let node_b = KvSessionBackend::new(kv.clone(), TTL, 1);

        // Both load the (empty) session before either commits.
        let va = node_a.acquire("s").await;
        let vb = node_b.acquire("s").await;
        let id_x = va.intern(b"secret-X", None);
        let id_y = vb.intern(b"secret-Y", None);
        assert_ne!(id_x, id_y, "node id-spaces must be disjoint");

        // Commit in interleaved order — neither clobbers the other's field.
        node_a.commit("s", &va).await;
        node_b.commit("s", &vb).await;

        // A later read sees BOTH originals (blob last-write-wins would lose one).
        let v = node_a.acquire("s").await;
        assert_eq!(v.resolve(id_x), Some(b"secret-X".to_vec()));
        assert_eq!(v.resolve(id_y), Some(b"secret-Y".to_vec()));
    }

    #[test]
    fn get_or_create_is_stable_per_key() {
        let reg = SessionRegistry::new(Duration::from_secs(60));
        let a = reg.get_or_create("s1");
        let b = reg.get_or_create("s1");
        let c = reg.get_or_create("s2");
        assert!(Arc::ptr_eq(&a, &b), "same key -> same vault");
        assert!(!Arc::ptr_eq(&a, &c), "different key -> different vault");
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn sweep_evicts_idle_sessions() {
        let reg = SessionRegistry::new(Duration::from_millis(20));
        let _ = reg.get_or_create("s1");
        assert_eq!(reg.len(), 1);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(reg.sweep(), 1);
        assert!(reg.is_empty());
    }

    #[test]
    fn duration_parsing() {
        let d = Duration::from_secs(99);
        assert_eq!(parse_duration(Some("30m"), d), Duration::from_secs(1800));
        assert_eq!(parse_duration(Some("1h"), d), Duration::from_secs(3600));
        assert_eq!(parse_duration(Some("45s"), d), Duration::from_secs(45));
        assert_eq!(parse_duration(Some("90"), d), Duration::from_secs(90));
        assert_eq!(parse_duration(Some(""), d), d);
        assert_eq!(parse_duration(None, d), d);
        assert_eq!(parse_duration(Some("garbage"), d), d);
    }
}
