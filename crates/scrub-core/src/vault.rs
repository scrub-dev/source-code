//! Reverse/forward mapping between originals and sentinel ids (DESIGN §2, §3).
//!
//! A [`Vault`] is thread-safe and used two ways:
//! - **request-scoped**: one per request, dropped (and zeroized) at response end;
//! - **session-scoped**: shared via `Arc` across a conversation's requests so the
//!   same original keeps the same pseudonym, retained until TTL eviction.
//!
//! Because a session vault is shared under a lock, [`MappingStore::resolve`]
//! returns *owned* bytes (a transient clone of the original we're about to emit
//! anyway) rather than a borrow held across the lock.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

use zeroize::Zeroize;

/// Forward (mask) and reverse (rehydrate) mapping for sentinel ids.
///
/// Implementors must guarantee: `resolve(intern(x)) == Some(x)` within a scope,
/// and that interning equal originals yields the same id (determinism + dedup).
pub trait MappingStore: Send + Sync {
    /// Record `original` (optionally typed) and return its stable id.
    fn intern(&self, original: &[u8], ty: Option<&str>) -> u32;
    /// Resolve an id back to its original bytes, or `None` if unknown.
    fn resolve(&self, id: u32) -> Option<Vec<u8>>;
    /// Number of distinct originals held.
    fn len(&self) -> usize;
    /// True when no originals are held.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Default)]
struct Inner {
    next: u32,
    /// content-hash(original) -> id, for dedup/determinism.
    forward: HashMap<u64, u32>,
    /// id -> original bytes.
    reverse: HashMap<u32, Vec<u8>>,
}

/// A half-open `[base, end)` id range a vault allocates from. For cross-node
/// sessions each node gets a disjoint space, so concurrent nodes never assign
/// the same id to different originals (DESIGN §8 v3). Dedup still works because
/// the forward map is rebuilt from *all* entries regardless of space.
#[derive(Debug, Clone, Copy)]
pub struct IdSpace {
    pub base: u32,
    pub end: u32,
}

impl IdSpace {
    /// The whole `u32` range (single-node / request scope).
    pub const FULL: IdSpace = IdSpace {
        base: 0,
        end: u32::MAX,
    };

    fn contains(&self, id: u32) -> bool {
        id >= self.base && id < self.end
    }
}

impl Default for IdSpace {
    fn default() -> Self {
        Self::FULL
    }
}

/// In-memory, thread-safe mapping. Dropping it securely wipes the originals.
pub struct Vault {
    inner: Mutex<Inner>,
    space: IdSpace,
}

/// Back-compat alias: the request-scoped use of a [`Vault`].
pub type RequestVault = Vault;

impl Default for Vault {
    fn default() -> Self {
        Self::with_id_space(IdSpace::FULL)
    }
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    /// A vault that allocates ids from `space` (node-disjoint cross-node ids).
    pub fn with_id_space(space: IdSpace) -> Self {
        Self {
            inner: Mutex::new(Inner {
                next: space.base,
                forward: HashMap::new(),
                reverse: HashMap::new(),
            }),
            space,
        }
    }

    /// Build a vault preloaded with `(id, original)` entries from a shared store.
    pub fn from_entries(entries: Vec<(u32, Vec<u8>)>) -> Self {
        Self::from_entries_in(entries, IdSpace::FULL)
    }

    /// Like [`from_entries`](Self::from_entries) but allocating new ids from
    /// `space`. Existing entries from *all* spaces are kept for dedup/rehydrate;
    /// the next id only advances past this space's own existing ids.
    pub fn from_entries_in(entries: Vec<(u32, Vec<u8>)>, space: IdSpace) -> Self {
        let mut inner = Inner {
            next: space.base,
            forward: HashMap::new(),
            reverse: HashMap::new(),
        };
        for (id, original) in entries {
            let mut h = DefaultHasher::new();
            original.hash(&mut h);
            inner.forward.insert(h.finish(), id);
            if space.contains(id) {
                inner.next = inner.next.max(id + 1);
            }
            inner.reverse.insert(id, original);
        }
        Self {
            inner: Mutex::new(inner),
            space,
        }
    }

    /// Snapshot all `(id, original)` entries.
    pub fn entries(&self) -> Vec<(u32, Vec<u8>)> {
        self.inner
            .lock()
            .unwrap()
            .reverse
            .iter()
            .map(|(&id, v)| (id, v.clone()))
            .collect()
    }

    /// Snapshot only the entries this vault allocated (ids in its own space).
    /// These are the fields a node commits to the shared store — it never writes
    /// another node's fields, so concurrent commits can't clobber each other.
    pub fn entries_in_space(&self) -> Vec<(u32, Vec<u8>)> {
        let space = self.space;
        self.inner
            .lock()
            .unwrap()
            .reverse
            .iter()
            .filter(|(&id, _)| space.contains(id))
            .map(|(&id, v)| (id, v.clone()))
            .collect()
    }
}

impl MappingStore for Vault {
    fn intern(&self, original: &[u8], _ty: Option<&str>) -> u32 {
        let mut h = DefaultHasher::new();
        original.hash(&mut h);
        let key = h.finish();

        let mut inner = self.inner.lock().unwrap();
        if let Some(&id) = inner.forward.get(&key) {
            return id;
        }
        let id = inner.next;
        inner.next += 1;
        inner.forward.insert(key, id);
        inner.reverse.insert(id, original.to_vec());
        id
    }

    fn resolve(&self, id: u32) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().reverse.get(&id).cloned()
    }

    fn len(&self) -> usize {
        self.inner.lock().unwrap().reverse.len()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // Secure destruction (DESIGN §7): wipe originals; forget the hashes.
        if let Ok(mut inner) = self.inner.lock() {
            for v in inner.reverse.values_mut() {
                v.zeroize();
            }
            inner.forward.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_dedups_equal_originals() {
        let v = Vault::new();
        let a = v.intern(b"john@acme.com", Some("EMAIL"));
        let b = v.intern(b"john@acme.com", Some("EMAIL"));
        let c = v.intern(b"jane@acme.com", Some("EMAIL"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn resolve_roundtrips() {
        let v = Vault::new();
        let id = v.intern(b"secret", None);
        assert_eq!(v.resolve(id), Some(b"secret".to_vec()));
        assert_eq!(v.resolve(999), None);
    }

    #[test]
    fn id_spaces_are_disjoint_but_dedup_is_global() {
        // Two "nodes" with disjoint id ranges.
        let space_a = IdSpace { base: 0, end: 1000 };
        let space_b = IdSpace {
            base: 1000,
            end: 2000,
        };

        let a = Vault::with_id_space(space_a);
        let ida = a.intern(b"alice", None); // 0, in A's space
        assert!(space_a.contains(ida));

        // Node B loads A's committed entry, then interns its own.
        let b = Vault::from_entries_in(a.entries(), space_b);
        // dedup across spaces: B reuses A's id for the same original
        assert_eq!(b.intern(b"alice", None), ida);
        let idb = b.intern(b"bob", None); // new -> in B's space, can't collide with A
        assert!(space_b.contains(idb));
        assert_ne!(idb, ida);

        // B only commits its own entries (not A's).
        let b_fields = b.entries_in_space();
        assert_eq!(b_fields.len(), 1);
        assert_eq!(b_fields[0].0, idb);
    }

    #[test]
    fn export_import_roundtrips_and_continues_ids() {
        let v = Vault::new();
        let a = v.intern(b"alice@x.com", Some("EMAIL"));
        let b = v.intern(b"bob@y.com", Some("EMAIL"));

        let restored = Vault::from_entries(v.entries());
        // existing originals keep their ids (dedup map rebuilt)
        assert_eq!(restored.intern(b"alice@x.com", Some("EMAIL")), a);
        assert_eq!(restored.resolve(b), Some(b"bob@y.com".to_vec()));
        // a new original gets a fresh, non-colliding id
        let c = restored.intern(b"carol@z.com", Some("EMAIL"));
        assert!(c != a && c != b);
    }
}
