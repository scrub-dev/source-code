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

use std::collections::HashMap;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Forward (mask) and reverse (rehydrate) mapping for sentinel ids.
///
/// Implementors must guarantee: `resolve(intern(x), tag(intern(x))) == Some(x)`
/// within a scope, and that interning equal originals yields the same id
/// (determinism + dedup).
pub trait MappingStore: Send + Sync {
    /// Record `original` (optionally typed) and return its stable id.
    fn intern(&self, original: &[u8], ty: Option<&str>) -> u32;
    /// The keyed MAC tag for `id`, embedded in the sentinel. Only sentinels this
    /// store issued (matching tag) will rehydrate, so a hostile upstream cannot
    /// forge one to read an arbitrary entry.
    fn tag(&self, id: u32) -> u32;
    /// Resolve `id` to its original bytes, but only if `tag` authenticates it
    /// (else `None` — the sentinel is emitted verbatim).
    fn resolve(&self, id: u32, tag: u32) -> Option<Vec<u8>>;
    /// Number of distinct originals held.
    fn len(&self) -> usize;
    /// True when no originals are held.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Keyed MAC (truncated HMAC-SHA256) of an id under `key`. 32 bits is ample: an
/// attacker gets no oracle, and each forgery attempt costs a full model round
/// trip, so 2^32 is far out of reach.
fn mac(key: &[u8; 32], id: u32) -> u32 {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(&id.to_le_bytes());
    let out = m.finalize().into_bytes();
    u32::from_le_bytes([out[0], out[1], out[2], out[3]])
}

/// A fresh random tag key from the system RNG.
fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("system RNG");
    k
}

#[derive(Default)]
struct Inner {
    next: u32,
    /// original bytes -> id, for dedup/determinism. Keyed by the *exact* original
    /// (not a truncated hash), so two distinct secrets can never be conflated
    /// into the same sentinel — a mis-rehydration would disclose one secret in
    /// place of another in a shared session vault.
    forward: HashMap<Vec<u8>, u32>,
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

/// Reserved id meaning "id space exhausted": the original is masked (hidden from
/// the upstream) but not stored, so it never collides with another node's range;
/// [`MappingStore::resolve`] returns `None` for it.
const OVERFLOW_ID: u32 = u32::MAX;

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
    /// Secret key that authenticates this vault's sentinels (see [`mac`]). Random
    /// per request/registry vault; for cross-node session vaults it is derived so
    /// every node agrees (see `from_entries_in_keyed`).
    tag_key: [u8; 32],
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

    /// A vault that allocates ids from `space` (node-disjoint cross-node ids),
    /// with a fresh random tag key.
    pub fn with_id_space(space: IdSpace) -> Self {
        Self {
            inner: Mutex::new(Inner {
                next: space.base,
                forward: HashMap::new(),
                reverse: HashMap::new(),
            }),
            space,
            tag_key: random_key(),
        }
    }

    /// Build a vault preloaded with `(id, original)` entries from a shared store.
    pub fn from_entries(entries: Vec<(u32, Vec<u8>)>) -> Self {
        Self::from_entries_in(entries, IdSpace::FULL)
    }

    /// Like [`from_entries`](Self::from_entries) but allocating new ids from
    /// `space` (fresh random tag key).
    pub fn from_entries_in(entries: Vec<(u32, Vec<u8>)>, space: IdSpace) -> Self {
        Self::from_entries_in_keyed(entries, space, random_key())
    }

    /// Like [`from_entries_in`](Self::from_entries_in) but with an explicit
    /// `tag_key`. Cross-node session backends derive a stable key per session so a
    /// sentinel minted on one node authenticates on another.
    pub fn from_entries_in_keyed(
        entries: Vec<(u32, Vec<u8>)>,
        space: IdSpace,
        tag_key: [u8; 32],
    ) -> Self {
        let mut inner = Inner {
            next: space.base,
            forward: HashMap::new(),
            reverse: HashMap::new(),
        };
        for (id, original) in entries {
            inner.forward.insert(original.clone(), id);
            if space.contains(id) {
                inner.next = inner.next.max(id + 1);
            }
            inner.reverse.insert(id, original);
        }
        Self {
            inner: Mutex::new(inner),
            space,
            tag_key,
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
        let mut inner = self.inner.lock().unwrap();
        if let Some(&id) = inner.forward.get(original) {
            return id;
        }
        // Never allocate at/after this vault's space end — that range belongs to
        // another node, and minting there would let a sentinel rehydrate to the
        // wrong secret across nodes. On exhaustion, mask with the reserved
        // OVERFLOW_ID: the value is still hidden from the upstream, it just won't
        // rehydrate (fail-safe — no cross-node confusion, no leak).
        if inner.next >= self.space.end || inner.next == OVERFLOW_ID {
            return OVERFLOW_ID;
        }
        let id = inner.next;
        inner.next += 1;
        inner.forward.insert(original.to_vec(), id);
        inner.reverse.insert(id, original.to_vec());
        id
    }

    fn tag(&self, id: u32) -> u32 {
        mac(&self.tag_key, id)
    }

    fn resolve(&self, id: u32, tag: u32) -> Option<Vec<u8>> {
        if id == OVERFLOW_ID {
            return None;
        }
        // Authenticate the sentinel: reject a forged/echoed one whose tag we did
        // not issue for this id (constant-time compare).
        if !bool::from(mac(&self.tag_key, id).ct_eq(&tag)) {
            return None;
        }
        self.inner.lock().unwrap().reverse.get(&id).cloned()
    }

    fn len(&self) -> usize {
        self.inner.lock().unwrap().reverse.len()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // Secure destruction (DESIGN §7): wipe every copy of the originals — both
        // the reverse values and the forward keys now hold plaintext.
        if let Ok(mut inner) = self.inner.lock() {
            for v in inner.reverse.values_mut() {
                v.zeroize();
            }
            for (mut k, _) in inner.forward.drain() {
                k.zeroize();
            }
        }
        self.tag_key.zeroize();
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
    fn distinct_originals_never_share_an_id() {
        // Dedup is keyed by the exact bytes, so different secrets can never be
        // conflated (which would mis-rehydrate one as the other).
        let v = Vault::new();
        let mut ids = std::collections::HashSet::new();
        for i in 0..2000u32 {
            let id = v.intern(format!("secret-{i}").as_bytes(), None);
            assert!(ids.insert(id), "id {id} reused for a distinct original");
        }
        // Same original still dedups to the same id.
        assert_eq!(v.intern(b"secret-1", None), v.intern(b"secret-1", None));
        // Each id resolves back to its own original.
        let id7 = v.intern(b"secret-7", None);
        assert_eq!(
            v.resolve(id7, v.tag(id7)).as_deref(),
            Some(&b"secret-7"[..])
        );
    }

    #[test]
    fn resolve_rejects_a_forged_or_wrong_tag() {
        // A sentinel with a guessed id but a tag we did not issue never resolves —
        // this is what stops a hostile upstream from echoing ⟦S·0⟧ to read the vault.
        let v = Vault::new();
        let id = v.intern(b"alice@corp.com", Some("EMAIL"));
        let good = v.tag(id);
        assert_eq!(v.resolve(id, good).as_deref(), Some(&b"alice@corp.com"[..]));
        assert_eq!(
            v.resolve(id, good.wrapping_add(1)),
            None,
            "wrong tag rejected"
        );
        assert_eq!(v.resolve(id, 0), None, "zero/absent tag rejected");
        // A different vault's key yields a different tag for the same id.
        let v2 = Vault::new();
        assert_ne!(v.tag(id), v2.tag(id), "tags are vault-specific (keyed)");
    }

    #[test]
    fn exhausted_space_never_crosses_into_the_next_node() {
        // Node A owns [10, 13); after 3 originals it must not mint id 13+ (node B's
        // range) — it returns the reserved overflow id instead.
        let a = Vault::with_id_space(IdSpace { base: 10, end: 13 });
        assert_eq!(a.intern(b"x", None), 10);
        assert_eq!(a.intern(b"y", None), 11);
        assert_eq!(a.intern(b"z", None), 12);
        // Exhausted: further distinct originals get the non-reversible overflow id.
        let of = a.intern(b"w", None);
        assert_eq!(of, u32::MAX);
        assert!(of < 13 || of == u32::MAX); // never in [13, ..) node B's space
        assert_eq!(a.intern(b"another", None), u32::MAX);
        // Overflow ids are masked but never rehydrate (fail-safe).
        assert_eq!(a.resolve(u32::MAX, 0), None);
        // Already-mapped originals still resolve correctly.
        assert_eq!(a.resolve(11, a.tag(11)).as_deref(), Some(&b"y"[..]));
    }

    #[test]
    fn resolve_roundtrips() {
        let v = Vault::new();
        let id = v.intern(b"secret", None);
        assert_eq!(v.resolve(id, v.tag(id)), Some(b"secret".to_vec()));
        assert_eq!(v.resolve(999, v.tag(999)), None);
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
        assert_eq!(
            restored.resolve(b, restored.tag(b)),
            Some(b"bob@y.com".to_vec())
        );
        // a new original gets a fresh, non-colliding id
        let c = restored.intern(b"carol@z.com", Some("EMAIL"));
        assert!(c != a && c != b);
    }
}
