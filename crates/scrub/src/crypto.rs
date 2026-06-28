//! At-rest encryption for session vaults stored in a shared backend (DESIGN §7).
//!
//! Secrets in a session vault would otherwise sit in Redis as plaintext. With an
//! `encryption_key` configured, the serialized vault is sealed with AES-256-GCM
//! (authenticated) before it leaves the process, so the store only ever holds
//! ciphertext. The key is derived from the configured passphrase via SHA-256 and
//! must match across nodes.
//!
//! Use a high-entropy passphrase: SHA-256 is not a password-stretching KDF.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};

const NONCE_LEN: usize = 12;

/// AES-256-GCM sealer for session blobs. Ciphertext layout: `nonce || sealed`.
#[derive(Clone)]
pub struct Cipher {
    gcm: Aes256Gcm,
}

impl Cipher {
    /// Derive a key from `passphrase` (SHA-256) and build a cipher.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        let key = hasher.finalize();
        let gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        Self { gcm }
    }

    /// Seal `plaintext` with a fresh random nonce. Returns `nonce || ciphertext`.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).expect("system RNG");
        let ct = self
            .gcm
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("AES-GCM encrypt");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Open a `nonce || ciphertext` blob. `None` on tamper / wrong key / short input.
    pub fn open(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < NONCE_LEN {
            return None;
        }
        let (nonce, ct) = data.split_at(NONCE_LEN);
        self.gcm.decrypt(Nonce::from_slice(nonce), ct).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrips() {
        let c = Cipher::from_passphrase("correct horse battery staple");
        let pt = b"some serialized session secrets";
        let blob = c.seal(pt);
        assert_ne!(
            &blob[NONCE_LEN..],
            pt,
            "ciphertext must differ from plaintext"
        );
        assert_eq!(c.open(&blob).as_deref(), Some(&pt[..]));
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let a = Cipher::from_passphrase("key-a");
        let b = Cipher::from_passphrase("key-b");
        let blob = a.seal(b"secret");
        assert_eq!(b.open(&blob), None);
    }

    #[test]
    fn fresh_nonce_each_seal() {
        let c = Cipher::from_passphrase("k");
        assert_ne!(
            c.seal(b"x"),
            c.seal(b"x"),
            "nonce should randomize ciphertext"
        );
    }
}
