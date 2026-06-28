//! TLS interception (SNI-transparent MITM) certificate minting (DESIGN §8 v5).
//!
//! Terminates client TLS by minting a per-host leaf certificate on the fly,
//! signed by a configured CA the client trusts. Routing/masking then proceed as
//! usual against the real upstream. This is *not* a CONNECT proxy — clients reach
//! SCRUB transparently (DNS/SNI redirection) and trust SCRUB's CA.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{Certificate, CertificateParams, DnType, KeyPair};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Mints and caches per-SNI leaf certificates signed by the configured CA.
pub struct CertMinter {
    ca_cert: Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertMinter {
    /// Build a minter from a PEM CA certificate and private key.
    pub fn from_ca_pem(ca_cert_pem: &str, ca_key_pem: &str) -> anyhow::Result<Self> {
        let ca_key = KeyPair::from_pem(ca_key_pem)?;
        // Reconstruct the CA cert so its DN/extensions are used as the issuer.
        let ca_cert = CertificateParams::from_ca_cert_pem(ca_cert_pem)?.self_signed(&ca_key)?;
        Ok(Self {
            ca_cert,
            ca_key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Get (or mint and cache) a leaf certificate for `host`.
    fn cert_for(&self, host: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        if let Some(ck) = self.cache.lock().unwrap().get(host) {
            return Ok(ck.clone());
        }
        let ck = Arc::new(self.mint(host)?);
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), ck.clone());
        Ok(ck)
    }

    fn mint(&self, host: &str) -> anyhow::Result<CertifiedKey> {
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        let leaf_key = KeyPair::generate()?;
        let cert = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;

        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
        Ok(CertifiedKey::new(vec![cert.der().clone()], signing_key))
    }
}

impl std::fmt::Debug for CertMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertMinter")
    }
}

impl ResolvesServerCert for CertMinter {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name()?;
        match self.cert_for(host) {
            Ok(ck) => Some(ck),
            Err(e) => {
                tracing::warn!(%host, error = %e, "failed to mint intercept cert");
                None
            }
        }
    }
}

/// Build a rustls `ServerConfig` that mints certs per-SNI via `minter`.
pub fn server_config(minter: Arc<CertMinter>) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(minter);
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed CA for tests: returns (cert_pem, key_pem).
    pub fn test_ca() -> (String, String) {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "SCRUB Test CA");
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn mints_leaf_for_host() {
        let (ca_cert, ca_key) = test_ca();
        let minter = CertMinter::from_ca_pem(&ca_cert, &ca_key).unwrap();
        let a = minter.cert_for("api.openai.com").unwrap();
        let b = minter.cert_for("api.openai.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "second mint should be cached");
        assert!(!a.cert.is_empty(), "leaf chain present");
        // a different host mints a distinct cert
        let c = minter.cert_for("api.anthropic.com").unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
    }
}
