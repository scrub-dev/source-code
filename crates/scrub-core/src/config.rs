//! Configuration schema (DESIGN §5). Deserialized once and compiled into
//! immutable matcher artifacts; hot-reload swaps the whole [`Config`].

use serde::Deserialize;

use crate::mask::MaskStyle;

/// Top-level SCRUB configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Inbound path -> upstream URL + scan profile. Provider-agnostic (DESIGN §5).
    pub routes: Vec<Route>,
    /// Named scan profiles describing *what* to scan per provider.
    pub profiles: std::collections::HashMap<String, Profile>,
    /// Masking behaviour.
    pub masking: Masking,
    /// Literal terms (glossary / secret-store-fed later) -> Aho-Corasick.
    pub glossary: Vec<GlossaryEntry>,
    /// Regex rules -> RegexSet.
    pub rules: Vec<Rule>,
    /// External secret sources whose values are masked (DESIGN §5, §8).
    pub sources: Vec<SourceSpec>,
    /// Optional generic high-entropy secret catcher.
    pub entropy: Entropy,
    /// Optional heuristic NER for person-name PII (DESIGN §8 v4).
    pub ner: Ner,
    /// Optional authentication for clients of the proxy itself.
    pub auth: Auth,
    /// Optional multi-tenant policy: a client key maps to a tenant with its own
    /// policy, glossary, and isolated session namespace (DESIGN §6, §7).
    pub tenants: Vec<Tenant>,
    /// Session storage backend (DESIGN §8 v3).
    pub sessions: Sessions,
    /// Optional tamper-evident audit log (DESIGN §7).
    pub audit: Audit,
    /// Optional full request/response transaction log (DESIGN §7).
    pub transactions: Transactions,
    /// Optional TLS termination for clients of the proxy.
    pub tls: Tls,
    /// Optional TLS interception (SNI-transparent MITM) mode (DESIGN §8 v5).
    pub intercept: Intercept,
}

/// SNI-transparent TLS interception: terminate client TLS with a per-host cert
/// minted from a configured CA, then route by `Host` to the real upstream and
/// mask as usual. Clients must trust the CA. Distinct from `tls` (termination).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Intercept {
    pub enabled: bool,
    /// CONNECT-proxy mode (clients set SCRUB as their HTTP proxy). When false,
    /// interception is SNI-transparent (clients reach SCRUB via DNS/SNI).
    pub connect: bool,
    /// Listen address for the interception endpoint.
    pub listen: Option<String>,
    /// PEM CA cert and key used to mint per-host leaf certs.
    pub ca_cert_path: Option<String>,
    pub ca_key_path: Option<String>,
    /// Optional extra CA (PEM) the proxy trusts when connecting to upstreams
    /// (e.g. an internal CA). Empty -> system roots only.
    pub upstream_ca_path: Option<String>,
}

/// Serve clients over HTTPS. When enabled, both paths are required (PEM).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Tls {
    pub enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

/// Append-only, hash-chained audit log of detections (counts/types, never values).
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Audit {
    pub enabled: bool,
    pub path: String,
}

impl Default for Audit {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "scrub-audit.jsonl".to_string(),
        }
    }
}

/// Full request/response transaction log. Records the **provider-facing**
/// exchange — the masked request sent upstream and the masked response received
/// — so every transaction is auditable without storing secrets at rest. (In
/// dry-run mode nothing is masked, so records reflect the original content.)
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Transactions {
    pub enabled: bool,
    pub path: String,
    /// Max bytes captured per request and per response body (each truncated).
    pub max_body_bytes: usize,
}

impl Default for Transactions {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "scrub-transactions.jsonl".to_string(),
            max_body_bytes: 64 * 1024,
        }
    }
}

/// Where session mappings live: in-process memory (single node) or a shared
/// store like Redis (cross-node).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Sessions {
    pub backend: SessionBackendKind,
    /// Connection URL when `backend: redis`, e.g. `redis://127.0.0.1/`.
    pub redis_url: Option<String>,
    /// Passphrase for at-rest encryption of stored session vaults. When set
    /// (with a shared backend), stored vaults are sealed with AES-256-GCM.
    pub encryption_key: Option<String>,
    /// Stable id of this node in a cluster (0..4095). Gives the node a disjoint
    /// id space so concurrent nodes never collide. If unset, a random id is
    /// chosen at startup (set it explicitly when running multiple nodes).
    pub node_id: Option<u16>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionBackendKind {
    #[default]
    Memory,
    Redis,
}

/// A tenant identified by one or more client keys. Policy fields override the
/// route/global masking defaults for requests authenticated as this tenant; the
/// glossary is added to this tenant's detection only.
#[derive(Debug, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub keys: Vec<String>,
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default)]
    pub scope: Option<Scope>,
    #[serde(default)]
    pub style: Option<Style>,
    #[serde(default)]
    pub glossary: Vec<GlossaryEntry>,
}

/// API-key authentication for the proxy (separate from any upstream credential).
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Auth {
    pub enabled: bool,
    /// Header carrying the client key.
    pub header: String,
    /// Accepted keys.
    pub keys: Vec<String>,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            enabled: false,
            header: "x-scrub-key".to_string(),
            keys: Vec::new(),
        }
    }
}

/// A source of literal secret values to mask. Data-only here (no I/O); the proxy
/// layer reads these and resolves them into terms at build / reload time.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceSpec {
    /// A `.env`-style file; each value (RHS of `KEY=VALUE`) becomes a secret.
    Dotenv {
        path: String,
        #[serde(default = "default_secret_type")]
        entity_type: String,
        #[serde(default = "default_source_priority")]
        priority: i32,
        #[serde(default = "default_min_len")]
        min_len: usize,
    },
    /// A plain file; each non-empty, non-comment line is a literal secret.
    File {
        path: String,
        #[serde(default = "default_secret_type")]
        entity_type: String,
        #[serde(default = "default_source_priority")]
        priority: i32,
        #[serde(default = "default_min_len")]
        min_len: usize,
    },
    /// HashiCorp Vault KV v2: read each `paths` entry and mask the string values.
    /// Resolved at startup/reload (no live polling). Token resolution order:
    /// `token` > `token_path` file > `token_env` (default `VAULT_TOKEN`).
    Vault {
        /// Base address, e.g. `https://vault.internal:8200`.
        address: String,
        /// KV v2 mount point.
        #[serde(default = "default_vault_mount")]
        mount: String,
        /// Secret paths under the mount (KV v2).
        paths: Vec<String>,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        token_path: Option<String>,
        #[serde(default)]
        token_env: Option<String>,
        #[serde(default = "default_secret_type")]
        entity_type: String,
        #[serde(default = "default_source_priority")]
        priority: i32,
        #[serde(default = "default_min_len")]
        min_len: usize,
    },
}

fn default_vault_mount() -> String {
    "secret".to_string()
}

fn default_secret_type() -> String {
    "SECRET".to_string()
}
fn default_source_priority() -> i32 {
    80
}
fn default_min_len() -> usize {
    5
}

/// Maps an inbound listen path to a configured upstream model API. The optional
/// policy fields override the global `masking` defaults for this route (e.g.
/// dry-run a canary route while enforcing elsewhere).
#[derive(Debug, Deserialize)]
pub struct Route {
    /// Inbound path prefix (path-based proxy mode). Empty for host-routed
    /// interception entries.
    #[serde(default)]
    pub listen_path: String,
    pub upstream: String,
    #[serde(default)]
    pub profile: Option<String>,
    /// In TLS-interception mode, the request `Host` this route matches (e.g.
    /// `api.openai.com`). Ignored in normal path-based routing.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default)]
    pub scope: Option<Scope>,
    #[serde(default)]
    pub style: Option<Style>,
}

/// Provider-aware description of which content to scan.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Profile {
    /// Request JSON content paths to scan/mask, e.g. `messages[].content`.
    pub scan_paths: Vec<String>,
    /// Streaming-response content paths to rehydrate per SSE event, e.g.
    /// `choices[].delta.content` (OpenAI) — needed because a sentinel is
    /// fragmented across delta events. Empty -> raw-byte rehydration.
    pub stream_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Masking {
    pub style: Style,
    pub scope: Scope,
    /// Enforce (mask) or just report what would be masked.
    pub mode: Mode,
    /// Session TTL, e.g. `30m`. Parsed by the proxy layer; opaque here.
    pub ttl: Option<String>,
    /// Request header that identifies a session when `scope: session`.
    pub session_header: String,
}

impl Default for Masking {
    fn default() -> Self {
        Self {
            style: Style::TypedSentinel,
            scope: Scope::Request,
            mode: Mode::Enforce,
            ttl: None,
            session_header: default_session_header(),
        }
    }
}

fn default_session_header() -> String {
    "x-scrub-session".to_string()
}

/// Whether SCRUB actually masks, or only observes and reports (DESIGN §7,
/// onboarding/dry-run). In `dry-run` the upstream receives the original payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Enforce,
    DryRun,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Style {
    TypedSentinel,
    BareSentinel,
}

impl From<Style> for MaskStyle {
    fn from(s: Style) -> Self {
        match s {
            Style::TypedSentinel => MaskStyle::TypedSentinel,
            Style::BareSentinel => MaskStyle::BareSentinel,
        }
    }
}

/// Determinism boundary for the mapping (DESIGN §2).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Request,
    Session,
}

#[derive(Debug, Deserialize)]
pub struct GlossaryEntry {
    pub term: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub pattern: String,
    #[serde(default)]
    pub priority: i32,
}

/// Generic high-entropy secret catcher: flags token-like runs whose Shannon
/// entropy and length exceed thresholds (DESIGN §5). Off by default; low
/// priority so named rules/glossary win on overlap.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Entropy {
    pub enabled: bool,
    /// Minimum bits-of-entropy per character (base64 randomness ≈ 5–6).
    pub min_bits: f32,
    /// Minimum token length to consider.
    pub min_len: usize,
    /// Overlap priority (kept low so explicit rules take precedence).
    pub priority: i32,
    pub entity_type: String,
}

impl Default for Entropy {
    fn default() -> Self {
        Self {
            enabled: false,
            min_bits: 3.5,
            min_len: 20,
            priority: 10,
            entity_type: "SECRET".to_string(),
        }
    }
}

/// Heuristic person-name detection (DESIGN §8 v4). Off by default; conservative
/// (honorifics, "name is"/"Dear" cues, or gazetteer first name + capitalized
/// surname) to keep precision acceptable without a trained model.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Ner {
    pub enabled: bool,
    pub entity_type: String,
    pub priority: i32,
    /// Extra first names to recognize, beyond the built-in gazetteer.
    pub names: Vec<String>,
}

impl Default for Ner {
    fn default() -> Self {
        Self {
            enabled: false,
            entity_type: "PERSON".to_string(),
            priority: 30,
            names: Vec::new(),
        }
    }
}

impl Config {
    /// Parse configuration from YAML.
    pub fn from_yaml(s: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let cfg = Config::from_yaml(
            r#"
routes:
  - { listen_path: "/openai", upstream: "https://api.openai.com", profile: openai }
profiles:
  openai:
    scan_paths: ["messages[].content"]
masking:
  style: typed-sentinel
  scope: session
  ttl: 30m
glossary:
  - { term: "Project Hufflepuff", type: CODENAME, priority: 100 }
rules:
  - { name: aws_key, type: SECRET, pattern: 'AKIA[0-9A-Z]{16}', priority: 90 }
entropy:
  enabled: true
  min_bits: 4.0
"#,
        )
        .unwrap();
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].upstream, "https://api.openai.com");
        assert_eq!(cfg.glossary.len(), 1);
        assert_eq!(cfg.rules[0].ty, "SECRET");
        assert!(cfg.entropy.enabled);
    }

    #[test]
    fn defaults_are_sane() {
        let cfg = Config::from_yaml("{}").unwrap();
        assert!(matches!(cfg.masking.style, Style::TypedSentinel));
        assert!(matches!(cfg.masking.scope, Scope::Request));
        assert!(cfg.glossary.is_empty());
    }
}
