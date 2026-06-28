//! Secret sources (DESIGN §8 v2): resolve external secret values into literal
//! terms for the masking automaton. This is the I/O half of the `SecretSource`
//! seam; `scrub-core` stays I/O-free and just consumes the resulting terms.
//!
//! v0 sources: `.env` files (mask each value) and plain secret files (one term
//! per line). Connectors for Vault / cloud secret managers slot in here later
//! behind the same `SecretSource` trait.

use std::path::{Path, PathBuf};

use scrub_core::config::SourceSpec;
use scrub_core::detect::LiteralTerm;

/// A resolvable origin of secret values to mask.
pub trait SecretSource {
    /// Human-readable name for logs (never logs values — DESIGN §7).
    fn name(&self) -> String;
    /// Resolve current secret values into literal terms.
    fn load(&self) -> std::io::Result<Vec<LiteralTerm>>;
}

/// Resolve every configured source against `base_dir`, returning all terms.
/// A failing source is logged and skipped so one bad path can't break reload.
pub fn load_sources(specs: &[SourceSpec], base_dir: &Path) -> Vec<LiteralTerm> {
    let mut terms = Vec::new();
    for spec in specs {
        let source = from_spec(spec, base_dir);
        match source.load() {
            Ok(t) => {
                tracing::info!(source = %source.name(), terms = t.len(), "loaded secret source");
                terms.extend(t);
            }
            Err(e) => {
                tracing::warn!(source = %source.name(), error = %e, "skipping secret source");
            }
        }
    }
    terms
}

/// Paths that should be watched for reload, resolved against `base_dir`.
pub fn source_paths(specs: &[SourceSpec], base_dir: &Path) -> Vec<PathBuf> {
    specs
        .iter()
        .filter_map(|s| match s {
            SourceSpec::Dotenv { path, .. } | SourceSpec::File { path, .. } => {
                Some(base_dir.join(path))
            }
            // Watch the token file (rotation triggers reload); the Vault secrets
            // themselves are pulled only on reload, not polled.
            SourceSpec::Vault { token_path, .. } => token_path.as_ref().map(|p| base_dir.join(p)),
        })
        .collect()
}

fn from_spec(spec: &SourceSpec, base_dir: &Path) -> Box<dyn SecretSource> {
    match spec {
        SourceSpec::Dotenv {
            path,
            entity_type,
            priority,
            min_len,
        } => Box::new(DotEnvSource {
            path: base_dir.join(path),
            entity_type: entity_type.clone(),
            priority: *priority,
            min_len: *min_len,
        }),
        SourceSpec::File {
            path,
            entity_type,
            priority,
            min_len,
        } => Box::new(FileSource {
            path: base_dir.join(path),
            entity_type: entity_type.clone(),
            priority: *priority,
            min_len: *min_len,
        }),
        SourceSpec::Vault {
            address,
            mount,
            paths,
            token,
            token_path,
            token_env,
            entity_type,
            priority,
            min_len,
        } => Box::new(VaultSource {
            address: address.trim_end_matches('/').to_string(),
            mount: mount.clone(),
            paths: paths.clone(),
            token: token.clone(),
            token_path: token_path.as_ref().map(|p| base_dir.join(p)),
            token_env: token_env.clone(),
            entity_type: entity_type.clone(),
            priority: *priority,
            min_len: *min_len,
        }),
    }
}

/// `.env` file: each `KEY=VALUE` line contributes VALUE as a secret term.
struct DotEnvSource {
    path: PathBuf,
    entity_type: String,
    priority: i32,
    min_len: usize,
}

impl SecretSource for DotEnvSource {
    fn name(&self) -> String {
        format!("dotenv:{}", self.path.display())
    }

    fn load(&self) -> std::io::Result<Vec<LiteralTerm>> {
        let content = std::fs::read_to_string(&self.path)?;
        let mut terms = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let Some((_key, value)) = line.split_once('=') else {
                continue;
            };
            let value = unquote(value.trim());
            if value.len() >= self.min_len {
                terms.push(LiteralTerm {
                    term: value.to_string(),
                    ty: Some(self.entity_type.clone()),
                    priority: self.priority,
                });
            }
        }
        Ok(terms)
    }
}

/// Plain file: each non-empty, non-comment line is a literal secret.
struct FileSource {
    path: PathBuf,
    entity_type: String,
    priority: i32,
    min_len: usize,
}

impl SecretSource for FileSource {
    fn name(&self) -> String {
        format!("file:{}", self.path.display())
    }

    fn load(&self) -> std::io::Result<Vec<LiteralTerm>> {
        let content = std::fs::read_to_string(&self.path)?;
        let mut terms = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.len() < self.min_len {
                continue;
            }
            terms.push(LiteralTerm {
                term: line.to_string(),
                ty: Some(self.entity_type.clone()),
                priority: self.priority,
            });
        }
        Ok(terms)
    }
}

/// HashiCorp Vault KV v2 source: reads each path and masks its string values.
struct VaultSource {
    address: String,
    mount: String,
    paths: Vec<String>,
    token: Option<String>,
    token_path: Option<PathBuf>,
    token_env: Option<String>,
    entity_type: String,
    priority: i32,
    min_len: usize,
}

impl VaultSource {
    /// Resolve the token: literal > token file > env (default `VAULT_TOKEN`).
    fn token(&self) -> std::io::Result<String> {
        if let Some(t) = &self.token {
            return Ok(t.clone());
        }
        if let Some(p) = &self.token_path {
            return Ok(std::fs::read_to_string(p)?.trim().to_string());
        }
        let var = self.token_env.as_deref().unwrap_or("VAULT_TOKEN");
        std::env::var(var)
            .map_err(|_| std::io::Error::other(format!("no Vault token ({var} unset)")))
    }
}

impl SecretSource for VaultSource {
    fn name(&self) -> String {
        format!("vault:{}/{}", self.address, self.mount)
    }

    fn load(&self) -> std::io::Result<Vec<LiteralTerm>> {
        let token = self.token()?;
        // Blocking client — `load` is sync and runs off the async runtime
        // (startup uses spawn_blocking; the reload watcher is its own thread).
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(std::io::Error::other)?;

        let mut terms = Vec::new();
        for path in &self.paths {
            // KV v2 data API: <addr>/v1/<mount>/data/<path>
            let url = format!("{}/v1/{}/data/{}", self.address, self.mount, path);
            let resp = client
                .get(&url)
                .header("X-Vault-Token", &token)
                .send()
                .and_then(|r| r.error_for_status())
                .map_err(|e| std::io::Error::other(format!("vault {url}: {e}")))?;
            let body = resp.text().map_err(std::io::Error::other)?;
            let json: serde_json::Value =
                serde_json::from_str(&body).map_err(std::io::Error::other)?;
            // KV v2 nests the secret map under data.data.
            if let Some(map) = json["data"]["data"].as_object() {
                for value in map.values() {
                    if let Some(s) = value.as_str() {
                        if s.len() >= self.min_len {
                            terms.push(LiteralTerm {
                                term: s.to_string(),
                                ty: Some(self.entity_type.clone()),
                                priority: self.priority,
                            });
                        }
                    }
                }
            }
        }
        Ok(terms)
    }
}

/// Strip a single pair of matching surrounding quotes.
fn unquote(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpfile(name: &str, content: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("scrub-test-{}-{name}", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn dotenv_extracts_values_over_min_len() {
        let path = tmpfile(
            "env",
            "# comment\nexport API_KEY=\"sk-supersecretvalue\"\nPORT=8080\nEMPTY=\n",
        );
        let src = DotEnvSource {
            path,
            entity_type: "SECRET".into(),
            priority: 80,
            min_len: 5,
        };
        let terms = src.load().unwrap();
        let values: Vec<&str> = terms.iter().map(|t| t.term.as_str()).collect();
        assert!(values.contains(&"sk-supersecretvalue"));
        assert!(!values.contains(&"8080")); // below min_len
        assert_eq!(terms[0].ty.as_deref(), Some("SECRET"));
    }

    #[test]
    fn file_one_term_per_line() {
        let path = tmpfile(
            "secrets",
            "# header\nhunter2password\nx\nanother-secret-here\n",
        );
        let src = FileSource {
            path,
            entity_type: "SECRET".into(),
            priority: 80,
            min_len: 5,
        };
        let terms = src.load().unwrap();
        assert_eq!(terms.len(), 2); // "x" dropped by min_len
    }
}
