//! SCRUB binary: masking/rehydration forward proxy for LLM providers.
//!
//! Usage:
//!   scrub [--config <path>] [--listen <addr>]   start the proxy
//!   scrub demo                                  run an offline round-trip demo
//!
//! Env: SCRUB_CONFIG, SCRUB_LISTEN, RUST_LOG.

mod demo;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;

use scrub::session::{self, SessionBackend};
use scrub::{proxy, redis_backend, reload};
use scrub_core::config::SessionBackendKind;

/// Fallback session TTL if not configured.
const DEFAULT_TTL: Duration = Duration::from_secs(1800);

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_CONFIG: &str = "scrub.example.yaml";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V" | "version") => {
            println!("scrub {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("demo") => return demo::run(),
        Some("audit-verify") => return audit_verify(args.get(1).map(String::as_str)),
        _ => {}
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "scrub=info,warn".into()),
        )
        .init();

    let config_path = flag(&args, "--config")
        .or_else(|| std::env::var("SCRUB_CONFIG").ok())
        .unwrap_or_else(|| DEFAULT_CONFIG.to_string());
    let listen = flag(&args, "--listen")
        .or_else(|| std::env::var("SCRUB_LISTEN").ok())
        .unwrap_or_else(|| DEFAULT_LISTEN.to_string());

    let config_path = PathBuf::from(config_path);
    // Off the async runtime: secret sources (e.g. Vault) may do blocking I/O.
    let (cfg, compiled) = {
        let cp = config_path.clone();
        tokio::task::spawn_blocking(move || reload::load(&cp))
            .await
            .context("config load task panicked")?
            .with_context(|| format!("compiling config {}", config_path.display()))?
    };
    let handle = Arc::new(ArcSwap::from_pointee(compiled));

    let ttl = session::parse_duration(cfg.masking.ttl.as_deref(), DEFAULT_TTL);
    let sessions: Arc<dyn SessionBackend> = match cfg.sessions.backend {
        SessionBackendKind::Memory => session::MemoryBackend::new(ttl),
        SessionBackendKind::Redis => {
            let url = cfg
                .sessions
                .redis_url
                .clone()
                .context("sessions.redis_url is required for the redis backend")?;
            let kv = redis_backend::RedisKv::connect(&url)
                .await
                .with_context(|| format!("connecting to redis at {url}"))?;
            let node_id = cfg.sessions.node_id.unwrap_or_else(random_node_id);
            tracing::info!(node_id, "cluster node id");
            match &cfg.sessions.encryption_key {
                Some(pass) => {
                    let cipher = scrub::crypto::Cipher::from_passphrase(pass);
                    tracing::info!(%url, "using redis session backend (encrypted at rest)");
                    session::KvSessionBackend::encrypted(kv, ttl, cipher, node_id)
                }
                None => {
                    tracing::warn!(%url, "using redis session backend (UNENCRYPTED at rest; set sessions.encryption_key)");
                    session::KvSessionBackend::new(kv, ttl, node_id)
                }
            }
        }
    };
    spawn_session_sweeper(sessions.clone(), ttl);

    if let Err(e) = reload::spawn_watcher(config_path.clone(), handle.clone()) {
        tracing::warn!(error = %e, "hot-reload disabled");
    }

    let mut state = proxy::AppState::new(handle, sessions)?;
    if cfg.audit.enabled {
        let log = scrub::audit::AuditLog::open(&cfg.audit.path)
            .with_context(|| format!("opening audit log {}", cfg.audit.path))?;
        tracing::info!(path = %cfg.audit.path, "audit log enabled");
        state = state.with_audit(log);
    }
    // Trust an extra CA for upstream connections (e.g. internal CAs / interception).
    if let Some(ca_path) = &cfg.intercept.upstream_ca_path {
        let pem = std::fs::read(ca_path).with_context(|| format!("reading {ca_path}"))?;
        let cert = reqwest::Certificate::from_pem(&pem)?;
        let client = reqwest::Client::builder()
            .add_root_certificate(cert)
            .build()?;
        state = state.with_upstream_client(client);
    }
    let state = Arc::new(state);

    if cfg.intercept.enabled {
        if cfg.intercept.connect {
            return serve_connect_proxy(&cfg.intercept, &listen, state).await;
        }
        return serve_intercept(&cfg.intercept, &listen, state).await;
    }

    let app = proxy::router(state);
    if cfg.tls.enabled {
        serve_tls(&cfg.tls, &listen, app).await
    } else {
        tracing::info!(config = %config_path.display(), %listen, "scrub starting (http)");
        let listener = tokio::net::TcpListener::bind(&listen)
            .await
            .with_context(|| format!("binding {listen}"))?;
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        Ok(())
    }
}

/// Serve over HTTPS via rustls (ring provider), with graceful shutdown.
async fn serve_tls(tls: &scrub_core::config::Tls, listen: &str, app: axum::Router) -> Result<()> {
    use axum_server::tls_rustls::RustlsConfig;
    use std::net::SocketAddr;

    let cert = tls
        .cert_path
        .clone()
        .context("tls.cert_path is required when tls.enabled")?;
    let key = tls
        .key_path
        .clone()
        .context("tls.key_path is required when tls.enabled")?;
    // Install the ring crypto provider (no aws-lc; keeps cross-compilation clean).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .with_context(|| format!("loading TLS cert/key ({cert}, {key})"))?;
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("tls requires a socket address, got {listen}"))?;

    let handle = axum_server::Handle::new();
    {
        let handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });
    }
    tracing::info!(%listen, "scrub starting (https)");
    axum_server::bind_rustls(addr, config)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

/// Load the interception CA and build a per-SNI cert-minting rustls server config.
fn intercept_tls(cfg: &scrub_core::config::Intercept) -> Result<Arc<rustls::ServerConfig>> {
    let ca_cert_path = cfg
        .ca_cert_path
        .clone()
        .context("intercept.ca_cert_path is required")?;
    let ca_key_path = cfg
        .ca_key_path
        .clone()
        .context("intercept.ca_key_path is required")?;
    let ca_cert = std::fs::read_to_string(&ca_cert_path)
        .with_context(|| format!("reading {ca_cert_path}"))?;
    let ca_key =
        std::fs::read_to_string(&ca_key_path).with_context(|| format!("reading {ca_key_path}"))?;
    let minter = Arc::new(scrub::mitm::CertMinter::from_ca_pem(&ca_cert, &ca_key)?);
    scrub::mitm::server_config(minter)
}

/// Serve SNI-transparent interception: per-host certs minted from the CA, routing
/// by `Host` to the real upstream (DESIGN §8 v5).
async fn serve_intercept(
    cfg: &scrub_core::config::Intercept,
    default_listen: &str,
    state: Arc<proxy::AppState>,
) -> Result<()> {
    use axum_server::tls_rustls::RustlsConfig;
    use std::net::SocketAddr;

    let tls = RustlsConfig::from_config(intercept_tls(cfg)?);

    let listen = cfg
        .listen
        .clone()
        .unwrap_or_else(|| default_listen.to_string());
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("intercept.listen must be a socket address, got {listen}"))?;

    let handle = axum_server::Handle::new();
    {
        let handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });
    }
    tracing::info!(%listen, "scrub starting (TLS interception, SNI-transparent)");
    axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(proxy::intercept_router(state).into_make_service())
        .await?;
    Ok(())
}

/// Serve CONNECT-proxy interception: clients set SCRUB as their HTTP proxy
/// (DESIGN §8 v5).
async fn serve_connect_proxy(
    cfg: &scrub_core::config::Intercept,
    default_listen: &str,
    state: Arc<proxy::AppState>,
) -> Result<()> {
    let tls = intercept_tls(cfg)?;
    let listen = cfg
        .listen
        .clone()
        .unwrap_or_else(|| default_listen.to_string());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    tracing::info!(%listen, "scrub starting (TLS interception, CONNECT proxy)");
    tokio::select! {
        _ = scrub::connect::serve(listener, state, tls) => {}
        _ = shutdown_signal() => {}
    }
    Ok(())
}

/// `scrub audit-verify <path>`: verify the audit log's hash chain.
fn audit_verify(path: Option<&str>) -> Result<()> {
    let path = path.context("usage: scrub audit-verify <path>")?;
    let report = scrub::audit::verify(path).with_context(|| format!("reading {path}"))?;
    if report.is_intact() {
        println!("OK: {} record(s) verified, chain intact", report.count);
        Ok(())
    } else {
        anyhow::bail!(
            "TAMPERED: chain breaks at record seq {} ({} verified before the break)",
            report.broken_at.unwrap(),
            report.count
        );
    }
}

/// A random node id in the 12-bit node space, used when none is configured.
fn random_node_id() -> u16 {
    let mut b = [0u8; 2];
    let _ = getrandom::getrandom(&mut b);
    u16::from_le_bytes(b) & 0x0fff
}

/// Read a `--flag value` pair from args.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

/// Periodically evict idle sessions (and zeroize their secrets). A no-op for
/// backends that manage TTL themselves (e.g. Redis).
fn spawn_session_sweeper(sessions: Arc<dyn SessionBackend>, ttl: Duration) {
    let period = (ttl / 2).max(Duration::from_secs(10));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        loop {
            tick.tick().await;
            let evicted = sessions.sweep();
            if evicted > 0 {
                tracing::info!(evicted, "swept idle sessions");
            }
        }
    });
}
