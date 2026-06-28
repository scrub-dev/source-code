//! The proxy layer (DESIGN §6): listener, route matching, request masking, and
//! streaming response rehydration.
//!
//! Request path: read body -> (if JSON) mask the route profile's `scan_paths` ->
//! forward to the configured upstream. Response path: for SSE streams (where a
//! sentinel is fragmented across `data:` events) rehydrate each event's
//! `stream_paths` content through a persistent rehydrator; for non-streaming
//! JSON, rehydrate the raw byte stream in JSON-string mode so a spliced original
//! can't break the frame.
//!
//! Built on axum + reqwest for v0. The engine is transport-agnostic, so a
//! `pingora`/`hyper` core can replace this without touching `scrub-core`.

use std::pin::Pin;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Router;
use futures_util::{Stream, StreamExt};
use subtle::ConstantTimeEq;

use scrub_core::config::{Config, Mode, Scope};
use scrub_core::detect::{Detector, LiteralTerm};
use scrub_core::mask::MaskStyle;
use scrub_core::rehydrate::{Encoding, Rehydrator};
use scrub_core::scan::process_json_paths;
use scrub_core::vault::{MappingStore, Vault};

use crate::session::SessionBackend;

/// Max request body we will buffer to mask (responses are streamed, not buffered).
const MAX_REQUEST_BODY: usize = 25 * 1024 * 1024;

/// Compiled, immutable matcher artifacts + routing. Rebuilt off the hot path and
/// swapped atomically on reload (DESIGN §4).
pub struct Compiled {
    /// Default detector (global glossary + rules + entropy + secret sources).
    detector: Detector,
    routes: Vec<RouteRt>,
    /// Header carrying the session key when `scope: session`.
    session_header: String,
    /// Client authentication for the proxy itself; `None` when disabled.
    auth: Option<AuthCfg>,
    /// Tenants by id, and the key -> tenant-id index for attribution.
    tenants: std::collections::HashMap<String, TenantRt>,
    key_to_tenant: std::collections::HashMap<String, String>,
}

/// A tenant resolved at compile time: policy overrides plus an optional
/// tenant-specific detector (global terms + this tenant's glossary).
struct TenantRt {
    id: String,
    style: Option<MaskStyle>,
    scope: Option<Scope>,
    dry_run: Option<bool>,
    /// Present only when the tenant has its own glossary; else use the default.
    detector: Option<Detector>,
}

/// A route resolved against its profile, with effective per-route policy.
struct RouteRt {
    listen_path: String,
    /// Host this route matches in TLS-interception mode (else `None`).
    host: Option<String>,
    /// Upstream base URL, no trailing slash.
    upstream: String,
    scan_paths: Vec<String>,
    /// Response content paths to rehydrate per SSE event (empty -> raw-byte).
    stream_paths: Vec<String>,
    style: MaskStyle,
    scope: Scope,
    /// Report-only: detect and report, but forward the original upstream.
    dry_run: bool,
}

/// Compiled proxy-auth settings. Keys are a `Vec` (not a set) so verification
/// can compare against every key in constant time, without a hash-lookup oracle.
struct AuthCfg {
    header: String,
    keys: Vec<String>,
}

impl Compiled {
    /// Compile from configuration plus already-resolved secret-source terms.
    pub fn build(cfg: &Config, secret_terms: Vec<LiteralTerm>) -> anyhow::Result<Self> {
        let detector = Detector::with_terms(cfg, secret_terms.clone())?;
        let m = &cfg.masking;

        let mut routes = Vec::new();
        for r in &cfg.routes {
            // Validate against silent-failure misconfigurations (DESIGN §7).
            let profile = r.profile.as_ref().and_then(|p| cfg.profiles.get(p));
            if let Some(name) = &r.profile {
                if profile.is_none() {
                    tracing::warn!(route = %r.listen_path, profile = %name,
                        "route references unknown profile; nothing will be masked");
                }
            }
            let scan_paths = profile.map(|p| p.scan_paths.clone()).unwrap_or_default();
            let stream_paths = profile.map(|p| p.stream_paths.clone()).unwrap_or_default();
            let dry_run = r.mode.unwrap_or(m.mode) == Mode::DryRun;
            if !dry_run && scan_paths.is_empty() {
                tracing::warn!(route = %r.listen_path,
                    "enforce-mode route has no scan_paths; requests pass through UNMASKED");
            }
            // Per-route policy falls back to the global masking defaults.
            routes.push(RouteRt {
                listen_path: r.listen_path.clone(),
                host: r.host.clone(),
                upstream: r.upstream.trim_end_matches('/').to_string(),
                scan_paths,
                stream_paths,
                style: r.style.unwrap_or(m.style).into(),
                scope: r.scope.unwrap_or(m.scope),
                dry_run,
            });
        }

        // Tenants: per-tenant detector (only when they add a glossary) + policy.
        let mut tenants = std::collections::HashMap::new();
        let mut key_to_tenant = std::collections::HashMap::new();
        for t in &cfg.tenants {
            let detector = if t.glossary.is_empty() {
                None
            } else {
                let mut terms = secret_terms.clone();
                terms.extend(t.glossary.iter().map(|g| LiteralTerm {
                    term: g.term.clone(),
                    ty: Some(g.ty.clone()),
                    priority: g.priority,
                }));
                Some(Detector::with_terms(cfg, terms)?)
            };
            for key in &t.keys {
                key_to_tenant.insert(key.clone(), t.id.clone());
            }
            tenants.insert(
                t.id.clone(),
                TenantRt {
                    id: t.id.clone(),
                    style: t.style.map(Into::into),
                    scope: t.scope,
                    dry_run: t.mode.map(|md| md == Mode::DryRun),
                    detector,
                },
            );
        }

        // Auth is required when tenants exist (we must identify the caller).
        // Accepted keys are the union of flat auth keys and all tenant keys.
        let auth_enabled = cfg.auth.enabled || !cfg.tenants.is_empty();
        let auth = auth_enabled.then(|| {
            let mut keys: Vec<String> = cfg.auth.keys.clone();
            keys.extend(key_to_tenant.keys().cloned());
            AuthCfg {
                header: cfg.auth.header.clone(),
                keys,
            }
        });

        Ok(Self {
            detector,
            routes,
            session_header: cfg.masking.session_header.clone(),
            auth,
            tenants,
            key_to_tenant,
        })
    }

    /// Resolve the tenant for a request from its auth-header key, if any.
    fn tenant_for(&self, headers: &HeaderMap) -> Option<&TenantRt> {
        let auth = self.auth.as_ref()?;
        let key = headers.get(&auth.header)?.to_str().ok()?;
        let id = self.key_to_tenant.get(key)?;
        self.tenants.get(id)
    }

    /// Find the route configured for `host` (interception mode). The `host` may
    /// include a port, which is ignored.
    fn match_host(&self, host: &str) -> Option<&RouteRt> {
        let host = host.split(':').next().unwrap_or(host);
        self.routes.iter().find(|r| r.host.as_deref() == Some(host))
    }

    /// Find the route whose `listen_path` prefixes `path`, returning it plus the
    /// remaining upstream path (always starting with `/`).
    fn match_route<'a>(&'a self, path: &str) -> Option<(&'a RouteRt, String)> {
        for r in &self.routes {
            let lp = &r.listen_path;
            if lp.is_empty() {
                continue; // host-routed (interception) entry; not path-matchable
            }
            if path == lp {
                return Some((r, "/".to_string()));
            }
            if let Some(rest) = path.strip_prefix(lp) {
                if rest.starts_with('/') {
                    return Some((r, rest.to_string()));
                }
            }
        }
        None
    }
}

/// Shared proxy state: a hot-swappable [`Compiled`] snapshot, the session
/// registry (persists across reloads), and a reusable upstream client.
pub struct AppState {
    compiled: Arc<ArcSwap<Compiled>>,
    sessions: Arc<dyn SessionBackend>,
    client: reqwest::Client,
    audit: Option<Arc<crate::audit::AuditLog>>,
}

impl AppState {
    /// Build state around an existing swappable compiled handle (the reload
    /// watcher updates the same handle) and a session backend.
    pub fn new(
        compiled: Arc<ArcSwap<Compiled>>,
        sessions: Arc<dyn SessionBackend>,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder().build()?;
        Ok(Self {
            compiled,
            sessions,
            client,
            audit: None,
        })
    }

    /// Attach a tamper-evident audit log (records every proxied request).
    pub fn with_audit(mut self, audit: Arc<crate::audit::AuditLog>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Replace the upstream HTTP client (e.g. one trusting an extra CA for
    /// interception upstreams).
    pub fn with_upstream_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Convenience for tests: compile from config alone (no secret sources, no
    /// watcher) with a default in-memory session backend.
    pub fn build(cfg: &Config) -> anyhow::Result<Self> {
        let compiled = Compiled::build(cfg, Vec::new())?;
        let ttl = crate::session::parse_duration(
            cfg.masking.ttl.as_deref(),
            std::time::Duration::from_secs(1800),
        );
        Self::new(
            Arc::new(ArcSwap::from_pointee(compiled)),
            crate::session::MemoryBackend::new(ttl),
        )
    }

    /// The session backend, for the background sweeper.
    pub fn sessions(&self) -> Arc<dyn SessionBackend> {
        self.sessions.clone()
    }
}

/// Build the axum router. All paths fall through to [`handle`], which routes by
/// configured `listen_path`.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new().fallback(handle).with_state(state)
}

/// Router for TLS-interception mode: routes by the request `Host` to the route
/// configured for that host (DESIGN §8 v5).
pub fn intercept_router(state: Arc<AppState>) -> Router {
    Router::new().fallback(intercept_handle).with_state(state)
}

async fn intercept_handle(State(state): State<Arc<AppState>>, req: Request) -> Response {
    match intercept_proxy(&state, req).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "intercept error");
            text_response(
                StatusCode::BAD_GATEWAY,
                format!("scrub: upstream error: {e}"),
            )
        }
    }
}

async fn intercept_proxy(state: &AppState, req: Request) -> anyhow::Result<Response> {
    let (parts, body) = req.into_parts();
    if parts.uri.path() == HEALTH_PATH {
        return Ok(text_response(StatusCode::OK, "ok".to_string()));
    }
    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| parts.uri.host())
        .map(|h| h.to_string());
    let Some(host) = host else {
        return Ok(text_response(
            StatusCode::BAD_REQUEST,
            "scrub: missing Host".to_string(),
        ));
    };
    Ok(proxy_to_host(state, &host, Request::from_parts(parts, body)).await)
}

/// Route `req` by `host` (interception) and mask/forward/rehydrate. Shared by the
/// SNI-transparent handler and the CONNECT-proxy server.
pub(crate) async fn proxy_to_host(state: &AppState, host: &str, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let compiled = state.compiled.load_full();
    let Some(route) = compiled.match_host(host) else {
        return text_response(
            StatusCode::NOT_FOUND,
            format!("scrub: no intercept route for host {host}"),
        );
    };
    let pq = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", route.upstream, pq);
    match forward(state, &compiled, route, url, parts, body).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "intercept forward error");
            text_response(
                StatusCode::BAD_GATEWAY,
                format!("scrub: upstream error: {e}"),
            )
        }
    }
}

/// Whether `host` has a configured interception route (else blind-tunnel).
pub fn intercepts_host(state: &AppState, host: &str) -> bool {
    state.compiled.load_full().match_host(host).is_some()
}

async fn handle(State(state): State<Arc<AppState>>, req: Request) -> Response {
    match proxy(&state, req).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "proxy error");
            text_response(
                StatusCode::BAD_GATEWAY,
                format!("scrub: upstream error: {e}"),
            )
        }
    }
}

/// Unauthenticated liveness endpoint for load balancers / orchestrators.
const HEALTH_PATH: &str = "/healthz";

async fn proxy(state: &AppState, req: Request) -> anyhow::Result<Response> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path();

    // Liveness check: no auth, no routing — answer before anything else.
    if path == HEALTH_PATH {
        return Ok(text_response(StatusCode::OK, "ok".to_string()));
    }

    // Per-request snapshot of the compiled config (lock-free; survives reloads).
    let compiled = state.compiled.load_full();

    // Authenticate the client to the proxy itself (before any work upstream).
    if let Some(auth) = &compiled.auth {
        if !authorized(&parts.headers, auth) {
            return Ok(text_response(
                StatusCode::UNAUTHORIZED,
                "scrub: unauthorized".to_string(),
            ));
        }
    }

    let Some((route, upstream_path)) = compiled.match_route(path) else {
        return Ok(text_response(
            StatusCode::NOT_FOUND,
            format!("scrub: no route for {path}"),
        ));
    };
    let url = match parts.uri.query() {
        Some(q) => format!("{}{}?{}", route.upstream, upstream_path, q),
        None => format!("{}{}", route.upstream, upstream_path),
    };
    forward(state, &compiled, route, url, parts, body).await
}

/// Mask the request, forward to `url`, and rehydrate the response. Shared by the
/// path-based proxy and the host-based interception handler.
async fn forward(
    state: &AppState,
    compiled: &Compiled,
    route: &RouteRt,
    url: String,
    parts: http::request::Parts,
    body: Body,
) -> anyhow::Result<Response> {
    let label = if route.listen_path.is_empty() {
        route.host.as_deref().unwrap_or("-")
    } else {
        route.listen_path.as_str()
    };

    // Resolve tenant (if any) and the effective policy: tenant > route > global.
    let tenant = compiled.tenant_for(&parts.headers);
    let style = tenant.and_then(|t| t.style).unwrap_or(route.style);
    let scope = tenant.and_then(|t| t.scope).unwrap_or(route.scope);
    let dry_run = tenant.and_then(|t| t.dry_run).unwrap_or(route.dry_run);
    let tenant_id = tenant.map(|t| t.id.as_str());
    let stream_paths = route.stream_paths.clone();
    // Tenant-specific detector when present, else the default.
    let detector = tenant
        .and_then(|t| t.detector.as_ref())
        .unwrap_or(&compiled.detector);

    let body_bytes = axum::body::to_bytes(body, MAX_REQUEST_BODY).await?;

    // Select the mapping vault: request-scoped (fresh, zeroized at response end)
    // or session-scoped (shared/persisted across the conversation). Session keys
    // are namespaced by tenant so tenants can never collide. `session_key` is set
    // only when we must commit new entries back to the session backend.
    let (vault, session_key) = select_vault(
        state,
        scope,
        &compiled.session_header,
        tenant_id,
        &parts.headers,
    )
    .await;

    // Scan the configured paths. In enforce mode this also masks in place; in
    // dry-run it only reports and the original payload is forwarded.
    let is_json = content_type_is_json(&parts.headers);
    let mut report = scrub_core::scan::DetectionReport::default();
    let out_body = if is_json && !route.scan_paths.is_empty() && !body_bytes.is_empty() {
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(mut value) => {
                let store: Option<&dyn MappingStore> =
                    if dry_run { None } else { Some(vault.as_ref()) };
                report = process_json_paths(&mut value, &route.scan_paths, detector, store, style);
                // Audit (DESIGN §7): counts and types only, never values.
                tracing::info!(
                    route = %label,
                    tenant = tenant_id.unwrap_or("-"),
                    mode = if dry_run { "dry-run" } else { "enforce" },
                    detected = report.total,
                    types = %report.summary(),
                    "request scanned"
                );
                if dry_run {
                    body_bytes.to_vec() // forward original
                } else {
                    serde_json::to_vec(&value)?
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "body not valid JSON; forwarding unmasked");
                body_bytes.to_vec()
            }
        }
    } else {
        body_bytes.to_vec()
    };

    // Persist any new session entries before the response so other nodes can see
    // them (no-op for request scope and the in-memory backend).
    if !dry_run {
        if let Some(key) = &session_key {
            state.sessions.commit(key, &vault).await;
        }
    }

    // Tamper-evident audit (counts/types only — never values).
    if let Some(audit) = &state.audit {
        audit.record(
            label,
            tenant_id,
            if dry_run { "dry-run" } else { "enforce" },
            report.total,
            &report.by_type,
        );
    }

    // Forward upstream. Force identity encoding so we see plaintext sentinels,
    // and never leak the proxy's own auth header to the provider.
    let auth_header = compiled.auth.as_ref().map(|a| a.header.as_str());
    let upstream_headers = forward_request_headers(&parts.headers, auth_header);
    let upstream = state
        .client
        .request(parts.method.clone(), &url)
        .headers(upstream_headers)
        .body(out_body)
        .send()
        .await?;

    // Build the client-facing response.
    let status = upstream.status();
    let is_sse = response_is_sse(upstream.headers());
    let mut builder = Response::builder().status(status);
    if let Some(h) = builder.headers_mut() {
        copy_response_headers(upstream.headers(), h);
        // Observability surface (counts/types only — safe to expose).
        h.insert(
            "x-scrub-mode",
            HeaderValue::from_static(if dry_run { "dry-run" } else { "enforce" }),
        );
        if let Ok(v) = HeaderValue::from_str(&report.summary()) {
            h.insert("x-scrub-detected", v);
        }
    }

    let body = if dry_run {
        // Dry-run forwarded the original — nothing to rehydrate.
        Body::from_stream(passthrough_stream(upstream))
    } else if is_sse && !stream_paths.is_empty() {
        // Streaming: a sentinel is fragmented across delta events, so rehydrate
        // per-event content through a persistent rehydrator (not raw bytes).
        Body::from_stream(sse_rehydrating_stream(upstream, vault, stream_paths))
    } else {
        // Non-streaming JSON: the full sentinel is contiguous in one body.
        Body::from_stream(rehydrating_stream(upstream, vault))
    };
    Ok(builder.body(body)?)
}

fn response_is_sse(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("event-stream"))
        .unwrap_or(false)
}

/// Stream an upstream response straight through (dry-run: nothing was masked).
fn passthrough_stream(
    upstream: reqwest::Response,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> {
    upstream
        .bytes_stream()
        .map(|r| r.map_err(std::io::Error::other))
}

/// Rehydrate an SSE response. The masked sentinel is fragmented across `data:`
/// events, so we buffer whole events (split on the blank line), parse each one's
/// JSON, and run the configured `stream_paths` content through a *persistent*
/// rehydrator — its carry buffer reassembles a sentinel spanning events, and
/// re-serialization re-escapes the spliced original. Non-`data:` lines, `[DONE]`,
/// and unparseable payloads pass through unchanged.
fn sse_rehydrating_stream(
    upstream: reqwest::Response,
    vault: Arc<dyn MappingStore>,
    stream_paths: Vec<String>,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> {
    struct St {
        up: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
        buf: Vec<u8>,
        re: Rehydrator,
        vault: Arc<dyn MappingStore>,
        paths: Vec<String>,
        done: bool,
    }

    let st = St {
        up: Box::pin(upstream.bytes_stream()),
        buf: Vec::new(),
        re: Rehydrator::new(), // Raw: serde re-escapes on re-serialization
        vault,
        paths: stream_paths,
        done: false,
    };

    futures_util::stream::unfold(st, |mut st| async move {
        loop {
            if st.done {
                return None;
            }
            // Emit every complete event currently buffered.
            let mut out = Vec::new();
            while let Some(pos) = find_event_end(&st.buf) {
                let event: Vec<u8> = st.buf.drain(..pos).collect();
                process_sse_event(&event, &mut st.re, st.vault.as_ref(), &st.paths, &mut out);
            }
            if !out.is_empty() {
                return Some((Ok(Bytes::from(out)), st));
            }
            match st.up.next().await {
                Some(Ok(chunk)) => {
                    st.buf.extend_from_slice(&chunk);
                }
                Some(Err(e)) => {
                    st.done = true;
                    return Some((Err(std::io::Error::other(e)), st));
                }
                None => {
                    st.done = true;
                    let mut out = Vec::new();
                    if !st.buf.is_empty() {
                        let event = std::mem::take(&mut st.buf);
                        process_sse_event(
                            &event,
                            &mut st.re,
                            st.vault.as_ref(),
                            &st.paths,
                            &mut out,
                        );
                    }
                    out.extend_from_slice(&st.re.finish()); // any held-back bytes, verbatim
                    if out.is_empty() {
                        return None;
                    }
                    return Some((Ok(Bytes::from(out)), st));
                }
            }
        }
    })
}

/// Byte offset just past the next event terminator (`\n\n`), if present.
fn find_event_end(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n").map(|p| p + 2)
}

/// Rehydrate one SSE event's `data:` JSON content paths, appending to `out`.
fn process_sse_event(
    event: &[u8],
    re: &mut Rehydrator,
    store: &dyn MappingStore,
    paths: &[String],
    out: &mut Vec<u8>,
) {
    let Ok(text) = std::str::from_utf8(event) else {
        out.extend_from_slice(event);
        return;
    };
    for line in text.split_inclusive('\n') {
        let trimmed = line.strip_suffix('\n').unwrap_or(line);
        let Some(payload) = trimmed.strip_prefix("data:") else {
            out.extend_from_slice(line.as_bytes());
            continue;
        };
        let payload = payload.trim();
        match serde_json::from_str::<serde_json::Value>(payload) {
            Ok(mut value) if payload != "[DONE]" => {
                scrub_core::scan::rehydrate_json_paths(&mut value, paths, re, store);
                out.extend_from_slice(b"data: ");
                match serde_json::to_string(&value) {
                    Ok(s) => out.extend_from_slice(s.as_bytes()),
                    Err(_) => out.extend_from_slice(payload.as_bytes()),
                }
                if line.ends_with('\n') {
                    out.push(b'\n');
                }
            }
            _ => out.extend_from_slice(line.as_bytes()),
        }
    }
}

/// Wrap an upstream response's byte stream in a rehydrating adapter. The vault
/// handle is moved into the stream's state, so it stays alive for the whole
/// response (a request-scoped vault is then zeroized when the stream completes).
fn rehydrating_stream(
    upstream: reqwest::Response,
    vault: Arc<dyn MappingStore>,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> {
    struct St {
        up: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
        re: Rehydrator,
        vault: Arc<dyn MappingStore>,
        done: bool,
    }

    let st = St {
        up: Box::pin(upstream.bytes_stream()),
        re: Rehydrator::with_encoding(Encoding::JsonString),
        vault,
        done: false,
    };

    futures_util::stream::unfold(st, |mut st| async move {
        loop {
            if st.done {
                return None;
            }
            match st.up.next().await {
                Some(Ok(chunk)) => {
                    let out = st.re.push(&chunk, st.vault.as_ref());
                    if out.is_empty() {
                        continue; // held back waiting for more bytes
                    }
                    return Some((Ok(Bytes::from(out)), st));
                }
                Some(Err(e)) => {
                    st.done = true;
                    return Some((Err(std::io::Error::other(e)), st));
                }
                None => {
                    st.done = true;
                    let tail = st.re.finish();
                    if tail.is_empty() {
                        return None;
                    }
                    return Some((Ok(Bytes::from(tail)), st));
                }
            }
        }
    })
}

/// Pick the mapping vault for this request. Session scope shares a vault keyed
/// by the configured header; if scope is session but the key is absent, fall
/// back to an ephemeral request-scoped vault (we can't correlate without a key).
/// Returns the working vault and, for committed session scope, the namespaced
/// session key to persist new entries under.
async fn select_vault(
    state: &AppState,
    scope: Scope,
    session_header: &str,
    tenant_id: Option<&str>,
    headers: &HeaderMap,
) -> (Arc<Vault>, Option<String>) {
    match scope {
        Scope::Request => (Arc::new(Vault::new()), None),
        Scope::Session => match session_key(headers, session_header) {
            // Namespace by tenant so two tenants' session keys never collide.
            Some(key) => {
                let namespaced = match tenant_id {
                    Some(t) => format!("{t}\u{1f}{key}"),
                    None => key,
                };
                let vault = state.sessions.acquire(&namespaced).await;
                (vault, Some(namespaced))
            }
            None => (Arc::new(Vault::new()), None),
        },
    }
}

/// True if the request carries an accepted key in the configured auth header.
///
/// Compares against every configured key in constant time (no early return, no
/// hash-lookup), so response timing can't be used as an oracle to recover a key.
fn authorized(headers: &HeaderMap, auth: &AuthCfg) -> bool {
    let Some(presented) = headers.get(&auth.header).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let mut matched = 0u8;
    for key in &auth.keys {
        matched |= key.as_bytes().ct_eq(presented.as_bytes()).unwrap_u8();
    }
    matched == 1
}

fn session_key(headers: &HeaderMap, header_name: &str) -> Option<String> {
    headers
        .get(header_name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn content_type_is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("json"))
        .unwrap_or(false)
}

/// Copy request headers for the upstream call, dropping hop-by-hop / length /
/// encoding headers (and the proxy's own auth header) and forcing
/// `accept-encoding: identity`.
fn forward_request_headers(src: &HeaderMap, auth_header: Option<&str>) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in src.iter() {
        let n = name.as_str();
        if matches!(
            n,
            "host" | "content-length" | "accept-encoding" | "connection"
        ) || auth_header.is_some_and(|h| h.eq_ignore_ascii_case(n))
        {
            continue;
        }
        out.insert(name.clone(), value.clone());
    }
    out.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    out
}

/// Copy upstream response headers downstream, dropping those invalidated by
/// rehydration (length changes) or decompression (we forced identity).
fn copy_response_headers(src: &HeaderMap, dst: &mut HeaderMap) {
    for (name, value) in src.iter() {
        match name.as_str() {
            "content-length" | "content-encoding" | "transfer-encoding" | "connection" => continue,
            _ => {
                dst.insert(name.clone(), value.clone());
            }
        }
    }
}

fn text_response(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .expect("static response builds")
}
