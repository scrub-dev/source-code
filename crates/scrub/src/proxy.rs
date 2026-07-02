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
use crate::transactions::{self, Recorder};

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

/// Compiled proxy-auth settings. We store SHA-256 digests of the accepted keys
/// (not the keys themselves), so verification compares fixed-length values in
/// constant time — no hash-lookup oracle and no key-length timing leak.
struct AuthCfg {
    header: String,
    key_hashes: Vec<[u8; 32]>,
}

/// SHA-256 of a string, used to compare auth keys at a fixed length.
fn sha256(s: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
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
                key_hashes: keys.iter().map(|k| sha256(k)).collect(),
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
    transactions: Option<(Arc<crate::transactions::TransactionLog>, usize)>,
}

impl AppState {
    /// Build state around an existing swappable compiled handle (the reload
    /// watcher updates the same handle) and a session backend.
    pub fn new(
        compiled: Arc<ArcSwap<Compiled>>,
        sessions: Arc<dyn SessionBackend>,
    ) -> anyhow::Result<Self> {
        // Never follow upstream redirects: a compromised/malicious upstream could
        // 3xx us to an internal service or metadata endpoint (SSRF), and — worse —
        // we would rehydrate that target's response, splicing the client's secrets
        // into attacker-controlled content. Pass 3xx through to the client instead.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            compiled,
            sessions,
            client,
            audit: None,
            transactions: None,
        })
    }

    /// Attach a tamper-evident audit log (records every proxied request).
    pub fn with_audit(mut self, audit: Arc<crate::audit::AuditLog>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Attach a full request/response transaction log (max bytes per body).
    pub fn with_transactions(
        mut self,
        log: Arc<crate::transactions::TransactionLog>,
        max_body: usize,
    ) -> Self {
        self.transactions = Some((log, max_body));
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
                if dry_run {
                    tracing::warn!(error = %e, "body not valid JSON; forwarding original (dry-run)");
                    body_bytes.to_vec()
                } else {
                    // Fail closed: a JSON-typed body we can't parse can't be masked,
                    // so refuse rather than forward secrets to the provider unmasked.
                    tracing::warn!(error = %e, route = %label,
                        "rejecting request: JSON body did not parse (enforce mode)");
                    return Ok(text_response(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "scrub: request body is not valid JSON; refusing to forward unmasked"
                            .to_string(),
                    ));
                }
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

    // Transaction capture (provider-facing exchange — masked, secret-free in
    // enforce mode). Build pending metadata + request snapshot before the body
    // is moved into the upstream request.
    let req_id = state
        .transactions
        .as_ref()
        .map(|_| transactions::request_id());
    let tx_pending = req_id.as_ref().map(|id| {
        let (log, max) = state.transactions.clone().unwrap();
        let meta = transactions::Meta {
            id: id.clone(),
            route: label.to_string(),
            tenant: tenant_id.map(str::to_string),
            method: parts.method.to_string(),
            path: parts.uri.path().to_string(),
            mode: if dry_run { "dry-run" } else { "enforce" }.to_string(),
            detected: report.total,
            types: report.by_type.clone(),
        };
        (log, max, meta, out_body.clone())
    });

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
    let recorder = tx_pending.map(|(log, max, meta, req)| {
        transactions::Recorder::new(log, meta, status.as_u16(), &req, max)
    });
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
        if let Some(v) = req_id
            .as_deref()
            .and_then(|i| HeaderValue::from_str(i).ok())
        {
            h.insert("x-scrub-request-id", v);
        }
    }

    let body = if dry_run {
        // Dry-run forwarded the original — nothing to rehydrate.
        Body::from_stream(passthrough_stream(upstream, recorder))
    } else if is_sse && !stream_paths.is_empty() {
        // Streaming: a sentinel is fragmented across delta events, so rehydrate
        // per-event content through a persistent rehydrator (not raw bytes).
        Body::from_stream(sse_rehydrating_stream(
            upstream,
            vault,
            stream_paths,
            recorder,
        ))
    } else {
        // Non-streaming JSON: the full sentinel is contiguous in one body.
        Body::from_stream(rehydrating_stream(upstream, vault, recorder))
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

/// Stream an upstream response straight through (dry-run: nothing was masked),
/// optionally recording the transaction.
fn passthrough_stream(
    upstream: reqwest::Response,
    recorder: Option<Recorder>,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> {
    struct St {
        up: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
        rec: Option<Recorder>,
        done: bool,
    }
    let st = St {
        up: Box::pin(upstream.bytes_stream()),
        rec: recorder,
        done: false,
    };
    futures_util::stream::unfold(st, |mut st| async move {
        if st.done {
            return None;
        }
        match st.up.next().await {
            Some(Ok(chunk)) => {
                if let Some(r) = &mut st.rec {
                    r.push_response(&chunk);
                }
                Some((Ok(chunk), st))
            }
            Some(Err(e)) => {
                st.done = true;
                Some((Err(std::io::Error::other(e)), st))
            }
            None => {
                st.done = true;
                if let Some(r) = st.rec.take() {
                    r.finish();
                }
                None
            }
        }
    })
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
    recorder: Option<Recorder>,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> {
    struct St {
        up: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
        buf: Vec<u8>,
        // One rehydrator per concrete leaf (e.g. `choices[0].delta.content`) so a
        // partial sentinel's carry never bleeds between leaves. Raw encoding: serde
        // re-escapes on re-serialization.
        res: std::collections::HashMap<String, Rehydrator>,
        vault: Arc<dyn MappingStore>,
        paths: Vec<String>,
        rec: Option<Recorder>,
        done: bool,
    }

    let st = St {
        up: Box::pin(upstream.bytes_stream()),
        buf: Vec::new(),
        res: std::collections::HashMap::new(),
        vault,
        paths: stream_paths,
        rec: recorder,
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
                process_sse_event(&event, &mut st.res, st.vault.as_ref(), &st.paths, &mut out);
            }
            if !out.is_empty() {
                return Some((Ok(Bytes::from(out)), st));
            }
            match st.up.next().await {
                Some(Ok(chunk)) => {
                    if let Some(r) = &mut st.rec {
                        r.push_response(&chunk); // capture the upstream (masked) bytes
                    }
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
                            &mut st.res,
                            st.vault.as_ref(),
                            &st.paths,
                            &mut out,
                        );
                    }
                    // Flush any held-back tail from every leaf's rehydrator, verbatim.
                    for re in st.res.values_mut() {
                        out.extend_from_slice(&re.finish());
                    }
                    if let Some(r) = st.rec.take() {
                        r.finish(); // upstream done — write the transaction record
                    }
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
/// `res` holds the persistent per-leaf rehydrators (shared across events).
fn process_sse_event(
    event: &[u8],
    res: &mut std::collections::HashMap<String, Rehydrator>,
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
                scrub_core::scan::rehydrate_json_paths(&mut value, paths, res, store);
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
    recorder: Option<Recorder>,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> {
    struct St {
        up: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
        re: Rehydrator,
        vault: Arc<dyn MappingStore>,
        rec: Option<Recorder>,
        done: bool,
    }

    let st = St {
        up: Box::pin(upstream.bytes_stream()),
        re: Rehydrator::with_encoding(Encoding::JsonString),
        vault,
        rec: recorder,
        done: false,
    };

    futures_util::stream::unfold(st, |mut st| async move {
        loop {
            if st.done {
                return None;
            }
            match st.up.next().await {
                Some(Ok(chunk)) => {
                    if let Some(r) = &mut st.rec {
                        r.push_response(&chunk); // capture the upstream (masked) bytes
                    }
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
                    if let Some(r) = st.rec.take() {
                        r.finish(); // upstream done — write the transaction record
                    }
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
            // Namespace by tenant so sessions never collide across the tenant
            // boundary. The scheme discriminator (`t`/`g`) is prepended by us, not
            // derived from the client-controlled key, so a global (flat-auth)
            // client cannot forge a tenant's key: its namespace always starts
            // `g\u{1f}…`, never `t\u{1f}…`.
            Some(key) => {
                let namespaced = session_namespace(tenant_id, &key);
                let vault = state.sessions.acquire(&namespaced).await;
                (vault, Some(namespaced))
            }
            None => (Arc::new(Vault::new()), None),
        },
    }
}

/// Build the tenant-isolated session namespace for a client session key.
///
/// The scheme discriminator (`t`/`g`) and separators are prepended by us, not
/// derived from the client-controlled `key`, so a global (flat-auth) client can
/// never forge a tenant's namespace: a global key is `g\u{1f}…`, a tenant key is
/// `t\u{1f}<id>\u{1f}…`, and the two prefixes are disjoint.
fn session_namespace(tenant_id: Option<&str>, key: &str) -> String {
    match tenant_id {
        Some(t) => format!("t\u{1f}{t}\u{1f}{key}"),
        None => format!("g\u{1f}{key}"),
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
    // Compare fixed-length digests so timing reveals neither which key matched
    // nor the length of any configured key.
    let presented = sha256(presented);
    let mut matched = 0u8;
    for key in &auth.key_hashes {
        matched |= key.ct_eq(&presented).unwrap_u8();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_session_key_cannot_forge_a_tenant_namespace() {
        // A tenant "acme" with session key "s".
        let tenant = session_namespace(Some("acme"), "s");
        // A flat-auth (global) client tries to reach it by crafting a key that
        // embeds the old separator scheme.
        let forged = session_namespace(None, "acme\u{1f}s");
        assert_ne!(tenant, forged, "global client must not forge a tenant key");
        // And two different tenants never collide.
        assert_ne!(
            session_namespace(Some("a"), "k"),
            session_namespace(Some("b"), "k")
        );
        // Prefixes are disjoint by construction.
        assert!(tenant.starts_with("t\u{1f}"));
        assert!(forged.starts_with("g\u{1f}"));
    }

    #[test]
    fn auth_is_constant_time_and_correct() {
        let auth = AuthCfg {
            header: "x-scrub-key".into(),
            key_hashes: vec![sha256("alpha-secret"), sha256("beta-secret")],
        };
        let mut ok = HeaderMap::new();
        ok.insert("x-scrub-key", HeaderValue::from_static("beta-secret"));
        assert!(authorized(&ok, &auth));
        let mut bad = HeaderMap::new();
        bad.insert("x-scrub-key", HeaderValue::from_static("beta-secre"));
        assert!(!authorized(&bad, &auth));
        assert!(!authorized(&HeaderMap::new(), &auth));
    }
}
