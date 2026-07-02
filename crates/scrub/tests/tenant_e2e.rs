//! Per-tenant policy, glossary isolation, and session namespacing (DESIGN §6, §7).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use axum::body::Bytes;
use axum::extract::State;
use axum::Router;

use scrub::proxy::{router, AppState, Compiled};
use scrub::session::MemoryBackend;
use scrub_core::config::Config;

async fn capture(State(seen): State<Arc<Mutex<String>>>, body: Bytes) -> &'static str {
    *seen.lock().unwrap() = String::from_utf8_lossy(&body).into_owned();
    "{}"
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn start(cfg: Config) -> SocketAddr {
    let handle = Arc::new(ArcSwap::from_pointee(
        Compiled::build(&cfg, Vec::new()).unwrap(),
    ));
    let state = AppState::new(
        handle,
        MemoryBackend::new(std::time::Duration::from_secs(60)),
    )
    .unwrap();
    spawn(router(Arc::new(state))).await
}

/// POST `content` as tenant `key`, optionally under session `sid`.
async fn post(proxy: SocketAddr, key: &str, sid: Option<&str>, content: &str) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(format!("http://{proxy}/up/x"))
        .header("content-type", "application/json")
        .header("x-scrub-key", key)
        .body(format!(
            r#"{{"messages":[{{"role":"user","content":"{content}"}}]}}"#
        ));
    if let Some(s) = sid {
        req = req.header("x-scrub-session", s);
    }
    req.send().await.unwrap()
}

#[tokio::test]
async fn tenant_policy_and_glossary_isolation() {
    let seen = Arc::new(Mutex::new(String::new()));
    let upstream = spawn(Router::new().fallback(capture).with_state(seen.clone())).await;

    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/up", upstream: "http://{upstream}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
masking:
  mode: enforce
auth:
  enabled: true
  header: x-scrub-key
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
tenants:
  - {{ id: acme, keys: ["acme-key"], glossary: [ {{ term: "FALCON", type: CODENAME, priority: 100 }} ] }}
  - {{ id: globex, keys: ["globex-key"], mode: dry-run }}
  - {{ id: base, keys: ["base-key"] }}
"#
    ))
    .unwrap();
    let proxy = start(cfg).await;

    // acme: enforce + its own glossary -> FALCON and email both masked.
    post(proxy, "acme-key", None, "launch FALCON for a@b.com").await;
    let b = seen.lock().unwrap().clone();
    assert!(b.contains("⟦S:CODENAME·"), "acme glossary not applied: {b}");
    assert!(b.contains("⟦S:EMAIL·"), "email not masked: {b}");

    // base: enforce but NO tenant glossary -> email masked, FALCON untouched.
    post(proxy, "base-key", None, "launch FALCON for a@b.com").await;
    let b = seen.lock().unwrap().clone();
    assert!(
        b.contains("FALCON"),
        "FALCON must not be masked for base: {b}"
    );
    assert!(b.contains("⟦S:EMAIL·"), "email should still be masked: {b}");

    // globex: dry-run override -> upstream sees the original.
    let resp = post(proxy, "globex-key", None, "launch FALCON for a@b.com").await;
    assert_eq!(resp.headers()["x-scrub-mode"], "dry-run");
    let b = seen.lock().unwrap().clone();
    assert!(
        b.contains("a@b.com") && !b.contains("⟦S"),
        "globex should be dry-run: {b}"
    );
}

#[tokio::test]
async fn tenant_session_namespacing_isolates() {
    let seen = Arc::new(Mutex::new(String::new()));
    let upstream = spawn(Router::new().fallback(capture).with_state(seen.clone())).await;

    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/up", upstream: "http://{upstream}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
masking:
  mode: enforce
  scope: session
  session_header: x-scrub-session
auth:
  enabled: true
  header: x-scrub-key
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
tenants:
  - {{ id: a, keys: ["a-key"] }}
  - {{ id: b, keys: ["b-key"] }}
"#
    ))
    .unwrap();
    let proxy = start(cfg).await;

    // Tenant A interns one email under session "S" (id 0).
    post(proxy, "a-key", Some("S"), "first alice@x.com").await;

    // Tenant B uses the SAME session value "S" but a different email. With proper
    // namespacing B has its own vault, so its first email is id 0 (not id 1).
    post(proxy, "b-key", Some("S"), "fresh bob@y.com").await;
    let b = seen.lock().unwrap().clone();
    assert!(
        b.contains("⟦S:EMAIL·0·"),
        "tenant B not isolated from A: {b}"
    );
}
