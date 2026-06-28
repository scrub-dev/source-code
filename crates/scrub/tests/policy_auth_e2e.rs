//! Per-route policy overrides + proxy authentication (DESIGN §6, §7).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Router;

use scrub::proxy::{router, AppState, Compiled};
use scrub::session::MemoryBackend;
use scrub_core::config::Config;

#[derive(Default)]
struct Seen {
    body: String,
    saw_key_header: bool,
}

async fn capture(
    State(seen): State<Arc<Mutex<Seen>>>,
    headers: HeaderMap,
    body: Bytes,
) -> &'static str {
    let mut s = seen.lock().unwrap();
    s.body = String::from_utf8_lossy(&body).into_owned();
    s.saw_key_header = headers.contains_key("x-scrub-key");
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

fn body() -> String {
    r#"{"messages":[{"role":"user","content":"mail a@b.com"}]}"#.to_string()
}

#[tokio::test]
async fn per_route_policy_overrides_global() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let upstream = spawn(Router::new().fallback(capture).with_state(seen.clone())).await;

    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/enforce", upstream: "http://{upstream}", profile: openai }}
  - {{ listen_path: "/dry", upstream: "http://{upstream}", profile: openai, mode: dry-run }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
masking:
  mode: enforce
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#
    ))
    .unwrap();
    let proxy = start(cfg).await;
    let client = reqwest::Client::new();

    // Global default (enforce): upstream sees masked content.
    client
        .post(format!("http://{proxy}/enforce/x"))
        .header("content-type", "application/json")
        .body(body())
        .send()
        .await
        .unwrap();
    assert!(seen.lock().unwrap().body.contains("⟦S:EMAIL·"));

    // Route override (dry-run): upstream sees the original.
    let resp = client
        .post(format!("http://{proxy}/dry/x"))
        .header("content-type", "application/json")
        .body(body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["x-scrub-mode"], "dry-run");
    let saw = seen.lock().unwrap().body.clone();
    assert!(
        saw.contains("a@b.com") && !saw.contains("⟦S"),
        "dry route masked: {saw}"
    );
}

#[tokio::test]
async fn auth_rejects_and_strips_key() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let upstream = spawn(Router::new().fallback(capture).with_state(seen.clone())).await;

    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/up", upstream: "http://{upstream}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
auth:
  enabled: true
  header: x-scrub-key
  keys: ["sekret-123"]
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#
    ))
    .unwrap();
    let proxy = start(cfg).await;
    let client = reqwest::Client::new();
    let url = format!("http://{proxy}/up/x");

    // No key -> 401.
    let r = client
        .post(&url)
        .header("content-type", "application/json")
        .body(body())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Wrong key -> 401.
    let r = client
        .post(&url)
        .header("content-type", "application/json")
        .header("x-scrub-key", "nope")
        .body(body())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Correct key -> 200, and the key is NOT forwarded upstream.
    let r = client
        .post(&url)
        .header("content-type", "application/json")
        .header("x-scrub-key", "sekret-123")
        .body(body())
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    {
        let s = seen.lock().unwrap();
        assert!(s.body.contains("⟦S:EMAIL·"), "masked content expected");
        assert!(!s.saw_key_header, "auth key must not leak upstream");
    }

    // /healthz is reachable without a key even when auth is enabled.
    let health = client
        .get(format!("http://{proxy}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    assert_eq!(health.text().await.unwrap(), "ok");
}
