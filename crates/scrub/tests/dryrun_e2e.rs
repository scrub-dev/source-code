//! Dry-run mode integration (DESIGN §7): the upstream receives the *original*
//! payload, but SCRUB still reports what it would have masked via response
//! headers (counts/types only).

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

#[tokio::test]
async fn dry_run_forwards_original_but_reports() {
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
  mode: dry-run
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#
    ))
    .unwrap();
    let handle = Arc::new(ArcSwap::from_pointee(
        Compiled::build(&cfg, Vec::new()).unwrap(),
    ));
    let state = AppState::new(
        handle,
        MemoryBackend::new(std::time::Duration::from_secs(60)),
    )
    .unwrap();
    let proxy = spawn(router(Arc::new(state))).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy}/up/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"reach me at a@b.com or c@d.com"}]}"#)
        .send()
        .await
        .unwrap();

    // Reported via headers, counts/types only.
    assert_eq!(resp.headers()["x-scrub-mode"], "dry-run");
    assert_eq!(resp.headers()["x-scrub-detected"], "EMAIL=2");

    // Upstream saw the ORIGINAL — dry-run does not mask.
    let upstream_saw = seen.lock().unwrap().clone();
    assert!(
        upstream_saw.contains("a@b.com"),
        "dry-run must forward original: {upstream_saw}"
    );
    assert!(
        !upstream_saw.contains("⟦S"),
        "dry-run must not mask: {upstream_saw}"
    );
}
