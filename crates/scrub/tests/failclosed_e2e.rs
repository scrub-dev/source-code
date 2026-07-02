//! Security: in enforce mode a JSON-typed body that does not parse is rejected
//! (422) rather than forwarded unmasked — SCRUB never leaks an unscannable body.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::any;
use axum::Router;

use scrub::proxy::{router, AppState};
use scrub_core::config::Config;

async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn record(State(hit): State<Arc<AtomicBool>>) -> String {
    hit.store(true, Ordering::SeqCst);
    "{}".to_string()
}

#[tokio::test]
async fn enforce_rejects_unparseable_json_body() {
    let hit = Arc::new(AtomicBool::new(false));
    let up = spawn(Router::new().fallback(any(record)).with_state(hit.clone())).await;

    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/up", upstream: "http://{up}", profile: openai }}
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
    let proxy = spawn(router(Arc::new(AppState::build(&cfg).unwrap()))).await;
    let client = reqwest::Client::new();

    // Malformed JSON with a JSON content-type + a secret: must be refused (422),
    // and the upstream must never receive it.
    let resp = client
        .post(format!("http://{proxy}/up/v1/x"))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"content":"leak alice@corp.com""#) // truncated / invalid
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422, "enforce must reject unparseable JSON");
    assert!(
        !hit.load(Ordering::SeqCst),
        "upstream must never receive the unmasked body"
    );

    // A well-formed request still flows (and reaches the upstream).
    let ok = client
        .post(format!("http://{proxy}/up/v1/x"))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"content":"hi alice@corp.com"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert!(
        hit.load(Ordering::SeqCst),
        "valid request should reach upstream"
    );
}
