//! Session-scoped mapping integration (DESIGN §2).
//!
//! Proves that within one session a given original keeps a stable pseudonym
//! across requests (so the model sees consistency), and that the response still
//! rehydrates through the shared session vault.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::response::Response;
use axum::Router;
use futures_util::StreamExt;

use scrub::proxy::{router, AppState, Compiled};
use scrub::session::MemoryBackend;
use scrub_core::config::Config;

/// Mock upstream: records the masked content it received and streams back
/// `{"content":"<masked content>"}` in 3-byte chunks.
async fn echo(State(seen): State<Arc<Mutex<String>>>, body: Bytes) -> Response {
    let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let masked = req["messages"][0]["content"].as_str().unwrap().to_string();
    *seen.lock().unwrap() = masked.clone();

    let frame = format!(
        "{{\"content\":{}}}",
        serde_json::to_string(&masked).unwrap()
    );
    let chunks: Vec<Bytes> = frame
        .into_bytes()
        .chunks(3)
        .map(Bytes::copy_from_slice)
        .collect();
    let stream = futures_util::stream::iter(chunks).map(Ok::<_, std::io::Error>);
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// POST `content` through the proxy under session `sid`; return the (rehydrated)
/// response body.
async fn post(proxy: SocketAddr, sid: &str, content: &str) -> String {
    reqwest::Client::new()
        .post(format!("http://{proxy}/up/v1/chat/completions"))
        .header("content-type", "application/json")
        .header("x-scrub-session", sid)
        .body(format!(
            r#"{{"messages":[{{"role":"user","content":"{content}"}}]}}"#
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

#[tokio::test]
async fn session_keeps_stable_pseudonyms() {
    let seen = Arc::new(Mutex::new(String::new()));
    let upstream = spawn(Router::new().fallback(echo).with_state(seen.clone())).await;

    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/up", upstream: "http://{upstream}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
masking:
  style: typed-sentinel
  scope: session
  session_header: x-scrub-session
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#
    ))
    .unwrap();
    let compiled = Compiled::build(&cfg, Vec::new()).unwrap();
    let handle = Arc::new(ArcSwap::from_pointee(compiled));
    let state = AppState::new(
        handle,
        MemoryBackend::new(std::time::Duration::from_secs(60)),
    )
    .unwrap();
    let proxy = spawn(router(Arc::new(state))).await;

    // Request 1 (session A): first email gets id 0.
    post(proxy, "A", "ping alice@x.com").await;
    assert!(seen.lock().unwrap().contains("⟦S:EMAIL·0·"));

    // Request 2 (session A): a NEW email appears first in the text, the OLD one
    // second. With a shared session vault the old email keeps id 0 and the new
    // one gets id 1 — a fresh per-request vault would have given the new email
    // id 0 instead.
    let resp2 = post(proxy, "A", "new bob@y.com old alice@x.com").await;
    let masked2 = seen.lock().unwrap().clone();
    assert!(masked2.contains("new ⟦S:EMAIL·1·"), "masked: {masked2}");
    assert!(masked2.contains("old ⟦S:EMAIL·0·"), "masked: {masked2}");

    // Response rehydrates through the shared session vault.
    let parsed: serde_json::Value = serde_json::from_str(&resp2).unwrap();
    assert_eq!(parsed["content"], "new bob@y.com old alice@x.com");

    // Request 3 (session B): isolated vault — alice is id 0 here, proving B does
    // not see A's mapping.
    post(proxy, "B", "only alice@x.com").await;
    assert!(seen.lock().unwrap().contains("only ⟦S:EMAIL·0·"));
}
