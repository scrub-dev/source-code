//! End-to-end proxy test (DESIGN §3 full round trip).
//!
//! Wiring: client -> SCRUB proxy -> mock upstream -> SCRUB proxy -> client.
//! Asserts the upstream saw only masked content, and the client received the
//! fully rehydrated response — with the mock streaming the body back in 3-byte
//! chunks to exercise sentinel splits across boundaries.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::response::Response;
use axum::Router;
use futures_util::StreamExt;

use scrub::proxy::{router, AppState};
use scrub_core::config::Config;

/// Mock upstream: captures the request body, then streams back
/// `{"content":"<masked content>"}` three bytes at a time.
async fn mock_upstream(State(captured): State<Arc<Mutex<String>>>, body: Bytes) -> Response {
    *captured.lock().unwrap() = String::from_utf8_lossy(&body).into_owned();

    let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let masked_content = req["messages"][0]["content"].as_str().unwrap().to_string();
    // Keeps the sentinel as raw UTF-8; echoes it inside a JSON content string.
    let frame = format!(
        "{{\"content\":{}}}",
        serde_json::to_string(&masked_content).unwrap()
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
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn round_trip_through_proxy() {
    // 1. Mock upstream.
    let captured = Arc::new(Mutex::new(String::new()));
    let upstream_app = Router::new()
        .fallback(mock_upstream)
        .with_state(captured.clone());
    let upstream_addr = spawn(upstream_app).await;

    // 2. SCRUB proxy pointed at the mock, scanning message content.
    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/up", upstream: "http://{upstream_addr}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
masking:
  style: typed-sentinel
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#
    ))
    .unwrap();
    let state = Arc::new(AppState::build(&cfg).unwrap());
    let proxy_addr = spawn(router(state)).await;

    // 3. Client request through the proxy.
    let original = "ping alice@example.com please";
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/up/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{original}"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let client_body = resp.text().await.unwrap();

    // 4a. Upstream saw masked content, never the raw email.
    let upstream_saw = captured.lock().unwrap().clone();
    assert!(
        upstream_saw.contains("⟦S:EMAIL·"),
        "upstream body: {upstream_saw}"
    );
    assert!(
        !upstream_saw.contains("alice@example.com"),
        "secret leaked upstream: {upstream_saw}"
    );

    // 4b. Client got a valid, fully rehydrated response.
    assert!(
        !client_body.contains("⟦S"),
        "sentinel leaked to client: {client_body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&client_body).unwrap();
    assert_eq!(parsed["content"], original);
}
