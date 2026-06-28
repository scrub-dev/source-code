//! Transaction-log integration: the proxy records the masked provider-facing
//! request/response per request, with a correlation id, and never the secrets.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use axum::body::Bytes;
use axum::extract::State;
use axum::Router;

use scrub::proxy::{router, AppState, Compiled};
use scrub::session::MemoryBackend;
use scrub::transactions::TransactionLog;
use scrub_core::config::Config;

/// Mock upstream: echoes the masked request content back in a JSON reply.
async fn echo(State(seen): State<Arc<Mutex<String>>>, body: Bytes) -> String {
    let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let masked = req["messages"][0]["content"].as_str().unwrap().to_string();
    *seen.lock().unwrap() = masked.clone();
    serde_json::json!({"choices":[{"message":{"content": masked}}]}).to_string()
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn records_masked_transaction() {
    let seen = Arc::new(Mutex::new(String::new()));
    let upstream = spawn(Router::new().fallback(echo).with_state(seen.clone())).await;

    let mut path = std::env::temp_dir();
    path.push(format!("scrub-tx-e2e-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/up", upstream: "http://{upstream}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#
    ))
    .unwrap();
    let handle = Arc::new(ArcSwap::from_pointee(
        Compiled::build(&cfg, Vec::new()).unwrap(),
    ));
    let log = TransactionLog::open(&path).unwrap();
    let state = AppState::new(
        handle,
        MemoryBackend::new(std::time::Duration::from_secs(60)),
    )
    .unwrap()
    .with_transactions(log, 64 * 1024);
    let proxy = spawn(router(Arc::new(state))).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy}/up/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"email alice@example.com now"}]}"#)
        .send()
        .await
        .unwrap();
    let req_id = resp
        .headers()
        .get("x-scrub-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    assert!(req_id.is_some(), "missing x-scrub-request-id header");
    let _ = resp.text().await.unwrap();

    // Read the transaction record.
    let line = std::fs::read_to_string(&path).unwrap();
    let rec: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();

    assert_eq!(rec["id"], req_id.unwrap());
    assert_eq!(rec["route"], "/up");
    assert_eq!(rec["status"], 200);
    assert_eq!(rec["types"]["EMAIL"], 1);
    // Request and response captured in their MASKED (secret-free) form.
    let req_body = rec["request"].as_str().unwrap();
    let resp_body = rec["response"].as_str().unwrap();
    assert!(
        req_body.contains("⟦S:EMAIL·"),
        "request not masked: {req_body}"
    );
    assert!(
        resp_body.contains("⟦S:EMAIL·"),
        "response not masked: {resp_body}"
    );
    assert!(
        !req_body.contains("alice@example.com"),
        "secret in request log"
    );
    assert!(
        !resp_body.contains("alice@example.com"),
        "secret in response log"
    );
}
