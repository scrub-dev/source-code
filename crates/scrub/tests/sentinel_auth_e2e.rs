//! Security: a sentinel only rehydrates if its keyed MAC tag is valid, so a
//! hostile/compromised upstream cannot echo a forged `⟦S:EMAIL·id·tag⟧` to read
//! an arbitrary vault entry. The legitimate sentinel (which the upstream actually
//! received, tag intact) still round-trips.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
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

// Hostile upstream: echo back the masked content it received (a valid sentinel),
// and also inject a FORGED sentinel with the same id but a bogus tag, trying to
// exfiltrate the vault entry.
async fn hostile(body: Bytes) -> String {
    let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let masked = req["messages"][0]["content"].as_str().unwrap();
    let forged = "\u{27e6}S:EMAIL\u{b7}0\u{b7}1\u{27e7}"; // ⟦S:EMAIL·0·1⟧ — guessed tag
    serde_json::json!({
        "choices": [{"message": {"content": format!("legit={masked} forged={forged}")}}]
    })
    .to_string()
}

#[tokio::test]
async fn forged_sentinel_is_not_rehydrated() {
    let up = spawn(Router::new().fallback(any(hostile))).await;

    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/up", upstream: "http://{up}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#
    ))
    .unwrap();
    let proxy = spawn(router(Arc::new(AppState::build(&cfg).unwrap()))).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy}/up/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"mail me at alice@corp.com ok"}]}"#)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // The legitimate sentinel (correct tag) rehydrated back to the real secret.
    assert!(
        resp.contains("alice@corp.com"),
        "valid sentinel should rehydrate: {resp}"
    );
    // The forged sentinel did NOT rehydrate — it is passed through verbatim, so
    // the secret does not appear a second time.
    assert!(
        resp.contains("forged=\u{27e6}S:EMAIL\u{b7}0\u{b7}1\u{27e7}"),
        "forged sentinel must be emitted verbatim, not resolved: {resp}"
    );
    assert_eq!(
        resp.matches("alice@corp.com").count(),
        1,
        "secret must appear exactly once (only via the authentic sentinel): {resp}"
    );
}
