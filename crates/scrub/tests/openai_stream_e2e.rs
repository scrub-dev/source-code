//! Realistic OpenAI streaming smoke test: the upstream returns a chat-completions
//! SSE stream whose `delta.content` is split into small pieces — so a masked
//! sentinel is fragmented across several `data:` events with JSON/SSE framing
//! between the pieces. The client must still reassemble the rehydrated original.

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

/// Mock OpenAI streaming upstream: echoes the masked prompt content back as a
/// chat-completions SSE, one 4-char piece per `delta`, ending with `[DONE]`.
async fn openai_stream(State(seen): State<Arc<Mutex<String>>>, body: Bytes) -> Response {
    let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let masked = req["messages"][0]["content"].as_str().unwrap().to_string();
    *seen.lock().unwrap() = masked.clone();

    // Split into 4-char pieces -> fragments any multi-char sentinel across events.
    let chars: Vec<char> = masked.chars().collect();
    let mut events: Vec<Bytes> = Vec::new();
    for piece in chars.chunks(4) {
        let content: String = piece.iter().collect();
        let frame = format!(
            "data: {}\n\n",
            serde_json::json!({"choices":[{"index":0,"delta":{"content":content}}]})
        );
        events.push(Bytes::from(frame));
    }
    events.push(Bytes::from_static(b"data: [DONE]\n\n"));

    let stream = futures_util::stream::iter(events).map(Ok::<_, std::io::Error>);
    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Concatenate all `delta.content` pieces from an SSE body.
fn reassemble(sse: &str) -> String {
    let mut out = String::new();
    for line in sse.lines() {
        let Some(payload) = line.strip_prefix("data: ") else {
            continue;
        };
        if payload == "[DONE]" {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
            if let Some(c) = v["choices"][0]["delta"]["content"].as_str() {
                out.push_str(c);
            }
        }
    }
    out
}

#[tokio::test]
async fn openai_streaming_round_trip() {
    let seen = Arc::new(Mutex::new(String::new()));
    let upstream = spawn(
        Router::new()
            .fallback(openai_stream)
            .with_state(seen.clone()),
    )
    .await;

    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ listen_path: "/openai", upstream: "http://{upstream}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
    stream_paths: ["choices[].delta.content"]
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

    let original = "email alice@example.com and bob@example.org please";
    let resp = reqwest::Client::new()
        .post(format!("http://{proxy}/openai/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"{original}"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
    let sse = resp.text().await.unwrap();

    // Upstream saw masked content; the reassembled client stream is rehydrated.
    assert!(
        seen.lock().unwrap().contains("⟦S:EMAIL·"),
        "upstream not masked"
    );
    assert!(!sse.contains("⟦S"), "sentinel leaked to client: {sse}");
    assert_eq!(reassemble(&sse), original);
}
