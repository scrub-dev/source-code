//! Streaming load/soak: many concurrent streamed requests through the proxy must
//! all round-trip correctly with no cross-request leakage and no sentinel leaks.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::{Body, Bytes};
use axum::response::Response;
use axum::Router;
use futures_util::StreamExt;

use scrub::proxy::{router, AppState, Compiled};
use scrub::session::MemoryBackend;
use scrub_core::config::Config;

/// Mock OpenAI streaming upstream: echoes masked prompt content as an SSE stream,
/// one 3-char piece per delta, fragmenting sentinels across events.
async fn openai_stream(body: Bytes) -> Response {
    let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let masked = req["messages"][0]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let chars: Vec<char> = masked.chars().collect();
    let mut events: Vec<Bytes> = Vec::new();
    for piece in chars.chunks(3) {
        let content: String = piece.iter().collect();
        events.push(Bytes::from(format!(
            "data: {}\n\n",
            serde_json::json!({"choices":[{"delta":{"content":content}}]})
        )));
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

fn reassemble(sse: &str) -> String {
    sse.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter(|p| *p != "[DONE]")
        .filter_map(|p| serde_json::from_str::<serde_json::Value>(p).ok())
        .filter_map(|v| {
            v["choices"][0]["delta"]["content"]
                .as_str()
                .map(String::from)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_streams_round_trip() {
    let upstream = spawn(Router::new().fallback(openai_stream)).await;
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

    const N: usize = 200;
    let client = reqwest::Client::new();
    let mut tasks = Vec::with_capacity(N);
    for i in 0..N {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            // Unique content per request — catches any cross-request leakage.
            let original = format!("from user{i}@a.com to admin{i}@b.example please");
            let resp = client
                .post(format!("http://{proxy}/openai/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(format!(
                    r#"{{"stream":true,"messages":[{{"role":"user","content":"{original}"}}]}}"#
                ))
                .send()
                .await
                .unwrap();
            let sse = resp.text().await.unwrap();
            (original, sse)
        }));
    }

    for task in tasks {
        let (original, sse) = task.await.unwrap();
        assert!(!sse.contains("⟦S"), "sentinel leaked: {sse}");
        assert_eq!(reassemble(&sse), original, "round trip mismatch under load");
    }
}
