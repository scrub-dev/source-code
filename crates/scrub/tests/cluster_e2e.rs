//! Cross-node session sharing (DESIGN §8 v3).
//!
//! Two independent proxy "nodes" back their sessions onto one shared KV store
//! (an in-memory stand-in for Redis). A session started on node A continues with
//! stable pseudonyms on node B — proving the load-modify-store design without a
//! live Redis.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::Bytes;
use axum::extract::State;
use axum::Router;

use scrub::proxy::{router, AppState, Compiled};
use scrub::session::{InMemoryKv, KvSessionBackend, SessionBackend};
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

/// A proxy node sharing `backend`, pointed at `upstream`.
async fn node(upstream: SocketAddr, backend: Arc<dyn SessionBackend>) -> SocketAddr {
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
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#
    ))
    .unwrap();
    let handle = Arc::new(ArcSwap::from_pointee(
        Compiled::build(&cfg, Vec::new()).unwrap(),
    ));
    let state = AppState::new(handle, backend).unwrap();
    spawn(router(Arc::new(state))).await
}

async fn post(proxy: SocketAddr, sid: &str, content: &str) {
    reqwest::Client::new()
        .post(format!("http://{proxy}/up/x"))
        .header("content-type", "application/json")
        .header("x-scrub-session", sid)
        .body(format!(
            r#"{{"messages":[{{"role":"user","content":"{content}"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn session_continues_across_nodes() {
    let seen = Arc::new(Mutex::new(String::new()));
    let upstream = spawn(Router::new().fallback(capture).with_state(seen.clone())).await;

    // One shared store; each node has its own backend instance + disjoint id space.
    let kv = Arc::new(InMemoryKv::default());
    let node_a = node(
        upstream,
        KvSessionBackend::new(kv.clone(), Duration::from_secs(60), 0),
    )
    .await;
    let node_b = node(
        upstream,
        KvSessionBackend::new(kv.clone(), Duration::from_secs(60), 1),
    )
    .await;

    // Node A interns alice (id 0) under session "S" and commits to the store.
    post(node_a, "S", "first alice@x.com").await;
    assert!(seen.lock().unwrap().contains("first ⟦S:EMAIL·0⟧"));

    // Node B loads the session: alice keeps id 0 (cross-node dedup); bob gets a
    // fresh id from node B's own space (not 0, and not colliding with A).
    post(node_b, "S", "old alice@x.com new bob@y.com").await;
    let masked = seen.lock().unwrap().clone();
    assert!(
        masked.contains("old ⟦S:EMAIL·0⟧"),
        "alice id not shared across nodes: {masked}"
    );
    assert!(
        masked.contains("new ⟦S:EMAIL·") && !masked.contains("new ⟦S:EMAIL·0⟧"),
        "bob should get a distinct node-B id: {masked}"
    );
}

/// Same cross-node check against a real Redis. Skipped unless `SCRUB_TEST_REDIS`
/// is set (e.g. `SCRUB_TEST_REDIS=redis://127.0.0.1/ cargo test`).
#[tokio::test]
async fn session_continues_across_nodes_redis() {
    let Ok(url) = std::env::var("SCRUB_TEST_REDIS") else {
        eprintln!("skipping: set SCRUB_TEST_REDIS to run the live-redis test");
        return;
    };

    let seen = Arc::new(Mutex::new(String::new()));
    let upstream = spawn(Router::new().fallback(capture).with_state(seen.clone())).await;

    let kv = scrub::redis_backend::RedisKv::connect(&url).await.unwrap();
    let node_a = node(
        upstream,
        KvSessionBackend::new(kv.clone(), Duration::from_secs(60), 0),
    )
    .await;
    let node_b = node(
        upstream,
        KvSessionBackend::new(kv, Duration::from_secs(60), 1),
    )
    .await;

    // Unique session id so reruns don't collide in a shared Redis.
    let sid = format!("it-{}", std::process::id());
    post(node_a, &sid, "first alice@x.com").await;
    post(node_b, &sid, "old alice@x.com new bob@y.com").await;
    let masked = seen.lock().unwrap().clone();
    assert!(masked.contains("old ⟦S:EMAIL·0⟧"), "redis: {masked}");
    assert!(
        masked.contains("new ⟦S:EMAIL·") && !masked.contains("new ⟦S:EMAIL·0⟧"),
        "redis: {masked}"
    );
}
