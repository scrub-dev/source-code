//! Secret-source + hot-reload integration (DESIGN §4, §8).
//!
//! Verifies that (a) `.env` values are pulled into the masking automaton, and
//! (b) editing a watched source file live-swaps the compiled config so newly
//! added secrets start being masked without a restart.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::Bytes;
use axum::extract::State;
use axum::Router;

use scrub::proxy::{router, AppState};
use scrub::reload;
use scrub::session::MemoryBackend;

/// Mock upstream that just records the (masked) request body it received.
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

fn tmpdir(tag: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("scrub-reload-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &PathBuf, content: &str) {
    std::fs::write(path, content).unwrap();
}

fn config_yaml(upstream: SocketAddr) -> String {
    format!(
        r#"
routes:
  - {{ listen_path: "/up", upstream: "http://{upstream}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
sources:
  - {{ kind: dotenv, path: ".env" }}
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#
    )
}

async fn post(proxy: SocketAddr, content: &str) {
    reqwest::Client::new()
        .post(format!("http://{proxy}/up/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"messages":[{{"role":"user","content":"{content}"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn dotenv_values_are_masked() {
    let seen = Arc::new(Mutex::new(String::new()));
    let upstream = spawn(Router::new().fallback(capture).with_state(seen.clone())).await;

    let dir = tmpdir("env");
    write(&dir.join(".env"), "SECRET_TOKEN=supersecret-abc123\n");
    let cfg_path = dir.join("scrub.yaml");
    write(&cfg_path, &config_yaml(upstream));

    let compiled = reload::compile(&cfg_path).unwrap();
    let handle = Arc::new(ArcSwap::from_pointee(compiled));
    let proxy = spawn(router(Arc::new(
        AppState::new(handle, MemoryBackend::new(Duration::from_secs(1800))).unwrap(),
    )))
    .await;

    post(proxy, "token supersecret-abc123 and a@b.com").await;

    let body = seen.lock().unwrap().clone();
    assert!(body.contains("⟦S:SECRET·"), "env secret not masked: {body}");
    assert!(body.contains("⟦S:EMAIL·"), "email not masked: {body}");
    assert!(
        !body.contains("supersecret-abc123"),
        "secret leaked: {body}"
    );
}

#[tokio::test]
async fn editing_env_reloads_live() {
    let seen = Arc::new(Mutex::new(String::new()));
    let upstream = spawn(Router::new().fallback(capture).with_state(seen.clone())).await;

    let dir = tmpdir("reload");
    let env_path = dir.join(".env");
    write(&env_path, "PLACEHOLDER=unused-value-x\n"); // no match for our request yet
    let cfg_path = dir.join("scrub.yaml");
    write(&cfg_path, &config_yaml(upstream));

    let handle = Arc::new(ArcSwap::from_pointee(reload::compile(&cfg_path).unwrap()));
    reload::spawn_watcher(cfg_path.clone(), handle.clone()).unwrap();
    let proxy = spawn(router(Arc::new(
        AppState::new(handle, MemoryBackend::new(Duration::from_secs(1800))).unwrap(),
    )))
    .await;

    // Before the edit: the secret is unknown, so it passes through unmasked.
    post(proxy, "deploy key rotated-secret-999").await;
    assert!(
        seen.lock().unwrap().contains("rotated-secret-999"),
        "expected unmasked before reload"
    );

    // Live edit: add the secret to the watched .env.
    write(
        &env_path,
        "PLACEHOLDER=unused-value-x\nTOKEN=rotated-secret-999\n",
    );

    // Poll until the watcher rebuilds and the secret starts being masked.
    let mut masked = false;
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        post(proxy, "deploy key rotated-secret-999").await;
        if seen.lock().unwrap().contains("⟦S:SECRET·") {
            masked = true;
            break;
        }
    }
    assert!(masked, "secret was not masked after live .env edit");
}
