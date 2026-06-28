//! Audit-log integration (DESIGN §7): the proxy appends a tamper-evident,
//! values-free record per request, and the chain verifies.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::Router;

use scrub::audit::{self, AuditLog};
use scrub::proxy::{router, AppState, Compiled};
use scrub::session::MemoryBackend;
use scrub_core::config::Config;

async fn ok() -> &'static str {
    "{}"
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn proxy_writes_verifiable_audit() {
    let upstream = spawn(Router::new().fallback(ok)).await;

    let mut path = std::env::temp_dir();
    path.push(format!("scrub-audit-e2e-{}.jsonl", std::process::id()));
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
    let log = AuditLog::open(&path).unwrap();
    let state = AppState::new(
        handle,
        MemoryBackend::new(std::time::Duration::from_secs(60)),
    )
    .unwrap()
    .with_audit(log);
    let proxy = spawn(router(Arc::new(state))).await;

    let client = reqwest::Client::new();
    for content in ["mail a@b.com and c@d.com", "no secrets here"] {
        client
            .post(format!("http://{proxy}/up/x"))
            .header("content-type", "application/json")
            .body(format!(
                r#"{{"messages":[{{"role":"user","content":"{content}"}}]}}"#
            ))
            .send()
            .await
            .unwrap();
    }

    // Chain verifies and has one record per request.
    let report = audit::verify(&path).unwrap();
    assert!(report.is_intact());
    assert_eq!(report.count, 2);

    // Records carry counts/types but never the secret values.
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("\"EMAIL\":2"),
        "audit should record EMAIL count: {body}"
    );
    assert!(
        !body.contains("a@b.com"),
        "audit must not contain values: {body}"
    );
}
