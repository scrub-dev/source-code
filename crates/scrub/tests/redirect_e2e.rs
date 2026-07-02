//! Security: SCRUB must not follow upstream redirects. A 3xx from the upstream is
//! passed through to the client verbatim; SCRUB never fetches the redirect target
//! (which could be an internal/metadata endpoint, and whose response would be
//! rehydrated with the client's secrets).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
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

// Upstream: everything 302s to /secret; /secret would leak — and records if hit.
async fn upstream(State(hit): State<Arc<AtomicBool>>, req: axum::extract::Request) -> Response {
    if req.uri().path() == "/secret" {
        hit.store(true, Ordering::SeqCst);
        return (StatusCode::OK, "LEAKED-SECRET-BODY").into_response();
    }
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", "/secret")
        .body(axum::body::Body::empty())
        .unwrap()
}

#[tokio::test]
async fn upstream_redirects_are_not_followed() {
    let hit = Arc::new(AtomicBool::new(false));
    let up = spawn(
        Router::new()
            .fallback(any(upstream))
            .with_state(hit.clone()),
    )
    .await;

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

    // Client must also not follow redirects, so we can observe SCRUB's response.
    let resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(format!("http://{proxy}/up/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"a@b.com"}]}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        302,
        "SCRUB should pass the 302 through, not follow it"
    );
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/secret"
    );
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("LEAKED"),
        "redirect target body must not be fetched"
    );
    assert!(
        !hit.load(Ordering::SeqCst),
        "SCRUB must never hit the redirect target"
    );
}
