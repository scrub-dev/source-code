//! Proxy-side TLS termination (DESIGN §7): the proxy serves clients over HTTPS.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum_server::tls_rustls::RustlsConfig;

use scrub::proxy::{router, AppState, Compiled};
use scrub::session::MemoryBackend;
use scrub_core::config::Config;

#[tokio::test]
async fn serves_over_tls() {
    // Server-side crypto provider (ring; matches our cross-compile-safe build).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Self-signed cert for the test.
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let tls = RustlsConfig::from_pem(
        ck.cert.pem().into_bytes(),
        ck.key_pair.serialize_pem().into_bytes(),
    )
    .await
    .unwrap();

    // Minimal proxy (no routes needed: /healthz answers before routing).
    let cfg = Config::from_yaml("{}").unwrap();
    let handle = Arc::new(ArcSwap::from_pointee(
        Compiled::build(&cfg, Vec::new()).unwrap(),
    ));
    let state = AppState::new(handle, MemoryBackend::new(Duration::from_secs(60))).unwrap();
    let app = router(Arc::new(state));

    let server = axum_server::Handle::new();
    {
        let server = server.clone();
        tokio::spawn(async move {
            axum_server::bind_rustls(SocketAddr::from(([127, 0, 0, 1], 0)), tls)
                .handle(server)
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
    }
    let addr = server.listening().await.unwrap();

    // Client over HTTPS (self-signed -> accept invalid cert).
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
