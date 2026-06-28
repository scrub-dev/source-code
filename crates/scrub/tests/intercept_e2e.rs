//! TLS interception (SNI-transparent MITM) end-to-end (DESIGN §8 v5).
//!
//! client --TLS(SCRUB-minted cert)--> SCRUB --TLS--> mock HTTPS upstream
//! The client trusts a test CA; SCRUB mints a per-host cert from that CA, decrypts,
//! masks, forwards to the real upstream over TLS, and rehydrates the response.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use axum::extract::State;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

use scrub::mitm::{server_config, CertMinter};
use scrub::proxy::{intercept_router, AppState, Compiled};
use scrub::session::MemoryBackend;
use scrub_core::config::Config;

const HOST: &str = "upstream.test";

fn gen_ca() -> (String, String) {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name
        .push(DnType::CommonName, "SCRUB Test CA");
    let key = KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn gen_leaf(ca_cert_pem: &str, ca_key_pem: &str, host: &str) -> (String, String) {
    let ca_key = KeyPair::from_pem(ca_key_pem).unwrap();
    let ca_cert = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .unwrap()
        .self_signed(&ca_key)
        .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let p = CertificateParams::new(vec![host.to_string()]).unwrap();
    let leaf = p.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    (leaf.pem(), leaf_key.serialize_pem())
}

/// Mock upstream: echoes the masked request content as a chat-completions reply.
async fn mock_handler(State(seen): State<Arc<Mutex<String>>>, body: axum::body::Bytes) -> String {
    let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let masked = req["messages"][0]["content"].as_str().unwrap().to_string();
    *seen.lock().unwrap() = masked.clone();
    serde_json::json!({"choices":[{"message":{"content": masked}}]}).to_string()
}

async fn serve_tls(addr_label: &str, tls: RustlsConfig, router: Router) -> SocketAddr {
    let _ = addr_label;
    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        axum_server::bind_rustls(SocketAddr::from(([127, 0, 0, 1], 0)), tls)
            .handle(h)
            .serve(router.into_make_service())
            .await
            .unwrap();
    });
    handle.listening().await.unwrap()
}

#[tokio::test]
async fn intercepts_and_masks_https() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_cert, ca_key) = gen_ca();

    // 1. Mock HTTPS upstream with a cert for HOST signed by the CA.
    let seen = Arc::new(Mutex::new(String::new()));
    let (leaf_cert, leaf_key) = gen_leaf(&ca_cert, &ca_key, HOST);
    let mock_tls = RustlsConfig::from_pem(leaf_cert.into_bytes(), leaf_key.into_bytes())
        .await
        .unwrap();
    let mock_app = Router::new()
        .fallback(mock_handler)
        .with_state(seen.clone());
    let mock_addr = serve_tls("mock", mock_tls, mock_app).await;

    // 2. Intercepting proxy: route by Host -> the mock; outbound trusts the CA and
    // resolves HOST to the mock's address.
    let cfg = Config::from_yaml(&format!(
        r#"
routes:
  - {{ host: "{HOST}", upstream: "https://{HOST}:{port}", profile: openai }}
profiles:
  openai:
    scan_paths: ["messages[].content"]
rules:
  - {{ name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }}
"#,
        port = mock_addr.port()
    ))
    .unwrap();
    let out_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_cert.as_bytes()).unwrap())
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], mock_addr.port())))
        .build()
        .unwrap();
    let handle = Arc::new(ArcSwap::from_pointee(
        Compiled::build(&cfg, Vec::new()).unwrap(),
    ));
    let state = AppState::new(
        handle,
        MemoryBackend::new(std::time::Duration::from_secs(60)),
    )
    .unwrap()
    .with_upstream_client(out_client);

    let minter = Arc::new(CertMinter::from_ca_pem(&ca_cert, &ca_key).unwrap());
    let proxy_tls = RustlsConfig::from_config(server_config(minter).unwrap());
    let proxy_addr = serve_tls("proxy", proxy_tls, intercept_router(Arc::new(state))).await;

    // 3. Client trusts the CA and is directed (via resolve) to the proxy as if it
    // were HOST.
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_cert.as_bytes()).unwrap())
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], proxy_addr.port())))
        .build()
        .unwrap();

    let original = "page alice@example.com please";
    let resp = client
        .post(format!(
            "https://{HOST}:{}/v1/chat/completions",
            proxy_addr.port()
        ))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"messages":[{{"role":"user","content":"{original}"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status {}", resp.status());
    let text = resp.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();

    // Upstream saw masked content; the client got the rehydrated original.
    assert!(
        seen.lock().unwrap().contains("⟦S:EMAIL·"),
        "upstream not masked"
    );
    assert_eq!(body["choices"][0]["message"]["content"], original);
}
