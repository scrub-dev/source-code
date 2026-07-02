//! Vault `SecretSource` connector against a mock KV v2 endpoint (DESIGN §8 v2).

use std::net::SocketAddr;
use std::path::Path;

use axum::routing::get;
use axum::{Json, Router};
use scrub_core::config::SourceSpec;

/// Mock Vault KV v2 `data` response.
async fn kv_data() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "data": { "data": {
            "api_key": "sk-supersecret-vault-value",
            "db_password": "vaultpass123",
            "port": "8200"
        }}
    }))
}

/// Start the mock Vault in its own runtime/thread; return its address.
fn spawn_mock_vault() -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            let app = Router::new().route("/v1/secret/data/{name}", get(kv_data));
            axum::serve(listener, app).await.unwrap();
        });
    });
    rx.recv().unwrap()
}

#[test]
fn vault_source_pulls_values() {
    let addr = spawn_mock_vault();
    let specs = vec![SourceSpec::Vault {
        address: format!("http://{addr}"),
        mount: "secret".to_string(),
        paths: vec!["app".to_string()],
        token: Some("test-token".to_string()),
        token_path: None,
        token_env: None,
        entity_type: "SECRET".to_string(),
        priority: 80,
        min_len: 5,
    }];

    let (terms, errored) = scrub::secrets::load_sources(&specs, Path::new("."));
    assert!(!errored, "vault source should load without error");
    let values: Vec<&str> = terms.iter().map(|t| t.term.as_str()).collect();

    assert!(values.contains(&"sk-supersecret-vault-value"), "{values:?}");
    assert!(values.contains(&"vaultpass123"), "{values:?}");
    assert!(
        !values.contains(&"8200"),
        "below min_len, should be skipped: {values:?}"
    );
    assert!(terms.iter().all(|t| t.ty.as_deref() == Some("SECRET")));
}
