//! Validate the curated `examples/common-rules.yaml`: it must compile, detect
//! representative secrets, and leave benign text alone.

use scrub_core::{Config, Detector};

const RULES: &str = include_str!("../../../examples/common-rules.yaml");
const PROXY: &str = include_str!("../../../examples/proxy.yaml");

fn detector() -> Detector {
    let cfg = Config::from_yaml(RULES).expect("common-rules.yaml parses");
    Detector::from_config(&cfg).expect("all patterns compile")
}

#[test]
fn proxy_example_is_valid() {
    let cfg = Config::from_yaml(PROXY).expect("proxy.yaml parses");
    assert!(
        cfg.intercept.enabled && cfg.intercept.connect,
        "CONNECT-proxy mode"
    );
    assert!(
        cfg.routes
            .iter()
            .any(|r| r.host.as_deref() == Some("api.openai.com")),
        "host-routed entries"
    );
    Detector::from_config(&cfg).expect("proxy.yaml patterns compile");
}

/// Return the entity types detected in `input`.
fn types(det: &Detector, input: &str) -> std::collections::BTreeSet<String> {
    det.find_spans(input.as_bytes())
        .into_iter()
        .filter_map(|s| s.ty)
        .collect()
}

#[test]
fn detects_common_secret_formats() {
    let det = detector();
    let cases: &[(&str, &str)] = &[
        ("AKIAIOSFODNN7EXAMPLE", "AWS_KEY"),
        ("ghp_0123456789abcdefghijABCDEFGHIJ012345", "GITHUB_TOKEN"),
        ("glpat-abcdEFGH1234ijklMNOP", "GITLAB_TOKEN"),
        ("xoxb-12345678901-abcdEFGHijklMNOP", "SLACK_TOKEN"),
        ("sk_live_0123456789abcdefABCDEFGH", "STRIPE_KEY"),
        ("AIzaSyA1234567890abcdefghijklmnop_qrstu", "GCP_KEY"),
        ("sk-ant-api03-abcDEF1234567890ghiJKL", "ANTHROPIC_KEY"),
        ("npm_0123456789abcdefghijABCDEFGHIJ012345", "NPM_TOKEN"),
        ("contact alice@example.com please", "EMAIL"),
        (
            "Authorization: Bearer abcDEF1234567890ghiJKLmnoPQRstu",
            "BEARER",
        ),
        (
            "db: postgres://admin:s3cr3tpw@db.internal:5432/app",
            "CREDENTIAL_URL",
        ),
        (r#"config: api_key = "abcd1234efgh5678ijkl""#, "SECRET"),
    ];
    for (input, expected) in cases {
        let found = types(&det, input);
        assert!(
            found.contains(*expected),
            "expected {expected} in {input:?}, got {found:?}"
        );
    }
}

#[test]
fn detects_pem_private_key_block() {
    let det = detector();
    let pem = "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJBAKj...lines...\nabcDEF==\n-----END RSA PRIVATE KEY-----\n";
    assert!(
        types(&det, pem).contains("PRIVATE_KEY"),
        "PEM block not masked"
    );
}

#[test]
fn leaves_benign_text_alone() {
    let det = detector();
    // No secrets here — should produce no spans.
    let benign = "The quick brown fox meets at 3pm on Tuesday to review the roadmap.";
    assert!(
        det.find_spans(benign.as_bytes()).is_empty(),
        "benign text falsely flagged: {:?}",
        det.find_spans(benign.as_bytes())
    );
}

#[test]
fn anthropic_beats_openai_on_overlap() {
    let det = detector();
    // "sk-ant-..." matches both the openai and anthropic patterns; the
    // higher-priority anthropic rule must win.
    let found = types(&det, "key sk-ant-api03-abcDEF1234567890ghiJKL");
    assert!(
        found.contains("ANTHROPIC_KEY") && !found.contains("OPENAI_KEY"),
        "{found:?}"
    );
}
