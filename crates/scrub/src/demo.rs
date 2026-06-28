//! Offline end-to-end demo: mask -> simulated streamed provider echo -> rehydrate.
//! Useful as a smoke test without a real upstream (`scrub demo`).

use anyhow::Result;

use scrub_core::config::Config;
use scrub_core::detect::Detector;
use scrub_core::mask::{mask, MaskStyle};
use scrub_core::rehydrate::Rehydrator;
use scrub_core::vault::{MappingStore, Vault};

const DEMO_CONFIG: &str = r#"
glossary:
  - { term: "Project Hufflepuff", type: CODENAME, priority: 100 }
rules:
  - { name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }
"#;

pub fn run() -> Result<()> {
    let cfg = Config::from_yaml(DEMO_CONFIG)?;
    let detector = Detector::from_config(&cfg)?;

    let prompt = b"Email john@acme.com about Project Hufflepuff (cc john@acme.com).";
    println!("ORIGINAL : {}", String::from_utf8_lossy(prompt));

    let vault = Vault::new();
    let masked = mask(prompt, &detector, &vault, MaskStyle::TypedSentinel);
    println!("MASKED   : {}", String::from_utf8_lossy(&masked));
    println!("(provider sees {} opaque id(s))", vault.len());

    let mut rehydrator = Rehydrator::new();
    let mut restored = Vec::new();
    for chunk in masked.chunks(7) {
        restored.extend_from_slice(&rehydrator.push(chunk, &vault));
    }
    restored.extend_from_slice(&rehydrator.finish());
    println!("RESTORED : {}", String::from_utf8_lossy(&restored));

    assert_eq!(restored, prompt, "round trip must be lossless");
    println!("\n✓ round trip lossless");
    Ok(())
}
