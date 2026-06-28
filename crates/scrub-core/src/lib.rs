//! SCRUB engine — detection, masking, and streaming rehydration.
//!
//! This crate is I/O-free: it turns bytes into masked bytes (egress) and masked
//! bytes back into originals (ingress), plus the config that drives it. The
//! proxy binary wires it to listeners, routes, and upstreams.
//!
//! See `DESIGN.md` for the architecture and the reversibility contract.

pub mod config;
pub mod detect;
pub mod error;
pub mod mask;
pub mod ner;
pub mod rehydrate;
pub mod scan;
pub mod sentinel;
pub mod vault;

pub use config::Config;
pub use detect::{Detector, Span, SpanDetector};
pub use error::{Error, Result};
pub use mask::{mask, MaskStyle};
pub use ner::NerDetector;
pub use rehydrate::{rehydrate_all, Encoding, Rehydrator};
pub use scan::{mask_json_paths, process_json_paths, rehydrate_json_paths, DetectionReport};
pub use vault::{IdSpace, MappingStore, RequestVault, Vault};
