//! Egress masking (DESIGN §3): apply a [`Detector`], intern each span in a
//! [`MappingStore`], and splice sentinels in place of the originals.

use crate::detect::{Detector, Span};
use crate::sentinel;
use crate::vault::MappingStore;

/// How sentinels carry type information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MaskStyle {
    /// `⟦S:EMAIL·id⟧` — type hint keeps model output coherent.
    #[default]
    TypedSentinel,
    /// `⟦S·id⟧` — no type leaked to the model.
    BareSentinel,
}

/// Mask `input`, recording originals in `store`. Returns the scrubbed bytes.
///
/// Zero-copy in spirit: untouched regions are copied as contiguous slices and
/// only matched spans allocate a sentinel.
pub fn mask(
    input: &[u8],
    detector: &Detector,
    store: &dyn MappingStore,
    style: MaskStyle,
) -> Vec<u8> {
    let spans = detector.find_spans(input);
    apply_spans(input, &spans, store, style)
}

/// Splice sentinels in place of pre-computed `spans` (assumed non-overlapping and
/// ordered by start). Shared by [`mask`] and the scan-path masker so detection
/// runs once per string.
pub(crate) fn apply_spans(
    input: &[u8],
    spans: &[Span],
    store: &dyn MappingStore,
    style: MaskStyle,
) -> Vec<u8> {
    if spans.is_empty() {
        return input.to_vec();
    }
    let mut out = Vec::with_capacity(input.len());
    let mut cursor = 0usize;
    for span in spans {
        out.extend_from_slice(&input[cursor..span.start]);
        let id = store.intern(&input[span.start..span.end], span.ty.as_deref());
        let ty = match style {
            MaskStyle::TypedSentinel => span.ty.as_deref(),
            MaskStyle::BareSentinel => None,
        };
        sentinel::encode(&mut out, ty, id);
        cursor = span.end;
    }
    out.extend_from_slice(&input[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::vault::Vault;

    fn detector() -> Detector {
        let cfg: Config = serde_yaml::from_str(
            r#"
glossary:
  - { term: "Project Hufflepuff", type: CODENAME, priority: 100 }
rules:
  - { name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }
"#,
        )
        .unwrap();
        Detector::from_config(&cfg).unwrap()
    }

    #[test]
    fn masks_and_dedups() {
        let det = detector();
        let v = Vault::new();
        let input = b"email john@acme.com about Project Hufflepuff, cc john@acme.com";
        let masked = mask(input, &det, &v, MaskStyle::TypedSentinel);
        let s = String::from_utf8(masked).unwrap();
        assert!(s.contains("⟦S:EMAIL·"));
        assert!(s.contains("⟦S:CODENAME·"));
        // two identical emails -> one interned original
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn bare_style_omits_type() {
        let det = detector();
        let v = Vault::new();
        let masked = mask(b"john@acme.com", &det, &v, MaskStyle::BareSentinel);
        let s = String::from_utf8(masked).unwrap();
        assert!(s.contains("⟦S·"));
        assert!(!s.contains("EMAIL"));
    }
}
