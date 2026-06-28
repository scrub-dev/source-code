//! Provider-aware scanning (DESIGN §4): mask only the configured JSON content
//! paths (e.g. `messages[].content`) rather than the whole body. Less work and
//! far fewer false positives than scanning headers, model names, etc.
//!
//! A path is a dot-separated list of segments; a `[]` suffix means "descend into
//! every element of this array". Leaves that are JSON strings get masked in
//! place; serde re-serialization re-escapes them correctly.

use serde_json::Value;

use std::collections::BTreeMap;

use crate::detect::Detector;
use crate::mask::{apply_spans, MaskStyle};
use crate::rehydrate::Rehydrator;
use crate::vault::MappingStore;

/// Tally of detections by entity type (DESIGN §7: counts and types, never
/// values). Produced in both enforce and dry-run modes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DetectionReport {
    pub by_type: BTreeMap<String, usize>,
    pub total: usize,
}

impl DetectionReport {
    fn record(&mut self, ty: Option<&str>) {
        *self
            .by_type
            .entry(ty.unwrap_or("UNTYPED").to_string())
            .or_default() += 1;
        self.total += 1;
    }

    /// Compact `EMAIL=2,SECRET=1` summary for headers/logs. Empty when nothing
    /// was detected.
    pub fn summary(&self) -> String {
        self.by_type
            .iter()
            .map(|(ty, n)| format!("{ty}={n}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Scan every string reachable by `paths`, tallying detections by type. When
/// `store` is `Some`, also masks in place (enforce); when `None`, leaves the
/// value untouched (dry-run). Detection runs once per string in both modes.
pub fn process_json_paths(
    value: &mut Value,
    paths: &[String],
    detector: &Detector,
    store: Option<&dyn MappingStore>,
    style: MaskStyle,
) -> DetectionReport {
    let mut report = DetectionReport::default();
    for path in paths {
        let segments: Vec<&str> = path.split('.').collect();
        walk(value, &segments, &mut |s: &mut String| {
            let spans = detector.find_spans(s.as_bytes());
            if spans.is_empty() {
                return;
            }
            for span in &spans {
                report.record(span.ty.as_deref());
            }
            if let Some(store) = store {
                let masked = apply_spans(s.as_bytes(), &spans, store, style);
                // apply_spans only inserts valid UTF-8 sentinels around UTF-8 input.
                *s = String::from_utf8(masked).expect("masked output is valid UTF-8");
            }
        });
    }
    report
}

/// Mask every string reachable by `paths`, interning originals into `store`.
/// Returns the number of detections. Thin wrapper over [`process_json_paths`].
pub fn mask_json_paths(
    value: &mut Value,
    paths: &[String],
    detector: &Detector,
    store: &dyn MappingStore,
    style: MaskStyle,
) -> usize {
    process_json_paths(value, paths, detector, Some(store), style).total
}

/// Rehydrate every string reachable by `paths` through a *persistent*
/// `rehydrator`, in document order. Used per SSE event so a sentinel fragmented
/// across delta events reassembles in the rehydrator's carry buffer; the JSON is
/// re-serialized afterwards, which re-escapes the spliced originals.
pub fn rehydrate_json_paths(
    value: &mut Value,
    paths: &[String],
    rehydrator: &mut Rehydrator,
    store: &dyn MappingStore,
) {
    for path in paths {
        let segments: Vec<&str> = path.split('.').collect();
        walk(value, &segments, &mut |s: &mut String| {
            let out = rehydrator.push(s.as_bytes(), store);
            *s = String::from_utf8_lossy(&out).into_owned();
        });
    }
}

/// Split a segment like `messages[]` into (`messages`, is_array=true).
fn parse_segment(seg: &str) -> (&str, bool) {
    match seg.strip_suffix("[]") {
        Some(key) => (key, true),
        None => (seg, false),
    }
}

/// Descend `segments` into `v`, invoking `f` on each string leaf reached.
fn walk(v: &mut Value, segments: &[&str], f: &mut dyn FnMut(&mut String)) {
    let Some((seg, rest)) = segments.split_first() else {
        if let Value::String(s) = v {
            f(s);
        }
        return;
    };

    let (key, is_array) = parse_segment(seg);
    let Some(child) = v.get_mut(key) else {
        return;
    };

    if is_array {
        if let Value::Array(items) = child {
            for item in items {
                walk(item, rest, f);
            }
        }
    } else {
        walk(child, rest, f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::vault::Vault;

    fn detector() -> Detector {
        let cfg = Config::from_yaml(
            r#"
rules:
  - { name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }
"#,
        )
        .unwrap();
        Detector::from_config(&cfg).unwrap()
    }

    #[test]
    fn masks_only_configured_paths() {
        let det = detector();
        let v = Vault::new();
        let mut body: Value = serde_json::from_str(
            r#"{
                "model": "gpt-4o",
                "messages": [
                    {"role": "user", "content": "ping me at a@b.com"},
                    {"role": "assistant", "content": "ok"}
                ]
            }"#,
        )
        .unwrap();

        let paths = vec!["messages[].content".to_string()];
        let n = mask_json_paths(&mut body, &paths, &det, &v, MaskStyle::TypedSentinel);

        assert_eq!(n, 1);
        // model untouched, email in content masked
        assert_eq!(body["model"], "gpt-4o");
        assert!(body["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("⟦S:EMAIL·"));
        assert_eq!(body["messages"][1]["content"], "ok");
    }

    #[test]
    fn dry_run_reports_without_mutating() {
        let det = detector();
        let mut body: Value =
            serde_json::from_str(r#"{"messages":[{"content":"mail a@b.com and c@d.com"}]}"#)
                .unwrap();
        let original = body.clone();

        let paths = vec!["messages[].content".to_string()];
        let report = process_json_paths(&mut body, &paths, &det, None, MaskStyle::TypedSentinel);

        assert_eq!(body, original, "dry-run must not mutate the value");
        assert_eq!(report.total, 2);
        assert_eq!(report.by_type.get("EMAIL"), Some(&2));
        assert_eq!(report.summary(), "EMAIL=2");
    }

    #[test]
    fn nested_array_path() {
        let det = detector();
        let v = Vault::new();
        let mut body: Value = serde_json::from_str(
            r#"{"messages":[{"tool_calls":[{"function":{"arguments":"to a@b.com"}}]}]}"#,
        )
        .unwrap();
        let paths = vec!["messages[].tool_calls[].function.arguments".to_string()];
        let n = mask_json_paths(&mut body, &paths, &det, &v, MaskStyle::TypedSentinel);
        assert_eq!(n, 1);
    }
}
