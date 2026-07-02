//! Provider-aware scanning (DESIGN §4): mask only the configured JSON content
//! paths (e.g. `messages[].content`) rather than the whole body. Less work and
//! far fewer false positives than scanning headers, model names, etc.
//!
//! A path is a dot-separated list of segments; a `[]` suffix means "descend into
//! every element of this array". Leaves that are JSON strings get masked in
//! place; serde re-serialization re-escapes them correctly.

use serde_json::Value;

use std::collections::{BTreeMap, HashMap};

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
        let mut visit = |s: &mut String| {
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
        };
        // `**` scans every string leaf (comprehensive, opt-in); else follow the
        // configured path.
        if path == "**" {
            walk_all(value, &mut visit);
        } else {
            let segments: Vec<&str> = path.split('.').collect();
            walk(value, &segments, &mut visit);
        }
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

/// Rehydrate every string reachable by `paths`, giving each **distinct leaf** its
/// own persistent [`Rehydrator`] (keyed by the concrete path incl. array indices)
/// in `rehydrators`. Persistence is *per leaf* so a sentinel fragmented across SSE
/// delta events reassembles for that leaf — while a partial sentinel's carry can
/// never bleed from one leaf (e.g. `choices[0]`) into another (`choices[1]`),
/// which would leak an un-rehydrated sentinel. The JSON is re-serialized
/// afterwards, which re-escapes the spliced originals.
pub fn rehydrate_json_paths(
    value: &mut Value,
    paths: &[String],
    rehydrators: &mut HashMap<String, Rehydrator>,
    store: &dyn MappingStore,
) {
    for path in paths {
        let mut visit = |key: &str, s: &mut String| {
            let re = rehydrators.entry(key.to_string()).or_default();
            let out = re.push(s.as_bytes(), store);
            *s = String::from_utf8_lossy(&out).into_owned();
        };
        if path == "**" {
            walk_all_keyed(value, String::new(), &mut visit);
        } else {
            let segments: Vec<&str> = path.split('.').collect();
            walk_keyed(value, &segments, String::new(), &mut visit);
        }
    }
}

/// Visit every string leaf anywhere in `v` (used by the `**` scan-all path).
fn walk_all(v: &mut Value, f: &mut dyn FnMut(&mut String)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(items) => items.iter_mut().for_each(|i| walk_all(i, f)),
        Value::Object(map) => map.iter_mut().for_each(|(_, val)| walk_all(val, f)),
        _ => {}
    }
}

/// Like [`walk_all`] but threads a concrete-path key for per-leaf state.
fn walk_all_keyed(v: &mut Value, key: String, f: &mut dyn FnMut(&str, &mut String)) {
    match v {
        Value::String(s) => f(&key, s),
        Value::Array(items) => items
            .iter_mut()
            .enumerate()
            .for_each(|(i, item)| walk_all_keyed(item, format!("{key}[{i}]"), f)),
        Value::Object(map) => map
            .iter_mut()
            .for_each(|(k, val)| walk_all_keyed(val, format!("{key}.{k}"), f)),
        _ => {}
    }
}

/// Split a segment like `messages[]` into (`messages`, is_array=true).
fn parse_segment(seg: &str) -> (&str, bool) {
    match seg.strip_suffix("[]") {
        Some(key) => (key, true),
        None => (seg, false),
    }
}

/// Like [`walk`], but threads a `key` identifying the concrete leaf (with array
/// indices, e.g. `choices[0].delta.content`) so callers can keep independent
/// per-leaf state. Invokes `f(key, leaf)` on each string leaf reached.
fn walk_keyed(v: &mut Value, segments: &[&str], key: String, f: &mut dyn FnMut(&str, &mut String)) {
    let Some((seg, rest)) = segments.split_first() else {
        if let Value::String(s) = v {
            f(&key, s);
        }
        return;
    };
    let (name, is_array) = parse_segment(seg);
    let Some(child) = v.get_mut(name) else {
        return;
    };
    if is_array {
        if let Value::Array(items) = child {
            for (i, item) in items.iter_mut().enumerate() {
                walk_keyed(item, rest, format!("{key}{name}[{i}]."), f);
            }
        }
    } else {
        walk_keyed(child, rest, format!("{key}{name}."), f);
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
    fn per_leaf_rehydrators_do_not_cross_contaminate() {
        // Regression: with n>1 choices and a sentinel fragmented across SSE events,
        // one leaf's partial-sentinel carry must not bleed into another leaf.
        let v = Vault::new();
        let id = v.intern(b"john@acme.com", Some("EMAIL"));
        let mut s = Vec::new();
        crate::sentinel::encode(&mut s, Some("EMAIL"), id, v.tag(id));
        let sent = String::from_utf8(s).unwrap();
        // Split inside the (ASCII) type name — a char boundary, mid-sentinel.
        let at = sent.find("EMAIL").unwrap() + 2;
        let (head, tail) = sent.split_at(at);

        let paths = vec!["choices[].delta.content".to_string()];
        let mut res: HashMap<String, Rehydrator> = HashMap::new();

        // Event 1: choice0 = start of the sentinel, choice1 = unrelated "X".
        let mut e1: Value =
            serde_json::json!({"choices":[{"delta":{"content":head}},{"delta":{"content":"X"}}]});
        rehydrate_json_paths(&mut e1, &paths, &mut res, &v);
        // Event 2: choice0 = rest of the sentinel, choice1 = "Y".
        let mut e2: Value =
            serde_json::json!({"choices":[{"delta":{"content":tail}},{"delta":{"content":"Y"}}]});
        rehydrate_json_paths(&mut e2, &paths, &mut res, &v);

        let c0 = format!(
            "{}{}",
            e1["choices"][0]["delta"]["content"].as_str().unwrap(),
            e2["choices"][0]["delta"]["content"].as_str().unwrap()
        );
        let c1 = format!(
            "{}{}",
            e1["choices"][1]["delta"]["content"].as_str().unwrap(),
            e2["choices"][1]["delta"]["content"].as_str().unwrap()
        );
        assert_eq!(
            c0, "john@acme.com",
            "choice 0 sentinel must rehydrate cleanly"
        );
        assert_eq!(c1, "XY", "choice 1 must be free of choice 0's carry");
    }

    #[test]
    fn scan_all_wildcard_masks_every_string_leaf() {
        let det = detector();
        let v = Vault::new();
        let mut body: Value = serde_json::from_str(
            r#"{"a":"x a@b.com","nested":{"b":"c@d.com"},"arr":["e@f.com"],"model":"gpt"}"#,
        )
        .unwrap();
        let n = mask_json_paths(
            &mut body,
            &["**".to_string()],
            &det,
            &v,
            MaskStyle::TypedSentinel,
        );
        assert_eq!(n, 3, "every email leaf, anywhere in the doc");
        assert!(body["a"].as_str().unwrap().contains("⟦S:EMAIL·"));
        assert!(body["nested"]["b"].as_str().unwrap().contains("⟦S:EMAIL·"));
        assert!(body["arr"][0].as_str().unwrap().contains("⟦S:EMAIL·"));
        assert_eq!(body["model"], "gpt"); // no secret -> untouched
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
