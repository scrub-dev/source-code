//! Egress detection (DESIGN §3, §4).
//!
//! All glossary literals compile into one Aho-Corasick automaton; all regex
//! rules into one `regex-automata` meta-engine matched in a single pass (DESIGN
//! §4: "one pass, two automata"). A scan produces candidate [`Span`]s which are
//! then resolved into a non-overlapping, deterministic set by (priority desc,
//! length desc).
//!
//! Rule patterns are ordered by priority before being handed to the engine, so
//! the engine's leftmost-first preference picks the higher-priority rule when
//! several match at the same offset; cross-source overlaps (glossary/regex/
//! entropy) are arbitrated afterwards by `resolve`.

use aho_corasick::{AhoCorasick, MatchKind};
use regex_automata::meta::Regex;

use crate::config::Config;
use crate::error::Result;

/// A literal term to mask, supplied outside the static config (e.g. pulled from
/// a secret store or `.env` at build/reload time). Merged into the same
/// Aho-Corasick automaton as the glossary.
#[derive(Debug, Clone)]
pub struct LiteralTerm {
    pub term: String,
    pub ty: Option<String>,
    pub priority: i32,
}

/// A pluggable detector that contributes spans (DESIGN §6 seam). The built-in
/// rule/entropy detection runs first; additional detectors — heuristic NER, or
/// an external model-backed detector injected by the host — run alongside, and
/// their spans go through the same priority-based [`resolve`].
pub trait SpanDetector: Send + Sync {
    fn detect(&self, input: &[u8], out: &mut Vec<Span>);
}

/// A detected region of the input to be masked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    /// Entity type that labels the sentinel (e.g. `EMAIL`); `None` -> bare.
    pub ty: Option<String>,
    /// Higher wins on overlap.
    pub priority: i32,
}

impl Span {
    fn len(&self) -> usize {
        self.end - self.start
    }
    fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Compiled, immutable detection artifacts. Built once from [`Config`] and
/// swapped wholesale on hot-reload (DESIGN §4).
pub struct Detector {
    ac: Option<AhoCorasick>,
    /// Per-literal metadata, indexed by Aho-Corasick pattern id.
    ac_meta: Vec<Meta>,
    /// One meta-engine over all rule patterns (single pass; DESIGN §4).
    regex: Option<Regex>,
    /// Per-rule metadata, indexed by the meta engine's pattern id.
    regex_meta: Vec<Meta>,
    entropy: EntropyCfg,
    /// Additional pluggable detectors (heuristic NER, injected model, …).
    extra: Vec<Box<dyn SpanDetector>>,
}

#[derive(Clone)]
struct Meta {
    ty: Option<String>,
    priority: i32,
}

/// Compiled entropy-detector settings.
struct EntropyCfg {
    enabled: bool,
    min_bits: f32,
    min_len: usize,
    ty: Option<String>,
    priority: i32,
}

impl Detector {
    /// Build detection artifacts from configuration alone.
    pub fn from_config(cfg: &Config) -> Result<Self> {
        Self::with_terms(cfg, Vec::new())
    }

    /// Build detection artifacts from configuration plus extra literal terms.
    pub fn with_terms(cfg: &Config, terms: Vec<LiteralTerm>) -> Result<Self> {
        Self::with_detectors(cfg, terms, Vec::new())
    }

    /// Like [`with_terms`](Self::with_terms) but also registering host-supplied
    /// detectors (e.g. a model-backed NER loaded by the proxy) — the injection
    /// seam for detection that can't live in this I/O-free crate.
    pub fn with_detectors(
        cfg: &Config,
        extra_terms: Vec<LiteralTerm>,
        mut extra: Vec<Box<dyn SpanDetector>>,
    ) -> Result<Self> {
        if cfg.ner.enabled {
            extra.push(Box::new(crate::ner::NerDetector::from_config(&cfg.ner)));
        }
        Self::build(cfg, extra_terms, extra)
    }

    fn build(
        cfg: &Config,
        extra: Vec<LiteralTerm>,
        extra_detectors: Vec<Box<dyn SpanDetector>>,
    ) -> Result<Self> {
        let mut literals = Vec::new();
        let mut ac_meta = Vec::new();
        let glossary = cfg.glossary.iter().map(|g| LiteralTerm {
            term: g.term.clone(),
            ty: Some(g.ty.clone()),
            priority: g.priority,
        });
        for t in glossary.chain(extra) {
            literals.push(t.term.into_bytes());
            ac_meta.push(Meta {
                ty: t.ty,
                priority: t.priority,
            });
        }
        let ac = if literals.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    // leftmost-longest so the automaton itself prefers longer hits
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&literals)?,
            )
        };

        // Build one meta-engine over all rule patterns. Patterns are ordered by
        // priority (desc) so that when several match at the same offset, the
        // engine's leftmost-first preference picks the higher-priority rule.
        let mut rules: Vec<&crate::config::Rule> = cfg.rules.iter().collect();
        rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        let regex = if patterns.is_empty() {
            None
        } else {
            Some(Regex::new_many(&patterns)?)
        };
        let regex_meta: Vec<Meta> = rules
            .iter()
            .map(|r| Meta {
                ty: Some(r.ty.clone()),
                priority: r.priority,
            })
            .collect();

        let entropy = EntropyCfg {
            enabled: cfg.entropy.enabled,
            min_bits: cfg.entropy.min_bits,
            min_len: cfg.entropy.min_len,
            ty: Some(cfg.entropy.entity_type.clone()),
            priority: cfg.entropy.priority,
        };

        Ok(Self {
            ac,
            ac_meta,
            regex,
            regex_meta,
            entropy,
            extra: extra_detectors,
        })
    }

    /// Find all spans to mask in `input`, resolved to a non-overlapping set
    /// ordered by start offset.
    pub fn find_spans(&self, input: &[u8]) -> Vec<Span> {
        let mut candidates = Vec::new();

        if let Some(ac) = &self.ac {
            for m in ac.find_iter(input) {
                let meta = &self.ac_meta[m.pattern().as_usize()];
                candidates.push(Span {
                    start: m.start(),
                    end: m.end(),
                    ty: meta.ty.clone(),
                    priority: meta.priority,
                });
            }
        }

        if let Some(regex) = &self.regex {
            // Single pass over the input for all rule patterns.
            for m in regex.find_iter(input) {
                let meta = &self.regex_meta[m.pattern().as_usize()];
                candidates.push(Span {
                    start: m.start(),
                    end: m.end(),
                    ty: meta.ty.clone(),
                    priority: meta.priority,
                });
            }
        }

        if self.entropy.enabled {
            self.entropy_spans(input, &mut candidates);
        }

        for detector in &self.extra {
            detector.detect(input, &mut candidates);
        }

        resolve(candidates)
    }

    /// Flag token-like runs whose Shannon entropy and length exceed the
    /// configured thresholds — generic secrets no named rule catches.
    fn entropy_spans(&self, input: &[u8], out: &mut Vec<Span>) {
        let mut i = 0;
        while i < input.len() {
            if !is_token_byte(input[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < input.len() && is_token_byte(input[i]) {
                i += 1;
            }
            let token = &input[start..i];
            if token.len() >= self.entropy.min_len && shannon_bits(token) >= self.entropy.min_bits {
                out.push(Span {
                    start,
                    end: i,
                    ty: self.entropy.ty.clone(),
                    priority: self.entropy.priority,
                });
            }
        }
    }
}

/// Characters that make up a secret/token run (base64/base62/hex-ish). `.` is
/// excluded so emails/domains/IPs aren't swallowed as one token.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// Shannon entropy of `token` in bits per character.
fn shannon_bits(token: &[u8]) -> f32 {
    let mut counts = [0u32; 256];
    for &b in token {
        counts[b as usize] += 1;
    }
    let n = token.len() as f32;
    let mut h = 0.0f32;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f32 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Resolve overlapping candidates: greedily accept by (priority desc, length
/// desc), dropping any that overlap an already-accepted span. The result is
/// re-sorted by start so masking is a single left-to-right pass.
fn resolve(mut candidates: Vec<Span>) -> Vec<Span> {
    candidates.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(b.len().cmp(&a.len()))
            .then(a.start.cmp(&b.start))
    });

    let mut chosen: Vec<Span> = Vec::with_capacity(candidates.len());
    for c in candidates {
        if !chosen.iter().any(|s| s.overlaps(&c)) {
            chosen.push(c);
        }
    }
    chosen.sort_by_key(|s| s.start);
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_priority_then_length() {
        // Two overlapping spans; higher priority wins even though shorter.
        let spans = resolve(vec![
            Span {
                start: 0,
                end: 10,
                ty: None,
                priority: 1,
            },
            Span {
                start: 2,
                end: 6,
                ty: Some("X".into()),
                priority: 9,
            },
        ]);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].priority, 9);
    }

    #[test]
    fn entropy_flags_random_token_not_prose() {
        let cfg = crate::config::Config::from_yaml(
            r#"
entropy:
  enabled: true
  min_bits: 3.5
  min_len: 20
"#,
        )
        .unwrap();
        let det = Detector::from_config(&cfg).unwrap();

        let input = b"the deploy key is sk-A1b2C3d4E5f6G7h8J9k0LmNoPqRs and nothing else here";
        let spans = det.find_spans(input);
        assert_eq!(spans.len(), 1, "exactly the high-entropy token");
        assert_eq!(spans[0].ty.as_deref(), Some("SECRET"));
        let matched = &input[spans[0].start..spans[0].end];
        assert_eq!(matched, b"sk-A1b2C3d4E5f6G7h8J9k0LmNoPqRs");
    }

    #[test]
    fn entropy_disabled_by_default() {
        let cfg = crate::config::Config::from_yaml("").unwrap();
        let det = Detector::from_config(&cfg).unwrap();
        assert!(det
            .find_spans(b"sk-A1b2C3d4E5f6G7h8J9k0LmNoPqRs")
            .is_empty());
    }

    #[test]
    fn named_rule_wins_over_entropy_on_overlap() {
        // An email is high-entropy-ish but should keep its EMAIL type, not SECRET.
        let cfg = crate::config::Config::from_yaml(
            r#"
rules:
  - { name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }
entropy:
  enabled: true
  min_bits: 2.0
  min_len: 8
  priority: 10
"#,
        )
        .unwrap();
        let det = Detector::from_config(&cfg).unwrap();
        let spans = det.find_spans(b"contact alice.longname@example.com now");
        let email = spans.iter().find(|s| s.ty.as_deref() == Some("EMAIL"));
        assert!(email.is_some(), "email rule should win: {spans:?}");
    }

    #[test]
    fn higher_priority_rule_wins_same_start_overlap() {
        // Two rules match at the same offset; the higher-priority one should win.
        let cfg = crate::config::Config::from_yaml(
            r#"
rules:
  - { name: aws,   type: SECRET, pattern: 'AKIA[0-9A-Z]{16}', priority: 90 }
  - { name: token, type: TOKEN,  pattern: '[A-Z0-9]+',        priority: 50 }
"#,
        )
        .unwrap();
        let det = Detector::from_config(&cfg).unwrap();
        let spans = det.find_spans(b"key AKIA0123456789ABCDEF rest");
        let s = spans
            .iter()
            .find(|s| s.start == 4)
            .expect("match at the key");
        assert_eq!(
            s.ty.as_deref(),
            Some("SECRET"),
            "aws rule should win: {spans:?}"
        );
    }

    #[test]
    fn multiple_rules_single_pass() {
        let cfg = crate::config::Config::from_yaml(
            r#"
rules:
  - { name: email, type: EMAIL,  pattern: '[\w.]+@[\w.]+',     priority: 50 }
  - { name: aws,   type: SECRET, pattern: 'AKIA[0-9A-Z]{16}',  priority: 90 }
"#,
        )
        .unwrap();
        let det = Detector::from_config(&cfg).unwrap();
        let spans = det.find_spans(b"a@b.com then AKIA0123456789ABCDEF");
        let kinds: std::collections::BTreeSet<_> =
            spans.iter().filter_map(|s| s.ty.as_deref()).collect();
        assert!(
            kinds.contains("EMAIL") && kinds.contains("SECRET"),
            "{spans:?}"
        );
    }

    #[test]
    fn ner_composes_into_detector_via_seam() {
        let cfg = crate::config::Config::from_yaml(
            r#"
rules:
  - { name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }
ner:
  enabled: true
"#,
        )
        .unwrap();
        let det = Detector::from_config(&cfg).unwrap();
        let spans = det.find_spans(b"email Dr. Sarah Connor at sarah@x.com");
        let kinds: std::collections::BTreeSet<_> =
            spans.iter().filter_map(|s| s.ty.as_deref()).collect();
        assert!(kinds.contains("PERSON"), "NER not applied: {spans:?}");
        assert!(kinds.contains("EMAIL"), "rules still apply: {spans:?}");
    }

    #[test]
    fn resolve_keeps_disjoint() {
        let spans = resolve(vec![
            Span {
                start: 0,
                end: 3,
                ty: None,
                priority: 1,
            },
            Span {
                start: 5,
                end: 8,
                ty: None,
                priority: 1,
            },
        ]);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[1].start, 5);
    }
}
