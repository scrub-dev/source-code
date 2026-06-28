//! Heuristic person-name (PII) detection (DESIGN §8 v4).
//!
//! This is a **dependency-free heuristic**, not a trained model: it flags a
//! capitalized name run only when there's a strong signal —
//! - an honorific or salutation cue (`Dr.`, `Mr.`, `Dear`, …) before it,
//! - the phrase `name is` / `named` before it, or
//! - a gazetteer first name immediately followed by a capitalized surname.
//!
//! That conservatism keeps precision reasonable (it won't mask every capitalized
//! word). A model-backed detector can replace or augment it behind the same
//! [`SpanDetector`] trait — see `Detector::with_detectors`.

use std::collections::HashSet;

use crate::config::Ner;
use crate::detect::{Span, SpanDetector};

/// Built-in first-name gazetteer (lowercased). Intentionally small; extend via
/// `ner.names`. Ambiguous common-word names (e.g. "Mark") are safe because rule
/// (3) requires a following capitalized surname.
const GAZETTEER: &[&str] = &[
    "james",
    "john",
    "robert",
    "michael",
    "william",
    "david",
    "richard",
    "joseph",
    "thomas",
    "charles",
    "daniel",
    "matthew",
    "anthony",
    "mark",
    "paul",
    "steven",
    "andrew",
    "joshua",
    "kevin",
    "brian",
    "george",
    "edward",
    "ronald",
    "timothy",
    "jason",
    "jeffrey",
    "ryan",
    "jacob",
    "gary",
    "nicholas",
    "eric",
    "jonathan",
    "stephen",
    "scott",
    "benjamin",
    "samuel",
    "alexander",
    "patrick",
    "jack",
    "peter",
    "henry",
    "adam",
    "nathan",
    "mary",
    "patricia",
    "jennifer",
    "linda",
    "elizabeth",
    "barbara",
    "susan",
    "jessica",
    "sarah",
    "karen",
    "nancy",
    "lisa",
    "margaret",
    "sandra",
    "ashley",
    "emily",
    "donna",
    "michelle",
    "laura",
    "olivia",
    "emma",
    "sophia",
    "anna",
    "grace",
    "maria",
    "ahmed",
    "mohammed",
    "fatima",
    "wei",
    "chen",
    "raj",
    "priya",
    "sofia",
    "lucas",
    "yuki",
    "ivan",
    "olga",
    "hans",
    "pierre",
    "sven",
    "amir",
];

/// Cue tokens (lowercased) that, immediately before a capitalized run, mark it
/// as a person name. Salutations like "hi"/"hello" are excluded on purpose
/// (too many false positives, e.g. "Hello World").
const CUES: &[&str] = &[
    "mr", "mrs", "ms", "mx", "dr", "prof", "sir", "madam", "miss", "dame", "lord", "lady", "dear",
    "named", "rev", "capt",
];

/// Max tokens in a single name run.
const MAX_RUN: usize = 3;

pub struct NerDetector {
    names: HashSet<String>,
    cues: HashSet<&'static str>,
    ty: Option<String>,
    priority: i32,
}

impl NerDetector {
    pub fn from_config(cfg: &Ner) -> Self {
        let mut names: HashSet<String> = GAZETTEER.iter().map(|s| s.to_string()).collect();
        for n in &cfg.names {
            names.insert(n.to_lowercase());
        }
        Self {
            names,
            cues: CUES.iter().copied().collect(),
            ty: Some(cfg.entity_type.clone()),
            priority: cfg.priority,
        }
    }

    fn span(&self, start: usize, end: usize) -> Span {
        Span {
            start,
            end,
            ty: self.ty.clone(),
            priority: self.priority,
        }
    }
}

impl SpanDetector for NerDetector {
    fn detect(&self, input: &[u8], out: &mut Vec<Span>) {
        let Ok(text) = std::str::from_utf8(input) else {
            return;
        };
        let tokens = tokenize(text);
        let mut i = 0;
        while i < tokens.len() {
            let lower = tokens[i].lower(text);

            // (1) honorific / salutation cue -> following capitalized run.
            // (2) "name is" -> following capitalized run.
            let cued = self.cues.contains(lower.as_str())
                || (lower == "is"
                    && i > 0
                    && tokens[i - 1].text(text).eq_ignore_ascii_case("name"));
            if cued {
                if let Some((start, end, next)) = cap_run(text, &tokens, i + 1) {
                    out.push(self.span(start, end));
                    i = next;
                    continue;
                }
            }

            // (3) gazetteer first name + capitalized surname.
            if is_capitalized(tokens[i].text(text))
                && self.names.contains(&lower)
                && i + 1 < tokens.len()
                && is_capitalized(tokens[i + 1].text(text))
                && whitespace_between(text, tokens[i].end, tokens[i + 1].start)
            {
                if let Some((start, end, next)) = cap_run(text, &tokens, i) {
                    out.push(self.span(start, end));
                    i = next;
                    continue;
                }
            }

            i += 1;
        }
    }
}

#[derive(Clone, Copy)]
struct Token {
    start: usize,
    end: usize,
}

impl Token {
    fn text<'a>(&self, src: &'a str) -> &'a str {
        &src[self.start..self.end]
    }
    fn lower(&self, src: &str) -> String {
        self.text(src).to_lowercase()
    }
}

/// Split `text` into word tokens (letters plus internal `'`/`-`).
fn tokenize(text: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if is_word_char(c) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            tokens.push(Token { start: s, end: i });
        }
    }
    if let Some(s) = start {
        tokens.push(Token {
            start: s,
            end: text.len(),
        });
    }
    tokens
}

fn is_word_char(c: char) -> bool {
    c.is_alphabetic() || c == '\'' || c == '-'
}

fn is_capitalized(tok: &str) -> bool {
    tok.chars().next().is_some_and(char::is_uppercase)
}

/// True when the bytes between `a` and `b` are only whitespace (so two tokens
/// form a contiguous name, not separated by a comma/period/other content).
fn whitespace_between(text: &str, a: usize, b: usize) -> bool {
    text[a..b].chars().all(char::is_whitespace)
}

/// Collect a run of up to [`MAX_RUN`] consecutive capitalized tokens starting at
/// `from`, separated only by whitespace. Returns `(byte_start, byte_end, next)`.
fn cap_run(text: &str, tokens: &[Token], from: usize) -> Option<(usize, usize, usize)> {
    if from >= tokens.len() || !is_capitalized(tokens[from].text(text)) {
        return None;
    }
    let start = tokens[from].start;
    let mut end = tokens[from].end;
    let mut i = from;
    while i + 1 < tokens.len()
        && i + 1 - from < MAX_RUN
        && is_capitalized(tokens[i + 1].text(text))
        && whitespace_between(text, tokens[i].end, tokens[i + 1].start)
    {
        i += 1;
        end = tokens[i].end;
    }
    Some((start, end, i + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> NerDetector {
        NerDetector::from_config(&Ner {
            enabled: true,
            ..Ner::default()
        })
    }

    fn names(input: &str) -> Vec<String> {
        let mut spans = Vec::new();
        detector().detect(input.as_bytes(), &mut spans);
        spans
            .iter()
            .map(|s| input[s.start..s.end].to_string())
            .collect()
    }

    #[test]
    fn honorific_cue() {
        assert_eq!(
            names("Please page Dr. Sarah Connor now"),
            vec!["Sarah Connor"]
        );
        assert_eq!(names("Dear Mark,"), vec!["Mark"]);
    }

    #[test]
    fn name_is_cue() {
        assert_eq!(
            names("Hi, my name is Olivia Carter."),
            vec!["Olivia Carter"]
        );
    }

    #[test]
    fn gazetteer_first_plus_surname() {
        assert_eq!(names("ping james wong")[..], [] as [String; 0]); // lowercase -> not a name
        assert_eq!(names("ask James Wong about it"), vec!["James Wong"]);
    }

    #[test]
    fn conservative_negatives() {
        // No cue, no gazetteer-name + surname -> nothing flagged.
        assert!(names("The Monday Meeting starts soon").is_empty());
        assert!(names("Visit New York in April").is_empty());
        assert!(names("a rose by any other name").is_empty());
    }
}
