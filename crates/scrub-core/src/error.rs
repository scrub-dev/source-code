//! Error types for the SCRUB engine.

use thiserror::Error;

/// Build/parse errors. The compiler-engine variants are boxed because their
/// inner error types are large (keeps `Result<_, Error>` small on the hot path).
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid regex rule: {0}")]
    Regex(Box<regex_automata::meta::BuildError>),

    #[error("failed to build glossary automaton: {0}")]
    AhoCorasick(Box<aho_corasick::BuildError>),

    #[error("invalid configuration: {0}")]
    Config(#[from] serde_yaml::Error),
}

impl From<regex_automata::meta::BuildError> for Error {
    fn from(e: regex_automata::meta::BuildError) -> Self {
        Error::Regex(Box::new(e))
    }
}

impl From<aho_corasick::BuildError> for Error {
    fn from(e: aho_corasick::BuildError) -> Self {
        Error::AhoCorasick(Box::new(e))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
