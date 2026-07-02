//! Hot-reload (DESIGN §4): compile config + secret sources into immutable
//! artifacts off the hot path, and swap them atomically via [`ArcSwap`] when the
//! config or a watched source file changes. A failed rebuild keeps the previous
//! good config — a bad edit never takes the proxy down.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use notify::{Event, RecursiveMode, Watcher};

use scrub_core::config::Config;

use crate::proxy::Compiled;
use crate::secrets;

/// Debounce window after a filesystem event before rebuilding.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// Read and parse the config, returning it alongside a compiled snapshot
/// (resolving secret sources). The parsed [`Config`] lets the caller read
/// runtime settings (e.g. session TTL) without a second file read.
pub fn load(config_path: &Path) -> anyhow::Result<(Config, Compiled)> {
    let yaml = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading config {}", config_path.display()))?;
    let cfg = Config::from_yaml(&yaml)
        .with_context(|| format!("parsing config {}", config_path.display()))?;
    let base = base_dir(config_path);
    let (terms, errored) = secrets::load_sources(&cfg.sources, &base);
    // Fail closed: never build a config with silently-dropped secret terms (that
    // would forward those secrets unmasked). On reload the caller keeps the
    // previous good config; at startup we refuse to run with reduced coverage.
    if errored {
        anyhow::bail!(
            "one or more secret sources failed to load; refusing to build a config \
             with reduced masking coverage (fix the source or remove it from config)"
        );
    }
    let compiled = Compiled::build(&cfg, terms)?;
    Ok((cfg, compiled))
}

/// Compile the config into a swappable [`Compiled`] snapshot (used on reload,
/// where only the matcher artifacts are needed).
pub fn compile(config_path: &Path) -> anyhow::Result<Compiled> {
    Ok(load(config_path)?.1)
}

/// Spawn a background watcher that rebuilds and swaps `handle` on change.
/// Watching failures are non-fatal: the proxy simply runs without hot-reload.
pub fn spawn_watcher(config_path: PathBuf, handle: Arc<ArcSwap<Compiled>>) -> anyhow::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        if res.is_ok() {
            let _ = tx.send(());
        }
    })?;

    for dir in dirs_to_watch(&config_path) {
        if let Err(e) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
            tracing::warn!(dir = %dir.display(), error = %e, "watch failed");
        } else {
            tracing::debug!(dir = %dir.display(), "watching");
        }
    }

    std::thread::Builder::new()
        .name("scrub-reload".into())
        .spawn(move || {
            let _watcher = watcher; // keep the watcher alive for the thread's life
            while rx.recv().is_ok() {
                // Coalesce bursts (editor save = several events).
                std::thread::sleep(DEBOUNCE);
                while rx.try_recv().is_ok() {}
                match compile(&config_path) {
                    Ok(compiled) => {
                        handle.store(Arc::new(compiled));
                        tracing::info!("config reloaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "reload failed; keeping previous config");
                    }
                }
            }
        })
        .context("spawning reload thread")?;
    Ok(())
}

/// Directory used to resolve relative source paths (config file's parent, or cwd).
fn base_dir(config_path: &Path) -> PathBuf {
    match config_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Config directory plus every secret-source file's directory (best effort).
fn dirs_to_watch(config_path: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![base_dir(config_path)];
    if let Ok(yaml) = std::fs::read_to_string(config_path) {
        if let Ok(cfg) = Config::from_yaml(&yaml) {
            let base = base_dir(config_path);
            for path in secrets::source_paths(&cfg.sources, &base) {
                let dir = match path.parent() {
                    Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                    _ => PathBuf::from("."),
                };
                if !dirs.contains(&dir) {
                    dirs.push(dir);
                }
            }
        }
    }
    dirs
}
