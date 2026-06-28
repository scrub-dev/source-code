# Changelog

All notable changes to SCRUB are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/) once it reaches `1.0`.

## [Unreleased]

### Added
- **HashiCorp Vault secret source** (`sources[].kind: vault`): pull KV v2 secret
  values at startup/reload and mask them, via the same `SecretSource` seam as
  `.env`/file sources (token from config / file / env).
- **Curated default rules** (`examples/common-rules.yaml`): ready-to-use regex
  ruleset for popular secret formats — AWS/GCP/DigitalOcean keys, GitHub/GitLab
  tokens, Slack/Stripe/SendGrid/Twilio/npm/OpenAI/Anthropic tokens, JWTs, PEM
  private keys, credential URLs, bearer tokens, and generic assignments — plus a
  high-entropy catcher. Validated by tests.

## [0.2.0] — 2026-06-28

### Added
- **CONNECT-proxy TLS interception** (`intercept.connect: true`): clients set SCRUB
  as their HTTP proxy; SCRUB handles `CONNECT`, MITMs configured hosts (per-host
  minted certs), and blind-tunnels the rest. Complements the existing
  SNI-transparent interception.

## [0.1.0] — 2026-06-28

First public pre-release. A single-binary forward proxy that masks secrets / PII
before requests reach an LLM provider and rehydrates them on the response,
including across streamed responses.

### Core engine (`scrub-core`)
- Reversible **sentinel** masking (`⟦S:TYPE·id⟧`); the id is an index into a
  request- or session-scoped reverse table, so the secret never leaves SCRUB.
- Detection: glossary (Aho-Corasick) + regex rules compiled into a single
  `regex-automata` meta-engine (one pass), deterministic overlap resolution,
  optional Shannon-entropy secret catcher, and a pluggable `SpanDetector` seam.
- **Streaming rehydration** state machine — lossless at every chunk boundary,
  JSON-string-safe, and **SSE-aware** (reassembles a sentinel fragmented across
  `data:` delta events, as real LLM streaming produces).
- `zeroize`-on-drop vault; provider-aware scan paths.

### Proxy (`scrub`)
- Async forward proxy (axum + reqwest); provider-agnostic upstream routing.
- **Hot-reload** of config + watched secret files (`arc-swap`); bad edits keep the
  last good config.
- **Secret sources**: `.env` and secret-file ingestion.
- **Sessions**: per-conversation stable pseudonyms; in-memory or **Redis** backend
  with node-disjoint id spaces + per-field hashes (no cross-node collisions or
  lost entries) and **AES-256-GCM at-rest encryption**.
- **Multi-tenant** policy (key → tenant → policy/glossary/isolated sessions),
  **per-route** policy overrides, and **dry-run** (report-only) mode.
- **Heuristic NER** person-name detection behind the `SpanDetector` seam.
- **Auth**: constant-time API-key check; key never forwarded upstream;
  unauthenticated `/healthz`.
- **TLS termination** and **SNI-transparent TLS interception (MITM)** with
  on-the-fly per-host certificate minting from a configured CA.
- **Tamper-evident audit log** (hash-chained JSONL; `scrub audit-verify`).
- Config-misconfiguration warnings (unknown profile, enforce route with no scan paths).

### Release
- Static single binary (rustls + `ring`, no OpenSSL/aws-lc).
- Multi-arch builds: linux gnu/musl × x86_64/aarch64, macOS x86_64/aarch64,
  Windows — via `scripts/build-release.sh` and the `Release` CI workflow.

### Deferred (until a stable `1.0`)
- Cloud secret-store connectors (Vault / AWS / GCP) — the `SecretSource` seam is in place.
- Media (image/audio) scanning — the `Detector`/`Span` seam is in place.
- CONNECT-proxy MITM mode (current interception is SNI-transparent).

[0.2.0]: https://github.com/scrub-dev/scrub/releases/tag/v0.2.0
[0.1.0]: https://github.com/scrub-dev/scrub/releases/tag/v0.1.0
