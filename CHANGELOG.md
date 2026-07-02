# Changelog

All notable changes to SCRUB are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

## [1.0.2] — 2026-06-29

### Added
- **AI-agent onboarding**: a root `SKILL.md` (agent skill) describing how to
  self-install and operate SCRUB, plus generated `/llms.txt` and `/llms-full.txt`
  on the docs site (the [llmstxt.org](https://llmstxt.org) convention) so AI agents
  can discover, install, and use SCRUB.

## [1.0.1] — 2026-06-29

Security-hardening release following a deep review of the data path. The only wire
change is the sentinel format (`⟦S:TYPE·id·tag⟧`); multi-node clusters must set
`sessions.encryption_key` (see below).

### Security — sentinel authentication & masking coverage
- **Authenticated sentinels** — every sentinel now carries a per-vault keyed MAC
  tag (`⟦S:TYPE·id·tag⟧`, HMAC-SHA256). Rehydration resolves an id only if its tag
  matches, so a hostile/compromised upstream can no longer forge or blindly
  enumerate sentinels (`⟦S·0⟧`, `⟦S·1⟧`, …) to read a session vault. Cross-node
  session tag keys derive from `sessions.encryption_key` (set it on clusters).
- **Enforce mode fails closed on unparseable JSON** — a JSON-typed request body
  that doesn't parse is rejected (422) instead of forwarded unmasked.
- **Opt-in comprehensive scanning** — `scan_paths: ["**"]` (and `stream_paths`)
  scans/rehydrates *every* string leaf, for deployments that want maximum coverage
  over provider-aware minimalism.

### Security — SSRF, isolation, DoS, and fail-closed
- **Upstream redirects are no longer followed** (proxy, interception, and Vault
  clients). Prevents SSRF to internal/metadata endpoints and stops a malicious
  upstream from getting a rehydrated (secret-bearing) response via a redirect; the
  Vault connector can no longer leak `X-Vault-Token` to a redirect target.
- **Session vaults are tenant-isolated by an unforgeable namespace scheme** — a
  flat-auth (non-tenant) client can no longer craft a session key that collides
  with a tenant's vault.
- **CONNECT-proxy tunnels refuse loopback / link-local targets** (blocks the cloud
  metadata endpoint `169.254.169.254` and localhost pivots) and connect to the
  exact vetted IP (no DNS-rebind window).
- **Certificate minting is restricted to configured interception hosts** (+ a cache
  cap), preventing a DoS from unbounded key-generation on arbitrary SNI values.
- **Audit and transaction logs are created `0600`** (owner-only) on Unix — the
  transaction log can hold original content in dry-run mode.
- **Proxy auth compares fixed-length SHA-256 digests** in constant time, removing a
  key-length timing side channel.
- **Vault dedup is keyed by the exact original bytes**, not a truncated 64-bit
  hash — two distinct secrets can no longer be conflated into one sentinel (which
  would mis-rehydrate one secret as another in a shared session vault). All
  plaintext copies (forward keys + reverse values) are zeroized on drop.
- **Per-leaf streaming rehydration**: each response content leaf (e.g. each
  `choices[i].delta.content`) gets its own rehydrator, so a partial sentinel's
  carry can no longer bleed between leaves and leak an un-rehydrated sentinel when
  `n > 1` (multiple choices / content items) with a sentinel split across events.
- **Id-space exhaustion is fail-safe**: a session vault never mints an id past its
  node's range (which would rehydrate to the wrong secret across nodes) — on
  exhaustion the value is masked with a reserved non-reversible id.
- **Secret-source loading fails closed**: if a configured source (file/Vault)
  errors, reload keeps the previous good config and startup refuses, rather than
  silently running with reduced masking coverage.
- **Loud warning when `sessions.node_id` is unset** with the Redis backend (random
  fallback can collide across nodes); Redis read failures are logged (not silently
  treated as an empty session); `masking.ttl` parsing no longer overflows.

## [1.0.0] — 2026-06-28

First production release. SCRUB is a single-binary forward proxy that masks
secrets / PII / sensitive data on outbound LLM-provider requests and rehydrates
them on responses (including streaming). The `0.x` entries below built up to this;
from `1.0` the public CLI, config schema, and chart values follow SemVer.

### Highlights
- **Engine**: reversible sentinel masking (`⟦S:TYPE·id⟧`), single-pass detection
  (glossary + regex meta-engine + entropy + heuristic NER), provider-aware scan
  paths, and streaming/SSE-correct rehydration.
- **Secret sources**: `.env`, file, and HashiCorp Vault (KV v2); a curated ruleset.
- **Sessions**: request- or session-scoped pseudonyms; in-memory or Redis backend
  with node-disjoint ids and AES-256-GCM at-rest encryption.
- **Policy**: dry-run, per-route overrides, multi-tenant isolation, constant-time auth.
- **Transport**: TLS termination and interception (SNI-transparent + CONNECT proxy)
  with on-the-fly per-host certs; usable as an OS HTTP proxy.
- **Auditing**: tamper-evident hash-chained audit log + full (masked) transaction log.
- **Delivery**: static multi-arch binaries, a multi-arch container image, and a
  Helm chart (single-node + HA StatefulSet/Redis) published as an OCI artifact;
  a documentation website.

## [0.4.2] — 2026-06-28

### Fixed
- **Image tag now matches the chart**: the release publishes a bare-semver image
  tag (`scrub:X.Y.Z`, no leading `v`) alongside `:vX.Y.Z`/`:latest`, so the Helm
  chart's `appVersion`-derived default image reference resolves.

### Added
- **Chart E2E smoke test**: a `kind` workflow installs the chart (default +
  HA/bundled-Redis) and runs `helm test` against a real cluster.

## [0.4.1] — 2026-06-28

### Added
- **Bundled Redis option** for the Helm chart (`redis.enabled=true`): a turnkey,
  dependency-free single Redis (official image, optional persistence) for HA, with
  the Redis URL + at-rest key kept in a Secret and injected via `secretKeyRef`.
  External/managed Redis (`redis.url`) remains the production path.
- **"Deploy on Kubernetes" guide** on the docs website.

## [0.4.0] — 2026-06-28

### Added
- **Helm chart** (`charts/scrub`), published as an **OCI artifact** to GHCR on each
  release (`oci://ghcr.io/scrub-dev/charts/scrub`). Single-node by default; an
  `ha.enabled` mode runs a **StatefulSet + Redis** where each pod gets a distinct
  `node_id` from its ordinal (PodDisruptionBudget, anti-affinity, optional HPA).
- **Session env overrides** — `SCRUB_NODE_ID`, `SCRUB_REDIS_URL`,
  `SCRUB_ENCRYPTION_KEY`, `SCRUB_SESSION_BACKEND` override the config's `sessions`
  block, so an orchestrator can inject per-instance cluster settings without
  templating the config file.
- **Documentation website** (`website/`): a zero-runtime static site (landing + docs +
  guides) styled in the shadcn design language, generated from the repository's canonical
  Markdown by a small Python builder, auto-deployed to GitHub Pages. Renders ` ```mermaid `
  blocks as theme-aware diagrams (loaded only on pages that have one).
- **HTTP-proxy quickstart**: `docs/HTTP-PROXY.md` (use SCRUB as your OS/app HTTP
  proxy), a ready-to-run `examples/proxy.yaml` (CONNECT-proxy interception for
  OpenAI/Anthropic/Gemini/Mistral wired to the curated ruleset), and
  `scripts/setup-ca.sh` (generate + OS-trust an interception CA).

## [0.3.3] — 2026-06-28

### CI/CD
- **Clean container manifest**: disable buildx provenance/SBOM attestations so the
  multi-arch image index is strictly `linux/amd64` + `linux/arm64` (no
  `unknown/unknown` attestation manifests).

## [0.3.2] — 2026-06-28

### CI/CD
- **Multi-arch container image**: the release now publishes a `linux/amd64` +
  `linux/arm64` image to GHCR (`ghcr.io/scrub-dev/scrub:<tag>` + `:latest`),
  packaging the prebuilt static musl binaries (no in-image compilation).

## [0.3.1] — 2026-06-28

### CI/CD
- **Release pipeline hardened**: SHA-256 `SHA256SUMS` for every artifact,
  CHANGELOG-derived release notes, a published GHCR container image
  (`ghcr.io/scrub-dev/scrub:<tag>` + `:latest`), and concurrency guards.
- **CI** now runs the test suite on Linux, macOS, and Windows.
- Fixed the release workflow's duplicate-`.cargo/config.toml` bug that failed
  all Linux build legs.

## [0.3.0] — 2026-06-28

### Added
- **Request/response transaction log** (`transactions.enabled`): one JSON line per
  request capturing the **masked provider-facing exchange** (request sent upstream
  + response received), with a correlation id (`x-scrub-request-id` header), route,
  tenant, status, and detection counts. Secret-free in enforce mode by design;
  bodies bounded by `max_body_bytes`.
- **HashiCorp Vault secret source** (`sources[].kind: vault`): pull KV v2 secret
  values at startup/reload and mask them, via the same `SecretSource` seam as
  `.env`/file sources (token from config / file / env).
- **Curated default rules** (`examples/common-rules.yaml`): ready-to-use regex
  ruleset for popular secret formats — AWS/GCP/DigitalOcean keys, GitHub/GitLab
  tokens, Slack/Stripe/SendGrid/Twilio/npm/OpenAI/Anthropic tokens, JWTs, PEM
  private keys, credential URLs, bearer tokens, and generic assignments — plus a
  high-entropy catcher. Validated by tests.

### Docs
- Comprehensive README and a full configuration reference (`docs/CONFIGURATION.md`).

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

[1.0.2]: https://github.com/scrub-dev/scrub/releases/tag/v1.0.2
[1.0.1]: https://github.com/scrub-dev/scrub/releases/tag/v1.0.1
[1.0.0]: https://github.com/scrub-dev/scrub/releases/tag/v1.0.0
[0.4.2]: https://github.com/scrub-dev/scrub/releases/tag/v0.4.2
[0.4.1]: https://github.com/scrub-dev/scrub/releases/tag/v0.4.1
[0.4.0]: https://github.com/scrub-dev/scrub/releases/tag/v0.4.0
[0.3.3]: https://github.com/scrub-dev/scrub/releases/tag/v0.3.3
[0.3.2]: https://github.com/scrub-dev/scrub/releases/tag/v0.3.2
[0.3.1]: https://github.com/scrub-dev/scrub/releases/tag/v0.3.1
[0.3.0]: https://github.com/scrub-dev/scrub/releases/tag/v0.3.0
[0.2.0]: https://github.com/scrub-dev/scrub/releases/tag/v0.2.0
[0.1.0]: https://github.com/scrub-dev/scrub/releases/tag/v0.1.0
