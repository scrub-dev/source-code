# SCRUB

**Secret Cleaning and Rehydration Utility Broker** — a single-binary forward proxy that
**masks** secrets / PII / sensitive data on outbound requests to LLM providers and
**rehydrates** (unmasks) it on the inbound response, including mid-stream.

The provider only ever sees opaque placeholders; your users receive fully reconstituted
responses. SCRUB is not an LLM gateway for routing/cost — it owns the payload and guarantees
a **lossless, reversible de-identification round trip**. The wedge is security & compliance
(SOC 2, PCI-DSS, HIPAA, GDPR).

```
        ┌────────┐   original    ┌────────┐   masked     ┌──────────┐
client ─┤  app   ├──────────────►│ SCRUB  ├─────────────►│ LLM API  │
        └────────┘  (secrets)    └────────┘ (⟦S:…⟧ ids)  └──────────┘
            ▲  rehydrated            │ reverse map (in-mem / Redis)  │
            └────────────────────────┴───────────────────────────────┘
```

- **Website:** a generated docs/guides site lives in [`website/`](website/) (shadcn-styled,
  static, deployed to GitHub Pages).
- **Docs:** [Configuration](docs/CONFIGURATION.md) · [Deployment & Ops](docs/DEPLOYMENT.md) ·
  [Use as an HTTP proxy](docs/HTTP-PROXY.md) · [Kubernetes (Helm)](docs/DEPLOYMENT.md#kubernetes-helm) ·
  [Security & Threat Model](SECURITY.md) · [Design](DESIGN.md) · [Changelog](CHANGELOG.md)
- **Example configs:** [`scrub.example.yaml`](scrub.example.yaml) ·
  [`examples/proxy.yaml`](examples/proxy.yaml) (HTTP-proxy) ·
  [`examples/common-rules.yaml`](examples/common-rules.yaml) (curated rules)

---

## How it works

1. **Detect** — on the request, SCRUB scans the configured JSON content paths
   (`messages[].content`, …) using a glossary (Aho-Corasick), a single-pass regex
   meta-engine, an optional entropy catcher, secret-store values, and an optional
   heuristic NER.
2. **Mask** — each detected span is replaced by a reversible **sentinel** `⟦S:TYPE·id⟧`.
   The `id` indexes a reverse table held only in SCRUB; the secret never leaves. Equal
   originals dedupe to the same id (stable pseudonyms).
3. **Forward** — the masked request goes to the configured upstream.
4. **Rehydrate** — as the response streams back, SCRUB splices the originals back in. It is
   correct at every byte boundary and **reassembles a sentinel fragmented across SSE
   `data:` events** (real LLM token streaming).
5. **Wipe** — request-scoped reverse maps are `zeroize`d at response end; session maps
   expire by TTL.

The reverse table is per-request by default, or **per-session** (stable pseudonyms across a
multi-turn conversation), backed by memory or Redis.

---

## Quick start

```sh
cargo run --bin scrub -- --config scrub.yaml --listen 127.0.0.1:8080
```

```yaml
# scrub.yaml
routes:
  - { listen_path: "/openai", upstream: "https://api.openai.com", profile: openai }
profiles:
  openai:
    scan_paths:   ["messages[].content"]
    stream_paths: ["choices[].delta.content"]   # required for streaming responses
rules:
  - { name: email, type: EMAIL, pattern: '[\w.+-]+@[\w.-]+\.\w+', priority: 50 }
```

Point your app at `http://scrub:8080/openai/v1/chat/completions`. The upstream sees masked
content; your app gets the rehydrated stream. Start with `masking.mode: dry-run` to validate
detection coverage before enforcing.

Prefer to set SCRUB as your **OS/app HTTP proxy** (no base-URL change)? See
[docs/HTTP-PROXY.md](docs/HTTP-PROXY.md) — `./scripts/setup-ca.sh ca` then
`scrub --config examples/proxy.yaml`.

```sh
cargo run --bin scrub demo            # offline mask → streamed echo → rehydrate
cargo run --bin scrub -- --version
cargo test                            # 73 tests
```

---

## Features

### Detection
- **Glossary** (literal terms) and **regex rules** compiled into one `regex-automata`
  meta-engine — a single pass whose cost is ~flat in rule count.
- **Curated ruleset** for popular secret formats (AWS/GCP/DigitalOcean keys; GitHub/GitLab/
  Slack/Stripe/SendGrid/Twilio/npm/OpenAI/Anthropic tokens; JWTs; PEM private keys;
  credential URLs; bearer tokens; generic assignments) in
  [`examples/common-rules.yaml`](examples/common-rules.yaml).
- **Entropy detector** for high-entropy secrets no named rule covers (opt-in).
- **Heuristic NER** for person-name PII behind a pluggable `SpanDetector` seam (opt-in;
  a model-backed detector can replace it via the same trait).
- **Secret sources** feed values into detection at startup/reload: `.env`, secret files,
  and **HashiCorp Vault** (KV v2).
- **Provider-aware scan paths** — mask only content, never `model`/metadata. Deterministic
  overlap resolution by priority.

### Masking & rehydration
- Reversible **sentinel** masking with reverse-table indices (secret never leaves SCRUB).
- **Streaming rehydration** state machine — lossless at every chunk boundary, JSON-string-safe.
- **SSE-aware rehydration** — reassembles sentinels fragmented across delta events
  (`stream_paths`).
- Per-request **dedup**; `zeroize`-on-drop vault.

### Sessions
- **Request scope** (default) or **session scope** (stable pseudonyms across a conversation,
  keyed by a request header), TTL-evicted.
- Backends: **in-memory** (single node) or **Redis** (cross-node). Each node gets a
  disjoint id space and writes per-field Redis hashes, so concurrent nodes never collide
  ids or lose entries. Stored vaults are **encrypted at rest** (AES-256-GCM) with an
  `encryption_key`.

### Policy & multi-tenancy
- **Dry-run mode** — detect and report (`x-scrub-detected` header) while forwarding the
  original, for onboarding/compliance trust.
- **Per-route policy** overrides (mode/scope/style) — e.g. dry-run a canary route.
- **Multi-tenant** — a client key → tenant with its own policy, private glossary, and
  isolated session namespace (tenant > route > global precedence).

### Security
- **Proxy auth** — optional API-key gate, compared in **constant time**; the key is never
  forwarded upstream. Unauthenticated `/healthz`.
- **TLS termination** — serve clients over HTTPS.
- **TLS interception (MITM)** — mint a per-host cert on the fly from a configured CA and
  mask any intercepted HTTPS, in **SNI-transparent** or **CONNECT-proxy** mode.
- rustls + `ring` throughout — no OpenSSL/aws-lc.

### Auditing
- **Tamper-evident audit log** — hash-chained JSONL of detections (counts/types, never
  values); `scrub audit-verify <path>` detects any edit/deletion.
- **Transaction log** — full per-request JSONL of the *masked* provider-facing request and
  response, with a `x-scrub-request-id` correlation id; secret-free in enforce mode.

### Operations
- **Hot-reload** — config + watched secret files recompile and swap atomically; a bad edit
  keeps the last good config.
- **Single static binary**, multi-arch; **container** image.

---

## Configuration

The full reference is in [docs/CONFIGURATION.md](docs/CONFIGURATION.md); the annotated
example is [`scrub.example.yaml`](scrub.example.yaml). Top-level sections:

| Section | Purpose |
|---------|---------|
| `routes[]` | inbound `listen_path` (or `host` for interception) → `upstream` + `profile` + optional policy |
| `profiles{}` | `scan_paths` (request) / `stream_paths` (SSE response) per provider |
| `masking` | global `mode` / `style` / `scope` / `ttl` / `session_header` |
| `rules[]`, `glossary[]`, `entropy`, `ner` | detection |
| `sources[]` | `.env` / secret-file / Vault ingestion |
| `auth`, `tenants[]` | proxy authentication and multi-tenant policy |
| `sessions` | `memory` / `redis` backend, `encryption_key`, `node_id` |
| `tls`, `intercept` | TLS termination / interception |
| `audit`, `transactions` | tamper-evident + full transaction logging |

**CLI:** `--config <path>`, `--listen <addr>`, `--version`, `demo`, `audit-verify <path>`.
**Env:** `SCRUB_CONFIG`, `SCRUB_LISTEN`, `RUST_LOG`, `VAULT_TOKEN`.

---

## Layout

```
crates/
  scrub-core/   I/O-free engine: config, detect, mask, scan, ner, rehydrate, sentinel, vault  (+ benches)
  scrub/        binary + lib:
                proxy (listener/router/forward), connect (CONNECT-proxy MITM),
                mitm (cert minter), secrets (.env/file/Vault), reload (watcher),
                session (backends/TTL), redis_backend, crypto (at-rest),
                audit (hash chain), transactions (request/response log), demo CLI
examples/       common-rules.yaml, …
docs/           CONFIGURATION.md, DEPLOYMENT.md
```

---

## Build & release

Static single binary, no OpenSSL (rustls + `ring`). Build all platforms with
`scripts/build-release.sh` (skips targets whose toolchain isn't installed), or via the
`Release` GitHub workflow on a `v*` tag. Supported targets:

| OS | x86_64 | aarch64 |
|----|--------|---------|
| Linux (glibc) | ✓ | ✓ |
| Linux (musl, static) | ✓ | ✓ |
| macOS | ✓ | ✓ |
| Windows | ✓ (msvc/gnu) | — |

**Container** — a multi-arch (amd64 + arm64) image is published on each release:

```sh
docker run --rm -p 8080:8080 -v "$PWD/scrub.yaml:/etc/scrub/scrub.yaml:ro" \
  ghcr.io/scrub-dev/scrub:latest --config /etc/scrub/scrub.yaml --listen 0.0.0.0:8080
```

Or build from source locally: `docker build -t scrub .`.

**Kubernetes** — a Helm chart is published as an OCI artifact on each release, with
single-node and **HA** (StatefulSet + Redis, distinct per-pod `node_id`) modes:

```sh
helm install scrub oci://ghcr.io/scrub-dev/charts/scrub --version X.Y.Z
```

See [Deployment → Kubernetes](docs/DEPLOYMENT.md#kubernetes-helm).

---

## Status

Pre-`1.0`. Feature-complete against the buildable roadmap (see [DESIGN §8](DESIGN.md)).
Deferred until `1.0`: AWS/GCP secret-manager connectors and media (image/audio) scanning —
the `SecretSource` and `SpanDetector` seams are already in place for them.

## License

Apache-2.0 — see [LICENSE](LICENSE). Report security issues per [SECURITY.md](SECURITY.md).
