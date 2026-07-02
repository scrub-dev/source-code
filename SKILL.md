---
name: scrub
description: >-
  Install, configure, and operate SCRUB — a reversible secret/PII masking proxy for
  LLM traffic. Use this when the user wants to stop secrets or PII from reaching an
  LLM provider (OpenAI/Anthropic/Gemini/Mistral/any HTTP LLM API), put SCRUB in front
  of a provider, write detection rules, run it as a reverse proxy or OS HTTP proxy, or
  deploy it via prebuilt binary, container, or Kubernetes/Helm.
license: Apache-2.0
homepage: https://github.com/scrub-dev/source-code
docs: https://scrub-dev.github.io/source-code/
---

# SCRUB — reversible secret & PII masking proxy

SCRUB is a single static binary that sits between an app and an LLM provider. On the
request it **masks** detected secrets/PII by replacing each with a reversible sentinel
`⟦S:TYPE·id·tag⟧`; on the response it **rehydrates** them (including mid-stream). The
provider only ever sees placeholders — the secret never leaves SCRUB. It is not an LLM
router; it owns the payload and guarantees a lossless, reversible round trip.

## When to use it
- An app sends user- or developer-authored text to an LLM API and must not leak API
  keys, tokens, customer PII, internal hostnames, etc. under SOC 2 / PCI-DSS / HIPAA / GDPR.
- You want frontier models but can't let raw secrets cross the wire.

## Install (pick one)

Prebuilt binary (fastest — no toolchain):
- Download from https://github.com/scrub-dev/source-code/releases (Linux/macOS/Windows,
  x86_64 + aarch64), verify against `SHA256SUMS`, then `scrub --version`.

Container (multi-arch):
```sh
docker run --rm -p 8080:8080 -v "$PWD/scrub.yaml:/etc/scrub/scrub.yaml:ro" \
  ghcr.io/scrub-dev/scrub:latest --config /etc/scrub/scrub.yaml --listen 0.0.0.0:8080
```

Kubernetes (OCI Helm chart):
```sh
helm install scrub oci://ghcr.io/scrub-dev/charts/scrub --version <X.Y.Z>
```

From source (Rust):
```sh
cargo build --release -p scrub   # binary at target/release/scrub
```

## Minimal config + run (reverse-proxy mode — recommended)
```yaml
# scrub.yaml
routes:
  - { listen_path: "/openai", upstream: "https://api.openai.com", profile: openai }
profiles:
  openai:
    scan_paths:   ["messages[].content"]        # request fields to mask
    stream_paths: ["choices[].delta.content"]    # response fields to rehydrate (SSE)
rules:
  - { name: email, type: EMAIL, pattern: '[\w.+-]+@[\w.-]+\.\w+', priority: 50 }
masking:
  mode: dry-run   # validate coverage first; switch to `enforce` when ready
```
```sh
scrub --config scrub.yaml --listen 127.0.0.1:8080
```
Then point the app's base URL at `http://127.0.0.1:8080/openai` instead of
`https://api.openai.com`. The upstream sees masked content; the app gets the
rehydrated stream, plus `x-scrub-detected` and `x-scrub-request-id` response headers.

## Recommended workflow (in order)
1. Start in **`masking.mode: dry-run`** — SCRUB detects and reports but forwards the
   original. Confirm coverage via the `x-scrub-detected` header and the audit log.
2. Switch to **`mode: enforce`** once coverage looks right.
3. Adopt the curated ruleset: copy `examples/common-rules.yaml` (AWS/GCP/GitHub/Slack/
   Stripe/OpenAI/Anthropic tokens, JWTs, PEM keys, credential URLs, …) into `rules:`.
4. Verify offline any time with `scrub demo` (mask → streamed echo → rehydrate).

## Two ways to deploy
- **Reverse proxy** (above): change one base URL. No CA, no SDK change. Prefer this.
- **OS HTTP proxy**: set SCRUB as `HTTPS_PROXY`; it MITMs configured hosts and tunnels
  the rest. Requires a CA (`./scripts/setup-ca.sh`) and `intercept:` config. See the
  HTTP-proxy guide.

## Facts an agent must not get wrong
- SCRUB masks the **configured `scan_paths`** only. Secrets outside those paths, or in a
  **non-JSON** body, are **not** masked. Use `scan_paths: ["**"]` to scan every string leaf.
- In **enforce** mode, a JSON-typed body that fails to parse is **rejected (422)**, not
  forwarded.
- Sentinels are `⟦S:TYPE·id·tag⟧` and **authenticated** (the `tag` is a keyed MAC). Do
  not fabricate or hand-edit them; only SCRUB-issued sentinels rehydrate.
- **Session scope** (`masking.scope: session` + a session header) gives stable pseudonyms
  across a conversation. Session-header values are **bearer secrets** — one per user,
  unguessable.
- **Multi-node HA** (Redis): give each node a distinct `sessions.node_id` (or
  `SCRUB_NODE_ID`) **and** a shared `sessions.encryption_key` — the latter is required for
  cross-node rehydration and at-rest encryption.
- The interception **CA key can mint any cert — never commit or share it**.
- `/healthz` is unauthenticated (for load balancers).

## CLI & environment
```
scrub [--config <path>] [--listen <addr>]   # start the proxy
scrub --version | demo | audit-verify <path>
```
Env: `SCRUB_CONFIG`, `SCRUB_LISTEN`, `RUST_LOG`, `VAULT_TOKEN`,
`SCRUB_NODE_ID`, `SCRUB_REDIS_URL`, `SCRUB_ENCRYPTION_KEY`, `SCRUB_SESSION_BACKEND`.

## Learn more
- Docs site: https://scrub-dev.github.io/source-code/
- Everything in one file (for ingestion): https://scrub-dev.github.io/source-code/llms-full.txt
- Configuration reference, Deployment/Kubernetes, Security & threat model, HTTP-proxy —
  all linked from the site and from `/llms.txt`.
