# Getting Started

SCRUB is a single binary. You give it a config that says **which upstreams to proxy**,
**which JSON paths to scan**, and **what to detect** — then point your app at it.

## 1. Install

Grab a binary from the [releases](https://github.com/scrub-dev/source-code/releases)
(Linux/macOS/Windows, x86_64 + arm64), or run the container:

```sh
docker run --rm -p 8080:8080 -v "$PWD/scrub.yaml:/etc/scrub/scrub.yaml:ro" \
  ghcr.io/scrub-dev/scrub:latest --config /etc/scrub/scrub.yaml --listen 0.0.0.0:8080
```

Or build from source: `cargo build --release -p scrub`.

## 2. Write a config

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
masking:
  mode: dry-run     # detect & report first; switch to enforce when you trust coverage
```

## 3. Run it

```sh
scrub --config scrub.yaml --listen 127.0.0.1:8080
```

Point your app's base URL at `http://127.0.0.1:8080/openai` instead of
`https://api.openai.com`. That's it — requests are scanned, the upstream sees masked
content, and the streamed response comes back rehydrated.

## 4. Validate, then enforce

Run in **`dry-run`** first: SCRUB detects and reports (via the `x-scrub-detected`
response header and the [audit log](../docs/security.html)) but forwards the original,
so you can confirm coverage without risk. When you're happy, set `masking.mode: enforce`.

```sh
scrub demo            # offline: mask → streamed echo → rehydrate, no network
```

## The mental model

```
your app ──original──► SCRUB ──masked (⟦S:TYPE·id⟧)──► provider
        ◄─rehydrated──        ◄──────────────────────
```

- **Detect** secrets/PII on the configured request paths.
- **Mask** each hit with a reversible sentinel; the real value is kept only inside SCRUB.
- **Forward** the masked request upstream.
- **Rehydrate** the response stream, splicing originals back — correct even when a
  sentinel is split across SSE token events.
- **Wipe** the per-request map when the response ends.

## Where to next

- [Why SCRUB?](why-scrub.html) — the problem, the benefits, and the trade-offs.
- [Detection & masking rules](rules.html) — write rules, use the curated ruleset.
- [Use as an HTTP proxy](http-proxy.html) — set SCRUB as your OS proxy (no base-URL change).
- [Configuration reference](../docs/configuration.html) — every config key.
