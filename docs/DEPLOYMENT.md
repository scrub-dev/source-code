# Deployment & Operations

This guide covers running SCRUB in production. See [`SECURITY.md`](../SECURITY.md)
for the threat model and [`scrub.example.yaml`](../scrub.example.yaml) for the full
annotated config.

## Modes

SCRUB runs in one of three serving modes (chosen by config):

| Mode | How clients reach it | Config |
|------|----------------------|--------|
| **Explicit endpoint** (default) | Point the client base URL at SCRUB and a `listen_path` route | `routes[].listen_path` |
| **TLS termination** | Same, but over HTTPS | `tls.enabled` + cert/key |
| **TLS interception (MITM)** | Transparent: client trusts SCRUB's CA; SCRUB mints per-host certs and routes by `Host` | `intercept.enabled` + CA + `routes[].host` |

Explicit-endpoint mode is the simplest and most robust — prefer it unless you
need to intercept clients you can't reconfigure.

## Quick start (explicit endpoint)

```sh
scrub --config scrub.yaml --listen 0.0.0.0:8080
```

```yaml
routes:
  - listen_path: "/openai"
    upstream: "https://api.openai.com"
    profile: openai
profiles:
  openai:
    scan_paths:  ["messages[].content"]
    stream_paths: ["choices[].delta.content"]   # required for streaming responses
rules:
  - { name: email, type: EMAIL, pattern: '[\w.+-]+@[\w.-]+\.\w+', priority: 50 }
```

Then point your app at `http://scrub:8080/openai/v1/chat/completions`.

> **Streaming:** set `stream_paths` for any provider you stream from. Without it, a
> sentinel fragmented across SSE `data:` events will not rehydrate. (`choices[].delta.content`
> for OpenAI, `delta.text` for Anthropic.)

## Onboarding safely (dry-run)

Run a new route in `mode: dry-run` first. SCRUB forwards the **original** payload
but reports what it *would* mask via the `x-scrub-detected` response header and
logs — validate coverage, then switch to `enforce`.

## TLS termination

```yaml
tls:
  enabled: true
  cert_path: /etc/scrub/tls/cert.pem
  key_path:  /etc/scrub/tls/key.pem
```

## TLS interception (MITM)

1. Create a CA (once) and distribute the **cert** to client trust stores:
   ```sh
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
     -keyout ca.key -out ca.pem -days 3650 -nodes -subj "/CN=SCRUB CA"
   ```
2. Configure interception and host-routed entries:
   ```yaml
   intercept:
     enabled: true
     listen: "0.0.0.0:8443"
     ca_cert_path: /etc/scrub/ca/ca.pem
     ca_key_path:  /etc/scrub/ca/ca.key      # protect like a root signing key
   routes:
     - { host: "api.openai.com", upstream: "https://api.openai.com", profile: openai }
   ```
3. Direct client traffic for those hosts to SCRUB (DNS / SNI redirection).

> The CA key can mint a cert for any host — restrict file permissions, keep it off
> shared storage, and rotate it. Use `intercept.upstream_ca_path` to trust an
> internal CA on the upstream side.

## High availability (multi-node)

Run several SCRUB instances behind a load balancer. For **session scope** to work
across nodes, use the Redis backend; give each node a distinct `node_id`:

```yaml
sessions:
  backend: redis
  redis_url: "rediss://redis.internal:6379/"
  encryption_key: "<high-entropy secret, identical on every node>"
  node_id: 1     # 0..4095, unique per node
```

- Node ids partition the sentinel id space, so concurrent nodes never collide.
- Enable `encryption_key` so Redis holds only ciphertext; run Redis with AUTH+TLS.
- Sticky sessions (route a conversation to one node) give the strongest ordering;
  without them, concurrent writes to the same session are last-write-wins per field.

Request scope needs no shared state — any node handles any request.

## Health & observability

- `GET /healthz` → `200 ok` (unauthenticated) for load-balancer liveness.
- Response headers `x-scrub-mode` and `x-scrub-detected` (counts/types only).
- Logs are structured (`RUST_LOG=scrub=info`); they never contain secret values.

## Audit

```yaml
audit:
  enabled: true
  path: /var/log/scrub/audit.jsonl
```

Verify integrity any time:

```sh
scrub audit-verify /var/log/scrub/audit.jsonl
# OK: N record(s) verified, chain intact   (exit 0)
# TAMPERED: chain breaks at record seq K   (exit 1)
```

Ship the file to append-only/WORM storage for compliance.

## Configuration reference

| Setting | Purpose |
|---------|---------|
| `routes[]` | inbound path (or `host`) → upstream + profile + optional policy overrides |
| `profiles{}` | `scan_paths` (request) / `stream_paths` (SSE response) per provider |
| `masking.{mode,style,scope,ttl,session_header}` | global policy defaults |
| `rules[]`, `glossary[]`, `entropy`, `ner` | detection |
| `sources[]` | `.env` / secret-file ingestion |
| `auth`, `tenants[]` | client auth and multi-tenant policy |
| `sessions` | backend (memory/redis), encryption, `node_id` |
| `tls`, `intercept` | TLS termination / interception |
| `audit` | tamper-evident log |

Env: `SCRUB_CONFIG`, `SCRUB_LISTEN`, `RUST_LOG`. CLI: `--config`, `--listen`,
`--version`, `demo`, `audit-verify <path>`.

## Containers

A multi-stage `Dockerfile` builds a static (musl) binary into a minimal image:

```sh
docker build -t scrub:0.1.0 .
docker run --rm -p 8080:8080 -v "$PWD/scrub.yaml:/etc/scrub/scrub.yaml:ro" \
  scrub:0.1.0 --config /etc/scrub/scrub.yaml --listen 0.0.0.0:8080
```
