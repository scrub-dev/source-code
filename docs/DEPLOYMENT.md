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
3. Direct client traffic to SCRUB. Two modes:
   - **SNI-transparent** (`connect: false`, default): redirect the hosts to SCRUB via
     DNS/SNI; SCRUB terminates TLS using the SNI.
   - **CONNECT proxy** (`connect: true`): clients set SCRUB as their HTTP(S) proxy
     (`HTTPS_PROXY=http://scrub:8443`). SCRUB MITMs configured hosts and
     blind-tunnels everything else untouched.

> For a complete "use SCRUB as your OS HTTP proxy" walkthrough (CA setup script,
> trust-store install per OS, a ready-to-run config), see
> [HTTP-PROXY.md](HTTP-PROXY.md).

> The CA key can mint a cert for any host — restrict file permissions, keep it off
> shared storage, and rotate it. Use `intercept.upstream_ca_path` to trust an
> internal CA on the upstream side.

## High availability (multi-node)

Run several SCRUB instances behind a load balancer. For **session scope** to work
across nodes, use the Redis backend; give each node a distinct `node_id`:

```mermaid
flowchart LR
    LB["Load balancer"] --> N0["SCRUB · node_id 0"]
    LB --> N1["SCRUB · node_id 1"]
    LB --> N2["SCRUB · node_id N"]
    N0 & N1 & N2 --> R[("Redis<br/>encrypted session maps")]
    N0 & N1 & N2 --> P[["LLM provider"]]
```



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

### Full transaction log

For request/response auditing, enable the transaction log — one JSON line per
request with the **masked provider-facing** request and response bodies, a
correlation id (returned as `x-scrub-request-id`), route/tenant/status, and
detection counts:

```yaml
transactions:
  enabled: true
  path: /var/log/scrub/transactions.jsonl
  max_body_bytes: 65536
```

In **enforce** mode the captured bodies are secret-free (only sentinels). In
**dry-run** mode nothing is masked, so records reflect the original content —
protect the file accordingly.

## Configuration reference

| Setting | Purpose |
|---------|---------|
| `routes[]` | inbound path (or `host`) → upstream + profile + optional policy overrides |
| `profiles{}` | `scan_paths` (request) / `stream_paths` (SSE response) per provider |
| `masking.{mode,style,scope,ttl,session_header}` | global policy defaults |
| `rules[]`, `glossary[]`, `entropy`, `ner` | detection (curated set: `examples/common-rules.yaml`) |
| `sources[]` | `.env` / secret-file / **Vault** (KV v2) ingestion |
| `auth`, `tenants[]` | client auth and multi-tenant policy |
| `sessions` | backend (memory/redis), encryption, `node_id` |
| `tls`, `intercept` | TLS termination / interception |
| `audit` | tamper-evident log |

Env: `SCRUB_CONFIG`, `SCRUB_LISTEN`, `RUST_LOG`. CLI: `--config`, `--listen`,
`--version`, `demo`, `audit-verify <path>`.

## Containers

Each release publishes a **multi-arch (amd64 + arm64)** image to GHCR, packaging
the static musl binary into a minimal `scratch` image:

```sh
docker run --rm -p 8080:8080 -v "$PWD/scrub.yaml:/etc/scrub/scrub.yaml:ro" \
  ghcr.io/scrub-dev/scrub:latest --config /etc/scrub/scrub.yaml --listen 0.0.0.0:8080
```

Tags: `:latest` and `:vX.Y.Z`. To build from source locally instead, the
multi-stage `Dockerfile` compiles a static binary into a minimal image:
`docker build -t scrub .`.

## Kubernetes (Helm)

A Helm chart is published as an **OCI artifact** to GHCR on each release:

```sh
# Single instance, default config (dry-run reverse proxy to OpenAI).
helm install scrub oci://ghcr.io/scrub-dev/charts/scrub --version X.Y.Z

# Your own config: put the scrub.yaml contents under `config:` in values.yaml.
helm install scrub oci://ghcr.io/scrub-dev/charts/scrub --version X.Y.Z -f my-values.yaml
```

The chart runs the hardened image (non-root, read-only rootfs), mounts the config
from a ConfigMap, exposes a `ClusterIP` Service on `:8080`, and wires `/healthz`
probes. `helm test scrub` runs a health smoke test.

### High availability

```sh
helm install scrub oci://ghcr.io/scrub-dev/charts/scrub --version X.Y.Z \
  --set ha.enabled=true --set replicaCount=3 \
  --set redis.url=rediss://scrub:pass@redis:6379/0 \
  --set sessions.encryptionKey=<high-entropy secret> \
  --set config.masking.scope=session
```

`ha.enabled` switches the workload to a **StatefulSet** so each pod gets a stable
ordinal, fed to SCRUB as a **distinct `node_id`** (the id-space partition that keeps
concurrent nodes from colliding). Pods share session state via **Redis**, encrypted
at rest with your key. The chart also adds a **PodDisruptionBudget** and soft
**anti-affinity**; set `autoscaling.enabled=true` for an HPA. The topology matches
the diagram in [High availability](#high-availability-multi-node) above.

> Requires Kubernetes ≥ 1.28 (the `apps.kubernetes.io/pod-index` downward-API label).
> The chart does not deploy Redis — point `redis.url` at your own (managed, or the
> Bitnami `redis` chart).

The same wiring works **without Helm** via environment variables that override the
config's `sessions` block — handy for any orchestrator:

| Env | Overrides |
|-----|-----------|
| `SCRUB_NODE_ID` | `sessions.node_id` (0..4095) |
| `SCRUB_REDIS_URL` | `sessions.redis_url` |
| `SCRUB_ENCRYPTION_KEY` | `sessions.encryption_key` |
| `SCRUB_SESSION_BACKEND` | `sessions.backend` (`memory`/`redis`) |
