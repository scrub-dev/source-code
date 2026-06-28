# Configuration Reference

SCRUB reads a single YAML config (default `scrub.example.yaml`; override with `--config`
or `SCRUB_CONFIG`). All sections are optional and default to off/empty. The annotated
[`scrub.example.yaml`](../scrub.example.yaml) is a working starting point;
[`examples/common-rules.yaml`](../examples/common-rules.yaml) is a ready-made detection
ruleset.

Config is compiled once into immutable matcher artifacts and **hot-reloaded** atomically
when the file (or a watched secret file) changes; a bad edit keeps the last good config.

- [`routes`](#routes) · [`profiles`](#profiles) · [`masking`](#masking)
- [`rules`](#rules) · [`glossary`](#glossary) · [`entropy`](#entropy) · [`ner`](#ner)
- [`sources`](#sources) · [`auth`](#auth) · [`tenants`](#tenants)
- [`sessions`](#sessions) · [`tls`](#tls) · [`intercept`](#intercept)
- [`audit`](#audit) · [`transactions`](#transactions)
- [CLI & environment](#cli--environment)

---

## `routes`

Maps inbound requests to an upstream. In normal (path) mode a route matches by
`listen_path` prefix; in [interception](#intercept) mode it matches by `host`.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `listen_path` | string | — | Inbound path prefix, e.g. `/openai`. Stripped before forwarding. |
| `host` | string | — | Host matched in interception mode (e.g. `api.openai.com`). |
| `upstream` | string | — | Base upstream URL, e.g. `https://api.openai.com`. |
| `profile` | string | — | Name of a [`profiles`](#profiles) entry. |
| `mode` | enum | global | Per-route override of `masking.mode` (`enforce`/`dry-run`). |
| `scope` | enum | global | Per-route override of `masking.scope` (`request`/`session`). |
| `style` | enum | global | Per-route override of `masking.style`. |

```yaml
routes:
  - { listen_path: "/openai",  upstream: "https://api.openai.com",    profile: openai }
  - { listen_path: "/canary",  upstream: "https://api.openai.com",    profile: openai, mode: dry-run }
  - { host: "api.openai.com",  upstream: "https://api.openai.com",    profile: openai }   # interception
```

> A route in `enforce` mode with no `scan_paths` logs a warning (it would pass requests
> through unmasked).

## `profiles`

Provider-aware content paths. A path is dot-separated; a `[]` suffix descends into every
array element. Only string leaves are masked/rehydrated.

| Key | Type | Notes |
|-----|------|-------|
| `scan_paths` | string[] | Request JSON paths to mask, e.g. `messages[].content`. |
| `stream_paths` | string[] | **SSE response** content paths to rehydrate per event, e.g. `choices[].delta.content` (OpenAI), `delta.text` (Anthropic). Required for streaming. |

```yaml
profiles:
  openai:
    scan_paths:   ["messages[].content", "messages[].tool_calls[].function.arguments"]
    stream_paths: ["choices[].delta.content"]
```

## `masking`

Global masking policy (each field overridable per route/tenant).

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `mode` | `enforce` \| `dry-run` | `enforce` | Dry-run forwards the original and only reports. |
| `style` | `typed-sentinel` \| `bare-sentinel` | `typed-sentinel` | `⟦S:EMAIL·id⟧` vs `⟦S·id⟧`. |
| `scope` | `request` \| `session` | `request` | Session scope gives stable pseudonyms across a conversation. |
| `ttl` | duration | `30m` | Session idle timeout (`45s`, `30m`, `1h`, `90`). |
| `session_header` | string | `x-scrub-session` | Request header identifying a session. |

## `rules`

Regex detection rules (compiled into one meta-engine). Patterns use Rust regex syntax;
write them as YAML single-quoted scalars so backslashes are literal.

| Key | Type | Notes |
|-----|------|-------|
| `name` | string | Label. |
| `type` | string | Entity type shown in the sentinel (e.g. `EMAIL`, `AWS_KEY`). |
| `pattern` | string | Regex. |
| `priority` | int | Higher wins on overlap. |

```yaml
rules:
  - { name: aws_key, type: AWS_KEY, pattern: '\bAKIA[0-9A-Z]{16}\b', priority: 95 }
```

See [`examples/common-rules.yaml`](../examples/common-rules.yaml) for a curated set.

## `glossary`

Literal terms (Aho-Corasick). Same matcher as secret sources.

```yaml
glossary:
  - { term: "Project Hufflepuff", type: CODENAME, priority: 100 }
```

## `entropy`

Generic high-entropy secret catcher. Off by default; low priority so named rules win.

| Key | Type | Default |
|-----|------|---------|
| `enabled` | bool | `false` |
| `min_bits` | float | `3.5` (bits/char) |
| `min_len` | int | `20` |
| `priority` | int | `10` |
| `entity_type` | string | `SECRET` |

## `ner`

Heuristic person-name detection (not a trained model; conservative). Off by default.

| Key | Type | Default |
|-----|------|---------|
| `enabled` | bool | `false` |
| `entity_type` | string | `PERSON` |
| `priority` | int | `30` |
| `names` | string[] | extra first names beyond the built-in gazetteer |

## `sources`

External secret values pulled at startup/reload and masked (same automaton as the
glossary). Each entry has a `kind`.

**`dotenv`** — each `KEY=VALUE` line contributes VALUE.
**`file`** — each non-empty, non-comment line is a literal secret.

| Key | Default | Notes |
|-----|---------|-------|
| `path` | — | File path (relative to the config dir). |
| `entity_type` | `SECRET` | |
| `priority` | `80` | |
| `min_len` | `5` | Skip values shorter than this. |

**`vault`** — HashiCorp Vault KV v2. Token resolution: `token` → `token_path` file →
`token_env` (default `VAULT_TOKEN`). Pulled at startup/reload (not polled).

| Key | Default | Notes |
|-----|---------|-------|
| `address` | — | e.g. `https://vault.internal:8200`. |
| `mount` | `secret` | KV v2 mount. |
| `paths` | — | Secret paths under the mount. |
| `token` / `token_path` / `token_env` | — | Token sources, in that order. |
| `entity_type`, `priority`, `min_len` | as above | |

```yaml
sources:
  - { kind: dotenv, path: ".env" }
  - { kind: file, path: "secrets.txt", min_len: 6 }
  - kind: vault
    address: "https://vault.internal:8200"
    paths: ["app/prod", "shared/api-keys"]
    token_env: "VAULT_TOKEN"
```

## `auth`

API-key gate on the proxy itself (keys compared in constant time; never forwarded
upstream). Required automatically when [`tenants`](#tenants) are defined.

| Key | Default | Notes |
|-----|---------|-------|
| `enabled` | `false` | |
| `header` | `x-scrub-key` | Header carrying the key. |
| `keys` | `[]` | Accepted keys. |

`/healthz` is always reachable without a key.

## `tenants`

Multi-tenant policy: a client key identifies a tenant with its own policy, private
glossary, and isolated session namespace (precedence: tenant > route > global).

| Key | Notes |
|-----|-------|
| `id` | Tenant id (used in logs/audit + session namespace). |
| `keys` | Client keys mapping to this tenant. |
| `mode` / `scope` / `style` | Optional policy overrides. |
| `glossary` | Tenant-private terms (masked only for this tenant). |

```yaml
tenants:
  - { id: acme, keys: ["acme-key"], scope: session, glossary: [ { term: "Falcon", type: CODENAME, priority: 100 } ] }
  - { id: globex, keys: ["globex-key"], mode: dry-run }
```

## `sessions`

Where session reverse-maps live.

| Key | Default | Notes |
|-----|---------|-------|
| `backend` | `memory` | `memory` (single node) or `redis` (cross-node). |
| `redis_url` | — | e.g. `rediss://redis.internal:6379/`. |
| `encryption_key` | — | Passphrase → AES-256-GCM at rest; required for secret-free Redis. |
| `node_id` | random | `0..4095`, **distinct per node**; partitions the id space. |

## `tls`

Terminate client HTTPS at the proxy (else plain HTTP). rustls + `ring`.

| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `cert_path` / `key_path` | — (PEM) |

## `intercept`

TLS interception (MITM): mint a per-host cert from a CA and route by `Host`. Clients must
trust the CA. **The CA key can mint any cert — protect it like a root key.**

| Key | Default | Notes |
|-----|---------|-------|
| `enabled` | `false` | |
| `connect` | `false` | `false` = SNI-transparent; `true` = CONNECT proxy. |
| `listen` | `--listen` | Interception endpoint. |
| `ca_cert_path` / `ca_key_path` | — | PEM CA used to mint leaf certs. |
| `upstream_ca_path` | — | Extra CA the proxy trusts for upstream connections. |

See [DEPLOYMENT.md → TLS interception](DEPLOYMENT.md#tls-interception-mitm).

## `audit`

Tamper-evident, append-only audit log (counts/types only — never values). Verify with
`scrub audit-verify <path>`.

| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `path` | `scrub-audit.jsonl` |

## `transactions`

Full request/response log of the **masked provider-facing exchange** (secret-free in
enforce mode). Each request also returns a `x-scrub-request-id` header.

| Key | Default | Notes |
|-----|---------|-------|
| `enabled` | `false` | |
| `path` | `scrub-transactions.jsonl` | |
| `max_body_bytes` | `65536` | Per-body capture limit (truncated beyond). |

---

## CLI & environment

```
scrub [--config <path>] [--listen <addr>]   # start the proxy
scrub --version                              # print version
scrub demo                                   # offline mask → rehydrate round-trip
scrub audit-verify <path>                    # verify an audit log's hash chain
```

| Env | Purpose |
|-----|---------|
| `SCRUB_CONFIG` | config path (overridden by `--config`) |
| `SCRUB_LISTEN` | listen address (overridden by `--listen`) |
| `RUST_LOG` | log filter, e.g. `scrub=info` |
| `VAULT_TOKEN` | default Vault token for `vault` sources |
| `SCRUB_SESSION_BACKEND` | override `sessions.backend` (`memory`/`redis`) |
| `SCRUB_REDIS_URL` | override `sessions.redis_url` |
| `SCRUB_ENCRYPTION_KEY` | override `sessions.encryption_key` (at-rest) |
| `SCRUB_NODE_ID` | override `sessions.node_id` (0..4095; e.g. a pod ordinal) |

The `SCRUB_*` session overrides let an orchestrator inject per-instance cluster
settings without templating the config — see
[Deployment → Kubernetes](DEPLOYMENT.md#kubernetes-helm).
