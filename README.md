# SCRUB

**Secret Cleaning and Rehydration Utility Broker** — a single-binary forward proxy
that **masks** secrets / PII / sensitive data on outbound requests to LLM providers and
**rehydrates** (unmasks) it on the inbound response, including mid-stream. The provider
only ever sees opaque placeholders; your users receive fully reconstituted responses.

See [`DESIGN.md`](DESIGN.md) for architecture, the reversibility contract, and the roadmap.

## Status

**v0.1.0** — first pre-release. Full mask→upstream→rehydrate round trip with correct
real-LLM streaming, sessions (in-mem + Redis, encrypted), multi-tenant policy, dry-run,
tamper-evident audit, TLS termination + interception, and heuristic NER — verified
end-to-end. Cloud secret-store connectors and media scanning are deferred until `1.0`
(see [`DESIGN.md`](DESIGN.md) §8). See [`CHANGELOG.md`](CHANGELOG.md),
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), and [`SECURITY.md`](SECURITY.md).

Implemented:
- Sentinel grammar (`⟦S:TYPE·id⟧`) with reverse-table indices — the secret never leaves SCRUB.
- Config-driven detection: glossary (Aho-Corasick) + regex rules, deterministic overlap resolution.
- Provider-aware **scan paths** (`messages[].content`, …) — mask only content, not metadata.
- Egress masking with per-request dedup and `zeroize`-on-drop vault.
- **Streaming rehydration state machine** — correct at every chunk boundary (tested byte-by-byte),
  JSON-string-safe so a spliced original can't break the SSE/JSON frame.
- **SSE-aware rehydration** — a sentinel fragmented across `data:` delta events (real LLM
  streaming) reassembles via per-event content rehydration (`stream_paths`).
- **Async proxy**: route matching to upstream URLs, request masking, streamed response rehydration.
- **Secret sources**: `.env`, secret-file, and **HashiCorp Vault** (KV v2) ingestion feeding
  the same masking automaton. Curated rules for common token/key formats in
  [`examples/common-rules.yaml`](examples/common-rules.yaml).
- **Hot-reload**: config + watched source files recompile and swap atomically (`arc-swap`); a
  bad edit keeps the last good config. No restart needed.
- **Session scope**: shared per-session vault keyed by a request header → stable pseudonyms
  across a multi-turn conversation, with TTL-based eviction (secrets zeroized on evict).
- **Dry-run mode**: detect and report (`x-scrub-detected: EMAIL=2` header, counts/types only)
  while forwarding the original upstream — for onboarding/compliance trust before enforcing.
- **Entropy detector**: flags high-entropy token-like secrets no named rule covers (opt-in).
- **NER/PII detector**: heuristic person-name detection behind a pluggable `SpanDetector`
  seam (a model-backed detector can slot in later via the same trait); opt-in.
- **Per-route policy**: each route can override the global mode/scope/style (e.g. dry-run a canary).
- **Proxy auth**: optional API-key gate on the proxy itself; the key is never forwarded upstream.
- **Multi-tenant**: a client key maps to a tenant with its own policy, private glossary, and
  isolated session namespace (tenant > route > global precedence).
- **Cross-node sessions**: pluggable session backend — in-memory (single node) or Redis, so a
  session started on one node rehydrates on another. Each node gets a **disjoint id space**
  and writes **per-field Redis hashes**, so concurrent nodes never collide ids or lose entries.
  Stored vaults are **encrypted at rest** (AES-256-GCM) when an `encryption_key` is set.
- **Tamper-evident audit**: hash-chained JSONL of detections (counts/types, never values);
  any edit/deletion breaks the chain. Verify with `scrub audit-verify <path>`.
- **Transaction log**: full per-request JSONL of the *masked* provider-facing request/response
  (correlation id via `x-scrub-request-id`) — auditable, secret-free in enforce mode.
- **Hardened auth**: API keys compared in constant time; unauthenticated `/healthz` liveness.
- **TLS termination**: serve clients over HTTPS (rustls + `ring`, no OpenSSL/aws-lc).
- **TLS interception (MITM)**: mints a per-host cert on the fly from a configured CA and masks
  intercepted HTTPS — in **SNI-transparent** or **CONNECT-proxy** mode (clients trust the CA).
- Provider-agnostic config (`routes` -> upstream URLs), criterion benches.

## Layout

```
crates/
  scrub-core/   engine: config, detect, mask, scan, ner, rehydrate, sentinel, vault  (+ benches)
  scrub/        binary + lib: proxy (listener/router), secrets (.env/file), reload (watcher),
                session (backends/TTL), redis_backend, crypto (at-rest), audit, mitm (cert minter), demo CLI
```

## Try it

```sh
cargo test                          # 65 tests incl. split-sentinel, e2e proxy, reload, session,
                                    # dry-run, auth, tenant, cross-node, crypto, audit, TLS+MITM, NER, SSE-stream, soak
cargo run --bin scrub demo          # offline mask -> streamed echo -> rehydrate
cargo run --bin scrub -- --config scrub.example.yaml --listen 127.0.0.1:8080
cargo bench                         # mask / rehydrate throughput
```

Point a client at `http://127.0.0.1:8080/<route>/…` (e.g. `/openai/v1/chat/completions`);
SCRUB masks the request, forwards to the route's upstream, and rehydrates the streamed
response. Configuration: see [`scrub.example.yaml`](scrub.example.yaml).

## Release builds

Single static binary, no OpenSSL (rustls + `ring`). Build all platforms with
`scripts/build-release.sh` (skips targets whose toolchain isn't installed), or via the
`Release` GitHub workflow on a `v*` tag. Supported targets:

| OS | x86_64 | aarch64 |
|----|--------|---------|
| Linux (glibc) | ✓ | ✓ |
| Linux (musl, static) | ✓ | ✓ |
| macOS | ✓ | ✓ |
| Windows | ✓ (msvc/gnu) | — |
