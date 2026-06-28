# SCRUB — Design

**Secret Cleaning and Rehydration Utility Broker**

A single-binary forward proxy that **masks** secrets / PII / sensitive data on outbound
requests and **rehydrates** (unmasks) it on the inbound response — including mid-stream.
It sits between your applications and external LLM providers so the provider only ever
sees opaque placeholders, while your users still receive fully reconstituted responses.

> Positioning: an LLM gateway optimizes routing, cost, and caching and treats the payload
> as opaque. SCRUB does the opposite — it owns the payload and guarantees a lossless,
> reversible de-identification round trip. The wedge is security & compliance
> (SOC 2, PCI-DSS, HIPAA, GDPR), not routing.

---

## 1. Goals & non-goals

### Goals
- **Lossless reversibility.** `mask → provider → rehydrate` reconstructs the original
  exactly. A leaked placeholder in user output is treated as a correctness failure.
- **Streaming-first.** Full SSE/chunked support with minimal added time-to-first-token.
- **Speed.** Sub-millisecond, near-zero-allocation scan on the hot path; overhead
  dominated by the upstream provider, not by SCRUB.
- **Config-driven first.** Glossary + regex + entropy rules from config files, hot-reloaded.
- **Provider-agnostic.** Upstreams (endpoint URLs) are defined in config, not hardcoded.
  Any OpenAI/Anthropic-compatible or arbitrary HTTP(S) model API works by adding a route.
- **Single binary, multi-arch.** No mandatory external dependency for single-node operation.
- **Provable compliance story.** The provider demonstrably saw only opaque ids;
  audit log records *what categories* were masked, never the values.

### Non-goals (initially)
- TLS interception / MITM. v0 is an **explicit endpoint** (clients point at SCRUB and
  SCRUB re-originates upstream). MITM is a later option, not the default.
- ML/NER PII detection inline. Deferred to a later phase behind the same span interface.
- Cost-based routing / load-balancing *across* providers (that's an LLM-gateway concern).
  Note: SCRUB still *routes by upstream* — each inbound route maps to a configured upstream
  URL — it just doesn't make cost/latency routing decisions.
- Media (image / audio / document) content scanning. Text-only in v0, but the pipeline is
  designed so a media `Detector` slots in later behind the same span interface (see §6, §8).

### Primary users
- **Enterprises** placing a compliance guardrail in front of external LLM APIs.
- **Developers** who want the same protection locally (later fed by `.env` / secret-file scans).

---

## 2. Reversibility model (the core decision)

Masking must be **reversible**, which rules out format-preserving fake values as the
default. A fake-but-valid replacement (e.g. swapping one email for another) looks natural
to the model, but on the return path it is indistinguishable from ordinary text. If the
model reformats, translates, or "corrects" it even slightly, rehydration silently fails
and a placeholder leaks. Unacceptable under a reversibility guarantee.

### Sentinel grammar

Default to a **deterministic sentinel** the model treats as an opaque identifier and tends
to pass through unchanged:

```
⟦S·7f3a⟧            bare      (generic)
⟦S:EMAIL·7f3a⟧      typed     (type hint keeps model output coherent)
```

Grammar (fixed, self-delimiting):

```
sentinel  := PREFIX [ ":" TYPE ] "·" ID SUFFIX
PREFIX    := "⟦S"
SUFFIX    := "⟧"
TYPE      := [A-Z]+                  // EMAIL, SECRET, CODENAME, ...
ID        := base62{ID_LEN}         // fixed width → cheap parse
```

Design properties:
- **Rare, self-delimiting prefix** → return-path scan is a single `memchr` for `⟦S`
  followed by a fixed-width parse. No per-request automaton to rebuild.
- **The id is an index, not the data.** `7f3a` indexes a request-local reverse table.
  The secret never leaves SCRUB's memory. This *is* the compliance guarantee.
- **Deterministic per scope.** A forward map `hash(original) → id` collapses repeated
  occurrences to the same id, so the model sees consistency and we dedupe for free.
- **Typed variant** is the quality knob: bare sentinels can make models hallucinate
  around "missing" context; a type hint mitigates it while staying trivially reversible.
  Configurable per rule.

> Format-preserving masking remains a *non-default, opt-in* style for cases where a rule
> is one-way (redaction, never rehydrated) or where model quality strictly requires it and
> the value is known to pass through verbatim.

---

## 3. Round trip

```
EGRESS (request)
  scan body bytes (single pass)
    └─ detect spans  ─ glossary (Aho-Corasick) ‖ regex (RegexSet) ‖ entropy
  for each span (priority, then longest-match-wins):
    id = forward_map.get_or_insert(hash(span))
    reverse[id] = span                     // request- or session-scoped
    emit ⟦S:TYPE·id⟧ in place of span
  forward scrubbed body upstream (vectored write of [slice|sentinel|slice|...])

INGRESS (response, possibly SSE stream)
  per chunk:
    memchr('⟦S') → parse id → reverse[id] → splice original back in
    hold back only a bounded tail that might be a partial sentinel (max_sentinel_len)
    flush everything before the tail immediately (protect TTFT)
  on stream end:
    zeroize reverse map + forward map (secure wipe)
```

### Correctness traps that must be handled in v0
1. **Partial sentinel across chunk boundaries.** Buffer back at most `max_sentinel_len`
   bytes; everything before it is safe to flush.
2. **Overlapping / competing matches on egress.** Deterministic resolution: by `priority`,
   then longest-match-wins. Without this, the same input can mask differently run-to-run,
   breaking determinism.
3. **Model-invented lookalikes.** An id not present in the reverse table is left verbatim
   (never error, never guess). Rare prefix makes collisions negligible.
   - **Cross-node concurrency.** Each node allocates ids from a disjoint `IdSpace`
     (`node_id` high bits + counter), and the Redis backend stores each entry as its own
     hash field — so two nodes interning concurrently in one session never collide ids and
     never clobber each other's entries (no lost rehydration). Dedup stays correct because
     the forward map is rebuilt from *all* nodes' entries on load.
4. **Mapping lifetime.** Request scope wipes at response end; session scope holds until TTL.
   Both use `zeroize` on drop.
5. **Sentinel fragmented across SSE delta events.** Real LLM streaming tokenizes a sentinel
   into several `data:` events with JSON/SSE framing *between the pieces* — so raw-byte
   scanning sees `⟦S:EM"}}…data:{…"AIL·0⟧` and can't reassemble it. The response path detects
   `text/event-stream`, buffers whole events, and runs each event's `stream_paths` content
   (e.g. `choices[].delta.content`) through a **persistent** rehydrator whose carry buffer
   spans events; re-serialization re-escapes the spliced original. (Non-streaming JSON keeps
   the simpler raw-byte path, where the full sentinel is contiguous in one body.)

---

## 4. Performance strategy

Ordered by impact.

### Detection (egress hot path)
- **One pass, two automata.** ✅ All glossary literals → a single `aho-corasick` automaton
  (SIMD Teddy / memchr). All regex rules → one `regex-automata` meta-engine via `new_many`,
  matched in a single pass (patterns ordered by priority for same-offset arbitration).
  Detection cost is ~flat in rule count: 2 rules ≈ 25 rules in `cargo bench`.
- **Compile config → immutable matcher artifacts once.** Never compile per request.
  Hot-reload builds new artifacts off-thread, swaps via `arc-swap` (lock-free reads).
- **Provider-aware scanning.** Parse only the sensitive JSON paths (`messages[].content`,
  tool-call arguments) — less work *and* fewer false positives.

### Allocation & copying
- **Zero-copy by default.** Body as `Bytes`; output is a list of slices
  `[orig 0..120][sentinel][orig 145..600]…` written vectored. Only matched spans allocate.
- **Per-request bump arena** (`bumpalo`) for span list + maps; dropped wholesale at
  request end. Pool and reuse scan buffers.
- **Byte-level work**, skipping UTF-8 revalidation where boundary safety is guaranteed.

### Concurrency & state
- **Request-local reverse map** → zero shared-lock contention on the default path.
- **Lock-free config** (`arc-swap`); sharded structures only where genuinely shared.
- **Redis is opt-in**, only for sessions that span nodes — never on the critical path.

### I/O & transport
- Build on **`pingora`** (or `hyper` + `tower`) for upstream connection pooling, keep-alive,
  and H2 multiplexing. Reusing the TLS session to the provider saves more wall-clock than
  any scan optimization.
- Streaming-first everywhere, bounded buffers, backpressure-aware vectored writes.

### Measurement
- p99 added-latency is a first-class metric from day one.
- `criterion` benches over a representative prompt corpus; every optimization proven,
  not assumed.

---

## 5. Configuration (v0)

Compiled once into immutable matchers, hot-reloaded on change.

```yaml
# scrub.yaml

# Upstreams are config, not code — point a route at any model API.
routes:
  - listen_path: "/openai"           # what clients hit on SCRUB
    upstream: "https://api.openai.com"
    profile: openai                  # which scan profile to apply
  - listen_path: "/anthropic"
    upstream: "https://api.anthropic.com"
    profile: anthropic
  - listen_path: "/internal-llm"     # self-hosted / arbitrary provider
    upstream: "http://llm.internal:8000"
    profile: openai                  # OpenAI-compatible schema → reuse profile

profiles:
  openai:
    scan_paths:
      - "messages[].content"
      - "messages[].tool_calls[].function.arguments"
  anthropic:
    scan_paths:
      - "messages[].content"
      - "system"

masking:
  style: typed-sentinel        # typed-sentinel | bare-sentinel | format-preserving(opt-in)
  scope: session               # request | session   (determinism boundary)
  ttl: 30m

glossary:                      # literal terms → Aho-Corasick
  - { term: "Project Hufflepuff", type: CODENAME, priority: 100 }

rules:                         # regex → RegexSet
  - { name: email,   type: EMAIL,  pattern: '…',                priority: 50 }
  - { name: aws_key, type: SECRET, pattern: 'AKIA[0-9A-Z]{16}', priority: 90 }

entropy:                       # optional generic-secret catcher
  enabled: true
  min_bits: 4.0
```

The glossary is the *same interface* a secret store will feed later — connectors just
become another source that populates the Aho-Corasick automaton at reload time. Nothing
in v0 is throwaway.

---

## 6. Component architecture

```
        ┌─────────────────────────────────────────────────┐
client → │ Listener (HTTP/1.1, H2, SSE; explicit endpoint)  │
        └───────────────────────┬─────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │ Detection pipeline      │ Aho-Corasick ‖ RegexSet ‖ entropy
                    │ (egress)                │ single pass, merged spans
                    └───────────┬───────────┘
                                │ spans
                    ┌───────────▼───────────┐
                    │ Vaultizer + Mapping     │ span → ⟦S:TYPE·id⟧
                    │ (request/session map)   │ in-mem; Redis opt-in for cluster
                    └───────────┬───────────┘
                                │ scrubbed body
                          upstream provider
                                │ response (often SSE)
                    ┌───────────▼───────────┐
                    │ Rehydration state-      │ memchr scan, reverse lookup,
                    │ machine (ingress)       │ bounded-tail buffering
                    └───────────┬───────────┘
                                │
                             client

cross-cutting: Config + hot reload · Policy engine · Observability/audit · Secure wipe
```

### Trait boundaries (stable seams for later phases)
- `SecretSource` — pluggable origin of sensitive terms (config file → Vault / AWS / GCP /
  `.env` / file-scan later). All feed the same matcher build.
- `Detector` — produces spans over a content unit (Aho-Corasick, RegexSet, entropy;
  ML/NER and **media detectors** later — OCR/vision over images, ASR over audio — all
  reduce to the same span output so the Vaultizer + mapping path is unchanged).
- `Vaultizer` — span → placeholder + reverse-map entry (sentinel default; FPE opt-in).
- `Upstream` / `Route` — maps an inbound listen path to a configured upstream URL +
  `ScanProfile`. Provider-agnostic: adding a model API is a config entry, not code.
- `ScanProfile` — per-route description of *what* to scan (JSON content paths today;
  media parts — `image_url`, base64 blobs, attachments — later).
- `MappingStore` — request-local (default) / session / Redis-backed.

---

## 7. Compliance & security posture
- **Provider sees only opaque ids** — attestable data-minimization property.
- **Tamper-evident audit log**: per request, the *categories* and *counts* detected/masked
  — never the values. Hash-chained; verified with `scrub audit-verify`. Writes are
  **synchronous and flushed per record** — a deliberate durability-over-latency choice so a
  crash cannot lose audit records for requests that were served (compliance > throughput).
- **Proxy authentication**: API keys compared in **constant time** (no early-return / hash
  oracle); the proxy's own key is never forwarded upstream.
- **At-rest encryption**: session vaults in a shared store are sealed with AES-256-GCM so
  Redis only ever holds ciphertext.
- **Policy-as-code** per route/tenant/data-class, with a **dry-run** mode (report what
  *would* be masked) for onboarding trust.
- **Secure destruction**: `zeroize` mappings on drop; bounded TTL for session scope.
- **No secret ever logged**; metrics are counts/types only.
- **Liveness**: unauthenticated `/healthz` for load balancers, bypassing auth and routing.

- **TLS termination**: optional client-facing HTTPS via rustls (`ring` provider — no
  OpenSSL/aws-lc, so the cross-compiled static binaries are unaffected).

---

## 8. Roadmap

Status: ✅ done · 🚧 partial · ⬜ not started.

| Phase | Status | Scope |
|-------|--------|-------|
| **v0** | ✅ | Explicit-endpoint proxy, provider-aware scan, glossary + regex + **entropy** from config, typed-sentinel masking, request + **session** in-mem map, **streaming rehydration**, **hot reload**, criterion benches. |
| v1 | ✅ | **Tamper-evident audit log** ✅, **dry-run mode** ✅, **per-route policy** ✅, **proxy auth** ✅, **per-tenant policy** ✅, **multi-arch release binaries** ✅ (CI + `build-release.sh`). |
| v2 | 🚧 | `.env` + secret-file ✅; **HashiCorp Vault (KV v2)** connector ✅; AWS / GCP secret managers ⏸️ (same `SecretSource` seam). Curated common-secret ruleset shipped. |
| v3 | ✅ | Redis-backed clustering for cross-node sessions (load-modify-store behind a `SessionBackend` seam); **AES-256-GCM at-rest encryption**; **node-disjoint ids + per-field hashes** for concurrent correctness. |
| v4 | ✅ | NER/PII detection behind the `SpanDetector` seam — heuristic person-name detector shipped; a model-backed detector plugs in via the same trait (`Detector::with_detectors`). |
| v5 | ✅ | TLS interception (MITM): per-host certs minted on the fly from a configured CA (`CertMinter` + rustls `ResolvesServerCert`), routed by `Host`. Both **SNI-transparent** and **CONNECT-proxy** modes (the latter blind-tunnels un-intercepted hosts). |
| v6 | ⏸️ | Media scanning — OCR/vision over images, ASR over audio — **deferred until a stable release**; reuses the span → Vaultizer → rehydration path. |

> **v2 and v6 are deferred** until SCRUB ships a stable, complete `1.0`. They remain
> designed-for (the `SecretSource` and `Detector`/`Span` seams are in place) but are not
> being built until the core is hardened and released.

---

## 9. First thing to prototype

The **streaming rehydration state machine** (§3 ingress) is the riskiest, demo-defining
piece — getting an SSE round trip with mid-stream sentinels rehydrating correctly is the
demo that makes the product believable. Build it first, behind a criterion bench.
