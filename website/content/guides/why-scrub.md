# Why SCRUB?

## The problem

LLM features ship by sending user text to a third-party API. That text routinely contains
things you are contractually or legally obligated **not** to share: API keys pasted into a
prompt, customer PII, internal hostnames, access tokens in a stack trace. Once it leaves
your perimeter, you've lost control of it — and "we'll ask the model nicely not to log it"
is not a compliance control.

The usual options are bad:

- **Redact destructively** — replace secrets with `***`. Now the model can't reason about
  the data and your response quality tanks.
- **Self-host a model** — expensive, and you lose the frontier models.
- **Trust the provider** — not an option under SOC 2 / PCI-DSS / HIPAA / GDPR.

## What SCRUB does

SCRUB sits in front of the provider as a forward proxy and performs a **lossless, reversible
de-identification round trip**:

1. It **masks** sensitive spans with typed, reversible placeholders — `⟦S:EMAIL·3⟧` — before
   the request leaves your network.
2. The provider processes the placeholder *as if it were the real token*, so the model keeps
   its full reasoning ability.
3. SCRUB **rehydrates** the response, putting the real values back before your user sees them.

The real secret is held only inside SCRUB, in a reverse table that's wiped at the end of the
request (or expired by TTL for multi-turn sessions). **It never reaches the provider.**

## Benefits

- **Reversible, not destructive.** The model sees a stable placeholder, not `***`, so
  answers stay coherent — and your users get the real values back.
- **Drop-in.** It's an HTTP proxy. Change a base URL (or set it as your OS proxy) — no SDK
  changes, no model changes.
- **Provider-aware.** Mask only the content fields you name (`messages[].content`), never
  `model`/metadata, so you don't corrupt the API contract.
- **Streaming-correct.** Rehydration is exact at every byte boundary and reassembles a
  sentinel even when the provider splits it across SSE token events.
- **Auditable.** A tamper-evident, hash-chained audit log (counts/types, never values) and
  an optional full transaction log of the *masked* exchange give you provable evidence.
- **Fast & small.** One static binary (rustls + ring, no OpenSSL), a single-pass regex
  meta-engine whose cost is roughly flat in rule count, multi-arch container.
- **Onboard safely.** `dry-run` mode reports what *would* be masked while forwarding the
  original, so teams can trust coverage before enforcing.

## Honest trade-offs

- **Detection is only as good as your rules.** SCRUB ships a curated ruleset for common
  token formats plus entropy and heuristic NER, but novel secret shapes need a rule. Run
  `dry-run` and review the audit log. Favor recall.
- **It masks structured text fields you configure.** It is not (yet) scanning images, audio,
  or arbitrary binary uploads — those seams exist but aren't shipped.
- **TLS interception requires trust.** Using it as a transparent HTTPS proxy means installing
  a CA; that CA key is powerful and must be guarded. (Reverse-proxy mode needs no CA.)
- **It is a payload-path component.** It buffers the request body to mask it (bounded), and
  streams the response. Size your deployment accordingly.

## When it's a fit

- You send user- or developer-authored text to an LLM API and have a compliance boundary.
- You want frontier models but can't let raw secrets/PII cross the wire.
- You need evidence (audit trail) that sensitive data was stripped.

If you only need request *routing* / cost control, a plain LLM gateway is simpler — SCRUB is
specifically about owning and reversing the payload.

Next: [Getting Started](getting-started.html) · [Detection & masking rules](rules.html) ·
[Security & threat model](../docs/security.html).
