# Security Policy

SCRUB is a security tool: it sits in the data path and handles plaintext secrets
and PII. Treat it as a high-value component and deploy it accordingly.

## Reporting a vulnerability

Please report security issues privately — do **not** open a public issue.

- Email: security@scrub.example (replace with your project contact)
- Include: affected version, a description, and reproduction steps or a PoC.

We aim to acknowledge within 3 business days and to provide a remediation
timeline after triage. Coordinated disclosure is appreciated; please give us a
reasonable window before public disclosure.

## Supported versions

SCRUB is pre-`1.0`. Only the latest `0.x` release receives security fixes until
`1.0` ships.

## Threat model

### What SCRUB protects
- **Data minimization to the provider.** With masking enforced, the upstream LLM
  provider receives only opaque sentinels — never the original secrets/PII. This
  is the core, attestable property.
- **Reversibility integrity.** A masked value round-trips losslessly, including
  across streamed (SSE) responses, or is left verbatim — it is never silently
  corrupted or mis-rehydrated.

### Trust boundary
SCRUB necessarily sees **plaintext** request/response content (it is the masking
broker). Run it inside your trust boundary, on hosts and networks you control,
with least-privilege access. Anyone who can read SCRUB's memory, its config, its
secret sources, or (for the Redis backend) the session store can see secrets.

### Sensitive material and how it is handled
- **In-memory vaults** (request/session mappings) are zeroized on drop; session
  scope is bounded by TTL.
- **Redis-backed sessions** persist mappings off-process. Enable
  `sessions.encryption_key` (AES-256-GCM) so the store holds only ciphertext, and
  run Redis with AUTH + TLS on a private network.
- **The interception CA key is the most dangerous secret in the system** — it can
  mint a trusted certificate for *any* host. Protect `intercept.ca_key_path` with
  the same rigor as a root signing key (restricted FS permissions, ideally an
  HSM/KMS in production), and scope the CA's distribution to managed clients only.
- **Auth keys** are compared in constant time and never forwarded upstream.
- **Audit log** is hash-chained and tamper-evident (`scrub audit-verify`), but it
  is a local file: protect it and consider shipping to append-only/WORM storage.
  It records detection **counts and types only — never values**.
- **Transaction log** (optional) captures the **masked provider-facing** request and
  response — secret-free in enforce mode. In **dry-run** mode nothing is masked, so
  records contain original content; protect the file and avoid dry-run + transactions
  outside a trusted boundary.

### Operational guidance
- Terminate client TLS at SCRUB (`tls`) or run it behind a TLS terminator; the
  plain-HTTP listener is for trusted local networks only.
- Start with **dry-run** mode to validate detection coverage before enforcing.
- Bias detection toward recall for secret/PII categories — a false negative
  (a leak) is worse than a false positive (a degraded prompt).
- Rotate auth keys and the interception CA on a schedule.

### Known limitations (as of 0.1.0)
- Auth keys are static (no built-in rotation/expiry).
- The heuristic NER is **not** a trained model; it favors precision and will miss
  many names. Use it as defense-in-depth, not a sole PII control.
- TLS interception is SNI-transparent (requires DNS/SNI redirection); a
  CONNECT-proxy mode is not yet implemented.
- Concurrent cross-node writes to the *same* session are last-write-wins per
  field; sticky sessions are recommended for strict ordering.
- Audit writes are synchronous (durability over throughput, by design).
