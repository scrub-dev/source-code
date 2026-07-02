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

The latest `1.x` release receives security fixes.

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

**Sentinels are authenticated; session keys are still bearer secrets.** Every
sentinel carries a per-vault keyed MAC tag (`⟦S:TYPE·id·tag⟧`), so a hostile or
compromised upstream **cannot forge or blindly enumerate** sentinels (`⟦S·0⟧`,
`⟦S·1⟧`, …) to read the vault — only sentinels SCRUB actually issued rehydrate.
What remains inherent to reversibility: with `scope: session`, everyone presenting
the same session-header value shares one vault, and an upstream that *received* a
sentinel earlier in the session can replay it — which re-reveals that value to the
session owner (not to the upstream). So still use **one session per
user/trust-unit**, make session keys **unguessable**, and don't mix different
users' secrets under one session key. (Request scope confines everything to the
caller's own current request.) For cross-node sessions the tag key is derived from
`sessions.encryption_key`, so set it — otherwise nodes can't agree on tags and a
session's sentinels won't rehydrate on another node.

### Sensitive material and how it is handled
- **In-memory vaults** (request/session mappings) are zeroized on drop; session
  scope is bounded by TTL.
- **Redis-backed sessions** persist mappings off-process. Enable
  `sessions.encryption_key` (AES-256-GCM) so the store holds only ciphertext, and
  run Redis with AUTH + TLS on a private network. Give **every node a distinct
  `sessions.node_id`** (the Helm chart derives it from the pod ordinal) — colliding
  ids share an id space and corrupt sessions. Run Redis **HA**: a transient read
  failure is surfaced loudly but can still corrupt a session's mappings for that
  request.
- **The interception CA key is the most dangerous secret in the system** — it can
  mint a trusted certificate for *any* host. Protect `intercept.ca_key_path` with
  the same rigor as a root signing key (restricted FS permissions, ideally an
  HSM/KMS in production), and scope the CA's distribution to managed clients only.
- **Auth keys** are compared as fixed-length SHA-256 digests in constant time
  (revealing neither which key matched nor any key's length) and never forwarded
  upstream.
- **Audit log** is hash-chained and tamper-evident (`scrub audit-verify`), but it
  is a local file: protect it and consider shipping to append-only/WORM storage.
  It records detection **counts and types only — never values**.
- **Transaction log** (optional) captures the **masked provider-facing** request and
  response — secret-free in enforce mode. In **dry-run** mode nothing is masked, so
  records contain original content; protect the file and avoid dry-run + transactions
  outside a trusted boundary. Audit and transaction logs are created `0600`
  (owner-only) on Unix.

### Network egress
- **Upstream redirects are never followed.** A 3xx from the upstream is passed
  through to the client, so a compromised/malicious upstream cannot redirect SCRUB
  to an internal service or metadata endpoint (SSRF), nor cause SCRUB to rehydrate
  an attacker-chosen target's response with the client's secrets. The Vault
  connector likewise never follows redirects (its token can't leak to another host).
- **The CONNECT proxy is not an open relay to internal hosts.** Blind tunnels
  refuse loopback and link-local targets (blocking the cloud metadata endpoint at
  `169.254.169.254` and localhost pivots), and connect to the exact vetted IP.
  Still, bind the proxy to trusted networks — it will relay to arbitrary *public*
  hosts by design.
- **Certificate minting is bounded to configured interception hosts**, so an
  attacker cannot force unbounded key-generation with arbitrary SNI values.

### Operational guidance
- Terminate client TLS at SCRUB (`tls`) or run it behind a TLS terminator; the
  plain-HTTP listener is for trusted local networks only.
- Start with **dry-run** mode to validate detection coverage before enforcing.
- Bias detection toward recall for secret/PII categories — a false negative
  (a leak) is worse than a false positive (a degraded prompt).
- Rotate auth keys and the interception CA on a schedule.

### Known limitations (as of 1.0)
- **Masking covers configured JSON content paths.** In enforce mode a JSON-typed
  body that does not parse is **rejected (422)** rather than forwarded, and a
  profile can set `scan_paths: ["**"]` to scan *every* string leaf. Still, a body
  sent with a non-JSON content type, or a secret no rule matches, passes through:
  SCRUB prevents leakage in well-formed provider requests; it is not a DLP control
  against a client *deliberately* exfiltrating over an unscanned channel.
- The at-rest `encryption_key` is derived via SHA-256, not a password-stretching
  KDF — use a **high-entropy** key (it is a shared cluster secret, not a password).
- The audit hash-chain detects edits and mid-file deletions, but truncation of the
  most recent records is not self-evident — ship to append-only/WORM storage if
  that matters.
- Auth keys are static (no built-in rotation/expiry).
- The heuristic NER is **not** a trained model; it favors precision and will miss
  many names. Use it as defense-in-depth, not a sole PII control.
- Concurrent cross-node writes to the *same* session are last-write-wins per
  field; sticky sessions are recommended for strict ordering.
- Audit writes are synchronous (durability over throughput, by design).
