# Detection & Masking Rules

Detection is what decides *what* gets masked. SCRUB combines several detectors into a single
pass and resolves overlaps deterministically by priority.

## Detectors

| Detector | What it catches | Config |
|----------|-----------------|--------|
| **Glossary** | exact literal terms (codenames, internal hostnames) | `glossary[]` |
| **Rules** | regex patterns (token/key formats, PII) | `rules[]` |
| **Entropy** | high-entropy strings no named rule covers | `entropy` |
| **NER** | person-name PII (heuristic) | `ner` |
| **Secret sources** | live values from `.env` / files / Vault | `sources[]` |

Glossary terms and secret-source values feed one Aho-Corasick automaton; rules compile into
one `regex-automata` meta-engine. Cost stays roughly flat as you add rules.

## Writing a rule

```yaml
rules:
  - name: aws_key
    type: AWS_KEY          # shown in the sentinel: ⟦S:AWS_KEY·id⟧
    pattern: '\bAKIA[0-9A-Z]{16}\b'
    priority: 95           # higher wins when spans overlap
```

Write patterns as YAML **single-quoted** scalars so backslashes are literal. `type` is the
label that appears in the sentinel and in audit counts. `priority` breaks overlaps — e.g. an
`ANTHROPIC_KEY` rule at 96 beats a generic `OPENAI_KEY` rule at 95 on `sk-ant-…`.

## Use the curated ruleset

Rather than start from scratch, copy
[`examples/common-rules.yaml`](https://github.com/scrub-dev/source-code/blob/main/examples/common-rules.yaml):
ready-to-use patterns for AWS/GCP/DigitalOcean keys, GitHub/GitLab/Slack/Stripe/SendGrid/
Twilio/npm/OpenAI/Anthropic tokens, JWTs, PEM private keys, credential URLs, bearer tokens,
generic `key = value` assignments, and email — plus a high-entropy catcher.

## Scan paths: mask content, not metadata

A rule only runs on the JSON paths a route's profile names. This is how you avoid masking
fields that would break the API:

```yaml
profiles:
  openai:
    scan_paths:   ["messages[].content"]          # mask these
    stream_paths: ["choices[].delta.content"]      # rehydrate these (SSE)
```

`[]` descends into every array element; only string leaves are touched. `model`,
`temperature`, tool schemas, etc. are left exactly as the client sent them.

## Tuning

- **Favor recall.** A missed secret is a leak; a false positive just masks a benign string
  that the model still reasons about via a stable placeholder.
- **Validate in `dry-run`.** SCRUB reports detections (header + audit log) without altering
  the request, so you can measure coverage and false-positive rate before enforcing.
- **Layer entropy last.** Give it a low priority so named rules win and label things
  precisely; entropy is the safety net for unknown formats.
- **Pull live secrets in.** Point a [Vault / .env source](../docs/configuration.html#sources)
  at your real credentials so they're masked even without a matching pattern.

See the full [configuration reference](../docs/configuration.html) for every detector option.
