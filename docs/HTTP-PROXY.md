# Using SCRUB as an HTTP(S) proxy

SCRUB can run as your OS/app **HTTP proxy** and transparently mask secrets/PII in
requests to LLM providers — without changing your app's base URL or API client.

This uses **CONNECT-proxy TLS interception** (`intercept.connect: true`): your app
sends SCRUB `CONNECT host:443`, SCRUB terminates TLS for the hosts you've
configured (presenting a certificate minted from your CA), masks the request,
forwards it to the real provider, and rehydrates the response. **Every other host
is blind-tunnelled byte-for-byte**, so the rest of your traffic is untouched.

```
app ──HTTP proxy──► SCRUB ──┬─ configured host?  ► MITM + mask ► provider ► rehydrate
   (HTTPS_PROXY)            └─ otherwise          ► blind tunnel ► host
```

## 1. Create and trust a CA

```sh
./scripts/setup-ca.sh ca
```

This generates `ca/ca.pem` + `ca/ca.key` and installs the cert into your OS trust
store. To do it manually:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout ca/ca.key -out ca/ca.pem -days 3650 -nodes -subj "/CN=SCRUB CA"
```

Trust the cert:

| OS | Command |
|----|---------|
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca/ca.pem` |
| Linux (Debian/Ubuntu) | `sudo cp ca/ca.pem /usr/local/share/ca-certificates/scrub-ca.crt && sudo update-ca-certificates` |
| Linux (RHEL/Fedora) | `sudo cp ca/ca.pem /etc/pki/ca-trust/source/anchors/scrub-ca.pem && sudo update-ca-trust` |
| Windows (admin) | `certutil -addstore -f ROOT ca\ca.pem` |

> **Firefox, Java, and some apps keep their own trust store** — import `ca/ca.pem`
> there too (Firefox: *Settings → Privacy & Security → Certificates → Import*).
>
> **Guard `ca/ca.key`** — it can mint a trusted certificate for *any* host. Restrict
> its permissions and never commit/share it.

## 2. Run SCRUB

A ready-to-run config (intercepts OpenAI/Anthropic/Gemini/Mistral, with the curated
secret ruleset) is provided:

```sh
scrub --config examples/proxy.yaml
# starts on 127.0.0.1:8443
```

Add hosts you want masked under `routes` (matched by `host`), and content paths
per provider under `profiles`. Everything else is tunneled untouched.

## 3. Point your OS/app at the proxy

**Per-shell / CLI tools** (curl, Python `requests`, Node, the OpenAI SDKs, …):

```sh
export HTTPS_PROXY=http://127.0.0.1:8443
export HTTP_PROXY=http://127.0.0.1:8443
export NO_PROXY=localhost,127.0.0.1     # don't proxy local traffic
```

**System-wide / browsers:**

- **macOS:** *System Settings → Network → (your interface) → Details → Proxies* →
  enable *Secure Web Proxy (HTTPS)* and *Web Proxy (HTTP)* → `127.0.0.1 : 8443`.
- **Windows:** *Settings → Network & Internet → Proxy → Manual proxy setup* →
  `127.0.0.1 : 8443`.
- **GNOME:** *Settings → Network → Network Proxy → Manual* → HTTP/HTTPS
  `127.0.0.1 : 8443`.

## 4. Verify

```sh
HTTPS_PROXY=http://127.0.0.1:8443 \
  curl -sS https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" -H "content-type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"email me at a@b.com"}]}' \
  -D - | grep -i x-scrub
```

You should see `x-scrub-mode: enforce` and `x-scrub-request-id: …` response
headers, the provider will have received the email masked as `⟦S:EMAIL·…⟧`, and the
reply comes back rehydrated. Enable the [transaction log](DEPLOYMENT.md#full-transaction-log)
to inspect exactly what was sent/received (masked).

## Caveats

- **Only configured `host:` routes are masked**; all other HTTPS is tunneled and
  never inspected — so this won't break your general browsing.
- **Trust is per-process.** Env-var proxies cover `curl`/Python/Node; OS settings
  cover browsers and system apps. Whatever makes the request must trust the CA.
- **HTTPS only** in this mode (via `CONNECT`); plain-HTTP proxying returns `405`.
  LLM APIs are HTTPS, so this is fine.
- **Certificate-pinned apps** (some mobile/desktop clients) reject any minted cert
  and cannot be intercepted — that's pinning working as intended.
- Start with `masking.mode: dry-run` to validate detection before enforcing.

## Alternative: SNI-transparent (no proxy setting)

If you can't set a proxy but can control DNS, use `intercept.connect: false` and
point the target hostnames at SCRUB (e.g. `/etc/hosts`); SCRUB terminates TLS using
the SNI. See [DEPLOYMENT.md → TLS interception](DEPLOYMENT.md#tls-interception-mitm).
