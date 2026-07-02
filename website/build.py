#!/usr/bin/env python3
"""Static site generator for the SCRUB website.

Renders the repository's canonical Markdown docs + the site's guides into a
zero-runtime static site (plain HTML + one CSS + a tiny JS), styled in the
shadcn design language. No framework, no client-side rendering.

    python build.py            # -> website/dist/

Reuses ../docs, ../SECURITY.md, ../DESIGN.md, ../CHANGELOG.md so docs never drift.
"""
import os
import re
import shutil
import html as html_mod

import markdown
from pygments.formatters import HtmlFormatter

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(ROOT)
DIST = os.path.join(ROOT, "dist")
ASSETS = os.path.join(ROOT, "assets")

GH = "https://github.com/scrub-dev/source-code"
GH_BLOB = GH + "/blob/main/"
GH_RELEASES = GH + "/releases"
GH_LICENSE = GH_BLOB + "LICENSE"

# Absolute base of the deployed site, used for the machine-readable llms.txt links.
SITE_BASE = "https://scrub-dev.github.io/source-code"

# One-line descriptions per page for llms.txt.
DESC = {
    "getting-started": "install, minimal config, and the mask → forward → rehydrate mental model",
    "why-scrub": "the problem, the benefits, and the honest trade-offs",
    "rules": "detectors, writing rules, the curated ruleset, and scan-path tuning",
    "http-proxy": "run SCRUB as your OS/app HTTP proxy (CONNECT-proxy interception)",
    "kubernetes": "deploy via the Helm chart, single-node and HA (StatefulSet + Redis)",
    "configuration": "exhaustive reference for every config section, CLI flag, and env var",
    "deployment": "modes, TLS, high availability, containers, and Kubernetes",
    "security": "threat model, trust boundary, and hardening guidance",
    "design": "architecture, the reversible sentinel model, and the round trip",
    "changelog": "release history",
}

# section -> list of (slug, title, source markdown path)
NAV = {
    "Guides": [
        ("getting-started", "Getting Started", "content/guides/getting-started.md"),
        ("why-scrub", "Why SCRUB?", "content/guides/why-scrub.md"),
        ("rules", "Detection & Masking", "content/guides/rules.md"),
        ("http-proxy", "Use as an HTTP Proxy", "../docs/HTTP-PROXY.md"),
        ("kubernetes", "Deploy on Kubernetes", "content/guides/kubernetes.md"),
    ],
    "Reference": [
        ("configuration", "Configuration", "../docs/CONFIGURATION.md"),
        ("deployment", "Deployment & Ops", "../docs/DEPLOYMENT.md"),
        ("security", "Security & Threat Model", "../SECURITY.md"),
        ("design", "Design & Architecture", "../DESIGN.md"),
        ("changelog", "Changelog", "../CHANGELOG.md"),
    ],
}
SECTION_DIR = {"Guides": "guides", "Reference": "docs"}

# basename of a known doc -> (output_dir, slug)
KNOWN = {}
for sec, pages in NAV.items():
    for slug, _title, src in pages:
        KNOWN[os.path.basename(src).lower()] = (SECTION_DIR[sec], slug)
KNOWN["readme.md"] = ("", "index")


def rewrite_link(href: str) -> str:
    """Rewrite a Markdown link target for the built site."""
    if not href or href.startswith(("http://", "https://", "#", "mailto:")):
        return href
    anchor = ""
    if "#" in href:
        href, anchor = href.split("#", 1)
        anchor = "#" + anchor
    base = os.path.basename(href).lower()
    if base in KNOWN:
        d, slug = KNOWN[base]
        # site-absolute (we fix up with a relative prefix at render time)
        return f"@@/{d + '/' if d else ''}{slug}.html{anchor}"
    if base.endswith(".html"):  # already a site link authored in a guide
        return href + anchor
    # any other repo path -> GitHub blob
    clean = re.sub(r"^(\.\./)+", "", href).lstrip("./")
    return GH_BLOB + clean + anchor


def md_to_html(path: str):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # Pull ```mermaid fences out before Markdown sees them, so they render as
    # diagrams (client-side) instead of highlighted code.
    mermaid = []

    def _stash(m):
        mermaid.append(m.group(1))
        return f"\n\nMERMAIDBLK{len(mermaid) - 1}ENDMERMAIDBLK\n\n"

    text = re.sub(r"```mermaid[ \t]*\n(.*?)\n```", _stash, text, flags=re.S)
    md = markdown.Markdown(
        extensions=["extra", "codehilite", "toc", "sane_lists", "admonition"],
        extension_configs={"codehilite": {"guess_lang": False, "css_class": "codehilite"}},
    )
    body = md.convert(text)
    # rewrite intra-repo links
    body = re.sub(r'href="([^"]+)"', lambda m: f'href="{rewrite_link(m.group(1))}"', body)
    # external links: open in new tab
    body = re.sub(
        r'href="(https?://[^"]+)"',
        r'href="\1" target="_blank" rel="noopener"',
        body,
    )
    # swap mermaid placeholders back in as diagram nodes
    for i, block in enumerate(mermaid):
        body = body.replace(
            f"<p>MERMAIDBLK{i}ENDMERMAIDBLK</p>",
            f'<pre class="mermaid">{html_mod.escape(block)}</pre>',
        )
    toc = getattr(md, "toc_tokens", [])
    # page title = first h1 text, else slug
    m = re.search(r"^#\s+(.+)$", text, re.M)
    title = m.group(1).strip() if m else None
    return body, toc, title, bool(mermaid)


def relprefix(depth: int) -> str:
    return "../" * depth


def fix_abs(htmltext: str, prefix: str) -> str:
    """Turn @@/-prefixed site-absolute links into relative ones."""
    return htmltext.replace('href="@@/', f'href="{prefix}').replace('href="@@', f'href="{prefix}index.html')


def toc_html(tokens, prefix) -> str:
    items = []

    def walk(toks):
        for t in toks:
            if t["level"] in (2, 3):
                cls = " class=\"toc-sub\"" if t["level"] == 3 else ""
                # toc_tokens "name" is already HTML-escaped by Markdown.
                items.append(f'<li{cls}><a href="#{t["id"]}">{t["name"]}</a></li>')
            if t.get("children"):
                walk(t["children"])

    walk(tokens)
    if not items:
        return ""
    return (
        '<aside class="toc"><div class="toc-title">On this page</div><ul>'
        + "".join(items)
        + "</ul></aside>"
    )


def icon(name: str) -> str:
    p = {
        "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
        "moon": '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
        "github": '<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>',
        "menu": '<path d="M3 6h18M3 12h18M3 18h18"/>',
        "arrow": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    }[name]
    return f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{p}</svg>'


LOGO = (
    '<span class="logo-mark" aria-hidden="true">'
    '<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 8 L8 8 L8 24 L12 24"/><path d="M20 8 L24 8 L24 24 L20 24"/>'
    '<circle cx="16" cy="16" r="2.2" fill="currentColor" stroke="none"/></svg></span>'
    '<span class="logo-word">SCRUB</span>'
)


def navbar(prefix: str) -> str:
    return f"""<header class="nav">
  <div class="nav-inner">
    <a class="logo" href="{prefix}index.html">{LOGO}</a>
    <nav class="nav-links">
      <a href="{prefix}guides/getting-started.html">Guides</a>
      <a href="{prefix}docs/configuration.html">Reference</a>
      <a href="{GH}" target="_blank" rel="noopener">GitHub</a>
    </nav>
    <div class="nav-actions">
      <button class="icon-btn" id="theme" aria-label="Toggle theme">{icon("sun")}{icon("moon")}</button>
      <a class="icon-btn" href="{GH}" target="_blank" rel="noopener" aria-label="GitHub">{icon("github")}</a>
      <button class="icon-btn menu-btn" id="menu" aria-label="Menu">{icon("menu")}</button>
    </div>
  </div>
</header>"""


def sidebar(prefix: str, active_sec: str, active_slug: str) -> str:
    out = ['<nav class="sidebar" id="sidebar"><div class="sidebar-inner">']
    for sec, pages in NAV.items():
        out.append(f'<div class="side-group"><div class="side-title">{sec}</div><ul>')
        d = SECTION_DIR[sec]
        for slug, title, _src in pages:
            cur = " aria-current=\"page\"" if (sec == active_sec and slug == active_slug) else ""
            out.append(f'<li><a{cur} href="{prefix}{d}/{slug}.html">{title}</a></li>')
        out.append("</ul></div>")
    out.append("</div></nav>")
    return "".join(out)


def footer(prefix: str) -> str:
    return f"""<footer class="footer">
  <div class="footer-inner">
    <div class="footer-brand"><a class="logo" href="{prefix}index.html">{LOGO}</a>
      <p>Reversible secret &amp; PII masking proxy for LLM traffic.</p></div>
    <div class="footer-cols">
      <div><h4>Guides</h4>
        <a href="{prefix}guides/getting-started.html">Getting Started</a>
        <a href="{prefix}guides/why-scrub.html">Why SCRUB?</a>
        <a href="{prefix}guides/http-proxy.html">HTTP Proxy</a></div>
      <div><h4>Reference</h4>
        <a href="{prefix}docs/configuration.html">Configuration</a>
        <a href="{prefix}docs/deployment.html">Deployment</a>
        <a href="{prefix}docs/security.html">Security</a></div>
      <div><h4>Project</h4>
        <a href="{GH}" target="_blank" rel="noopener">GitHub</a>
        <a href="{GH_LICENSE}" target="_blank" rel="noopener">License (Apache-2.0)</a>
        <a href="{GH_RELEASES}" target="_blank" rel="noopener">Releases</a></div>
    </div>
  </div>
  <div class="footer-base">
    <span>Apache-2.0 licensed.</span>
    <span>Built as a single static binary — rustls + ring.</span>
  </div>
</footer>"""


def head(title: str, prefix: str, desc: str) -> str:
    return f"""<!doctype html>
<html lang="en" class="">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html_mod.escape(title)}</title>
<meta name="description" content="{html_mod.escape(desc)}">
<link rel="icon" type="image/svg+xml" href="{prefix}assets/favicon.svg">
<link rel="stylesheet" href="{prefix}assets/pygments.css">
<link rel="stylesheet" href="{prefix}assets/styles.css">
<script>(function(){{try{{var t=localStorage.getItem('theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');if(t==='dark')document.documentElement.classList.add('dark');}}catch(e){{}}}})();</script>
</head>"""


def doc_page(sec, slug, title, body, toc, prefix, has_mermaid=False):
    mermaid = (
        f'<script type="module" src="{prefix}assets/mermaid-init.js"></script>'
        if has_mermaid else ""
    )
    return "\n".join([
        head(f"{title} · SCRUB", prefix, f"SCRUB documentation — {title}."),
        "<body>",
        navbar(prefix),
        '<div class="layout">',
        sidebar(prefix, sec, slug),
        f'<main class="content"><article class="prose">{body}</article></main>',
        toc,
        "</div>",
        footer(prefix),
        f'<script src="{prefix}assets/app.js"></script>',
        mermaid,
        "</body></html>",
    ])


# ---------------------------------------------------------------------------
# Landing page (hand authored)
# ---------------------------------------------------------------------------
FEATURES = [
    ("Reversible masking", "Secrets become typed placeholders <code>&#10214;S:TYPE&middot;id&#10215;</code> — never <code>***</code>. The model reasons over a stable token; the real value never leaves SCRUB."),
    ("Streaming-correct", "Lossless rehydration at every byte boundary, reassembling a sentinel even when the provider splits it across SSE token events."),
    ("Provider-aware", "Mask only the content paths you name (<code>messages[].content</code>) — never <code>model</code> or metadata, so the API contract stays intact."),
    ("Detection that scales", "Glossary + a single-pass regex meta-engine + entropy + heuristic NER, fed by <code>.env</code> / file / Vault secret sources. Cost ~flat in rule count."),
    ("Sessions & tenancy", "Per-request or per-session pseudonyms (memory or Redis, encrypted at rest), with multi-tenant policy and isolated namespaces."),
    ("HTTP proxy or reverse proxy", "Drop in by changing a base URL, or run it as your OS HTTPS proxy via on-the-fly per-host certificates."),
    ("Provable auditing", "Tamper-evident hash-chained audit log (counts/types, never values) plus an optional full transaction log of the masked exchange."),
    ("Small & fast", "One static binary — rustls + ring, no OpenSSL — multi-arch container, hot-reloaded config."),
]

STEPS = [
    ("Detect", "Scan the configured request paths for secrets &amp; PII."),
    ("Mask", "Replace each hit with a reversible sentinel; keep the original only inside SCRUB."),
    ("Forward", "Send the masked request to the real provider."),
    ("Rehydrate", "Splice originals back into the response stream as it flows."),
    ("Wipe", "Zeroize the per-request map when the response ends."),
]


def landing():
    prefix = ""
    feat_cards = "".join(
        f'<div class="card"><h3>{t}</h3><p>{d}</p></div>' for t, d in FEATURES
    )
    step_items = "".join(
        f'<li><span class="step-n">{i+1}</span><div><strong>{t}</strong><p>{d}</p></div></li>'
        for i, (t, d) in enumerate(STEPS)
    )
    quickstart = html_mod.escape(
        "# scrub.yaml\n"
        "routes:\n"
        '  - { listen_path: "/openai", upstream: "https://api.openai.com", profile: openai }\n'
        "profiles:\n"
        "  openai:\n"
        '    scan_paths:   ["messages[].content"]\n'
        '    stream_paths: ["choices[].delta.content"]\n'
        "rules:\n"
        "  - { name: email, type: EMAIL, pattern: '[\\w.+-]+@[\\w.-]+\\.\\w+', priority: 50 }"
    )
    run = html_mod.escape("scrub --config scrub.yaml --listen 127.0.0.1:8080")
    body = f"""<body>
{navbar(prefix)}
<main>
  <section class="hero">
    <div class="hero-inner">
      <span class="pill">Secret Cleaning &amp; Rehydration Utility Broker</span>
      <h1>Send prompts to any LLM<br>without sending your <span class="grad">secrets</span>.</h1>
      <p class="lede">SCRUB is a single-binary forward proxy that <strong>masks</strong> secrets, PII, and
      sensitive data on the way out to an LLM provider — and <strong>rehydrates</strong> the response on the
      way back, including mid-stream. The provider sees placeholders; your users get the real thing.</p>
      <div class="cta">
        <a class="btn btn-primary" href="{prefix}guides/getting-started.html">Get started {icon("arrow")}</a>
        <a class="btn btn-ghost" href="{GH}" target="_blank" rel="noopener">{icon("github")} View on GitHub</a>
      </div>
      <div class="flow">
        <span>your app</span>{icon("arrow")}<span class="masked">SCRUB</span>{icon("arrow")}<span>LLM API</span>
        <em>original &rarr; &#10214;S:EMAIL&middot;3&#10215; &rarr; rehydrated</em>
      </div>
    </div>
  </section>

  <section class="band">
    <div class="band-inner problem">
      <div><h2>The wedge is compliance, not routing.</h2>
        <p>LLM features ship by sending user text to a third party. That text contains API keys, customer
        PII, internal hostnames, tokens in stack traces — things you're contractually obligated not to share.
        Destructive redaction (<code>***</code>) wrecks answer quality; trusting the provider isn't an option
        under SOC&nbsp;2 / PCI-DSS / HIPAA / GDPR.</p>
        <p>SCRUB gives you a <strong>lossless, reversible de-identification round trip</strong> instead.</p>
        <a class="link" href="{prefix}guides/why-scrub.html">Why SCRUB &amp; the trade-offs {icon("arrow")}</a>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="section-head"><h2>Everything you need, on the wire</h2>
      <p>A payload-owning proxy — not an SDK, not a model change.</p></div>
    <div class="grid">{feat_cards}</div>
  </section>

  <section class="section alt">
    <div class="two">
      <div>
        <div class="section-head left"><h2>How it works</h2>
          <p>Five steps, every request. The secret never reaches the provider.</p></div>
        <ol class="steps">{step_items}</ol>
      </div>
      <div class="code-col">
        <div class="codeframe"><div class="codeframe-bar"><span></span><span></span><span></span><b>scrub.yaml</b></div>
        <pre class="plain"><code>{quickstart}</code></pre></div>
        <div class="codeframe"><div class="codeframe-bar"><span></span><span></span><span></span><b>shell</b></div>
        <pre class="plain"><code>$ {run}</code></pre></div>
        <p class="muted">Point your app at <code>http://127.0.0.1:8080/openai</code>. Start in
        <code>dry-run</code>, then enforce.</p>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="section-head"><h2>Use it your way</h2></div>
    <div class="grid g3">
      <div class="card"><h3>Reverse proxy</h3><p>Change a base URL. No CA, no SDK changes. The simplest, safest start.</p>
        <a class="link" href="{prefix}guides/getting-started.html">Getting Started {icon("arrow")}</a></div>
      <div class="card"><h3>OS HTTP proxy</h3><p>Set SCRUB as your <code>HTTPS_PROXY</code>; it MITMs configured
        hosts with minted certs and tunnels the rest untouched.</p>
        <a class="link" href="{prefix}guides/http-proxy.html">HTTP Proxy guide {icon("arrow")}</a></div>
      <div class="card"><h3>Container</h3><p>Multi-arch image on GHCR, published every release.</p>
        <a class="link" href="{prefix}docs/deployment.html">Deployment {icon("arrow")}</a></div>
    </div>
  </section>

  <section class="band">
    <div class="band-inner final">
      <h2>Read the docs, run the binary.</h2>
      <p>Everything is in the open — configuration reference, threat model, and the full design.</p>
      <div class="cta">
        <a class="btn btn-primary" href="{prefix}guides/getting-started.html">Get started {icon("arrow")}</a>
        <a class="btn btn-ghost" href="{prefix}docs/configuration.html">Configuration reference</a>
      </div>
    </div>
  </section>
</main>
{footer(prefix)}
<script src="{prefix}assets/app.js"></script>
</body></html>"""
    return head("SCRUB — reversible secret & PII masking for LLM traffic", prefix, ""
                "Single-binary forward proxy that masks secrets and PII in LLM requests and "
                "rehydrates responses, including streaming.") + "\n" + body


def write_pygments_css():
    light = HtmlFormatter(style="default").get_style_defs(".codehilite")
    try:
        dark_style = "one-dark"
        dark = HtmlFormatter(style=dark_style).get_style_defs("html.dark .codehilite")
    except Exception:
        dark = HtmlFormatter(style="monokai").get_style_defs("html.dark .codehilite")
    with open(os.path.join(DIST, "assets", "pygments.css"), "w", encoding="utf-8") as f:
        f.write("/* generated by build.py */\n" + light + "\n" + dark + "\n")


def _read_src(src: str) -> str:
    """Read a NAV source markdown file (relative to the website dir)."""
    path = os.path.normpath(os.path.join(ROOT, src))
    with open(path, encoding="utf-8") as f:
        return f.read()


def write_llms():
    """Emit /llms.txt (the llmstxt.org index) and /llms-full.txt (all docs inline),
    and copy the agent SKILL.md — so AI agents can discover, self-install, and
    operate SCRUB."""
    # llms.txt — concise, link-first index.
    out = [
        "# SCRUB",
        "",
        "> Reversible secret & PII masking proxy for LLM traffic. A single-binary "
        "forward proxy that masks secrets/PII on outbound LLM-provider requests "
        "(as reversible sentinels) and rehydrates them on responses, including "
        "streaming — the provider only ever sees opaque placeholders.",
        "",
        "SCRUB sits between an app and an LLM provider (OpenAI/Anthropic/Gemini/"
        "Mistral/any HTTP API). Deploy as a reverse proxy (change one base URL) or an "
        "OS HTTP proxy; ship as a static multi-arch binary, a container image, or a "
        "Helm chart. Start in dry-run to validate detection, then enforce.",
        "",
        "## Agent skill",
        f"- [SKILL.md]({SITE_BASE}/SKILL.md): how an AI agent installs and operates "
        "SCRUB — install options, minimal config, run, verify, and the gotchas.",
        "",
        "## Guides",
    ]
    for slug, title, _ in NAV["Guides"]:
        out.append(f"- [{title}]({SITE_BASE}/guides/{slug}.html): {DESC.get(slug, '')}")
    out += ["", "## Reference"]
    for slug, title, _ in NAV["Reference"]:
        out.append(f"- [{title}]({SITE_BASE}/docs/{slug}.html): {DESC.get(slug, '')}")
    out += [
        "",
        "## Optional",
        f"- [Full docs, one file]({SITE_BASE}/llms-full.txt): every guide and reference "
        "page concatenated for ingestion.",
        f"- [GitHub repository]({GH}): source, releases (binaries + SHA256SUMS), the "
        "`ghcr.io/scrub-dev/scrub` image, and the `oci://ghcr.io/scrub-dev/charts/scrub` chart.",
        "",
    ]
    with open(os.path.join(DIST, "llms.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(out))

    # llms-full.txt — the skill plus every doc, inline.
    full = ["# SCRUB — full documentation\n", _read_src("../SKILL.md"), ""]
    for sec, pages in NAV.items():
        for _slug, title, src in pages:
            full.append(f"\n\n---\n\n<!-- {sec}: {title} -->\n")
            full.append(_read_src(src))
    with open(os.path.join(DIST, "llms-full.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(full))

    # Serve the raw skill file too.
    shutil.copy(os.path.join(REPO, "SKILL.md"), os.path.join(DIST, "SKILL.md"))


def main():
    if os.path.exists(DIST):
        shutil.rmtree(DIST)
    os.makedirs(os.path.join(DIST, "assets"))
    os.makedirs(os.path.join(DIST, "docs"))
    os.makedirs(os.path.join(DIST, "guides"))

    for fn in ("styles.css", "app.js", "favicon.svg", "mermaid-init.js"):
        shutil.copy(os.path.join(ASSETS, fn), os.path.join(DIST, "assets", fn))
    write_pygments_css()

    n = 0
    for sec, pages in NAV.items():
        d = SECTION_DIR[sec]
        for slug, title, src in pages:
            srcpath = src if os.path.isabs(src) else os.path.join(ROOT, src)
            if src.startswith("../"):
                srcpath = os.path.normpath(os.path.join(ROOT, src))
            body, toc, h1, has_mermaid = md_to_html(srcpath)
            prefix = relprefix(1)
            body = fix_abs(body, prefix)
            page = doc_page(sec, slug, h1 or title, body, toc_html(toc, prefix), prefix, has_mermaid)
            with open(os.path.join(DIST, d, f"{slug}.html"), "w", encoding="utf-8") as f:
                f.write(page)
            n += 1

    with open(os.path.join(DIST, "index.html"), "w", encoding="utf-8") as f:
        f.write(landing())

    write_llms()

    print(
        f"built {n} doc pages + landing + llms.txt/llms-full.txt/SKILL.md "
        f"-> {os.path.relpath(DIST, REPO)}"
    )


if __name__ == "__main__":
    main()
