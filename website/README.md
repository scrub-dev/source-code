# SCRUB website

A zero-runtime static site (landing + docs + guides), styled in the shadcn design
language. No framework: a small Python generator renders the repository's canonical
Markdown into plain HTML + one CSS + a tiny JS, so the docs never drift from the code.

```
website/
  build.py            generator (Markdown -> static HTML)
  requirements.txt    markdown + pygments
  assets/             styles.css, app.js, favicon.svg
  content/guides/     site-authored guides (Markdown)
  dist/               build output (gitignored)
```

Reference docs are pulled straight from `../docs/*.md`, `../SECURITY.md`, `../DESIGN.md`,
and `../CHANGELOG.md`.

## Build & preview

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python build.py            # -> dist/
.venv/bin/python -m http.server --directory dist 8000
# open http://localhost:8000
```

## Editing

- **Landing copy / sections** — `build.py` (`landing()`, `FEATURES`, `STEPS`).
- **Design tokens / layout** — `assets/styles.css` (shadcn zinc tokens at the top).
- **Guides** — add a Markdown file under `content/guides/` and register it in the `NAV`
  table in `build.py`.
- **Reference pages** — edit the source Markdown in `../docs/` etc.; they re-render on build.

Cross-document links written as `FILENAME.md#anchor` are rewritten to site routes; links
to other repo paths become GitHub `blob` links automatically.

## Deploy

Pushing to `main` triggers `.github/workflows/pages.yml`, which builds and deploys to
GitHub Pages. Enable it once under **Settings → Pages → Source → GitHub Actions**.
