// Loaded only on pages that contain a ```mermaid block. Mermaid itself is pulled
// from a pinned CDN so the repo stays light; diagrams follow the site theme.
import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";

const nodes = () => document.querySelectorAll("pre.mermaid");
// stash the original source so we can re-render on theme change
nodes().forEach((n) => { if (!n.dataset.src) n.dataset.src = n.textContent; });

const themeName = () =>
  document.documentElement.classList.contains("dark") ? "dark" : "neutral";

async function render() {
  const els = nodes();
  els.forEach((n) => { n.removeAttribute("data-processed"); n.innerHTML = n.dataset.src; });
  mermaid.initialize({
    startOnLoad: false,
    theme: themeName(),
    fontFamily: "inherit",
    securityLevel: "strict",
  });
  try { await mermaid.run({ nodes: els }); } catch (e) { /* leave source visible */ }
}

render();

// Re-render when the light/dark class on <html> flips.
let t;
new MutationObserver(() => { clearTimeout(t); t = setTimeout(render, 60); })
  .observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
