// SCRUB website — minimal progressive enhancement (~1KB).
(function () {
  // Theme toggle (initial class is set inline in <head> to avoid flash).
  var t = document.getElementById("theme");
  if (t) t.addEventListener("click", function () {
    var dark = document.documentElement.classList.toggle("dark");
    try { localStorage.setItem("theme", dark ? "dark" : "light"); } catch (e) {}
  });

  // Mobile sidebar.
  var m = document.getElementById("menu");
  var sb = document.getElementById("sidebar");
  if (m && sb) {
    m.addEventListener("click", function () { sb.classList.toggle("open"); });
    sb.addEventListener("click", function (e) {
      if (e.target.tagName === "A") sb.classList.remove("open");
    });
    document.addEventListener("click", function (e) {
      if (sb.classList.contains("open") && !sb.contains(e.target) && e.target !== m && !m.contains(e.target))
        sb.classList.remove("open");
    });
  }

  // Copy buttons on code blocks (not on mermaid diagrams).
  document.querySelectorAll(".prose pre:not(.mermaid)").forEach(function (pre) {
    var b = document.createElement("button");
    b.className = "copy-btn"; b.type = "button"; b.textContent = "Copy";
    b.addEventListener("click", function () {
      var code = pre.querySelector("code") || pre;
      navigator.clipboard.writeText(code.innerText).then(function () {
        b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1400);
      });
    });
    pre.appendChild(b);
  });

  // TOC scrollspy.
  var links = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (links.length && "IntersectionObserver" in window) {
    var map = {};
    links.forEach(function (a) { map[a.getAttribute("href").slice(1)] = a; });
    var seen = new Set();
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) seen.add(en.target.id); else seen.delete(en.target.id);
      });
      links.forEach(function (a) { a.classList.remove("active"); });
      for (var i = 0; i < links.length; i++) {
        var id = links[i].getAttribute("href").slice(1);
        if (seen.has(id)) { links[i].classList.add("active"); break; }
      }
    }, { rootMargin: "-72px 0px -70% 0px" });
    document.querySelectorAll(".prose h2, .prose h3").forEach(function (h) {
      if (h.id) io.observe(h);
    });
  }
})();
