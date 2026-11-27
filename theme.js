/* theme.js - light/dark toggle for the QUREO public site.
   External file (CSP-safe: api.py only allows 'self' + one pinned inline hash).
   Restores the saved theme before first paint, then wires the toggle. */
(function () {
  try {
    var saved = localStorage.getItem("q-theme");
    if (saved) document.documentElement.dataset.theme = saved;
  } catch (e) { /* storage unavailable - stay dark */ }

  function bind() {
    var btn = document.querySelector(".theme-toggle");
    if (btn) btn.addEventListener("click", function () {
      var root = document.documentElement;
      var goingDark = root.dataset.theme === "light";
      if (goingDark) root.removeAttribute("data-theme");
      else root.dataset.theme = "light";
      try { localStorage.setItem("q-theme", goingDark ? "" : "light"); } catch (e) {}
    });

    /* glass topbar once the page scrolls */
    var wrap = document.querySelector(".topbar-wrap");
    if (wrap) {
      var onScroll = function () { wrap.classList.toggle("stuck", window.scrollY > 8); };
      window.addEventListener("scroll", onScroll, { passive: true });
      onScroll();
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bind);
  else bind();
})();
