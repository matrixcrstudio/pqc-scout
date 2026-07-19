// Theme toggle: persists the viewer's choice, respects OS default until set.
// Progressive enhancement — the page is fully readable with JS disabled.
(function () {
  var KEY = "pqc-scout-theme";
  var root = document.documentElement;

  function stored() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function apply(theme) {
    if (theme === "light" || theme === "dark") {
      root.setAttribute("data-theme", theme);
    } else {
      root.removeAttribute("data-theme");
    }
  }
  function current() {
    var s = stored();
    if (s) return s;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  apply(stored());

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.querySelector(".theme-toggle");
    if (!btn) return;
    function sync() {
      var mode = current();
      btn.setAttribute("aria-pressed", mode === "dark" ? "true" : "false");
      btn.textContent = mode === "dark" ? "Light theme" : "Dark theme";
    }
    sync();
    btn.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      try { localStorage.setItem(KEY, next); } catch (e) {}
      apply(next);
      sync();
    });
  });
})();
