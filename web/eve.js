/* eve.hartle.tech — the page's only script.
 *
 * Three small enhancements and nothing else: a border on the bar once it has
 * something to sit above, a reveal as sections come into view, and the counters
 * in the stats row. No framework, no CDN — the site's CSP is `script-src 'self'`
 * precisely so that nothing a third party controls can run here.
 *
 * Everything below is an enhancement. The page is complete without it, which is
 * why <html> ships with `no-js` and this file's first job is to take it off.
 */

(function () {
  "use strict";

  document.documentElement.classList.remove("no-js");

  var reduced = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ── the bar ────────────────────────────────────────────────────────── */

  var bar = document.getElementById("bar");
  if (bar) {
    var onScroll = function () {
      bar.classList.toggle("stuck", window.scrollY > 8);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }

  /* ── the reveal ─────────────────────────────────────────────────────── */

  var targets = document.querySelectorAll("[data-reveal]");

  // No IntersectionObserver, or the visitor asked for less motion: show
  // everything at once rather than leaving the page blank.
  if (reduced || !("IntersectionObserver" in window)) {
    for (var i = 0; i < targets.length; i++) targets[i].classList.add("in");
    countUp(document.querySelectorAll("[data-count]"), true);
    return;
  }

  var seen = new IntersectionObserver(function (entries, obs) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) return;
      // The stagger between siblings is a :nth-child rule in the stylesheet
      // rather than a delay written from here. Whether CSSOM writes are exempt
      // from `style-src 'self'` is a detail not worth depending on, and the
      // grids that need staggering are known at author time.
      entry.target.classList.add("in");
      obs.unobserve(entry.target);
    });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });

  for (var j = 0; j < targets.length; j++) seen.observe(targets[j]);

  /* ── the counters ───────────────────────────────────────────────────── */

  var stats = document.querySelectorAll("[data-count]");
  if (stats.length) {
    var counting = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        countUp([entry.target], false);
        obs.unobserve(entry.target);
      });
    }, { threshold: 0.6 });
    for (var k = 0; k < stats.length; k++) counting.observe(stats[k]);
  }

  function countUp(nodes, instant) {
    Array.prototype.forEach.call(nodes, function (node) {
      var target = parseInt(node.getAttribute("data-count"), 10) || 0;
      if (instant || target === 0) {
        node.textContent = String(target);
        return;
      }
      var started = null;
      var span = 900;
      var step = function (now) {
        if (started === null) started = now;
        var t = Math.min((now - started) / span, 1);
        // Ease out, so the last digits settle instead of snapping.
        var eased = 1 - Math.pow(1 - t, 3);
        node.textContent = String(Math.round(target * eased));
        if (t < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    });
  }
})();
