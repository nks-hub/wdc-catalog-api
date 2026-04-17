// Minimal progressive-enhancement script for the admin UI.
//
// Served from /static/admin.js — covered by strict CSP
// (script-src 'self'), so no inline handlers. Everything here is
// additive: the UI must remain usable if this file fails to load.
(function () {
  "use strict";

  // Copy-to-clipboard for elements marked data-copy-target="<id>".
  // Used by the hero block rendered after minting a PAT so admins can
  // grab the plaintext token without fiddling with selection.
  function wireCopyButtons(root) {
    var buttons = root.querySelectorAll("[data-copy-target]");
    for (var i = 0; i < buttons.length; i++) {
      (function (btn) {
        var originalLabel = btn.textContent;
        btn.addEventListener("click", function () {
          var target = document.getElementById(btn.getAttribute("data-copy-target"));
          if (!target) return;
          var text = target.textContent.trim();
          var done = function (ok) {
            btn.classList.toggle("is-copied", ok);
            btn.textContent = ok ? "Copied" : "Copy failed";
            setTimeout(function () {
              btn.textContent = originalLabel;
              btn.classList.remove("is-copied");
            }, 1800);
          };
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(
              function () { done(true); },
              function () { done(false); }
            );
          } else {
            // Fallback: select-all so Ctrl+C works immediately.
            var range = document.createRange();
            range.selectNodeContents(target);
            var sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            done(true);
          }
        });
      })(buttons[i]);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { wireCopyButtons(document); });
  } else {
    wireCopyButtons(document);
  }
})();
