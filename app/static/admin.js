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

  // Live audit tail — EventSource-based row prepend for /admin/audit.
  function wireLiveToggle(root) {
    var btn = root.querySelector("button.live-toggle");
    if (!btn) return;

    var tbody = document.getElementById("audit-tbody");
    if (!tbody) return;

    // Parse active URL filters once at initialisation time.
    var params = new URLSearchParams(window.location.search);
    var filterAction       = params.get("action")        || "";
    var filterResourceType = params.get("resource_type") || "";
    var filterResourceId   = params.get("resource_id")   || "";
    var filterActorId      = params.get("actor_id")      || "";

    var es = null;

    function escText(val) {
      // Safe text assignment via textContent — no innerHTML with user data.
      return val == null ? "" : String(val);
    }

    function matchesFilter(evt) {
      if (filterAction       && evt.action        !== filterAction)       return false;
      if (filterResourceType && evt.resource_type !== filterResourceType) return false;
      if (filterResourceId   && evt.resource_id   !== filterResourceId)   return false;
      // actor_id arrives as a number from JSON; filter param is a string.
      if (filterActorId && String(evt.actor_id) !== filterActorId)        return false;
      return true;
    }

    function buildRow(evt) {
      var tr = document.createElement("tr");
      tr.className = "audit-row-new";

      // When
      var tdWhen = document.createElement("td");
      tdWhen.className = "nowrap";
      tdWhen.textContent = escText(evt.created_at);
      tr.appendChild(tdWhen);

      // Actor
      var tdActor = document.createElement("td");
      if (evt.actor_email) {
        tdActor.textContent = evt.actor_email;
      } else if (evt.actor_id) {
        tdActor.textContent = "#" + evt.actor_id;
      } else {
        var muted = document.createElement("span");
        muted.className = "muted";
        muted.textContent = "\u2014";
        tdActor.appendChild(muted);
      }
      tr.appendChild(tdActor);

      // Action
      var tdAction = document.createElement("td");
      var code = document.createElement("code");
      code.textContent = escText(evt.action);
      tdAction.appendChild(code);
      tr.appendChild(tdAction);

      // Resource
      var tdRes = document.createElement("td");
      if (evt.resource_type) {
        var pill = document.createElement("span");
        pill.className = "pill";
        pill.textContent = escText(evt.resource_type);
        tdRes.appendChild(pill);
      }
      if (evt.resource_id) {
        var rcode = document.createElement("code");
        rcode.textContent = escText(evt.resource_id);
        tdRes.appendChild(rcode);
      }
      tr.appendChild(tdRes);

      // IP
      var tdIp = document.createElement("td");
      tdIp.className = "muted";
      tdIp.textContent = evt.ip || "\u2014";
      tr.appendChild(tdIp);

      // Detail
      var tdDetail = document.createElement("td");
      if (evt.detail != null) {
        var details = document.createElement("details");
        var summary = document.createElement("summary");
        summary.textContent = "view";
        details.appendChild(summary);
        var pre = document.createElement("pre");
        pre.className = "detail";
        pre.textContent = JSON.stringify(evt.detail, null, 2);
        details.appendChild(pre);
        tdDetail.appendChild(details);
      } else {
        var dash = document.createElement("span");
        dash.className = "muted";
        dash.textContent = "\u2014";
        tdDetail.appendChild(dash);
      }
      tr.appendChild(tdDetail);

      return tr;
    }

    function openStream() {
      es = new EventSource("/admin/audit/stream");

      es.addEventListener("audit", function (ev) {
        var evt;
        try { evt = JSON.parse(ev.data); } catch (e) { return; }
        if (!matchesFilter(evt)) return;

        var tr = buildRow(evt);
        tbody.insertBefore(tr, tbody.firstChild);

        setTimeout(function () {
          tr.classList.remove("audit-row-new");
        }, 600);
      });

      es.addEventListener("error", function () {
        console.warn("[live-audit] EventSource error — native reconnect in progress");
      });
    }

    function closeStream() {
      if (es) { es.close(); es = null; }
    }

    btn.addEventListener("click", function () {
      if (btn.getAttribute("data-live") === "off") {
        openStream();
        btn.setAttribute("data-live", "on");
        btn.setAttribute("aria-pressed", "true");
        btn.classList.add("is-active");
      } else {
        closeStream();
        btn.setAttribute("data-live", "off");
        btn.setAttribute("aria-pressed", "false");
        btn.classList.remove("is-active");
      }
    });

    window.addEventListener("beforeunload", closeStream);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      wireCopyButtons(document);
      wireLiveToggle(document);
    });
  } else {
    wireCopyButtons(document);
    wireLiveToggle(document);
  }
})();
