/* dn42 Autopeer WebUI — progressive enhancement. No framework, no build step.
   Everything here is optional sugar: with JS disabled the forms still POST and pages still work. */
(function () {
  "use strict";

  // ---------- copy to clipboard ----------
  function writeClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    // Fallback for non-secure contexts (plain http on a LAN IP).
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        document.body.removeChild(ta);
      }
    });
  }

  function flashButton(btn, label) {
    var original = btn.dataset.label || btn.textContent;
    btn.dataset.label = original;
    btn.textContent = label;
    setTimeout(function () {
      btn.textContent = btn.dataset.label;
    }, 1400);
  }

  // ---------- async looking glass result rendering ----------
  function renderLgResult(container, data) {
    var ok = !!data.ok;
    var text =
      data.output != null ? data.output : data.detail != null ? data.detail : "Query failed";
    if (!text) text = "(no output)";
    container.innerHTML = "";
    var wrap = document.createElement("div");
    wrap.className = "codewrap";
    var copy = document.createElement("button");
    copy.type = "button";
    copy.className = "copy-btn";
    copy.textContent = "Copy";
    var pre = document.createElement("pre");
    pre.className = "terminal " + (ok ? "ok" : "bad");
    pre.textContent = text;
    wrap.appendChild(copy);
    wrap.appendChild(pre);
    container.appendChild(wrap);
  }

  function fadeRemove(el) {
    if (!el) return;
    el.style.transition = "opacity 0.3s";
    el.style.opacity = "0";
    setTimeout(function () {
      el.remove();
    }, 300);
  }

  function peerLinkLocalFromAsn(value) {
    var asn = (value || "").trim().toUpperCase();
    if (asn.indexOf("AS") === 0) asn = asn.slice(2);
    if (!/^\d+$/.test(asn)) return "";
    var suffix;
    if (asn.length < 4) {
      suffix = asn;
    } else if (asn.indexOf("424242") === 0) {
      suffix = asn.slice(6);
    } else {
      suffix = asn.slice(-4);
    }
    suffix = suffix.replace(/^0+/, "") || "0";
    return "fe80::" + suffix.toLowerCase();
  }

  function setupAdminPeerForm() {
    var asnInput = document.getElementById("admin-peer-asn");
    var addrInput = document.getElementById("admin-peer-link-address");
    if (!asnInput || !addrInput) return;

    function maybeFillPeerAddress() {
      var next = peerLinkLocalFromAsn(asnInput.value);
      var previous = addrInput.dataset.autofilledValue || "";
      if (!next) return;
      if (!addrInput.value.trim() || addrInput.value.trim() === previous) {
        addrInput.value = next;
        addrInput.dataset.autofilledValue = next;
      }
    }

    asnInput.addEventListener("input", maybeFillPeerAddress);
    asnInput.addEventListener("change", maybeFillPeerAddress);
    maybeFillPeerAddress();
  }

  document.addEventListener("DOMContentLoaded", function () {
    // Copy buttons: literal `data-copy`, or the <pre> inside the button's `.codewrap`.
    document.addEventListener("click", function (e) {
      var btn = e.target.closest && e.target.closest(".copy-btn");
      if (!btn) return;
      var text = btn.getAttribute("data-copy");
      if (text === null) {
        var wrap = btn.closest(".codewrap");
        var pre = wrap
          ? wrap.querySelector("pre")
          : document.querySelector(btn.getAttribute("data-copy-target") || "pre");
        text = pre ? pre.innerText : "";
      }
      writeClipboard(text).then(
        function () {
          flashButton(btn, "Copied!");
        },
        function () {
          flashButton(btn, "Press Ctrl+C");
        }
      );
    });

    // Confirm dialogs for destructive actions (data-confirm on the button or its form).
    document.addEventListener("submit", function (e) {
      var form = e.target;
      var trigger = e.submitter;
      var msg =
        (trigger && trigger.getAttribute("data-confirm")) || form.getAttribute("data-confirm");
      if (msg && !window.confirm(msg)) {
        e.preventDefault();
      }
    });

    // Async looking glass: swap the result in place instead of a full page reload.
    var lgForm = document.getElementById("lg-form");
    var lgResult = document.getElementById("lg-result");
    if (lgForm && lgResult) {
      // `status` is router-wide and takes no target — disable (and clear) the Target field while
      // it is selected so a target can't be entered (the backend rejects one anyway).
      var lgQuery = lgForm.querySelector('select[name="query_type"]');
      var lgTarget = lgForm.querySelector('input[name="target"]');
      if (lgQuery && lgTarget) {
        var syncTarget = function () {
          if (lgTarget.dataset.placeholder == null) {
            lgTarget.dataset.placeholder = lgTarget.getAttribute("placeholder") || "";
          }
          if (lgQuery.value === "status") {
            lgTarget.value = "";
            lgTarget.disabled = true;
            lgTarget.placeholder = "Not used for status";
          } else {
            lgTarget.disabled = false;
            lgTarget.placeholder = lgTarget.dataset.placeholder;
          }
        };
        lgQuery.addEventListener("change", syncTarget);
        syncTarget();
      }

      lgForm.addEventListener("submit", function (e) {
        e.preventDefault();
        var btn = lgForm.querySelector('button[type="submit"]');
        var prev = btn ? btn.textContent : "";
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Running…";
        }
        fetch("/lg", {
          method: "POST",
          body: new FormData(lgForm),
          headers: { "X-Requested-With": "fetch", Accept: "application/json" },
        })
          .then(function (resp) {
            return resp.json().catch(function () {
              return { ok: false, output: "Unexpected response (HTTP " + resp.status + ")" };
            });
          })
          .then(function (data) {
            renderLgResult(lgResult, data);
          })
          .catch(function (err) {
            renderLgResult(lgResult, { ok: false, output: "Request failed: " + err });
          })
          .finally(function () {
            if (btn) {
              btn.disabled = false;
              btn.textContent = prev;
            }
          });
      });
    }

    setupAdminPeerForm();

    // Flash banners: close button always; auto-dismiss non-errors after a few seconds.
    document.addEventListener("click", function (e) {
      if (e.target.classList && e.target.classList.contains("flash-close")) {
        fadeRemove(e.target.closest(".flash"));
      }
    });
    document.querySelectorAll(".flash:not(.flash-error)").forEach(function (el) {
      setTimeout(function () {
        fadeRemove(el);
      }, 6000);
    });
  });
})();
