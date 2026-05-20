/**
 * ScamGuard — Auth Modal Controller (v3)
 * =======================================
 * Manages the #authModal overlay with zero dependency on Bootstrap CSS.
 * The auth modal uses inline styles + sg-modal-content classes only —
 * NO Bootstrap .modal/.modal-dialog classes that set pointer-events:none.
 *
 * Exposes: window.bootstrap.Modal (getOrCreateInstance, getInstance)
 * Also:    window.bootstrap.Collapse (for navbar hamburger)
 */
(function (global) {
  "use strict";

  /* ─── Modal ──────────────────────────────────────────────────────────── */
  class Modal {
    constructor(el) {
      this._el       = typeof el === "string" ? document.querySelector(el) : el;
      this._isShown  = false;
      this._lastFocus = null;
      this._keyFn    = null;

      // Wire close buttons (data-bs-dismiss="modal")
      this._el?.querySelectorAll("[data-bs-dismiss='modal']").forEach(btn => {
        btn.addEventListener("click", e => { e.stopPropagation(); this.hide(); });
      });

      // Click on the dark overlay backdrop (not the white card) closes modal
      this._el?.addEventListener("click", e => {
        // Only close if the click target IS the overlay itself, not a child
        if (e.target === this._el) this.hide();
      });
    }

    show() {
      if (this._isShown) return;
      this._isShown   = true;
      this._lastFocus = document.activeElement;

      // Lock body scroll
      document.body.style.overflow    = "hidden";
      document.body.style.paddingRight = "0";

      // Show overlay — use flex so content is centred
      Object.assign(this._el.style, {
        display:        "flex",
        opacity:        "0",
        transition:     "opacity .2s ease",
      });
      this._el.removeAttribute("aria-hidden");
      this._el.setAttribute("aria-modal", "true");

      // Fade in
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          this._el.style.opacity = "1";
        });
      });

      // Focus first input after animation
      setTimeout(() => {
        const firstInput = this._el.querySelector(
          "input:not([disabled]):not([type='hidden'])"
        );
        firstInput?.focus();
        this._el.dispatchEvent(new CustomEvent("shown.bs.modal", { bubbles: true }));
      }, 220);

      // Keyboard handler
      this._keyFn = e => {
        if (!this._isShown) return;
        if (e.key === "Escape") { e.preventDefault(); this.hide(); return; }
        if (e.key === "Tab")   this._trapFocus(e);
      };
      document.addEventListener("keydown", this._keyFn);
    }

    hide() {
      if (!this._isShown) return;
      this._isShown = false;

      if (this._keyFn) {
        document.removeEventListener("keydown", this._keyFn);
        this._keyFn = null;
      }

      // Fade out
      this._el.style.opacity = "0";

      setTimeout(() => {
        this._el.style.display = "none";
        this._el.style.transition = "";
        this._el.setAttribute("aria-hidden", "true");
        this._el.removeAttribute("aria-modal");
        document.body.style.overflow    = "";
        document.body.style.paddingRight = "";
        try { this._lastFocus?.focus?.(); } catch (_) {}
        this._el.dispatchEvent(new CustomEvent("hidden.bs.modal", { bubbles: true }));
      }, 210);
    }

    _trapFocus(e) {
      const all = Array.from(this._el.querySelectorAll(
        "button:not([disabled]),input:not([disabled]),textarea:not([disabled])," +
        "select:not([disabled]),a[href],[tabindex]:not([tabindex='-1'])"
      )).filter(el => {
        const s = window.getComputedStyle(el);
        return s.display !== "none" && s.visibility !== "hidden" && el.offsetParent !== null;
      });
      if (all.length < 2) return;
      const first = all[0], last = all[all.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault(); last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault(); first.focus();
      }
    }

    static getOrCreateInstance(el) {
      if (typeof el === "string") el = document.querySelector(el);
      if (!el) return null;
      if (!el.__sgModal) el.__sgModal = new Modal(el);
      return el.__sgModal;
    }

    static getInstance(el) {
      if (typeof el === "string") el = document.querySelector(el);
      return el?.__sgModal ?? null;
    }
  }

  /* ─── Collapse (navbar toggler) ─────────────────────────────────────── */
  class Collapse {
    constructor(el, opts = {}) {
      if (typeof el === "string") el = document.querySelector(el);
      this._el = el;
      if (opts.toggle !== false) this.toggle();
    }
    show()   { if (!this._el) return; this._el.classList.add("show"); this._el.style.height = "auto"; }
    hide()   { if (!this._el) return; this._el.classList.remove("show"); this._el.style.height = ""; }
    toggle() { this._el?.classList.contains("show") ? this.hide() : this.show(); }
    static getOrCreateInstance(el) {
      if (typeof el === "string") el = document.querySelector(el);
      if (!el) return null;
      if (!el.__sgCollapse) el.__sgCollapse = new Collapse(el, { toggle: false });
      return el.__sgCollapse;
    }
  }

  /* ─── Expose as window.bootstrap ───────────────────────────────────── */
  global.bootstrap = { Modal, Collapse };

  /* ─── Auto-wire data-bs-toggle="collapse" ───────────────────────────── */
  document.addEventListener("click", e => {
    const tog = e.target.closest("[data-bs-toggle='collapse']");
    if (!tog) return;
    const target = document.querySelector(tog.getAttribute("data-bs-target") || "");
    if (target) Collapse.getOrCreateInstance(target).toggle();
  });

})(window);
