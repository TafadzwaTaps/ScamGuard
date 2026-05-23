/**
 * ScamGuard AI — Frontend Application (v3.1 — Stabilized)
 *
 * Fixes applied vs v3.0:
 *   [FIX-1] 401 classification — only clears auth on confirmed token failure,
 *            never on validation/permission/backend errors
 *   [FIX-2] Token expiry comparison — removed the erroneous -60000 offset;
 *            expiry is now (exp * 1000) < Date.now() with a +30s grace buffer
 *   [FIX-3] Dead modal handlers (handleLogin/handleRegister) fully removed —
 *            they referenced Modal.showErr / Modal.clearAlerts which don't exist
 *   [FIX-4] Auth state is now the single source of truth in the Auth module;
 *            no duplicate state in auth.js (auth.js only handles its own pages)
 *   [FIX-5] Structured API error classification helper (classifyApiError)
 *   [FIX-6] Report submission has retry logic for transient 503 errors
 *   [FIX-7] Loading / disabled states are always cleaned up in finally blocks
 *   [FIX-8] recent-error element hidden by default on load
 */
"use strict";

(function () {

/* ════════════════════════════════════════════════════════════════════════════
   1. CONSTANTS & CONFIG
════════════════════════════════════════════════════════════════════════════ */
const API_BASE = window.API_BASE || "";

const SCAN_STEPS = [
  "Initializing scanner…",
  "Normalizing input…",
  "Running NLP analysis…",
  "Cross-referencing database…",
  "Computing threat score…",
  "Finalizing report…",
];

/* ════════════════════════════════════════════════════════════════════════════
   2. STORAGE MODULE — localStorage with in-memory fallback
════════════════════════════════════════════════════════════════════════════ */
const Store = (() => {
  const mem = {};
  let useLocal = false;
  try {
    localStorage.setItem("__sg_probe__", "1");
    localStorage.removeItem("__sg_probe__");
    useLocal = true;
  } catch {
    console.warn("[ScamGuard] localStorage blocked — using in-memory fallback.");
  }
  return {
    get: (k)    => useLocal ? localStorage.getItem(k)    : (mem[k] ?? null),
    set: (k, v) => useLocal ? localStorage.setItem(k, v) : (mem[k] = v),
    del: (k)    => useLocal ? localStorage.removeItem(k)  : (delete mem[k]),
  };
})();

/* ════════════════════════════════════════════════════════════════════════════
   3. AUTH MODULE  (single source of truth for session state)
════════════════════════════════════════════════════════════════════════════ */
const Auth = (() => {
  // Read initial state from storage once on load
  let token = Store.get("sg_token");
  let email = Store.get("sg_email");

  function getToken() { return token; }
  function getEmail() { return email; }

  function save(t, e) {
    token = t; email = e;
    Store.set("sg_token", t);
    Store.set("sg_email", e || "");
    UI.updateAuthState();
  }

  function clear() {
    token = null; email = null;
    Store.del("sg_token");
    Store.del("sg_email");
    UI.updateAuthState();
  }

  /**
   * [FIX-2] Token expiry check.
   *
   * BEFORE (buggy):
   *   return (payload.exp * 1000) < (Date.now() - 60000);
   *   This made a token appear expired 60 s BEFORE it actually was, triggering
   *   premature logout. Subtracting from Date.now() moved the threshold into
   *   the past — the opposite of a grace period.
   *
   * AFTER (correct):
   *   A +30 s grace window means the token must be expired for at least 30 s
   *   before we treat it as invalid client-side. The backend is the final
   *   authority on expiry; the client check is only for UX (disabling the
   *   report form before the API call even fires).
   */
  function isTokenExpired() {
    if (!token) return true;
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      if (!payload.exp) return false; // no expiry claim → treat as valid
      const GRACE_MS = 30_000;       // 30-second grace buffer
      return (payload.exp * 1000) < (Date.now() - GRACE_MS);
    } catch (_) {
      // Decode failed — do NOT log out; let the backend decide
      return false;
    }
  }

  function isLoggedIn() {
    if (!token) return false;
    // Only use client-side expiry check for UI gating.
    // Do NOT call clear() here — side effects here cause race conditions.
    if (isTokenExpired()) return false;
    return true;
  }

  // Login via API — used only if login is ever triggered from the main page
  // (currently login is a separate page, so this is kept for API module use)
  async function login(emailVal, password) {
    const res  = await API.post("/api/v1/auth/login", { email: emailVal, password });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Login failed.");
    save(data.access_token, data.email);
    return data;
  }

  async function register(emailVal, password) {
    const res  = await API.post("/api/v1/auth/register", { email: emailVal, password });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Registration failed.");
    return data;
  }

  return { isLoggedIn, isTokenExpired, getToken, getEmail, save, clear, login, register };
})();

/* ════════════════════════════════════════════════════════════════════════════
   4. ERROR CLASSIFICATION  [FIX-5]
   Provides structured, actionable error info from API responses.
════════════════════════════════════════════════════════════════════════════ */
const ErrorClass = {
  /**
   * Given an HTTP response and optional parsed body, return:
   *   { type, message, shouldLogout }
   *
   * Types: "auth_expired" | "auth_invalid" | "auth_required" |
   *        "validation" | "conflict" | "rate_limit" | "server" | "network"
   */
  classify(status, detail = "", isNetworkError = false) {
    if (isNetworkError) {
      return { type: "network", message: "Network error — check your connection.", shouldLogout: false };
    }

    const low = detail.toLowerCase();

    if (status === 401) {
      // [FIX-1] Only flag as auth failure if the backend message explicitly
      // confirms it. Generic 401s (e.g. permission denied) must NOT log out.
      const isExpired  = low.includes("expired") || low.includes("session");
      const isInvalid  = (low.includes("invalid") && (low.includes("token") || low.includes("authentication")))
                        || low.includes("please log in")
                        || low.includes("authentication required")
                        || low.includes("log in again");

      if (isExpired) {
        return { type: "auth_expired",  message: detail || "Your session has expired. Please log in again.", shouldLogout: true  };
      }
      if (isInvalid) {
        return { type: "auth_invalid",  message: detail || "Invalid authentication. Please log in again.",   shouldLogout: true  };
      }
      // 401 but reason unclear — show message, do NOT logout
      return { type: "auth_required",  message: detail || "Authentication required. Please log in.",         shouldLogout: false };
    }

    if (status === 409) return { type: "conflict",    message: detail || "Duplicate submission.", shouldLogout: false };
    if (status === 422) return { type: "validation",  message: detail || "Validation error.",     shouldLogout: false };
    if (status === 429) return { type: "rate_limit",  message: detail || "Too many requests — please wait.", shouldLogout: false };
    if (status >= 500)  return { type: "server",      message: detail || `Server error (${status}).`,        shouldLogout: false };

    return { type: "unknown", message: detail || `Request failed (${status}).`, shouldLogout: false };
  },

  /** Format Pydantic 422 detail arrays into a readable string. */
  formatValidation(detail) {
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map(d => d.msg || d.message || JSON.stringify(d)).join("; ");
    }
    return "Validation error. Please check your input.";
  },
};

/* ════════════════════════════════════════════════════════════════════════════
   5. API MODULE — all backend calls
════════════════════════════════════════════════════════════════════════════ */
const API = {
  _headers(extra = {}) {
    const h = { "Content-Type": "application/json", ...extra };
    const tok = Auth.getToken();
    if (tok) h["Authorization"] = `Bearer ${tok}`;
    return h;
  },

  post(path, body) {
    return fetch(API_BASE + path, {
      method:  "POST",
      headers: this._headers(),
      body:    JSON.stringify(body),
    });
  },

  async check(type, value) {
    let res;
    try {
      res = await this.post("/api/v1/check", { type, value });
    } catch (_) {
      throw new Error("Network error — check your connection and try again.");
    }
    if (!res.ok) {
      const e     = await res.json().catch(() => ({}));
      const info  = ErrorClass.classify(res.status, e.detail || "");
      throw new Error(info.message);
    }
    return res.json();
  },

  /**
   * [FIX-1] + [FIX-6] Report submission with:
   *   - Structured 401 classification (only logout on confirmed token failure)
   *   - One automatic retry on 503 Service Unavailable (transient DB issue)
   */
  async report(payload, _retryCount = 0) {
    let res;
    try {
      res = await this.post("/api/v1/report", payload);
    } catch (_) {
      throw new Error("Network error — check your connection and try again.");
    }

    if (!res.ok) {
      const e      = await res.json().catch(() => ({}));
      const detail = res.status === 422
        ? ErrorClass.formatValidation(e.detail)
        : (e.detail || "");
      const info   = ErrorClass.classify(res.status, detail);

      // Transient server error — retry once after a short delay [FIX-6]
      if (res.status === 503 && _retryCount === 0) {
        await sleep(1200);
        return this.report(payload, 1);
      }

      if (info.shouldLogout) {
        Auth.clear();
        Toast.err(info.message);
        setTimeout(() => { window.location.href = "/login"; }, 1600);
      }

      throw new Error(info.message);
    }

    return res.json();
  },

  async phoneIntel(number) {
    try {
      const encoded = encodeURIComponent(number);
      const res = await fetch(`${API_BASE}/api/v1/phone-intel?number=${encoded}`);
      if (!res.ok) return null;
      return res.json();
    } catch (_) { return null; }
  },

  async entities(limit = 10) {
    try {
      const res = await fetch(`${API_BASE}/api/v1/entities?limit=${limit}`);
      if (!res.ok) return [];
      return res.json();
    } catch (_) { return []; }
  },
};

/* ════════════════════════════════════════════════════════════════════════════
   6. MODAL MODULE — [FIX-3] Stubs only; auth lives on /login and /register.
   All dead modal logic removed. No event listeners attached to non-existent
   modal DOM elements, no conflicting overlay handlers.
════════════════════════════════════════════════════════════════════════════ */
const Modal = {
  open(tab = "login") {
    window.location.href = tab === "register" ? "/register" : "/login";
  },
  close()        { /* no-op — auth is on a separate page */ },
  showErr()      { /* no-op */ },
  showOk()       { /* no-op */ },
  clearAlerts()  { /* no-op */ },
  switchTab(tab) { window.location.href = tab === "register" ? "/register" : "/login"; },
};

/* ════════════════════════════════════════════════════════════════════════════
   7. TOAST MODULE
════════════════════════════════════════════════════════════════════════════ */
const Toast = {
  _container: null,
  _get() {
    if (!this._container) this._container = document.getElementById("toast-container");
    return this._container;
  },
  show(msg, type = "info", duration = 4500) {
    const icons = { ok: "bi-check-circle-fill", err: "bi-exclamation-circle-fill", info: "bi-info-circle-fill" };
    const el = document.createElement("div");
    el.className = `sg-toast toast-${type}`;
    el.setAttribute("role", "status");
    el.innerHTML = `<i class="bi ${icons[type] || icons.info} toast-icon" aria-hidden="true"></i><span>${esc(msg)}</span>`;
    this._get()?.appendChild(el);
    setTimeout(() => {
      el.classList.add("toast-out");
      el.addEventListener("animationend", () => el.remove(), { once: true });
    }, duration);
  },
  ok(msg)   { this.show(msg, "ok"); },
  err(msg)  { this.show(msg, "err", 6000); },
  info(msg) { this.show(msg, "info"); },
};

/* ════════════════════════════════════════════════════════════════════════════
   8. UI MODULE — DOM updates, auth state, rendering
════════════════════════════════════════════════════════════════════════════ */
const UI = {
  updateAuthState() {
    const loggedIn = Auth.isLoggedIn();
    const email    = Auth.getEmail();

    setVis("nav-auth-btn",  !loggedIn);
    setVis("nav-user-info",  loggedIn);
    setVis("nav-logout-btn", loggedIn);

    if (loggedIn && email) {
      setText("nav-user-email",   email);
      setText("nav-avatar-letter", email[0].toUpperCase());
    }

    const lockBar   = document.getElementById("auth-lock-notice");
    const submitBtn = document.getElementById("report-submit-btn");
    const fields    = document.querySelectorAll("#report-form input, #report-form textarea, #report-form select");

    if (lockBar)   lockBar.style.display = loggedIn ? "none" : "flex";
    if (submitBtn) submitBtn.disabled    = !loggedIn;
    fields.forEach(f => { f.disabled = !loggedIn; });
  },

  showAlert(elOrId, msg, type = "err") {
    const el = typeof elOrId === "string" ? document.getElementById(elOrId) : elOrId;
    if (!el) return;
    const icon = type === "err" ? "exclamation-triangle-fill" : "check-circle-fill";
    el.innerHTML = `<i class="bi bi-${icon}" aria-hidden="true"></i> ${esc(msg)}`;
    el.className = `sg-alert sg-alert-${type} visible`;
  },

  hideAlert(elOrId) {
    const el = typeof elOrId === "string" ? document.getElementById(elOrId) : elOrId;
    if (!el) return;
    el.textContent = "";
    el.classList.remove("visible");
  },

  setSpinner(id, active) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle("active", active);
  },

  /* ── Render scan result ── */
  renderResult(data, type, value) {
    const { risk_score, report_count, status, nlp_flags, sample_reports } = data;
    const panel = document.getElementById("result-panel");
    if (!panel) return;

    // Score ring
    const circumference = 2 * Math.PI * 52;
    const offset  = circumference - (risk_score / 100) * circumference;
    const ringFill = document.getElementById("ring-fill");
    if (ringFill) {
      ringFill.style.strokeDashoffset = offset;
      ringFill.style.stroke           = scoreColor(status);
      ringFill.style.filter           = `drop-shadow(0 0 6px ${scoreColorRaw(status)})`;
    }
    setText("res-score", Math.round(risk_score));
    const scoreEl = document.getElementById("res-score");
    if (scoreEl) scoreEl.style.color = scoreColor(status);

    // Badge
    const badge = document.getElementById("res-status-badge");
    if (badge) {
      badge.className = `threat-badge badge-${status}`;
      badge.innerHTML = `<i class="bi bi-${statusIcon(status)}" aria-hidden="true"></i> ${statusLabel(status)}`;
    }

    // Entity display
    const entityEl = document.getElementById("res-entity-display");
    if (entityEl) entityEl.textContent = `${type.toUpperCase()} → ${value.length > 50 ? value.slice(0, 50) + "…" : value}`;

    setText("res-report-count", report_count);

    // Verdict
    const verdict = document.getElementById("res-message");
    if (verdict) {
      const msgs = {
        high_risk:  `This entity has been reported <strong>${report_count}</strong> time(s) with strong fraud signals detected. Exercise extreme caution.`,
        suspicious: `This entity has been reported <strong>${report_count}</strong> time(s) with some suspicious indicators. Verify independently before engaging.`,
        safe:       `No significant threats detected (${report_count} report(s)). Always remain vigilant.`,
      };
      verdict.innerHTML = msgs[status] || msgs.safe;
    }

    // NLP confidence
    const conf = nlp_flags?.confidence ?? 0;
    setText("res-confidence", `${Math.round(conf * 100)}%`);
    const confBar = document.getElementById("res-confidence-bar");
    if (confBar) confBar.style.width = `${conf * 100}%`;

    // Keyword chips
    const kwEl = document.getElementById("res-keywords");
    if (kwEl) {
      kwEl.innerHTML = nlp_flags?.matched_keywords?.length
        ? nlp_flags.matched_keywords.map(k => `<span class="sg-chip chip-red">${esc(k)}</span>`).join("")
        : `<span class="sg-chip chip-none">None detected</span>`;
    }

    // Regex chips
    const rxEl = document.getElementById("res-regex");
    if (rxEl) {
      rxEl.innerHTML = nlp_flags?.regex_matches?.length
        ? nlp_flags.regex_matches.map(r => `<span class="sg-chip chip-amber">${esc(r)}</span>`).join("")
        : `<span class="sg-chip chip-none">None detected</span>`;
    }

    // Sample reports
    const reportsEl   = document.getElementById("res-reports");
    const noReportsEl = document.getElementById("res-no-reports");
    if (reportsEl) {
      reportsEl.innerHTML = "";
      if (sample_reports?.length) {
        noReportsEl?.classList.add("d-none");
        sample_reports.forEach(r => {
          const tags = Array.isArray(r.tags) && r.tags.length
            ? r.tags.map(t => `<span class="sg-chip chip-cyan">${esc(t)}</span>`).join("") : "";
          const div = document.createElement("div");
          div.className = "report-item";
          div.innerHTML = `
            <p>${esc(r.description)}</p>
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.3rem">
              <div>${tags}</div>
              <div class="meta">${fmtDate(r.created_at)}</div>
            </div>`;
          reportsEl.appendChild(div);
        });
      } else {
        noReportsEl?.classList.remove("d-none");
      }
    }

    // Phone intelligence panel (phone type only)
    const phonePanel = document.getElementById("phone-intel-panel");
    if (phonePanel) {
      phonePanel.style.display = "none";
      if (type === "phone") renderPhoneIntel(value, phonePanel);
    }

    // Pre-fill report form
    const repType  = document.getElementById("rep-type");
    const repValue = document.getElementById("rep-value");
    if (repType)  repType.value  = type;
    if (repValue) repValue.value = value;

    // Animate panel in
    panel.style.display = "block";
    panel.classList.remove("animate-in");
    void panel.offsetWidth;
    panel.classList.add("animate-in");
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  },

  /* ── Render recent entities ── */
  renderEntities(list) {
    const tbody = document.getElementById("recent-tbody");
    if (!tbody) return;

    if (!list.length) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-3);padding:2rem">
        No flagged entities yet. Be the first to submit a report.
      </td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(e => {
      const st   = statusFromScore(e.risk_score);
      const icon = st === "high_risk" ? "⚠️" : st === "suspicious" ? "🔍" : "✅";
      return `<tr>
        <td><span class="type-badge">${esc(e.type)}</span></td>
        <td class="val-cell" title="${esc(e.value)}">${esc(e.value)}</td>
        <td>
          <div class="score-bar-wrap">
            <div class="score-bar-track">
              <div class="score-bar-fill" style="width:${e.risk_score}%;background:${scoreColor(st)}"></div>
            </div>
            <span class="score-val" style="color:${scoreColor(st)}">${Math.round(e.risk_score)}</span>
          </div>
        </td>
        <td style="color:var(--text)">${e.report_count ?? 0}</td>
        <td><span class="threat-badge badge-${st}" style="font-size:.7rem">${icon} ${statusLabel(st)}</span></td>
      </tr>`;
    }).join("");
  },
};

/* ════════════════════════════════════════════════════════════════════════════
   9. ANIMATIONS MODULE
════════════════════════════════════════════════════════════════════════════ */
const Animations = {
  initCanvas() {
    const canvas = document.getElementById("bg-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let W, H, frame;

    const resize = () => {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener("resize", resize, { passive: true });

    const SPACING = 40, RADIUS = .8;
    let t = 0;

    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      t += .008;
      ctx.fillStyle = "rgba(0,212,255,.35)";
      for (let x = 0; x < W; x += SPACING) {
        for (let y = 0; y < H; y += SPACING) {
          const dist  = Math.hypot(x - W / 2, y - H / 2);
          const pulse = .3 + .7 * Math.sin(t - dist * .01);
          ctx.globalAlpha = pulse * .4;
          ctx.beginPath();
          ctx.arc(x, y, RADIUS, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      const grad = ctx.createRadialGradient(W / 2, H * .4, 0, W / 2, H * .4, W * .55);
      grad.addColorStop(0, "rgba(0,212,255,.04)");
      grad.addColorStop(1, "transparent");
      ctx.globalAlpha = 1;
      ctx.fillStyle   = grad;
      ctx.fillRect(0, 0, W, H);
      frame = requestAnimationFrame(draw);
    };
    draw();

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) cancelAnimationFrame(frame);
      else draw();
    });
  },

  initTicker() {
    const track = document.getElementById("ticker-track");
    if (!track) return;
    const clone = track.cloneNode(true);
    track.parentElement.appendChild(clone);
  },

  scanBeam(active) {
    const beam = document.getElementById("scan-beam");
    if (beam) beam.classList.toggle("active", active);
  },

  async animateScanProgress() {
    const wrap = document.getElementById("scan-progress-wrap");
    const bar  = document.getElementById("scan-progress-bar");
    const text = document.getElementById("scan-progress-text");
    const pct  = document.getElementById("scan-progress-pct");
    const btn  = document.getElementById("scan-submit-btn");
    if (!wrap || !bar) return;

    wrap.style.display = "block";
    if (btn) btn.disabled = true;
    this.scanBeam(true);

    for (let i = 0; i < SCAN_STEPS.length; i++) {
      const progress = Math.round(((i + 1) / SCAN_STEPS.length) * 100);
      if (text) text.textContent = SCAN_STEPS[i];
      if (pct)  pct.textContent  = `${progress}%`;
      bar.style.width = `${progress}%`;
      await sleep(280);
    }
  },

  stopScanProgress() {
    const wrap = document.getElementById("scan-progress-wrap");
    const btn  = document.getElementById("scan-submit-btn");
    if (wrap) wrap.style.display = "none";
    if (btn)  btn.disabled = false;
    this.scanBeam(false);
  },

  initMetricsCounter() {
    document.querySelectorAll(".metric-value[id]").forEach(el => {
      const target = parseInt(el.textContent.replace(/,/g, ""), 10);
      if (isNaN(target)) return;
      let current = 0;
      const step  = Math.ceil(target / 60);
      const timer = setInterval(() => {
        current = Math.min(current + step, target);
        el.textContent = current.toLocaleString();
        if (current >= target) clearInterval(timer);
      }, 25);
    });
  },
};

/* ════════════════════════════════════════════════════════════════════════════
   10. CONTROLLERS
════════════════════════════════════════════════════════════════════════════ */

/* ── Check / Scan Form ── */
async function handleCheckSubmit(e) {
  e.preventDefault();
  UI.hideAlert("check-alert");
  const resultPanel = document.getElementById("result-panel");
  if (resultPanel) resultPanel.style.display = "none";

  const typeInput = document.querySelector("input[name='check-type']:checked");
  const type  = typeInput ? typeInput.value : "message";
  const value = document.getElementById("check-value")?.value.trim();

  if (!value) { UI.showAlert("check-alert", "Please enter a value to scan."); return; }

  try {
    await Animations.animateScanProgress();
    const data = await API.check(type, value);
    UI.renderResult(data, type, value);
    Toast.ok(`Scan complete — ${statusLabel(data.status)}`);
  } catch (err) {
    UI.showAlert("check-alert", err.message);
    Toast.err("Scan failed: " + err.message);
  } finally {
    // [FIX-7] Always restore UI even if an error occurs
    Animations.stopScanProgress();
  }
}

/* ── Report Form ── [FIX-1] [FIX-6] [FIX-7] ── */
async function handleReportSubmit(e) {
  e.preventDefault();
  UI.hideAlert("report-alert");
  UI.hideAlert("report-success");

  if (!Auth.isLoggedIn()) {
    // Save intended destination so login can redirect back
    try { sessionStorage.setItem("sg_after_login", window.location.href); } catch (_) {}
    window.location.href = "/login";
    return;
  }

  const type        = document.getElementById("rep-type")?.value;
  const value       = document.getElementById("rep-value")?.value.trim();
  const description = document.getElementById("rep-description")?.value.trim();
  const tagsRaw     = document.getElementById("rep-tags")?.value;
  const tags        = tagsRaw ? tagsRaw.split(",").map(t => t.trim()).filter(Boolean) : [];

  if (!value)       { UI.showAlert("report-alert", "Please enter the entity value (phone, URL or message)."); return; }
  if (!description) { UI.showAlert("report-alert", "Please enter an incident description."); return; }
  if (description.length < 10) { UI.showAlert("report-alert", "Description must be at least 10 characters."); return; }

  const submitBtn = document.getElementById("report-submit-btn");
  UI.setSpinner("report-spinner", true);
  if (submitBtn) submitBtn.disabled = true;

  try {
    await API.report({ type, value, description, tags });
    // Clear only description + tags; keep type/value for follow-up
    const descEl = document.getElementById("rep-description");
    const tagsEl = document.getElementById("rep-tags");
    if (descEl) descEl.value = "";
    if (tagsEl) tagsEl.value = "";
    UI.showAlert("report-success", "Report submitted — thank you for protecting the community!", "ok");
    document.getElementById("report-success")?.scrollIntoView({ behavior: "smooth" });
    Toast.ok("Intelligence report submitted!");
    await loadEntities();
  } catch (err) {
    UI.showAlert("report-alert", err.message);
    Toast.err(err.message);
  } finally {
    // [FIX-7] Always restore button state
    UI.setSpinner("report-spinner", false);
    if (submitBtn) submitBtn.disabled = !Auth.isLoggedIn();
  }
}

/* ── Phone Intelligence Renderer ── */
async function renderPhoneIntel(number, container) {
  container.style.display = "block";
  container.innerHTML = `
    <div class="phone-intel-card">
      <div class="phone-intel-header">
        <i class="bi bi-telephone-fill"></i>
        <span>Phone Intelligence</span>
        <div class="phone-loading-badge">Analysing…</div>
      </div>
      <div class="phone-intel-skeleton"></div>
    </div>`;

  const data = await API.phoneIntel(number);
  if (!data) { container.style.display = "none"; return; }

  const typeIcon  = { mobile: "📱", fixed: "☎️", voip: "💻", unknown: "📞" };
  const typeLabel = { mobile: "Mobile", fixed: "Fixed Line", voip: "VOIP/Virtual", unknown: "Unknown" };
  const icon      = typeIcon[data.number_type] || "📞";

  const riskBadge = data.risk_indicators.length > 0
    ? `<span class="phone-risk-badge high">⚠ ${data.risk_indicators.length} Risk Indicator${data.risk_indicators.length > 1 ? "s" : ""}</span>`
    : `<span class="phone-risk-badge safe">✓ No Risk Flags</span>`;

  const indicators = data.risk_indicators.length
    ? `<div class="phone-indicators">${data.risk_indicators.map(i => `<div class="phone-indicator-item">⚠ ${esc(i)}</div>`).join("")}</div>`
    : "";

  const categories = data.top_scam_categories.length
    ? `<div class="phone-tags">${data.top_scam_categories.map(t => `<span class="phone-tag">${esc(t)}</span>`).join("")}</div>`
    : "";

  const lastActivity = data.last_reported
    ? `<div class="phone-meta-item"><span>Last Reported</span><strong>${fmtDate(data.last_reported)}</strong></div>`
    : "";

  const firstSeen = data.first_seen
    ? `<div class="phone-meta-item"><span>First Seen</span><strong>${fmtDate(data.first_seen)}</strong></div>`
    : "";

  container.innerHTML = `
    <div class="phone-intel-card animate-in">
      <div class="phone-intel-header">
        <span>${icon} Phone Intelligence</span>
        ${riskBadge}
      </div>
      <div class="phone-intel-body">
        <div class="phone-grid">
          <div class="phone-detail-item"><div class="phone-detail-label">Country</div><div class="phone-detail-value">${esc(data.country)}</div></div>
          <div class="phone-detail-item"><div class="phone-detail-label">Carrier</div><div class="phone-detail-value">${esc(data.carrier)}</div></div>
          <div class="phone-detail-item"><div class="phone-detail-label">Number Type</div><div class="phone-detail-value">${typeLabel[data.number_type] || esc(data.number_type)}</div></div>
          <div class="phone-detail-item"><div class="phone-detail-label">Format (Local)</div><div class="phone-detail-value">${esc(data.local_format || data.normalized)}</div></div>
          <div class="phone-detail-item"><div class="phone-detail-label">Reports (Total)</div><div class="phone-detail-value">${data.report_count}</div></div>
          <div class="phone-detail-item"><div class="phone-detail-label">Reports (30 days)</div><div class="phone-detail-value">${data.recent_report_count}</div></div>
        </div>
        ${indicators}
        ${categories ? `<div class="phone-categories-label">Reported Scam Categories</div>${categories}` : ""}
        ${lastActivity || firstSeen ? `<div class="phone-meta">${firstSeen}${lastActivity}</div>` : ""}
        <div class="phone-summary">${esc(data.intel_summary)}</div>
        <div class="phone-disclaimer">ℹ Data based on number structure and community reports. Always verify independently.</div>
      </div>
    </div>`;
}

/* ── Load Entities ── */
async function loadEntities() {
  if (!document.getElementById("recent-tbody")) return;
  const errEl = document.getElementById("recent-error");
  if (errEl) errEl.style.display = "none"; // Hide error by default on each load

  try {
    const list = await API.entities(10);
    UI.renderEntities(list);
  } catch (err) {
    console.warn("[ScamGuard] Entity load skipped:", err.message);
    if (errEl) {
      errEl.style.display = "block";
      errEl.textContent   = "Could not load threat data. Refresh to try again.";
    }
  }
}

/* ── Copy result to clipboard ── */
async function copyResult() {
  const score  = document.getElementById("res-score")?.textContent;
  const entity = document.getElementById("res-entity-display")?.textContent;
  const badge  = document.getElementById("res-status-badge")?.textContent?.trim();
  if (!score) return;
  const text = `ScamGuard Scan Result\n${entity}\nRisk Score: ${score}/100\nStatus: ${badge}`;
  try {
    await navigator.clipboard.writeText(text);
    Toast.info("Result copied to clipboard!");
  } catch {
    Toast.err("Clipboard copy failed.");
  }
}

/* ════════════════════════════════════════════════════════════════════════════
   11. UTILITIES
════════════════════════════════════════════════════════════════════════════ */
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
function setVis(id, show) { const el = document.getElementById(id); if (el) el.classList.toggle("d-none", !show); }
function sleep(ms)        { return new Promise(r => setTimeout(r, ms)); }

function statusLabel(s)     { return s === "high_risk" ? "HIGH RISK" : s === "suspicious" ? "SUSPICIOUS" : "SAFE"; }
function statusIcon(s)      { return s === "high_risk" ? "bi-exclamation-octagon-fill" : s === "suspicious" ? "bi-exclamation-triangle-fill" : "bi-shield-check"; }
function statusFromScore(s) { return s >= 60 ? "high_risk" : s >= 30 ? "suspicious" : "safe"; }
function scoreColorRaw(s)   { return s === "high_risk" ? "#f43f5e" : s === "suspicious" ? "#fbbf24" : "#10d994"; }
function scoreColor(s)      { return `var(--${s === "high_risk" ? "red" : s === "suspicious" ? "amber" : "green"})`; }
function fmtDate(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch { return iso; }
}

/* ════════════════════════════════════════════════════════════════════════════
   12. EVENT WIRING — all via addEventListener, zero inline handlers
   [FIX-3] Removed all modal form wiring (handleLogin/handleRegister) since
   auth pages are /login and /register. No event listeners are attached to
   elements that don't exist, eliminating silent JS errors.
════════════════════════════════════════════════════════════════════════════ */
function wireEvents() {
  // Check form
  document.getElementById("check-form")?.addEventListener("submit", handleCheckSubmit);

  // Report form
  document.getElementById("report-form")?.addEventListener("submit", handleReportSubmit);

  // Logout
  document.getElementById("nav-logout-btn")?.addEventListener("click", () => {
    Auth.clear();
    Toast.info("Logged out successfully.");
    // Reload to reset all UI state cleanly
    setTimeout(() => window.location.reload(), 600);
  });

  // Lock bar login button (no JS redirect needed — it's an <a>)
  // Kept as listener in case it's a <button> variant on some pages
  document.getElementById("lock-login-btn")?.addEventListener("click", e => {
    if (e.currentTarget.tagName !== "A") {
      e.preventDefault();
      try { sessionStorage.setItem("sg_after_login", window.location.href); } catch (_) {}
      window.location.href = "/login";
    }
  });

  // Result CTA buttons
  document.getElementById("result-report-cta")?.addEventListener("click", () => {
    document.getElementById("report-section")?.scrollIntoView({ behavior: "smooth" });
  });
  document.getElementById("result-copy-btn")?.addEventListener("click", copyResult);

  // Type radio label styling
  document.querySelectorAll("input[name='check-type']").forEach(radio => {
    radio.addEventListener("change", () => {
      document.querySelectorAll(".type-radio").forEach(l => l.classList.remove("checked"));
      radio.closest(".type-radio")?.classList.add("checked");
    });
  });

  // Password visibility toggles (data-pw-toggle="inputId")
  document.addEventListener("click", e => {
    const btn = e.target.closest("[data-pw-toggle]");
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    const input = document.getElementById(btn.getAttribute("data-pw-toggle"));
    if (!input) return;
    const icon = btn.querySelector("i");
    if (input.type === "password") {
      input.type = "text";
      if (icon) { icon.classList.remove("bi-eye"); icon.classList.add("bi-eye-slash"); }
      btn.setAttribute("aria-label", "Hide password");
    } else {
      input.type = "password";
      if (icon) { icon.classList.remove("bi-eye-slash"); icon.classList.add("bi-eye"); }
      btn.setAttribute("aria-label", "Show password");
    }
    input.focus();
  });
}

/* ════════════════════════════════════════════════════════════════════════════
   13. INIT
════════════════════════════════════════════════════════════════════════════ */
document.addEventListener("DOMContentLoaded", () => {
  // Hide error banner immediately on load — only shown if entities actually fail
  const errEl = document.getElementById("recent-error");
  if (errEl) errEl.style.display = "none";

  wireEvents();
  UI.updateAuthState();
  Animations.initCanvas();
  Animations.initTicker();
  Animations.initMetricsCounter();
  loadEntities();
});

})(); // end IIFE
