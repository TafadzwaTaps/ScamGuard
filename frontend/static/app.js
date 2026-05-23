/**
 * ScamGuard AI — Frontend Application
 * Modular vanilla JS: no inline handlers, no global pollution.
 * Preserves all existing FastAPI backend API contracts.
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
   2. STORAGE MODULE — localStorage with in-memory fallback (Edge tracking fix)
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
    get: (k)    => useLocal ? localStorage.getItem(k) : (mem[k] ?? null),
    set: (k, v) => useLocal ? localStorage.setItem(k, v) : (mem[k] = v),
    del: (k)    => useLocal ? localStorage.removeItem(k) : delete mem[k],
  };
})();

/* ════════════════════════════════════════════════════════════════════════════
   3. AUTH MODULE
════════════════════════════════════════════════════════════════════════════ */
const Auth = (() => {
  let token = Store.get("sg_token");
  let email = Store.get("sg_email");

  function getToken()   { return token; }
  function getEmail()   { return email; }

  function save(t, e) {
    token = t; email = e;
    Store.set("sg_token", t);
    Store.set("sg_email", e);
    UI.updateAuthState();
  }

  function clear() {
    token = null; email = null;
    Store.del("sg_token"); Store.del("sg_email");
    UI.updateAuthState();
  }

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

  function isTokenExpired() {
    if (!token) return true;
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      if (!payload.exp) return false;   // no expiry claim — treat as valid
      // Token is expired when exp (seconds) * 1000 < now (milliseconds)
      // We do NOT add grace here — let the backend be the authority on expiry
      // The 60s buffer here would cause premature logout; backend validates exactly
      return (payload.exp * 1000) < Date.now();
    } catch (_) { return false; }   // decode error → treat as valid (backend will reject if bad)
  }

  function isLoggedIn() {
    if (!token) return false;
    // Do NOT call clear() here — that triggers DOM updates mid-request
    // Just signal: token looks expired. The 401 handler will clear cleanly.
    if (isTokenExpired()) return false;
    return true;
  }

  return { isLoggedIn, isTokenExpired, getToken, getEmail, save, clear, login, register };
})();

/* ════════════════════════════════════════════════════════════════════════════
   4. API MODULE — all backend calls
════════════════════════════════════════════════════════════════════════════ */
const API = {
  _headers(extra = {}) {
    const h = { "Content-Type": "application/json", ...extra };
    if (Auth.isLoggedIn()) h["Authorization"] = `Bearer ${Auth.getToken()}`;
    return h;
  },
  post(path, body) {
    return fetch(API_BASE + path, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
  },
  async check(type, value) {
    let res;
    try {
      res = await this.post("/api/v1/check", { type, value });
    } catch (netErr) {
      throw new Error("Network error — check your connection and try again.");
    }
    if (res.status === 429) throw new Error("Rate limit reached. Please wait a moment.");
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.detail || `Scan failed (${res.status}). Please try again.`);
    }
    return res.json();
  },
  async report(payload) {
    const res = await this.post("/api/v1/report", payload);

    if (res.status === 401) {
      const errData = await res.json().catch(() => ({}));
      const msg = errData.detail || "";
      const msgLow = msg.toLowerCase();

      // Only redirect + clear if backend confirms authentication failure
      // NOT for generic permission errors, validation errors, or backend bugs
      const isAuthFailure =
        msgLow.includes("expired") ||
        msgLow.includes("invalid") && msgLow.includes("token") ||
        msgLow.includes("authentication required") ||
        msgLow.includes("please log in");

      if (isAuthFailure) {
        Auth.clear();
        // Show message first, redirect after short delay so user sees why
        Toast.err(msg || "Session expired — please log in again.");
        setTimeout(() => { window.location.href = "/login"; }, 1500);
        throw new Error(msg || "Session expired. Please log in again.");
      }

      // 401 but NOT a clear auth failure — show message, do NOT logout
      throw new Error(msg || "Authorisation error. Please try again.");
    }

    if (res.status === 409) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.detail || "You have already submitted a report for this entity.");
    }
    if (res.status === 422) {
      const e = await res.json().catch(() => ({}));
      const detail = e.detail;
      const msg = Array.isArray(detail)
        ? detail.map(d => d.msg || d.message || JSON.stringify(d)).join(", ")
        : (detail || "Validation error. Please check your input.");
      throw new Error(msg);
    }
    if (res.status === 429) {
      throw new Error("Too many requests. Please wait a moment before trying again.");
    }
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.detail || `Server error (${res.status}). Please try again.`);
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
      if (!res.ok) return [];   // Silently return empty — never redirect
      return res.json();
    } catch (_) {
      return [];
    }
  },
};

/* ════════════════════════════════════════════════════════════════════════════
   5. MODAL MODULE — replaced with page redirects
   Login → /login page   Register → /register page
   Session stored in localStorage is read on every page load.
════════════════════════════════════════════════════════════════════════════ */
const Modal = {
  open(tab = "login") {
    window.location.href = tab === "register" ? "/register" : "/login";
  },
  close()       { /* no-op */ },
  showErr()     { /* no-op */ },
  showOk()      { /* no-op */ },
  switchTab(tab){ window.location.href = tab === "register" ? "/register" : "/login"; },
  _currentTab: "login",
};

/* ════════════════════════════════════════════════════════════════════════════
   6. TOAST MODULE
════════════════════════════════════════════════════════════════════════════ */
const Toast = {
  _container: null,
  _get() {
    if (!this._container) this._container = document.getElementById("toast-container");
    return this._container;
  },
  show(msg, type = "info", duration = 4000) {
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
  err(msg)  { this.show(msg, "err"); },
  info(msg) { this.show(msg, "info"); },
};

/* ════════════════════════════════════════════════════════════════════════════
   7. UI MODULE — DOM updates, auth state, rendering
════════════════════════════════════════════════════════════════════════════ */
const UI = {
  updateAuthState() {
    const loggedIn = Auth.isLoggedIn();
    const email    = Auth.getEmail();

    setVis("nav-auth-btn",   !loggedIn);
    setVis("nav-user-info",   loggedIn);
    setVis("nav-logout-btn",  loggedIn);

    if (loggedIn && email) {
      setText("nav-user-email",   email);
      setText("nav-avatar-letter", email[0].toUpperCase());
    }

    const lockBar  = document.getElementById("auth-lock-notice");
    const submitBtn = document.getElementById("report-submit-btn");
    const fields    = document.querySelectorAll("#report-form input, #report-form textarea, #report-form select");

    if (lockBar)  lockBar.style.display  = loggedIn ? "none" : "flex";
    if (submitBtn) submitBtn.disabled     = !loggedIn;
    fields.forEach(f => { f.disabled = !loggedIn; });
  },

  showAlert(elOrId, msg, type = "err") {
    const el = typeof elOrId === "string" ? document.getElementById(elOrId) : elOrId;
    if (!el) return;
    el.innerHTML = `<i class="bi bi-${type === "err" ? "exclamation-triangle-fill" : "check-circle-fill"}" aria-hidden="true"></i> ${esc(msg)}`;
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
    const circumference = 2 * Math.PI * 52; // r=52
    const offset = circumference - (risk_score / 100) * circumference;
    const ringFill = document.getElementById("ring-fill");
    if (ringFill) {
      ringFill.style.strokeDashoffset = offset;
      ringFill.style.stroke = scoreColor(status);
      ringFill.style.filter = `drop-shadow(0 0 6px ${scoreColorRaw(status)})`;
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

    // Report count
    setText("res-report-count", report_count);

    // Verdict text
    const verdict = document.getElementById("res-message");
    if (verdict) {
      const msgs = {
        high_risk:   `This entity has been reported <strong>${report_count}</strong> time(s) with strong fraud signals detected. Exercise extreme caution.`,
        suspicious:  `This entity has been reported <strong>${report_count}</strong> time(s) with some suspicious indicators. Verify independently before engaging.`,
        safe:        `No significant threats detected (${report_count} report(s)). Always remain vigilant.`,
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

    // Phone intelligence card (shown only for phone type)
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

    // Show panel
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
   8. ANIMATIONS MODULE — canvas grid + scan beam + ticker
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

    // Grid dots
    const SPACING = 40, RADIUS = .8;
    let t = 0;

    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      t += .008;

      // Grid
      ctx.fillStyle = "rgba(0,212,255,.35)";
      for (let x = 0; x < W; x += SPACING) {
        for (let y = 0; y < H; y += SPACING) {
          const dist = Math.hypot(x - W / 2, y - H / 2);
          const pulse = .3 + .7 * Math.sin(t - dist * .01);
          ctx.globalAlpha = pulse * .4;
          ctx.beginPath();
          ctx.arc(x, y, RADIUS, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      // Radial gradient overlay
      const grad = ctx.createRadialGradient(W / 2, H * .4, 0, W / 2, H * .4, W * .55);
      grad.addColorStop(0, "rgba(0,212,255,.04)");
      grad.addColorStop(1, "transparent");
      ctx.globalAlpha = 1;
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, W, H);

      frame = requestAnimationFrame(draw);
    };
    draw();

    // Cleanup on page hide
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) cancelAnimationFrame(frame);
      else draw();
    });
  },

  initTicker() {
    // Duplicate ticker items for seamless loop
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
    const wrap    = document.getElementById("scan-progress-wrap");
    const bar     = document.getElementById("scan-progress-bar");
    const text    = document.getElementById("scan-progress-text");
    const pct     = document.getElementById("scan-progress-pct");
    const btn     = document.getElementById("scan-submit-btn");
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
    // Animated number increment for hero metrics
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
   9. CONTROLLERS — form submit handlers, wired via addEventListener
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
    Animations.stopScanProgress();
  }
}

/* ── Report Form ── */
async function handleReportSubmit(e) {
  e.preventDefault();
  UI.hideAlert("report-alert");
  UI.hideAlert("report-success");

  if (!Auth.isLoggedIn()) { window.location.href = "/login"; return; }

  const type        = document.getElementById("rep-type")?.value;
  const value       = document.getElementById("rep-value")?.value.trim();
  const description = document.getElementById("rep-description")?.value.trim();
  const tagsRaw     = document.getElementById("rep-tags")?.value;
  const tags        = tagsRaw ? tagsRaw.split(",").map(t => t.trim()).filter(Boolean) : [];

  if (!value || !description) { UI.showAlert("report-alert", "Value and description are required."); return; }
  if (description.length < 10) { UI.showAlert("report-alert", "Description must be at least 10 characters."); return; }

  UI.setSpinner("report-spinner", true);
  try {
    await API.report({ type, value, description, tags });
    document.getElementById("rep-description").value = "";
    document.getElementById("rep-tags").value = "";
    UI.showAlert("report-success", "Report submitted — thank you for protecting the community!", "ok");
    document.getElementById("report-success")?.scrollIntoView({ behavior: "smooth" });
    Toast.ok("Intelligence report submitted!");
    await loadEntities();
  } catch (err) {
    UI.showAlert("report-alert", err.message);
    Toast.err(err.message);
  } finally {
    UI.setSpinner("report-spinner", false);
  }
}

/* ── Login Form ── */
async function handleLogin() {
  const email    = document.getElementById("login-email")?.value.trim();
  const password = document.getElementById("login-password")?.value;
  if (!email) { Modal.showErr("Please enter your email address."); return; }
  if (!password) { Modal.showErr("Please enter your password."); return; }
  if (!email.includes("@")) { Modal.showErr("Please enter a valid email address."); return; }

  const btn = document.getElementById("login-submit-btn");
  if (btn) { btn.disabled = true; btn.style.opacity = ".6"; }
  UI.setSpinner("login-spinner", true);
  Modal.clearAlerts();

  try {
    await Auth.login(email, password);
    Modal.close();
    Toast.ok(`Welcome back, ${Auth.getEmail()}!`);
  } catch (err) {
    Modal.showErr(err.message);
  } finally {
    UI.setSpinner("login-spinner", false);
    if (btn) { btn.disabled = false; btn.style.opacity = ""; }
  }
}

/* ── Register Form ── */
async function handleRegister() {
  const email    = document.getElementById("reg-email")?.value.trim();
  const password = document.getElementById("reg-password")?.value;
  if (!email) { Modal.showErr("Please enter your email address."); return; }
  if (!email.includes("@")) { Modal.showErr("Please enter a valid email address."); return; }
  if (!password) { Modal.showErr("Please enter a password."); return; }
  if (password.length < 6) { Modal.showErr("Password must be at least 6 characters."); return; }

  const btn = document.getElementById("register-submit-btn");
  if (btn) { btn.disabled = true; btn.style.opacity = ".6"; }
  UI.setSpinner("register-spinner", true);
  Modal.clearAlerts();

  try {
    const data = await Auth.register(email, password);
    Modal.showOk(data.message || "Account created! Check your email inbox to confirm, then log in.");
    Toast.ok("Account created — check your email!");
    // Clear fields after success
    const emailEl = document.getElementById("reg-email");
    const pwEl    = document.getElementById("reg-password");
    if (emailEl) emailEl.value = "";
    if (pwEl)    pwEl.value    = "";
  } catch (err) {
    Modal.showErr(err.message);
  } finally {
    UI.setSpinner("register-spinner", false);
    if (btn) { btn.disabled = false; btn.style.opacity = ""; }
  }
}

/* ── Load Entities ── */
async function renderPhoneIntel(number, container) {
  // Show skeleton while loading
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
  if (!data) {
    container.style.display = "none";
    return;
  }

  const typeIcon = { mobile: "📱", fixed: "☎️", voip: "💻", unknown: "📞" };
  const typeLabel = { mobile: "Mobile", fixed: "Fixed Line", voip: "VOIP/Virtual", unknown: "Unknown" };
  const icon = typeIcon[data.number_type] || "📞";

  const riskBadge = data.risk_indicators.length > 0
    ? `<span class="phone-risk-badge high">⚠ ${data.risk_indicators.length} Risk Indicator${data.risk_indicators.length > 1 ? "s" : ""}</span>`
    : `<span class="phone-risk-badge safe">✓ No Risk Flags</span>`;

  const indicators = data.risk_indicators.length
    ? `<div class="phone-indicators">
        ${data.risk_indicators.map(i => `<div class="phone-indicator-item">⚠ ${esc(i)}</div>`).join("")}
      </div>` : "";

  const categories = data.top_scam_categories.length
    ? `<div class="phone-tags">${data.top_scam_categories.map(t =>
        `<span class="phone-tag">${esc(t)}</span>`).join("")}</div>` : "";

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
          <div class="phone-detail-item">
            <div class="phone-detail-label">Country</div>
            <div class="phone-detail-value">${esc(data.country)}</div>
          </div>
          <div class="phone-detail-item">
            <div class="phone-detail-label">Carrier</div>
            <div class="phone-detail-value">${esc(data.carrier)}</div>
          </div>
          <div class="phone-detail-item">
            <div class="phone-detail-label">Number Type</div>
            <div class="phone-detail-value">${typeLabel[data.number_type] || esc(data.number_type)}</div>
          </div>
          <div class="phone-detail-item">
            <div class="phone-detail-label">Format (Local)</div>
            <div class="phone-detail-value">${esc(data.local_format || data.normalized)}</div>
          </div>
          <div class="phone-detail-item">
            <div class="phone-detail-label">Reports (Total)</div>
            <div class="phone-detail-value">${data.report_count}</div>
          </div>
          <div class="phone-detail-item">
            <div class="phone-detail-label">Reports (30 days)</div>
            <div class="phone-detail-value">${data.recent_report_count}</div>
          </div>
        </div>
        ${indicators}
        ${categories ? `<div class="phone-categories-label">Reported Scam Categories</div>${categories}` : ""}
        ${lastActivity || firstSeen ? `<div class="phone-meta">${firstSeen}${lastActivity}</div>` : ""}
        <div class="phone-summary">${esc(data.intel_summary)}</div>
        <div class="phone-disclaimer">
          ℹ Data based on number structure and community reports. Always verify independently.
        </div>
      </div>
    </div>`;
}

async function loadEntities() {
  const errEl = document.getElementById("recent-error");
  // Guard: only run if the table exists on this page
  if (!document.getElementById("recent-tbody")) return;
  try {
    const list = await API.entities(10);
    UI.renderEntities(list);
  } catch (err) {
    console.warn("[ScamGuard] Entity load skipped:", err.message);
    // Show friendly error but do NOT redirect or retry-loop
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
   10. UTILITIES
════════════════════════════════════════════════════════════════════════════ */
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function setText(id, val)   { const el = document.getElementById(id); if (el) el.textContent = val; }
function setVis(id, show)   { const el = document.getElementById(id); if (el) el.classList.toggle("d-none", !show); }
function sleep(ms)          { return new Promise(r => setTimeout(r, ms)); }

function statusLabel(s)     { return s === "high_risk" ? "HIGH RISK" : s === "suspicious" ? "SUSPICIOUS" : "SAFE"; }
function statusIcon(s)      { return s === "high_risk" ? "bi-exclamation-octagon-fill" : s === "suspicious" ? "bi-exclamation-triangle-fill" : "bi-shield-check"; }
function statusFromScore(s) { return s >= 60 ? "high_risk" : s >= 30 ? "suspicious" : "safe"; }
function scoreColorRaw(s)   { return s === "high_risk" ? "#f43f5e" : s === "suspicious" ? "#fbbf24" : "#10d994"; }
function scoreColor(s)      { return `var(--${s === "high_risk" ? "red" : s === "suspicious" ? "amber" : "green"})`; }
function fmtDate(iso) {
  try { return new Date(iso).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return iso; }
}

/* ════════════════════════════════════════════════════════════════════════════
   11. EVENT WIRING — all via addEventListener, no inline onclick
════════════════════════════════════════════════════════════════════════════ */
function wireEvents() {
  // Check form
  document.getElementById("check-form")?.addEventListener("submit", handleCheckSubmit);

  // Report form
  document.getElementById("report-form")?.addEventListener("submit", handleReportSubmit);

  // Auth buttons (no inline onclick)
  // nav-auth-btn is an <a href="/login"> — no JS needed
  document.getElementById("nav-logout-btn")?.addEventListener("click", () => { Auth.clear(); Toast.info("Logged out."); });
  document.getElementById("lock-login-btn")?.addEventListener("click", () => window.location.href = "/login");

  // Auth is on separate pages (/login, /register) — no modal wiring needed here

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
    const inputId = btn.getAttribute("data-pw-toggle");
    const input   = document.getElementById(inputId);
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
   12. INIT
════════════════════════════════════════════════════════════════════════════ */
document.addEventListener("DOMContentLoaded", () => {
  wireEvents();
  UI.updateAuthState();
  Animations.initCanvas();
  Animations.initTicker();
  Animations.initMetricsCounter();
  loadEntities();
  // Note: no modal tab init needed — auth uses separate pages
});

})(); // end IIFE
