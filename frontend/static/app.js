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

  function isLoggedIn() { return !!token; }
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

  return { isLoggedIn, getToken, getEmail, save, clear, login, register };
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
    const res = await this.post("/api/v1/check", { type, value });
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.detail || `Error ${res.status}`); }
    return res.json();
  },
  async report(payload) {
    const res = await this.post("/api/v1/report", payload);
    if (res.status === 401) { Auth.clear(); Modal.open("login"); throw new Error("Session expired. Please log in again."); }
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.detail || `Error ${res.status}`); }
    return res.json();
  },
  async entities(limit = 10) {
    const res = await fetch(`${API_BASE}/api/v1/entities?limit=${limit}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },
};

/* ════════════════════════════════════════════════════════════════════════════
   5. MODAL MODULE — Bootstrap 5 wrapper, no duplicate instances, keyboard safe
════════════════════════════════════════════════════════════════════════════ */
const Modal = (() => {
  let _instance = null;

  function _getInstance() {
    if (_instance) return _instance;
    const el = document.getElementById("authModal");
    if (!el) return null;
    // bootstrap-modal.js is loaded synchronously before app.js,
    // so bootstrap is always defined here. Guard kept for safety.
    if (typeof bootstrap === "undefined" || !bootstrap.Modal) {
      console.error("[ScamGuard] bootstrap.Modal not found — bootstrap-modal.js may not have loaded.");
      // Manual fallback so UI still works
      return {
        show() {
          el.style.display = "flex";
          el.style.alignItems = "center";
          el.style.justifyContent = "center";
          el.style.position = "fixed";
          el.style.inset = "0";
          el.style.zIndex = "9999";
          el.style.background = "rgba(0,0,0,.7)";
          el.classList.add("show");
          el.removeAttribute("aria-hidden");
          document.body.style.overflow = "hidden";
        },
        hide() {
          el.style.display = "none";
          el.classList.remove("show");
          el.setAttribute("aria-hidden", "true");
          document.body.style.overflow = "";
        },
      };
    }
    // Prevent duplicate instances — use getOrCreateInstance
    _instance = bootstrap.Modal.getOrCreateInstance(el);
    return _instance;
  }

  function open(tab = "login") {
    Modal.clearAlerts();
    Modal.switchTab(tab);
    const m = _getInstance();
    if (m) m.show();
  }

  function close() {
    const m = _getInstance();
    if (m) m.hide();
  }

  function switchTab(tab) {
    const loginWrap = document.getElementById("login-form-wrap");
    const regWrap   = document.getElementById("register-form-wrap");
    const tabLogin  = document.getElementById("tab-login");
    const tabReg    = document.getElementById("tab-register");
    const slider    = document.getElementById("tab-slider");

    if (!loginWrap || !regWrap) return;
    const isLogin = tab === "login";
    loginWrap.classList.toggle("d-none", !isLogin);
    regWrap.classList.toggle("d-none",    isLogin);
    tabLogin.classList.toggle("active",   isLogin);
    tabReg.classList.toggle("active",    !isLogin);
    tabLogin.setAttribute("aria-selected",  String(isLogin));
    tabReg.setAttribute("aria-selected",   String(!isLogin));

    // Animate slider
    if (slider) {
      const activeBtn = isLogin ? tabLogin : tabReg;
      slider.style.left  = activeBtn.offsetLeft + "px";
      slider.style.width = activeBtn.offsetWidth + "px";
    }
    Modal.clearAlerts();
  }

  function clearAlerts() {
    ["auth-modal-alert", "auth-modal-success"].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.textContent = ""; el.classList.remove("visible"); }
    });
  }

  function showErr(msg) {
    const el = document.getElementById("auth-modal-alert");
    if (el) { el.innerHTML = `<i class="bi bi-exclamation-triangle-fill"></i> ${esc(msg)}`; el.classList.add("visible"); }
  }

  function showOk(msg) {
    const el = document.getElementById("auth-modal-success");
    if (el) { el.innerHTML = `<i class="bi bi-check-circle-fill"></i> ${esc(msg)}`; el.classList.add("visible"); }
  }

  return { open, close, switchTab, clearAlerts, showErr, showOk };
})();

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

  if (!Auth.isLoggedIn()) { Modal.open("login"); return; }

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
  if (!email || !password) { Modal.showErr("Email and password are required."); return; }
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
  }
}

/* ── Register Form ── */
async function handleRegister() {
  const email    = document.getElementById("reg-email")?.value.trim();
  const password = document.getElementById("reg-password")?.value;
  if (!email || !password) { Modal.showErr("Email and password are required."); return; }
  if (password.length < 6)  { Modal.showErr("Password must be at least 6 characters."); return; }
  UI.setSpinner("register-spinner", true);
  Modal.clearAlerts();
  try {
    const data = await Auth.register(email, password);
    Modal.showOk(data.message || "Account created! Check your email to confirm.");
    Toast.ok("Account created successfully!");
  } catch (err) {
    Modal.showErr(err.message);
  } finally {
    UI.setSpinner("register-spinner", false);
  }
}

/* ── Load Entities ── */
async function loadEntities() {
  const errEl = document.getElementById("recent-error");
  UI.hideAlert("recent-error");
  try {
    const list = await API.entities(10);
    UI.renderEntities(list);
  } catch (err) {
    console.error("[ScamGuard] Entity load error:", err);
    if (errEl) UI.showAlert("recent-error", "Could not load threat intelligence feed.");
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
  document.getElementById("nav-auth-btn")?.addEventListener("click", () => Modal.open("login"));
  document.getElementById("nav-logout-btn")?.addEventListener("click", () => { Auth.clear(); Toast.info("Logged out."); });
  document.getElementById("lock-login-btn")?.addEventListener("click", () => Modal.open("login"));

  // Modal tab buttons
  document.getElementById("tab-login")?.addEventListener("click",    () => Modal.switchTab("login"));
  document.getElementById("tab-register")?.addEventListener("click", () => Modal.switchTab("register"));

  // Modal submit buttons
  document.getElementById("login-submit-btn")?.addEventListener("click",    handleLogin);
  document.getElementById("register-submit-btn")?.addEventListener("click", handleRegister);

  // Allow Enter key in password fields
  document.getElementById("login-password")?.addEventListener("keydown",  e => { if (e.key === "Enter") handleLogin(); });
  document.getElementById("reg-password")?.addEventListener("keydown",    e => { if (e.key === "Enter") handleRegister(); });

  // Tab switcher links inside modal (data-switch-tab attribute)
  document.addEventListener("click", e => {
    const sw = e.target.closest("[data-switch-tab]");
    if (sw) Modal.switchTab(sw.dataset.switchTab);
    const tab = e.target.closest("[data-tab]");
    if (tab && tab.id.startsWith("tab-")) Modal.switchTab(tab.dataset.tab);
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

  // Bootstrap modal: init slider after shown
  const authModal = document.getElementById("authModal");
  if (authModal) {
    authModal.addEventListener("shown.bs.modal", () => Modal.switchTab("login"));
    // Manual modal close (fallback)
    authModal.addEventListener("click", e => {
      if (e.target === authModal) Modal.close();
    });
  }

  // Keyboard: Escape closes manual modal
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") {
      const authModal = document.getElementById("authModal");
      if (authModal?.classList.contains("manual-show")) Modal.close();
    }
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

  // Init tab slider position after fonts load
  requestAnimationFrame(() => Modal.switchTab("login"));
});

})(); // end IIFE
