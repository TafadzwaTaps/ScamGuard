/**
 * ScamGuard — Auth Pages Shared JS
 * Used by both login.html and register.html.
 * Zero dependencies. Pure vanilla JS.
 */
"use strict";

// Alert CSS classes used: auth-alert-err  auth-alert-ok
/* ── Storage (localStorage with in-memory fallback) ──────────────────────── */
const Store = (() => {
  const mem = {};
  let ok = false;
  try { localStorage.setItem("__t__","1"); localStorage.removeItem("__t__"); ok = true; } catch(_) {}
  return {
    get: k    => ok ? localStorage.getItem(k)    : (mem[k] ?? null),
    set: (k,v)=> ok ? localStorage.setItem(k, v) : (mem[k] = String(v)),
    del: k    => ok ? localStorage.removeItem(k)  : (delete mem[k]),
  };
})();

/* ── API base ────────────────────────────────────────────────────────────── */
const API_BASE = window.API_BASE || "";

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function esc(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function showAlert(el, msg, type = "err") {
  if (!el) return;
  el.className = `auth-alert auth-alert-${type === "err" ? "err" : "ok"} visible`;
  const icon = type === "err"
    ? `<svg viewBox="0 0 20 20"><path d="M10 18a8 8 0 100-16 8 8 0 000 16zm0-9v4m0-6h.01"/></svg>`
    : `<svg viewBox="0 0 20 20"><path d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293l-4 4a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L9 10.586l3.293-3.293a1 1 0 011.414 1.414z"/></svg>`;
  el.innerHTML = `${icon}<span>${esc(msg)}</span>`;
  el.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function hideAlert(el) {
  if (!el) return;
  el.className = "auth-alert";
  el.innerHTML = "";
}

function setLoading(btn, active) {
  if (!btn) return;
  btn.classList.toggle("loading", active);
  btn.disabled = active;
}

/* ── Password toggle ─────────────────────────────────────────────────────── */
document.addEventListener("click", e => {
  const btn = e.target.closest(".pw-toggle");
  if (!btn) return;
  const input = document.getElementById(btn.dataset.for);
  if (!input) return;
  const isHidden = input.type === "password";
  input.type = isHidden ? "text" : "password";
  btn.innerHTML = isHidden
    ? `<svg viewBox="0 0 20 20"><path d="M13.359 11.238C15.06 9.72 16 8 16 8s-3-5.5-6-5.5a7 7 0 00-2.79.588l.77.771A5.944 5.944 0 0110 3.5c2.12 0 4.178 1.956 5.34 3.5a13.055 13.055 0 01-.786 1.027zM10 5.5A4.5 4.5 0 005.5 10c0 .68.13 1.33.36 1.93L7.5 10.29A2.5 2.5 0 0110 7.5c.28 0 .55.05.8.14l1.64-1.64A4.478 4.478 0 0010 5.5zM2 4.27l1.36 1.36.26.26A11.68 11.68 0 001 8s3 5.5 6 5.5a6.92 6.92 0 003.2-.78l.3.3L12.73 15 14 13.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65a2.5 2.5 0 002.5 2.5c.22 0 .44-.03.65-.08l1.55 1.55A4.492 4.492 0 0110 14.5C7.88 14.5 5.82 12.544 4.66 11a13.22 13.22 0 012.87-1.2z"/></svg>`
    : `<svg viewBox="0 0 20 20"><path d="M10 3.5C7 3.5 4 8 4 8s3 4.5 6 4.5S16 8 16 8s-3-4.5-6-4.5zM10 11a3 3 0 110-6 3 3 0 010 6z"/></svg>`;
  input.focus();
});

/* ── Login handler ───────────────────────────────────────────────────────── */
async function handleLogin(email, password, btn, alertEl) {
  hideAlert(alertEl);

  if (!email || !email.includes("@")) {
    showAlert(alertEl, "Please enter a valid email address."); return;
  }
  if (!password) {
    showAlert(alertEl, "Please enter your password."); return;
  }

  setLoading(btn, true);

  try {
    const res  = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
    });
    const data = await res.json();

    if (!res.ok) {
      showAlert(alertEl, data.detail || "Login failed. Please try again.");
      return;
    }

    // Store session
    Store.set("sg_token", data.access_token);
    Store.set("sg_email", data.email);

    // Redirect to where user came from, or home
    let dest = "/";
    try {
      const stored = sessionStorage.getItem("sg_after_login");
      if (stored) { sessionStorage.removeItem("sg_after_login"); dest = stored; }
    } catch(_) {}
    window.location.href = dest;

  } catch (_) {
    showAlert(alertEl, "Network error — please check your connection and try again.");
  } finally {
    setLoading(btn, false);
  }
}

/* ── Register handler ────────────────────────────────────────────────────── */
async function handleRegister(email, password, btn, alertEl) {
  hideAlert(alertEl);

  if (!email || !email.includes("@")) {
    showAlert(alertEl, "Please enter a valid email address."); return;
  }
  if (!password || password.length < 6) {
    showAlert(alertEl, "Password must be at least 6 characters."); return;
  }

  setLoading(btn, true);

  try {
    const res  = await fetch(`${API_BASE}/api/v1/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
    });
    const data = await res.json();

    if (!res.ok) {
      showAlert(alertEl, data.detail || "Registration failed. Please try again.");
      return;
    }

    // Redirect to /confirm which shows the "check your email" instructions
    // Store the email so the confirm page can personalise the message
    try { sessionStorage.setItem("sg_pending_email", email); } catch(_) {}
    window.location.href = "/confirm";

  } catch (_) {
    showAlert(alertEl, "Network error — please check your connection and try again.");
  } finally {
    setLoading(btn, false);
  }
}
