// /app/dashboard.js
import { session, logout } from "/app/auth.js";

const $ = (s)=>document.querySelector(s);
const statusEl = $("#status");
const sessionBadge = $("#sessionBadge");
const out = $("#out");

function toast(msg, kind="info") {
  statusEl.innerHTML = `<div class="toast ${kind}">${msg}</div>`;
  setTimeout(()=>{ statusEl.innerHTML=""; }, 3200);
}

async function ensureSessionOrRedirect() {
  const u = await session();
  if (!u) {
    window.location.href = "/app/index.html";
    return null;
  }
  sessionBadge.textContent = u.email;
  sessionBadge.className = "badge ok";
  return u;
}

async function fetchRestricted() {
  try {
    const r = await fetch("/api/restricted_field", { method: "GET" });
    if (!r.ok) {
      const txt = await r.text();
      throw new Error(`${r.status} ${r.statusText}: ${txt}`);
    }
    const j = await r.json();
    out.textContent = JSON.stringify(j, null, 2);
    toast("Fetched restricted field","ok");
  } catch (e) {
    out.textContent = (e && e.message) ? e.message : String(e);
    toast("Access denied or not logged in","error");
  }
}

$("#btn-fetch")?.addEventListener("click", fetchRestricted);

$("#btn-logout")?.addEventListener("click", async ()=>{
  try {
    await logout();
    toast("Signed out","ok");
    sessionBadge.textContent = "guest";
    sessionBadge.className = "badge";
    // Try fetching again after logout — should fail
    await fetchRestricted();
  } catch (e) {
    toast(e.message || String(e), "error");
  }
});

// Init
await ensureSessionOrRedirect();
