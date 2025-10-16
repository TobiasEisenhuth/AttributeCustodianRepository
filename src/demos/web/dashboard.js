// /app/dashboard.js
import { session, logout } from "/app/auth.js";

const $ = (s)=>document.querySelector(s);
const statusEl = $("#status");
const outEl = $("#out");
const sessionBadge = $("#sessionBadge");

function toast(msg, kind="info") {
  statusEl.innerHTML = `<div class="toast ${kind}">${msg}</div>`;
  setTimeout(()=>{ statusEl.innerHTML=""; }, 3200);
}

(async ()=>{
  try {
    const u = await session();
    sessionBadge.textContent = u.email;
    sessionBadge.className = "badge ok";
  } catch {
    window.location.href = "/app/index.html";
    return;
  }
})();

$("#btn-fetch")?.addEventListener("click", async ()=>{
  outEl.textContent = "";
  try {
    const r = await fetch("/api/restricted_field");
    if (!r.ok) throw new Error(await r.text());
    outEl.textContent = JSON.stringify(await r.json(), null, 2);
  } catch (e) {
    outEl.textContent = "Error: " + (e.message || String(e));
  }
});

$("#btn-logout")?.addEventListener("click", async ()=>{
  try { await logout(); } catch {}
  window.location.href = "/app/index.html";
});
