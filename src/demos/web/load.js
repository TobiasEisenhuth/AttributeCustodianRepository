// /app/load.js
import { session, setStage, logout } from "/app/auth.js";

// Minimal unlock using same format as sender.js: "ACSE" + ver(1) + salt(16) + nonce(12) + ct
const MAGIC = new Uint8Array([0x41,0x43,0x53,0x45]); // "ACSE"
const VER = 1;

const $ = (s)=>document.querySelector(s);
const statusEl = $("#status");
const outEl = $("#out");
const sessionBadge = $("#sessionBadge");

function toast(msg, kind="info") {
  statusEl.innerHTML = `<div class="toast ${kind}">${msg}</div>`;
  setTimeout(()=>{ statusEl.innerHTML=""; }, 3200);
}

(async ()=> {
  try {
    const u = await session();
    sessionBadge.textContent = u.email;
    sessionBadge.className = "badge ok";
  } catch {
    // If no session, server middleware will already block this page, but be safe:
    window.location.href="/app/index.html";
    return;
  }
})();

async function scryptKey(pass, salt) {
  const { scrypt } = await import("https://esm.sh/scrypt-js@3.0.1");
  const pw = new TextEncoder().encode(pass);
  const dk = await scrypt(pw, salt, 1<<14, 8, 1, 32);
  return new Uint8Array(dk);
}
async function aesGcmDecrypt(keyBytes, nonce, ciphertext) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt  = await crypto.subtle.decrypt({ name:"AES-GCM", iv: nonce }, key, ciphertext);
  return new Uint8Array(pt);
}

function parseStore(bytes) {
  if (bytes.length < (4+1+16+12+1)) throw new Error("Store too short");
  if (bytes[0]!==MAGIC[0]||bytes[1]!==MAGIC[1]||bytes[2]!==MAGIC[2]||bytes[3]!==MAGIC[3]) throw new Error("Wrong magic (ACSE)");
  if (bytes[4] !== VER) throw new Error("Wrong version");
  const salt  = bytes.slice(5,21);
  const nonce = bytes.slice(21,33);
  const ct    = bytes.slice(33);
  return { salt, nonce, ct };
}

async function getStorePassword() {
  const r = await fetch("/api/store_password");
  if (!r.ok) throw new Error("Failed to fetch store password");
  const j = await r.json();
  return j.password;
}

$("#btn-load")?.addEventListener("click", async ()=>{
  outEl.textContent = "";
  const file = $("#fileIn").files?.[0];
  if (!file) { toast("Select a file first","error"); return; }
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const { salt, nonce, ct } = parseStore(bytes);
    const pass = await getStorePassword();
    const key  = await scryptKey(pass, salt);
    await aesGcmDecrypt(key, nonce, ct); // if it throws, password/file mismatch
    await setStage("store_ok");
    toast("Store unlocked. Redirecting…","ok");
    window.location.href = "/app/dashboard.html";
  } catch (e) {
    outEl.textContent = "Unlock failed: " + (e.message || String(e));
    toast("Unlock failed","error");
  }
});

$("#btn-return")?.addEventListener("click", async ()=>{
  try { await logout(); } catch {}
  window.location.href = "/app/index.html";
});
