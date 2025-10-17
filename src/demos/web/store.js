// /app/store.js
import { session, setStage, logout } from "/app/auth.js";

// Bytes helpers
const te = new TextEncoder();
const td = new TextDecoder();
const b64e = (u8) => btoa(String.fromCharCode(...u8));
const b64d = (s)  => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// "ACSE" container: [MAGIC(4),VER(1),SALT(16),NONCE(12),CT(..)]
const MAGIC = new Uint8Array([0x41,0x43,0x53,0x45]);
const VER = 1;

const $ = (s)=>document.querySelector(s);
const statusEl = $("#status");
function toast(msg, kind="info") {
  statusEl.innerHTML = `<div class="toast ${kind}">${msg}</div>`;
  setTimeout(()=>{ statusEl.innerHTML=""; }, 3200);
}

async function scryptKey(pass, salt) {
  const { scrypt } = await import("https://esm.sh/scrypt-js@3.0.1");
  const pw = te.encode(pass);
  const dk = await scrypt(pw, salt, 1<<14, 8, 1, 32);
  return new Uint8Array(dk);
}
async function aesGcmEncrypt(keyBytes, nonce, plaintext) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ct  = await crypto.subtle.encrypt({ name:"AES-GCM", iv: nonce }, key, plaintext);
  return new Uint8Array(ct);
}
async function aesGcmDecrypt(keyBytes, nonce, ciphertext) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt  = await crypto.subtle.decrypt({ name:"AES-GCM", iv: nonce }, key, ciphertext);
  return new Uint8Array(pt);
}
function parseACSE(bytes){
  if (bytes.length < (4+1+16+12+1)) throw new Error("Blob too short");
  if (bytes[0]!==MAGIC[0]||bytes[1]!==MAGIC[1]||bytes[2]!==MAGIC[2]||bytes[3]!==MAGIC[3]) throw new Error("Bad magic");
  if (bytes[4] !== VER) throw new Error("Bad version");
  const salt  = bytes.slice(5,21);
  const nonce = bytes.slice(21,33);
  const ct    = bytes.slice(33);
  return { salt, nonce, ct };
}
function wrapACSE(salt, nonce, ct){
  const out = new Uint8Array(4+1+16+12+ct.length);
  out.set(MAGIC,0); out[4]=VER; out.set(salt,5); out.set(nonce,21); out.set(ct,33);
  return out;
}

async function getEncryptedStore() {
  const r = await fetch("/api/user_store");
  if (!r.ok) throw new Error("Store query failed");
  return r.json();
}
async function putEncryptedStore(bytes){
  const blob_b64 = b64e(bytes);
  const r = await fetch("/api/user_store", {
    method:"POST", headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ blob_b64 })
  });
  if(!r.ok){ throw new Error(await r.text()); }
}

(async ()=>{
  // must be logged in (middleware already enforces)
  await session().catch(()=>{ window.location.href="/app/index.html"; });

  const existsCard = $("#card-exists");
  const newCard    = $("#card-new");

  try {
    const j = await getEncryptedStore();
    if (j.exists) {
      existsCard.style.display = "";
      newCard.style.display = "none";

      $("#btn-unlock")?.addEventListener("click", async ()=>{
        $("#out-exist").textContent = "";
        const pw = ($("#pw-exist").value||"").toString();
        if (!pw) { toast("Enter your store password","error"); return; }
        try{
          const blob = b64d(j.blob_b64);
          const { salt, nonce, ct } = parseACSE(blob);
          const key  = await scryptKey(pw, salt);
          const pt   = await aesGcmDecrypt(key, nonce, ct); // throws if wrong pw
          // keep plaintext only in sessionStorage during the session
          sessionStorage.setItem("crs_store_plain", b64e(pt));
          sessionStorage.setItem("crs_store_password", pw);
          await setStage("store_ok");
          window.location.href = "/app/dashboard.html";
        }catch(e){
          $("#out-exist").textContent = "Unlock failed: " + (e.message||String(e));
          toast("Unlock failed","error");
        }
      });

      $("#btn-logout")?.addEventListener("click", async ()=>{
        sessionStorage.removeItem("crs_store_plain");
        sessionStorage.removeItem("crs_store_password");
        await logout().catch(()=>{});
        window.location.href="/app/index.html";
      });

    } else {
      // create a new empty store
      existsCard.style.display = "none";
      newCard.style.display = "";

      $("#btn-create")?.addEventListener("click", async ()=>{
        $("#out-new").textContent = "";
        const p1 = ($("#pw1").value||"").toString();
        const p2 = ($("#pw2").value||"").toString();
        if (!p1 || p1.length<10) { toast("Password too short (min 10)","error"); return; }
        if (p1 !== p2) { toast("Passwords do not match","error"); return; }
        try{
          // empty msgpack map as plaintext
          const { encode: msgpackEncode } = await import("https://esm.sh/@msgpack/msgpack@3.0.0");
          const pt = msgpackEncode({});
          const salt  = crypto.getRandomValues(new Uint8Array(16));
          const nonce = crypto.getRandomValues(new Uint8Array(12));
          const key   = await scryptKey(p1, salt);
          const ct    = await aesGcmEncrypt(key, nonce, pt);
          const acse  = wrapACSE(salt, nonce, ct);
          await putEncryptedStore(acse);
          sessionStorage.setItem("crs_store_plain", b64e(new Uint8Array(pt)));
          sessionStorage.setItem("crs_store_password", p1);
          await setStage("store_ok");
          window.location.href="/app/dashboard.html";
        }catch(e){
          $("#out-new").textContent = "Create failed: " + (e.message||String(e));
          toast("Create failed","error");
        }
      });

      $("#btn-logout2")?.addEventListener("click", async ()=>{
        sessionStorage.removeItem("crs_store_plain");
        sessionStorage.removeItem("crs_store_password");
        await logout().catch(()=>{});
        window.location.href="/app/index.html";
      });
    }
  } catch (e) {
    toast("Error loading store: "+(e.message||String(e)), "error");
  }
})();
