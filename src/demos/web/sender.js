// CRS Sender Web — using self-hosted Umbral WASM (API per your umbral_pre_wasm.js)

(() => {
  // Firefox < 128 polyfill for FinalizationRegistry-related symbols occasionally referenced
  try {
    if (typeof Symbol.dispose === "undefined") Object.defineProperty(Symbol, "dispose", { value: Symbol("Symbol.dispose") });
    if (typeof Symbol.asyncDispose === "undefined") Object.defineProperty(Symbol, "asyncDispose", { value: Symbol("Symbol.asyncDispose") });
  } catch { /* ignore */ }
})();

(async () => {
  // ===== Load self-hosted WASM pack exactly like your working smoke test
  const Umbral = await import("/app/umbral/umbral_pre_wasm.js");
  await Umbral.default(new URL("/app/umbral/umbral_pre_wasm_bg.wasm", window.location.href));

  // Shorthands (from your wasm exports)
  const {
    SecretKey, PublicKey, Signer,
    Capsule, CapsuleFrag,
    encrypt, reencrypt, generateKFrags,
  } = Umbral;

  // ======= DOM =======
  const $  = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));
  const statusEl = $("#status");

  const senderIdDefault = $("#senderIdDefault");
  const healthBadge = $("#healthBadge");
  const storeBadge  = $("#storeBadge");

  const formAdd    = $("#form-add"),    addOut = $("#add-output"), btnListSecrets=$("#btn-list-secrets");
  const formDelete = $("#form-delete"), delOut = $("#delete-output");
  const formReq    = $("#form-requests"), reqList=$("#requests-list");
  const formRevoke = $("#form-revoke"),  revokeOut=$("#revoke-output");
  const formGrants = $("#form-grants"),  grantsOut=$("#grants-output");

  const storeOut = $("#store-output");
  const btnOpenFS  = $("#btnOpenFS");
  const btnResaveFS= $("#btnResaveFS");
  const btnCloseFS = $("#btnCloseFS");
  const passFS     = $("#storePassFS");

  const btnImport  = $("#btnImport");
  const btnExport  = $("#btnExport");
  const passIn     = $("#storePassIn");
  const fileIn     = $("#storeFileIn");

  function toast(msg, kind="info") {
    statusEl.innerHTML = `<div class="toast ${kind}">${escapeHtml(msg)}</div>`;
    setTimeout(()=>{ statusEl.innerHTML=""; }, 3200);
  }
  function escapeHtml(s){return (s||"").replace(/[&<>"']/g,c=>({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
  function showView(name){ $$(".view").forEach(v=>v.classList.add("hidden")); $("#view-"+name)?.classList.remove("hidden"); }
  $$(".nav-btn").forEach(btn => btn.addEventListener("click", ()=>showView(btn.dataset.view)));
  showView("add");

  // Health
  try { const r=await fetch("/health"); const j=await r.json();
    healthBadge.textContent = j.ok ? "healthy" : "unhealthy";
    healthBadge.className = "badge " + (j.ok ? "ok":"bad");
  } catch { healthBadge.textContent="unreachable"; healthBadge.className="badge bad"; }

  // ======= API =======
  async function apiPost(path, payload){
    const url = path.startsWith("/api") ? path : "/api"+path;
    const r = await fetch(url, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify(payload) });
    if(!r.ok) throw new Error(`${r.status} ${r.statusText} — ${await r.text()}`);
    return r.json();
  }

  // ======= utils =======
  const te = new TextEncoder(); const td = new TextDecoder();
  const b64e = (u8) => btoa(String.fromCharCode(...u8));
  const b64d = (s)  => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  const prefs = {
    get senderId(){ return localStorage.getItem("senderIdDefault") || ""; },
    set senderId(v){ localStorage.setItem("senderIdDefault", v||""); },
  };
  senderIdDefault.value = prefs.senderId;
  senderIdDefault.addEventListener("input", () => prefs.senderId = senderIdDefault.value.trim());

  // ======= Encrypted store (same format as Python: magic "ACSE", ver=1, scrypt + AES-GCM) =======
  const MAGIC = new Uint8Array([0x41,0x43,0x53,0x45]); // "ACSE"
  const VER = 1;

  // scrypt-js via CDN
  const { scrypt } = await import("https://esm.sh/scrypt-js@3.0.1");
  const { encode: msgpackEncode, decode: msgpackDecode } = await import("https://esm.sh/@msgpack/msgpack@3.0.0");

  async function scryptKey(pass, salt) {
    const pw = new TextEncoder().encode(pass);
    const dk = await scrypt(pw, salt, 1<<14, 8, 1, 32); // n=2**14, r=8, p=1, dk=32
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

  let senderStore = {};  // secret_id -> { secret_key, public_key, signing_key, verifying_key } (all Uint8Array)
  let storePassword = "";
  let storeHandle = null;
  let storeFilename = "";

  function setStoreBadge() {
    if (storeHandle) { storeBadge.textContent = `opened: ${storeFilename||"store.msgpack"}`; storeBadge.className="badge ok"; }
    else if (Object.keys(senderStore).length>0) { storeBadge.textContent = "loaded (memory only)"; storeBadge.className="badge ok"; }
    else { storeBadge.textContent = "no store"; storeBadge.className="badge"; }
  }
  setStoreBadge();

  function serializeStoreForDisk() {
    const obj = {};
    for (const [sid, rec] of Object.entries(senderStore)) {
      obj[sid] = {
        secret_key:    rec.secret_key,     // SecretKey.toBEBytes()
        public_key:    rec.public_key,     // PublicKey.toCompressedBytes()
        signing_key:   rec.signing_key,    // SecretKey.toBEBytes()
        verifying_key: rec.verifying_key,  // PublicKey.toCompressedBytes()
      };
    }
    return msgpackEncode(obj);
  }
  async function exportStoreBytes(password) {
    if (!password) throw new Error("Password required");
    const salt  = crypto.getRandomValues(new Uint8Array(16));
    const key   = await scryptKey(password, salt);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const payload = serializeStoreForDisk();
    const ct = await aesGcmEncrypt(key, nonce, payload);
    const out = new Uint8Array(4+1+16+12+ct.length);
    out.set(MAGIC, 0); out[4]=VER; out.set(salt,5); out.set(nonce,21); out.set(ct,33);
    return out;
  }
  async function importStoreBytes(fileBytes, password) {
    if (fileBytes.length < (4+1+16+12+1)) throw new Error("Store too short");
    if (fileBytes[0]!==0x41||fileBytes[1]!==0x43||fileBytes[2]!==0x53||fileBytes[3]!==0x45) throw new Error("Wrong magic (ACSE)");
    if (fileBytes[4]!==VER) throw new Error("Wrong version (expected 1)");
    const salt  = fileBytes.slice(5,21);
    const nonce = fileBytes.slice(21,33);
    const ct    = fileBytes.slice(33);
    const key   = await scryptKey(password, salt);
    let pt;
    try { pt = await aesGcmDecrypt(key, nonce, ct); }
    catch { throw new Error("Decryption failed (bad password or corrupted file)"); }
    const obj = msgpackDecode(pt);
    const toU8 = (v)=> (v instanceof Uint8Array)? v : new Uint8Array(v);
    const st = {};
    for (const [sid, rec] of Object.entries(obj||{})) {
      st[sid] = {
        secret_key:    toU8(rec.secret_key),
        public_key:    toU8(rec.public_key),
        signing_key:   toU8(rec.signing_key),
        verifying_key: toU8(rec.verifying_key),
      };
    }
    senderStore = st;
  }

  async function saveStoreIfPossible() {
    if (!storePassword) return;
    try {
      const bytes = await exportStoreBytes(storePassword);
      if (storeHandle?.createWritable) {
        const w = await storeHandle.createWritable();
        await w.write(bytes); await w.close();
        toast("Store saved","ok");
      }
    } catch (e) { console.warn("Auto-save failed:", e); }
  }

  async function openStoreViaFS() {
    if (!window.showOpenFilePicker) throw new Error("File System Access API not supported in this browser");
    const pass = passFS.value; if (!pass) throw new Error("Enter password first");
    const [handle] = await window.showOpenFilePicker({
      types: [{ description:"CRS Sender Store", accept: { "application/octet-stream":[".msgpack",".bin",".store"]}}],
      excludeAcceptAllOption:false, multiple:false
    });
    const file = await handle.getFile();
    const bytes = new Uint8Array(await file.arrayBuffer());
    await importStoreBytes(bytes, pass);
    storePassword = pass; storeHandle = handle; storeFilename = file.name||"store.msgpack";
    setStoreBadge();
    storeOut.textContent = `Opened '${storeFilename}', loaded ${Object.keys(senderStore).length} secret(s).`;
    toast("Store loaded","ok");
  }
  async function resaveFS(){ if(!storeHandle) return toast("No opened store file","info"); if(!storePassword) return toast("No password set","error"); await saveStoreIfPossible(); }
  function closeFS(){ storeHandle=null; storeFilename=""; setStoreBadge(); toast("Closed store file","ok"); }

  async function importFallback(){
    const pass = passIn.value; const file = fileIn.files?.[0];
    if(!pass || !file) throw new Error("Choose file and enter password");
    const bytes = new Uint8Array(await file.arrayBuffer());
    await importStoreBytes(bytes, pass);
    storePassword = pass; setStoreBadge();
    storeOut.textContent = `Imported ${Object.keys(senderStore).length} secret(s) from '${file.name}'.`;
    toast("Store imported","ok");
  }
  async function exportFallback(){
    if(!storePassword) throw new Error("Enter export password (use the same one)");
    const bytes = await exportStoreBytes(storePassword);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([bytes],{type:"application/octet-stream"}));
    a.download = `sender_store_${senderIdDefault.value||"web"}.msgpack`; a.click();
    toast("Store exported (download)","ok");
  }

  // ======= Key mgmt (IMPORTANT: matches your wasm API!)
  //   SecretKey:   toBEBytes() <-> fromBEBytes(u8)
  //   PublicKey:   toCompressedBytes() <-> fromCompressedBytes(u8)
  function skToBytes(sk) { return sk.toBEBytes(); }
  function pkToBytes(pk) { return pk.toCompressedBytes(); }

  function ensureKeys(secretId) {
    if (!senderStore[secretId]) {
      const sk  = SecretKey.random();
      const pk  = sk.publicKey();
      const ssk = SecretKey.random();
      const vpk = ssk.publicKey();
      senderStore[secretId] = {
        secret_key:    skToBytes(sk),
        public_key:    pkToBytes(pk),
        signing_key:   skToBytes(ssk),
        verifying_key: pkToBytes(vpk),
      };
    }
    const rec = senderStore[secretId];
    const secretKey    = SecretKey.fromBEBytes(rec.secret_key);
    const publicKey    = PublicKey.fromCompressedBytes(rec.public_key);
    const signingKey   = SecretKey.fromBEBytes(rec.signing_key);
    const verifyingKey = PublicKey.fromCompressedBytes(rec.verifying_key);
    return { secretKey, publicKey, signingKey, verifyingKey };
  }

  // ======= Wire forms =======
  function applyDefaultSender(form){ const i=form?.querySelector('input[name="senderId"]'); if(i && !i.value && prefs.senderId) i.value=prefs.senderId; }
  applyDefaultSender(formAdd); applyDefaultSender(formDelete); applyDefaultSender(formReq); applyDefaultSender(formRevoke); applyDefaultSender(formGrants);

  formAdd.addEventListener("submit", async (e)=>{
    e.preventDefault(); addOut.textContent="";
    const fd = new FormData(formAdd);
    const senderId=(fd.get("senderId")||"").toString().trim();
    const secretId=(fd.get("secretId")||"").toString().trim();
    const secretValue=(fd.get("secretValue")||"").toString();
    if(!senderId||!secretId) return toast("senderId and secretId required","error");
    prefs.senderId = senderId;

    try {
      const { publicKey, verifyingKey } = ensureKeys(secretId);
      const [capsule, ciphertext] = encrypt(publicKey, te.encode(secretValue));

      await apiPost("/add_or_update_secret", {
        sender_id: senderId,
        secret_id: secretId,
        capsule_b64: b64e(capsule.toBytes()),
        ciphertext_b64: b64e(ciphertext),
        sender_public_key_b64:    b64e(pkToBytes(publicKey)),
        sender_verifying_key_b64: b64e(pkToBytes(verifyingKey)),
      });

      await saveStoreIfPossible();
      toast(`Upserted '${secretId}' for '${senderId}'`,"ok");
      addOut.textContent = `OK: upserted ${secretId}`;
    } catch (err) {
      toast("Add/Update failed: "+err.message,"error");
      addOut.textContent="Error: "+err.message;
    }
  });

  btnListSecrets?.addEventListener("click", async ()=>{
    const senderId=(new FormData(formAdd).get("senderId")||prefs.senderId||"").toString().trim();
    if(!senderId) return toast("Enter Sender ID","info");
    try{ const j = await apiPost("/list_grants",{ sender_id: senderId }); addOut.textContent = JSON.stringify(j,null,2); }
    catch(e){ addOut.textContent = "Error: "+e.message; }
  });

  formDelete.addEventListener("submit", async (e)=>{
    e.preventDefault(); delOut.textContent="";
    const fd=new FormData(formDelete);
    const senderId=(fd.get("senderId")||"").toString().trim();
    const secretId=(fd.get("secretId")||"").toString().trim();
    if(!senderId||!secretId) return toast("senderId and secretId required","error");
    prefs.senderId = senderId;
    try{
      await apiPost("/delete_secret",{ sender_id: senderId, secret_id: secretId });
      delete senderStore[secretId];
      await saveStoreIfPossible();
      toast(`Deleted '${secretId}' for '${senderId}'`,"ok");
      delOut.textContent=`OK: deleted ${secretId}`;
    }catch(err){ toast("Delete failed: "+err.message,"error"); delOut.textContent="Error: "+err.message; }
  });

  formReq.addEventListener("submit", async (e)=>{
    e.preventDefault(); reqList.innerHTML="";
    const fd=new FormData(formReq);
    const senderId=(fd.get("senderId")||"").toString().trim();
    if(!senderId) return toast("senderId required","error");
    prefs.senderId = senderId;
    try{
      const j = await apiPost("/pull_inbox/sender", { sender_id: senderId });
      const messages = j?.payload?.messages||[];
      const requests = messages.filter(m=>m.action==="REQUEST_ACCESS" && m.payload?.sender_id===senderId).map(m=>m.payload);
      if(requests.length===0){ reqList.innerHTML=`<div class="muted">(no pending requests)</div>`; return; }

      for(const r of requests){
        const card=document.createElement("div"); card.className="card";
        card.innerHTML = `
          <div><strong>Receiver:</strong> ${escapeHtml(r.receiver_id)}</div>
          <div><strong>Secret:</strong> ${escapeHtml(r.secret_id)}</div>
          <div class="actions">
            <button class="grant">Grant</button>
            <button class="deny danger">Deny</button>
          </div>`;
        const btnGrant=card.querySelector(".grant");
        const btnDeny =card.querySelector(".deny");

        btnGrant.addEventListener("click", async ()=>{
          try{
            const { secretKey, publicKey, signingKey, verifyingKey } = ensureKeys(r.secret_id);
            const signer = new Signer(signingKey);
            const recvPk = PublicKey.fromCompressedBytes(b64d(r.receiver_public_key_b64));

            const kfrags = generateKFrags(
              secretKey, recvPk, signer,
              1, 1,  // threshold, shares
              true,  // sign delegating key
              true   // sign receiving key
            );

            await apiPost("/grant_access_receiver", {
              sender_id: senderId,
              receiver_id: r.receiver_id,
              secret_id: r.secret_id,
              public_key_b64:    b64e(pkToBytes(publicKey)),
              verifying_key_b64: b64e(pkToBytes(verifyingKey)),
            });

            await apiPost("/grant_access_proxy", {
              sender_id: senderId,
              receiver_id: r.receiver_id,
              secret_id: r.secret_id,
              kfrags_b64: kfrags.map(k => b64e(k.toBytes())),
            });

            await saveStoreIfPossible();
            toast(`Granted ${r.receiver_id} -> ${r.secret_id}`,"ok");
            card.remove();
          }catch(err){ toast("Grant failed: "+err.message,"error"); }
        });

        btnDeny.addEventListener("click", ()=>{ card.remove(); toast(`Denied ${r.receiver_id} -> ${r.secret_id}`,"ok"); });
        reqList.appendChild(card);
      }
    }catch(err){ toast("Loading requests failed: "+err.message,"error"); }
  });

  formRevoke.addEventListener("submit", async (e)=>{
    e.preventDefault(); revokeOut.textContent="";
    const fd=new FormData(formRevoke);
    const senderId=(fd.get("senderId")||"").toString().trim();
    const receiverId=(fd.get("receiverId")||"").toString().trim();
    const secretId=(fd.get("secretId")||"").toString().trim();
    if(!senderId||!receiverId||!secretId) return toast("All fields required","error");
    prefs.senderId = senderId;
    try{
      await apiPost("/revoke_access",{ sender_id: senderId, receiver_id: receiverId, secret_id: secretId });
      await saveStoreIfPossible();
      toast(`Revoked ${receiverId} -> ${secretId}`,"ok");
      revokeOut.textContent=`OK: revoked ${receiverId} -> ${secretId}`;
    }catch(err){ toast("Revoke failed: "+err.message,"error"); revokeOut.textContent="Error: "+err.message; }
  });

  formGrants.addEventListener("submit", async (e)=>{
    e.preventDefault(); grantsOut.textContent="";
    const fd=new FormData(formGrants);
    const senderId=(fd.get("senderId")||"").toString().trim();
    if(!senderId) return toast("senderId required","error");
    prefs.senderId = senderId;
    try{
      const j = await apiPost("/list_grants",{ sender_id: senderId });
      grantsOut.textContent = (j.action==="GRANTS_SUMMARY") ? JSON.stringify(j.payload,null,2) : ("Unexpected reply: "+(j.action||"unknown"));
    }catch(err){ toast("Load summary failed: "+err.message,"error"); grantsOut.textContent="Error: "+err.message; }
  });

  // Store UI
  $("#btnOpenFS")?.addEventListener("click", async (e)=>{ e.preventDefault(); try{ await openStoreViaFS(); } catch(err){ toast(err.message,"error"); }});
  $("#btnResaveFS")?.addEventListener("click", async (e)=>{ e.preventDefault(); try{ await resaveFS(); } catch(err){ toast(err.message,"error"); }});
  $("#btnCloseFS")?.addEventListener("click", (e)=>{ e.preventDefault(); closeFS(); });
  $("#btnImport")?.addEventListener("click", async (e)=>{ e.preventDefault(); try{ await importFallback(); } catch(err){ toast(err.message,"error"); storeOut.textContent="Error: "+err.message; }});
  $("#btnExport")?.addEventListener("click", async (e)=>{ e.preventDefault(); try{ await exportFallback(); } catch(err){ toast(err.message,"error"); }});

})();
