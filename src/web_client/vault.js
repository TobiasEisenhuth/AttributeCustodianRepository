import {
  nowIso,
  enc,
  dec,
  fail,
  normalizeText,
  generateItemId,
  bytesToBase64,
  base64ToBytes,
} from "/app/utils.js";

import { deriveArgon2id } from "./argon2id.js";
import { decryptBlobToStore } from "./utils.js";

const STORE_SS_KEY   = 'crs:store';

// todo - true for production
const USE_CRYPTO = false;

export function initUserStore({ api, passkey, email, ui = {} }) {
  const setStateChip   = ui.setStateChip   || (() => {});
  const setStatus      = ui.setStatus      || (() => {});

  let user_store = null;

  setStateChip('Loading…');
  setStatus('Loading from vault…');

  try {
      const envelope_b64 = api.loadFromVault();
      user_store = decryptBlobToStore(envelope_b64, passkey);

      const envelope_bytes = base64ToBytes(envelope_b64);
      const envelope_utf_8 = dec.decode(envelope_bytes);
      const envelope = JSON.parse(envelope_utf_8);

      if (!envelope || envelope.v !== 1 || !envelope.ct_b64) {
        throw new Error("Invalid vault envelope.");
      }

      if (envelope.enc === "none") {
        const user_store_bytes = base64ToBytes(envelope.ct_b64);
        const user_store_json = dec.decode(user_store_bytes);
        user_store = JSON.parse(user_store_json);
      }
      
      if (envelope.enc === "aes-256-gcm") {
        
      }

        throw new Error(`Unsupported envelope enc: ${String(envelope.enc)}`);

      if (!vault_b64 || typeof vault_b64 !== 'string') throw new Error('Bad vault payload');

      const { kind } = ingestVault(vault_b64);
      encryptedBlobB64 = b64;

      // If server had plaintext but we’re in encrypted mode, force a re-save
      if (USE_CRYPTO && kind === 'plain') {
        lastSavedB64 = null;      // nothing "encrypted" saved yet
        dirty = true;
        setStateChip('Unsaved (will re-encrypt)', 'warn');
        setStatus('Loaded legacy/plain vault; will re-encrypt on next save.', 'warn');
      } else {
        lastSavedB64 = b64;
        dirty = false;
        setStateChip('Synced', 'ok');
        setStatus('Vault loaded from server.', 'ok');
      }

      try { localStorage.setItem(LAST_SAVED_KEY, lastSavedB64 || ''); } catch {}
      try {
        const s = store ?? readStoreFromSession();
        localStorage.setItem(CACHE_KEY, JSON.stringify({
          ts: Date.now(), b64, email, version: s?.version ?? 1
        }));
      } catch {}
    } catch (e) {
      // Server unavailable or unreadable: try local cache
      const cached = readEncryptedCache();
      if (cached?.b64) {
        try {
          await decryptBlobToStore(cached.b64);
          encryptedBlobB64 = cached.b64;
          dirty = true; // local cache means we might be ahead of server
          setStateChip('Unsaved (from cache)', 'warn');
          setStatus('Loaded vault from local cache (server unavailable).', 'warn');
        } catch {
          setStateChip('Error', 'err');
          setStatus('Could not decrypt cached vault. Wrong key or corrupted data.', 'err');
        }
      } else {
        // First-time: start empty and create initial blob
        setStatus('No server vault. Starting with an empty local store.', 'warn');
        writeStoreToSession(ensureVaultShape({}));
        const b64 = await encryptAndCachePrivate();
        encryptedBlobB64 = b64;
        dirty = true;
        setStateChip('Unsaved', 'warn');
      }
    } finally {
      updateButtons();
    }

  /* ------------ session mirroring ------------ */
  function writeStoreToSession(obj) {
    store = obj || {};
    try { sessionStorage.setItem(STORE_SS_KEY, JSON.stringify(store)); } catch {}
  }
  function readStoreFromSession() {
    try {
      const raw = sessionStorage.getItem(STORE_SS_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  }

  function ensureVaultShape(obj) {
    const s = (obj && typeof obj === 'object') ? obj : {};
    if (typeof s.version !== 'number') s.version = 1;
    if (!s.created_at) s.created_at = nowIso();
    if (!s.updated_at) s.updated_at = s.created_at;
    if (!s.persistent || typeof s.persistent !== 'object') s.persistent = {};
    if (!Array.isArray(s.persistent.provider.items)) s.persistent.provider.items = [];
    if (!s.meta || typeof s.meta !== 'object') s.meta = { schema: 'crs/v1', owner: email || '' };
    return s;
  }

  /* ------------ AES key (only if encrypted mode) ------------ */
  let aesKeyPromise = null;
  function getAesKey() {
    if (!USE_CRYPTO) return null;
    if (!passkey) throw new Error('No passkey provided for AES-GCM mode.');
    if (!aesKeyPromise) {
      aesKeyPromise = crypto.subtle.importKey(
        'raw',
        b64ToBytes(passkey),         // passkey is base64 of raw key bytes
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
      );
    }
    return aesKeyPromise;
  }

  /* ------------ CRYPTO (dual) ------------ */


  // Save according to the build-time flag
  async function encryptStoreToBlob() {
    const s = store ?? readStoreFromSession() ?? ensureVaultShape({});
    const payload = {
      version: s.version ?? 1,
      created_at: s.created_at || nowIso(),
      updated_at: nowIso(),
      private: s.persistent || {},
      meta: s.meta || { schema: 'crs/v1', owner: email || '' },
    };
    // keep timestamps consistent in-memory
    writeStoreToSession(ensureVaultShape(payload));

    if (!USE_CRYPTO) {
      // Debug/plain mode: base64(JSON)
      return btoa(JSON.stringify(payload));
    }

    // Encrypted mode: AES-GCM( IV(12) || CIPHERTEXT+TAG ), base64 encoded
    const key = await getAesKey();
    const iv = new Uint8Array(12); crypto.getRandomValues(iv);
    const pt = new TextEncoder().encode(JSON.stringify(payload));
    const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
    const ct = new Uint8Array(ctBuf);
    return bytesToB64(concatBytes(iv, ct));
  }

  async function encryptAndCachePrivate() {
    const b64 = await encryptStoreToBlob();
    encryptedBlobB64 = b64;

    try { localStorage.setItem(LAST_SAVED_KEY, b64); } catch {}
    try {
      const s = store ?? readStoreFromSession();
      localStorage.setItem(CACHE_KEY, JSON.stringify({
        ts: Date.now(), b64, email, version: s?.version ?? 1
      }));
    } catch {}

    dirty = (lastSavedB64 == null) ? true : (encryptedBlobB64 !== lastSavedB64);
    return b64;
  }

  function readEncryptedCache() {
    try {
      const cached = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null');
      return cached && typeof cached.b64 === 'string' ? cached : null;
    } catch { return null; }
  }

  /* ------------ public actions ------------ */
  async function loadVault() {
    setStateChip('Loading…');
    setStatus('Loading vault…');

    try {
      const res = await api.loadFromVault();
      const b64 = res?.encrypted_localstore_b64;
      if (!b64 || typeof b64 !== 'string') throw new Error('Bad vault payload');

      const { kind } = await decryptBlobToStore(b64);
      encryptedBlobB64 = b64;

      // If server had plaintext but we’re in encrypted mode, force a re-save
      if (USE_CRYPTO && kind === 'plain') {
        lastSavedB64 = null;      // nothing "encrypted" saved yet
        dirty = true;
        setStateChip('Unsaved (will re-encrypt)', 'warn');
        setStatus('Loaded legacy/plain vault; will re-encrypt on next save.', 'warn');
      } else {
        lastSavedB64 = b64;
        dirty = false;
        setStateChip('Synced', 'ok');
        setStatus('Vault loaded from server.', 'ok');
      }

      try { localStorage.setItem(LAST_SAVED_KEY, lastSavedB64 || ''); } catch {}
      try {
        const s = store ?? readStoreFromSession();
        localStorage.setItem(CACHE_KEY, JSON.stringify({
          ts: Date.now(), b64, email, version: s?.version ?? 1
        }));
      } catch {}
    } catch (e) {
      // Server unavailable or unreadable: try local cache
      const cached = readEncryptedCache();
      if (cached?.b64) {
        try {
          await decryptBlobToStore(cached.b64);
          encryptedBlobB64 = cached.b64;
          dirty = true; // local cache means we might be ahead of server
          setStateChip('Unsaved (from cache)', 'warn');
          setStatus('Loaded vault from local cache (server unavailable).', 'warn');
        } catch {
          setStateChip('Error', 'err');
          setStatus('Could not decrypt cached vault. Wrong key or corrupted data.', 'err');
        }
      } else {
        // First-time: start empty and create initial blob
        setStatus('No server vault. Starting with an empty local store.', 'warn');
        writeStoreToSession(ensureVaultShape({}));
        const b64 = await encryptAndCachePrivate();
        encryptedBlobB64 = b64;
        dirty = true;
        setStateChip('Unsaved', 'warn');
      }
    } finally {
      updateButtons();
    }
  }

  /* ------------ exports ------------ */
  return {
    loadVault,
    get store() { return store ?? readStoreFromSession(); },
    get encryptedBlobB64() { return encryptedBlobB64; },
    get lastSavedB64() { return lastSavedB64; },
    get dirty() { return dirty; },
    setDirty(v = true) { dirty = !!v; },
    ensureVaultShape,
    encryptAndCachePrivate,
    // optional dev hook to hot-swap crypto (kept for parity)
    _dev_replaceCrypto({ decrypt = decryptBlobToStore, encrypt = encryptStoreToBlob } = {}) {
      if (decrypt) decryptBlobToStore = decrypt;
      if (encrypt) encryptStoreToBlob = encrypt;
    }
  };
}

async function hydrateAndRenderPersonal({ api, vault }) {
  setStateChip("Loading…");
  setStatus("Loading inventory…");

  // Disable Add-row until hydrated
  const addBtn = document.querySelector('.panel[data-panel="personal"] [data-action="add-row"]');
  if (addBtn) addBtn.disabled = true;

  // Ensure DOM exists
  const panel = document.querySelector('.panel[data-panel="personal"]');
  const tbody = panel?.querySelector("tbody");
  if (tbody) tbody.innerHTML = "";

  // Load Umbral
  const umbral = await loadUmbral();
  if (!umbral) {
    setStateChip("Umbral missing", "err");
    setStatus("Umbral WASM not available; cannot decrypt items.", "err");
    if (addBtn) addBtn.disabled = false; // still allow adding new plaintext rows
    return;
  }

  // Local store with keys
  const s = vault.store || {};
  const localItems = Array.isArray(s?.persistent?.provider?.items) ? s.persistent.provider.items : [];

  // Pull server inventory (encrypted blobs)
  let serverItems = [];
  try {
    const res = await api.listMyItems();
    serverItems = Array.isArray(res?.items) ? res.items : [];
  } catch (e) {
    setStateChip("Error", "err");
    setStatus(e?.message || "Failed to fetch items from server.", "err");
    if (addBtn) addBtn.disabled = false;
    return;
  }

  // Mismatch detection (count or ids differ)
  const localIds  = new Set(localItems.map(i => i?.item_id).filter(Boolean));
  const serverIds = new Set(serverItems.map(i => i?.item_id).filter(Boolean));
  const sameCount = localIds.size === serverIds.size;
  const sameIds   = sameCount && [...localIds].every(id => serverIds.has(id)) && [...serverIds].every(id => localIds.has(id));
  if (!sameIds) {
    setStateChip("Mismatch", "warn");
    setStatus("Local vault and server inventory differ (IDs or count).", "warn");
  } else {
    setStateChip("Synced", "ok");
    setStatus("Inventory synced.", "ok");
  }

  const byId = new Map(serverItems.map(x => [x.item_id, x]));
  s.ephemeral = s.ephemeral || {};
  s.ephemeral.provider = s.ephemeral.provider || {};
  const values = (s.ephemeral.provider.values = {});

  for (const entry of localItems) {
    const id = entry?.item_id;
    const srv = id ? byId.get(id) : null;
    if (!id || !srv) continue;

    try {
      const skBE = entry?.keys?.secret_key_b64;
      if (!skBE) throw new Error("missing secret_key_b64");
      const sk = umbral.SecretKey.fromBEBytes(base64ToBytes(skBE));
      const capsule = umbral.Capsule.fromBytes(base64ToBytes(srv.capsule_b64));
      const ct = base64ToBytes(srv.ciphertext_b64);
      const pt = umbral.decryptOriginal(sk, capsule, ct);
      values[id] = dec.decode(pt);
    } catch {
      values[id] = "(decrypt failed)";
    }
  }

  // Mirror hydrated store back to Session Storage (vault persists `private` only)
  try { sessionStorage.setItem('crs:store', JSON.stringify(s)); } catch {}

  // Render Personal table using hydrated plaintext
  for (const entry of localItems) {
    const name = entry?.item_name || entry?.item_id || "";
    const val  = s?.ephemeral?.provider?.values?.[entry?.item_id] ?? "";
    const itemId = entry?.item_id
    appendRowToPersonal(name, val, itemId);
  }

  if (addBtn) addBtn.disabled = false;
}