const LAST_SAVED_KEY = 'crs:last_saved_b64';
const CACHE_KEY      = 'crs:vault_cache';
const STORE_SS_KEY   = 'crs:store';

// Set to true for encrypted vault blobs (AES-GCM with `passkey`), false for plaintext base64 JSON (debug)
const USE_AES_GCM = false;

/* ------------ small utils ------------ */
function nowIso() { return new Date().toISOString(); }
function b64ToBytes(b64) {
  const s = atob(b64);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
}
function bytesToB64(bytes) {
  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}

/**
 * Initialize a vault controller.
 * @param {object} cfg
 * @param {object} cfg.api - CRSClient instance with loadFromVault()
 * @param {string|null} cfg.passkey - base64 raw AES key bytes (when USE_AES_GCM = true)
 * @param {string|null} cfg.email - optional, for cache metadata
 * @param {object} [cfg.ui] - UI hooks: setStateChip, setStatus, updateButtons
 */
export function initVault({ api, passkey, email, ui = {} }) {
  const setStateChip   = ui.setStateChip   || (() => {});
  const setStatus      = ui.setStatus      || (() => {});
  const updateButtons  = ui.updateButtons  || (() => {});

  // In-memory state (per tab)
  let store = null;             // decrypted store object (also mirrored to Session Storage)
  let encryptedBlobB64 = null;  // last loaded/generated blob
  let lastSavedB64 = null;      // blob considered saved on server
  let dirty = false;

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

  /* ------------ shape (keep current infra: private.items) ------------ */
  function ensureVaultShape(obj) {
    const s = (obj && typeof obj === 'object') ? obj : {};
    if (typeof s.version !== 'number') s.version = 1;
    if (!s.created_at) s.created_at = nowIso();
    if (!s.updated_at) s.updated_at = s.created_at;
    if (!s.private || typeof s.private !== 'object') s.private = {};
    if (!Array.isArray(s.private.items)) s.private.items = [];
    if (!s.meta || typeof s.meta !== 'object') s.meta = { schema: 'crs/v1', owner: email || '' };
    return s;
  }

  /* ------------ AES key (only if encrypted mode) ------------ */
  let aesKeyPromise = null;
  function getAesKey() {
    if (!USE_AES_GCM) return null;
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
  // Always *accept* both encodings on load:
  //  1) Try AES-GCM (IV(12) || ciphertext+tag)
  //  2) Fallback: plaintext base64(JSON-string)
  // Returns { kind: 'aes' | 'plain' }
  async function decryptBlobToStore(b64Blob) {
    const bytes = b64ToBytes(b64Blob);

    // 1) Attempt AES-GCM if it looks like it could be
    if (bytes.length >= 12 + 16) {
      try {
        const key = await getAesKey(); // may throw if USE_AES_GCM and no passkey
        if (key) {
          const iv = bytes.slice(0, 12);
          const ct = bytes.slice(12);
          const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
          const obj = JSON.parse(new TextDecoder().decode(new Uint8Array(ptBuf)));
          writeStoreToSession(ensureVaultShape(obj));
          return { kind: 'aes' };
        }
      } catch { /* fall through to plaintext */ }
    }

    // 2) Plaintext base64(JSON)
    try {
      const json = atob(b64Blob);
      const obj = JSON.parse(json);
      writeStoreToSession(ensureVaultShape(obj));
      return { kind: 'plain' };
    } catch {
      throw new Error('Decryption failed (not AES-GCM, not plaintext JSON).');
    }
  }

  // Save according to the build-time flag
  async function encryptStoreToBlob() {
    const s = store ?? readStoreFromSession() ?? ensureVaultShape({});
    const payload = {
      version: s.version ?? 1,
      created_at: s.created_at || nowIso(),
      updated_at: nowIso(),
      private: s.private || {},
      meta: s.meta || { schema: 'crs/v1', owner: email || '' },
    };
    // keep timestamps consistent in-memory
    writeStoreToSession(ensureVaultShape(payload));

    if (!USE_AES_GCM) {
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
      if (USE_AES_GCM && kind === 'plain') {
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
