const LAST_SAVED_KEY = 'crs:last_saved_b64';
const CACHE_KEY      = 'crs:vault_cache';
const STORE_SS_KEY   = 'crs:store';

/**
 * Initialize a vault controller.
 * @param {object} cfg
 * @param {object} cfg.api - CRSClient instance with loadFromVault()
 * @param {string|null} cfg.passkey - vault key from login (then removed from SS)
 * @param {string|null} cfg.email - optional, for cache metadata
 * @param {object} [cfg.ui] - UI hooks: setStateChip, setStatus, updateButtons
 */
export function initVault({ api, passkey, email, ui = {} }) {
  // UI hooks with safe defaults
  const setStateChip   = ui.setStateChip   || (() => {});
  const setStatus      = ui.setStatus      || (() => {});
  const updateButtons  = ui.updateButtons  || (() => {});

  // In-memory state (per tab)
  let store = null;             // decrypted store object (also mirrored to Session Storage)
  let encryptedBlobB64 = null;  // last loaded encrypted blob
  let lastSavedB64 = null;      // last blob we consider "saved"
  let dirty = false;

  /* ----------------- helpers ----------------- */

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
    const s = obj || {};
    if (typeof s.version !== 'number') s.version = 1;
    if (!s.data || typeof s.data !== 'object') s.data = {};
    return s;
  }

  // ---- CRYPTO PLACEHOLDERS (replace with your real crypto) ----
  async function decryptBlobToStore(b64Blob) {
    // TODO: replace with real decryption using `passkey`
    // Example assumes the blob is base64(JSON-string)
    try {
      const json = atob(b64Blob);
      const obj = JSON.parse(json);
      writeStoreToSession(ensureVaultShape(obj));
    } catch (e) {
      throw new Error('Decryption failed');
    }
  }

  async function encryptStoreToBlob() {
    // TODO: replace with real encryption using `passkey`
    const s = store ?? readStoreFromSession() ?? ensureVaultShape({});
    const json = JSON.stringify(s);
    return btoa(json);
  }
  // --------------------------------------------------------------

  async function encryptAndCachePrivate() {
    const b64 = await encryptStoreToBlob();
    try { localStorage.setItem(LAST_SAVED_KEY, b64); } catch {}
    try { localStorage.setItem(CACHE_KEY, JSON.stringify({ ts: Date.now(), b64, email, version: (store?.version ?? 1) })); } catch {}
    return b64;
  }

  function readEncryptedCache() {
    try {
      const cached = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null');
      return cached && typeof cached.b64 === 'string' ? cached : null;
    } catch { return null; }
  }

  /* ----------------- public API ----------------- */

  async function loadVault() {
    setStateChip('Loading…');
    setStatus('Loading vault…');

    try {
      const res = await api.loadFromVault();
      const b64 = res?.encrypted_localstore_b64;
      if (!b64 || typeof b64 !== 'string') throw new Error('Bad vault payload');

      await decryptBlobToStore(b64);
      encryptedBlobB64 = b64;
      lastSavedB64 = b64;

      try { localStorage.setItem(LAST_SAVED_KEY, lastSavedB64); } catch {}
      try {
        const s = store ?? readStoreFromSession();
        localStorage.setItem(CACHE_KEY, JSON.stringify({
          ts: Date.now(), b64, email, version: s?.version ?? 1
        }));
      } catch {}

      dirty = false;
      setStateChip('Synced', 'ok');
      setStatus('Vault loaded from server.', 'ok');
    } catch (e) {
      // Server unavailable or bad payload: try local encrypted cache
      const cached = readEncryptedCache();
      if (cached?.b64) {
        try {
          await decryptBlobToStore(cached.b64);
          encryptedBlobB64 = cached.b64;
          dirty = true; // local cache means we’re ahead/unsynced
          setStateChip('Unsaved (from cache)', 'warn');
          setStatus('Loaded vault from local cache (server unavailable).', 'warn');
        } catch {
          setStateChip('Error', 'err');
          setStatus('Could not decrypt cached vault. Wrong key or corrupted data.', 'err');
        }
      } else {
        // First-time user: start empty, cache an encrypted seed
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

  return {
    // actions
    loadVault,
    // state accessors
    get store() { return store ?? readStoreFromSession(); },
    get encryptedBlobB64() { return encryptedBlobB64; },
    get lastSavedB64() { return lastSavedB64; },
    get dirty() { return dirty; },
    setDirty(v = true) { dirty = !!v; },
    // utilities (exported in case you need them)
    ensureVaultShape,
    encryptAndCachePrivate,
    // placeholders to swap with your real crypto
    _dev_replaceCrypto({ decrypt = decryptBlobToStore, encrypt = encryptStoreToBlob } = {}) {
      if (decrypt) decryptBlobToStore = decrypt;
      if (encrypt) encryptStoreToBlob = encrypt;
    }
  };
}

