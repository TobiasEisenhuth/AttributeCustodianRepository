import { loadUmbral } from "/app/umbral-loader.js";
import {
  nowIso,
  enc,
  dec,
  fail,
  normalizeText,
  generateItemId,
  bytesToBase64,
  revisiting,
  setStateChip,
  setStatus,
  base64ToBytes,
} from "/app/utils.js";
import { appendRowToGui } from "/app/upsert-items.js";

async function deriveAesKeyPBKDF2(passkeyBytes, saltBytes, iterations = 100_000, keyLen = 256) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passkeyBytes,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: keyLen },
    false,
    ["encrypt", "decrypt"]
  );
}

// todo - set to true for production
const USE_CRYPTO = false;
export async function packUserStoreToEnvelope(store, passkey) {
  const persistent = store.persistent;
  const persistent_utf_8 = JSON.stringify(persistent);
  const persistent_bytes = enc.encode(persistent_utf_8);

  if (!USE_CRYPTO) {
    const envelope = {
      v: 1,
      enc: "none",
      ct_b64: bytesToBase64(persistent_bytes),
    };
    const envelope_bytes = enc.encode(JSON.stringify(envelope));
    return bytesToBase64(envelope_bytes);
  }

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  const key = await deriveAesKeyPBKDF2(enc.encode(passkey), salt);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, persistent_bytes);
  const cipher_bytes = new Uint8Array(cipher);

  const envelope = {
    v: 1,
    enc: "aes-256-gcm",
    kdf: "pbkdf2-sha256",
    iterations: 100_000,
    salt_b64: bytesToBase64(salt),
    nonce_b64: bytesToBase64(nonce),
    ct_b64: bytesToBase64(cipher_bytes),
  };
  const envelope_bytes = enc.encode(JSON.stringify(envelope));
  return bytesToBase64(envelope_bytes);
}

export async function extractStoreFromEnvelope(envelopeB64, passkey = null ) {
  const envelope_bytes = base64ToBytes(envelopeB64);
  const envelope_utf_8 = dec.decode(envelope_bytes);
  const envelope = JSON.parse(envelope_utf_8);

  if (!envelope || envelope.v !== 1 || !envelope.enc) {
    throw new Error("Invalid envelope.");
  }

  if (envelope.enc === "none") {
    const plain_text_bytes = base64ToBytes(envelope.ct_b64);
    return JSON.parse(dec.decode(plain_text_bytes));
  }

  if (envelope.enc === "aes-256-gcm") {
    if (!passkey) throw new Error("Passkey required to decrypt.");
    const salt = base64ToBytes(envelope.salt_b64);
    const nonce = base64ToBytes(envelope.nonce_b64);
    const cipher_text = base64ToBytes(envelope.ct_b64);
    const iterations = envelope.iterations;
    const key = await deriveAesKeyPBKDF2(enc.encode(passkey), salt, iterations);

    const plain_text_buffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, cipher_text);
    const plain_text_bytes = new Uint8Array(plain_text_buffer);
    return JSON.parse(dec.decode(plain_text_bytes));
  }

  throw new Error(`Unsupported enc: ${envelope.enc}`);
}

export async function hydrateUserState(api, store) {
  if (revisiting('hydrateUserState')) return;

  setStateChip("Composing…");
  setStatus("Composing inventory…");

  const addBtn = document.querySelector('.panel[data-panel="personal"] [data-action="add-row"]');
  const panel  = document.querySelector('.panel[data-panel="personal"]');
  const tbody  = panel?.querySelector("tbody");
  if (tbody) tbody.innerHTML = "";
  if (addBtn) addBtn.disabled = true;

  try {
    if (!store || !store.good) {
      setStateChip("Error", "err");
      setStatus("Store not initialized.", "err");
      return;
    }

    const local_items = Array.isArray(store.persistent?.provider?.items)
      ? store.persistent.provider.items
      : [];

    let server_items = [];
    try {
      const res = await api.listMyItems();
      server_items = Array.isArray(res.items) ? res.items : [];
    } catch (e) {
      setStateChip("Error", "err");
      setStatus(e?.message || "Failed to fetch items from server.", "err");
      server_items = [];
    }

    const local_ids  = new Set(local_items.map(i => i.item_id).filter(Boolean));
    const server_ids = new Set(server_items.map(i => i.item_id).filter(Boolean));

    // IDs that exist only on one side
    const onlyLocalIds  = [...local_ids].filter(id => !server_ids.has(id));
    const onlyServerIds = [...server_ids].filter(id => !local_ids.has(id));

    const ids_are_identical =
      onlyLocalIds.length === 0 && onlyServerIds.length === 0;

    if (!ids_are_identical) {
      setStateChip("Mismatch", "warn");
      setStatus(
        `Inventory differs (local-only: ${onlyLocalIds.length}, server-only: ${onlyServerIds.length}). Showing best-effort view.`,
        "warn"
      );
    } else {
      setStateChip("Synced", "ok");
      setStatus("Inventory synced.", "ok");
    }

    const serverById = new Map(server_items.map(x => [x.item_id, x]));

    const umbral = await loadUmbral();
    if (!umbral) {
      setStateChip("Error", "err");
      setStatus("Umbral not available.", "err");
      return;
    }

    for (const entry of local_items) {
      const item_id   = entry.item_id;
      const item_name = entry.item_name || "(unnamed item)";

      const bundle = serverById.get(item_id);
      let plain_value = "";
      let isMismatch  = false;

      if (!bundle) {
        plain_value = "(cipher missing on server)";
        isMismatch  = true;
      } else {
        try {
          const secret_key_b64 = entry?.keys?.secret_key_b64;
          if (!secret_key_b64) throw new Error("Missing secret key");

          const sk        = umbral.SecretKey.fromBEBytes(base64ToBytes(secret_key_b64));
          const capsule   = umbral.Capsule.fromBytes(base64ToBytes(bundle.capsule_b64));
          const ct_bytes  = base64ToBytes(bundle.ciphertext_b64);
          const pt_buffer = umbral.decryptOriginal(sk, capsule, ct_bytes);
          plain_value     = dec.decode(pt_buffer);
        } catch (err) {
          plain_value = "(decrypt failed)";
          isMismatch  = true;
        }
      }

      store.ephemeral.provider.values.set(item_id, plain_value);

      const label = isMismatch
        ? `${item_name} (mismatch)`
        : item_name;

      appendRowToGui(label, plain_value, item_id);
    }

    for (const id of onlyServerIds) {
      const bundle = serverById.get(id);

      const item_name   = "(mismatch: server-only item)";
      const plain_value = "(cipher present but no local metadata)";

      appendRowToGui(item_name, plain_value, id);
    }

    if (local_items.length === 0 && onlyServerIds.length === 0) {
      setStatus("No personal items yet. Use “Add Row” to create one.", "muted");
    }

  } finally {
    if (addBtn) addBtn.disabled = false;
    // todo - remove for production
    try { sessionStorage.setItem('crs:store', JSON.stringify(store)); } catch {}
  }
}

let store = {
  good: false,
  persistent: {},
  ephemeral: {},
};

export async function initUserStore({ api, passkey }) {
  if (revisiting('initUserStore')) return;

  setStateChip('Loading…');
  setStatus('Loading from vault…');

  let persistedBranche;
  try {
    const { envelope_b64 } = await api.loadFromVault();
    persistedBranche = await extractStoreFromEnvelope(envelope_b64, passkey);
  } catch (err) {
    setStateChip("Error", "err");
    setStatus(err.message || "Failed to load from vault", "err");
    return;
  }

  Object.assign(store.persistent, persistedBranche.persistent);

  if (!store.persistent) store.persistent = {};
  if (!store.persistent.provider) store.persistent.provider = {}
  if (!Array.isArray(store.persistent.provider.items)) { store.persistent.provider.items = []; }
  if (!store.persistent.requester) store.persistent.requester = {};
  if (!Array.isArray(store.persistent.requester.items)) { store.persistent.requester.items = []; }
 
  store.ephemeral = {};
  store.ephemeral.provider = {};
  store.ephemeral.provider.values = new Map();
  store.ephemeral.provider.requests = [];

  store.good = true;
  await hydrateUserState(api, store);

  return store;
}
