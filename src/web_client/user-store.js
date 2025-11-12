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
import { appendRowToGui } from "/app/add-items.js";

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

// todo - true for production
const USE_CRYPTO = false;
export async function packUserStoreToEnvelope(userStore, passkey) {
  const {ephemeral, ...persistent} = userStore;
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

export async function hydrateUserStore(api, userStore) {
  if (revisiting('hydrateUserStore')) return;

  setStateChip("Composing…");
  setStatus("Composing inventory…");

  const umbral = await loadUmbral();
  if (!umbral) {
    setStateChip("Umbral missing", "err");
    setStatus("Umbral WASM not available; cannot decrypt items.", "err");
    return;
  }

  const addBtn = document.querySelector('.panel[data-panel="personal"] [data-action="add-row"]');
  if (addBtn) addBtn.disabled = true;

  const panel = document.querySelector('.panel[data-panel="personal"]');
  const tbody = panel?.querySelector("tbody");
  if (tbody) tbody.innerHTML = "";

  const local_items = Array.isArray(userStore.persistent?.provider?.items)
  ? userStore.persistent.provider.items
  : [];

  let server_items = [];
  try {
    const res = await api.listMyItems();
    server_items = Array.isArray(res.items) ? res.items : [];
  } catch (e) {
    setStateChip("Error", "err");
    setStatus(e?.message || "Failed to fetch items from server.", "err");
    if (addBtn) addBtn.disabled = false;
    return;
  }

  const local_ids  = new Set(local_items.map(i => i.item_id).filter(Boolean));
  const server_ids = new Set(server_items.map(i => i.item_id).filter(Boolean));

  const same_count = local_ids.size === server_ids.size;
  const ids_are_identical = same_count && [...server_ids].every(id => local_ids.has(id));
  if (!ids_are_identical) {
    setStateChip("Mismatch", "warn");
    setStatus("Local user store and server inventory differ (IDs or count).", "warn");
    return;
  } else {
    setStateChip("Synced", "ok");
    setStatus("Inventory synced.", "ok");
  }

  userStore.ephemeral = { provider: { values: new Map() } };

  const server_items_by_id = new Map(server_items.map(x => [x.item_id, x]));
  for (const entry of local_items) {
    const common_id = entry.item_id;
    const matching_item = server_items_by_id.get(common_id);

    const item_name = entry.item_name;
    let plain_value;
    try {
      const secret_key_b64 = entry.keys.secret_key_b64;
      const secret_key = umbral.SecretKey.fromBEBytes(base64ToBytes(secret_key_b64));
      const capsule = umbral.Capsule.fromBytes(base64ToBytes(matching_item.capsule_b64));
      const cipher_text = base64ToBytes(matching_item.ciphertext_b64);
      const plain_value_buffer = umbral.decryptOriginal(secret_key, capsule, cipher_text);
      plain_value = dec.decode(plain_value_buffer)
    } catch {
      plain_value = "(decrypt failed)";
    }
    userStore.ephemeral.provider.values.set(common_id, plain_value);

    appendRowToGui(item_name, plain_value, common_id);
  }

  if (addBtn) addBtn.disabled = false;
  
  // todo - remove for production
  try { sessionStorage.setItem('crs:userStore', JSON.stringify(userStore)); } catch {} 
}

export async function initUserStore({ api, passkey }) {
  if (revisiting('initUserStore')) return;

  setStateChip('Loading…');
  setStatus('Loading from vault…');

  let user_store;
  try {
    const { envelope_b64 } = await api.loadFromVault();
    user_store = await extractStoreFromEnvelope(envelope_b64, passkey);
    await hydrateUserStore(api, user_store);
  } catch (err) {
    setStateChip("Error", "err");
    setStatus(err.message || "Failed to load from vault", "err");
    return;
  }

  return user_store;
}