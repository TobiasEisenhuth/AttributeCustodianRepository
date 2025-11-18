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

export function getCurrentOptions(store) {
  const items = store?.persistent?.provider?.items || [];
  const values = store?.ephemeral?.provider?.values || new Map();

  const options = items.map(it => ({
    id: it.item_id,
    label: values.get(it.item_id)
  }));

  return options;
}

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
export async function packUserStoreToEnvelope(store, passkey) {
  const {ephemeral, ...persistent} = store;
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

export async function hydrateUserStore(api, store) {
  if (revisiting('hydrateUserStore')) return;

  setStateChip("Composing…");
  setStatus("Composing inventory…");

  const addBtn = document.querySelector('.panel[data-panel="personal"] [data-action="add-row"]');
  const panel  = document.querySelector('.panel[data-panel="personal"]');
  const tbody  = panel?.querySelector("tbody");
  if (tbody) tbody.innerHTML = "";
  if (addBtn) addBtn.disabled = true;

  try {
    const local_items = store.persistent?.provider?.items;

    // Fetch server side inventory (crypto_bundle rows → via your SDK)
    let server_items = [];
    try {
      const res = await api.listMyItems();
      server_items = Array.isArray(res.items) ? res.items : [];
    } catch (e) {
      setStateChip("Error", "err");
      setStatus(e?.message || "Failed to fetch items from server.", "err");
      // Continue: we can still show local items as "(not on server)"
      server_items = [];
    }

    // Build id sets to compare
    const local_ids  = new Set(local_items.map(i => i.item_id).filter(Boolean));
    const server_ids = new Set(server_items.map(i => i.item_id).filter(Boolean));

    const same_count = local_ids.size === server_ids.size;
    const ids_are_identical = same_count && [...server_ids].every(id => local_ids.has(id));

    // Report state, but DO NOT early-return anymore
    if (!ids_are_identical) {
      const onlyLocal  = [...local_ids].filter(id => !server_ids.has(id)).length;
      const onlyServer = [...server_ids].filter(id => !local_ids.has(id)).length;
      setStateChip("Mismatch", "warn");
      setStatus(`Inventory differs (local-only: ${onlyLocal}, server-only: ${onlyServer}). Showing best-effort view.`, "warn");
    } else {
      setStateChip("Synced", "ok");
      setStatus("Inventory synced.", "ok");
    }

    // Fast lookup of server bundles by item_id
    const serverById = new Map(server_items.map(x => [x.item_id, x]));

    const umbral = await loadUmbral();
    if (!umbral) {
      setStateChip("Error", "err");
      setStatus("Umbral not available.", "err");
      return;
    }

    // Render every LOCAL item; if missing on server, mark it as such
    for (const entry of local_items) {
      const item_id   = entry.item_id;
      const item_name = entry.item_name;

      const bundle = serverById.get(item_id); // may be undefined
      let plain_value = "";
      if (!bundle) {
        // No server-side crypto bundle for this item
        plain_value = "(not on server)";
      } else {
        try {
          const secret_key_b64 = entry?.keys?.secret_key_b64;
          if (!secret_key_b64) throw new Error("Missing secret key");
          const sk        = umbral.SecretKey.fromBEBytes(base64ToBytes(secret_key_b64));
          const capsule   = umbral.Capsule.fromBytes(base64ToBytes(bundle.capsule_b64));
          const ct_bytes  = base64ToBytes(bundle.ciphertext_b64);
          const pt_buffer = umbral.decryptOriginal(sk, capsule, ct_bytes);
          plain_value     = dec.decode(pt_buffer);
        } catch {
          plain_value = "(decrypt failed)";
        }
      }

      // Mirror to ephemeral map for provider UX (inbound suggestions, etc.)
      store.ephemeral.provider.values.set(item_id, plain_value);

      // Paint the row in the Personal table
      appendRowToGui(item_name, plain_value, item_id);
    }

    // (Optional) If there are server-only items, you could surface a hint.
    // We do not render them here since there is no local metadata/keys.

    // If absolutely nothing to show, keep UI usable and clear status
    if (local_items.length === 0) {
      setStatus("No personal items yet. Use “Add Row” to create one.", "muted");
    }

  } finally {
    // ALWAYS re-enable the Add Row button
    if (addBtn) addBtn.disabled = false;
    // For debugging / dev
    try { sessionStorage.setItem('crs:store', JSON.stringify(store)); } catch {}
  }
}

export async function initUserStore({ api, passkey }) {
  if (revisiting('initUserStore')) return;

  setStateChip('Loading…');
  setStatus('Loading from vault…');

  let store;
  try {
    const { envelope_b64 } = await api.loadFromVault();
    store = await extractStoreFromEnvelope(envelope_b64, passkey);
  } catch (err) {
    setStateChip("Error", "err");
    setStatus(err.message || "Failed to load from vault", "err");
    return;
  }

  if (!store.persistent) store.persistent = {};
  if (!store.persistent.provider) store.persistent.provider = {}
  if (!Array.isArray(store.persistent.provider.items)) { store.persistent.provider.items = []; }
  if (!store.persistent.requester) store.persistent.requester = {};
  if (!Array.isArray(store.persistent.requester.items)) { store.persistent.requester.items = []; }

  store.ephemeral = {};
  store.ephemeral.provider = {};
  store.ephemeral.provider.values = new Map();

  await hydrateUserStore(api, store);

  return store;
}