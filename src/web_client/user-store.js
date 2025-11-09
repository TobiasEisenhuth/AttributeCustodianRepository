import {
  nowIso,
  enc,
  dec,
  fail,
  normalizeText,
  generateItemId,
  bytesToBase64,
  base64ToBytes,
  extractStoreFromEnvelope,
} from "/app/utils.js";

const STORE_SS_KEY   = 'crs:store';

// todo - true for production
const USE_CRYPTO = false;

export async function initUserStore({ api, passkey, email, ui = {} }) {
  const setStateChip   = ui.setStateChip   || (() => {});
  const setStatus      = ui.setStatus      || (() => {});

  let user_store = null;

  setStateChip('Loading…');
  setStatus('Loading from vault…');

  try {
    const envelope_b64 = api.loadFromVault();
    user_store = await extractStoreFromEnvelope(envelope_b64, passkey);

  } finally {
    updateButtons();
  }
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