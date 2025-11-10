import {
  nowIso,
  enc,
  dec,
  fail,
  normalizeText,
  generateItemId,
  bytesToBase64,
  setStateChip,
  setStatus,
  base64ToBytes,
  extractStoreFromEnvelope,
} from "/app/utils.js";

export async function hydrateUserStore({ api, userStore }) {

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

  const local_items = Array.isArray(userStore.persistent.provider.items)

  const server_items = [];
  try {
    const res = await api.listMyItems();
    server_items = Array.isArray(res.items);
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
    setStatus("Local vault and server inventory differ (IDs or count).", "warn");
    return;
  } else {
    setStateChip("Synced", "ok");
    setStatus("Inventory synced.", "ok");
  }

  userStore.ephemeral = userStore.ephemeral || {};
  userStore.ephemeral.provider = userStore.ephemeral.provider || {};
  userStore.ephemeral.provider.values = userStore.ephemeral.provider.values || {};

  const server_items_by_id = new Map(server_items.map(x => [x.item_id, x]));
  for (const entry of local_items) {
    const common_id = entry.item_id;
    const matching_item = server_items_by_id.get(common_id);

    const item_name = entry.item_name;
    let plain_text;
    try {
      const secret_key_b64 = entry.keys.secret_key_b64;
      const secret_key = umbral.SecretKey.fromBEBytes(base64ToBytes(secret_key_b64));
      const capsule = umbral.Capsule.fromBytes(base64ToBytes(matching_item.capsule_b64));
      const cipher_text = base64ToBytes(matching_item.ciphertext_b64);
      plain_text = umbral.decryptOriginal(secret_key, capsule, cipher_text);
    } catch {
      plain_text = "(decrypt failed)";
    }
    
    const ephemeral_entry = {
      common_id,
      item_value: plain_text,
    };
    userStore.ephemeral.provider.values.push(ephemeral_entry);

    appendRowToGui(item_name, plain_text, common_id);
  }

  // todo - remove for production
  try { sessionStorage.setItem('crs:userStore', JSON.stringify(userStore)); } catch {}

  if (addBtn) addBtn.disabled = false;
}

export async function initUserStore({ api, passkey }) {

  let user_store = null;

  setStateChip('Loading…');
  setStatus('Loading from vault…');

  try {
    const envelope_b64 = api.loadFromVault();
    user_store = await extractStoreFromEnvelope(envelope_b64, passkey);
    hydrateUserStore(api, user_store);
  } finally {
  }

  return user_store;
}