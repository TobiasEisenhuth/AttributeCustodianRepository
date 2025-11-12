import { loadUmbral } from "/app/umbral-loader.js";
import { needsSave } from "/app/save.js"
import {
  base64ToBytes,
  bytesToBase64,
  enc,
  fail,
  generateItemId,
  normalizeText,
  nowIso,
  revisiting,
  setStateChip,
  setStatus,
} from "/app/utils.js";

export function appendRowToGui(itemName, valueStr, itemId) {
  const panel = document.querySelector('.panel[data-panel="personal"]');
  const tbody = panel?.querySelector("tbody");
  if (!tbody) return;

  const tr = document.createElement("tr");
  if (itemId) tr.dataset.itemId = itemId;

  const td1 = document.createElement("td");
  { const { wrapper } = makePersonalCell(itemName, "Item Name"); td1.appendChild(wrapper); }

  const td2 = document.createElement("td");
  { const { wrapper } = makePersonalCell(valueStr, "Value"); td2.appendChild(wrapper); }

  tr.appendChild(td1);
  tr.appendChild(td2);
  tbody.appendChild(tr);
}

export function makePersonalCell(initialValue, placeholder) {
  const wrapper = document.createElement("div");
  wrapper.className = "cell read-mode";

  const ro = document.createElement("span");
  ro.className = "ro-text";

  const text = initialValue ?? "";
  ro.textContent = text;

  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = placeholder || "";
  input.autocomplete = "off";
  input.readOnly = true;
  input.tabIndex = 0;
  input.value = text;

  wrapper.appendChild(ro);
  wrapper.appendChild(input);
  return { wrapper, ro, input };
}

// Item Upsert Heavy Lifting
export async function upsertItem({
  api,
  userStore,
  itemName,
  valueStr,
  itemId = null,
  setStatus = () => {},
  setStateChip = () => {},
}) {
  itemName = normalizeText(itemName);
  valueStr = normalizeText(valueStr);
  if (!itemName) return fail("Please provide an item name.");
  if (!valueStr)  return fail("Please provide a value.");

  const umbral = await loadUmbral();
  if (!umbral) return fail("Umbral not loaded; cannot add item.");

  // todo - ill formed user store is silent
  const persistentItems = userStore.persistent.provider.items;

  let delegating_sk, delegating_pk, signing_sk, verifying_pk;
  let idx = -1, item_id;

  if (itemId) {
    item_id = itemId;
    idx = persistentItems.findIndex(i => i?.item_id === itemId);
    if (idx === -1) { return fail("itemId not found!") }
    delegating_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(persistentItems[idx].keys.secret_key_b64));
    delegating_pk = delegating_sk.publicKey();
    signing_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(persistentItems[idx].keys.signing_key_b64));
    verifying_pk = signing_sk.publicKey();
  } else {
    const existing = new Set(persistentItems.map(it => it?.item_id).filter(Boolean));
    item_id = generateItemId(existing);
    delegating_sk = umbral.SecretKey.random();
    delegating_pk = delegating_sk.publicKey();
    signing_sk    = umbral.SecretKey.random();
    verifying_pk  = signing_sk.publicKey();
  }

  setStateChip("Encrypting…");
  setStatus("Encrypting item…");

  const plainBytes = enc.encode(valueStr);
  const [capsule, ciphertext] = umbral.encrypt(delegating_pk, plainBytes);
  if (!(capsule instanceof umbral.Capsule)) throw new Error("Umbral encrypt(): first element is not a Capsule");
  if (!(ciphertext instanceof Uint8Array)) throw new Error("Umbral encrypt(): second element is not Uint8Array");
  
  const payload = {
    item_id,
    capsule_b64: bytesToBase64(capsule.toBytes()),
    ciphertext_b64: bytesToBase64(ciphertext),
    provider_public_key_b64:    bytesToBase64(delegating_pk.toCompressedBytes()),
    provider_verifying_key_b64: bytesToBase64(verifying_pk.toCompressedBytes()),
  };

  const now = nowIso();
  const persistent_entry = {
    item_id,
    item_name: itemName,
    keys: {
      secret_key_b64:  bytesToBase64(delegating_sk.toBEBytes()),
      signing_key_b64: bytesToBase64(signing_sk.toBEBytes()),
    },
  };

  if (idx > -1) {
    persistentItems[idx] = { ...persistentItems[idx], ...persistent_entry, updated_at: now };
  } else {
    persistentItems.push({...persistent_entry, created_at: now, updated_at: now });
  }

  userStore.ephemeral.provider.values.set(item_id, valueStr);

  needsSave(true);

  // todo - remove for production
  try { sessionStorage.setItem("crs:userStore", JSON.stringify(userStore)); } catch {}

  setStateChip("Upserting…");
  setStatus("Saving encrypted item to server…");

  await api.upsertItem(payload);

  setStateChip("Synced", "ok");
  setStatus(`Item "${itemName}" saved.`, "ok");

  return item_id;
}

export function wireUpAddItemDialog({ api, userStore }) {
  if (revisiting('wireUpAddItemDialog')) return;

  const dialog = document.getElementById("new-item-dialog");
  if (!dialog) return;

  const btnAdd = dialog.querySelector('[data-action="confirm-dialog"]');
  const btnCancel = dialog.querySelector('[data-action="cancel-dialog"]');
  const inpName  = dialog.querySelector('input[data-field="Item Name"]');
  const inpValue = dialog.querySelector('input[data-field="Value"]');

  const closeDialog = () => {
    dialog.classList.remove('open');
    dialog.setAttribute('aria-hidden', 'true');
  };
  
  btnCancel.addEventListener('click', (ev) => { ev.preventDefault(); closeDialog(); });
  dialog.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeDialog(); });
  // dialog.addEventListener('click', (ev) => { if (ev.target === dialog) closeDialog(); });

  const openDialog = () => {
    inpName.value = '';
    inpValue.value = '';
    btnAdd.disabled = true;
    dialog.classList.add('open');
    dialog.setAttribute('aria-hidden', 'false');
    inpName.focus();
  };

  const personalPanel = document.querySelector('.panel[data-panel="personal"]');
  const btnAddRow = personalPanel.querySelector('[data-action="add-row"]');
  btnAddRow.addEventListener('click', (ev) => {
    ev.preventDefault(); openDialog();
  });

  const updateBtn = () => {
    btnAdd.disabled = !(inpName.value.trim() && inpValue.value.trim());
  };
  inpName.addEventListener('input', updateBtn);
  inpValue.addEventListener('input', updateBtn);

  btnAdd.addEventListener("click", async (ev) => {
    ev.preventDefault();
    if (btnAdd.disabled) return;
    if (btnAdd.dataset.busy === "1") return;
    btnAdd.dataset.busy = "1";

    try {
      const itemName = inpName.value;
      const valueStr = inpValue.value;
      if (!itemName) return fail('Please provide an item name.');
      if (!valueStr)  return fail('Please provide a value.');

      const itemId = await upsertItem({itemName, valueStr, api, userStore, setStatus, setStateChip});
      appendRowToGui(itemName, valueStr, itemId);
      closeDialog();
    } catch (err) {
      console.error(err);
      fail(err?.message || "Failed to add item.");
    } finally {
      delete btnAdd.dataset.busy;
    }
  });
}
