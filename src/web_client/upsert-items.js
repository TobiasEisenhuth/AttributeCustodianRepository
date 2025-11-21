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
import { updateProviderDatalist } from "/app/inbound-request.js";

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
  store,
  itemName = null,
  valueStr,
  itemId = null,
  setStatus = () => {},
  setStateChip = () => {},
}) {
  if (itemName == null) {
    if (!itemId) return fail("itemId required when itemName is omitted.");
    const items = store.persistent.provider.items;
    const entry = items.find(it => it?.item_id === itemId);
    itemName = entry?.item_name ?? "Item";
  }
  
  itemName = normalizeText(itemName);
  valueStr = normalizeText(valueStr);

  if (!itemName) return fail("Please provide an item name.");
  if (!valueStr)  return fail("Please provide a value.");

  const providerItems = store.persistent.provider.items;

  let delegating_sk, delegating_pk, signing_sk, verifying_pk;
  let idx = -1, item_id;

  const umbral = await loadUmbral();
  if (!umbral) {
    setStateChip("Error", "err");
    setStatus("Umbral not available.", "err");
    return;
  }

  if (itemId) {
    item_id = itemId;
    idx = providerItems.findIndex(i => i?.item_id === itemId);
    if (idx === -1) { return fail("itemId not found!") }
    delegating_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(providerItems[idx].keys.secret_key_b64));
    delegating_pk = delegating_sk.publicKey();
    signing_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(providerItems[idx].keys.signing_key_b64));
    verifying_pk = signing_sk.publicKey();
  } else {
    const existing = new Set(providerItems.map(it => it?.item_id).filter(Boolean));
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
    providerItems[idx] = { ...providerItems[idx], ...persistent_entry, updated_at: now };
  } else {
    providerItems.push({...persistent_entry, created_at: now, updated_at: now });
  }

  store.ephemeral.provider.values.set(item_id, valueStr);

  needsSave(true);

  // todo - remove for production
  try { sessionStorage.setItem("crs:store", JSON.stringify(store)); } catch {}

  setStateChip("Upserting…");
  setStatus("Saving encrypted item to server…");

  await api.upsertItem(payload);

  setStateChip("Synced", "ok");
  setStatus(`Item "${itemName}" saved.`, "ok");

  updateProviderDatalist(store);

  return item_id;
}

export function wireUpAddItemDialog({ api, store }) {
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

      const itemId = await upsertItem({itemName, valueStr, api, store, setStatus, setStateChip});
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

export function wireUpItemUpdate({ api, store }) {
  if (revisiting("wireUpItemUpdate")) return;

  const enterEditMode = (wrapper, input) => {
    input.readOnly = false;
    wrapper.classList.remove("read-mode");
    wrapper.classList.add("edit-mode");
    setTimeout(() => { input.focus({ preventScroll: true }); input.select(); }, 0);
  };

  const exitEditMode = (wrapper, ro, input) => {
    ro.textContent = normalizeText(input.value || "");
    input.readOnly = true;
    wrapper.classList.remove("edit-mode");
    wrapper.classList.add("read-mode");
  };

  const setCtrlDown = (on) => document.body.classList.toggle("ctrl-down", !!on);
  document.addEventListener("keydown", (ev) => { if (ev.ctrlKey) setCtrlDown(true); });
  document.addEventListener("keyup", (ev) => { if (ev.key === "Control" || !ev.ctrlKey) setCtrlDown(false); });
  window.addEventListener("blur", () => setCtrlDown(false));

  const personalPanel = document.querySelector('.panel[data-panel="personal"]');

  personalPanel.addEventListener("mousedown", (ev) => {
    const td = ev.target.closest("td");
    if (!td || !personalPanel.contains(td)) return;

    const wrapper = ev.target.closest('.cell');
    const input = wrapper?.querySelector('input[type="text"]');
    const ro    = wrapper?.querySelector(".ro-text");
    if (!wrapper || !input || !ro) return;

    if (ev.button === 2) { // right-click
      ev.preventDefault();
      exitEditMode(wrapper, ro, input);
      return;
    }
    if (ev.button === 0 && ev.ctrlKey) {
      enterEditMode(wrapper, input);
    }
  });

  personalPanel.addEventListener("keydown", (ev) => {
    const input = ev.target;
    if (!(input instanceof HTMLInputElement)) return;
    if (ev.key === "Enter" || ev.key === "Escape") input.blur();
  });

  personalPanel.addEventListener("blur", async (ev) => {
    const input = ev.target;
    if (!(input instanceof HTMLInputElement)) return;

    const wrapper = input.closest(".cell");
    const ro   = wrapper?.querySelector(".ro-text");
    const td   = wrapper?.closest("td");
    const tr   = wrapper?.closest("tr");
    if (!wrapper || !ro || !td || !tr) return;

    const oldVal = ro.textContent || "";
    const newVal = normalizeText(input.value || "");

    exitEditMode(wrapper, ro, input);
    if (newVal === oldVal) return;

    // Determine column (0 = name, 1 = value)
    const colIndex = Array.prototype.indexOf.call(tr.children, td);
    const itemId   = tr.dataset.itemId;
    if (!itemId) return;

    try {
      if (colIndex === 0) {
        const items = store.persistent?.provider?.items || [];
        const entry = items.find(it => it?.item_id === itemId);
        if (!entry) throw new Error("Item not found");
        if (!newVal) throw new Error("Item name cannot be empty");

        entry.item_name = newVal;
        entry.updated_at = nowIso();

        needsSave(true);
        setStateChip("Unsaved", "warn");
        setStatus("Name updated.", "ok");
      } else if (colIndex === 1) {
        if (!newVal) {
          ro.textContent = oldVal; input.value = oldVal;
          setStateChip("Error", "err");
          setStatus("Value cannot be empty.", "err");
          return;
        }

        setStateChip("Saving…", "warn");
        setStatus("Updating encrypted value…");

        await upsertItem({
          api,
          store,
          valueStr: newVal,
          itemId
        });

        setStateChip("Synced", "ok");
        setStatus("Item value updated.", "ok");
      }
    } catch (err) {
      ro.textContent = oldVal;
      input.value    = oldVal;
      setStateChip("Error", "err");
      setStatus(err?.message || "Failed to save edit.", "err");
    }
  }, true);
}