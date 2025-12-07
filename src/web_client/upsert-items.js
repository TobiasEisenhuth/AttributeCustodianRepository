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

const eraseButtons = new Set();

function refreshEraseButtons() {
  const ctrlDown = document.body.classList.contains("ctrl-down");
  for (const btn of eraseButtons) {
    if (ctrlDown) {
      btn.classList.add("btn-armed");
      btn.classList.remove("btn-disarmed");
    } else {
      btn.classList.remove("btn-armed");
      btn.classList.add("btn-disarmed");
    }
  }
}

export async function revokeGrant(api, grant) {
  return api.revokeAccess({
    requester_id: grant.requester_id,
    provider_item_id: grant.provider_item_id,
  });
}

function removeLocalItem(store, itemId, tr) {
  const items = store?.persistent?.provider?.items;
  if (Array.isArray(items)) {
    const idx = items.findIndex(it => it.item_id === itemId);
    if (idx !== -1) items.splice(idx, 1);
  }

  store?.ephemeral?.provider?.values?.delete(itemId);

  if (tr && tr.parentNode) {
    const btn = tr.querySelector(".btn-erase");
    if (btn && eraseButtons.has(btn)) {
      eraseButtons.delete(btn);
    }
    tr.parentNode.removeChild(tr);
  }

  needsSave(true);
  // todo - remove for production
  try { sessionStorage.setItem("crs:store", JSON.stringify(store)); } catch {}
  updateProviderDatalist(store);
}

function showEraseBlockedOverlay(api, store, itemId, tr, grants) {
  const old = document.getElementById("erase-blocked-overlay");
  if (old) old.remove();

  const backdrop = document.createElement("div");
  backdrop.id = "erase-blocked-overlay";
  backdrop.style.position = "fixed";
  backdrop.style.inset = "0";
  backdrop.style.background = "rgba(0,0,0,0.35)";
  backdrop.style.display = "flex";
  backdrop.style.alignItems = "center";
  backdrop.style.justifyContent = "center";
  backdrop.style.zIndex = "2000";

  const box = document.createElement("div");
  box.style.background = "#fff";
  box.style.border = "1px solid #ddd";
  box.style.borderRadius = "8px";
  box.style.padding = "16px";
  box.style.maxWidth = "480px";
  box.style.width = "min(480px, 92vw)";

  const title = document.createElement("h3");
  title.textContent = "Cannot erase item";
  title.style.marginTop = "0";

  const msg = document.createElement("p");
  msg.textContent = "This item is referenced by existing grants:";

  const list = document.createElement("ul");
  for (const g of grants) {
    const li = document.createElement("li");
    li.textContent = g.requester_email;
    list.appendChild(li);
  }

  const hint = document.createElement("p");
  hint.textContent = "You can keep the grants and item, or remove them.";
  hint.style.fontSize = "0.9rem";
  hint.style.color = "#666";

  const buttonRow = document.createElement("div");
  buttonRow.style.display = "flex";
  buttonRow.style.justifyContent = "flex-end";
  buttonRow.style.gap = "8px";
  buttonRow.style.marginTop = "16px";

  const keepBtn = document.createElement("button");
  keepBtn.type = "button";
  keepBtn.className = "btn";
  keepBtn.textContent = "Keep grant(s) and item";

  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "btn primary";
  removeBtn.textContent = "Remove grant(s) and item";

  keepBtn.addEventListener("click", () => {
    backdrop.remove();
    setStateChip("Ready", "muted");
    setStatus("Item kept; grants unchanged.", "muted");
  });

  removeBtn.addEventListener("click", async () => {
    keepBtn.disabled = true;
    removeBtn.disabled = true;

    try {
      setStateChip("Revoking…", "warn");
      setStatus("Revoking grants…");

      for (const g of grants) {
        try {
          await revokeGrant(api, g);
        } catch (err) {
          setStateChip("Error", "err");
          setStatus(err?.message || "Failed to revoke one of the grants.", "err");
          return;
        }
      }

      setStateChip("Erasing…", "warn");
      setStatus("Erasing item…");

      try {
        await api.eraseItem(itemId);
      } catch (err) {
        if (err.status === 409) {
          setStateChip("Error", "err");
          setStatus("Still blocked by grants after revocation attempt.", "err");
          return;
        }
        if (err.status === 404 && err.data?.detail === "item_not_found") {
          setStateChip("Error", "err");
          setStatus("Item not found on server. Removing local copy.", "err");
        } else {
          setStateChip("Error", "err");
          setStatus(err?.message || "Failed to erase item after revoking grants.", "err");
          return;
        }
      }

      removeLocalItem(store, itemId, tr);

      setStateChip("Ready", "ok");
      setStatus("Grants and item removed.");

    } finally {
      backdrop.remove();
    }
  });

  buttonRow.appendChild(keepBtn);
  buttonRow.appendChild(removeBtn);

  box.appendChild(title);
  box.appendChild(msg);
  box.appendChild(list);
  box.appendChild(hint);
  box.appendChild(buttonRow);
  backdrop.appendChild(box);

  document.body.appendChild(backdrop);
}

async function handleEraseItemClick(api, store, itemId, tr) {
  if (!itemId) return;

  setStateChip("Erasing…", "warn");
  setStatus("Erasing item…");

  try {
    await api.eraseItem(itemId);

    removeLocalItem(store, itemId, tr);

    setStateChip("Ready", "ok");
    setStatus("Item erased.");
  } catch (err) {
    if (err.status === 409 &&
        err.data?.error === "grants_exist" &&
        Array.isArray(err.data.grants)) {
      setStateChip("Blocked", "warn");
      setStatus("Item is used in one or more grants.", "warn");
      showEraseBlockedOverlay(
        api,
        store,
        itemId,
        tr,
        err.data.grants);
      return;
    }

    if (err.status === 404 && err.data?.detail === "item_not_found") {
      setStateChip("Error", "err");
      setStatus("Item not found on server. Removing local copy.", "err");
      removeLocalItem(store, itemId, tr);
      return;
    }

    setStateChip("Error", "err");
    setStatus(err?.message || "Failed to erase item.", "err");
    return;
  }
}

export function appendRowToGui(api, store, itemName, valueStr, itemId) {
  const panel = document.querySelector('.panel[data-panel="personal"]');
  const tbody = panel?.querySelector("tbody");
  if (!tbody) return;

  const tr = document.createElement("tr");
  if (itemId) tr.dataset.itemId = itemId;

  const td1 = document.createElement("td");
  { const { wrapper } = makePersonalCell(itemName, "Item Name"); td1.appendChild(wrapper); }

  const td2 = document.createElement("td");
  {
    const rowContainer = document.createElement("div");
    rowContainer.style.display = "flex";
    rowContainer.style.alignItems = "center";

    const { wrapper } = makePersonalCell(valueStr, "Value");
    rowContainer.appendChild(wrapper);

    if (api && store && itemId) {
      const eraseBtn = document.createElement("button");
      eraseBtn.type = "button";
      eraseBtn.className = "btn btn-erase";
      eraseBtn.textContent = "Erase";
      eraseBtn.style.marginLeft = "0.5rem";

      eraseButtons.add(eraseBtn);

      const ctrlDown = document.body.classList.contains("ctrl-down");
      if (ctrlDown) {
        eraseBtn.classList.add("btn-armed");
      } else {
        eraseBtn.classList.add("btn-disarmed");
      }

      eraseBtn.addEventListener("click", (ev) => {
        if (!(ev.ctrlKey && ev.button === 0)) return;
        void handleEraseItemClick(api, store, itemId, tr);
      });

      rowContainer.appendChild(eraseBtn);
    }

    td2.appendChild(rowContainer);
  }

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
      appendRowToGui(api, store, itemName, valueStr, itemId);
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

  let ctrlDown = false;

  const setCtrlDown = (on) => {
    const next = !!on;
    if (ctrlDown === next) return;
    ctrlDown = next;
    document.body.classList.toggle("ctrl-down", ctrlDown);
    refreshEraseButtons();
  };

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Control") setCtrlDown(true);
  });

  document.addEventListener("keyup", (ev) => {
    if (ev.key === "Control") setCtrlDown(false);
  });

  window.addEventListener("blur", () => setCtrlDown(false));

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) setCtrlDown(false);
  });

  setCtrlDown(false);


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