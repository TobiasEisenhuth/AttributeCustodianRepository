// /app/items-add.js
import { loadUmbral } from "/app/umbral-loader.js";

/* ---------- tiny utils ---------- */
const enc = new TextEncoder();

function bytesToBase64(bytes) {
  // Safe for typical ciphertext/capsule sizes
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64UrlFromBytes(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeItemName(s) {
  return String(s ?? "").trim();
}

/**
 * Generate a collision-free, random item_id.
 * 128-bit randomness -> base64url(22 chars), no info about user/item/count.
 */
function generateItemId(existingIds) {
  let id;
  do {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    id = base64UrlFromBytes(buf);
  } while (existingIds.has(id));
  return id;
}

/* ---------- DOM helpers (matches your table structure) ---------- */
function makePersonalCell(initialValue, placeholder) {
  const wrapper = document.createElement("div");
  wrapper.className = "cell read-mode";

  const ro = document.createElement("span");
  ro.className = "ro-text";
  ro.textContent = initialValue || "";

  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = placeholder || "";
  input.autocomplete = "off";
  input.readOnly = true;   // read-mode by default
  input.tabIndex = 0;

  wrapper.appendChild(ro);
  wrapper.appendChild(input);
  return { wrapper, ro, input };
}

function appendRowToPersonal(itemName, value) {
  const panel = document.querySelector('.panel[data-panel="personal"]');
  const tbody = panel?.querySelector("tbody");
  if (!tbody) return;

  const tr = document.createElement("tr");

  // Field / Item Name
  const td1 = document.createElement("td");
  {
    const { wrapper } = makePersonalCell(itemName, "Field");
    td1.appendChild(wrapper);
  }

  // Value (plaintext lives in DOM only)
  const td2 = document.createElement("td");
  {
    const { wrapper } = makePersonalCell(value, "Value");
    td2.appendChild(wrapper);
  }

  tr.appendChild(td1);
  tr.appendChild(td2);
  tbody.appendChild(tr);
}

/* ---------- main wiring ---------- */
/**
 * Hook the "Add" button to create + encrypt + upload an item,
 * then update the vault and the Personal table.
 *
 * @param {object} args
 * @param {object} args.api      - CRSClient instance
 * @param {object} args.vault    - return value of initVault(...) (needs .store, .ensureVaultShape, .encryptAndCachePrivate)
 * @param {function} args.setStatus     - UI status(line)
 * @param {function} args.setStateChip  - UI state chip
 */
export function wireAddItemWithUmbral({ api, vault, setStatus = () => {}, setStateChip = () => {} }) {
  const dialog = document.getElementById("new-item-dialog");
  if (!dialog) return;

  const btnAdd = dialog.querySelector('[data-action="confirm-dialog"]');
  const btnCancel = dialog.querySelector('[data-action="cancel-dialog"]');

  // Avoid wiring twice if this function is called again
  if (!btnAdd || btnAdd.dataset.wiredUmbral === "1") return;
  btnAdd.dataset.wiredUmbral = "1";

  btnAdd.addEventListener("click", async (ev) => {
    ev.preventDefault();
    if (btnAdd.disabled) return;
    if (btnAdd.dataset.busy === "1") return;  // avoid double-click races
    btnAdd.dataset.busy = "1";

    try {
      // Collect fields from modal
      const itemName = normalizeItemName(dialog.querySelector('input[data-field="Item Name"]')?.value);
      const valueStr = String(dialog.querySelector('input[data-field="Value"]')?.value ?? "");
      if (!itemName) { setStatus("Please provide an item name.", "err"); return; }
      if (!valueStr)  { setStatus("Please provide a value.", "err"); return; }

      // Load Umbral
      const umbral = await loadUmbral();
      if (!umbral) { setStatus("Umbral not loaded; cannot add item.", "err"); return; }

      setStateChip("Encrypting…");
      setStatus("Encrypting item…");

      // 1) Generate per-item key material
      const delegating_sk = umbral.SecretKey.random();
      const delegating_pk = delegating_sk.publicKey();
      const signing_sk    = umbral.SecretKey.random();
      const verifying_pk  = signing_sk.publicKey();

      // 2) Encrypt plaintext value to provider key
      const ptBytes = enc.encode(valueStr);
      const [capsule, ciphertext] = umbral.encrypt(delegating_pk, ptBytes);
      if (!(capsule instanceof umbral.Capsule)) throw new Error("Umbral encrypt(): first element is not a Capsule");
      if (!(ciphertext instanceof Uint8Array)) throw new Error("Umbral encrypt(): second element is not Uint8Array");

      // 3) Build server payload
      const s = vault.store || {};
      const items = s?.private?.items || [];
      const existing = new Set(items.map(it => it?.item_id).filter(Boolean));
      const item_id = generateItemId(existing);

      const payload = {
        item_id,
        capsule_b64: bytesToBase64(capsule.toBytes()),
        ciphertext_b64: bytesToBase64(ciphertext),
        provider_public_key_b64:     bytesToBase64(delegating_pk.toCompressedBytes()),
        provider_verifying_key_b64:  bytesToBase64(verifying_pk.toCompressedBytes()),
      };

      // 4) Upload to service
      setStateChip("Saving…");
      setStatus("Saving encrypted item to server…");
      await api.upsertItem(payload);

      // 5) Update local vault store (NO PLAINTEXT), then re-encrypt+cache
      const entry = {
        item_id,
        item_name: itemName,
        keys: {
          secret_key_b64:  bytesToBase64(delegating_sk.toBEBytes()),
          signing_key_b64: bytesToBase64(signing_sk.toBEBytes()),
        },
        created_at: nowIso(),
        updated_at: nowIso(),
      };

      const shape = (obj) => {
        const root = vault.ensureVaultShape?.(obj) || (obj || {});
        root.private = root.private || {};
        root.private.items = root.private.items || [];
        return root;
      };

      const store = shape(vault.store || {});
      const idx = store.private.items.findIndex(i => i.item_id === item_id);
      if (idx === -1) store.private.items.push(entry);
      else store.private.items[idx] = { ...store.private.items[idx], ...entry, updated_at: nowIso() };

      try { sessionStorage.setItem('crs:store', JSON.stringify(store)); } catch {}
      await (vault.encryptAndCachePrivate?.());

      setStateChip("Synced", "ok");
      setStatus(`Item "${itemName}" saved.`, "ok");

      // 6) Update UI with plaintext (DOM-only)
      appendRowToPersonal(itemName, valueStr);

      // 7) Close modal
      dialog.classList.remove("open");
      dialog.setAttribute("aria-hidden", "true");
    } catch (e) {
      console.error(e);
      setStateChip("Error", "err");
      setStatus(e?.message || "Failed to add item.", "err");
    } finally {
      delete btnAdd.dataset.busy;
    }
  });
}
