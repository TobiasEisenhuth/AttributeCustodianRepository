// /app/builder.js
// Purpose: ONLY Request Builder business logic (no view toggling).
// - Generates per-item Umbral keypair on "Use input"
// - Persists secret keys in store.persistent.requester.items
// - Maintains single outbound draft in store.ephemeral.requester.outBound
// - Renders "Compounded Items" list and count
// - Encrypts/saves private on each add

// ---- small local helpers (keep module self-contained) ----
function base64ToBytes(b64) {
  const s = atob(b64);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
}
function bytesToBase64(bytes) {
  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}
// URL-safe base64 (for IDs)
function b64urlFromBytes(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function newItemId() {
  const rnd = crypto.getRandomValues(new Uint8Array(18)); // 144 bits
  return "itm_" + b64urlFromBytes(rnd);
}

function q(sel, root = document) { return root.querySelector(sel); }
function qa(sel, root = document) { return Array.from(root.querySelectorAll(sel)); }

// Ensure nested objects/arrays exist and return a reference
function ensure(obj, path, finalType = "object") {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length; i++) {
    const k = parts[i];
    const isLast = i === parts.length - 1;
    if (!(k in cur) || cur[k] == null) {
      cur[k] = isLast
        ? (finalType === "array" ? [] : {})
        : {};
    }
    cur = cur[k];
  }
  return cur;
}

// ---- DOM hooks for the builder view ----
function getDomRefs() {
  const formPanel   = q('.panel[data-panel="builder-form"]');
  const itemsPanel  = q('.panel[data-panel="builder-items"]');

  // Form inputs (HTML will use Recipient; we also accept legacy To just in case)
  const infoInput      = formPanel?.querySelector('input[data-field="Info String"]') || null;
  const recipientInput = formPanel?.querySelector('input[data-field="Recipient"], input[data-field="To"]') || null;
  const nameInput      = formPanel?.querySelector('input[data-field="Item Name"]') || null;
  const exampleInput   = formPanel?.querySelector('input[data-field="Example Value"]') || null;
  const defaultInput   = formPanel?.querySelector('input[data-field="Default Field"]') || null;

  const applyBtn   = formPanel?.querySelector('[data-action="builder-apply"]') || null;

  const tbody      = itemsPanel?.querySelector('tbody') || null;
  const countEl    = itemsPanel?.querySelector('.column-title .count') || null;
  const commitBtn  = itemsPanel?.querySelector('[data-action="builder-commit"]') || null;

  return {
    formPanel, itemsPanel,
    infoInput, recipientInput, nameInput, exampleInput, defaultInput,
    applyBtn, tbody, countEl, commitBtn
  };
}

// Render the right-hand table from ephemeral.requester.outBound
function renderList({ vault, tbody, countEl, commitBtn }) {
  const s = vault.store || {};
  const outBound = s?.ephemeral?.requester?.outBound || null;

  // Clear
  if (tbody) tbody.innerHTML = "";

  let itemCount = 0;

  // Header rows first (non-counting)
  if (outBound?.header) {
    const { info_string = "", recipient = "" } = outBound.header || {};
    if (tbody) {
      const tr1 = document.createElement("tr");
      tr1.innerHTML = `<th scope="row">Info String</th><td>${info_string}</td>`;
      tbody.appendChild(tr1);

      const tr2 = document.createElement("tr");
      tr2.innerHTML = `<th scope="row">Recipient</th><td>${recipient}</td>`;
      tbody.appendChild(tr2);
    }
  }

  // Items
  const items = Array.isArray(outBound?.items) ? outBound.items : [];
  for (const it of items) {
    const tr = document.createElement("tr");
    const label = it?.item_name ?? it?.item_id ?? "";
    const value = it?.example_value ?? "";
    tr.innerHTML = `<th scope="row">${label}</th><td>${value}</td>`;
    tbody?.appendChild(tr);
    itemCount++;
  }

  if (countEl) countEl.textContent = String(itemCount);
  if (commitBtn) commitBtn.disabled = itemCount === 0;

  // Notify (simple, optional)
  window.dispatchEvent(new CustomEvent("builder:listchange", { detail: { items, count: itemCount } }));
}

// Collision check against private.requester.items only
function hasCollision({ vault }, candidateId) {
  const list = vault?.store?.persistent?.requester?.items;
  if (!Array.isArray(list)) return false;
  return list.some(e => e?.item_id === candidateId);
}

// Save private side (encrypt + mark dirty) and mirror whole store to session
async function persistPrivate({ vault }) {
  try { sessionStorage.setItem('crs:userStore', JSON.stringify(vault.store || {})); } catch {}
  await vault.encryptAndCachePrivate();
  vault.setDirty(true);
}

export function wireUpRequestBuilder({ vault, loadUmbral, setStatus, setStateChip }) {
  const dom = getDomRefs();
  if (!dom.formPanel || !dom.itemsPanel) return; // builder view not present

  // Initial paint (in case something is already in store)
  renderList({ vault, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });

  // Apply button = add one sub-request
  dom.applyBtn?.addEventListener("click", async () => {
    // Read & trim inputs
    const info_string = (dom.infoInput?.value || "").trim();
    const recipient   = (dom.recipientInput?.value || "").trim();   // was "To"
    const item_name   = (dom.nameInput?.value || "").trim();
    const example_val = (dom.exampleInput?.value || "").trim();

    // "Default Field" is currently forced to "None" regardless of user text
    const default_field = "None";

    // Validate required fields
    if (!recipient || !item_name || !example_val) {
      setStatus("Recipient, Item Name, and Example Value are required.", "err");
      return;
    }

    // Load Umbral
    const umbral = await loadUmbral();
    if (!umbral) { setStatus("Umbral not loaded.", "err"); return; }

    // Generate per-item keypair
    const sk = umbral.SecretKey.random();
    const pk = sk.publicKey();

    const secret_key_b64  = bytesToBase64(sk.toBEBytes());
    const public_key_b64  = bytesToBase64(pk.toCompressedBytes());

    // Ensure store scaffolding (new layout)
    const s = vault.store || (vault.store = {});
    const prvProviderItems = ensure(s, "private.provider.items", "array");
    const prvRequesterItems = ensure(s, "private.requester.items", "array");

    const ephProviderValues = ensure(s, "ephemeral.provider.values");
    const outBound = ensure(s, "ephemeral.requester.outBound");
    outBound.header = outBound.header || { info_string: "", recipient: "" };
    outBound.items  = Array.isArray(outBound.items) ? outBound.items : [];

    let item_id = newItemId();
    for (let i = 0; i < 5 && hasCollision({ vault }, item_id); i++) {
      item_id = newItemId();
    }
    if (hasCollision({ vault }, item_id)) {
      setStatus("Failed to allocate unique item id. Try again.", "err");
      return;
    }

    // Persist secret key under private.requester.items
    prvRequesterItems.push({
      item_id,
      item_name,
      keys: { secret_key_b64 },
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    // Update ephemeral outbound draft (single request)
    outBound.header.info_string = info_string;
    outBound.header.recipient   = recipient;
    outBound.items.push({
      item_id,
      item_name,
      example_value: example_val,
      default_field,
      public_key_b64,
    });

    // Save + mark unsaved state
    setStateChip("Saving…", "warn");
    try {
      await persistPrivate({ vault });
      setStateChip("Unsaved", "warn"); // private differs from lastSaved until sync
      setStatus("Row added to draft.", "ok");
    } catch (e) {
      setStateChip("Error", "err");
      setStatus(e?.message || "Failed to save.", "err");
      return;
    }

    // Re-render the right-hand list
    renderList({ vault, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });
  });

  // Commit button: emit event (no business logic yet)
  dom.commitBtn?.addEventListener("click", () => {
    const s = vault.store || {};
    const outBound = s?.ephemeral?.requester?.outBound || { header: {}, items: [] };
    window.dispatchEvent(new CustomEvent("builder:confirm", { detail: outBound }));
  });

  // Optional: keep count fresh when navigating back to this view
  window.addEventListener("viewchange", (e) => {
    if (e?.detail?.view !== "builder") return;
    renderList({ vault, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });
  });
}

