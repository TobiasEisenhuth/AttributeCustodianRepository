import { CRSClient } from "/app/crs-sdk.js";
import { initVault } from "/app/vault.js";

import {
  wireAddItemWithUmbral,
  appendRowToPersonal,
  makePersonalCell,
} from "/app/items-add.js";

import { wireLogoutAndSync } from "/app/logout.js";
import { loadUmbral } from "/app/umbral-loader.js";

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8");

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

const api = new CRSClient();

/* === read+remove passkey/email ASAP (your existing code) === */
const PASSKEY = (() => {
  const k = sessionStorage.getItem("crs:passkey") || null;
  if (k) sessionStorage.removeItem("crs:passkey");
  return k;
})();
const EMAIL = (() => {
  const e = sessionStorage.getItem("crs:email") || null;
  if (e) sessionStorage.removeItem("crs:email");
  return e;
})();
const IS_OWNER_TAB = !!PASSKEY;

/* === set the Personal title (optional) === */
if (EMAIL) {
  window.addEventListener("DOMContentLoaded", () => {
    const title = document.querySelector('.panel[data-panel="personal"] .column-title');
    if (title) title.textContent = `Personal Data | ${EMAIL}`;
  }, { once: true });
    window.addEventListener("DOMContentLoaded", () => {
    const title = document.querySelector('.panel[data-panel="builder-form"] .column-title');
    if (title) title.textContent = `Item builder | ${EMAIL}`;
  }, { once: true });
}

/* === UI hooks you already use === */
function setStateChip(text, tone = "muted") {
  const el = document.getElementById("state-chip");
  if (!el) return;
  el.textContent = text;
  el.className = `chip ${tone}`;
}
function setStatus(text, tone = "muted") {
  const el = document.getElementById("status-line");
  if (!el) return;
  el.textContent = text;
  el.className = tone;
}
function updateButtons() {}

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
  const localItems = Array.isArray(s?.private?.items) ? s.private.items : [];

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

  // Build lookup and hydrate plaintext into ephemeral (not persisted)
  const byId = new Map(serverItems.map(x => [x.item_id, x]));
  s.ephemeral = s.ephemeral || {};
  s.ephemeral.personal = s.ephemeral.personal || {};
  const values = (s.ephemeral.personal.valuesById = {});

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
    const val  = s?.ephemeral?.personal?.valuesById?.[entry?.item_id] ?? "";
    const itemId = entry?.item_id
    appendRowToPersonal(name, val, itemId);
  }

  if (addBtn) addBtn.disabled = false;
}

/* === Initialize vault and load, only for owner tab === */
let vault = null;
if (IS_OWNER_TAB) {
  vault = initVault({ api, passkey: PASSKEY, email: EMAIL, ui: { setStateChip, setStatus, updateButtons } });
  (async () => {
    try {
      await vault.loadVault();
      await hydrateAndRenderPersonal({ api, vault });
    } finally {
      // hook up the Add dialog last (so first click won’t race hydration)
      wireAddItemWithUmbral({ api, vault, setStatus, setStateChip });
    }
  })();
  wireLogoutAndSync({ api, vault, setStatus, setStateChip });

} else {
  // Non-owner tab: show your "already open" overlay (you already do this)
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay open';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="tabLockTitle">
      <h3 id="tabLockTitle" class="modal-title">Already Open in Another Tab</h3>
      <div class="modal-body"><p>You are already using a different tab. Close this tab and go back to the original tab.</p></div>
    </div>`;
  if (document.body) document.body.appendChild(overlay);
  else window.addEventListener('DOMContentLoaded', () => document.body.appendChild(overlay), { once: true });
}

/* =====================  LAST-TAB LOGOUT (DO NOT LOG OUT OTHERS)  ===================== */

// Cross-tab presence to know if we’re the last dashboard tab.
const bc = ("BroadcastChannel" in window) ? new BroadcastChannel("crs:dashboard:presence") : null;
const tabId = (crypto?.randomUUID?.()) || (Date.now().toString(36) + Math.random().toString(36).slice(2));
const peers = new Set();

if (bc) {
  bc.onmessage = (e) => {
    const msg = e?.data || {};
    if (!msg || msg.id === tabId) return;
    if (msg.t === "hello") {
      peers.add(msg.id);
      bc.postMessage({ t: "iam", id: tabId });
    } else if (msg.t === "iam") {
      peers.add(msg.id);
    } else if (msg.t === "bye") {
      peers.delete(msg.id);
    }
  };
  // Announce presence
  bc.postMessage({ t: "hello", id: tabId });
}

// Only when the **last** tab closes, clear storage + logout.
// Non-last tabs do nothing, so they won’t kill the session of the owner tab.
let didClose = false;
function clearAndMaybeLogout() {
  if (didClose) return;
  didClose = true;

  try { bc && bc.postMessage({ t: "bye", id: tabId }); } catch {}

  // If BroadcastChannel unsupported, we can’t safely know last-tab. Be conservative: do nothing.
  if (!bc) return;

  // Last tab => clear + logout (keepalive)
  if (peers.size === 0) {
    try { sessionStorage.clear(); } catch {}
    try { api.logout({ keepalive: true }); } catch {}
  }
}

// Fire on real unloads (skip when BFCache persists the page)
window.addEventListener("pagehide", (e) => { if (!e.persisted) clearAndMaybeLogout(); });
window.addEventListener("beforeunload", clearAndMaybeLogout);

/* =====================  EXISTING DASHBOARD UI LOGIC (unchanged)  ===================== */
/*  The rest is your table/UX code. It runs in all tabs, but the overlay blocks non-owner tabs. */

function enterEditMode(wrapper, input) {
  input.readOnly = false;
  input.classList.add('editing');
  wrapper.classList.remove('read-mode');
  wrapper.classList.add('edit-mode');
  setTimeout(() => { input.focus(); }, 0);
}

function exitEditMode(wrapper, ro, input) {
  ro.textContent = input.value || '';
  input.readOnly = true;
  input.classList.remove('editing');
  wrapper.classList.remove('edit-mode');
  wrapper.classList.add('read-mode');
}

/* ---------------- Row creation ---------------- */

function createRow(panelEl) {
  const isRequests = panelEl?.dataset.panel === 'requests';
  const tr = document.createElement('tr');

  // First column
  const td1 = document.createElement('td');
  if (isRequests) {
    const input1 = document.createElement('input');
    input1.type = 'text';
    input1.placeholder = 'Request';
    input1.autocomplete = 'off';
    td1.appendChild(input1);
  } else {
    const { wrapper } = makePersonalCell('', 'Field');
    td1.appendChild(wrapper);
  }

  // Second column
  const td2 = document.createElement('td');
  if (isRequests) {
    const input2 = document.createElement('input');
    input2.type = 'text';
    input2.placeholder = 'Details';
    input2.autocomplete = 'off';
    td2.appendChild(input2);
  } else {
    const { wrapper } = makePersonalCell('', 'Value');
    td2.appendChild(wrapper);
  }

  tr.appendChild(td1);
  tr.appendChild(td2);
  return tr;
}

function updateRequestsCount(panelEl) {
  if (!panelEl || panelEl.dataset.panel !== 'requests') return;
  const tbody = panelEl.querySelector('tbody');
  const countEl = panelEl.querySelector('.column-title .count');
  if (tbody && countEl) countEl.textContent = String(tbody.rows.length);
}

function addRowForPanel(panelEl) {
  const tbody = panelEl.querySelector('tbody');
  if (!tbody) return;
  const row = createRow(panelEl);
  tbody.appendChild(row);
  updateRequestsCount(panelEl);
}

/* ---------------- New Item Modal (Personal -> Add row) ---------------- */

const newItemOverlay = document.getElementById('new-item-dialog');
const newItemConfirm = newItemOverlay?.querySelector('[data-action="confirm-dialog"]');
const newItemCancel  = newItemOverlay?.querySelector('[data-action="cancel-dialog"]');

function openNewItemDialog() {
  if (!newItemOverlay) return;
  newItemOverlay.querySelectorAll('input[type="text"]').forEach((inp) => { inp.value = ''; });
  if (newItemConfirm) newItemConfirm.disabled = true;
  newItemOverlay.classList.add('open');
  const first = newItemOverlay.querySelector('input[data-field="Item Name"]');
  if (first) first.focus();
}
function closeNewItemDialog() { newItemOverlay?.classList.remove('open'); }

function validateNewItemDialog() {
  if (!newItemOverlay || !newItemConfirm) return;
  const name  = newItemOverlay.querySelector('input[data-field="Item Name"]').value.trim();
  const value = newItemOverlay.querySelector('input[data-field="Value"]').value.trim();
  newItemConfirm.disabled = !(name && value);
}

newItemOverlay?.addEventListener('input', (e) => {
  if (e.target.matches('.modal-table input[type="text"]')) validateNewItemDialog();
});
newItemCancel?.addEventListener('click', closeNewItemDialog);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && newItemOverlay?.classList.contains('open')) closeNewItemDialog();
});
newItemOverlay?.addEventListener('mousedown', (e) => {
  if (e.target === newItemOverlay) closeNewItemDialog();
});

/* ----------- Ctrl + Left-click editing (PERSONAL ONLY) ----------- */
(function setupCtrlClickEditing() {
  const personalPanel = document.querySelector('.panel[data-panel="personal"]');
  if (!personalPanel) return;
  const tbody = personalPanel.querySelector('tbody');

  // Track Ctrl key for hover-caret CSS (.ctrl-down on <body>)
  function setCtrlDown(on) { document.body.classList.toggle('ctrl-down', !!on); }
  document.addEventListener('keydown', (e) => { if (e.ctrlKey) setCtrlDown(true); });
  document.addEventListener('keyup', (e) => {
    if (e.key === 'Control' || !e.ctrlKey) setCtrlDown(false);
  });
  window.addEventListener('blur', () => setCtrlDown(false));

  // Mousedown handler controls mode switching
  personalPanel.addEventListener('mousedown', (e) => {
    const td = e.target.closest('td');
    if (!td) return;
    const wrapper = td.querySelector('.cell');
    if (!wrapper) return;
    const input = wrapper.querySelector('input[type="text"]');
    const ro = wrapper.querySelector('.ro-text');
    if (!input || !ro || !tbody.contains(wrapper)) return;

    // Right-click: prevent caret & exit edit mode if active
    if (e.button === 2) {
      e.preventDefault();
      exitEditMode(wrapper, ro, input);
      return;
    }

    // Ctrl + left-click: enter edit mode
    if (e.button === 0 && e.ctrlKey) {
      enterEditMode(wrapper, input);
      return;
    }
  });

  // Exit edit mode on Enter/Escape -> blur
  personalPanel.addEventListener('keydown', (e) => {
    const input = e.target;
    if (!(input instanceof HTMLInputElement)) return;
    if (e.key === 'Enter' || e.key === 'Escape') input.blur();
  });

  personalPanel.addEventListener('blur', async (e) => {
    const input = e.target;
    if (!(input instanceof HTMLInputElement)) return;

    const wrapper = input.closest('.cell');
    const ro = wrapper?.querySelector('.ro-text');
    const td = wrapper?.closest('td');
    const tr = wrapper?.closest('tr');
    if (!wrapper || !ro || !td || !tr) return;

    // Capture old before we overwrite the ro-text
    const oldVal = (ro.textContent || "").trim();

    // Leave edit mode visually
    exitEditMode(wrapper, ro, input);

    // Commit if actually changed
    const newVal = (input.value || "").trim();
    if (newVal === oldVal) return;

    // Identify which column (0 = name, 1 = value)
    const colIndex = Array.prototype.indexOf.call(td.parentElement.children, td);
    const itemId = tr.dataset.itemId || null;

    // Only the owner tab can persist
    if (!IS_OWNER_TAB) return;

    try {
      if (colIndex === 0) {
        // --- ITEM NAME EDIT -> update user store only ---
        const store = vault.store || {};
        const items = store?.private?.items || [];
        const entry = items.find(it => it?.item_id === itemId);
        if (!entry) throw new Error("Item not found in store");
        if (!newVal) throw new Error("Item name cannot be empty");

        entry.item_name = newVal;
        entry.updated_at = new Date().toISOString();

        // mirror to session + re-encrypt/cached (no server save here; logout will sync)
        try { sessionStorage.setItem('crs:store', JSON.stringify(store)); } catch {}
        await vault.encryptAndCachePrivate();
        vault.setDirty(true);
        setStatus(`Name updated.`, "ok");
        setStateChip("Unsaved", "warn");   // vault differs from lastSaved
      } else if (colIndex === 1) {
        // --- VALUE EDIT -> re-encrypt & upsert to service ---
        if (!newVal) { 
          // decide policy; here we reject empties like in "add"
          setStatus("Value cannot be empty.", "err");
          // revert UI
          ro.textContent = oldVal; input.value = oldVal;
          return;
        }

        const store = vault.store || {};
        const items = store?.private?.items || [];
        const entry = items.find(it => it?.item_id === itemId);
        if (!entry?.keys?.secret_key_b64) throw new Error("Missing secret key for this item");

        const umbral = await loadUmbral();
        if (!umbral) throw new Error("Umbral not loaded");

        // Re-encrypt with existing provider keys
        const delegating_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(entry.keys.secret_key_b64));
        const delegating_pk = delegating_sk.publicKey();

        // Signing/verifying key is optional in payload; include if present
        let verifying_pk_b64 = null;
        if (entry.keys.signing_key_b64) {
          const signing_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(entry.keys.signing_key_b64));
          const signer = new umbral.Signer(signing_sk);
          const verifying_pk = signer.verifyingKey();
          verifying_pk_b64 = bytesToBase64(verifying_pk.toCompressedBytes());
        }

        const ptBytes = enc.encode(newVal);
        const [capsule, ciphertext] = umbral.encrypt(delegating_pk, ptBytes);

        const payload = {
          item_id: itemId,
          capsule_b64: bytesToBase64(capsule.toBytes()),
          ciphertext_b64: bytesToBase64(ciphertext),
          provider_public_key_b64: bytesToBase64(delegating_pk.toCompressedBytes()),
        };
        if (verifying_pk_b64) payload.provider_verifying_key_b64 = verifying_pk_b64;

        setStateChip("Saving…", "warn");
        setStatus("Updating encrypted value…");

        await api.upsertItem(payload);

        // Optionally bump local updated_at so vault shows activity; no plaintext stored
        entry.updated_at = new Date().toISOString();
        try { sessionStorage.setItem('crs:store', JSON.stringify(store)); } catch {}
        await vault.encryptAndCachePrivate();
        vault.setDirty(true);

        setStateChip("Synced", "ok");
        setStatus("Item value updated.", "ok");
      }
    } catch (err) {
      // revert UI on failure
      ro.textContent = oldVal;
      input.value = oldVal;
      setStateChip("Error", "err");
      setStatus(err?.message || "Failed to save edit.", "err");
    }
  }, true);
})();

/* ---------------- Event wiring ---------------- */
document.addEventListener('click', function (e) {
  const btn = e.target.closest('[data-action="add-row"]');
  if (!btn || btn.disabled) return;
  const panelEl = btn.closest('.panel');
  if (!panelEl) return;

  if (panelEl.dataset.panel === 'personal') {
    openNewItemDialog();
  } else {
    addRowForPanel(panelEl);
  }
});

// Initialize requests count on load
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.panel').forEach(updateRequestsCount);
});
