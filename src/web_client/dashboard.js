import { CRSClient } from "/app/crs-sdk.js";
import { initVault } from "/app/vault.js";          // from earlier step
import { wireAddItemWithUmbral } from "/app/items-add.js";
import { wireLogoutAndSync } from "/app/logout.js";
import { loadUmbral } from "/app/umbral-loader.js";

const dec = new TextDecoder();
function base64ToBytes(b64) {
  const s = atob(b64);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
}

function appendPersonalRow(itemName, valueStr) {
  const panel = document.querySelector('.panel[data-panel="personal"]');
  const tbody = panel?.querySelector("tbody");
  if (!tbody) return;

  const tr = document.createElement("tr");

  const td1 = document.createElement("td");
  td1.appendChild(makePersonalCell(itemName || "", "Field").wrapper);

  const td2 = document.createElement("td");
  td2.appendChild(makePersonalCell(valueStr || "", "Value").wrapper);

  tr.appendChild(td1);
  tr.appendChild(td2);
  tbody.appendChild(tr);
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
    appendPersonalRow(name, val);
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

function makePersonalCell(initialValue, placeholder) {
  // <div class="cell read-mode"><span class="ro-text"></span><input ...></div>
  const wrapper = document.createElement('div');
  wrapper.className = 'cell read-mode';

  const ro = document.createElement('span');
  ro.className = 'ro-text';
  ro.textContent = initialValue || '';

  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = placeholder || '';
  input.autocomplete = 'off';
  input.readOnly = true; // read-mode by default
  input.tabIndex = 0;

  wrapper.appendChild(ro);
  wrapper.appendChild(input);

  return { wrapper, ro, input };
}

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

    // Plain left click: read-mode text can be selected/copy; do nothing
  });

  // Exit edit mode on Enter/Escape -> blur
  personalPanel.addEventListener('keydown', (e) => {
    const input = e.target;
    if (!(input instanceof HTMLInputElement)) return;
    if (e.key === 'Enter' || e.key === 'Escape') input.blur();
  });

  // On blur: lock and remove edit border, sync text
  personalPanel.addEventListener('blur', (e) => {
    const input = e.target;
    if (!(input instanceof HTMLInputElement)) return;
    const wrapper = input.closest('.cell');
    const ro = wrapper?.querySelector('.ro-text');
    if (!wrapper || !ro || !tbody.contains(wrapper)) return;
    exitEditMode(wrapper, ro, input);
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
