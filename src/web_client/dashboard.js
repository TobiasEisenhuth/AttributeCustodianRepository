import { CRSClient } from "/app/crs-sdk.js";
import { initVault } from "/app/vault.js";          // from earlier step
import { wireAddItemWithUmbral } from "/app/items-add.js";

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
function setStateChip(text, tone) { /* no-op or update a chip */ }
function setStatus(text, tone)     { /* no-op or status line */ }
function updateButtons()           { /* enable/disable UI */ }

/* === Initialize vault and load, only for owner tab === */
let vault = null;
if (IS_OWNER_TAB) {
  vault = initVault({ api, passkey: PASSKEY, email: EMAIL, ui: { setStateChip, setStatus, updateButtons } });
  // Immediately load the vault (fetch+decrypt into Session Storage)
  vault.loadVault();
  // Wire the "Add" dialog to crypto+persist+UI
  wireAddItemWithUmbral({ api, vault, setStatus, setStateChip });
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
  if (!btn) return;
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
