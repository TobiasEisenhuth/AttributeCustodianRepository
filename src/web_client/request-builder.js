// request-builder.js
import {
  revisiting,
  normalizeText,
  setStateChip,
  setStatus,
  nowIso,
  bytesToBase64,
  base64UrlFromBytes,
} from "/app/utils.js";
import { needsSave } from "/app/save.js";
import { loadUmbral } from "/app/umbral-loader.js";

/* ------------------------- tiny helpers ------------------------- */

const q  = (sel, root = document) => root.querySelector(sel);
const qa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function newRequesterItemId() {
  const rnd = crypto.getRandomValues(new Uint8Array(18)); // 144 bits
  return "req_" + base64UrlFromBytes(rnd);
}

function injectSelectionStylesOnce() {
  if (document.getElementById("builder-selection-style")) return;
  const css = `
  /* --- form panel: cells aren't selectable & never show focus ring --- */
  .panel[data-panel="builder-form"] .data-table th,
  .panel[data-panel="builder-form"] .data-table td { user-select: none; }
  .panel[data-panel="builder-form"] table:focus,
  .panel[data-panel="builder-form"] tr:focus,
  .panel[data-panel="builder-form"] td:focus,
  .panel[data-panel="builder-form"] th:focus { outline: none !important; }

  /* --- items panel: suppress UA focus ring on rows/cells --- */
  .panel[data-panel="builder-items"] table:focus,
  .panel[data-panel="builder-items"] tr:focus,
  .panel[data-panel="builder-items"] td:focus,
  .panel[data-panel="builder-items"] th:focus { outline: none !important; }

  /* selected item look: blue background + solid accent border */
  .panel[data-panel="builder-items"] tr.selected td {
    background: rgba(0, 95, 204, .18); /* blue-ish */
    box-shadow: inset 0 0 0 2px var(--accent);
  }
  `;
  const style = document.createElement("style");
  style.id = "builder-selection-style";
  style.textContent = css;
  document.head.appendChild(style);
}

/* --------------------- DOM refs for builder --------------------- */

function getDomRefs() {
  const formPanel  = q('.panel[data-panel="builder-form"]');
  const itemsPanel = q('.panel[data-panel="builder-items"]');

  const infoInput      = formPanel?.querySelector('input[data-field="Info String"]') || null;
  const addresseeInput = formPanel?.querySelector('input[data-field="Addressee"], input[data-field="To"]') || null;
  const nameInput      = formPanel?.querySelector('input[data-field="Item Name"]') || null;
  const exampleInput   = formPanel?.querySelector('input[data-field="Example Value"]') || null;
  const defaultInput   = formPanel?.querySelector('input[data-field="Default Field"]') || null;

  const applyBtn  = formPanel?.querySelector('[data-action="builder-apply"]') || null;

  const table     = itemsPanel?.querySelector('table') || null;
  const tbody     = table?.querySelector('tbody') || null;
  const countEl   = itemsPanel?.querySelector('.column-title .count') || null;
  const commitBtn = itemsPanel?.querySelector('[data-action="builder-commit"]') || null;

  return {
    formPanel, itemsPanel,
    infoInput, addresseeInput, nameInput, exampleInput, defaultInput,
    applyBtn, table, tbody, countEl, commitBtn
  };
}

/* ------------- explicit scaffold (boring but readable) ----------- */

function initRequesterScaffold(userStore) {
  if (!userStore.persistent) userStore.persistent = {};
  if (!userStore.persistent.requester) userStore.persistent.requester = {};
  if (!Array.isArray(userStore.persistent.requester.items)) {
    userStore.persistent.requester.items = [];
  }
  if (!userStore.ephemeral) userStore.ephemeral = {};
  if (!userStore.ephemeral.requester) userStore.ephemeral.requester = {};
  if (!userStore.ephemeral.requester.outbound) userStore.ephemeral.requester.outbound = {};

  const outbound = userStore.ephemeral.requester.outbound;
  if (!outbound.header) outbound.header = {};
  if (typeof outbound.header.info_string !== "string") outbound.header.info_string = "";
  if (typeof outbound.header.addressee   !== "string") outbound.header.addressee   = "";
  if (!Array.isArray(outbound.items)) outbound.items = [];
}

/* -------------------- render right-hand table -------------------- */

function headerRow(label, value) {
  const tr = document.createElement("tr");
  tr.dataset.kind = "header";
  tr.setAttribute("tabindex", "-1");
  const td = document.createElement("td");
  td.textContent = `${label} | ${value ?? ""}`;
  tr.appendChild(td);
  return tr;
}

function itemRow(it) {
  const tr = document.createElement("tr");
  tr.dataset.kind = "item";
  tr.dataset.itemId = it.item_id;
  tr.setAttribute("tabindex", "-1");
  const td = document.createElement("td");
  const label = it?.item_name ?? it?.item_id ?? "";
  const value = it?.example_value ?? "";
  td.textContent = `${label} | ${value}`;
  tr.appendChild(td);
  return tr;
}

function renderList({ userStore, tbody, countEl, commitBtn }) {
  if (!tbody) return;
  tbody.innerHTML = "";

  const out = userStore?.ephemeral?.requester?.outbound || {};
  const header = out.header || {};
  const items  = Array.isArray(out.items) ? out.items : [];

  if (items.length > 0) {
    tbody.appendChild(headerRow("Info String", header.info_string || ""));
    tbody.appendChild(headerRow("Addressee",   header.addressee   || ""));
  }
  for (const it of items) tbody.appendChild(itemRow(it));

  if (countEl) countEl.textContent = String(items.length);
  if (commitBtn) commitBtn.disabled = items.length === 0;
}

/* ------------- mutate userStore for add / delete ops ------------- */

async function addDraftItem({ userStore, info_string, addressee, item_name, example_value, default_field }) {
  initRequesterScaffold(userStore);

  const outbound = userStore.ephemeral.requester.outbound;
  outbound.header.info_string = info_string;
  outbound.header.addressee   = addressee;

  const umbral = await loadUmbral();
  if (!umbral) throw new Error("Umbral not loaded.");

  const sk = umbral.SecretKey.random();
  const pk = sk.publicKey();
  const item_id = newRequesterItemId();

  userStore.persistent.requester.items.push({
    item_id,
    item_name,
    keys: { secret_key_b64: bytesToBase64(sk.toBEBytes()) },
    created_at: nowIso(),
    updated_at: nowIso(),
  });

  outbound.items.push({
    item_id,
    item_name,
    example_value,
    default_field,
    public_key_b64: bytesToBase64(pk.toCompressedBytes()),
  });
}

function deleteDraftItemsByIds(userStore, itemIds) {
  if (!itemIds?.size) return 0;
  initRequesterScaffold(userStore);

  const itemsP = userStore.persistent.requester.items;
  const itemsE = userStore.ephemeral.requester.outbound.items;

  let removed = 0;

  for (let i = itemsP.length - 1; i >= 0; i--) {
    const id = itemsP[i]?.item_id;
    if (itemIds.has(id)) { itemsP.splice(i, 1); removed++; }
  }
  for (let i = itemsE.length - 1; i >= 0; i--) {
    const id = itemsE[i]?.item_id;
    if (itemIds.has(id)) itemsE.splice(i, 1);
  }

  if (itemsE.length === 0) {
    const header = userStore.ephemeral.requester.outbound.header;
    header.info_string = "";
    header.addressee   = "";
  }
  return removed;
}

/* ------------------------- main wire-up -------------------------- */

export function wireUpRequestBuilder({ api, userStore }) {
  if (revisiting("wireUpRequestBuilder")) return;

  injectSelectionStylesOnce();

  const dom = getDomRefs();
  if (!dom.formPanel || !dom.itemsPanel) return;

  renderList({ userStore, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });

  dom.applyBtn?.addEventListener("click", async () => {
    const info_string   = normalizeText(dom.infoInput?.value ?? "");
    const addressee     = normalizeText(dom.addresseeInput?.value ?? "");
    const item_name     = normalizeText(dom.nameInput?.value ?? "");
    const example_val   = normalizeText(dom.exampleInput?.value ?? "");
    const default_field = normalizeText(dom.defaultInput?.value ?? "None") || "None";

    if (!info_string || !addressee || !item_name) {
      setStateChip("Error", "err");
      setStatus("Please fill Info String, Addressee, and Item Name.", "err");
      return;
    }

    try {
      setStateChip("Building…", "warn");
      setStatus("Adding item to request…", "warn");

      await addDraftItem({
        userStore,
        info_string,
        addressee,
        item_name,
        example_value: example_val || "",
        default_field,
      });

      needsSave(true);
      setStateChip("Unsaved", "warn");
      setStatus("Item added to current request.", "ok");

      if (dom.nameInput)    dom.nameInput.value = "";
      if (dom.exampleInput) dom.exampleInput.value = "";
      if (dom.defaultInput) dom.defaultInput.value = "None";

      renderList({ userStore, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });
    } catch (e) {
      setStateChip("Error", "err");
      setStatus(e?.message || "Failed to add item.", "err");
    }
  });

  /* ---------- multi-select (Ctrl+click) and clearing behavior ---------- */

  const selectedIds = new Set();

  function clearSelection() {
    selectedIds.clear();
    qa('tr[data-kind="item"].selected', dom.tbody).forEach(tr => tr.classList.remove('selected'));
  }
  function toggleRowSelection(tr) {
    if (!tr || tr.dataset.kind !== "item") return;
    const id = tr.dataset.itemId;
    if (!id) return;
    if (selectedIds.has(id)) { selectedIds.delete(id); tr.classList.remove("selected"); }
    else { selectedIds.add(id); tr.classList.add("selected"); }
  }

  // Inside items panel:
  dom.itemsPanel.addEventListener("mousedown", (e) => {
    const tr = e.target.closest("tr");
    if (!tr || !dom.tbody?.contains(tr)) return;

    // Ctrl + left click toggles items only
    if (e.button === 0 && e.ctrlKey) {
      if (tr.dataset.kind === "item") toggleRowSelection(tr);
      e.preventDefault(); e.stopPropagation();
      return;
    }

    // Plain left click anywhere in the panel clears selection
    if (e.button === 0 && !e.ctrlKey) {
      clearSelection();
    }

    // Right click clears selection
    if (e.button === 2) {
      e.preventDefault();
      clearSelection();
    }
  });

  // Click anywhere outside the items panel clears selection
  document.addEventListener("mousedown", (e) => {
    if (!dom.itemsPanel.contains(e.target)) clearSelection();
  });

  // Escape or window blur clears selection
  dom.itemsPanel.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { clearSelection(); return; }
    if (selectedIds.size === 0) return;
    if (e.key !== "Delete" && e.key !== "Backspace") return;
    e.preventDefault();

    try {
      const removed = deleteDraftItemsByIds(userStore, selectedIds);
      if (removed > 0) {
        needsSave(true);
        setStateChip("Unsaved", "warn");
        setStatus(removed === 1 ? "Item removed." : `${removed} items removed.`, "ok");
      }
      clearSelection();
      renderList({ userStore, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });
    } catch (err) {
      setStateChip("Error", "err");
      setStatus(err?.message || "Failed to delete.", "err");
    }
  });

  window.addEventListener("blur", clearSelection);

  // Make the items panel focusable so it can receive Delete/Escape
  dom.itemsPanel.tabIndex = 0;

  /* -------------------- commit (hook only for now) -------------------- */

  dom.commitBtn?.addEventListener("click", () => {
    const out = userStore?.ephemeral?.requester?.outbound || { header: {}, items: [] };
    window.dispatchEvent(new CustomEvent("builder:confirm", { detail: out }));
    setStateChip("Info", "muted");
    setStatus("Request sending is not implemented yet.", "muted");
  });

  /* --------------------- optional: Ctrl visual hint -------------------- */

  const setCtrlDown = (on) => document.body.classList.toggle("ctrl-down", !!on);
  document.addEventListener("keydown", (ev) => { if (ev.ctrlKey) setCtrlDown(true); });
  document.addEventListener("keyup",   (ev) => { if (ev.key === "Control" || !ev.ctrlKey) setCtrlDown(false); });
  window.addEventListener("blur", () => setCtrlDown(false));
}
