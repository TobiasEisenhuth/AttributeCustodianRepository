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

function ensure(obj, path, finalType = "object") {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length; i++) {
    const k = parts[i], last = i === parts.length - 1;
    if (!(k in cur) || cur[k] == null) {
      cur[k] = last ? (finalType === "array" ? [] : {}) : {};
    }
    cur = cur[k];
  }
  return cur;
}

function newRequesterItemId() {
  const rnd = crypto.getRandomValues(new Uint8Array(18)); // 144 bits
  return "req_" + base64UrlFromBytes(rnd);
}

/* --------------------- DOM refs for builder --------------------- */

function getDomRefs() {
  const formPanel = q('.panel[data-panel="builder-form"]');
  const itemsPanel = q('.panel[data-panel="builder-items"]');

  const infoInput = formPanel?.querySelector('input[data-field="Info String"]') || null;
  const toInput = formPanel?.querySelector('input[data-field="To"]') || null;
  const nameInput = formPanel?.querySelector('input[data-field="Item Name"]') || null;
  const exampleInput = formPanel?.querySelector('input[data-field="Example Value"]') || null;
  const defaultInput = formPanel?.querySelector('input[data-field="Default Field"]') || null;

  const applyBtn = formPanel?.querySelector('[data-action="builder-apply"]') || null;

  const tbody = itemsPanel?.querySelector('tbody') || null;
  const countEl = itemsPanel?.querySelector('.column-title .count') || null;
  const commitBtn = itemsPanel?.querySelector('[data-action="builder-commit"]') || null;

  return { formPanel, itemsPanel, infoInput, toInput, nameInput, exampleInput, defaultInput, applyBtn, tbody, countEl, commitBtn };
}

/* -------------------- render right-hand table -------------------- */

function renderList({ userStore, tbody, countEl, commitBtn }) {
  if (!tbody) return;
  tbody.innerHTML = "";

  const out = userStore?.ephemeral?.requester?.outbound || {};
  const header = out.header || {};
  const items  = Array.isArray(out.items) ? out.items : [];

  let count = 0;

  // Header rows (only if present or we already have items)
  const showHeader = (header.info_string || header.to || items.length > 0);
  if (showHeader) {
    const tr1 = document.createElement("tr");
    tr1.dataset.kind = "header"; tr1.dataset.header = "info";
    tr1.innerHTML = `<th scope="row">Info String</th><td>${header.info_string ?? ""}</td>`;
    tbody.appendChild(tr1);

    const tr2 = document.createElement("tr");
    tr2.dataset.kind = "header"; tr2.dataset.header = "to";
    tr2.innerHTML = `<th scope="row">To</th><td>${header.to ?? ""}</td>`;
    tbody.appendChild(tr2);
  }

  // Item rows
  for (const it of items) {
    const tr = document.createElement("tr");
    tr.dataset.kind = "item";
    tr.dataset.itemId = it.item_id;
    const label = it.item_name ?? it.item_id ?? "";
    const value = it.example_value ?? "";
    tr.innerHTML = `<th scope="row">${label}</th><td>${value}</td>`;
    tbody.appendChild(tr);
    count++;
  }

  if (countEl) countEl.textContent = String(count);
  if (commitBtn) commitBtn.disabled = count === 0;
}

/* ------------- mutate userStore for add / delete ops ------------- */

function ensureRequesterScaffold(userStore) {
  ensure(userStore, "persistent.requester.items", "array");
  ensure(userStore, "ephemeral.requester.outbound.items", "array");
  ensure(userStore, "ephemeral.requester.outbound.header");
  // header fields default
  const header = userStore.ephemeral.requester.outbound.header;
  if (!("info_string" in header)) header.info_string = "";
  if (!("to" in header)) header.to = "";
}

async function addDraftItem({ userStore, loadUmbral, info_string, to, item_name, example_value, default_field }) {
  ensureRequesterScaffold(userStore);

  // Update header (persist until changed)
  userStore.ephemeral.requester.outbound.header.info_string = info_string;
  userStore.ephemeral.requester.outbound.header.to = to;

  // Per-item requester keypair
  const umbral = await loadUmbral();
  if (!umbral) throw new Error("Umbral not loaded.");
  const sk = umbral.SecretKey.random();
  const pk = sk.publicKey();

  const item_id = newRequesterItemId();

  // Persistent: store secret for later decrypt (requester side)
  userStore.persistent.requester.items.push({
    item_id,
    item_name,
    keys: { secret_key_b64: bytesToBase64(sk.toBEBytes()) },
    created_at: nowIso(),
    updated_at: nowIso(),
  });

  // Ephemeral outbound: what we intend to send
  userStore.ephemeral.requester.outbound.items.push({
    item_id,
    item_name,
    example_value,
    default_field,
    public_key_b64: bytesToBase64(pk.toCompressedBytes()),
  });
}

function deleteDraftItemById(userStore, itemId) {
  ensureRequesterScaffold(userStore);
  const itemsP = userStore.persistent.requester.items;
  const itemsE = userStore.ephemeral.requester.outbound.items;

  const pIdx = itemsP.findIndex(i => i?.item_id === itemId);
  if (pIdx > -1) itemsP.splice(pIdx, 1);

  const eIdx = itemsE.findIndex(i => i?.item_id === itemId);
  if (eIdx > -1) itemsE.splice(eIdx, 1);

  // If no items remain, clear header too
  if (itemsE.length === 0) {
    userStore.ephemeral.requester.outbound.header.info_string = "";
    userStore.ephemeral.requester.outbound.header.to = "";
  }
}

function clearHeaderIfNoItems(userStore) {
  ensureRequesterScaffold(userStore);
  const itemsE = userStore.ephemeral.requester.outbound.items;
  if (itemsE.length === 0) {
    userStore.ephemeral.requester.outbound.header.info_string = "";
    userStore.ephemeral.requester.outbound.header.to = "";
  }
}

/* ------------------------- main wire-up -------------------------- */

export function wireUpRequestBuilder({ api, userStore }) {
  if (revisiting("wireUpRequestBuilder")) return;

  const dom = getDomRefs();
  if (!dom.formPanel || !dom.itemsPanel) return;

  // Initial paint
  renderList({ userStore, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });

  // Apply button: add one row
  dom.applyBtn?.addEventListener("click", async () => {
    const info_string = normalizeText(dom.infoInput?.value ?? "");
    const to = normalizeText(dom.toInput?.value ?? "");
    const item_name = normalizeText(dom.nameInput?.value ?? "");
    const example_val = normalizeText(dom.exampleInput?.value ?? "");
    const default_field = normalizeText(dom.defaultInput?.value ?? "None") || "None";

    if (!info_string || !to || !item_name) {
      setStateChip("Error", "err");
      setStatus("Please fill Info String, To, and Item Name.", "err");
      return;
    }

    try {
      setStateChip("Building…", "warn");
      setStatus("Adding item to request…", "warn");

      await addDraftItem({
        userStore,
        loadUmbral,
        info_string,
        to,
        item_name,
        example_value: example_val || "",   // optional → ""
        default_field,                      // optional → "None"
      });

      needsSave(true); // local state changed
      setStateChip("Unsaved", "warn");
      setStatus("Item added to draft.", "ok");

      renderList({ userStore, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });
    } catch (e) {
      setStateChip("Error", "err");
      setStatus(e?.message || "Failed to add item.", "err");
    }
  });

  /* ---------- selection (Ctrl+click) and Delete behavior ---------- */

  let selectedRow = null;
  const clearSelection = () => {
    selectedRow?.classList.remove("selected");
    selectedRow = null;
  };

  dom.itemsPanel.addEventListener("mousedown", (e) => {
    const tr = e.target.closest("tr");
    if (!tr || !dom.tbody?.contains(tr)) return;

    if (e.button === 0 && e.ctrlKey) {
      // toggle selection
      if (selectedRow === tr) {
        clearSelection();
      } else {
        clearSelection();
        selectedRow = tr;
        tr.classList.add("selected");
      }
    }
    if (e.button === 2) {
      e.preventDefault();
      clearSelection();
    }
  });

  dom.itemsPanel.addEventListener("keydown", (e) => {
    if (!selectedRow) return;
    if (e.key !== "Delete" && e.key !== "Backspace") return;
    e.preventDefault();

    const kind = selectedRow.dataset.kind;

    try {
      if (kind === "item") {
        const itemId = selectedRow.dataset.itemId;
        if (!itemId) return;

        deleteDraftItemById(userStore, itemId);
        needsSave(true);
        setStateChip("Unsaved", "warn");
        setStatus("Item removed.", "ok");
        clearSelection();
        renderList({ userStore, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });
      } else if (kind === "header") {
        // Only allow header removal if there are no item rows
        ensureRequesterScaffold(userStore);
        const itemsE = userStore.ephemeral.requester.outbound.items;
        if (itemsE.length > 0) {
          setStateChip("Info", "muted");
          setStatus("Remove all items first to clear header.", "muted");
          return;
        }
        // Clear whichever header row was selected
        const which = selectedRow.dataset.header; // "info" | "to"
        if (which === "info") userStore.ephemeral.requester.outbound.header.info_string = "";
        if (which === "to")   userStore.ephemeral.requester.outbound.header.to = "";
        clearHeaderIfNoItems(userStore);
        needsSave(true);
        setStateChip("Unsaved", "warn");
        setStatus("Header cleared.", "ok");
        clearSelection();
        renderList({ userStore, tbody: dom.tbody, countEl: dom.countEl, commitBtn: dom.commitBtn });
      }
    } catch (err) {
      setStateChip("Error", "err");
      setStatus(err?.message || "Failed to delete.", "err");
    }
  });

  // Make the items panel focusable so it can receive Delete key
  dom.itemsPanel.tabIndex = 0;

  /* -------------------- commit (hook only for now) -------------------- */

  dom.commitBtn?.addEventListener("click", () => {
    const out = userStore?.ephemeral?.requester?.outbound || { header: {}, items: [] };
    // Emit event for future sending logic
    window.dispatchEvent(new CustomEvent("builder:confirm", { detail: out }));
    setStateChip("Info", "muted");
    setStatus("Draft ready to send (not implemented yet).", "muted");
  });

  /* --------------------- optional: Ctrl visual hint -------------------- */

  const setCtrlDown = (on) => document.body.classList.toggle("ctrl-down", !!on);
  document.addEventListener("keydown", (ev) => { if (ev.ctrlKey) setCtrlDown(true); });
  document.addEventListener("keyup",   (ev) => { if (ev.key === "Control" || !ev.ctrlKey) setCtrlDown(false); });
  window.addEventListener("blur", () => setCtrlDown(false));
}
