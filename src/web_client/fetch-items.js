// fetch-items.js
import {
  setStatus,
  setStateChip,
  bytesToBase64,
  base64ToBytes,
  enc,
  dec,
} from "/app/utils.js";
import { loadUmbral } from "/app/umbral-loader.js";

/* ---------------- DOM helpers ---------------- */
const q  = (sel, root = document) => root.querySelector(sel);
const qa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function tableClear(tbody) {
  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
}
function td(colspan = 1) { const d = document.createElement("td"); d.colSpan = colspan; return d; }
function tr() { return document.createElement("tr"); }

/* ---------------- Build the query table ---------------- */
function buildQueryUI(panel, requesterIndex) {
  const table = panel.querySelector("table.data-table");
  if (!table) return null;

  // Ensure THEAD/TBODY exist
  let thead = table.querySelector("thead");
  let tbody = table.querySelector("tbody");
  if (!thead) { thead = document.createElement("thead"); table.appendChild(thead); }
  if (!tbody) { tbody = document.createElement("tbody"); table.appendChild(tbody); }
  thead.innerHTML = ""; // no headers per spec
  tableClear(tbody);

  // 1) Provider ID row (spans 2 columns)
  const rProv = tr();
  const tdProv = td(2);
  const inputProv = document.createElement("input");
  inputProv.type = "text";
  inputProv.placeholder = "Provider ID";
  inputProv.autocomplete = "off";
  inputProv.dataset.role = "provider-id";
  tdProv.appendChild(inputProv);
  rProv.appendChild(tdProv);
  tbody.appendChild(rProv);

  // Shared datalist of requester item names (for suggestions)
  const dlId = "req-item-names";
  if (!document.getElementById(dlId)) {
    const dl = document.createElement("datalist");
    dl.id = dlId;
    for (const it of requesterIndex.list) {
      const opt = document.createElement("option");
      opt.value = it.item_name; // label shown
      // for disambiguation you could add opt.label or opt.textContent here
      dl.appendChild(opt);
    }
    document.body.appendChild(dl);
  }

  // Helper to create one item row
  function makeItemRow() {
    const row = tr();
    // Left input: requester item (by name)
    const nameCell = td(1);
    const inName = document.createElement("input");
    inName.type = "text";
    inName.setAttribute("list", dlId);
    inName.placeholder = "Item Name";
    inName.autocomplete = "off";
    inName.className = "query-item-input";
    nameCell.appendChild(inName);

    // Right cell: output (readonly text)
    const outCell = td(1);
    outCell.className = "query-item-output";
    outCell.textContent = ""; // filled after fetch

    row.appendChild(nameCell);
    row.appendChild(outCell);

    // When the name field changes, resolve to requester_item_id
    function resolveMapping() {
      const label = (inName.value || "").trim();
      const entry = requesterIndex.byName.get(label);
      if (entry) {
        row.dataset.requesterItemId = entry.item_id;
      } else {
        delete row.dataset.requesterItemId;
      }
    }
    inName.addEventListener("change", resolveMapping);
    inName.addEventListener("input", resolveMapping);

    // Keep an open-end row: when the last row becomes non-empty, append another
    inName.addEventListener("blur", () => {
      const rows = qa("tbody tr", table).slice(1); // skip provider row
      const last = rows[rows.length - 1];
      const lastInput = last?.querySelector(".query-item-input");
      if (last && lastInput && lastInput.value && row === last) {
        tbody.appendChild(makeItemRow());
      }
    });

    return row;
  }

  // Start with a single empty item row
  tbody.appendChild(makeItemRow());

  return { table, tbody, inputProv };
}

/* ---------------- Requester index (name -> item) ---------------- */
function buildRequesterIndex(userStore) {
  const list = Array.isArray(userStore?.persistent?.requester?.items)
    ? userStore.persistent.requester.items
    : [];

  const byId = new Map();
  const byName = new Map();
  for (const it of list) {
    if (!it?.item_id || !it?.item_name) continue;
    byId.set(it.item_id, it);
    // if duplicate names exist, the first one wins
    if (!byName.has(it.item_name)) byName.set(it.item_name, it);
  }
  return { list, byId, byName };
}

/* ---------------- Main wire-up ---------------- */
export function wireUpQueryItems({ api, userStore }) {
  const panel = q('.panel[data-panel="query-form"]');
  if (!panel) return;

  const requesterIndex = buildRequesterIndex(userStore);
  const ui = buildQueryUI(panel, requesterIndex);
  if (!ui) return;

  const btn = panel.querySelector('[data-action="fetch-items"]');

  btn?.addEventListener("click", async () => {
    const providerId = ui.inputProv.value.trim();
    if (!providerId) {
      setStateChip("Error", "err");
      setStatus("Please enter Provider ID.", "err");
      return;
    }

    // Collect item rows with a mapped requester_item_id
    const rows = qa("tbody tr", ui.table).slice(1); // skip provider row
    const targets = rows
      .map(r => ({
        row: r,
        input: r.querySelector(".query-item-input"),
        out: r.querySelector(".query-item-output"),
        requester_item_id: r.dataset.requesterItemId || null,
      }))
      .filter(x => x.requester_item_id);

    if (targets.length === 0) {
      setStateChip("Info", "muted");
      setStatus("No items selected.", "muted");
      return;
    }

    const umbral = await loadUmbral();
    if (!umbral) {
      setStateChip("Error", "err");
      setStatus("Umbral not available.", "err");
      return;
    }

    setStateChip("Fetching…", "warn");
    setStatus(`Requesting ${targets.length} item(s)…`);

    for (const t of targets) {
      // Look up requester's secret for this item to derive receiving_pk
      const entry = requesterIndex.byId.get(t.requester_item_id);
      if (!entry?.keys?.secret_key_b64) {
        t.out.textContent = "(failed)";
        continue;
      }

      try {
        const receiving_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(entry.keys.secret_key_b64));
        const receiving_pk = receiving_sk.publicKey();
        const requester_public_key_b64 = bytesToBase64(receiving_pk.toCompressedBytes());

        // 1) Ask service for capsule, ciphertext, cfrags and provider keys
        const resp = await api.requestItem({
          provider_id: providerId,
          requester_item_id: t.requester_item_id,
          requester_public_key_b64,
        }, { signal: AbortSignal.timeout(15000) });

        // 2) Rebuild objects
        const capsule       = umbral.Capsule.fromBytes(base64ToBytes(resp.capsule_b64));
        const ciphertext    = base64ToBytes(resp.ciphertext_b64);
        const delegating_pk = umbral.PublicKey.fromCompressedBytes(base64ToBytes(resp.delegating_pk_b64));
        const verifying_pk  = umbral.PublicKey.fromCompressedBytes(base64ToBytes(resp.verifying_pk_b64));
        const cfragsBytes   = (resp.cfrags_b64 || []).map(b => base64ToBytes(b));

        // 3) Verify every cfrag client-side
        const vcfrags = cfragsBytes.map(c =>
          // If your binding differs, adapt this call accordingly
          umbral.verify(capsule, verifying_pk, delegating_pk, receiving_pk, c)
        );

        // 4) Decrypt with verified cfrags
        const ptBytes = umbral.decryptReencrypted(
          receiving_sk,
          delegating_pk,
          capsule,
          vcfrags,
          ciphertext
        );
        const plain = dec.decode(ptBytes);
        t.out.textContent = plain;
      } catch (e) {
        t.out.textContent = "(failed)";
      }
    }

    setStateChip("Done", "ok");
    setStatus("Fetch complete.");
  });
}
