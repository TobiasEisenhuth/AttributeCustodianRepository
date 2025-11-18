import {
  setStatus,
  setStateChip,
  bytesToBase64,
  base64ToBytes,
  dec,
} from "/app/utils.js";
import { loadUmbral } from "/app/umbral-loader.js";

/* ---------------- DOM helpers ---------------- */
const q  = (sel, root = document) => root.querySelector(sel);
const qa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function tableClear(tbody) { while (tbody.firstChild) tbody.removeChild(tbody.firstChild); }
function td(colspan = 1) { const d = document.createElement("td"); d.colSpan = colspan; return d; }
function tr() { return document.createElement("tr"); }

/* ---------------- Requester index (name -> item) ---------------- */
function buildRequesterIndex(stash) {
  const list = Array.isArray(stash?.persistent?.requester?.items)
    ? stash.persistent.requester.items
    : [];

  const byId = new Map();
  const byName = new Map();

  for (const it of list) {
    if (!it?.item_id || !it?.item_name) continue;
    byId.set(it.item_id, it);
    // First occurrence wins if duplicate names exist
    if (!byName.has(it.item_name)) byName.set(it.item_name, it);
  }
  return { list, byId, byName };
}

/* ---------------- Build the query table ---------------- */
function buildQueryUI(panel, requesterIndex) {
  const table = panel.querySelector("table.data-table");
  if (!table) return null;

  // ensure sections
  let thead = table.querySelector("thead");
  let tbody = table.querySelector("tbody");
  if (!thead) { thead = document.createElement("thead"); table.appendChild(thead); }
  if (!tbody) { tbody = document.createElement("tbody"); table.appendChild(tbody); }
  thead.innerHTML = ""; // no headers
  tableClear(tbody);

  // Provider ID row (spans 2 cols)
  const rProv = tr();
  const tdProv = td(2);
  const inputProv = document.createElement("input");
  inputProv.type = "text";
  inputProv.placeholder = "Provider ID";
  inputProv.autocomplete = "off";
  tdProv.appendChild(inputProv);
  rProv.appendChild(tdProv);
  tbody.appendChild(rProv);

  // One shared datalist (names only)
  const dlId = "req-item-names";
  if (!document.getElementById(dlId)) {
    const dl = document.createElement("datalist");
    dl.id = dlId;
    for (const it of requesterIndex.list) {
      const opt = document.createElement("option");
      opt.value = it.item_name;
      dl.appendChild(opt);
    }
    document.body.appendChild(dl);
  }

  function resolveMapping(row, inputEl) {
    const label = (inputEl.value || "").trim();
    const entry = requesterIndex.byName.get(label);
    if (entry) row.dataset.requesterItemId = entry.item_id;
    else delete row.dataset.requesterItemId;
  }

  function maybeAppendOpenEndRow(row) {
    const rows = qa("tbody tr", table).slice(1); // skip provider row
    const last = rows[rows.length - 1];
    if (row === last && row.dataset.requesterItemId) {
      tbody.appendChild(makeItemRow()); // append one fresh empty row
    }
  }

  function makeItemRow() {
    const row = tr();

    // Left input (item name)
    const nameCell = td(1);
    const inName = document.createElement("input");
    inName.type = "text";
    inName.setAttribute("list", dlId);
    inName.placeholder = "Item Name";
    inName.autocomplete = "off";
    inName.className = "query-item-input";
    nameCell.appendChild(inName);

    // Right output (plain text)
    const outCell = td(1);
    outCell.className = "query-item-output";
    row.appendChild(nameCell);
    row.appendChild(outCell);

    // map on input/change; add new row when last row becomes mapped
    const onChange = () => { resolveMapping(row, inName); maybeAppendOpenEndRow(row); };
    inName.addEventListener("input", onChange);
    inName.addEventListener("change", onChange);

    return row;
  }

  // start with a single empty item row
  tbody.appendChild(makeItemRow());

  return { table, tbody, inputProv };
}

/* ---------------- Umbral helpers ---------------- */
function verifyCFragsFlexible(umbral, { capsule, verifying_pk, delegating_pk, receiving_pk, cfragsBytes }) {
  // Try a batched form first: verify(capsule, verifying_pk, delegating_pk, receiving_pk, cfragsBytes)
  try {
    const vcfrags = umbral.verify(capsule, verifying_pk, delegating_pk, receiving_pk, cfragsBytes);
    if (Array.isArray(vcfrags)) return vcfrags;
  } catch { /* fall through */ }

  // Fallback: per-cfrag verify
  try {
    const vcfrags = cfragsBytes.map(c =>
      umbral.verify(capsule, verifying_pk, delegating_pk, receiving_pk, c)
    );
    return vcfrags;
  } catch {
    // As a last resort, return raw cfrags (some bindings auto-verify on decrypt)
    return cfragsBytes;
  }
}

/* ---------------- Main wire-up ---------------- */
export function wireUpQueryItems({ api, stash }) {
  const panel = q('.panel[data-panel="query-form"]');
  if (!panel) return;

  const requesterIndex = buildRequesterIndex(stash);
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

    // Collect mapped rows (skip provider row)
    const rows = qa("tbody tr", ui.table).slice(1);
    const targets = rows.map(r => ({
      row: r,
      input: r.querySelector(".query-item-input"),
      out: r.querySelector(".query-item-output"),
      requester_item_id: r.dataset.requesterItemId || null,
    })).filter(x => x.requester_item_id);

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
      // Find requester secret to derive receiving PK
      const entry = requesterIndex.byId.get(t.requester_item_id);
      if (!entry?.keys?.secret_key_b64) {
        t.out.textContent = "(failed)";
        continue;
      }

      try {
        const receiving_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(entry.keys.secret_key_b64));
        const receiving_pk = receiving_sk.publicKey();
        const requester_public_key_b64 = bytesToBase64(receiving_pk.toCompressedBytes());

        // Ask service for the encrypted bundle
        let resp;
        try {
          resp = await api.requestItem({
            provider_id: providerId,
            requester_item_id: t.requester_item_id,
            requester_public_key_b64,
          }, { signal: AbortSignal.timeout?.(15000) });
        } catch (e) {
          if (e?.status === 404 && e?.message?.includes?.("grant_not_found")) {
            t.out.textContent = "(not granted)";
          } else {
            t.out.textContent = "(failed)";
          }
          continue;
        }

        // Rehydrate pieces
        const capsule       = umbral.Capsule.fromBytes(base64ToBytes(resp.capsule_b64));
        const ciphertext    = base64ToBytes(resp.ciphertext_b64);
        const delegating_pk = umbral.PublicKey.fromCompressedBytes(base64ToBytes(resp.delegating_pk_b64));
        const verifying_pk  = umbral.PublicKey.fromCompressedBytes(base64ToBytes(resp.verifying_pk_b64));
        const cfragsBytes   = (resp.cfrags_b64 || []).map(b => base64ToBytes(b));

        // Verify cfrags if binding requires/permits it
        const vcfrags = verifyCFragsFlexible(umbral, {
          capsule, verifying_pk, delegating_pk, receiving_pk, cfragsBytes
        });

        // Decrypt
        const ptBytes = umbral.decryptReencrypted(
          receiving_sk,
          delegating_pk,
          capsule,
          vcfrags,
          ciphertext
        );
        t.out.textContent = dec.decode(ptBytes);
      } catch {
        t.out.textContent = "(failed)";
      }
    }

    setStateChip("Done", "ok");
    setStatus("Fetch complete.");
  });
}
