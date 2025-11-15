import {
  setStatus,
  setStateChip,
  bytesToBase64,
  base64ToBytes,
} from "/app/utils.js";
import { loadUmbral } from "/app/umbral-loader.js";

/* ---------------- api fallbacks if missing on api object ---------------- */

function ensureApi(api) {
  if (!api.pullSolicitationBundle) {
    api.pullSolicitationBundle = (rest = {}) =>
      api._fetch("/api/pull_solicitation_bundle", { body: {}, ...rest });
  }
  if (!api.ackSolicitationBundle) {
    api.ackSolicitationBundle = (requester_id, ack_token, rest = {}) =>
      api._fetch("/api/ack_solicitation_bundle", {
        body: {
          requester_id,
          max_created_at: ack_token?.max_created_at,
          max_request_id: ack_token?.max_request_id,
        },
        ...rest,
      });
  }
  if (!api.grantAccess) {
    api.grantAccess = (payload, rest = {}) =>
      api._fetch("/api/grant_access", { body: payload, ...rest });
  }
}

/* ---------------- dom helpers ---------------- */

const q  = (sel, root = document) => root.querySelector(sel);
const qa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function clearTbody(tbody) {
  if (!tbody) return;
  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
}

function tdColspan(text, span = 2) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = span;
  td.textContent = text;
  tr.appendChild(td);
  return tr;
}

function itemRow({ item_name, value_example, requester_item_id }) {
  const tr = document.createElement("tr");
  tr.dataset.kind = "item";

  const tdName = document.createElement("td");
  tdName.textContent = item_name;
  tdName.dataset.readonly = "1";

  const tdEdit = document.createElement("td");
  tdEdit.className = "inbound-edit-cell";
  tdEdit.innerHTML = `
    <div class="inbound-input-wrap">
      <input type="text" class="inbound-value-input"
             placeholder="${value_example || ""}"
             autocomplete="off" />
      <div class="suggestbox" hidden></div>
    </div>
  `;

  // stash requester item id on the editable cell
  tdEdit.dataset.requesterItemId = requester_item_id;
  tr.appendChild(tdName);
  tr.appendChild(tdEdit);
  return tr;
}

/* ---------------- suggestions (very small custom dropdown) ---------------- */

function attachSuggestBehavior(tdEdit, options, onChange) {
  // options: [{ id: provider_item_id, label: valueString }, ...]
  const wrap = tdEdit.querySelector(".inbound-input-wrap");
  const input = tdEdit.querySelector(".inbound-value-input");
  const box = tdEdit.querySelector(".suggestbox");
  if (!wrap || !input || !box) return;

  let filtered = options.slice();
  let hotIndex = -1;

  function renderList() {
    box.innerHTML = "";
    if (filtered.length === 0) {
      box.hidden = true;
      return;
    }
    const ul = document.createElement("ul");
    ul.className = "suggestlist";
    filtered.forEach((opt, i) => {
      const li = document.createElement("li");
      li.className = "suggestitem" + (i === hotIndex ? " hot" : "");
      li.textContent = opt.label;
      li.dataset.id = opt.id;
      li.addEventListener("mousedown", (e) => {
        e.preventDefault();
        pick(opt);
      });
      ul.appendChild(li);
    });
    box.appendChild(ul);
    box.hidden = false;
  }

  function pick(opt) {
    input.value = opt.label;
    tdEdit.dataset.providerItemId = opt.id;      // <-- attach the chosen mapping
    box.hidden = true;
    hotIndex = -1;
    onChange?.();
  }

  function filterNow() {
    const q = (input.value || "").toLowerCase();
    filtered = options.filter(o => o.label.toLowerCase().includes(q));
    // auto-pick if exactly one and it exactly matches
    if (filtered.length === 1 && filtered[0].label.toLowerCase() === q) {
      pick(filtered[0]);
      return;
    }
    // else clear selection until explicitly picked
    delete tdEdit.dataset.providerItemId;
    hotIndex = filtered.length ? 0 : -1;
    renderList();
    onChange?.();
  }

  input.addEventListener("focus", () => {
    filterNow();
  });

  input.addEventListener("input", () => {
    filterNow();
  });

  input.addEventListener("keydown", (e) => {
    if (box.hidden) {
      // Tab completion when hidden: nothing special
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (filtered.length) {
        hotIndex = (hotIndex + 1) % filtered.length;
        renderList();
      }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (filtered.length) {
        hotIndex = (hotIndex - 1 + filtered.length) % filtered.length;
        renderList();
      }
    } else if (e.key === "Enter") {
      if (hotIndex >= 0 && filtered[hotIndex]) {
        e.preventDefault();
        pick(filtered[hotIndex]);
      }
    } else if (e.key === "Tab") {
      // if exactly one candidate left, autocomplete to it and allow tab to move on
      if (filtered.length === 1) {
        pick(filtered[0]);
      }
    } else if (e.key === "Escape") {
      box.hidden = true;
      hotIndex = -1;
    }
  });

  document.addEventListener("mousedown", (e) => {
    if (!wrap.contains(e.target)) {
      box.hidden = true;
      hotIndex = -1;
    }
  });
}

/* ---------------- rendering & flow ---------------- */

function renderBundleIntoTable({ table, bundleJson, providerOptions, onGrant }) {
  // Returns a cleanup function
  const tbody = table.querySelector("tbody");
  const createdRows = [];

  const reqId = bundleJson.requester_id;
  const ackToken = bundleJson.bundle?.ack_token || null;

  // Combine all requests rows into single flat list; capture info_string if present
  const requests = Array.isArray(bundleJson.bundle?.requests)
    ? bundleJson.bundle.requests
    : [];

  let infoString = "";
  const flatRows = [];
  for (const req of requests) {
    const payload = req.payload || {};
    if (typeof payload.info_string === "string" && payload.info_string && !infoString) {
      infoString = payload.info_string;
    }
    const rows = Array.isArray(payload.rows) ? payload.rows : [];
    for (const r of rows) {
      const item_name = r.item_name || "";
      const requester_item_id = r.secret_id || r.requester_item_id || ""; // payload field name was "secret_id"
      const value_example = r.value_example || "";
      const requester_public_key_b64 = r.requester_public_key_b64 || "";
      flatRows.push({ item_name, requester_item_id, value_example, requester_public_key_b64 });
    }
  }

  // Header rows
  const header1 = tdColspan(`Requester: ${reqId}`, 2);
  const header2 = tdColspan(`Info String: ${infoString || "(not provided)"}`, 2);
  tbody.appendChild(header1); createdRows.push(header1);
  tbody.appendChild(header2); createdRows.push(header2);

  // Item rows
  const itemTrs = [];
  for (const r of flatRows) {
    const tr = itemRow({
      item_name: r.item_name,
      value_example: r.value_example,
      requester_item_id: r.requester_item_id,
    });
    // keep requester public key on the editable cell
    const tdEdit = tr.lastElementChild;
    tdEdit.dataset.requesterPkB64 = r.requester_public_key_b64 || "";
    tbody.appendChild(tr);
    createdRows.push(tr);
    itemTrs.push(tr);
  }

  // Button row
  const btnRow = document.createElement("tr");
  const tdBtn = document.createElement("td");
  tdBtn.colSpan = 2;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn primary";
  btn.textContent = "Grant Request";
  btn.disabled = true;
  tdBtn.appendChild(btn);
  btnRow.appendChild(tdBtn);
  tbody.appendChild(btnRow);
  createdRows.push(btnRow);

  // Build provider options from userStore ephemeral.provider.values (Map)
  for (const tr of itemTrs) {
    const tdEdit = tr.lastElementChild;
    attachSuggestBehavior(tdEdit, providerOptions, () => {
      // Enable button if all items have a mapping
      const allMapped = itemTrs.every((it) => {
        const c = it.lastElementChild;
        return !!c.dataset.providerItemId;
      });
      btn.disabled = !allMapped;
    });
  }

  // Grant handler
  btn.addEventListener("click", () => {
    if (btn.disabled) return;
    onGrant?.({
      requester_id: reqId,
      ack_token: ackToken,
      items: itemTrs.map((tr) => {
        const tdEdit = tr.lastElementChild;
        const name = tr.firstElementChild?.textContent || "";
        return {
          item_name: name,
          requester_item_id: tdEdit.dataset.requesterItemId,
          requester_public_key_b64: tdEdit.dataset.requesterPkB64 || "",
          provider_item_id: tdEdit.dataset.providerItemId,
        };
      }),
      cleanup: () => {
        // remove this section
        for (const row of createdRows) row.remove();
      },
    });
  });

  return () => {
    for (const row of createdRows) row.remove();
  };
}

/* ---------------- main wire-up ---------------- */

export function wireUpInboundRequests({ api, userStore }) {
  ensureApi(api);

  const panel = q('.panel[data-panel="requests"]');
  if (!panel) return;
  const table = panel.querySelector("table");
  const tbody = table?.querySelector("tbody");
  const countEl = panel.querySelector(".count");
  if (!table || !tbody) return;

  // Build provider options from ephemeral map: [{id, label}]
  const providerMap = userStore?.ephemeral?.provider?.values;
  const providerOptions = [];
  if (providerMap && typeof providerMap.forEach === "function") {
    providerMap.forEach((value, id) => {
      // value is plaintext string, id is provider_item_id
      providerOptions.push({ id, label: String(value || "") });
    });
  }

  // keep total row count for the header counter
  let totalRows = 0;
  function setCount(n) { if (countEl) countEl.textContent = String(n); }

  async function pullAndRenderOne() {
    setStateChip("Loading…", "warn");
    setStatus("Checking inbound requests…");

    const res = await api.pullSolicitationBundle({ signal: AbortSignal.timeout(15000) });

    if (!res?.has_bundle) {
      // nothing to render (leave any existing rows intact)
      setStateChip("Idle", "muted");
      setStatus("No inbound requests.");
      return false;
    }

    const cleanup = renderBundleIntoTable({
      table,
      bundleJson: res,
      providerOptions,
      onGrant: ({ requester_id, ack_token, items, cleanup }) => grantFlow({ requester_id, ack_token, items, cleanup }),
    });

    // update header counter (add the # of item rows we just appended)
    const justAdded = (Array.isArray(res.bundle?.requests)
      ? res.bundle.requests.reduce((acc, r) => acc + ((r.payload?.rows?.length) || 0), 0)
      : 0);
    totalRows += justAdded;
    setCount(totalRows);

    setStateChip("Ready", "ok");
    setStatus("Inbound request loaded.");
    return true;
  }

  async function grantFlow({ requester_id, ack_token, items, cleanup }) {
    const umbral = await loadUmbral();
    if (!umbral) {
      setStateChip("Error", "err");
      setStatus("Umbral not available; cannot grant.");
      return;
    }

    // Find provider persistent items (need secret & signing keys)
    const providerItems = userStore?.persistent?.provider?.items;
    if (!Array.isArray(providerItems)) {
      setStateChip("Error", "err");
      setStatus("No provider items found in persistent store.");
      return;
    }

    setStateChip("Granting…", "warn");
    setStatus("Generating re-encryption keys…");

    try {
      // For each requested item, generate kfrags and send grant_access
      for (const it of items) {
        const pEntry = providerItems.find(e => e?.item_id === it.provider_item_id);
        if (!pEntry?.keys?.secret_key_b64 || !pEntry?.keys?.signing_key_b64) {
          throw new Error(`Missing keys for provider item ${it.provider_item_id}.`);
        }

        const delegating_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(pEntry.keys.secret_key_b64));
        const signing_sk    = umbral.SecretKey.fromBEBytes(base64ToBytes(pEntry.keys.signing_key_b64));
        const signer        = new umbral.Signer(signing_sk);

        // Requester public key (compressed)
        const recv_pk_b   = base64ToBytes(it.requester_public_key_b64);
        const receiving_pk = umbral.PublicKey.fromCompressedBytes(recv_pk_b);

        // Minimal policy: 1-of-1 kfrag
        const m = 1, n = 1;
        const kfrags = umbral.generateKFrags(delegating_sk, receiving_pk, signer, m, n);
        if (!Array.isArray(kfrags) || kfrags.length === 0) {
          throw new Error("Failed to generate kfrags.");
        }
        const kfrags_b64 = kfrags.map(k => bytesToBase64(k.toBytes()));

        await api.grantAccess({
          requester_id,
          provider_item_id: it.provider_item_id,
          requester_item_id: it.requester_item_id,
          kfrags_b64,
        }, { signal: AbortSignal.timeout(15000) });
      }

      setStatus("Access granted. Acknowledging bundle…");

      // Ack the whole bundle for this requester, then remove these rows and load next
      await api.ackSolicitationBundle(requester_id, ack_token, { signal: AbortSignal.timeout(15000) });

      // Clean up this group from UI and update count
      const removedRows = items.length + 2 /*headers*/ + 1 /*button row*/;
      totalRows = Math.max(0, totalRows - removedRows);
      setCount(totalRows);
      cleanup();

      setStateChip("Synced", "ok");
      setStatus("Bundle acknowledged. Loading next (if any)…");

      // Pull next group (if present)
      await pullAndRenderOne();
    } catch (err) {
      setStateChip("Error", "err");
      setStatus(err?.message || "Failed to grant/acknowledge bundle.");
    }
  }

  // Initial: clear table body and load one bundle
  clearTbody(tbody);
  setCount(0);
  pullAndRenderOne().catch((e) => {
    setStateChip("Error", "err");
    setStatus(e?.message || "Failed to load inbound requests.");
  });
}
