import {
  setStatus,
  setStateChip,
  bytesToBase64,
  base64ToBytes,
  dec,
} from "/app/utils.js";
import { loadUmbral } from "/app/umbral-loader.js";

/* ------------- DOM helpers ------------- */
const q = (sel, root = document) => root.querySelector(sel);

/* ------------- Entry point ------------- */

export function wireUpQueryItems({ api, store }) {
  // If the store isn't loaded/usable, don't wire anything.
  if (!store || !store.good) return;

  const panel = q('.panel[data-panel="query-form"]');
  if (!panel) return;

  const table = panel.querySelector("table.data-table");
  if (!table) return;

  buildGrantedItemsTable({ table, api, store });
}

/**
 * Build a table like:
 *
 *  ProviderID (header row)
 *    item_name        [Click to decrypt]
 *    item_name        [Click to decrypt]
 *
 * Items are grouped by provider_id from store.persistent.requester.items.
 */
function buildGrantedItemsTable({ table, api, store }) {
  table.innerHTML = "";

  const thead = document.createElement("thead");
  const tbody = document.createElement("tbody");
  table.appendChild(thead);
  table.appendChild(tbody);

  // Simple header row
  const hr = document.createElement("tr");
  const thItem = document.createElement("th");
  const thVal  = document.createElement("th");
  thItem.textContent = "Item";
  thVal.textContent  = "Value";
  hr.appendChild(thItem);
  hr.appendChild(thVal);
  thead.appendChild(hr);

  const byProvider = store?.persistent?.requester?.items;
  const hasMap = byProvider && typeof byProvider === "object" && !Array.isArray(byProvider);

  if (!hasMap) {
    appendEmptyRow(tbody, "No granted items yet.");
    return;
  }

  const providerIds = Object.keys(byProvider)
    .filter(id => Array.isArray(byProvider[id]) && byProvider[id].length > 0)
    .sort();

  if (providerIds.length === 0) {
    appendEmptyRow(tbody, "No granted items yet.");
    return;
  }

  for (const providerId of providerIds) {
    const items = byProvider[providerId];
    if (!Array.isArray(items) || items.length === 0) continue;

    // Provider row
    const prow = document.createElement("tr");
    prow.className = "provider-row";
    prow.dataset.providerId = providerId;

    const pcell = document.createElement("td");
    pcell.colSpan = 2;
    pcell.textContent = providerId;
    pcell.style.fontWeight = "600";
    pcell.style.cursor = "pointer";

    prow.appendChild(pcell);
    tbody.appendChild(prow);

    // Item rows are initially collapsed
    for (const it of items) {
      const irow = document.createElement("tr");
      irow.className = "provider-item-row";
      irow.dataset.providerId = providerId;
      irow.dataset.requesterItemId = it.item_id;
      irow.style.display = "none";

      const nameCell = document.createElement("td");
      nameCell.textContent = it.item_name || "(unnamed)";

      const valueCell = document.createElement("td");

      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn";
      btn.textContent = "Click to decrypt";

      btn.addEventListener("click", () => {
        handleDecryptClick({
          api,
          store,
          providerId,
          requesterItemId: it.item_id,
          valueCell,
          button: btn,
        });
      });

      valueCell.appendChild(btn);
      irow.appendChild(nameCell);
      irow.appendChild(valueCell);
      tbody.appendChild(irow);
    }

    // Toggle item rows when provider row is clicked
    prow.addEventListener("click", () => {
      const isOpen = prow.dataset.open === "1";
      prow.dataset.open = isOpen ? "0" : "1";

      const rows = tbody.querySelectorAll(
        `tr.provider-item-row[data-provider-id="${providerId}"]`
      );
      rows.forEach(r => {
        r.style.display = isOpen ? "none" : "";
      });
    });
  }
}

/* ------------- Decrypt handler ------------- */

async function handleDecryptClick({
  api,
  store,
  providerId,
  requesterItemId,
  valueCell,
  button,
}) {
  if (!store || !store.good) {
    setStateChip("Error", "err");
    setStatus("Store not initialized.", "err");
    return;
  }

  const byProvider = store?.persistent?.requester?.items;
  const items = byProvider?.[providerId];

  if (!Array.isArray(items)) {
    valueCell.textContent = "(missing requester metadata)";
    return;
  }

  const entry = items.find(it => it.item_id === requesterItemId);
  if (!entry || !entry.keys || !entry.keys.secret_key_b64) {
    valueCell.textContent = "(missing key)";
    return;
  }

  button.disabled = true;
  setStateChip("Fetching…", "warn");
  setStatus("Requesting item…");

  const umbral = await loadUmbral();
  if (!umbral) {
    button.disabled = false;
    valueCell.textContent = "(Umbral unavailable)";
    setStateChip("Error", "err");
    setStatus("Umbral not available.", "err");
    return;
  }

  try {
    const sk = umbral.SecretKey.fromBEBytes(
      base64ToBytes(entry.keys.secret_key_b64)
    );
    const pk = sk.publicKey();
    const requester_public_key_b64 = bytesToBase64(
      pk.toCompressedBytes()
    );

    let resp;
    try {
      resp = await api.requestItem(
        {
          provider_id: providerId,
          requester_item_id: requesterItemId,
          requester_public_key_b64,
        },
        { signal: AbortSignal.timeout?.(15000) }
      );
    } catch (e) {
      if (e?.status === 404 && e?.data?.detail === "grant_not_found") {
        valueCell.textContent = "(not granted)";
      } else if (e?.status === 404 && e?.data?.detail === "item_not_found") {
        valueCell.textContent = "(item unavailable)";
      } else {
        valueCell.textContent = "(request failed)";
      }
      return;
    }

    const capsule = umbral.Capsule.fromBytes(
      base64ToBytes(resp.capsule_b64)
    );
    const ciphertext = base64ToBytes(resp.ciphertext_b64);
    const delegating_pk = umbral.PublicKey.fromCompressedBytes(
      base64ToBytes(resp.delegating_pk_b64)
    );
    const verifying_pk = umbral.PublicKey.fromCompressedBytes(
      base64ToBytes(resp.verifying_pk_b64)
    );

    const vcfrags = (resp.cfrags_b64 || []).map((b64) => {
      const cfragBytes = base64ToBytes(b64);
      const cfrag = umbral.CapsuleFrag.fromBytes(cfragBytes);
      return cfrag.verify(
        capsule,
        verifying_pk,
        delegating_pk,
        pk
      );
    });

    if (!vcfrags.length) {
      valueCell.textContent = "(no reencrypt fragments)";
      setStateChip("Error", "err");
      setStatus("No re-encryption fragments returned.", "err");
      return;
    }

    const ptBytes = umbral.decryptReencrypted(
      sk,
      delegating_pk,
      capsule,
      vcfrags,
      ciphertext
    );
    const plainText = dec.decode(ptBytes);

    valueCell.textContent = plainText;
    setStateChip("Done", "ok");
    setStatus("Item decrypted.", "ok");
  } catch (err) {
    console.error("decryptReencrypted failed", err);
    valueCell.textContent = "(decrypt failed)";
    setStateChip("Error", "err");
    setStatus(err?.message || "Failed to decrypt item.", "err");
  } finally {
    button.disabled = false;
  }
}

/* ------------- Small helper ------------- */

function appendEmptyRow(tbody, message) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 2;
  td.textContent = message;
  td.style.fontStyle = "italic";
  tr.appendChild(td);
  tbody.appendChild(tr);
}
