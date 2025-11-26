import {
  setStatus,
  setStateChip,
  bytesToBase64,
  base64ToBytes,
  dec,
  revisiting,
} from "/app/utils.js";
import { loadUmbral } from "/app/umbral-loader.js";
import { needsSave } from "/app/save.js";

const q = (sel, root = document) => root.querySelector(sel);

let ctrlDown = false;
const forgetButtons = new Set();
let ctrlListenersAttached = false;

function ensureCtrlTracking() {
  if (ctrlListenersAttached) return;
  ctrlListenersAttached = true;

  const refreshAllForgetButtons = () => {
    for (const btn of forgetButtons) {
      if (ctrlDown) {
        btn.style.backgroundColor = "coral";
      } else {
        btn.style.backgroundColor = "gray";
      }
    }
  };

  window.addEventListener("keydown", (e) => {
    if (e.key === "Control" && !ctrlDown) {
      ctrlDown = true;
      refreshAllForgetButtons();
    }
  });

  window.addEventListener("keyup", (e) => {
    if (e.key === "Control") {
      ctrlDown = false;
      refreshAllForgetButtons();
    }
  });

  window.addEventListener("blur", () => {
    ctrlDown = false;
    refreshAllForgetButtons();
  });
}

export function wireUpQueryItems({ api, store }) {
  if (revisiting("wireUpQueryItems")) return;
  if (!store || !store.good) return;

  const panel = q('.panel[data-panel="query-form"]');
  if (!panel) return;

  const table = panel.querySelector("table.data-table");
  if (!table) return;

  ensureCtrlTracking();
  buildGrantedItemsTable({ table, api, store });
}

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
    .filter((id) => Array.isArray(byProvider[id]) && byProvider[id].length > 0)
    .sort();

  if (providerIds.length === 0) {
    appendEmptyRow(tbody, "No granted items yet.");
    return;
  }

  for (const providerId of providerIds) {
    const items = byProvider[providerId];
    if (!Array.isArray(items) || items.length === 0) continue;

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

    for (const it of items) {
      const irow = document.createElement("tr");
      irow.className = "provider-item-row";
      irow.dataset.providerId = providerId;
      irow.dataset.requesterItemId = it.item_id;
      irow.style.display = "none";

      const nameCell = document.createElement("td");
      nameCell.textContent = it.item_name || "(unnamed)";

      const valueCell = document.createElement("td");

      const decryptBtn = document.createElement("button");
      decryptBtn.type = "button";
      decryptBtn.className = "btn";
      decryptBtn.textContent = "Click to decrypt";

      decryptBtn.addEventListener("click", () => {
        handleDecryptClick({
          api,
          store,
          providerId,
          requesterItemId: it.item_id,
          button: decryptBtn,
        });
      });

      const forgetBtn = document.createElement("button");
      forgetBtn.type = "button";
      forgetBtn.className = "btn";
      forgetBtn.textContent = "Forget";
      forgetBtn.style.marginLeft = "0.5rem";

      forgetButtons.add(forgetBtn);
      if (ctrlDown) {
        forgetBtn.style.backgroundColor = "coral";
      } else {
        forgetBtn.style.backgroundColor = "gray";
      }

      forgetBtn.addEventListener("click", async (ev) => {
        if (!ev.ctrlKey || ev.button !== 0) {
          return;
        }

        await handleForgetRequesterItem({
          api,
          store,
          providerId,
          requesterItemId: it.item_id,
          row: irow,
          table,
          forgetBtn,
        });
      });

      valueCell.appendChild(decryptBtn);
      valueCell.appendChild(forgetBtn);
      irow.appendChild(nameCell);
      irow.appendChild(valueCell);
      tbody.appendChild(irow);
    }

    prow.addEventListener("click", () => {
      const isOpen = prow.dataset.open === "1";
      prow.dataset.open = isOpen ? "0" : "1";

      const rows = tbody.querySelectorAll(
        `tr.provider-item-row[data-provider-id="${providerId}"]`
      );
      rows.forEach((r) => {
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
    button.textContent = "(missing requester metadata)";
    return;
  }

  const entry = items.find((it) => it.item_id === requesterItemId);
  if (!entry || !entry.keys || !entry.keys.secret_key_b64) {
    button.textContent = "(missing key)";
    return;
  }

  button.disabled = true;
  setStateChip("Fetching…", "warn");
  setStatus("Requesting item…");

  const umbral = await loadUmbral();
  if (!umbral) {
    button.disabled = false;
    button.textContent = "(Umbral unavailable)";
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
        button.textContent = "(not granted)";
      } else if (e?.status === 404 && e?.data?.detail === "item_not_found") {
        button.textContent = "(item unavailable)";
      } else {
        button.textContent = "(request failed)";
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
      button.textContent = "(no reencrypt fragments)";
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

    button.textContent = plainText;
    setStateChip("Done", "ok");
    setStatus("Item decrypted.", "ok");

    if (entry.request_id) {
      delete entry.request_id;
      needsSave(true);
    }
  } catch (err) {
    console.error("decryptReencrypted failed", err);
    button.textContent = "(decrypt failed)";
    setStateChip("Error", "err");
    setStatus(err?.message || "Failed to decrypt item.", "err");
  } finally {
    button.disabled = false;
  }
}

/* ------------- Forget handler ------------- */

async function handleForgetRequesterItem({
  api,
  store,
  providerId,
  requesterItemId,
  row,
  table,
  forgetBtn,
}) {
  const byProvider = store?.persistent?.requester?.items;
  if (!byProvider || typeof byProvider !== "object") return;

  const items = byProvider[providerId];
  if (!Array.isArray(items)) return;

  const idx = items.findIndex((it) => it.item_id === requesterItemId);
  if (idx === -1) return;

  const entry = items[idx];

  forgetBtn.disabled = true;

  if (entry.request_id) {
    setStateChip("Checking…", "warn");
    setStatus("Verifying that the request has been processed…", "warn");

    try {
      const resp = await api.checkSolicitationStatus(entry.request_id);
      const pending = !!resp?.pending;

      if (pending) {
        setStateChip("Pending", "warn");
        setStatus(
          "This item is part of a pending request. Try again after the provider has processed it.",
          "warn"
        );
        forgetBtn.disabled = false;
        return;
      }
    } catch (err) {
      if (err?.status === 404) {
        console.info(
          "Solicitation not found for request_id; treating as processed.",
          entry.request_id
        );
      } else {
        console.error("Failed to check solicitation status", err);
        setStateChip("Error", "err");
        setStatus(
          "Could not verify whether the request was processed. Not deleting.",
          "err"
        );
        forgetBtn.disabled = false;
        return;
      }
    }
  }

  setStateChip("Revoking…", "warn");
  setStatus("Revoking grant on server…", "warn");
  try {
    await api.dismissGrant({
      provider_id: providerId,
      requester_item_id: requesterItemId,
    });
  } catch (err) {
    if (err?.status === 404 && err?.data?.detail === "grant_not_found") {
      console.info(
        "Grant not found on server when dismissing; treating as already revoked.",
        { providerId, requesterItemId }
      );
    } else {
      console.error("Failed to dismiss grant on server", err);
      setStateChip("Error", "err");
      setStatus(
        "Could not revoke grant on server. Not deleting locally.",
        "err"
      );
      forgetBtn.disabled = false;
      return;
    }
  }

  items.splice(idx, 1);

  if (row && row.parentNode) {
    row.parentNode.removeChild(row);
  }

  if (forgetBtn) {
    forgetButtons.delete(forgetBtn);
  }

  if (items.length === 0) {
    delete byProvider[providerId];

    const tbody = table.querySelector("tbody");
    if (tbody) {
      const providerRow = tbody.querySelector(
        `tr.provider-row[data-provider-id="${providerId}"]`
      );
      if (providerRow && providerRow.parentNode) {
        providerRow.parentNode.removeChild(providerRow);
      }

      const leftoverItemRows = tbody.querySelectorAll(
        `tr.provider-item-row[data-provider-id="${providerId}"]`
      );
      leftoverItemRows.forEach((r) => r.parentNode && r.parentNode.removeChild(r));

      const anyProviderRows = tbody.querySelector("tr.provider-row");
      if (!anyProviderRows) {
        tbody.innerHTML = "";
        appendEmptyRow(tbody, "No granted items yet.");
      }
    }
  }

  needsSave(true);
  setStateChip("Forgotten", "ok");
  setStatus("Item removed and grant revoked.", "ok");
  forgetBtn.disabled = false;
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
