import {
  revisiting,
  normalizeText,
  setStateChip,
  setStatus,
  nowIso,
  enc,
  bytesToBase64,
  generateItemId,
} from "/app/utils.js";
import { needsSave } from "/app/save.js";
import { loadUmbral } from "/app/umbral-loader.js";

const q = (sel, root = document) => root.querySelector(sel);

function buildTableSkeleton(tableEl) {
  tableEl.innerHTML = "";
  const tbody = document.createElement("tbody");

  const trInfo = document.createElement("tr");
  trInfo.dataset.kind = "info";
  const tdInfo = document.createElement("td");
  tdInfo.colSpan = 3;
  tdInfo.innerHTML = `<input type="text" data-role="info" placeholder="Info String" autocomplete="off" />`;
  trInfo.appendChild(tdInfo);
  tbody.appendChild(trInfo);

  const trAddr = document.createElement("tr");
  trAddr.dataset.kind = "addressee";
  const tdAddr = document.createElement("td");
  tdAddr.colSpan = 3;
  tdAddr.innerHTML = `<input type="text" data-role="addressee" placeholder="Addressee" autocomplete="off" />`;
  trAddr.appendChild(tdAddr);
  tbody.appendChild(trAddr);

  tbody.appendChild(buildItemRow());

  tableEl.appendChild(tbody);
  return tbody;
}

function buildItemRow(init = { name: "", value: "", def: "" }) {
  const tr = document.createElement("tr");
  tr.dataset.kind = "item";

  const tdName = document.createElement("td");
  tdName.innerHTML = `<input type="text" data-field="name" placeholder="Item Name" autocomplete="off" />`;
  const tdValue = document.createElement("td");
  tdValue.innerHTML = `<input type="text" data-field="value" placeholder="Example Value" autocomplete="off" />`;
  const tdDef = document.createElement("td");
  tdDef.innerHTML = `<input type="text" data-field="default" placeholder="Default Field" autocomplete="off" />`;

  tr.appendChild(tdName);
  tr.appendChild(tdValue);
  tr.appendChild(tdDef);

  tdName.querySelector("input").value = init.name || "";
  tdValue.querySelector("input").value = init.value || "";
  tdDef.querySelector("input").value = init.def || "";

  return tr;
}

function getLastItemRow(tbody) {
  const rows = Array.from(tbody.querySelectorAll('tr[data-kind="item"]'));
  return rows[rows.length - 1] || null;
}

function anyValueFilledInRow(tr) {
  if (!tr) return false;
  const name = tr.querySelector('input[data-field="name"]')?.value?.trim() || "";
  const val  = tr.querySelector('input[data-field="value"]')?.value?.trim() || "";
  const def  = tr.querySelector('input[data-field="default"]')?.value?.trim() || "";
  return !!(name || val || def);
}

function ensureOpenEnded(tbody) {
  const last = getLastItemRow(tbody);
  if (!last || anyValueFilledInRow(last)) {
    tbody.appendChild(buildItemRow());
  }
}

function resetBuilderTable(tableEl) {
  const tbody = tableEl.querySelector("tbody");
  if (!tbody) return;

  const info = tableEl.querySelector('input[data-role="info"]');
  const addr = tableEl.querySelector('input[data-role="addressee"]');
  if (info) info.value = "";
  if (addr) addr.value = "";

  tbody.querySelectorAll('tr[data-kind="item"]').forEach(tr => tr.remove());
  tbody.appendChild(buildItemRow());

  tableEl.closest(".table-scroll")?.scrollTo({ top: 0, behavior: "instant" });
  info?.focus();
}

function readForm(tableEl) {
  const info = normalizeText(tableEl.querySelector('input[data-role="info"]')?.value || "");
  const provider_id = normalizeText(tableEl.querySelector('input[data-role="addressee"]')?.value || "");

  const inputs = [];
  const rows = Array.from(tableEl.querySelectorAll('tbody tr[data-kind="item"]'));
  for (const tr of rows) {
    const name  = normalizeText(tr.querySelector('input[data-field="name"]')?.value || "");
    if (!name) continue;

    const value = normalizeText(tr.querySelector('input[data-field="value"]')?.value || "");
    const deflt = normalizeText(tr.querySelector('input[data-field="default"]')?.value || "");

    const item = { item_name: name };
    if (value) item.value_example = value;
    if (deflt) item.default_field = deflt;

    inputs.push( item );
  }

  return { info, provider_id, inputs };
}

export function wireUpRequestBuilder({ api, store }) {
  if (revisiting("wireUpRequestBuilder")) return;

  const panel = q('.panel[data-panel="builder-form"]');
  if (!panel) return;

  const form = panel.querySelector(".builder-form");
  const table = form?.querySelector(".data-table");
  const applyBtn = panel.querySelector('[data-action="builder-apply"]');
  if (!table) return;

  const tbody = buildTableSkeleton(table);

  table.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const tr = e.target.closest('tr[data-kind="item"]');
    if (!tr) return;
    const last = getLastItemRow(tbody);
    if (tr === last && anyValueFilledInRow(last)) {
      e.preventDefault();
      ensureOpenEnded(tbody);
      getLastItemRow(tbody)?.querySelector('input[data-field="name"]')?.focus();
    }
  });

  applyBtn?.addEventListener("click", async () => {
    if (applyBtn.dataset.busy === "1") return;
    applyBtn.dataset.busy = "1";
    applyBtn.disabled = true;

    const umbral = await loadUmbral();
    if (!umbral) {
      setStateChip("Error", "err");
      setStatus("Umbral not available.", "err");
      return;
    }

    try {
      const { info, provider_id, inputs } = readForm(table);
      if (!info)      throw new Error("Please fill Info String.");
      if (!provider_id) throw new Error("Please fill Addressee.");
      if (inputs.length === 0) throw new Error("Please add at least one item.");

      setStateChip("Preparing…", "warn");
      setStatus("Generating keys and building solicitation…");

      const created_at = nowIso();
      const items = [];

      const requesterItems = store.persistent.requester.items;
      const existing = new Set(requesterItems.map(it => it?.item_id).filter(Boolean));

      for (const item of inputs) {
        const item_id = generateItemId(existing);
        existing.add(item_id);

        const sk = umbral.SecretKey.random();
        const pk = sk.publicKey();

        requesterItems.push({
          item_id: item_id,
          item_name: item.item_name,
          keys: { secret_key_b64: bytesToBase64(sk.toBEBytes()) },
          last_touched: created_at,
        });

        items.push({
          item_id: item_id,
          item_name: item.item_name,
          requester_public_key_b64: bytesToBase64(pk.toCompressedBytes()),
          value_example: item.value_example,
          default_field: item.default_field,
        });
      }

      const request = { info_string: info, items };
      const request_bytes = enc.encode(JSON.stringify(request));
      const request_b64 = bytesToBase64(request_bytes);

      setStateChip("Sending…", "warn");
      setStatus("Pushing solicitation to server…");
      await api.pushSolicitation(
        provider_id,
        request_b64
      );

      needsSave(true);
      resetBuilderTable(table);

      setStateChip("Sent", "ok");
      setStatus("Solicitation pushed. Form cleared. Remember to save your vault to persist keys.", "ok");
    } catch (err) {
      setStateChip("Error", "err");
      setStatus(err?.message || "Failed to build/send solicitation.", "err");
    } finally {
      delete applyBtn.dataset.busy;
      applyBtn.disabled = false;
    }
  });
}
