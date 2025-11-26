import { revisiting } from "/app/utils.js";

const q  = (sel, root = document) => root.querySelector(sel);
const qa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

export function wireUpOverview({ api, store }) {
  if (revisiting("wireUpOverview")) return;
  if (!store || !store.good) return;

  const panel = q('.panel[data-panel="overview"]');
  if (!panel) return;

  const table = panel.querySelector("table.data-table");
  if (!table) return;

  const tbody = table.querySelector("tbody");
  if (!tbody) return;

  const buttons = qa(".overview-mode-btn", panel);
  if (!buttons.length) return;

  // Local state for this wiring only
  let currentMode = "by-item"; // "by-item" | "by-requester"

  function updateModeButtonState() {
    buttons.forEach((btn) => {
      const isActive = btn.dataset.mode === currentMode;
      btn.setAttribute("aria-pressed", isActive ? "true" : "false");
      if (isActive) {
        btn.classList.add("primary");
      } else {
        btn.classList.remove("primary");
      }
    });
  }

  async function renderOverview(options = {}) {
    const { focusItemId = null, focusRequesterId = null } = options || {};

    tbody.innerHTML = "";

    let res;
    try {
      res = await api.listMyGrants();
    } catch (err) {
      console.error("Failed to load grants overview", err);
      appendEmptyRow(tbody, "Failed to load grants overview.");
      return;
    }

    const rawGrants = Array.isArray(res?.grants) ? res.grants : [];
    if (!rawGrants.length) {
      appendEmptyRow(tbody, "No grants yet.");
      return;
    }

    // Local provider metadata
    const providerItems  = store.persistent?.provider?.items || [];
    const providerValues = store.ephemeral?.provider?.values;

    // Build a quick lookup from item_id -> item record
    const itemMap = new Map();
    for (const it of providerItems) {
      if (it && it.item_id) {
        itemMap.set(it.item_id, it);
      }
    }

    // Hydrate each grant with local item_name and valueStr (if available)
    const grants = rawGrants.map((g) => {
      const itemId = g.provider_item_id;
      const item = itemMap.get(itemId);
      const itemName = item?.item_name || itemId;

      let valueStr = undefined;
      if (providerValues && typeof providerValues.get === "function") {
        const raw = providerValues.get(itemId);  // Map lookup
        if (raw !== undefined && raw !== null) {
          valueStr = String(raw);               // plain_value -> string
        }
      }

      return {
        provider_item_id: itemId,
        provider_item_name: itemName,
        provider_valueStr: valueStr,
        requester_id: String(g.requester_id),
      };
    });

    if (!grants.length) {
      appendEmptyRow(tbody, "No grants yet.");
      return;
    }

    // Jump helpers (used by ctrl+click in child rows)
    const jumpToRequester = (requesterId) => {
      if (!requesterId) return;
      currentMode = "by-requester";
      updateModeButtonState();
      renderOverview({ focusRequesterId: requesterId }).catch((err) =>
        console.error("Overview render failed on jumpToRequester", err)
      );
    };

    const jumpToItem = (itemId) => {
      if (!itemId) return;
      currentMode = "by-item";
      updateModeButtonState();
      renderOverview({ focusItemId: itemId }).catch((err) =>
        console.error("Overview render failed on jumpToItem", err)
      );
    };

    if (currentMode === "by-requester") {
      renderByRequester(tbody, grants, { onJumpToItem: jumpToItem });
      if (focusRequesterId) {
        focusAndExpandRequesterRow(tbody, focusRequesterId);
      }
    } else {
      renderByItem(tbody, grants, { onJumpToRequester: jumpToRequester });
      if (focusItemId) {
        focusAndExpandItemRow(tbody, focusItemId);
      }
    }
  }

  // Wire mode buttons
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const mode = btn.dataset.mode;
      if (!mode || mode === currentMode) return;
      currentMode = mode;
      updateModeButtonState();
      renderOverview().catch((err) =>
        console.error("Overview render failed after mode switch", err)
      );
    });
  });

  // Re-render when view changes back to overview
  window.addEventListener("viewchange", (ev) => {
    if (ev?.detail?.view === "overview") {
      renderOverview().catch((err) =>
        console.error("Overview render failed on viewchange", err)
      );
    }
  });

  // Hook for when provider grants change (e.g. inbound requests processed)
  window.addEventListener("provider-grants-updated", () => {
    renderOverview().catch((err) =>
      console.error("Overview render failed on provider-grants-updated", err)
    );
  });

  // Initial render
  updateModeButtonState();
  renderOverview().catch((err) =>
    console.error("Initial overview render failed", err)
  );
}

/**
 * grants: Array of:
 * {
 *   provider_item_id: string,
 *   provider_item_name: string,
 *   provider_valueStr?: string,
 *   requester_id: string
 * }
 */

/* ---------- Mode: By Item ---------- */

function renderByItem(tbody, grants, opts = {}) {
  const { onJumpToRequester } = opts || {};
  const byItem = new Map();

  for (const g of grants) {
    if (!g || !g.provider_item_id) continue;
    const key = g.provider_item_id;

    let slot = byItem.get(key);
    if (!slot) {
      slot = {
        itemId: key,
        itemName: g.provider_item_name || g.provider_item_id,
        valueStr: g.provider_valueStr,
        grants: [],
      };
      byItem.set(key, slot);
    }
    slot.grants.push(g);
  }

  const groups = Array.from(byItem.values()).sort((a, b) => {
    const an = (a.itemName || "").toLowerCase();
    const bn = (b.itemName || "").toLowerCase();
    if (an < bn) return -1;
    if (an > bn) return 1;
    return a.itemId.localeCompare(b.itemId);
  });

  if (!groups.length) {
    appendEmptyRow(tbody, "No grants yet.");
    return;
  }

  for (const group of groups) {
    const prow = document.createElement("tr");
    prow.className = "overview-item-row";
    prow.dataset.itemId = group.itemId;
    prow.dataset.open = "0";

    const nameCell = document.createElement("td");
    // Store base label so we can rebuild text when toggling arrow
    nameCell.dataset.labelBase = group.itemName || group.itemId;

    const countCell = document.createElement("td");
    const count = group.grants.length;

    // Style choice: only show requester count here, keep it clean.
    countCell.textContent = count
      ? `${count} requester${count === 1 ? "" : "s"}`
      : "No requesters";

    prow.appendChild(nameCell);
    prow.appendChild(countCell);
    tbody.appendChild(prow);

    // Initial label with arrow
    updateItemRowLabel(prow, nameCell);

    // Child rows (one per requester)
    for (const g of group.grants) {
      const row = document.createElement("tr");
      row.className = "overview-item-grant-row";
      row.dataset.itemId = group.itemId;
      row.dataset.requesterId = g.requester_id;
      row.style.display = "none";

      const primary = document.createElement("td");
      // Tree-ish: prefix with arrow and indent
      primary.textContent = `↳ ${g.requester_id}`;
      primary.style.paddingLeft = "1.5rem";

      const secondary = document.createElement("td");
      // No item_value here; that shows when the item is a child (by-requester mode)
      secondary.textContent = "";

      row.appendChild(primary);
      row.appendChild(secondary);
      tbody.appendChild(row);

      // Ctrl+click on requester -> jump to "By Requester" for that requester
      row.addEventListener("click", (ev) => {
        if (!(ev.ctrlKey && ev.button === 0)) return;
        ev.preventDefault();
        ev.stopPropagation();
        if (typeof onJumpToRequester === "function") {
          onJumpToRequester(g.requester_id);
        }
      });
    }

    prow.style.cursor = "pointer";
    prow.addEventListener("click", () => {
      const isOpen = prow.dataset.open === "1";
      prow.dataset.open = isOpen ? "0" : "1";

      const rows = tbody.querySelectorAll(
        `tr.overview-item-grant-row[data-item-id="${group.itemId}"]`
      );
      rows.forEach((r) => {
        r.style.display = isOpen ? "none" : "";
      });

      updateItemRowLabel(prow, nameCell);
    });
  }
}

/* ---------- Mode: By Requester ---------- */

function renderByRequester(tbody, grants, opts = {}) {
  const { onJumpToItem } = opts || {};
  const byRequester = new Map();

  for (const g of grants) {
    if (!g || !g.requester_id) continue;
    const key = g.requester_id;

    let slot = byRequester.get(key);
    if (!slot) {
      slot = {
        requesterId: key,
        grants: [],
      };
      byRequester.set(key, slot);
    }
    slot.grants.push(g);
  }

  const groups = Array.from(byRequester.values()).sort((a, b) => {
    const an = (a.requesterId || "").toLowerCase();
    const bn = (b.requesterId || "").toLowerCase();
    if (an < bn) return -1;
    if (an > bn) return 1;
    return a.requesterId.localeCompare(b.requesterId);
  });

  if (!groups.length) {
    appendEmptyRow(tbody, "No grants yet.");
    return;
  }

  for (const group of groups) {
    const prow = document.createElement("tr");
    prow.className = "overview-requester-row";
    prow.dataset.requesterId = group.requesterId;
    prow.dataset.open = "0";

    const nameCell = document.createElement("td");
    nameCell.dataset.labelBase = group.requesterId;

    const countCell = document.createElement("td");
    const count = group.grants.length;
    countCell.textContent = count
      ? `${count} item${count === 1 ? "" : "s"}`
      : "No items";

    prow.appendChild(nameCell);
    prow.appendChild(countCell);
    tbody.appendChild(prow);

    // Initial label with arrow
    updateRequesterRowLabel(prow, nameCell);

    // Child rows (one per granted item)
    for (const g of group.grants) {
      const row = document.createElement("tr");
      row.className = "overview-requester-grant-row";
      row.dataset.requesterId = group.requesterId;
      row.dataset.itemId = g.provider_item_id;
      row.style.display = "none";

      const primary = document.createElement("td");
      const baseName = g.provider_item_name || g.provider_item_id;
      primary.textContent = `↳ ${baseName}`;
      primary.style.paddingLeft = "1.5rem";

      const secondary = document.createElement("td");
      // Here the valueStr lives naturally next to the item name
      secondary.textContent = g.provider_valueStr || "";

      row.appendChild(primary);
      row.appendChild(secondary);
      tbody.appendChild(row);

      // Ctrl+click on item -> jump to "By Item" for that item
      row.addEventListener("click", (ev) => {
        if (!(ev.ctrlKey && ev.button === 0)) return;
        ev.preventDefault();
        ev.stopPropagation();
        if (typeof onJumpToItem === "function") {
          onJumpToItem(g.provider_item_id);
        }
      });
    }

    prow.style.cursor = "pointer";
    prow.addEventListener("click", () => {
      const isOpen = prow.dataset.open === "1";
      prow.dataset.open = isOpen ? "0" : "1";

      const rows = tbody.querySelectorAll(
        `tr.overview-requester-grant-row[data-requester-id="${group.requesterId}"]`
      );
      rows.forEach((r) => {
        r.style.display = isOpen ? "none" : "";
      });

      updateRequesterRowLabel(prow, nameCell);
    });
  }
}

/* ---------- Label helpers for parent rows ---------- */

function updateItemRowLabel(prow, nameCell) {
  const arrow = prow.dataset.open === "1" ? "▼" : "▶";
  const base  = nameCell.dataset.labelBase || "";
  nameCell.textContent = `${arrow} ${base}`;
}

function updateRequesterRowLabel(prow, nameCell) {
  const arrow = prow.dataset.open === "1" ? "▼" : "▶";
  const base  = nameCell.dataset.labelBase || "";
  nameCell.textContent = `${arrow} ${base}`;
}

/* ---------- Focus & expand helpers ---------- */

function focusAndExpandItemRow(tbody, itemId) {
  if (!itemId) return;
  const prow = tbody.querySelector(
    `tr.overview-item-row[data-item-id="${itemId}"]`
  );
  if (!prow) return;

  const nameCell = prow.querySelector("td");
  prow.dataset.open = "1";

  const rows = tbody.querySelectorAll(
    `tr.overview-item-grant-row[data-item-id="${itemId}"]`
  );
  rows.forEach((r) => {
    r.style.display = "";
  });

  if (nameCell) {
    updateItemRowLabel(prow, nameCell);
  }

  if (!prow.hasAttribute("tabindex")) {
    prow.setAttribute("tabindex", "-1");
  }
  prow.focus({ preventScroll: false });
  prow.scrollIntoView({ block: "nearest" });
}

function focusAndExpandRequesterRow(tbody, requesterId) {
  if (!requesterId) return;
  const prow = tbody.querySelector(
    `tr.overview-requester-row[data-requester-id="${requesterId}"]`
  );
  if (!prow) return;

  const nameCell = prow.querySelector("td");
  prow.dataset.open = "1";

  const rows = tbody.querySelectorAll(
    `tr.overview-requester-grant-row[data-requester-id="${requesterId}"]`
  );
  rows.forEach((r) => {
    r.style.display = "";
  });

  if (nameCell) {
    updateRequesterRowLabel(prow, nameCell);
  }

  if (!prow.hasAttribute("tabindex")) {
    prow.setAttribute("tabindex", "-1");
  }
  prow.focus({ preventScroll: false });
  prow.scrollIntoView({ block: "nearest" });
}

/* ---------- Small helper ---------- */

function appendEmptyRow(tbody, message) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 2;
  td.textContent = message;
  td.style.fontStyle = "italic";
  tr.appendChild(td);
  tbody.appendChild(tr);
}
