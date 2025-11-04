// In-memory only; no storage.
// Personal table: read-only by default; editable ONLY with Ctrl + left click.
// Simple left click = focus/caret, no border. Right click = no caret, no border, exit edit mode.
// Requests table unchanged.

(function () {
  /* ---------------- Utilities ---------------- */
  function createRow(panelEl) {
    const isRequests = panelEl?.dataset.panel === 'requests';

    const tr = document.createElement('tr');

    // First column
    const td1 = document.createElement('td');
    const input1 = document.createElement('input');
    input1.type = 'text';
    input1.placeholder = isRequests ? 'Request' : 'Field';
    input1.autocomplete = 'off';
    if (!isRequests) {
      input1.readOnly = true;  // personal: RO by default
      input1.tabIndex = 0;     // allow caret/selection
    }
    td1.appendChild(input1);

    // Second column
    const td2 = document.createElement('td');
    const input2 = document.createElement('input');
    input2.type = 'text';
    input2.placeholder = isRequests ? 'Details' : 'Value';
    input2.autocomplete = 'off';
    if (!isRequests) {
      input2.readOnly = true;  // personal: RO by default
      input2.tabIndex = 0;
    }
    td2.appendChild(input2);

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

    if (panelEl.dataset.panel === 'personal') {
      const val = row.querySelector('td:nth-child(2) input[type="text"]');
      if (val) val.focus(); // caret ok, still read-only
    }

    updateRequestsCount(panelEl);
  }

  /* ---------------- New Item Modal (Personal -> Add row) ---------------- */
  const newItemOverlay = document.getElementById('new-item-dialog');
  const newItemConfirm = newItemOverlay.querySelector('[data-action="confirm-dialog"]');
  const newItemCancel  = newItemOverlay.querySelector('[data-action="cancel-dialog"]');

  function openNewItemDialog() {
    newItemOverlay.querySelectorAll('input[type="text"]').forEach((inp) => { inp.value = ''; });
    newItemConfirm.disabled = true;
    newItemOverlay.classList.add('open');
    const first = newItemOverlay.querySelector('input[data-field="Item Name"]');
    if (first) first.focus();
  }
  function closeNewItemDialog() { newItemOverlay.classList.remove('open'); }
  function validateNewItemDialog() {
    const name  = newItemOverlay.querySelector('input[data-field="Item Name"]').value.trim();
    const value = newItemOverlay.querySelector('input[data-field="Value"]').value.trim();
    newItemConfirm.disabled = !(name && value);
  }
  newItemOverlay.addEventListener('input', (e) => {
    if (e.target.matches('.modal-table input[type="text"]')) validateNewItemDialog();
  });
  newItemCancel.addEventListener('click', closeNewItemDialog);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && newItemOverlay.classList.contains('open')) closeNewItemDialog();
  });
  newItemOverlay.addEventListener('mousedown', (e) => {
    if (e.target === newItemOverlay) closeNewItemDialog();
  });
  newItemConfirm.addEventListener('click', () => {
    if (newItemConfirm.disabled) return;

    const rows = newItemOverlay.querySelectorAll('.modal-table tbody tr');
    const content = Array.from(rows).map((row) => {
      const label = row.querySelector('th')?.textContent?.trim() || '';
      const value = row.querySelector('input')?.value?.trim() || '';
      return [label, value];
    });

    const name  = content[0]?.[1] || '';
    const value = content[1]?.[1] || '';

    const personalPanel = document.querySelector('.panel[data-panel="personal"]');
    const tbody = personalPanel?.querySelector('tbody');
    if (tbody) {
      const row = createRow(personalPanel);
      const inputs = row.querySelectorAll('input[type="text"]');
      if (inputs[0]) inputs[0].value = name;
      if (inputs[1]) inputs[1].value = value;
      tbody.appendChild(row);
      if (inputs[1]) inputs[1].focus();
    }

    closeNewItemDialog();
  });

  /* ----------- Ctrl + Left-click editing (PERSONAL ONLY) ----------- */
  (function setupCtrlClickEditing() {
    const personalPanel = document.querySelector('.panel[data-panel="personal"]');
    if (!personalPanel) return;

    const tbody = personalPanel.querySelector('tbody');

    // Handle mouse down first to set editability BEFORE focus/caret is placed.
    personalPanel.addEventListener('mousedown', (e) => {
      // Support clicks anywhere in the cell (td) or directly on the input
      const cell = e.target.closest('td');
      if (!cell) return;
      const input = cell.querySelector('input[type="text"]');
      if (!input || !tbody.contains(input)) return;

      // Right-click: prevent caret & exit edit mode
      if (e.button === 2) {
        e.preventDefault();                 // avoid focusing/caret on right click
        input.readOnly = true;
        input.classList.remove('editing');  // no border
        return;
      }

      // Ctrl + left-click: enter edit mode (show border)
      if (e.button === 0 && e.ctrlKey) {
        input.readOnly = false;
        input.classList.add('editing');
        // allow default so caret lands correctly
        return;
      }

      // Plain left-click: stay read-only, no border
      if (e.button === 0 && !e.ctrlKey) {
        input.readOnly = true;
        input.classList.remove('editing');
        // allow default (caret & selection OK)
        return;
      }
    });

    // Exit edit mode on Enter/Escape -> blur
    personalPanel.addEventListener('keydown', (e) => {
      const input = e.target;
      if (!(input instanceof HTMLInputElement)) return;
      if (e.key === 'Enter' || e.key === 'Escape') input.blur();
    });

    // On blur: lock and remove edit border
    personalPanel.addEventListener('blur', (e) => {
      const input = e.target;
      if (!(input instanceof HTMLInputElement)) return;
      if (!tbody.contains(input)) return;
      input.readOnly = true;
      input.classList.remove('editing');
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
})();
