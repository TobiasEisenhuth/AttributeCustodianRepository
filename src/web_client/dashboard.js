// In-memory only; no storage.
// Personal table: read-mode text (copyable) + Ctrl+Left-click to switch to edit mode.
// Plain left click: highlight/copy only (no focus/caret). Ctrl+Left-click: editable with border.
// Right click exits edit mode. Requests table unchanged.

(function () {
  /* ---------------- Helpers ---------------- */

  function makePersonalCell(initialValue, placeholder) {
    // <div class="cell read-mode"><span class="ro-text"></span><input ...></div>
    const wrapper = document.createElement('div');
    wrapper.className = 'cell read-mode';

    const ro = document.createElement('span');
    ro.className = 'ro-text';
    ro.textContent = initialValue || '';

    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = placeholder || '';
    input.autocomplete = 'off';
    input.readOnly = true; // read-mode by default
    input.tabIndex = 0;

    wrapper.appendChild(ro);
    wrapper.appendChild(input);

    return { wrapper, ro, input };
  }

  function enterEditMode(wrapper, input) {
    input.readOnly = false;
    input.classList.add('editing');
    wrapper.classList.remove('read-mode');
    wrapper.classList.add('edit-mode');
    // Let the browser handle caret placement naturally
    setTimeout(() => { input.focus(); }, 0);
  }

  function exitEditMode(wrapper, ro, input) {
    // Sync display text, lock input, remove border, show read-mode
    ro.textContent = input.value || '';
    input.readOnly = true;
    input.classList.remove('editing');
    wrapper.classList.remove('edit-mode');
    wrapper.classList.add('read-mode');
  }

  /* ---------------- Row creation ---------------- */

  function createRow(panelEl) {
    const isRequests = panelEl?.dataset.panel === 'requests';
    const tr = document.createElement('tr');

    // First column
    const td1 = document.createElement('td');
    if (isRequests) {
      const input1 = document.createElement('input');
      input1.type = 'text';
      input1.placeholder = 'Request';
      input1.autocomplete = 'off';
      td1.appendChild(input1);
    } else {
      const { wrapper, ro, input } = makePersonalCell('', 'Field');
      td1.appendChild(wrapper);
    }

    // Second column
    const td2 = document.createElement('td');
    if (isRequests) {
      const input2 = document.createElement('input');
      input2.type = 'text';
      input2.placeholder = 'Details';
      input2.autocomplete = 'off';
      td2.appendChild(input2);
    } else {
      const { wrapper, ro, input } = makePersonalCell('', 'Value');
      td2.appendChild(wrapper);
    }

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
      // Fill values and sync ro-text
      const cells = row.querySelectorAll('td .cell');
      const [fieldCell, valueCell] = cells;
      if (fieldCell) {
        const input = fieldCell.querySelector('input');
        const ro = fieldCell.querySelector('.ro-text');
        input.value = name;
        ro.textContent = name;
      }
      if (valueCell) {
        const input = valueCell.querySelector('input');
        const ro = valueCell.querySelector('.ro-text');
        input.value = value;
        ro.textContent = value;
      }
      tbody.appendChild(row);
    }

    closeNewItemDialog();
  });

  /* ----------- Ctrl + Left-click editing (PERSONAL ONLY) ----------- */
  (function setupCtrlClickEditing() {
    const personalPanel = document.querySelector('.panel[data-panel="personal"]');
    if (!personalPanel) return;
    const tbody = personalPanel.querySelector('tbody');

    // Track Ctrl key for hover-caret CSS (.ctrl-down on <body>)
    function setCtrlDown(on) { document.body.classList.toggle('ctrl-down', !!on); }
    document.addEventListener('keydown', (e) => { if (e.ctrlKey) setCtrlDown(true); });
    document.addEventListener('keyup', (e) => {
      if (e.key === 'Control' || !e.ctrlKey) setCtrlDown(false);
    });
    window.addEventListener('blur', () => setCtrlDown(false));

    // Mousedown handler controls mode switching
    personalPanel.addEventListener('mousedown', (e) => {
      const td = e.target.closest('td');
      if (!td) return;
      const wrapper = td.querySelector('.cell');
      if (!wrapper) return;
      const input = wrapper.querySelector('input[type="text"]');
      const ro = wrapper.querySelector('.ro-text');
      if (!input || !ro || !tbody.contains(wrapper)) return;

      // Right-click: prevent caret & exit edit mode if active
      if (e.button === 2) {
        e.preventDefault();
        exitEditMode(wrapper, ro, input);
        return;
      }

      // Ctrl + left-click: enter edit mode
      if (e.button === 0 && e.ctrlKey) {
        enterEditMode(wrapper, input);
        return;
      }

      // Plain left click: read-mode text can be selected/copy; do nothing (no preventDefault)
    });

    // Exit edit mode on Enter/Escape -> blur
    personalPanel.addEventListener('keydown', (e) => {
      const input = e.target;
      if (!(input instanceof HTMLInputElement)) return;
      if (e.key === 'Enter' || e.key === 'Escape') input.blur();
    });

    // On blur: lock and remove edit border, sync text
    personalPanel.addEventListener('blur', (e) => {
      const input = e.target;
      if (!(input instanceof HTMLInputElement)) return;
      const wrapper = input.closest('.cell');
      const ro = wrapper?.querySelector('.ro-text');
      if (!wrapper || !ro || !tbody.contains(wrapper)) return;
      exitEditMode(wrapper, ro, input);
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
