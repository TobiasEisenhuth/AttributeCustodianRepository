// JS without inline handlers.
// - Requests panel: "Add row" appends blank row (as before)
// - Personal panel: "Add row" opens the New Item dialog
// - Personal panel: left ("Field") inputs are read-only by default; require right-click to edit

(function () {
  /* ---------------- Utilities ---------------- */

  function createRow(panelEl) {
    const isRequests = panelEl?.dataset.panel === 'requests';

    const tr = document.createElement('tr');

    const td1 = document.createElement('td');
    const input1 = document.createElement('input');
    input1.type = 'text';
    input1.placeholder = isRequests ? 'Request' : 'Field';
    input1.autocomplete = 'off';
    if (!isRequests) {
      // Personal panel: protect Field cell by default
      input1.readOnly = true;
      input1.classList.add('protected-field');
    }
    td1.appendChild(input1);

    const td2 = document.createElement('td');
    const input2 = document.createElement('input');
    input2.type = 'text';
    input2.placeholder = isRequests ? 'Details' : 'Value';
    input2.autocomplete = 'off';
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

    // Focus second cell by default (since first may be read-only)
    const focusTarget = row.querySelector('td:nth-child(2) input[type="text"]') || row.querySelector('input[type="text"]');
    if (focusTarget) focusTarget.focus();

    updateRequestsCount(panelEl);
  }

  /* ---------------- Modal: New Item ---------------- */

  const overlay = document.getElementById('new-item-dialog');
  const confirmBtn = overlay.querySelector('[data-action="confirm-dialog"]');
  const cancelBtn  = overlay.querySelector('[data-action="cancel-dialog"]');

  function openNewItemDialog() {
    // Clear inputs
    overlay.querySelectorAll('input[type="text"]').forEach((inp, idx) => {
      inp.value = '';
    });
    confirmBtn.disabled = true;
    overlay.classList.add('open');
    // Focus first input
    const first = overlay.querySelector('input[data-field="Item Name"]');
    if (first) first.focus();
  }

  function closeNewItemDialog() {
    overlay.classList.remove('open');
  }

  function validateDialog() {
    const name  = overlay.querySelector('input[data-field="Item Name"]').value.trim();
    const value = overlay.querySelector('input[data-field="Value"]').value.trim();
    confirmBtn.disabled = !(name && value);
  }

  overlay.addEventListener('input', (e) => {
    if (e.target.matches('.modal-table input[type="text"]')) validateDialog();
  });

  cancelBtn.addEventListener('click', closeNewItemDialog);

  // Close on ESC or clicking outside the modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlay.classList.contains('open')) {
      closeNewItemDialog();
    }
  });
  overlay.addEventListener('mousedown', (e) => {
    if (e.target === overlay) closeNewItemDialog();
  });

  confirmBtn.addEventListener('click', () => {
    if (confirmBtn.disabled) return;

    // Build JSON array of table content: [ [label, value], ... ]
    const rows = overlay.querySelectorAll('.modal-table tbody tr');
    const content = Array.from(rows).map((row) => {
      const label = row.querySelector('th')?.textContent?.trim() || '';
      const value = row.querySelector('input')?.value?.trim() || '';
      return [label, value];
    });

    // Store in sessionStorage
    try {
      sessionStorage.setItem('newItem', JSON.stringify(content));
      const key = 'newItems';
      const arr = JSON.parse(sessionStorage.getItem(key) || '[]');
      arr.push(content);
      sessionStorage.setItem(key, JSON.stringify(arr));
    } catch (err) {
      // Swallow storage errors silently for now
    }

    // Insert into the PERSONAL table: left = Item Name, right = Value
    const name  = content[0]?.[1] || '';
    const value = content[1]?.[1] || '';

    const personalPanel = document.querySelector('.panel[data-panel="personal"]');
    const tbody = personalPanel?.querySelector('tbody');
    if (tbody) {
      const row = createRow(personalPanel);
      const inputs = row.querySelectorAll('input[type="text"]');
      if (inputs[0]) inputs[0].value = name;   // Field (read-only, protected)
      if (inputs[1]) inputs[1].value = value;  // Value
      tbody.appendChild(row);
      // Focus the Value cell
      if (inputs[1]) inputs[1].focus();
    }

    closeNewItemDialog();
  });

  /* ---------------- Event wiring ---------------- */

  // "Add row" buttons (requests adds directly; personal opens dialog)
  document.addEventListener('click', function (e) {
    const btn = e.target.closest('[data-action="add-row"]');
    if (!btn) return;
    const panelEl = btn.closest('.panel');
    if (!panelEl) return;

    if (panelEl.dataset.panel === 'personal') {
      openNewItemDialog();
    } else {
      addRowForPanel(panelEl); // requests: same direct-add behavior
    }
  });

  // Initialize counts on load
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.panel').forEach(updateRequestsCount);
  });

  /* ----------- Protected left cell behavior (PERSONAL ONLY) ----------- */
  (function setupProtectedFieldEditing() {
    const personalPanel = document.querySelector('.panel[data-panel="personal"]');
    if (!personalPanel) return;

    // Left-click: focus but keep readOnly
    personalPanel.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return; // left only
      const input = e.target.closest('td:first-child input[type="text"]');
      if (!input) return;
      input.focus(); // focus/“select”
      // keep readOnly; user must right-click next
      e.preventDefault();
    });

    // Right-click (context menu): if focused, temporarily allow editing
    personalPanel.addEventListener('contextmenu', (e) => {
      const input = e.target.closest('td:first-child input[type="text"]');
      if (!input) return;
      e.preventDefault(); // use right-click to toggle edit

      if (document.activeElement !== input) return; // must have left-clicked first

      // Temporarily enable editing
      input.readOnly = false;
      input.classList.add('editing-field');
      input.select();

      // Finish editing on blur or Enter/Escape
      const onKey = (ev) => {
        if (ev.key === 'Enter' || ev.key === 'Escape') {
          ev.preventDefault();
          input.blur();
        }
      };
      const onBlur = () => {
        input.readOnly = true;
        input.classList.remove('editing-field');
        input.removeEventListener('keydown', onKey);
        input.removeEventListener('blur', onBlur);
      };

      input.addEventListener('keydown', onKey);
      input.addEventListener('blur', onBlur);
    });
  })();
})();
