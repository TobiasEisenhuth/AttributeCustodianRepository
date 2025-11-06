// navigation.js (ES module)
// Purpose: ONLY handle view switching (visibility/activeness). No business logic.

const DEFAULT_VIEW = 'share';

let currentView = null;
let panels = [];
let navButtons = [];
let dashboardEl = null;

function q(sel, root = document) { return root.querySelector(sel); }
function qa(sel, root = document) { return Array.from(root.querySelectorAll(sel)); }

function init() {
  dashboardEl = q('.dashboard');
  panels = qa('.panel');
  navButtons = qa('.nav-btn[data-action="nav-view"]');

  // Initial view: hash -> aria-current -> default
  const hashView = (location.hash || '').slice(1);
  const ariaCurrent = q('.nav-btn[aria-current="page"]')?.dataset.view;
  const initial = hashView || ariaCurrent || DEFAULT_VIEW;

  // Wire events
  document.addEventListener('click', onNavClick);
  window.addEventListener('hashchange', onHashChange);

  // First paint
  setView(initial, { push: false, focus: false });
  // After DOM is painted, move focus politely
  queueMicrotask(() => focusActiveHeading());
}

function onNavClick(e) {
  const btn = e.target.closest('.nav-btn[data-action="nav-view"]');
  if (!btn) return;
  const view = btn.dataset.view;
  setView(view);
}

function onHashChange() {
  const view = (location.hash || '').slice(1);
  if (!view) return;
  setView(view, { push: false });
}

function focusActiveHeading() {
  const title = q(`.panel[data-view="${currentView}"]:not([hidden]) .column-title`);
  if (!title) return;
  if (!title.hasAttribute('tabindex')) title.setAttribute('tabindex', '-1');
  title.focus({ preventScroll: false });
}

function updateNavState(view) {
  navButtons.forEach(btn => {
    if (btn.dataset.view === view) btn.setAttribute('aria-current', 'page');
    else btn.removeAttribute('aria-current');
  });
}

function togglePanels(view) {
  panels.forEach(p => {
    const active = p.dataset.view === view;
    p.toggleAttribute('hidden', !active);
    p.toggleAttribute('inert', !active);
  });

  // Toggle one-column layout if this view has no visible right panel
  const hasRight = panels.some(
    p => p.dataset.view === view && p.dataset.slot === 'right' && !p.hasAttribute('hidden')
  );
  dashboardEl?.classList.toggle('is-one-col', !hasRight);
}

export function setView(view, { push = true, focus = true } = {}) {
  if (!view) view = DEFAULT_VIEW;
  if (currentView === view) {
    // Even if same view, ensure hash/nav/panels are consistent
    if (push && location.hash !== `#${view}`) history.pushState({ view }, '', `#${view}`);
    updateNavState(view);
    togglePanels(view);
    if (focus) focusActiveHeading();
    return;
  }

  currentView = view;
  updateNavState(view);
  togglePanels(view);

  if (push && location.hash !== `#${view}`) {
    history.pushState({ view }, '', `#${view}`);
  }

  // Announce to other modules
  window.dispatchEvent(new CustomEvent('viewchange', { detail: { view } }));

  if (focus) focusActiveHeading();
}

export function getView() {
  return currentView || DEFAULT_VIEW;
}

// Auto-init when DOM is ready (works even if script is before </body>)
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init, { once: true });
} else {
  init();
}

