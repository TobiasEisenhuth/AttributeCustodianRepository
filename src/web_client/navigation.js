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

  const hashView = (location.hash || '').slice(1);
  const ariaCurrent = q('.nav-btn[aria-current="page"]')?.dataset.view;
  const initial = hashView || ariaCurrent || DEFAULT_VIEW;

  document.addEventListener('click', onNavClick);
  window.addEventListener('hashchange', onHashChange);

  setView(initial, { push: false, focus: false });
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

  const hasRight = panels.some(
    p => p.dataset.view === view && p.dataset.slot === 'right' && !p.hasAttribute('hidden')
  );
  dashboardEl?.classList.toggle('is-one-col', !hasRight);
}

export function setView(view, { push = true, focus = true } = {}) {
  if (!view) view = DEFAULT_VIEW;
  if (currentView === view) {
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

  window.dispatchEvent(new CustomEvent('viewchange', { detail: { view } }));

  if (focus) focusActiveHeading();
}

export function getView() {
  return currentView || DEFAULT_VIEW;
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init, { once: true });
} else {
  init();
}

