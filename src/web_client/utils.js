const set = new Set();
export function revisiting(name) {
  if (set.has(name)) return true;
  set.add(name);
  return false;
}

export const enc = new TextEncoder();
export const dec = new TextDecoder("utf-8");

export function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
} // -> string

export function base64ToBytes(base64) {
  const s = atob(base64);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
} // -> Uint8Array

export function base64UrlFromBytes(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
} // -> string (url safe)

export function nowIso() {
  return new Date().toISOString();
}

export function normalizeText(str) {
  return String(str ?? "").replace(/\s+/g, " ").trim();
}

export function generateItemId(existingIds) {
  let id;
  do {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    id = bytesToBase64(buf);
  } while (existingIds.has(id));
  return id;
}

export function setStateChip(text, tone = "muted") {
  const el = document.getElementById("state-chip");
  if (!el) return;
  el.textContent = text;
  el.className = `chip ${tone}`;
}

export function setStatus(text, tone = "muted") {
  const el = document.getElementById("status-line");
  if (!el) return;
  el.textContent = text;
  el.className = tone;
}

export function fail(message, tone = "err") {
  setStateChip("Error", "err");
  setStatus(message, tone);
}

// todo - use AJV?
function checkStoreMinimalCorrectness(store) {
  correct = false;
  return correct;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}

export function initUser() {
  if (revisiting('initUser')) return;

  const passkey = sessionStorage.getItem("crs:passkey") || null;
  if (passkey)
    sessionStorage.removeItem("crs:passkey");

  const email = sessionStorage.getItem("crs:email") || null;
  if (email)
    sessionStorage.removeItem("crs:email");

  if (email) {
    window.addEventListener("DOMContentLoaded", () => {
      const title = document.querySelector('.panel[data-panel="personal"] .column-title');
      if (title) title.textContent = `Personal Data | ${email}`;
    }, { once: true });
      window.addEventListener("DOMContentLoaded", () => {
      const title = document.querySelector('.panel[data-panel="builder-form"] .column-title');
      if (title) title.textContent = `Item builder | ${email}`;
    }, { once: true });
  }

  const is_owner_tab = !!passkey;

  return {is_owner_tab, passkey};
}