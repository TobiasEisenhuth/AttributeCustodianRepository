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

export function normalizeText(s) {
  return String(s ?? "").replace(/\s+/g, " ").trim();
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
  delete btnAdd.dataset.busy;
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

async function deriveAesKeyPBKDF2(passkeyBytes, saltBytes, iterations = 100_000, keyLen = 256) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passkeyBytes,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: keyLen },
    false,
    ["encrypt", "decrypt"]
  );
}

// todo - true for production
const USE_CRYPTO = false;
export async function packUserStoreToEnvelope(userStore, passkey) {
  const {ephemeral, ...persistent} = userStore
  const persistent_utf_8 = JSON.stringify(persistent);
  const persistent_bytes = end.encode(persistent_utf_8);

  if (!USE_CRYPTO) {
    const envelope = {
      v: 1,
      enc: "none",
      ct_b64: bytesToBase64(persistent_bytes),
    };
    const envelope_bytes = enc.encode(JSON.stringify(envelope));
    return bytesToBase64(envelope_bytes);
  }

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  const key = await deriveAesKeyPBKDF2(enc.encode(passkey), salt);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, persistent_bytes);
  const cipher_bytes = new Uint8Array(cipher);

  const envelope = {
    v: 1,
    enc: "aes-256-gcm",
    kdf: "pbkdf2-sha256",
    iterations: 100_000,
    salt_b64: bytesToBase64(salt),
    nonce_b64: bytesToBase64(nonce),
    ct_b64: bytesToBase64(cipher_bytes),
  };
  const envelope_bytes = enc.encode(JSON.stringify(envelope));
  return bytesToBase64(envelope_bytes);
}

export async function extractStoreFromEnvelope(envelopeB64, passkey = null ) {
  const envelope_bytes = base64ToBytes(envelopeB64);
  const envelope_utf_8 = dec.decode(envelope_bytes);
  const envelope = JSON.parse(envelope_utf_8);

  if (!envelope || envelope.v !== 1 || !envelope.enc) {
    throw new Error("Invalid envelope.");
  }

  if (envelope.enc === "none") {
    const plaint_text = base64ToBytes(envelope.ct_b64);
    return JSON.parse(dec.decode(plaint_text));
  }

  if (envelope.enc === "aes-256-gcm") {
    if (!passkey) throw new Error("Passkey required to decrypt.");
    const salt = base64ToBytes(envelope.salt_b64);
    const nonce = base64ToBytes(envelope.nonce_b64);
    const cipher_text = base64ToBytes(envelope.ct_b64);
    const iterations = envelope.iterations;
    const key = await deriveAesKeyPBKDF2(enc.encode(passkey), salt, iterations);

    const plain_text_b64 = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, cipher_text);
    const plain_text_bytes = new Uint8Array(plain_text_b64);
    return JSON.parse(dec.decode(plain_text_bytes));
  }

  throw new Error(`Unsupported enc: ${envelope.enc}`);
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