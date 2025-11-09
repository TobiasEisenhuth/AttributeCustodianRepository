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

export function fail(message, tone = "err") {
  setStateChip("Error", "err");
  setStatus(message, tone);
  delete btnAdd.dataset.busy;
}

function ensureVault(store) {
  store.persistent ??= {};
  store.persistent.provider ??= {};
  store.persistent.provider.items ??= [];
  store.ephemeral ??= {};
  store.ephemeral.provider ??= {};
  store.ephemeral.provider.values ??= [];
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

export async function packStoreToEnvelope(store, passkey = null) {
  const payloadText = JSON.stringify(store);
  const payloadBytes = te.encode(payloadText);

  if (!passkey) {
    const envelope = {
      v: 1,
      enc: "none",
      ct_b64: bytesToBase64(payloadBytes),
    };
    const envBytes = enc.encode(JSON.stringify(envelope));
    return bytesToBase64(envBytes);
  }

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  const key = await deriveAesKeyPBKDF2(enc.encode(passkey), salt);
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, payloadBytes);
  const cipher_text = new Uint8Array(ctBuf);

  const envelope = {
    v: 1,
    enc: "aes-256-gcm",
    kdf: "pbkdf2-sha256",
    iterations: 100_000,
    salt_b64: bytesToBase64(salt),
    nonce_b64: bytesToBase64(nonce),
    ct_b64: bytesToBase64(cipher_text),
  };
  const envBytes = te.encode(JSON.stringify(envelope));
  return bytesToBase64(envBytes);
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

// ---------- Public: manager that “just does the right thing” ----------
export async function materializeStoreFromBlob(envelopeB64, { passkey = null } = {}) {
  // Single entry point for callers who don't care about modes.
  return decryptBlobToStore(envelopeB64, { passkey });
}