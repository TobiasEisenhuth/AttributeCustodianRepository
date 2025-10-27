// crs-sdk.js (ESM)
export class CRSClient {
  /**
   * @param {string} base Base URL (default same-origin, e.g. "")
   */
  constructor(base = "") {
    this.base = base;
  }

  async _fetch(path, { method = "POST", body } = {}) {
    const res = await fetch(this.base + path, {
      method,
      credentials: "include", // send __Host-session cookie
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch {}
    if (!res.ok) {
      const msg = data?.detail || data?.error || `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  // ---------- Auth ----------
  register(email, password) {
    return this._fetch("/auth/register", { body: { email, password } });
  }
  login(email, password) {
    return this._fetch("/auth/login", { body: { email, password } });
  }
  logout() {
    return this._fetch("/auth/logout");
  }

  // ---------- Vault ----------
  /**
   * @param {string} encrypted_localstore_b64
   * @param {string} vault_salt_b64 (>=16 bytes when decoded)
   */
  saveToVault(encrypted_localstore_b64, vault_salt_b64) {
    return this._fetch("/api/save_to_vault", {
      method: "PUT",
      body: { encrypted_localstore_b64, vault_salt_b64 },
    });
  }
  loadFromVault() {
    return this._fetch("/api/load_from_vault", { method: "GET" });
  }

  // ---------- Post Office (Solicitations) ----------
  /**
   * @param {string} provider_id UUID
   * @param {{rows: Array<{field_description:string, secret_id:string, value_example_format:string, requester_public_key_b64:string, default_field?:string, request_order?:number}>}} payload
   */
  pushSolicitation(provider_id, payload) {
    return this._fetch("/api/push_solicitation", { body: { provider_id, payload } });
  }
  pullSolicitationBundle() {
    // server expects a POST with an (empty) JSON body
    return this._fetch("/api/pull_solicitation_bundle", { body: {} });
  }
  /**
   * @param {string} requester_id
   * @param {string} max_created_at ISO-8601
   * @param {string} max_request_id UUID
   */
  ackSolicitationBundle({ requester_id, max_created_at, max_request_id }) {
    return this._fetch("/api/ack_solicitation_bundle", {
      body: { requester_id, max_created_at, max_request_id },
    });
  }

  // ---------- CRS (PRE) ----------
  /**
   * @param {{item_id:string, capsule_b64:string, ciphertext_b64:string, provider_public_key_b64:string, provider_verifying_key_b64:string}} b
   */
  upsertItem(b) {
    return this._fetch("/api/upsert_item", { body: b });
  }
  eraseItem(item_id) {
    return this._fetch("/api/erase_item", { body: { item_id } });
  }
  /**
   * @param {{requester_id:string, provider_item_id:string, requester_item_id:string, kfrags_b64:string[]}} b
   */
  grantAccess(b) {
    return this._fetch("/api/grant_access", { body: b });
  }
  revokeAccess({ requester_id, provider_item_id }) {
    return this._fetch("/api/revoke_access", { body: { requester_id, provider_item_id } });
  }
  /**
   * @param {{provider_id:string, requester_item_id:string, requester_public_key_b64:string}} b
   */
  requestItem(b) {
    return this._fetch("/api/request_item", { body: b });
  }
}

