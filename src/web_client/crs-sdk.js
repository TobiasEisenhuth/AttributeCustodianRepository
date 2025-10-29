// crs-sdk.js (ESM)
export class CRSClient {
  /**
   * @param {string} base Base URL (default same-origin, e.g. "")
   */
  constructor(base = "") {
    this.base = base;
  }

  async _fetch(path, { method = "POST", body, signal } = {}) {
    const res = await fetch(this.base + path, {
      method,
      signal,
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
  register(email, password, opts = {}) {
    return this._fetch("/auth/register", { body: { email, password }, ...opts });
  }
  login(email, password, opts = {}) {
    return this._fetch("/auth/login", { body: { email, password }, ...opts });
  }
  logout(opts = {}) {
    return this._fetch("/auth/logout", opts);
  }

  // ---------- Vault (no vault_salt anymore) ----------
  saveToVault(encrypted_localstore_b64, opts = {}) {
    return this._fetch("/api/save_to_vault", {
      method: "PUT",
      body: { encrypted_localstore_b64 },
      ...opts,
    });
  }
  loadFromVault(opts = {}) {
    return this._fetch("/api/load_from_vault", { method: "GET", ...opts });
  }

  // ---------- Post Office (Solicitations) ----------
  pushSolicitation(provider_id, payload, opts = {}) {
    return this._fetch("/api/push_solicitation", { body: { provider_id, payload }, ...opts });
  }
  pullSolicitationBundle(opts = {}) {
    // server expects a POST with an (empty) JSON body
    return this._fetch("/api/pull_solicitation_bundle", { body: {}, ...opts });
  }
  ackSolicitationBundle({ requester_id, max_created_at, max_request_id }, opts = {}) {
    return this._fetch("/api/ack_solicitation_bundle", {
      body: { requester_id, max_created_at, max_request_id },
      ...opts,
    });
  }

  // ---------- CRS (PRE) ----------
  upsertItem(b, opts = {}) {
    return this._fetch("/api/upsert_item", { body: b, ...opts });
  }
  eraseItem(item_id, opts = {}) {
    return this._fetch("/api/erase_item", { body: { item_id }, ...opts });
  }
  grantAccess(b, opts = {}) {
    return this._fetch("/api/grant_access", { body: b, ...opts });
  }
  revokeAccess({ requester_id, provider_item_id }, opts = {}) {
    return this._fetch("/api/revoke_access", { body: { requester_id, provider_item_id }, ...opts });
  }
  requestItem(b, opts = {}) {
    return this._fetch("/api/request_item", { body: b, ...opts });
  }
}
