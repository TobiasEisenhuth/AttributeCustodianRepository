// crs-sdk.js (ESM)
export class CRSClient {
  /**
   * @param {string} base Base URL (default same-origin, e.g. "")
   */
  constructor(base = "") {
    this.base = base;
  }

  async _fetch(path, opts = {}) {
    const { method = "POST", body, headers = {}, ...rest } = opts;
    const jsonHeader = body ? { "Content-Type": "application/json" } : null;
    const mergedHeaders = jsonHeader ? { ...jsonHeader, ...headers } : headers;

    const res = await fetch(this.base + path, {
      method,
      body: body ? JSON.stringify(body) : undefined,
      headers: mergedHeaders,
      ...rest,
      credentials: "include",
    });

    let data = null;
    try { data = await res.json(); } catch {}

    if (!res.ok) {
      let msg = data?.detail || data?.error || `HTTP ${res.status}`;
      if (Array.isArray(data?.detail)) {
        msg = data.detail.map(d => d?.msg || JSON.stringify(d)).join(" | ");
      }
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  // ---------- Auth ----------
  register(email, password, rest) {
    return this._fetch("/auth/register", { body: { email, password }, ...(rest||{}) });
  }
  login(email, password, rest) {
    return this._fetch("/auth/login", { body: { email, password }, ...(rest||{}) });
  }
  logout(rest) {
    return this._fetch("/auth/logout", { ...(rest||{}) });
  }

  // ---------- Vault ----------
  saveToVault(user_store_b64, rest) {
    return this._fetch("/api/save_to_vault", {
      method: "PUT",
      body: { user_store_b64 },
      ...(rest||{}),
    });
  }
  loadFromVault(rest) {
    return this._fetch("/api/load_from_vault", { method: "GET", ...(rest||{}) });
  }

  // ---------- Inventory (provider) ----------
  listMyItems(rest) {
    return this._fetch("/api/list_my_items", { method: "GET", ...(rest||{}) });
  }

  // ---------- Post Office (Solicitations) ----------
  pushSolicitation(provider_id, payload, rest) {
    return this._fetch("/api/push_solicitation", { body: { provider_id, payload }, ...(rest||{}) });
  }
  pullSolicitationBundle(rest) {
    // server expects POST with (empty) JSON body
    return this._fetch("/api/pull_solicitation_bundle", { body: {}, ...(rest||{}) });
  }
  ackSolicitationBundle({ requester_id, max_created_at, max_request_id }, rest) {
    return this._fetch("/api/ack_solicitation_bundle", {
      body: { requester_id, max_created_at, max_request_id },
      ...(rest||{}),
    });
  }

  // ---------- CRS (PRE) ----------
  upsertItem(b, rest) {
    return this._fetch("/api/upsert_item", { body: b, ...(rest||{}) });
  }
  eraseItem(item_id, rest) {
    return this._fetch("/api/erase_item", { body: { item_id }, ...(rest||{}) });
  }
  grantAccess(b, rest) {
    return this._fetch("/api/grant_access", { body: b, ...(rest||{}) });
  }
  revokeAccess({ requester_id, provider_item_id }, rest) {
    return this._fetch("/api/revoke_access", { body: { requester_id, provider_item_id }, ...(rest||{}) });
  }
  requestItem(b, rest) {
    return this._fetch("/api/request_item", { body: b, ...(rest||{}) });
  }
}
