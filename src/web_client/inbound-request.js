import {
  setStatus,
  setStateChip,
  bytesToBase64,
  base64ToBytes,
} from "/app/utils.js";
import { getCurrentOptions } from "/app/user-store.js";
import { loadUmbral } from "/app/umbral-loader.js";

async function grantFlow({ requester_id, ack_token, items, cleanup }) {

    const providerItems = store?.persistent?.provider?.items;
    if (!Array.isArray(providerItems)) {
      setStateChip("Error", "err");
      setStatus("No provider items found in persistent store.");
      return;
    }

    setStateChip("Granting…", "warn");
    setStatus("Generating re-encryption keys…");

    const umbral = await loadUmbral();
    if (!umbral) {
      setStateChip("Error", "err");
      setStatus("Umbral not available.", "err");
      return;
    }

    try {
      for (const it of items) {
        const pEntry = providerItems.find(e => e?.item_id === it.provider_item_id);
        if (!pEntry?.keys?.secret_key_b64 || !pEntry?.keys?.signing_key_b64) {
          throw new Error(`Missing keys for provider item ${it.provider_item_id}.`);
        }

        const delegating_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(pEntry.keys.secret_key_b64));
        const signing_sk    = umbral.SecretKey.fromBEBytes(base64ToBytes(pEntry.keys.signing_key_b64));
        const signer        = new umbral.Signer(signing_sk);

        const recv_pk_b     = base64ToBytes(it.requester_public_key_b64);
        const receiving_pk  = umbral.PublicKey.fromCompressedBytes(recv_pk_b);

        // 1-of-1 kfrags
        const kfrags = umbral.generateKFrags(delegating_sk, receiving_pk, signer, 1, 1);
        if (!Array.isArray(kfrags) || !kfrags.length) {
          throw new Error("Failed to generate kfrags.");
        }
        const kfrags_b64 = kfrags.map(k => bytesToBase64(k.toBytes()));

        await api.grantAccess({
          requester_id,
          provider_item_id: it.provider_item_id,
          requester_item_id: it.requester_item_id,
          kfrags_b64,
        }, withTimeoutInit());
      }

      setStatus("Access granted. Acknowledging bundle…");

      await api.ackSolicitationBundle({
        requester_id,
        max_created_at: ack_token?.max_created_at,
        max_request_id: ack_token?.max_request_id,
      }, withTimeoutInit());

      // Remove the rendered group & reset count
      cleanup();
      totalRows = 0;

      setStateChip("Synced", "ok");
      setStatus("Bundle acknowledged. Loading next (if any)…");

      await pullAndRender();
    } catch (err) {
      setStateChip("Error", "err");
      setStatus(err?.message || "Failed to grant/acknowledge bundle.");
    }
  }

export function wireUpInboundRequests({ api, store }) {

  const panel = q('.panel[data-panel="requests"]');
  const table = panel.querySelector("table");
  const tbody = table?.querySelector("tbody");

  const options = getCurrentOptions(store);

  async function pullAndRender() {
    if (!panel.isConnected) return false;

    setStateChip("Loading…", "warn");
    setStatus("Checking inbound requests…");
    let res = null;

    try {
      res = await api.pullSolicitationBundle(withTimeoutInit());
    } catch (e) {
      setStateChip("Error", "err");
      setStatus(e?.message || "Failed to load inbound requests.");
      return false;
    }

    if (!panel.isConnected) return false;

    if (!res?.has_any) {
      totalRows = 0;
      setCount(0);
      tbody.appendChild(tdColspan("No inbound requests.", 2));
      setStateChip("Idle", "muted");
      setStatus("No inbound requests.");
      return false;
    }

    renderBundleIntoTable({
      table,
      bundleJson: res,
      options,
      onGrant: ({ requester_id, ack_token, items, cleanup }) => grantFlow({ requester_id, ack_token, items, cleanup }),
    });

    const justAdded = (Array.isArray(res.bundle?.requests)
      ? res.bundle.requests.reduce((acc, r) => acc + ((r.payload?.rows?.length) || 0), 0)
      : 0);
    totalRows = justAdded;  // we just replaced table; count what’s visible
    setCount(totalRows);

    setStateChip("Ready", "ok");
    setStatus("Inbound request loaded.");
    return true;
  }

  

  pullAndRender().catch((e) => {
    setStateChip("Error", "err");
    setStatus(e?.message || "Failed to load inbound requests.");
  });
}
