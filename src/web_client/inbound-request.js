import {
  dec,
  revisiting,
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
        });
      }

      setStatus("Access granted. Acknowledging bundle…");

      await api.ackSolicitationBundle({
        requester_id,
        max_created_at: ack_token?.max_created_at,
        max_request_id: ack_token?.max_request_id,
      });

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

async function loadInboundRequests(api, store) {
  setStateChip("Loading…", "warn");
  setStatus("Loading inbound solicitations…");

  let bundle;
  try {
    bundle = await api.pullSolicitationBundle();
  } catch (err) {
    setStateChip("Error", "err");
    setStatus(err?.message || "Failed to load inbound requests.");
  }

  if (!bundle.has_any) {
    setStateChip("Idle", "muted");
    setStatus("No inbound requests.");
  }

  if (!store.good) {
    setStateChip("Error", "err");
    setStatus("Store not good!");
  }

  const umbral = await loadUmbral();
  if (!umbral) {
    setStateChip("Error", "err");
    setStatus("Umbral not available.", "err");
    return;
  }

  const requests = store.ephemeral.provider.requests;

  const existingIds = new Set(requests.map(it => it?.request_id).filter(Boolean));

  for (const request of bundle.solicitations) {

    let payload;
    try {
      const request_bytes = base64ToBytes(request.payload_b64);
      const request_utf_8 = dec.decode(request_bytes);
      payload = JSON.parse(request_utf_8);
    } catch (err) {
      console.error("Failed to decode solicitation payload", err, payload);
      continue;
    }

    if (existingIds.has(request.request_id)) continue;

    const items = [];
    for (const item of payload.items) {
      items.push({
        item_id: item.item_id,
        item_name: item.item_name,
        requester_public_key_b64: item.requester_public_key_b64,
        value_example: item.value_example,
        default_field: item.default_field,
      })
    }

    requests.push({
      request_id: request.request_id,
      requester_id: request.requester_id,
      info_string: payload.info_string || "",
      items: items,
    });
  }

  setStateChip("Ready", "ok");
  setStatus(`Loaded ${requests.length} inbound payload(s).`);

  // todo - remove for production
  try { sessionStorage.setItem('crs:store', JSON.stringify(store)); } catch {}
}

export async function wireUpInboundRequests({ api, store }) {
  if (revisiting("wireUpInboundRequests")) return;

  await loadInboundRequests(api, store);
}
