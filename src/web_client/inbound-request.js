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

function populateRequestsWidget(store) {
  const container = document.getElementById('requestsContainer');
  const requests = store.ephemeral.provider.requests;
  
  if (!requests || requests.length === 0) {
    container.innerHTML = '<div class="empty-state">No requests at this time</div>';
    return;
  }

  container.innerHTML = '';

  // Build provider options (filter to only items that have values)
  const providerOptions = [];
  for (const providerItem of store.persistent.provider.items) {
    const value = store.ephemeral.provider.values.get(providerItem.item_id);
    if (value !== undefined && value !== null) {
      providerOptions.push({
        item_id: providerItem.item_id,
        displayText: `${providerItem.item_name} -> ${value}`
      });
    }
  }

  // Group requests by requester_id (they're already ordered)
  let currentRequesterId = null;
  let requesterCard = null;
  let requesterContent = null;

  for (const request of requests) {
    // Start new requester card if requester_id changes
    if (request.requester_id !== currentRequesterId) {
      // Append previous requester card if it exists
      if (requesterCard && requesterContent) {
        requesterCard.appendChild(requesterContent);
        container.appendChild(requesterCard);
      }

      // Create new requester card
      currentRequesterId = request.requester_id;
      requesterCard = document.createElement('details');
      requesterCard.className = 'requester-card';
      requesterCard.open = true;

      const requesterSummary = document.createElement('summary');
      requesterSummary.textContent = request.requester_id;
      requesterCard.appendChild(requesterSummary);

      requesterContent = document.createElement('div');
      requesterContent.className = 'requester-content';
    }

    // Create request card
    const requestCard = document.createElement('article');
    requestCard.className = 'request-card';

    const requestTitle = document.createElement('h4');
    requestTitle.textContent = request.request_id;
    requestCard.appendChild(requestTitle);

    // Create form
    const form = document.createElement('form');
    form.className = 'request-form';
    form.dataset.requesterId = request.requester_id;
    form.dataset.requestId = request.request_id;

    const fieldset = document.createElement('fieldset');
    
    const legend = document.createElement('legend');
    legend.textContent = request.info_string || 'Request Details';
    fieldset.appendChild(legend);

    // Create form rows for each item
    request.items.forEach((item, index) => {
      const formRow = document.createElement('div');
      formRow.className = 'form-row';
      formRow.dataset.requesterId = request.requester_id;
      formRow.dataset.requestId = request.request_id;
      formRow.dataset.requesterItemId = item.item_id;

      const label = document.createElement('label');
      label.textContent = item.item_name;
      label.htmlFor = `${request.request_id}-item-${index}`;
      formRow.appendChild(label);

      const select = document.createElement('select');
      select.id = `${request.request_id}-item-${index}`;
      select.name = `item-${item.item_id}`;

      // Add placeholder option
      const placeholderOption = document.createElement('option');
      placeholderOption.value = '';
      if (item.value_example) {
        placeholderOption.textContent = `e.g., ${item.value_example}`;
      } else {
        placeholderOption.textContent = '-- Select --';
      }
      placeholderOption.disabled = true;
      placeholderOption.selected = true;
      select.appendChild(placeholderOption);

      // Add provider options
      providerOptions.forEach(providerOption => {
        const option = document.createElement('option');
        option.value = providerOption.item_id;
        option.textContent = providerOption.displayText;
        select.appendChild(option);
      });

      formRow.appendChild(select);
      fieldset.appendChild(formRow);
    });

    form.appendChild(fieldset);

    // Create button group
    const buttonGroup = document.createElement('div');
    buttonGroup.className = 'button-group';

    const approveBtn = document.createElement('button');
    approveBtn.type = 'button';
    approveBtn.className = 'btn btn-approve';
    approveBtn.textContent = 'Approve';
    // Handler to be implemented later

    const denyBtn = document.createElement('button');
    denyBtn.type = 'button';
    denyBtn.className = 'btn btn-deny';
    denyBtn.textContent = 'Deny';
    // Handler to be implemented later

    buttonGroup.appendChild(approveBtn);
    buttonGroup.appendChild(denyBtn);
    form.appendChild(buttonGroup);

    requestCard.appendChild(form);
    requesterContent.appendChild(requestCard);
  }

  // Append the last requester card
  if (requesterCard && requesterContent) {
    requesterCard.appendChild(requesterContent);
    container.appendChild(requesterCard);
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

  populateRequestsWidget(store);
}

export async function wireUpInboundRequests({ api, store }) {
  if (revisiting("wireUpInboundRequests")) return;

  await loadInboundRequests(api, store);
}
