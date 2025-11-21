import {
  dec,
  revisiting,
  setStatus,
  setStateChip,
  bytesToBase64,
  base64ToBytes,
} from "/app/utils.js";
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
      const pEntry = providerItems.find(event => event?.item_id === it.provider_item_id);
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

export function updateProviderDatalist(store) {
  const validProviderIds = new Set();
  const datalist = document.getElementById('providerOptionsDatalist');
  if (!datalist) return validProviderIds;

  datalist.innerHTML = '';
  
  for (const providerItem of store.persistent.provider.items) {
    const value = store.ephemeral.provider.values.get(providerItem.item_id);
    if (value !== undefined && value !== null) {
      const option = document.createElement('option');
      option.dataset.itemId = providerItem.item_id;
      option.value = value;
      option.textContent = `${providerItem.item_name}: ${value}`;
      datalist.appendChild(option);
      validProviderIds.add(providerItem.item_id);
    }
  }

  return validProviderIds;
}

function validateInput(input, datalist, warn = false) {
  const options = Array.from(datalist.options);
  const match = options.find(opt => opt.value === input.value);

  if (input.value === '') {
    input.style.borderColor = '';
    delete input.dataset.itemId;
    return;
  }

  if (!match) {
    if (warn) input.style.borderColor = 'red';
    delete input.dataset.itemId;
    return;
  }

  input.style.borderColor = 'green';
  input.dataset.itemId = match.dataset.itemId;
}

function removeRequestFromUI(requestId) {
  const container = document.getElementById('requestsContainer');
  if (!container) return;

  // find the form for this request
  const forms = container.querySelectorAll('form.request-form');
  let targetForm = null;
  for (const form of forms) {
    if (form.dataset.requestId === requestId) {
      targetForm = form;
      break;
    }
  }
  if (!targetForm) return;

  const requestCard     = targetForm.closest('.request-card');
  const requesterContent = targetForm.closest('.requester-content');
  const requesterCard   = targetForm.closest('.requester-card');

  if (requestCard) {
    requestCard.remove();
  }

  // if requester has no more request cards, remove the whole requester section
  if (requesterContent && !requesterContent.querySelector('.request-card')) {
    if (requesterCard) {
      requesterCard.remove();
    }
  }

  // if container is now empty, show empty state
  if (!container.querySelector('.requester-card')) {
    container.innerHTML = '<div class="empty-state">No inbound requests at this time</div>';
  }
}

async function handleDenyClick(event, store, api) {
  const formEl = event.currentTarget.closest('form.request-form');
  if (!formEl) return;

  const requestId = formEl.dataset.requestId;

  setStateChip("Sending…", "warn");
  setStatus(`Denying request ${requestId}…`);

  try {
    await api.ackSolicitation(requestId);
  } catch (err) {
    setStateChip("Error", "err");
    setStatus(err?.message || "Failed to deny request.", "err");
    return;
  }

  // remove from local store
  const list = store?.ephemeral?.provider?.requests;
  if (Array.isArray(list)) {
    const idx = list.findIndex(r => r.request_id === requestId);
    if (idx !== -1) list.splice(idx, 1);
  }

  // clean up the DOM
  removeRequestFromUI(requestId);

  setStateChip("Ready", "ok");
  setStatus(`Request ${requestId} denied.`);
}

function populateRequestsWidget(api, store) {

  const container = document.getElementById('requestsContainer');
  const inboundRequests = store.ephemeral.provider.requests;
  
  if (!inboundRequests || inboundRequests.length === 0) {
    container.innerHTML = '<div class="empty-state">No inbound requests at this time</div>';
    return;
  }

  container.innerHTML = '';

  let datalist = document.getElementById('providerOptionsDatalist');
  if (!datalist) {
    datalist = document.createElement('datalist');
    datalist.id = 'providerOptionsDatalist';
    document.body.appendChild(datalist);
  }

  const validProviderIds = updateProviderDatalist(store);

  let currentRequesterId, requesterCard, requesterContent;

  for (const request of inboundRequests) {
    if (request.requester_id !== currentRequesterId) {
      if (requesterCard && requesterContent) {
        requesterCard.appendChild(requesterContent);
        container.appendChild(requesterCard);
      }

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

    const requestCard = document.createElement('article');
    requestCard.className = 'request-card';

    const requestTitle = document.createElement('h4');
    requestTitle.textContent = request.request_id;
    requestCard.appendChild(requestTitle);

    const form = document.createElement('form');
    form.className = 'request-form';
    form.dataset.requesterId = request.requester_id;
    form.dataset.requestId = request.request_id;
    form.addEventListener('submit', event => event.preventDefault());

    const fieldset = document.createElement('fieldset');
    
    const legend = document.createElement('legend');
    legend.textContent = request.info_string || 'Request Details';
    fieldset.appendChild(legend);

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

      const input = document.createElement('input');
      input.type = 'text';
      input.id = `${request.request_id}-item-${index}`;
      input.name = `item-${item.item_id}`;
      input.setAttribute('list', 'providerOptionsDatalist');
      input.autocomplete = 'off';
      if (item.value_example) {
        input.placeholder = '< ' + item.value_example + ' >';
      } else {
        input.placeholder = 'Type to search, click to select';
      }

      input.addEventListener('blur', function(event) {
        validateInput(event.target, datalist, true);
      });

      input.addEventListener('keydown', function(event) {
        if (event.key === 'Enter') {
          validateInput(event.target, datalist, true);
        }
        if (event.key === 'Tab') {
          validateInput(event.target, datalist, true);
        }
      });

      input.addEventListener('input', function(event) {
        validateInput(event.target, datalist);
      });

      formRow.appendChild(input);
      fieldset.appendChild(formRow);
    });

    form.appendChild(fieldset);

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
    denyBtn.addEventListener('click', (event) => {
      handleDenyClick(event, store, api);
    });

    buttonGroup.appendChild(approveBtn);
    buttonGroup.appendChild(denyBtn);
    form.appendChild(buttonGroup);

    requestCard.appendChild(form);
    requesterContent.appendChild(requestCard);
  }

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

  populateRequestsWidget(api, store); // todo - this is the right follow up but not in this function
}

export async function wireUpInboundRequests({ api, store }) {
  if (revisiting("wireUpInboundRequests")) return;

  await loadInboundRequests(api, store);
}
