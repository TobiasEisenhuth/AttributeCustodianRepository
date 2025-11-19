import {
  dec,
  revisiting,
  setStatus,
  setStateChip,
  bytesToBase64,
  base64ToBytes,
  updateProviderDatalist,
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

  updateProviderDatalist(store);

  const container = document.getElementById('requestsContainer');
  const requests = store.ephemeral.provider.requests;
  
  if (!requests || requests.length === 0) {
    container.innerHTML = '<div class="empty-state">No requests at this time</div>';
    return;
  }

  container.innerHTML = '';

  // Create or update the shared datalist
  let datalist = document.getElementById('providerOptionsDatalist');
  if (!datalist) {
    datalist = document.createElement('datalist');
    datalist.id = 'providerOptionsDatalist';
    document.body.appendChild(datalist);
  }

  // Build provider options
  datalist.innerHTML = '';
  const validProviderIds = new Set();
  
  for (const providerItem of store.persistent.provider.items) {
    const value = store.ephemeral.provider.values.get(providerItem.item_id);
    if (value !== undefined && value !== null) {
      const option = document.createElement('option');
      option.value = providerItem.item_id;
      option.textContent = `${providerItem.item_name} -> ${value}`;
      // Store display text as data attribute for validation
      option.dataset.displayText = option.textContent;
      datalist.appendChild(option);
      validProviderIds.add(providerItem.item_id);
    }
  }

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

      const input = document.createElement('input');
      input.type = 'text';
      input.id = `${request.request_id}-item-${index}`;
      input.name = `item-${item.item_id}`;
      input.setAttribute('list', 'providerOptionsDatalist');
      input.autocomplete = 'off';
      
      // Set placeholder
      if (item.value_example) {
        input.placeholder = `e.g., ${item.value_example} (type to search, click to select)`;
      } else {
        input.placeholder = 'Type to search, click to select';
      }

      // Store the valid provider IDs for this input's validation
      input.dataset.validIds = JSON.stringify([...validProviderIds]);

      // Validation: only accept click selection or valid item_id
      input.addEventListener('blur', function(e) {
        validateInput(e.target, datalist);
      });

      input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          validateInput(e.target, datalist);
          e.target.blur();
        }
      });

      // When user selects from datalist (click or arrow+enter on suggestion)
      input.addEventListener('input', function(e) {
        // Check if the current value matches an option's value (item_id)
        const options = Array.from(datalist.options);
        const match = options.find(opt => opt.value === e.target.value);
        
        if (match) {
          // Valid selection - store the display text for showing
          e.target.dataset.selectedDisplay = match.dataset.displayText;
          e.target.value = match.dataset.displayText;
        }
      });

      formRow.appendChild(input);
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

/**
 * Validates input against datalist options
 * Clears input if value is not valid
 */
function validateInput(input, datalist) {
  const options = Array.from(datalist.options);
  
  // Check if input value matches any option's display text
  const match = options.find(opt => opt.dataset.displayText === input.value);
  
  if (!match) {
    // Invalid input - clear it
    input.value = '';
    delete input.dataset.selectedDisplay;
  }
}

/**
 * Gets the selected provider item_id from an input field
 * Returns null if no valid selection
 */
function getSelectedProviderId(input) {
  if (!input.dataset.selectedDisplay || !input.value) {
    return null;
  }
  
  const datalist = document.getElementById('providerOptionsDatalist');
  const options = Array.from(datalist.options);
  const match = options.find(opt => opt.dataset.displayText === input.value);
  
  return match ? match.value : null;
}

// To get form data on approve:
// const inputs = form.querySelectorAll('input[type="text"]');
// inputs.forEach(input => {
//   const requesterItemId = input.closest('.form-row').dataset.requesterItemId;
//   const providerItemId = getSelectedProviderId(input);
//   console.log(`Map ${requesterItemId} -> ${providerItemId}`);
// });

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
