import {
  dec,
  enc,
  revisiting,
  setStatus,
  setStateChip,
  bytesToBase64,
  base64ToBytes,
} from "/app/utils.js";
import { loadUmbral } from "/app/umbral-loader.js";

// -------------------- Provider datalist --------------------

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

// -------------------- Store/UI removal helpers --------------------

function removeRequestFromStore(store, requestId) {
  const list = store?.ephemeral?.provider?.requests;
  if (Array.isArray(list)) {
    const idx = list.findIndex(r => r.request_id === requestId);
    if (idx !== -1) list.splice(idx, 1);
  }
}

function removeRequestFromUI(requestId) {
  const container = document.getElementById('requestsContainer');
  if (!container) return;

  const forms = container.querySelectorAll('form.request-form');
  let targetForm = null;
  for (const form of forms) {
    if (form.dataset.requestId === requestId) {
      targetForm = form;
      break;
    }
  }
  if (!targetForm) return;

  const requestCard = targetForm.closest('.request-card');
  const requesterContent = targetForm.closest('.requester-content');
  const requesterCard = targetForm.closest('.requester-card');

  if (requestCard) {
    requestCard.remove();
  }

  if (requesterContent && !requesterContent.querySelector('.request-card')) {
    if (requesterCard) {
      requesterCard.remove();
    }
  }

  if (!container.querySelector('.requester-card')) {
    container.innerHTML = '<div class="empty-state">No inbound requests at this time</div>';
  }
}

// -------------------- Approve/Deny handlers (PRE) --------------------

async function handleApprove(api, store, event) {
  const formEl = event.currentTarget.closest('form.request-form');
  if (!formEl) return;

  const requesterId = formEl.dataset.requesterId;
  const requestId = formEl.dataset.requestId;

  if (!requesterId) {
    setStateChip("Error", "err");
    setStatus("Missing requester id on this solicitation.", "err");
    return;
  }

  const formRows = formEl.querySelectorAll('.form-row');
  const items = [];

  for (const row of formRows) {
    const input = row.querySelector('input[type="text"]');
    if (!input) continue;

    const providerItemId = input.dataset.itemId;
    const requesterItemId = row.dataset.requesterItemId;

    if (!providerItemId) {
      setStateChip("Error", "err");
      setStatus("Please select a provider item for all fields.", "err");
      return;
    }

    // Find the requester's public key from the original request
    const request = store.ephemeral.provider.requests.find(r => r.request_id === requestId);
    if (!request) {
      setStateChip("Error", "err");
      setStatus("Request not found in store.", "err");
      return;
    }

    const requestItem = request.items.find(it => it.item_id === requesterItemId);
    if (!requestItem || !requestItem.requester_public_key_b64) {
      setStateChip("Error", "err");
      setStatus(`Missing public key for requester item ${requesterItemId}.`, "err");
      return;
    }

    items.push({
      provider_item_id: providerItemId,
      requester_item_id: requesterItemId,
      requester_public_key_b64: requestItem.requester_public_key_b64
    });
  }

  if (items.length === 0) {
    setStateChip("Error", "err");
    setStatus("No items to grant.", "err");
    return;
  }

  const providerItems = store?.persistent?.provider?.items;
  if (!Array.isArray(providerItems)) {
    setStateChip("Error", "err");
    setStatus("No provider items found in persistent store.", "err");
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
    for (const item of items) {
      const pEntry = providerItems.find(entry => entry?.item_id === item.provider_item_id);
      if (!pEntry?.keys?.secret_key_b64 || !pEntry?.keys?.signing_key_b64) {
        throw new Error(`Missing keys for provider item ${item.provider_item_id}.`);
      }

      const delegating_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(pEntry.keys.secret_key_b64));
      const signing_sk = umbral.SecretKey.fromBEBytes(base64ToBytes(pEntry.keys.signing_key_b64));
      const signer = new umbral.Signer(signing_sk);
      const recv_pk_b = base64ToBytes(item.requester_public_key_b64);
      const receiving_pk = umbral.PublicKey.fromCompressedBytes(recv_pk_b);

      const kfrags = umbral.generateKFrags(delegating_sk, receiving_pk, signer, 1, 1);
      if (!Array.isArray(kfrags) || !kfrags.length) {
        throw new Error("Failed to generate kfrags.");
      }

      const kfrags_b64 = kfrags.map(k => bytesToBase64(k.toBytes()));
      
      await api.grantAccess({
        requester_id: requesterId,
        provider_item_id: item.provider_item_id,
        requester_item_id: item.requester_item_id,
        kfrags_b64,
      });
    }

    setStatus("Access granted. Acknowledging bundle…");
    await api.ackSolicitation(requestId);

    removeRequestFromStore(store, requestId);
    removeRequestFromUI(requestId);
    
    setStateChip("Synced", "ok");
    setStatus("Access granted and request acknowledged.");
    
  } catch (err) {
    setStateChip("Error", "err");
    setStatus(err?.message || "Failed to grant/acknowledge bundle.", "err");
  }
}

async function handleDenyClick(api, store, event) {
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

  removeRequestFromStore(store, requestId);
  removeRequestFromUI(requestId);

  setStateChip("Ready", "ok");
  setStatus(`Request ${requestId} denied.`);
}

// -------------------- UI helpers --------------------

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

  updateProviderDatalist(store);

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
    approveBtn.addEventListener('click', async (event) => {
      await handleApprove(api, store, event);
    });

    const denyBtn = document.createElement('button');
    denyBtn.type = 'button';
    denyBtn.className = 'btn btn-deny';
    denyBtn.textContent = 'Deny';
    denyBtn.addEventListener('click', (event) => {
      handleDenyClick(api, store, event);
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

// -------------------- WebCrypto E2EE decryption --------------------

// We stored the inbox private key as: base64(JSON(JWK))
async function importInboxPrivateKeyFromStore(store) {
  const sk_b64 = store?.persistent?.private?.inbox?.secret_key_b64;
  if (!sk_b64) {
    throw new Error("Missing inbox private key in vault. Please re-login or re-initialize E2EE.");
  }

  let jwk;
  try {
    const jwkJson = dec.decode(base64ToBytes(sk_b64));
    jwk = JSON.parse(jwkJson);
  } catch {
    throw new Error("Inbox private key is not valid JWK JSON.");
  }

  try {
    return await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
  } catch {
    throw new Error("Failed to import inbox private key.");
  }
}

async function importEphemeralPublicKey(epk_jwk) {
  try {
    return await crypto.subtle.importKey(
      "jwk",
      epk_jwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
  } catch {
    throw new Error("Failed to import requester ephemeral public key.");
  }
}

async function deriveAesKeyForDecrypt(sharedBits, infoStr) {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"]
  );

  const info = enc.encode(infoStr || "crs:solicitation:v1");

  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptSolicitationEnvelope(encrypted_payload_b64, store) {
  if (!crypto?.subtle) {
    throw new Error("WebCrypto not available in this browser.");
  }

  // 1) Decode envelope JSON
  let envelope;
  try {
    const envBytes = base64ToBytes(encrypted_payload_b64);
    const envText  = dec.decode(envBytes);
    envelope = JSON.parse(envText);
  } catch {
    throw new Error("Encrypted solicitation envelope is not valid JSON.");
  }

  if (!envelope?.epk_jwk || !envelope?.iv_b64 || !envelope?.ct_b64) {
    throw new Error("Encrypted solicitation envelope is missing required fields.");
  }

  // 2) Import keys
  const inboxSk = await importInboxPrivateKeyFromStore(store);
  const epk     = await importEphemeralPublicKey(envelope.epk_jwk);

  // 3) Derive shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: epk },
    inboxSk,
    256
  );

  // 4) HKDF -> AES key
  const aesKey = await deriveAesKeyForDecrypt(sharedBits, envelope.info);

  // 5) AES-GCM decrypt
  const iv = base64ToBytes(envelope.iv_b64);
  const ct = base64ToBytes(envelope.ct_b64);

  let ptBuf;
  try {
    ptBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      ct
    );
  } catch {
    throw new Error("Failed to decrypt solicitation (wrong key or corrupted payload).");
  }

  return new Uint8Array(ptBuf);
}

// -------------------- Load inbound requests --------------------

async function loadInboundRequests(api, store) {
  setStateChip("Loading…", "warn");
  setStatus("Loading inbound solicitations…");

  let bundle;
  try {
    bundle = await api.pullSolicitationBundle();
  } catch (err) {
    setStateChip("Error", "err");
    setStatus(err?.message || "Failed to load inbound requests.");
    return;
  }

  if (!bundle.has_any) {
    setStateChip("Idle", "muted");
    setStatus("No inbound requests.");
    populateRequestsWidget(api, store);
    return;
  }

  if (!store.good) {
    setStateChip("Error", "err");
    setStatus("Store not good!");
    return;
  }

  const requests = store.ephemeral.provider.requests;
  const existingIds = new Set(requests.map(item => item?.request_id).filter(Boolean));

  for (const request of bundle.solicitations) {
    if (existingIds.has(request.request_id)) continue;

    let payload;
    try {
      const ptBytes = await decryptSolicitationEnvelope(request.encrypted_payload_b64, store);
      const ptText  = dec.decode(ptBytes);
      payload = JSON.parse(ptText);
    } catch (err) {
      console.error("Failed to decrypt solicitation payload", err);
      continue;
    }

    const items = [];
    for (const item of (payload.items || [])) {
      items.push({
        item_id: item.item_id,
        item_name: item.item_name,
        requester_public_key_b64: item.requester_public_key_b64,
        value_example: item.value_example,
        default_field: item.default_field,
      });
    }

    requests.push({
      request_id: request.request_id,
      requester_id: request.requester_id,
      info_string: payload.info_string || "",
      items,
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
