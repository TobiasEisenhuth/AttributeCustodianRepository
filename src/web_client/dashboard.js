import { initUserStore } from "/app/user-store.js";
import { initSaveLogic } from "/app/save.js";

import { initUser } from "/app/utils.js";

import { CRSClient } from "/app/crs-sdk.js";
import { wireUpAddItemDialog, wireUpItemUpdate } from "/app/upsert-items.js";
import { wireUpRequestBuilder } from "/app/request-builder.js";
import { wireUpInboundRequests } from "/app/inbound-request.js";
import { wireUpQueryItems } from "/app/fetch-items.js";
import { wireUpLogout, wireUpUnexpectedExit } from "/app/logout.js";

const { is_owner_tab, passkey } = initUser();
const api = new CRSClient();

let store = null;
if (is_owner_tab) {
  initSaveLogic();
  store = await initUserStore({ api, passkey });
  await wireUpLogout({ api, store, passkey });
  await wireUpUnexpectedExit({api, store, passkey});
  await wireUpAddItemDialog({ api, store });
  await wireUpItemUpdate({ api, store });
  await wireUpInboundRequests({api, store});
  await wireUpRequestBuilder({ api, store });
  await wireUpQueryItems({ api, store });
} else {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay open';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="tabLockTitle">
      <h3 id="tabLockTitle" class="modal-title">Already Open in Another Tab</h3>
      <div class="modal-body"><p>You are already using a different tab. Close this tab and go back to the original tab.</p></div>
    </div>`;
  if (document.body) document.body.appendChild(overlay);
  else window.addEventListener('DOMContentLoaded', () => document.body.appendChild(overlay), { once: true });
}

// // Only when the **last** tab closes, clear storage + logout.
// // Non-last tabs do nothing, so they won’t kill the session of the owner tab.
// let didClose = false;
// function clearAndMaybeLogout() {
//   if (didClose) return;
//   didClose = true;

//   try { bc && bc.postMessage({ t: "bye", id: tabId }); } catch {}

//   // If BroadcastChannel unsupported, we can’t safely know last-tab. Be conservative: do nothing.
//   if (!bc) return;

//   // Last tab => clear + logout (keepalive)
//   if (peers.size === 0) {
//     try { sessionStorage.clear(); } catch {}
//     try { api.logout({ keepalive: true }); } catch {}
//   }
// }

// // Fire on real unloads (skip when BFCache persists the page)
// window.addEventListener("pagehide", (e) => { if (!e.persisted) clearAndMaybeLogout(); });
// window.addEventListener("beforeunload", clearAndMaybeLogout);