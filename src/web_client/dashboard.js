import { initUserStore } from "/app/user-store.js";
import { initSaveLogic } from "/app/save.js";
import { initSessionMeter } from "/app/session-meter.js";
import { initUser } from "/app/utils.js";

import { CRSClient } from "/app/crs-sdk.js";
import { wireUpAddItemDialog, wireUpItemUpdate } from "/app/upsert-items.js";
import { wireUpRequestBuilder } from "/app/request-builder.js";
import { wireUpInboundRequests } from "/app/inbound-request.js";
import { wireUpQueryItems } from "/app/fetch-items.js";
import { wireUpLogout, wireUpUnexpectedExit } from "/app/logout.js";
import { wireUpOverview } from "/app/overview.js";

const { is_owner_tab, passkey } = initUser();
const api = new CRSClient();

let store = null;
let logoutFn = null;

if (is_owner_tab) {
  initSessionMeter({
    api,
    onTimeout: () => {
      if (typeof logoutFn === "function") {
        logoutFn(api, store, passkey);
      } else {
        console.warn("Session expired but logoutFn is not wired yet.");
      }
    },
  });

  initSaveLogic();
  store = await initUserStore({ api, passkey });
  if (!store || !store.good) {console.error("Failed to initialize store");}
  logoutFn = await wireUpLogout({ api, store, passkey });
  await wireUpUnexpectedExit({ api, store, passkey });
  await wireUpAddItemDialog({ api, store });
  await wireUpItemUpdate({ api, store });
  await wireUpInboundRequests({ api, store });
  await wireUpRequestBuilder({ api, store });
  await wireUpQueryItems({ api, store });
  await wireUpOverview({ api, store });
} else {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay open";
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="tabLockTitle">
      <h3 id="tabLockTitle" class="modal-title">Already Open in Another Tab</h3>
      <div class="modal-body"><p>You are already using a different tab. Close this tab and go back to the original tab.</p></div>
    </div>`;
  if (document.body) document.body.appendChild(overlay);
  else window.addEventListener(
    "DOMContentLoaded",
    () => document.body.appendChild(overlay),
    { once: true },
  );
}