import { setStateChip, setStatus } from "/app/utils.js"
import { packStoreToEnvelope } from "/app/user_store.js";

let tearingDown = false;
function beginTeardown() {
  if (tearingDown) return false;
  tearingDown = true;
  return true;
}

function nukeStorage() {
  localStorage.clear();
  sessionStorage.clear();
}

export async function bestEffortSave(api, userStore, passkey) {

  let envelope;
  try { envelope = await packStoreToEnvelope(userStore, passkey); } catch {}

  try {
    const signal = AbortSignal.timeout(7000);

    await api.saveToVault(envelope, { signal });
    DIRTY = false;

    setStateChip("Synced", "ok");
    setStatus("Saved to server. Logging out…", "ok");
  } catch (e) {
    const timedOut =
      (e?.name === "AbortError" || e?.name === "TimeoutError");

    setStateChip("Unsaved", "warn");
    setStatus(
      `Save failed (${timedOut ? "timeout" : (e?.message || "network error")}). Logging out anyway…`,
      "warn"
    );
  }
}

async function bestEffortSaveAndLogout(api, userStore, passkey) {
  if (!beginTeardown()) return;

  try {
    await bestEffortSave(api, userStore, passkey);

    try {
      await api.logout();
    } catch {
      setStateChip("Unsaved", "warn");
      setStatus("Logout failed", "warn");
    }

  } finally {
    try { nukeStorage(); } catch {}
  }
}

export let DIRTY = false;
export function wireUpLogoutAndSync({ api, userStore, passkey }) {
  const btn = document.querySelector('[data-action="logout"]');
  if (!btn || btn.dataset.isWiredUp === "1") return;
  btn.dataset.isWiredUp = "1";

  window.addEventListener('beforeunload', (ev) => {
    if (DIRTY) { ev.preventDefault(); }
  });

  window.addEventListener('pagehide', (ev) => {
    if (ev.persisted && DIRTY) {
      document.documentElement.setAttribute('data-locked', '');
      bestEffortSaveAndLogout(api, userStore, passkey);
      try { nukeStorage(); } catch {}
    } else {
      api.logout({ keepalive: true });
      try { nukeStorage(); } catch {}
    }
  }, { capture: true });

  window.addEventListener('pageshow', (ev) => {
    if (ev.persisted) {
      bestEffortSaveAndLogout(api, userStore, passkey);
    }
  }, { capture: true });

  let in_flight = false;
  btn.addEventListener("click", async () => {
    if (in_flight) return;
    in_flight = true;
    btn.disabled = true;

    if (!DIRTY) {
      api.logout();
      try { nukeStorage(); } catch {}
      return;
    }

    setStateChip("Saving…", "warn");
    setStatus("Saving latest changes…");

    await bestEffortSaveAndLogout(api, userStore, passkey);
    
    location.replace("/app/login.html");
  });
}