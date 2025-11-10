import { setStateChip, setStatus } from "/app/utils.js"
import { packStoreToEnvelope } from "/app/user_store.js";

export function wireUpLogoutAndSync({ api, userStore, passkey }) {
  const btn = document.querySelector('[data-action="logout"]');
  if (!btn || btn.dataset.isWiredUp === "1") return;
  btn.dataset.isWiredUp = "1";

  let in_flight = false;

  btn.addEventListener("click", async () => {
    if (in_flight) return;
    in_flight = true;
    btn.disabled = true;

    setStateChip("Saving…", "warn");
    setStatus("Saving latest changes…");

    try {
      const envelope = await packStoreToEnvelope(userStore, passkey);

      try {
        const signal = AbortSignal.timeout(7000);

        await api.saveToVault(envelope, { signal });

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

    } finally {
      try { await api.logout({ keepalive: true }); } catch {}
      location.replace("/app/login.html");
    }
  });
}
