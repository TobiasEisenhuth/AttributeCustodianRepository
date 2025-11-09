// /app/logout.js
export function wireUpLogoutAndSync({ api, vault, setStatus = () => {}, setStateChip = () => {} }) {
  const btn = document.querySelector('[data-action="logout"]');
  if (!btn) return;

  let inflight = false;

  btn.addEventListener("click", async () => {
    if (inflight) return;
    inflight = true;
    btn.disabled = true;

    try {
      // 1) Ensure we have the freshest encrypted blob
      setStateChip("Saving…", "warn");
      setStatus("Saving latest changes…");

      let b64 = null;
      try {
        b64 = await vault.encryptAndCachePrivate?.();
        if (!b64) b64 = vault.getEncryptedBlobB64?.();
      } catch (_) {
        // If encryption fails, we still proceed to logout, but warn.
      }

      // 2) Best-effort push to server (with timeout)
      if (b64) {
        const ac = new AbortController();
        const t = setTimeout(() => ac.abort(), 7000);
        try {
          await api.saveToVault(b64, { signal: ac.signal });
          setStateChip("Synced", "ok");
          setStatus("Saved to server. Logging out…", "ok");
        } catch (e) {
          setStateChip("Unsaved", "warn");
          setStatus(`Save failed (${e?.message || "network error"}). Logging out anyway…`, "warn");
        } finally {
          clearTimeout(t);
        }
      } else {
        // Nothing to save (empty store or encrypt not ready). Proceed.
        setStatus("Nothing to save. Logging out…");
      }
    } finally {
      // 3) Always clear client state + end session
      try {
        sessionStorage.removeItem("crs:passkey");
        sessionStorage.removeItem("crs:email");
        sessionStorage.removeItem("crs:store");
      } catch {}

      try { await api.logout({ keepalive: true }); } catch {}

      // 4) Redirect to login
      location.replace("/app/login.html");
    }
  });
}

