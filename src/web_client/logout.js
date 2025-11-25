import { revisiting, setStateChip, setStatus } from "/app/utils.js"
import { needsSave, bestEffortSave } from "/app/save.js";

const logout = async (api, store, passkey) => {
  if (revisiting('logout'))
    return;

  if (needsSave()) {
    setStateChip("Saving…", "warn");
    setStatus("Saving latest changes…");
    await bestEffortSave(api, store, passkey);
  }

  try {
    await api.logout();
    location.replace("/app/login.html");
  } catch {
    setStateChip("Still Logged In", "warn");
    setStatus("Could Not Log Out");
  } finally {
    sessionStorage.clear();
  }
}

export function wireUpLogout({ api, store, passkey }) {
  if (revisiting('wireUpLogout')) return;

  const btn = document.querySelector('[data-action="logout"]');
  btn.addEventListener("click", () => logout(api, store, passkey));

  return logout;
}

export function wireUpUnexpectedExit({ api, store, passkey }) {
  if (revisiting('wireUpUnexpectedExit')) return;

  window.addEventListener('pagehide', (ev) => {
    if (ev.persisted && needsSave()) {
      document.documentElement.setAttribute('data-locked', '');
    }
  }, { capture: true });

  window.addEventListener('pageshow', async (ev) => {
    if (ev.persisted && !revisiting('final')) {
      await logout(api, store, passkey)
    }
  }, { capture: true });
}