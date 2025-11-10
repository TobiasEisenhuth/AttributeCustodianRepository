import { revisiting, setStateChip, setStatus } from "/app/utils.js"
import { needsSave, bestEffortSave } from "/app/save.js";

const logout = async (api, userStore, passkey) => {
  if (revisiting('logout'))
    return;

  if (needsSave()) {
    setStateChip("Saving…", "warn");
    setStatus("Saving latest changes…");
    await bestEffortSave(api, userStore, passkey);
  }

  try {
    await api.logout();
    location.replace("/app/login.html");
  } catch {
    setStateChip("Still Logged In", "warn");
    setStatus("Could Not Log Out");
  }
}

export function wireUpLogout({ api, userStore, passkey }) {
  if (revisiting('wireUpLogout')) return;

  const btn = document.querySelector('[data-action="logout"]');
  btn.addEventListener("click", () => logout(api, userStore, passkey));
}

export function wireUpUnexpectedExit({ api, userStore, passkey }) {
  if (revisiting('wireUpUnexpectedExit')) return;

  window.addEventListener('pagehide', (ev) => {
    if (ev.persisted && needsSave()) {
      document.documentElement.setAttribute('data-locked', '');
    }
  }, { capture: true });

  window.addEventListener('pageshow', async (ev) => {
    if (ev.persisted && !revisiting('final')) {
      await logout(api, userStore, passkey)
    }
  }, { capture: true });
}