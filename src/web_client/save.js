import {
  packUserStoreToEnvelope,
  revisiting,
  setStateChip,
  setStatus
} from "/app/utils.js"

const intercept = (ev) => {
  ev.preventDefault();
  ev.returnValue = '';
}

function enableLeavePrompt() {
  window.addEventListener('beforeunload', intercept, { capture: true });
}

function disableLeavePrompt() {
  window.removeEventListener('beforeunload', intercept, { capture: true });
}

let DIRTY;
export function needsSave(set = false) {
  if (set) { 
    DIRTY = true;
    enableLeavePrompt();
  }
  return DIRTY;
}

export function initSaveLogic() {
  if (revisiting('initSaveLogic'))
    return;

  DIRTY = false;
  disableLeavePrompt();
}

export async function bestEffortSave(api, userStore, passkey) {

  let envelope;
  try {
    envelope = await packUserStoreToEnvelope(userStore, passkey);
  } catch {
    setStateChip("Saving Not Possible", "warn");
    setStatus("Could Not Pack User Store", "warn");
    return;
  }

  try {
    await api.saveToVault(envelope, { signal: AbortSignal.timeout(10000) });
    DIRTY = false;
    disableLeavePrompt();

    setStateChip("Synced", "ok");
    setStatus("Saved To Server", "ok");
  } catch {
    setStateChip("Probably Unsaved", "warn");
    setStatus("Server Not Reachable Or Missing ACK", "warn");
  }
}