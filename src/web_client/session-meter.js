import { revisiting } from "/app/utils.js"

export function initSessionMeter({ api, onTimeout } = {}) {
  if (revisiting("initSessionMeter")) return;

  const GREEN_MIN_RATIO  = 0.25;
  const ORANGE_MIN_RATIO = 0.15;

  let meter = null;
  let refreshBtn = null;

  let displayTotal = null;
  let lastTouchMs = null;
  let intervalId = null;

  function applyMeterRanges() {
    if (!displayTotal || !meter) return;

    const orangeStart = Math.round(displayTotal * ORANGE_MIN_RATIO);
    const greenStart  = Math.round(displayTotal * GREEN_MIN_RATIO);

    meter.low = orangeStart;
    meter.high = greenStart;
    meter.optimum = displayTotal;
  }

  function updateMeter() {
    if (!displayTotal || !lastTouchMs || !meter) return;

    const elapsed = (Date.now() - lastTouchMs) / 1000;
    let remaining = Math.round(displayTotal - elapsed);

    if (remaining <= 0) {
      remaining = 0;
      meter.value = 0;
      stopTimer();
      if (typeof onTimeout === "function") onTimeout();
      return;
    }

    if (remaining > displayTotal) remaining = displayTotal;
    meter.value = remaining;
  }

  function startTimer() {
    if (intervalId) clearInterval(intervalId);
    intervalId = window.setInterval(updateMeter, 1000);
  }

  function stopTimer() {
    if (intervalId) {
      clearInterval(intervalId);
      intervalId = null;
    }
  }

  function handleSessionTouched() {
    if (!displayTotal || !meter) return;
    lastTouchMs = Date.now();
    meter.value = displayTotal;
  }

  async function initTTL() {
    try {
      const res = await api.refreshSessionTTL();
      const t = Number(res?.ttl_seconds);

      if (!Number.isFinite(t) || t <= 0) {
        console.warn("refreshSessionTTL returned invalid ttl_seconds:", res);
        return;
      }

      displayTotal = t;

      meter.min = 0;
      meter.max = displayTotal;
      meter.value = displayTotal;
      applyMeterRanges();

      lastTouchMs = Date.now();
      startTimer();
    } catch (err) {
      console.error("Failed to initialize TTL for session meter:", err);
    }
  }

  function setup() {
    meter = document.getElementById("page-meter");
    refreshBtn = document.getElementById("session-refresh-btn");

    if (!meter || !refreshBtn) {
      console.warn("Session meter elements not found in DOM.");
      return;
    }

    if (typeof api.setSessionTouchedCallback === "function") {
      api.setSessionTouchedCallback(handleSessionTouched);
    } else {
      console.warn("CRSClient.setSessionTouchedCallback is not available.");
    }

    refreshBtn.addEventListener("click", () => {
      api.refreshSessionTTL().catch(err => {
        console.error("Manual TTL refresh failed:", err);
      });
    });

    initTTL();
  }

  if (document.readyState === "loading") {
    window.addEventListener("DOMContentLoaded", setup, { once: true });
  } else {
    setup();
  }

  return {
    stop: () => stopTimer(),
  };
}