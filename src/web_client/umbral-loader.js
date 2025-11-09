let U = null;

/**
 * Dynamically load Umbral WASM bindings (once).
 * Returns the Umbral module or null if unavailable.
 */
export async function loadUmbral() {
  if (U) return U;
  try {
    const mod = await import("/app/umbral/umbral_pre_wasm.js");
    if (typeof mod.default === "function") {
      await mod.default("/app/umbral/umbral_pre_wasm_bg.wasm");
    }
    U = mod;
    return U;
  } catch (e) {
    console.error("Umbral import/init failed:", e);
    return null;
  }
}

