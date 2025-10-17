// /app/polyfills.js
(() => {
  try {
    // Only define if missing; don't overwrite if present
    if (typeof Symbol !== "undefined") {
      if (!("dispose" in Symbol)) {
        Object.defineProperty(Symbol, "dispose", {
          value: Symbol("Symbol.dispose"),
          configurable: false,
          enumerable: false,
          writable: false,
        });
      }
      if (!("asyncDispose" in Symbol)) {
        Object.defineProperty(Symbol, "asyncDispose", {
          value: Symbol("Symbol.asyncDispose"),
          configurable: false,
          enumerable: false,
          writable: false,
        });
      }
    }
  } catch {
    /* no-op */
  }
})();
