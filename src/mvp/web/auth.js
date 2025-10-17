// /app/auth.js
export async function session() {
  const r = await fetch("/auth/session");
  if (!r.ok) throw new Error("No active session");
  const j = await r.json();
  return j.user;
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : null,
  });
  if (!r.ok) {
    let msg = "Request failed";
    try { const t = await r.text(); msg = t || msg; } catch {}
    throw new Error(msg);
  }
  return r.json();
}

export async function login(email, password) {
  return postJSON("/auth/login", { email, password });
}

export async function register(email, password, display_name) {
  return postJSON("/auth/register", { email, password, display_name });
}

export async function logout() {
  return postJSON("/auth/logout");
}

export async function allowRegister() {
  return postJSON("/auth/allow_register");
}

export async function setStage(stage) {
  return postJSON("/auth/stage", { stage });
}
