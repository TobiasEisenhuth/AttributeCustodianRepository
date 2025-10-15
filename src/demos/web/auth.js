// /app/auth.js
export async function session() {
  try {
    const r = await fetch("/auth/session", { method: "GET" });
    if (!r.ok) throw new Error(await r.text());
    const j = await r.json();
    return j.user || null;
  } catch {
    return null;
  }
}

export async function register(email, password, display_name) {
  const r = await fetch("/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, display_name }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function login(email, password) {
  const r = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function logout() {
  const r = await fetch("/auth/logout", { method: "POST" });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
