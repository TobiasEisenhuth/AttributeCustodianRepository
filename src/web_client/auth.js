async function postJSON(url, data) {
  const res = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    let msg = "Request failed";
    try { msg = (await res.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

const loginForm = document.getElementById("login-form");
if (loginForm) {
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(loginForm).entries());
    try {
      await postJSON("/auth/login", data);
      location.href = "/app/dashboard.html";
    } catch (err) {
      document.getElementById("login-error").textContent = err.message;
    }
  });
}

const regForm = document.getElementById("register-form");
if (regForm) {
  regForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(regForm).entries());
    try {
      await postJSON("/auth/register", data);
      location.href = "/app/dashboard.html";
    } catch (err) {
      document.getElementById("register-error").textContent = err.message;
    }
  });
}
