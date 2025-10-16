# proxy.py
import mimetypes
mimetypes.add_type('application/wasm', '.wasm')  # ensure correct MIME for .wasm

import os
import sys
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

import anyio
import msgpack
import psycopg
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from umbral_pre import PublicKey, Capsule, KeyFrag, reencrypt

# Password hashing (Argon2id)
from argon2 import PasswordHasher
from argon2.low_level import Type as Argon2Type
from argon2.exceptions import VerifyMismatchError, InvalidHash

from protocol import (
    b64d, b64e,
    ADD_OR_UPDATE_SECRET, DELETE_SECRET, GRANT_ACCESS_PROXY, GRANT_ACCESS_RECEIVER,
    REVOKE_ACCESS, REQUEST_SECRET, LIST_GRANTS, GRANTS_SUMMARY, REQUEST_ACCESS,
    PULL_INBOX_SENDER, PULL_INBOX_RECEIVER, INBOX_CONTENTS, RESPONSE_SECRET
)

PROXY_HOST = os.getenv("PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.getenv("PROXY_PORT", "8000"))

# ---- DB config (env-overridable) ----
DB_HOST = os.getenv("PGHOST", "localhost")
DB_PORT = int(os.getenv("PGPORT", "5432"))
DB_USER = os.getenv("PGUSER", "postgres")
DB_NAME = os.getenv("PGDATABASE", "postgres")

# Require password ONLY via CLI: python proxy.py <PGPASSWORD>
if len(sys.argv) < 2 or not sys.argv[1]:
    raise SystemExit("[Proxy] FATAL: DB password must be provided as the first CLI argument (no env fallback).")
DB_PASS = sys.argv[1]

DSN = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={DB_USER} password={DB_PASS}"

def get_conn():
    return psycopg.connect(DSN)

# =================== DB INIT ===================

def init_db():
    with get_conn() as conn:
        # Existing CRS tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
              sender_id TEXT NOT NULL,
              secret_id TEXT NOT NULL,
              capsule BYTEA NOT NULL,
              ciphertext BYTEA NOT NULL,
              sender_public_key BYTEA NOT NULL,
              sender_verifying_key BYTEA NOT NULL,
              PRIMARY KEY (sender_id, secret_id)
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS grants (
              sender_id TEXT NOT NULL,
              receiver_id TEXT NOT NULL,
              secret_id TEXT NOT NULL,
              kfrags_blob BYTEA NOT NULL,
              PRIMARY KEY (sender_id, receiver_id, secret_id)
            );
        """)
        # inbox tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sender_inbox (
              sender_id  TEXT NOT NULL,
              msg_blob   BYTEA NOT NULL,
              created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS receiver_inbox (
              receiver_id TEXT NOT NULL,
              msg_blob    BYTEA NOT NULL,
              created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)

        # New: Users / Sessions (+ store password)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              email TEXT UNIQUE NOT NULL,
              display_name TEXT,
              password_hash TEXT NOT NULL,
              store_password TEXT,
              created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)
        # In case the table already existed without store_password:
        try:
            conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS store_password TEXT;")
        except Exception:
            pass

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
              expires_at TIMESTAMPTZ NOT NULL,
              user_agent TEXT,
              ip TEXT
            );
        """)
    print("[Proxy] DB initialized.")

# =================== CRS HELPERS (existing) ===================

def upsert_secret(payload: Dict[str, Any]) -> None:
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO secrets (
              sender_id, secret_id, capsule, ciphertext, sender_public_key, sender_verifying_key
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (sender_id, secret_id) DO UPDATE SET
              capsule = EXCLUDED.capsule,
              ciphertext = EXCLUDED.ciphertext,
              sender_public_key = EXCLUDED.sender_public_key,
              sender_verifying_key = EXCLUDED.sender_verifying_key
        """, (
            payload["sender_id"],
            payload["secret_id"],
            payload["capsule"],
            payload["ciphertext"],
            payload["sender_public_key"],
            payload["sender_verifying_key"],
        ))

def delete_secret(sender_id: str, secret_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM secrets WHERE sender_id=%s AND secret_id=%s", (sender_id, secret_id))
        conn.execute("DELETE FROM grants  WHERE sender_id=%s AND secret_id=%s", (sender_id, secret_id))

def insert_or_replace_grant(sender_id: str, receiver_id: str, secret_id: str, kfrags_bytes_list: List[bytes]) -> None:
    blob = msgpack.packb(kfrags_bytes_list, use_bin_type=True)
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO grants (sender_id, receiver_id, secret_id, kfrags_blob)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (sender_id, receiver_id, secret_id) DO UPDATE SET
              kfrags_blob = EXCLUDED.kfrags_blob
        """, (sender_id, receiver_id, secret_id, blob))

def revoke_grant(sender_id: str, receiver_id: str, secret_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM grants WHERE sender_id=%s AND receiver_id=%s AND secret_id=%s",
                     (sender_id, receiver_id, secret_id))

def load_secret(sender_id: str, secret_id: str):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT capsule, ciphertext, sender_public_key, sender_verifying_key
            FROM secrets
            WHERE sender_id=%s AND secret_id=%s
        """, (sender_id, secret_id)).fetchone()
    if not row:
        return None
    capsule_b, ciphertext_b, spk_b, svk_b = row
    return {
        "capsule": Capsule.from_bytes(capsule_b),
        "ciphertext": ciphertext_b,
        "sender_public_key": PublicKey.from_compressed_bytes(spk_b),
        "sender_verifying_key": PublicKey.from_compressed_bytes(svk_b),
    }

def load_grant_kfrags(sender_id: str, receiver_id: str, secret_id: str) -> List[KeyFrag]:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT kfrags_blob
            FROM grants
            WHERE sender_id=%s AND receiver_id=%s AND secret_id=%s
        """, (sender_id, receiver_id, secret_id)).fetchone()
    if not row:
        return []
    (blob,) = row
    kfrag_bytes_list = msgpack.unpackb(blob, raw=False)
    return [KeyFrag.from_bytes(b) for b in kfrag_bytes_list]

def list_grants_for_sender(sender_id: str) -> dict:
    by_secret: Dict[str, List[str]] = {}
    total_grants = 0
    with get_conn() as conn:
        secrets = [r[0] for r in conn.execute(
            "SELECT secret_id FROM secrets WHERE sender_id=%s", (sender_id,)
        ).fetchall()]
        for sec in secrets:
            by_secret.setdefault(sec, [])
        rows = conn.execute(
            "SELECT secret_id, receiver_id FROM grants WHERE sender_id=%s ORDER BY secret_id, receiver_id",
            (sender_id,)
        ).fetchall()
    for sec_id, recv_id in rows:
        by_secret.setdefault(sec_id, []).append(recv_id)
        total_grants += 1
    return {"by_secret": by_secret, "totals": {"secrets": len(by_secret), "grants": total_grants}}

# ---------- inbox helpers ----------
def enqueue_for_sender(sender_id: str, action: str, payload: dict) -> None:
    blob = msgpack.packb({"action": action, "payload": payload}, use_bin_type=True)
    with get_conn() as conn:
        conn.execute("INSERT INTO sender_inbox (sender_id, msg_blob) VALUES (%s, %s)", (sender_id, blob))

def enqueue_for_receiver(receiver_id: str, action: str, payload: dict) -> None:
    blob = msgpack.packb({"action": action, "payload": payload}, use_bin_type=True)
    with get_conn() as conn:
        conn.execute("INSERT INTO receiver_inbox (receiver_id, msg_blob) VALUES (%s, %s)", (receiver_id, blob))

def pull_sender_inbox(sender_id: str) -> List[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT msg_blob FROM sender_inbox WHERE sender_id=%s ORDER BY created_at ASC",
            (sender_id,)
        ).fetchall()
        conn.execute("DELETE FROM sender_inbox WHERE sender_id=%s", (sender_id,))
    return [msgpack.unpackb(r[0], raw=False) for r in rows]

def pull_receiver_inbox(receiver_id: str) -> List[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT msg_blob FROM receiver_inbox WHERE receiver_id=%s ORDER BY created_at ASC",
            (receiver_id,)
        ).fetchall()
        conn.execute("DELETE FROM receiver_inbox WHERE receiver_id=%s", (receiver_id,))
    return [msgpack.unpackb(r[0], raw=False) for r in rows]

# =================== AUTH (email + password) ===================

SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", str(60*5)))  # default 5 minutes

# Argon2id parameters (balanced & modern)
ph = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Argon2Type.ID,
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def cookie_name_and_secure(req: Request) -> tuple[str, bool]:
    # Use __Host- cookie on HTTPS (not on localhost HTTP)
    is_https = (req.url.scheme == "https")
    host = (req.url.hostname or "").lower()
    dev_http_local = (req.url.scheme == "http" and host in ("localhost", "127.0.0.1"))
    if is_https and not dev_http_local:
        return "__Host-session", True
    return "session", False

def secure_flag(req: Request) -> bool:
    is_https = (req.url.scheme == "https")
    host = (req.url.hostname or "").lower()
    dev_http_local = (req.url.scheme == "http" and host in ("localhost", "127.0.0.1"))
    return (is_https and not dev_http_local)

def set_session_cookie(resp: Response, req: Request, token: str) -> None:
    name, secure = cookie_name_and_secure(req)
    resp.set_cookie(
        key=name,
        value=token,
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/",
        max_age=SESSION_TTL_SECONDS,
    )

def clear_session_cookie(resp: Response, req: Request) -> None:
    name, _ = cookie_name_and_secure(req)
    resp.delete_cookie(name, path="/")

# Flow cookies (UI gating)
REG_COOKIE = "reg_ok"         # allows /app/register.html for a short time after pressing the button
STAGE_COOKIE = "flow_stage"   # set to "store_ok" after successful local unlock

def set_reg_cookie(resp: Response, req: Request) -> None:
    resp.set_cookie(
        key=REG_COOKIE,
        value="1",
        httponly=False,
        samesite="lax",
        secure=secure_flag(req),
        path="/app/register.html",
        max_age=120,  # 2 minutes window to open register page
    )

def clear_reg_cookie(resp: Response) -> None:
    resp.delete_cookie(REG_COOKIE, path="/app/register.html")

def set_stage_cookie(resp: Response, req: Request, value: str) -> None:
    resp.set_cookie(
        key=STAGE_COOKIE,
        value=value,
        httponly=True,
        samesite="strict",
        secure=secure_flag(req),
        path="/",
        max_age=SESSION_TTL_SECONDS,
    )

def clear_stage_cookie(resp: Response) -> None:
    resp.delete_cookie(STAGE_COOKIE, path="/")

def validate_email(email: str) -> str:
    e = (email or "").strip().lower()
    if not EMAIL_RE.match(e):
        raise HTTPException(status_code=400, detail="Invalid email address")
    return e

def validate_password(pw: str) -> str:
    if not pw or len(pw) < 10:
        raise HTTPException(status_code=400, detail="Password too short (min 10 characters)")
    return pw

def create_user(email: str, display_name: Optional[str], password: str) -> str:
    email = validate_email(email)
    validate_password(password)
    pw_hash = ph.hash(password)
    store_pw = secrets.token_urlsafe(16)  # random per-user store password returned to client after login
    with get_conn() as conn:
        row = conn.execute("SELECT id FROM users WHERE email=%s", (email,)).fetchone()
        if row:
            raise HTTPException(status_code=409, detail="Email already registered")
        user_id = secrets.token_hex(16)
        conn.execute("""
            INSERT INTO users (id, email, display_name, password_hash, store_password)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, email, display_name or email, pw_hash, store_pw))
        return user_id

def get_user_by_email(email: str) -> Optional[dict]:
    email = validate_email(email)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, email, display_name, password_hash, store_password FROM users WHERE email=%s",
            (email,),
        ).fetchone()
    if not row:
        return None
    return {"id": row[0], "email": row[1], "display_name": row[2], "password_hash": row[3], "store_password": row[4]}

def create_session(user_id: str, req: Request) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = now_utc() + timedelta(seconds=SESSION_TTL_SECONDS)
    ua = req.headers.get("user-agent", "")
    ip = (req.client.host if req.client else "") or ""
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO sessions (token, user_id, expires_at, user_agent, ip)
            VALUES (%s, %s, %s, %s, %s)
        """, (token, user_id, expires_at, ua, ip))
    return token

def get_session(req: Request) -> Optional[dict]:
    cookies = req.cookies or {}
    token = cookies.get("__Host-session") or cookies.get("session")
    if not token:
        return None
    with get_conn() as conn:
        row = conn.execute("""
            SELECT s.user_id, u.email, u.display_name, s.expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token=%s AND s.expires_at > NOW()
        """, (token,)).fetchone()
    if not row:
        return None
    return {"user_id": row[0], "email": row[1], "display_name": row[2], "expires_at": row[3]}

def delete_session(req: Request) -> None:
    cookies = req.cookies or {}
    token = cookies.get("__Host-session") or cookies.get("session")
    if not token:
        return
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token=%s", (token,))

def get_store_password_for_user(user_id: str) -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT store_password FROM users WHERE id=%s", (user_id,)).fetchone()
    if not row or not row[0]:
        # If missing (older rows), mint one now
        pw = secrets.token_urlsafe(16)
        with get_conn() as conn:
            conn.execute("UPDATE users SET store_password=%s WHERE id=%s", (pw, user_id))
        return pw
    return row[0]

# =================== FastAPI app ===================

app = FastAPI(title="CRS Proxy API")

@app.get("/health")
def health():
    return {"ok": True}

# Serve the browser app at /app
web_dir = os.path.join(os.path.dirname(__file__), "web")
app.mount("/app", StaticFiles(directory=web_dir, html=True), name="app")

def _ok(payload: dict | None = None) -> JSONResponse:
    return JSONResponse(payload or {"ok": True})

@app.on_event("startup")
def _startup():
    init_db()

# --------- Require login for Web Client (/app/*) only + flow gating ----------

# Anonymous users may load only these (landing + base assets)
ALLOW_ANON_PATHS = {
    "/app/",
    "/app/index.html",
    "/app/style.css",
    "/app/auth.js",
    "/app/favicon.ico",
}
# APIs, auth endpoints, and health are never gated here.
ALLOW_PREFIXES = ("/auth", "/api", "/health")

@app.middleware("http")
async def webclient_requires_login(request: Request, call_next):
    path = request.url.path

    # Never gate these prefixes (API/auth/health remain unaffected)
    if path.startswith(ALLOW_PREFIXES):
        return await call_next(request)

    # Gate only the Web Client static site
    if path.startswith("/app"):
        # Registration page only allowed if short-lived reg cookie is set
        if path == "/app/register.html":
            reg_cookie = request.cookies.get(REG_COOKIE)
            if not reg_cookie:
                return RedirectResponse("/app/index.html", status_code=303)
            # allow to proceed

        # Load page requires active session
        if path == "/app/load.html":
            sess = await anyio.to_thread.run_sync(get_session, request)
            if not sess:
                return RedirectResponse("/app/index.html", status_code=303)

        # Dashboard requires session + stage "store_ok"
        if path == "/app/dashboard.html":
            sess = await anyio.to_thread.run_sync(get_session, request)
            if not sess:
                return RedirectResponse("/app/index.html", status_code=303)
            stage = request.cookies.get(STAGE_COOKIE)
            if stage != "store_ok":
                return RedirectResponse("/app/load.html", status_code=303)

        # For any other /app path (like sender.html, umbral wasm, etc.):
        if request.method in ("GET", "HEAD"):
            sess = await anyio.to_thread.run_sync(get_session, request)
            if not sess and path not in ALLOW_ANON_PATHS and path != "/app/register.html":
                return RedirectResponse("/app/index.html", status_code=303)

    return await call_next(request)

# -------------- Existing CRS API (unchanged) --------------

@app.post("/api/add_or_update_secret")
def api_add_or_update_secret(body: dict):
    try:
        payload = {
            "sender_id": body["sender_id"],
            "secret_id": body["secret_id"],
            "capsule": b64d(body["capsule_b64"]),
            "ciphertext": b64d(body["ciphertext_b64"]),
            "sender_public_key": b64d(body["sender_public_key_b64"]),
            "sender_verifying_key": b64d(body["sender_verifying_key_b64"]),
        }
        upsert_secret(payload)
        return _ok()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/delete_secret")
def api_delete_secret(body: dict):
    try:
        delete_secret(body["sender_id"], body["secret_id"])
        return _ok()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/grant_access_proxy")
def api_grant_access_proxy(body: dict):
    try:
        sender_id   = body["sender_id"]
        receiver_id = body["receiver_id"]
        secret_id   = body["secret_id"]
        kfrags      = [b64d(b) for b in body["kfrags_b64"]]
        insert_or_replace_grant(sender_id, receiver_id, secret_id, kfrags)
        return _ok()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/grant_access_receiver")
def api_grant_access_receiver(body: dict):
    try:
        receiver_id = body["receiver_id"]
        enqueue_for_receiver(receiver_id, GRANT_ACCESS_RECEIVER, body)
        return _ok()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/revoke_access")
def api_revoke_access(body: dict):
    try:
        revoke_grant(body["sender_id"], body["receiver_id"], body["secret_id"])
        return _ok()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/request_secret")
def api_request_secret(body: dict):
    try:
        receiver_id = body["receiver_id"]
        sender_id   = body["sender_id"]
        secret_id   = body["secret_id"]
        receiving_pk  = PublicKey.from_compressed_bytes(b64d(body["receiver_public_key_b64"]))

        secret = load_secret(sender_id, secret_id)
        if not secret:
            return {"action": "ERROR", "payload": {"error": f"Unknown secret '{secret_id}'"}}

        kfrags = load_grant_kfrags(sender_id, receiver_id, secret_id)
        if not kfrags:
            return {"action": "ERROR", "payload": {"error": f"No grant for {receiver_id} -> {secret_id}"}}

        capsule       = secret["capsule"]
        ciphertext    = secret["ciphertext"]
        delegating_pk = secret["sender_public_key"]
        verifying_pk  = secret["sender_verifying_key"]

        verified_kfrags = [
            kf.verify(
                delegating_pk=delegating_pk,
                receiving_pk=receiving_pk,
                verifying_pk=verifying_pk
            )
            for kf in kfrags
        ]
        cfrags = [reencrypt(capsule=capsule, kfrag=vkf) for vkf in verified_kfrags]

        return {
            "action": RESPONSE_SECRET,
            "payload": {
                "capsule_b64": b64e(bytes(capsule)),
                "ciphertext_b64": b64e(ciphertext),
                "cfrags_b64": [b64e(bytes(c)) for c in cfrags]
            }
        }
    except Exception as e:
        return {"action": "ERROR", "payload": {"error": f"Proxy error: {e}"}}

@app.post("/api/list_grants")
def api_list_grants(body: dict):
    try:
        sender_id = body["sender_id"]
        summary = list_grants_for_sender(sender_id)
        return {"action": GRANTS_SUMMARY, "payload": summary}
    except Exception as e:
        return {"action": "ERROR", "payload": {"error": str(e)}}

@app.post("/api/request_access")
def api_request_access(body: dict):
    try:
        sender_id   = body["sender_id"]
        receiver_id = body["receiver_id"]
        secret_id   = body["secret_id"]
        if not sender_id or not receiver_id or not secret_id:
            raise ValueError("Missing sender_id/receiver_id/secret_id")
        enqueue_for_sender(sender_id, REQUEST_ACCESS, body)
        return _ok()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/pull_inbox/sender")
def api_pull_inbox_sender(body: dict):
    try:
        sender_id = body["sender_id"]
        msgs = pull_sender_inbox(sender_id)
        return {"action": INBOX_CONTENTS, "payload": {"messages": msgs}}
    except Exception as e:
        return {"action": "ERROR", "payload": {"error": str(e)}}

@app.post("/api/pull_inbox/receiver")
def api_pull_inbox_receiver(body: dict):
    try:
        receiver_id = body["receiver_id"]
        msgs = pull_receiver_inbox(receiver_id)
        return {"action": INBOX_CONTENTS, "payload": {"messages": msgs}}
    except Exception as e:
        return {"action": "ERROR", "payload": {"error": str(e)}}

# -------------- NEW: Auth & flow endpoints --------------

@app.get("/")
def root():
    return RedirectResponse("/app/", status_code=307)

@app.get("/auth/session")
def auth_session(req: Request):
    sess = get_session(req)
    if not sess:
        raise HTTPException(status_code=401, detail="No active session")
    return {
        "user": {
            "id": sess["user_id"],
            "email": sess["email"],
            "display_name": sess["display_name"],
        },
        "expires_at": sess["expires_at"].isoformat(),
    }

@app.post("/auth/logout")
def auth_logout(req: Request):
    delete_session(req)
    resp = _ok({"ok": True})
    clear_session_cookie(resp, req)
    clear_reg_cookie(resp)
    clear_stage_cookie(resp)
    return resp

@app.post("/auth/register")
def auth_register(req: Request, body: dict):
    """
    Body: { "email": "alice@example.com", "password": "strong password", "display_name": "Alice" }
    """
    email = validate_email(body.get("email", ""))
    password = validate_password(body.get("password", ""))
    display_name = (body.get("display_name") or email)
    user_id = create_user(email, display_name, password)
    token = create_session(user_id, req)
    resp = _ok({"ok": True})
    set_session_cookie(resp, req, token)
    # clear reg cookie once used
    clear_reg_cookie(resp)
    return resp

@app.post("/auth/login")
def auth_login(req: Request, body: dict):
    """
    Body: { "email": "alice@example.com", "password": "..." }
    """
    email = validate_email(body.get("email", ""))
    password = body.get("password", "") or ""
    user = get_user_by_email(email)
    # Reduce user-enumeration signal: verify a dummy hash if user missing
    dummy_hash = ph.hash("x"*12)
    stored_hash = (user or {}).get("password_hash") or dummy_hash
    try:
        ok = ph.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHash):
        ok = False

    if not (user and ok):
        import time as _t; _t.sleep(0.25)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    try:
        if user and ph.check_needs_rehash(stored_hash):
            new_hash = ph.hash(password)
            with get_conn() as conn:
                conn.execute("UPDATE users SET password_hash=%s WHERE id=%s", (new_hash, user["id"]))
    except Exception:
        pass

    token = create_session(user["id"], req)
    resp = _ok({"ok": True})
    set_session_cookie(resp, req, token)
    return resp

@app.post("/auth/allow_register")
def allow_register(req: Request):
    """Set short-lived cookie to allow /app/register.html."""
    resp = _ok({"ok": True})
    set_reg_cookie(resp, req)
    return resp

@app.post("/auth/stage")
def set_stage(req: Request, body: dict):
    """Set flow stage cookie after successful local unlock. Body: {"stage":"store_ok"}"""
    sess = get_session(req)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")
    stage = (body or {}).get("stage")
    if stage not in ("store_ok",):
        raise HTTPException(status_code=400, detail="Unknown stage")
    resp = _ok({"ok": True, "stage": stage})
    set_stage_cookie(resp, req, stage)
    return resp

@app.get("/api/store_password")
def api_store_password(req: Request):
    """Return the per-user store password to unlock local file (only when logged in)."""
    sess = get_session(req)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")
    pw = get_store_password_for_user(sess["user_id"])
    return {"password": pw}

# -------------- NEW: Restricted example field --------------

@app.get("/api/restricted_field")
def api_restricted_field(req: Request):
    sess = get_session(req)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Example private data
    return {"field": f"Hello {sess['display_name']} — this is your restricted field."}

# -------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run("proxy:app", host=PROXY_HOST, port=PROXY_PORT, reload=False)
