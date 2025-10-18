# utils
from typing import List, Dict, Any, Optional

# pre proxy core
from umbral_pre import PublicKey, Capsule, KeyFrag, reencrypt
import psycopg
import msgpack
import secrets

# system utils
import os
import sys

# utils
import re
from datetime import datetime, timedelta, timezone

# web utils
import anyio
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse
from contextlib import asynccontextmanager

# web assambly mimetypes (for wasm umbral bindings)
import mimetypes;
mimetypes.add_type('application/wasm', '.wasm')

# password hashing (Argon2id)
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

# =================== DB INIT & Tables ===================

def init_db():
    with get_conn() as conn:
        # users
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
              user_id TEXT PRIMARY KEY,
              email TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL
            );
        """)
        # session
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
              user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
              token TEXT PRIMARY KEY,
              expires_at TIMESTAMPTZ NOT NULL
            );
        """)
        # encrypted user blob
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_blob_store (
              user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
              blob BYTEA NOT NULL
            );
        """)
        # ciphers
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ciphers (
              user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
              secret_id TEXT NOT NULL,
              capsule BYTEA NOT NULL,
              ciphertext BYTEA NOT NULL,
              sender_public_key BYTEA NOT NULL,
              sender_verifying_key BYTEA NOT NULL,
              PRIMARY KEY (user_id, secret_id)
            );
        """)
        # grants 
        # TODO merge grants and secret_id_mappping
        conn.execute("""
            CREATE TABLE IF NOT EXISTS grants (
              delegator_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
              delegatee_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
              delegator_secret_id TEXT NOT NULL,
              delegatee_secret_id TEXT NOT NULL,
              kfrags_b BYTEA NOT NULL,
              PRIMARY KEY (delegator_id, delegatee_id, delegator_secret_id),
              UNIQUE (delegator_id, delegatee_id, delegatee_secret_id),
              CONSTRAINT not_selfmap CHECK (delegator_id <> delegatee_id),
              FOREIGN KEY (delegator_id, delegator_secret_id) REFERENCES ciphers(user_id, secret_id) ON DELETE CASCADE,
              CREATE INDEX ON grants (delegatee_id, delegatee_secret_id);
            );
        """)
        # inbox
        conn.execute("""
            CREATE TABLE IF NOT EXISTS inbox (
              user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
              msg BYTEA NOT NULL
            );
        """)
    print("[Proxy] DB initialized.")

# =================== CRS DB HELPERS ===================

def upsert_secret(payload: Dict[str, Any]) -> None:
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO ciphers (
              user_id, secret_id, capsule, ciphertext, sender_public_key, sender_verifying_key
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (user_id, secret_id) DO UPDATE SET
              capsule = EXCLUDED.capsule,
              ciphertext = EXCLUDED.ciphertext,
              sender_public_key = EXCLUDED.sender_public_key,
              sender_verifying_key = EXCLUDED.sender_verifying_key
        """, (
            payload["user_id"],
            payload["secret_id"],
            payload["capsule"],
            payload["ciphertext"],
            payload["sender_public_key"],
            payload["sender_verifying_key"],
        ))

def erase_cipher(user_id: str, secret_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM ciphers WHERE user_id=%s AND secret_id=%s", (user_id, secret_id))
        conn.execute("DELETE FROM grants  WHERE user_id=%s AND secret_id=%s", (user_id, secret_id))

def upsert_grant(delegator_id: str, delegatee_id: str, secret_id: str, kfrags_bytes_list: List[bytes]) -> None:
    kfrags = msgpack.packb(kfrags_bytes_list, use_bin_type=True)
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO grants (delegator_id, delegatee_id, secret_id, kfrags)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (delegator_id, delegatee_id, secret_id) DO UPDATE SET
              kfrags = EXCLUDED.kfrags
        """, (delegator_id, delegatee_id, secret_id, kfrags))

def revoke_grant(delegator_id: str, delegatee_id: str, secret_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM grants WHERE delegator_id=%s AND delegatee_id=%s AND secret_id=%s",
                     (delegator_id, delegatee_id, secret_id))

def load_cipher(user_id: str, secret_id: str):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT capsule, ciphertext, sender_public_key, sender_verifying_key
            FROM ciphers
            WHERE user_id=%s AND secret_id=%s
        """, (user_id, secret_id)).fetchone()
    if not row:
        return None
    capsule_b, ciphertext_b, spk_b, svk_b = row
    return {
        "capsule": Capsule.from_bytes(capsule_b),
        "ciphertext": ciphertext_b,
        "sender_public_key": PublicKey.from_compressed_bytes(spk_b),
        "sender_verifying_key": PublicKey.from_compressed_bytes(svk_b),
    }

def fetch_grant_kfrags(delegator_id: str, delegatee_id: str, secret_id: str) -> List[KeyFrag]:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT kfrags_b
            FROM grants
            WHERE delegator_id=%s AND delegatee_id=%s AND secret_id=%s
        """, (delegator_id, delegatee_id, secret_id)).fetchone()
    if not row:
        return []
    (blob,) = row
    kfrag_bytes_list = msgpack.unpackb(blob, raw=False)
    return [KeyFrag.from_bytes(b) for b in kfrag_bytes_list]
#^
def query_grants_for(user_id: str) -> dict:
    by_secret: Dict[str, List[str]] = {}
    total_grants = 0
    with get_conn() as conn:
        all_users_secret_id = [r[0] for r in conn.execute(
            "SELECT secret_id FROM ciphers WHERE user_id=%s", (user_id,)
        ).fetchall()]
        for secret_id in all_users_secret_id:
            by_secret.setdefault(secret_id, [])
        rows = conn.execute(
            "SELECT delegator_id, delegatee_id FROM grants WHERE user_id=%s ORDER BY delegator_id, delegatee_id",
            (user_id,)
        ).fetchall()
    for secret_id, delegatee_id in rows:
        by_secret.setdefault(secret_id, []).append(delegatee_id)
        total_grants += 1
    return {"by_secret": by_secret, "totals": {"ciphers": len(by_secret), "grants": total_grants}}

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
    is_https = ("https" == req.url.scheme)
    host = (req.url.hostname or "").lower()
    dev_http_local = ("http" == req.url.scheme and host in ("localhost", "127.0.0.1"))
    if is_https and not dev_http_local:
        return "__Host-session", True
    return "session", False

def secure_flag(req: Request) -> bool:
    is_https = ("http" == req.url.scheme)
    host = (req.url.hostname or "").lower()
    dev_http_local = ("http" == req.url.scheme and host in ("localhost", "127.0.0.1"))
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
STAGE_COOKIE = "flow_stage"   # set to "store_ok" after successful decrypt/create

def set_reg_cookie(resp: Response, req: Request) -> None:
    resp.set_cookie(
        key=REG_COOKIE,
        value="1",
        httponly=False,
        samesite="lax",
        secure=secure_flag(req),
        path="/app/register.html",
        max_age=120,  # 2 minutes
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
    with get_conn() as conn:
        row = conn.execute("SELECT id FROM users WHERE email=%s", (email,)).fetchone()
        if row:
            raise HTTPException(status_code=409, detail="Email already registered")
        user_id = secrets.token_hex(16)
        conn.execute("""
            INSERT INTO users (id, email, display_name, password_hash)
            VALUES (%s, %s, %s, %s)
        """, (user_id, email, display_name or email, pw_hash))
        return user_id

def get_user_by_email(email: str) -> Optional[dict]:
    email = validate_email(email)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, email, display_name, password_hash FROM users WHERE email=%s",
            (email,),
        ).fetchone()
    if not row:
        return None
    return {"id": row[0], "email": row[1], "display_name": row[2], "password_hash": row[3]}

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

# =================== FastAPI app ===================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await anyio.to_thread.run_sync(init_db)
    yield

app = FastAPI(title="CRS Proxy API", lifespan=lifespan)

@app.get("/health")
def health():
    return {"ok": True}

# Serve the browser app at /app (support both old 'web' and new 'web_client')
_base_dir = os.path.dirname(__file__)
_candidates = [
    os.path.join(_base_dir, "web_client"),            # container: /app/web_client
    os.path.join(_base_dir, "web"),                   # container (legacy): /app/web
    os.path.join(_base_dir, "..", "web_client"),     # local dev: src/python_server -> ../web_client
    os.path.join(_base_dir, "..", "web"),            # local dev (legacy)
]
for _p in _candidates:
    if os.path.isdir(_p):
        web_dir = os.path.abspath(_p)
        break
else:
    # default to new name under current dir; FastAPI will error on startup if missing
    web_dir = os.path.abspath(os.path.join(_base_dir, "web_client"))

app.mount("/app", StaticFiles(directory=web_dir, html=True), name="app")

def _ok(payload: dict | None = None) -> JSONResponse:
    return JSONResponse(payload or {"ok": True})

# --------- Require login for Web Client (/app/*) only + flow gating ----------

ALLOW_ANON_PATHS = {
    "/app/",
    "/app/index.html",
    "/app/style.css",
    "/app/auth.js",
    "/app/favicon.ico",
}
ALLOW_PREFIXES = ("/auth", "/api", "/health")

@app.middleware("http")
async def webclient_requires_login(request: Request, call_next):
    path = request.url.path

    if path.startswith(ALLOW_PREFIXES):
        return await call_next(request)

    if path.startswith("/app"):
        # gate register page with short-lived cookie
        if "/app/register.html" == path:
            # If already logged in, send folks to the next step in the flow.
            sess = await anyio.to_thread.run_sync(get_session, request)
            if sess:
                if "store_ok" == request.cookies.get("flow_stage"):
                    return RedirectResponse("/app/dashboard.html", status_code=303)
                return RedirectResponse("/app/store.html", status_code=303)

        # store page requires session
        if "/app/store.html" == path:
            sess = await anyio.to_thread.run_sync(get_session, request)
            if not sess:
                return RedirectResponse("/app/index.html", status_code=303)

        # dashboard requires session + stage
        if "/app/dashboard.html" == path:
            sess = await anyio.to_thread.run_sync(get_session, request)
            if not sess:
                return RedirectResponse("/app/index.html", status_code=303)
            if request.cookies.get("flow_stage") != "store_ok":
                return RedirectResponse("/app/store.html", status_code=303)

        if request.method in ("GET", "HEAD"):
            sess = await anyio.to_thread.run_sync(get_session, request)
            if not sess and path not in ALLOW_ANON_PATHS and path != "/app/register.html":
                return RedirectResponse("/app/index.html", status_code=303)

    return await call_next(request)

# -------------- CRS API --------------

@app.post("/api/add_or_update_secret")
def api_add_or_update_secret(body: dict):
    try:
        # TODO change sender_id with session token
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

@app.post("/api/erase_secret")
def api_delete_secret(body: dict):
    try:
        erase_cipher(body["sender_id"], body["secret_id"])
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
        upsert_grant(sender_id, receiver_id, secret_id, kfrags)
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

        secret = load_cipher(sender_id, secret_id)
        if not secret:
            return {"action": "ERROR", "payload": {"error": f"Unknown secret '{secret_id}'"}}

        kfrags = fetch_grant_kfrags(sender_id, receiver_id, secret_id)
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
        summary = query_grants_for(sender_id)
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
    email = validate_email(body.get("email", ""))
    password = validate_password(body.get("password", ""))
    display_name = (body.get("display_name") or email)
    user_id = create_user(email, display_name, password)
    token = create_session(user_id, req)
    resp = _ok({"ok": True})
    set_session_cookie(resp, req, token)
    clear_reg_cookie(resp)
    return resp

@app.post("/auth/login")
def auth_login(req: Request, body: dict):
    email = validate_email(body.get("email", ""))
    password = body.get("password", "") or ""
    user = get_user_by_email(email)
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
    resp = _ok({"ok": True})
    set_reg_cookie(resp, req)
    return resp

@app.post("/auth/stage")
def set_stage(req: Request, body: dict):
    sess = get_session(req)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")
    stage = (body or {}).get("stage")
    if stage not in ("store_ok",):
        raise HTTPException(status_code=400, detail="Unknown stage")
    resp = _ok({"ok": True, "stage": stage})
    set_stage_cookie(resp, req, stage)
    return resp

# -------------- NEW: Encrypted per-user store API --------------

@app.get("/api/user_store")
def api_user_store_get(req: Request):
    """Return encrypted store blob if present; never returns plaintext."""
    sess = get_session(req)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")
    with get_conn() as conn:
        row = conn.execute("SELECT blob, updated_at FROM user_stores WHERE user_id=%s", (sess["user_id"],)).fetchone()
    if not row:
        return {"exists": False}
    blob, updated_at = row
    return {"exists": True, "blob_b64": b64e(blob), "updated_at": updated_at.isoformat()}

@app.post("/api/user_store")
def api_user_store_put(req: Request, body: dict):
    """Replace encrypted store blob with client-provided ciphertext."""
    sess = get_session(req)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")
    blob_b64 = (body or {}).get("blob_b64") or ""
    if not blob_b64:
        raise HTTPException(status_code=400, detail="Missing blob_b64")
    blob = b64d(blob_b64)
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO user_stores (user_id, blob, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (user_id) DO UPDATE SET blob=EXCLUDED.blob, updated_at=NOW()
        """, (sess["user_id"], blob))
    return _ok({"ok": True})

# -------------- Example restricted field --------------

@app.get("/api/restricted_field")
def api_restricted_field(req: Request):
    sess = get_session(req)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"field": f"Hello {sess['display_name']} — this is your restricted field."}

# -------------------------------------------------------------

if "__main__" == __name__:
    init_db()
    import uvicorn
    uvicorn.run("proxy:app", host=PROXY_HOST, port=PROXY_PORT, reload=False)
