# language utils
from base64 import b64encode as b64e, b64decode as b64d
from typing import List, Optional, Dict, Any
from pydantic import EmailStr
from uuid import UUID
import re

# pre proxy core
from umbral_pre import PublicKey, Capsule, KeyFrag, reencrypt
import psycopg
import msgpack
import secrets

# system utils
import os
import sys

# time
import time
from datetime import datetime, timedelta, timezone

# json
import json

# web utils
import anyio
import uvicorn
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager

# web assambly mimetypes (for serving the wasm umbral bindings)
import mimetypes;
mimetypes.add_type('application/wasm', '.wasm')

# password hashing (Argon2id)
from argon2 import PasswordHasher
from argon2.low_level import Type as Argon2Type
from argon2.exceptions import VerifyMismatchError, InvalidHash

from common import (
    LoginRequest, Password,
    UpsertItemRequest, EraseItemRequest,
    GrantAccessRequest, RevokeAccessRequest,
    RequestItemRequest,
    SaveToVaultRequest,
    PushSolicitationRequest, PullSolicitationBundleRequest, AckSolicitationBundleRequest
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
        conn.execute("CREATE EXTENSION IF NOT EXISTS citext;")
        # users
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email CITEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        """)
        # sessions
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                token TEXT PRIMARY KEY,
                expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '5 minutes')
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS by_expires_at ON sessions (expires_at);")
        # user's encrypted store
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                encrypted_localstore BYTEA NOT NULL
            );
        """)
        # crypto_bundle
        conn.execute("""
            CREATE TABLE IF NOT EXISTS crypto_bundle (
                user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                item_id TEXT NOT NULL,
                capsule BYTEA NOT NULL,
                ciphertext BYTEA NOT NULL,
                provider_public_key BYTEA NOT NULL,
                provider_verifying_key BYTEA NOT NULL,
                PRIMARY KEY (user_id, item_id)
            );
        """)
        # grants
        conn.execute("""
            CREATE TABLE IF NOT EXISTS grants (
                provider_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                requester_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                provider_item_id TEXT NOT NULL,
                requester_item_id TEXT NOT NULL,
                kfrags_b BYTEA NOT NULL,
                PRIMARY KEY (provider_id, requester_id, provider_item_id),
                UNIQUE (provider_id, requester_id, requester_item_id),
                CONSTRAINT not_selfmap CHECK (provider_id <> requester_id),
                FOREIGN KEY (provider_id, provider_item_id)
                    REFERENCES crypto_bundle(user_id, item_id) ON DELETE RESTRICT
            );
        """)
        # solicitations
        conn.execute("""
            CREATE TABLE IF NOT EXISTS solicitations (
                request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                requester_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                provider_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                payload JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS by_provider_and_created
            ON solicitations (provider_id, created_at, request_id);
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS by_pair_and_created
            ON solicitations (provider_id, requester_id, created_at, request_id);
        """)
    print("[Proxy] DB initialized.")

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

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def set_session_cookie(resp: Response, req: Request, token: str) -> None:
    resp.set_cookie(
        key="__Host-session",
        value=token,
        httponly=True,
        samesite="strict",
        secure=True,
        path="/",
        max_age=SESSION_TTL_SECONDS,
    )

def clear_session_cookie(resp: Response, req: Request) -> None:
    resp.delete_cookie(
        key="__Host-session",
        httponly=True,
        samesite="strict",
        secure=True,
        path="/",
    )

# =================== AUTH DB HELPERS ===================

def create_user(email: EmailStr, password: Password) -> UUID:
    pw_hash = ph.hash(password)
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email=%s", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="Email already registered")
        cur = conn.execute("""
            INSERT INTO users (email, password_hash)
            VALUES (%s, %s)
            RETURNING user_id
        """, (email, pw_hash))
        (user_id,) = cur.fetchone()
        return user_id

def create_session(user_id: UUID, req: Request) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = now_utc() + timedelta(seconds=SESSION_TTL_SECONDS)
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO sessions (token, user_id, expires_at)
            VALUES (%s, %s, %s)
        """, (token, user_id, expires_at))
    return token

def refresh_session_expiry(token: str) -> None:
    if not token:
        return
    new_exp = now_utc() + timedelta(seconds=SESSION_TTL_SECONDS)
    with get_conn() as conn:
        conn.execute("UPDATE sessions SET expires_at=%s WHERE token=%s", (new_exp, token))

def get_user_by_email(email: EmailStr) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT user_id, password_hash FROM users WHERE email=%s",
            (email,),
        ).fetchone()
    if not row:
        return None
    return {"user_id": row[0], "password_hash": row[1]}

def get_session_user_by_request(req: Request) -> Optional[dict]:
    cookies = req.cookies or {}
    token = cookies.get("__Host-session")
    if not token:
        return None
    with get_conn() as conn:
        row = conn.execute("""
            SELECT s.user_id, u.email, s.expires_at
            FROM sessions s
            JOIN users u ON u.user_id = s.user_id
            WHERE s.token=%s AND s.expires_at > NOW()
        """, (token,)).fetchone()
    if not row:
        return None
    return {"user_id": row[0], "email": row[1]}

def user_id_by_token(token: str) -> Optional[UUID]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT user_id FROM sessions WHERE token=%s AND expires_at > NOW()",
            (token,)
        ).fetchone()
    return row[0] if row else None

async def user_id_by_session(request: Request) -> Optional[UUID]:
    token = (request.cookies or {}).get("__Host-session")
    if not token:
        return None
    return await anyio.to_thread.run_sync(user_id_by_token, token)

def delete_session(req: Request) -> None:
    cookies = req.cookies or {}
    token = cookies.get("__Host-session")
    if not token:
        return
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token=%s", (token,))

SESSION_JANITOR_SECONDS = int(os.getenv("SESSION_JANITOR_SECONDS", "60"))

def cleanup_expired_sessions() -> int:
    """Delete expired sessions. Returns number of rows deleted."""
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE expires_at <= NOW()")
        return cur.rowcount

# =================== PRE DB HELPERS ===================

def fetch_crypto_bundle(user_id: UUID, item_id: str):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT capsule, ciphertext, provider_public_key, provider_verifying_key
            FROM crypto_bundle
            WHERE user_id=%s AND item_id=%s
            """,
            (user_id, item_id)).fetchone()
    if not row:
        return None
    capsule_b, ciphertext_b, spk_b, svk_b = row
    return {
        "capsule": Capsule.from_bytes(capsule_b),
        "ciphertext": ciphertext_b,
        "provider_public_key": PublicKey.from_compressed_bytes(spk_b),
        "provider_verifying_key": PublicKey.from_compressed_bytes(svk_b),
    }

def fetch_granted_kfrags(provider_id: UUID, requester_id: UUID, requester_item_id: str) -> List[KeyFrag]:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT kfrags_b
            FROM grants
            WHERE provider_id=%s AND requester_id=%s AND requester_item_id=%s
        """, (provider_id, requester_id, requester_item_id)).fetchone()
    if not row:
        return []
    (blob,) = row
    kfrag_bytes_list = msgpack.unpackb(blob, raw=False)
    return [KeyFrag.from_bytes(b) for b in kfrag_bytes_list]

# =================== FastAPI app ===================

@asynccontextmanager
async def lifespan(app: FastAPI):
    await anyio.to_thread.run_sync(init_db)

    async def _session_janitor():
        while True:
            try:
                await anyio.sleep(SESSION_JANITOR_SECONDS)
                deleted = await anyio.to_thread.run_sync(cleanup_expired_sessions)
                if deleted:
                    print(f"[Proxy] Session janitor pruned {deleted} expired session(s).")
            except Exception as e:
                print(f"[Proxy] Session janitor error: {e!r}")

    async with anyio.create_task_group() as tg:
        tg.start_soon(_session_janitor)
        yield
        tg.cancel_scope.cancel()


app = FastAPI(title="CRS Proxy API", lifespan=lifespan)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=["app.localhost"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["app.localhost"])

_base_dir = os.path.dirname(__file__)
web_dir = os.path.abspath(os.path.join(_base_dir, "web_client"))

app.mount("/app", StaticFiles(directory=web_dir, html=True), name="app")

def _ok(payload: dict | None = None) -> JSONResponse:
    return JSONResponse(payload or {"ok": True})

# =================== Middleware Wiring ===================

LOGIN_PAGE = "/app/login.html"
DASHBOARD_PAGE = "/app/dashboard.html"

PRE_LOGIN_PATHS = {
    LOGIN_PAGE,
    "/app/style.css",
    "/app/favicon.ico",
    "/app/crs-sdk.js",
}

@app.middleware("http")
async def gatekeeper(request: Request, call_next):
    path = request.url.path

    # auth Backend always availbale
    if path.startswith("/auth"):
        return await call_next(request)

    user_id = await user_id_by_session(request)
    logged_in = bool(user_id)

    # API always exposed but only available in session
    if path.startswith("/api"):
        if not logged_in:
            return JSONResponse({"error": "not_authenticated"}, status_code=401)
        request.state.user_id = user_id
        token = (request.cookies or {}).get("__Host-session")
        refresh_session_expiry(token)
        return await call_next(request)

    # default to login page or dashboard depending on session or nah
    if path == "/":
        if not logged_in:
            return RedirectResponse(LOGIN_PAGE, status_code=303)
        return RedirectResponse(DASHBOARD_PAGE, status_code=303)

    # serve login or skip if already in session
    if path in PRE_LOGIN_PATHS:
        if path == LOGIN_PAGE and logged_in:
            return RedirectResponse(DASHBOARD_PAGE, status_code=303)
        return await call_next(request)

    # not serving anything web without login
    if not logged_in:
        if request.method in ("GET", "HEAD"):
            return RedirectResponse(LOGIN_PAGE, status_code=303)
        return JSONResponse({"error": "not_authenticated"}, status_code=401)

    # if we can't serve it ... dashboard it is
    response = await call_next(request)
    if response.status_code == 404 and request.method in ("GET", "HEAD"):
        return RedirectResponse(DASHBOARD_PAGE, status_code=303)
    return response

# =================== CRS API ===================

# ------------------- authentication ---------------------

@app.post("/auth/register")
def auth_register(req: Request, body: LoginRequest):
    user_id = create_user(body.email, body.password)
    token = create_session(user_id, req)
    resp = _ok({"ok": True})
    set_session_cookie(resp, req, token)
    return resp

DUMMY_HASH = ph.hash("€0nStDumrnyPW-15")

@app.post("/auth/login")
def auth_login(req: Request, body: LoginRequest):
    user_entry = get_user_by_email(body.email)
    stored_hash = (user_entry or {}).get("password_hash") or DUMMY_HASH

    try:
        ok = ph.verify(stored_hash, body.password)
    except (VerifyMismatchError, InvalidHash):
        ok = False

    if not (user_entry and ok):
        time.sleep(0.25)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if ph.check_needs_rehash(stored_hash):
        new_hash = ph.hash(body.password)
        with get_conn() as conn:
            conn.execute("UPDATE users SET password_hash=%s WHERE user_id=%s", (new_hash, user_entry["user_id"]))

    token = create_session(user_entry["user_id"], req)
    resp = _ok({"ok": True})
    set_session_cookie(resp, req, token)
    return resp

@app.post("/auth/logout")
def auth_logout(req: Request):
    delete_session(req)
    resp = _ok({"ok": True})
    clear_session_cookie(resp, req)
    return resp

# ------------------- user vaults ---------------------

MAX_VAULT_BYTES = int(os.getenv("MAX_VAULT_BYTES", str(3 * 1024 * 1024)))  # 3 MiB default

@app.put("/api/save_to_vault")
def api_save_to_vault(request: Request, body: SaveToVaultRequest):
    user_id = request.state.user_id
    try:
        encrypted_localstore = b64d(body.encrypted_localstore_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="bad_base64")

    if len(encrypted_localstore) > MAX_VAULT_BYTES:
        return JSONResponse(
            {"error": "payload_too_large", "max_bytes": MAX_VAULT_BYTES},
            status_code=413,
        )

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO vault (user_id, encrypted_localstore)
            VALUES (%s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                encrypted_localstore = EXCLUDED.encrypted_localstore
            """,
            (user_id, encrypted_localstore),
        )
    return _ok()

@app.get("/api/load_from_vault")
def api_load_from_vault(request: Request):
    user_id = request.state.user_id
    with get_conn() as conn:
        row = conn.execute(
            "SELECT encrypted_localstore FROM vault WHERE user_id=%s",
            (user_id,),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="vault_not_found")

    encrypted_localstore = row[0]
    return { "encrypted_localstore_b64": b64e(encrypted_localstore).decode("ascii") }

# ------------------- post office ---------------------

def _validate_solicitation_payload(payload: Dict[str, Any]) -> None:
    rows = payload.get("rows")
    if not isinstance(rows, list) or not rows:
        raise HTTPException(status_code=400, detail="invalid_payload_rows")
    for r in rows:
        if not isinstance(r, dict):
            raise HTTPException(status_code=400, detail="invalid_row_type")
        for k in ("field_description", "secret_id", "value_example_format", "requester_public_key_b64"):
            v = r.get(k)
            if not isinstance(v, str) or not v:
                raise HTTPException(status_code=400, detail=f"missing_{k}")
        if "default_field" in r and not isinstance(r["default_field"], (str, type(None))):
            raise HTTPException(status_code=400, detail="bad_default_field")
        if "request_order" in r:
            ro = r["request_order"]
            if not ((isinstance(ro, str) and re.match(r"^\d+\.\d+$", ro))):
                raise HTTPException(status_code=400, detail="bad_request_order")
        try:
            b64d(r["requester_public_key_b64"])
        except Exception:
            raise HTTPException(status_code=400, detail="bad_public_key_b64")

@app.post("/api/push_solicitation")
def api_push_solicitation(request: Request, body: PushSolicitationRequest):
    requester_id = request.state.user_id
    if requester_id == body.provider_id:
        raise HTTPException(status_code=400, detail="self_request_forbidden")

    _validate_solicitation_payload(body.payload)
    payload_json = json.dumps(body.payload, separators=(",", ":"))

    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO solicitations (requester_id, provider_id, payload)
            VALUES (%s, %s, %s::jsonb)
            RETURNING request_id, created_at
            """,
            (requester_id, body.provider_id, payload_json),
        )
        request_id, created_at = cur.fetchone()

    return {
        "request_id": str(request_id),
        "created_at": created_at.isoformat(),
    }

@app.post("/api/pull_solicitation_bundle")
def api_pull_solicitation_bundle(request: Request, body: PullSolicitationBundleRequest):
    provider_id = request.state.user_id

    with get_conn() as conn:
        head = conn.execute(
            """
            SELECT requester_id, request_id, created_at
            FROM solicitations
            WHERE provider_id=%s
            ORDER BY created_at ASC, request_id ASC
            LIMIT 1
            """,
            (provider_id,),
        ).fetchone()

        if not head:
            return {"has_bundle": False, "has_more": False}

        target_requester_id = head[0]

        rows = conn.execute(
            """
            SELECT request_id, payload, created_at
            FROM solicitations
            WHERE provider_id=%s AND requester_id=%s
            ORDER BY created_at ASC, request_id ASC
            """,
            (provider_id, target_requester_id),
        ).fetchall()

        (has_more,) = conn.execute(
            """
            SELECT EXISTS(
                SELECT 1 FROM solicitations
                WHERE provider_id=%s AND requester_id <> %s
            )
            """,
            (provider_id, target_requester_id),
        ).fetchone()

    last_created_at = rows[-1][2]
    last_request_id = rows[-1][0]

    bundle_requests = []
    for req_id, payload, created_at in rows:
        if isinstance(payload, str):
            payload = json.loads(payload)
        bundle_requests.append({
            "request_id": str(req_id),
            "payload": payload,
            "created_at": created_at.isoformat(),
        })

    return {
        "has_bundle": True,
        "requester_id": str(target_requester_id),
        "bundle": {
            "requests": bundle_requests,  # oldest -> newest
            "ack_token": {
                "max_created_at": last_created_at.isoformat(),
                "max_request_id": str(last_request_id),
            },
        },
        "has_more": bool(has_more),
    }

@app.post("/api/ack_solicitation_bundle")
def api_ack_solicitation_bundle(request: Request, body: AckSolicitationBundleRequest):
    provider_id = request.state.user_id
    with get_conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM solicitations
            WHERE provider_id=%s AND requester_id=%s
              AND (created_at, request_id) <= (%s, %s)
            """,
            (provider_id, body.requester_id, body.max_created_at, body.max_request_id),
        )
    return _ok({"deleted": cur.rowcount})

# ------------------- CRS ---------------------

@app.post("/api/upsert_item")
def api_upsert_item(request: Request, body: UpsertItemRequest):

    with get_conn() as conn:
        conn.execute("""
            INSERT INTO crypto_bundle (
                user_id, item_id, capsule, ciphertext, provider_public_key, provider_verifying_key
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (user_id, item_id) DO UPDATE SET
                capsule = EXCLUDED.capsule,
                ciphertext = EXCLUDED.ciphertext,
                provider_public_key = EXCLUDED.provider_public_key,
                provider_verifying_key = EXCLUDED.provider_verifying_key
        """,(
                request.state.user_id,
                body.item_id,
                b64d(body.capsule_b64),
                b64d(body.ciphertext_b64),
                b64d(body.provider_public_key_b64),
                b64d(body.provider_verifying_key_b64),
        ),)
    return _ok()

@app.post("/api/erase_item")
def api_erase_item(request: Request, body: EraseItemRequest):
    user_id = request.state.user_id

    try:
        with get_conn() as conn:
            cur = conn.execute(
                "DELETE FROM crypto_bundle WHERE user_id=%s AND item_id=%s",
                (user_id, body.item_id),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="item_not_found")
            return _ok()

    except psycopg.errors.ForeignKeyViolation:
        with get_conn() as conn:
            rows = conn.execute("""
                SELECT DISTINCT requester_id
                FROM grants
                WHERE provider_id=%s AND provider_item_id=%s
                ORDER BY requester_id
            """,(user_id,body.item_id),
            ).fetchall()
        requesters = [r[0] for r in rows]
        return JSONResponse(
            {"error": "grants_exist", "requester_ids": requesters},
            status_code=409,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/grant_access")
def api_grant_access(request: Request, body: GrantAccessRequest):
    provider_id = request.state.user_id

    try:
        kfrags_bytes = [b64d(b) for b in body.kfrags_b64]
    except Exception:
        raise HTTPException(status_code=400, detail="bad_kfrags_b64")
    kfrags_blob = msgpack.packb(kfrags_bytes, use_bin_type=True)

    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO grants (provider_id, requester_id, provider_item_id, requester_item_id, kfrags_b)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (provider_id, requester_id, requester_item_id)
                DO UPDATE SET
                    provider_item_id = EXCLUDED.provider_item_id,
                    kfrags_b            = EXCLUDED.kfrags_b
            """,(
                provider_id,
                body.requester_id,
                body.provider_item_id,
                body.requester_item_id,
                kfrags_blob,
            ),)
        return _ok()

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="internal_error")

@app.post("/api/revoke_access")
def api_revoke_access(request: Request, body: RevokeAccessRequest):
    provider_id = request.state.user_id

    with get_conn() as conn:
        cur = conn.execute("""
            DELETE FROM grants
            WHERE provider_id=%s AND requester_id=%s AND provider_item_id=%s
        """,
            (provider_id, body.requester_id, body.provider_item_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="grant_not_found")

    return _ok()

@app.post("/api/request_item")
def api_request_item(request: Request, body: RequestItemRequest):
    requester_id = request.state.user_id

    try:
        requester_pk = PublicKey.from_compressed_bytes(b64d(body.requester_public_key_b64))
    except Exception:
        raise HTTPException(status_code=400, detail="bad_requester_public_key")

    with get_conn() as conn:
        grant_row = conn.execute("""
            SELECT provider_item_id, kfrags_b
            FROM grants
            WHERE provider_id=%s
              AND requester_id=%s
              AND requester_item_id=%s
        """,
            (body.provider_id, requester_id, body.requester_item_id),
        ).fetchone()

    if not grant_row:
        raise HTTPException(status_code=404, detail="grant_not_found")

    provider_item_id, kfrags_blob = grant_row
    kfrag_bytes_list = msgpack.unpackb(kfrags_blob, raw=False)
    kfrags: List[KeyFrag] = [KeyFrag.from_bytes(b) for b in kfrag_bytes_list]

    with get_conn() as conn:
        bundle_row = conn.execute("""
            SELECT capsule, ciphertext, provider_public_key, provider_verifying_key
            FROM crypto_bundle
            WHERE user_id=%s AND item_id=%s
        """,
            (body.provider_id, provider_item_id),
        ).fetchone()

    if not bundle_row:
        raise HTTPException(status_code=404, detail="item_not_found")

    capsule_b, ciphertext_b, spk_b, svk_b = bundle_row
    capsule       = Capsule.from_bytes(capsule_b)
    ciphertext    = ciphertext_b
    delegating_pk = PublicKey.from_compressed_bytes(spk_b)
    verifying_pk  = PublicKey.from_compressed_bytes(svk_b)

    verified_kfrags = [
        kf.verify(
            delegating_pk=delegating_pk,
            receiving_pk=requester_pk,
            verifying_pk=verifying_pk,
        )
        for kf in kfrags
    ]
    cfrags = [reencrypt(capsule=capsule, kfrag=vkf) for vkf in verified_kfrags]

    return {
        "capsule_b64": b64e(bytes(capsule)),
        "ciphertext_b64": b64e(ciphertext),
        "cfrags_b64": [b64e(bytes(c)) for c in cfrags],
    }

@app.get("/api/list_my_items")
def api_list_my_items(request: Request):
    user_id = request.state.user_id
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT item_id, capsule, ciphertext
            FROM crypto_bundle
            WHERE user_id=%s
            ORDER BY item_id
            """,
            (user_id,),
        ).fetchall()

    items = [
        {
            "item_id": row[0],
            "capsule_b64": b64e(row[1]).decode("ascii"),
            "ciphertext_b64": b64e(row[2]).decode("ascii"),
        }
        for row in rows
    ]
    return {"items": items}


# =================== Application ===================

if "__main__" == __name__:
    init_db()
    uvicorn.run(
        "proxy:app",
        host=PROXY_HOST,
        port=PROXY_PORT,
        reload=False,
        proxy_headers=True,
        forwarded_allow_ips="172.18.0.0/16",
    )
