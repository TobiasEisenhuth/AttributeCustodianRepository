# language utils
from typing import List, Optional, Dict, Any
from pydantic import EmailStr
from uuid import UUID

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
    b64d, b64e,
    LoginRequest,
    UpsertItemRequest, EraseItemRequest,
    GrantAccessRequest, RevokeAccessRequest,
    RequestItemRequest,
    SaveToVaultRequest, LoadFromVaultRequest,
    PushSolicitationRequest, PullSolicitationRequest, AckSolicitationRequest
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
        conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
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
        # user's encrypted store
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                blob BYTEA NOT NULL
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
                request_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                requester_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                provider_id  UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                payload JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                UNIQUE (requester_id, provider_id)
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS by_created_at
            ON solicitations (provider_id, created_at, request_id);
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
    resp.delete_cookie("__Host-session", path="/")

# =================== AUTH DB HELPERS ===================

def create_user(email: LoginRequest.email, password: LoginRequest.password) -> UUID:
    pw_hash = ph.hash(password)
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email=%s", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="Email already registered")
        cursor = conn.execute("""
            INSERT INTO users (email, password_hash)
            VALUES (%s, %s)
            RETURNING user_id
        """, (email, pw_hash))
        (user_id,) = cursor.fetchone()
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
    yield

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
    "/app/auth.js",
    "/app/favicon.ico",
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

@app.get("/auth/session")
def auth_session(req: Request):
    user = get_session_user_by_request(req)
    if not user:
        raise HTTPException(status_code=401, detail="No active session")
    return {
        "user": {
            "email": user["email"]
        }
    }

# ------------------- user vaults ---------------------

@app.put("/api/save_to_vault")
def api_save_to_vault(request: Request, body: SaveToVaultRequest):
    user_id = request.state.user_id
    try:
        blob = b64d(body.blob_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="bad_blob_b64")

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO vault (user_id, blob)
            VALUES (%s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                blob = EXCLUDED.blob
            """,
            (user_id, blob),
        )
    return _ok()

@app.get("/api/load_from_vault")
def api_load_from_vault(request: Request, body: LoadFromVaultRequest):
    user_id = request.state.user_id
    with get_conn() as conn:
        row = conn.execute(
            "SELECT blob FROM vault WHERE user_id=%s",
            (user_id,),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="vault_not_found")

    (blob,) = row
    return {"blob_b64": b64e(blob)}

# ------------------- post office ---------------------

def _validate_solicitation_payload(payload: Dict[str, Any]) -> None:
    # Expected minimal shape:
    # {
    #   "rows": [
    #     {
    #       "field_description": str,
    #       "secret_id": str,
    #       "value_example_format": str,
    #       "requester_public_key_b64": str,
    #       "default_field_id": str (optional),
    #       "field_order": int (optional)
    #     },
    #     ...
    #   ]
    # }
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
        # optional fields
        if "default_field_id" in r and not isinstance(r["default_field_id"], str):
            raise HTTPException(status_code=400, detail="bad_default_field_id")
        if "field_order" in r and not isinstance(r["field_order"], int):
            raise HTTPException(status_code=400, detail="bad_field_order")
        # sanity check pubkey b64 (opaque to server beyond base64 parse)
        try:
            b64d(r["requester_public_key_b64"])
        except Exception:
            raise HTTPException(status_code=400, detail="bad_public_key_b64")


# ---- endpoints ----

@app.post("/api/push_solicitation")
def api_push_solicitation(request: Request, body: PushSolicitationRequest):
    requester_id = request.state.user_id

    if requester_id == body.provider_id:
        raise HTTPException(status_code=400, detail="self_request_forbidden")

    # minimal shape validation (keeps server flexible but avoids garbage)
    _validate_solicitation_payload(body.payload)

    # compact JSON and cast to jsonb
    payload_json = json.dumps(body.payload, separators=(",", ":"))

    with get_conn() as conn:
        try:
            if body.request_id:
                cur = conn.execute(
                    """
                    INSERT INTO solicitations (request_id, requester_id, provider_id, payload)
                    VALUES (%s, %s, %s, %s::jsonb)
                    RETURNING request_id, created_at
                    """,
                    (body.request_id, requester_id, body.provider_id, payload_json),
                )
            else:
                cur = conn.execute(
                    """
                    INSERT INTO solicitations (requester_id, provider_id, payload)
                    VALUES (%s, %s, %s::jsonb)
                    RETURNING request_id, created_at
                    """,
                    (requester_id, body.provider_id, payload_json),
                )
            request_id, created_at = cur.fetchone()
        except psycopg.errors.UniqueViolation:
            # enforced by UNIQUE (requester_id, provider_id)
            raise HTTPException(status_code=409, detail="prev_unacked")

    # server ack to requester: stored successfully
    return {
        "request_id": str(request_id),
        "created_at": created_at.isoformat(),
    }


@app.post("/api/pull_solicitation")
def api_pull_solicitation(request: Request, body: PullSolicitationRequest):
    provider_id = request.state.user_id

    # fetch 2 to compute has_more without a second round trip
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT request_id, requester_id, payload
            FROM solicitations
            WHERE provider_id=%s
            ORDER BY created_at ASC, request_id ASC
            LIMIT 2
            """,
            (provider_id,),
        ).fetchall()

    if not rows:
        return {"has_request": False, "has_more": False}

    (request_id, requester_id, payload), *rest = rows
    has_more = bool(rest)

    # psycopg3 returns JSONB as dict by default; if not, ensure it is
    if isinstance(payload, str):
        payload = json.loads(payload)

    return {
        "has_request": True,
        "request_id": str(request_id),
        "requester_id": str(requester_id),
        "payload": payload,   # opaque JSON your clients understand
        "has_more": has_more,
    }


@app.post("/api/ack_solicitation")
def api_ack_solicitation(request: Request, body: AckSolicitationRequest):
    provider_id = request.state.user_id

    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM solicitations WHERE request_id=%s AND provider_id=%s",
            (body.request_id, provider_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="solicitation_not_found")

    return _ok()

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
            cursor = conn.execute(
                "DELETE FROM crypto_bundle WHERE user_id=%s AND item_id=%s",
                (user_id, body.item_id),
            )
            if cursor.rowcount == 0:
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
