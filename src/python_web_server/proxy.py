# language utils
from typing import List, Optional, Union
from pydantic import EmailStr
from uuid import UUID

from base64 import b64encode, b64decode
BytesLike = Union[bytes, bytearray, memoryview]
def _transport_safe_b_string(parcel: BytesLike) -> str:
    if parcel is None:
        raise ValueError("parcel is None")
    return b64encode(parcel).decode("ascii")

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

# web utils
import anyio
import uvicorn
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
    ResolveRequesterItemRequest, RequestItemRequest, DismissGrantRequest,
    UpsertInboxKeyRequest, GetInboxKeyRequest,
    SaveToVaultRequest, SolicitationStatusRequest,
    PushSolicitationRequest, AckSolicitationRequest
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
        conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
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
            CREATE TABLE IF NOT EXISTS user_vault (
                user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                envelope BYTEA NOT NULL
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
        # aliases
        conn.execute("""
            CREATE TABLE IF NOT EXISTS requester_item_aliases (
                provider_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                requester_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                alias_item_id TEXT,
                canonical_item_id TEXT,
                PRIMARY KEY (provider_id, requester_id, alias_item_id),
                FOREIGN KEY (provider_id, requester_id, canonical_item_id) 
                    REFERENCES grants(provider_id, requester_id, requester_item_id)
                    ON DELETE CASCADE
            );
        """)
        # user_inbox_e2ee_keys
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_inbox_e2ee_keys (
                user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                inbox_public_key BYTEA NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """)
        # solicitations
        conn.execute("""
            CREATE TABLE IF NOT EXISTS solicitations (
                request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                requester_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                provider_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                encrypted_payload BYTEA NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """)
        # todo - remove asap
        conn.execute("""
            DROP INDEX CONCURRENTLY IF EXISTS by_provider_and_created;
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS by_pair_and_created_mixed_ordering
            ON solicitations (provider_id ASC, requester_id ASC, created_at DESC, request_id DESC);
        """)
        # todo - remove asap
        conn.execute("""
            DROP INDEX CONCURRENTLY IF EXISTS by_pair_and_created;
        """)
    print("[Proxy] DB initialized.")

# =================== AUTH (email + password) ===================

SERVER_SESSION_TTL_SECONDS = int(os.getenv("SERVER_SESSION_TTL_SECONDS", str(60*5))) # default 5 minutes
assert SERVER_SESSION_TTL_SECONDS >= 300, "Sessions shorter than 5 min, are impractical."

# The server session has to survive both cookie and client, while the cookie has to survive the client too.
COOKIE_SESSION_TTL_SECONDS = int(0.9 * SERVER_SESSION_TTL_SECONDS)
CLIENT_SESSION_TTL_SECONDS = int(0.8 * SERVER_SESSION_TTL_SECONDS)

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
        max_age=COOKIE_SESSION_TTL_SECONDS,
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
    expires_at = now_utc() + timedelta(seconds=SERVER_SESSION_TTL_SECONDS)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE user_id = %s FOR UPDATE", (user_id,))

            cur.execute(
                "DELETE FROM sessions WHERE user_id = %s AND expires_at <= now()",
                (user_id,)
            )


            cur.execute(
                "SELECT token FROM sessions WHERE user_id = %s LIMIT 1",
                (user_id,)
            )
            row = cur.fetchone()
            if row:
                raise HTTPException(
                    status_code=409,
                    detail="Another active session exists for this account."
                )

            cur.execute(
                """
                INSERT INTO sessions (user_id, token, expires_at)
                VALUES (%s, %s, %s)
                """,
                (user_id, token, expires_at)
            )

    return token

def refresh_session_expiry(request: Request, response: Response) -> None:
    cookies = request.cookies or {}
    token = cookies.get("__Host-session")
    if not token:
        return

    new_exp = now_utc() + timedelta(seconds=SERVER_SESSION_TTL_SECONDS)
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE sessions SET expires_at=%s WHERE token=%s",
            (new_exp, token),
        )
        if cur.rowcount == 0:
            return

    set_session_cookie(response, request, token)

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
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "consently.eu",
        "www.consently.eu",
        "consently.online",
        "www.consently.online",
        "ownlyfacts.com",
        "www.ownlyfacts.com",
    ],
)

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

    # auth Backend always available
    if path.startswith("/auth/"):
        return await call_next(request)

    user_id = await user_id_by_session(request)
    logged_in = bool(user_id)

    # API always exposed but only available in session
    if path.startswith("/api/"):
        if not logged_in:
            return JSONResponse({"error": "not_authenticated"}, status_code=401)
        request.state.user_id = user_id
        response = await call_next(request)
        refresh_session_expiry(request, response)
        return response

    # default to login page or dashboard depending on session or nah
    if path == "/":
        if not logged_in:
            return RedirectResponse(LOGIN_PAGE, status_code=303)
        return RedirectResponse(DASHBOARD_PAGE, status_code=303)

    # serve login or skip if already in session
    if path in PRE_LOGIN_PATHS:
        if path == LOGIN_PAGE and logged_in:
            return RedirectResponse(DASHBOARD_PAGE, status_code=303)

        response = await call_next(request)

        if path == LOGIN_PAGE:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response

    # not serving anything web without login
    if not logged_in:
        if request.method in ("GET", "HEAD"):
            return RedirectResponse(LOGIN_PAGE, status_code=303)
        return JSONResponse({"error": "not_authenticated"}, status_code=401)

    response = await call_next(request)
    return response

# =================== CRS API ===================

# ------------------- authentication ---------------------

@app.post("/auth/register")
def auth_register(req: Request, body: LoginRequest):
    existing = get_session_user_by_request(req)
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="An active session already exists in this browser. Please log out before creating a new account."
        )

    user_id = create_user(body.email, body.password)
    token = create_session(user_id, req)
    resp = _ok({"ok": True})
    set_session_cookie(resp, req, token)
    return resp

DUMMY_HASH = ph.hash("€0nStDumrnyPW-15")

@app.post("/auth/login")
def auth_login(req: Request, body: LoginRequest):
    existing = get_session_user_by_request(req)
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="An active session already exists in this browser. Please log out before logging in again."
        )

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
            conn.execute(
                "UPDATE users SET password_hash=%s WHERE user_id=%s",
                (new_hash, user_entry["user_id"])
            )

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

@app.post("/api/refresh_session_ttl")
def api_refresh_session_ttl(req: Request):
    return {"ttl_seconds": CLIENT_SESSION_TTL_SECONDS}

# ------------------- user vaults ---------------------

MAX_VAULT_BYTES = int(os.getenv("MAX_VAULT_BYTES", str(3 * 1024 * 1024)))  # 3 MiB default

@app.put("/api/save_to_vault")
def api_save_to_vault(request: Request, body: SaveToVaultRequest):
    user_id = request.state.user_id
    try:
        envelope = b64decode(body.envelope_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="bad_base64")

    if len(envelope) > MAX_VAULT_BYTES:
        return JSONResponse(
            {"error": "envelope_too_large", "max_bytes": MAX_VAULT_BYTES},
            status_code=413,
        )

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO user_vault (user_id, envelope)
            VALUES (%s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                envelope = EXCLUDED.envelope
            """,
            (user_id, envelope),
        )
    return _ok()

@app.get("/api/load_from_vault")
def api_load_from_vault(request: Request):
    user_id = request.state.user_id
    with get_conn() as conn:
        row = conn.execute(
            "SELECT envelope FROM user_vault WHERE user_id=%s",
            (user_id,),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="vault_not_found")

    envelope = row[0]
    return { "envelope_b64": _transport_safe_b_string(envelope) }

# ------------------- post office ---------------------

@app.post("/api/upsert_inbox_public_key")
def api_upsert_inbox_public_key(request: Request, body: UpsertInboxKeyRequest):
    user_id = request.state.user_id
    try:
        pk = b64decode(body.inbox_public_key_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="bad_base64")

    if len(pk) > 512:
        raise HTTPException(status_code=400, detail="public_key_too_large")

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO user_inbox_keys (user_id, inbox_public_key)
            VALUES (%s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                inbox_public_key = EXCLUDED.inbox_public_key,
                updated_at = now()
            """,
            (user_id, pk),
        )
    return _ok()

# in common models:
# class GetInboxKeyRequest(BaseModel):
#     provider_email: EmailStr

@app.post("/api/get_inbox_public_key")
def api_get_inbox_public_key(request: Request, body: GetInboxKeyRequest):
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT u.user_id, k.inbox_public_key
            FROM users u
            JOIN user_inbox_keys k ON k.user_id = u.user_id
            WHERE u.email = %s
            """,
            (body.provider_email,),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="inbox_key_not_found")

    _, pk = row
    return {"inbox_public_key_b64": _transport_safe_b_string(pk)}

MAX_SOLICITATION_BYTES = int(os.getenv("MAX_SOLICITATION_BYTES", str(3 * 1024 * 1024)))  # 3 MiB default

@app.put("/api/push_solicitation")
def api_push_solicitation(request: Request, body: PushSolicitationRequest):
    requester_id = request.state.user_id

    try:
        encrypted_payload = b64decode(body.encrypted_payload_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="bad_base64")

    if len(encrypted_payload) > MAX_SOLICITATION_BYTES:
        return JSONResponse(
            {"error": "encrypted_payload_too_large", "max_bytes": MAX_SOLICITATION_BYTES},
            status_code=413,
        )

    with get_conn() as conn:
        row = conn.execute(
            "SELECT user_id FROM users WHERE email=%s",
            (body.provider_email,),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="provider_not_found")

        provider_id = row[0]

        if requester_id == provider_id:
            raise HTTPException(status_code=400, detail="self_request_forbidden")

        cur = conn.execute(
            """
            INSERT INTO solicitations (requester_id, provider_id, encrypted_payload)
            VALUES (%s, %s, %s)
            RETURNING request_id, created_at
            """,
            (requester_id, provider_id, encrypted_payload),
        )
        request_id, _ = cur.fetchone()

    return {"request_id": str(request_id)}

@app.post("/api/pull_solicitation_bundle")
def api_pull_solicitation_bundle(request: Request):
    provider_id = request.state.user_id

    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT s.request_id, s.requester_id, u.email, s.encrypted_payload, s.created_at
            FROM solicitations s
            JOIN users u ON u.user_id = s.requester_id
            WHERE s.provider_id = %s
            ORDER BY s.requester_id ASC, s.created_at DESC, s.request_id DESC
            LIMIT 20
            """,
            (provider_id,),
        ).fetchall()

    if not rows:
        return {
            "has_any": False,
            "count": 0,
            "solicitations": [],
        }

    out = []
    for request_id, requester_id, requester_email, encrypted_payload, created_at in rows:
        out.append({
            "request_id": str(request_id),
            "requester_email": requester_email,
            "encrypted_payload_b64": _transport_safe_b_string(encrypted_payload),
            "created_at": created_at.isoformat(),
        })

    return {
        "has_any": True,
        "count": len(out),
        "solicitations": out,
    }

@app.post("/api/ack_solicitation")
def api_ack_solicitation(request: Request, body: AckSolicitationRequest):
    provider_id = request.state.user_id
    with get_conn() as conn:
        conn.execute(
            """
            DELETE FROM solicitations
            WHERE provider_id=%s AND request_id=%s
            """,
            (provider_id, body.request_id),
        )
    return _ok({"deleted": str(body.request_id)})

@app.post("/api/solicitation_status")
def api_solicitation_status(request: Request, body: SolicitationStatusRequest):
    requester_id = request.state.user_id

    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM solicitations
            WHERE request_id = %s
              AND requester_id = %s
            """,
            (body.request_id, requester_id),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="not_found")

    return {"pending": True}

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
                b64decode(body.capsule_b64),
                b64decode(body.ciphertext_b64),
                b64decode(body.provider_public_key_b64),
                b64decode(body.provider_verifying_key_b64),
        ),)
    return _ok()

@app.post("/api/erase_item")
def api_erase_item(request: Request, body: EraseItemRequest):
    user_id = request.state.user_id

    try:
        with get_conn() as conn:
            rows = conn.execute(
                """
                SELECT provider_id, requester_id, provider_item_id, requester_item_id
                FROM grants
                WHERE provider_id = %s AND provider_item_id = %s
                ORDER BY requester_id, requester_item_id
                """,
                (user_id, body.item_id),
            ).fetchall()

            if rows:
                grants = [
                    {
                        "provider_id": str(r[0]),
                        "requester_id": str(r[1]),
                        "provider_item_id": r[2],
                        "requester_item_id": r[3],
                    }
                    for r in rows
                ]
                return JSONResponse(
                    {"error": "grants_exist", "grants": grants},
                    status_code=409,
                )

            cur = conn.execute(
                "DELETE FROM crypto_bundle WHERE user_id=%s AND item_id=%s",
                (user_id, body.item_id),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="item_not_found")

            return _ok()

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="internal_error")

@app.post("/api/grant_access")
def api_grant_access(request: Request, body: GrantAccessRequest):
    provider_id = request.state.user_id

    try:
        with get_conn() as conn:
            cur = conn.execute(
                """
                SELECT requester_item_id
                FROM grants
                WHERE provider_id = %s
                  AND requester_id = %s
                  AND provider_item_id = %s
                """,
                (provider_id, body.requester_id, body.provider_item_id),
            )
            row = cur.fetchone()

            if row is not None:
                # Existing canonical grant for this provider_item_id
                canonical_requester_item_id = row[0]
                if canonical_requester_item_id != body.requester_item_id:
                    conn.execute(
                        """
                        INSERT INTO requester_item_aliases (
                            provider_id,
                            requester_id,
                            alias_item_id,
                            canonical_item_id)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (provider_id, requester_id, alias_item_id) DO NOTHING
                        """,
                        (
                            provider_id,
                            body.requester_id,
                            body.requester_item_id,
                            canonical_requester_item_id,
                        ),
                    )
            else:
                # New grant for this provider_item_id: create a new canonical grant row.
                try:
                    kfrags_bytes = [b64decode(b) for b in body.kfrags_b64]
                except Exception:
                    raise HTTPException(status_code=400, detail="bad_kfrags_b64")
                kfrags_blob = msgpack.packb(kfrags_bytes, use_bin_type=True)

                conn.execute(
                    """
                    INSERT INTO grants (provider_id, requester_id, provider_item_id, requester_item_id, kfrags_b)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (provider_id, requester_id, requester_item_id)
                    DO UPDATE SET
                        provider_item_id = EXCLUDED.provider_item_id,
                        kfrags_b = EXCLUDED.kfrags_b
                    """,
                    (
                        provider_id,
                        body.requester_id,
                        body.provider_item_id,
                        body.requester_item_id,
                        kfrags_blob,
                    ),
                )
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

@app.post("/api/resolve_requester_item_id")
def api_resolve_requester_item_id(request: Request, body: ResolveRequesterItemRequest):
    requester_id = request.state.user_id

    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT canonical_item_id
            FROM requester_item_aliases
            WHERE provider_id = %s
              AND requester_id = %s
              AND alias_item_id = %s
            """,
            (body.provider_id, requester_id, body.requester_item_id),
        ).fetchone()

    if not row:
        return {
            "is_alias": False,
            "canonical_requester_item_id": body.requester_item_id,
        }

    canonical_item_id = row[0]
    return {
        "is_alias": True,
        "canonical_requester_item_id": canonical_item_id,
    }

@app.post("/api/request_item")
def api_request_item(request: Request, body: RequestItemRequest):
    requester_id = request.state.user_id

    try:
        requester_pk = PublicKey.from_compressed_bytes(
            b64decode(body.requester_public_key_b64)
        )
    except Exception:
        raise HTTPException(status_code=400, detail="bad_requester_public_key")

    with get_conn() as conn:
        grant_row = conn.execute(
            """
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
        bundle_row = conn.execute(
            """
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
        "requester_item_id": body.requester_item_id,
        "provider_item_id": provider_item_id,
        "capsule_b64": _transport_safe_b_string(bytes(capsule)),
        "ciphertext_b64": _transport_safe_b_string(ciphertext),
        "cfrags_b64": [_transport_safe_b_string(bytes(c)) for c in cfrags],
        "delegating_pk_b64": _transport_safe_b_string(spk_b),
        "verifying_pk_b64": _transport_safe_b_string(svk_b),
    }

@app.post("/api/dismiss_grant")
def api_dismiss_grant(request: Request, body: DismissGrantRequest):
    requester_id = request.state.user_id

    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT canonical_item_id
            FROM requester_item_aliases
            WHERE provider_id = %s
              AND requester_id = %s
              AND alias_item_id = %s
            """,
            (body.provider_id, requester_id, body.requester_item_id),
        ).fetchone()

        effective_requester_item_id = row[0] if row else body.requester_item_id

        cur = conn.execute(
            """
            DELETE FROM grants
            WHERE provider_id = %s
              AND requester_id = %s
              AND requester_item_id = %s
            """,
            (body.provider_id, requester_id, effective_requester_item_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="grant_not_found")

    return _ok()

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
            "capsule_b64": _transport_safe_b_string(row[1]),
            "ciphertext_b64": _transport_safe_b_string(row[2]),
        }
        for row in rows
    ]
    return {"items": items}

@app.get("/api/list_my_grants")
def api_list_my_grants(request: Request):
    provider_id = request.state.user_id

    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT requester_id, provider_item_id, requester_item_id
            FROM grants
            WHERE provider_id = %s
            ORDER BY provider_item_id, requester_id, requester_item_id
            """,
            (provider_id,),
        ).fetchall()

    grants = [
        {
            "requester_id": str(row[0]),
            "provider_item_id": row[1],
            "requester_item_id": row[2],
        }
        for row in rows
    ]

    return {"grants": grants}

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
