# proxy.py
import os
import sys
import msgpack
import psycopg
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from umbral import Capsule, KeyFrag, reencrypt
from umbral.keys import PublicKey
from typing import List, Dict, Any
import uvicorn
from protocol import (
    b64d, b64e,
    ADD_OR_UPDATE_SECRET, DELETE_SECRET, GRANT_ACCESS_PROXY, GRANT_ACCESS_RECEIVER,
    REVOKE_ACCESS, REQUEST_SECRET, LIST_GRANTS, GRANTS_SUMMARY, REQUEST_ACCESS,
    PULL_INBOX_SENDER, PULL_INBOX_RECEIVER, INBOX_CONTENTS,
)

PROXY_HOST = os.getenv("PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.getenv("PROXY_PORT", "6000"))

PROXY_ID = "ursula"

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

def init_db():
    with get_conn() as conn:
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
        # inbox tables for routing by ID
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
    print("[Proxy] DB initialized.")

# ---------- Persistence helpers ----------
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
            payload["capsule"],                 # bytes
            payload["ciphertext"],              # bytes
            payload["sender_public_key"],       # bytes
            payload["sender_verifying_key"],    # bytes
        ))

def delete_secret(sender_id: str, secret_id: str) -> None:
    with get_conn() as conn:
        # delete secret and any grants for that secret (no FK; explicit cleanup)
        conn.execute("DELETE FROM secrets WHERE sender_id=%s AND secret_id=%s", (sender_id, secret_id))
        conn.execute("DELETE FROM grants  WHERE sender_id=%s AND secret_id=%s", (sender_id, secret_id))

def insert_or_replace_grant(sender_id: str, receiver_id: str, secret_id: str, kfrags_bytes_list: list[bytes]) -> None:
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
        conn.execute("""
            DELETE FROM grants WHERE sender_id=%s AND receiver_id=%s AND secret_id=%s
        """, (sender_id, receiver_id, secret_id))

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
        "sender_public_key": PublicKey.from_bytes(spk_b),
        "sender_verifying_key": PublicKey.from_bytes(svk_b),
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
    """Return {by_secret: {secret_id: [receiver_id, ...]}, totals:{...}}"""
    by_secret: Dict[str, List[str]] = {}
    total_grants = 0
    with get_conn() as conn:
        # gather all secrets for sender (even without grants)
        secrets = [r[0] for r in conn.execute(
            "SELECT secret_id FROM secrets WHERE sender_id=%s", (sender_id,)
        ).fetchall()]
        for sec in secrets:
            by_secret.setdefault(sec, [])
        # gather all grants
        rows = conn.execute(
            "SELECT secret_id, receiver_id FROM grants WHERE sender_id=%s ORDER BY secret_id, receiver_id",
            (sender_id,)
        ).fetchall()
    for sec_id, recv_id in rows:
        by_secret.setdefault(sec_id, []).append(recv_id)
        total_grants += 1
    return {
        "by_secret": by_secret,
        "totals": {"secrets": len(by_secret), "grants": total_grants}
    }

# ---------- inbox helpers ----------

def enqueue_for_sender(sender_id: str, action: str, payload: dict) -> None:
    blob = msgpack.packb({"action": action, "payload": payload}, use_bin_type=True)
    with get_conn() as conn:
        conn.execute("INSERT INTO sender_inbox (sender_id, msg_blob) VALUES (%s, %s)", (sender_id, blob))

def enqueue_for_receiver(receiver_id: str, action: str, payload: dict) -> None:
    blob = msgpack.packb({"action": action, "payload": payload}, use_bin_type=True)
    with get_conn() as conn:
        conn.execute("INSERT INTO receiver_inbox (receiver_id, msg_blob) VALUES (%s, %s)", (receiver_id, blob))

def pull_sender_inbox(sender_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT msg_blob FROM sender_inbox WHERE sender_id=%s ORDER BY created_at ASC",
            (sender_id,)
        ).fetchall()
        conn.execute("DELETE FROM sender_inbox WHERE sender_id=%s", (sender_id,))
    return [msgpack.unpackb(r[0], raw=False) for r in rows]

def pull_receiver_inbox(receiver_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT msg_blob FROM receiver_inbox WHERE receiver_id=%s ORDER BY created_at ASC",
            (receiver_id,)
        ).fetchall()
        conn.execute("DELETE FROM receiver_inbox WHERE receiver_id=%s", (receiver_id,))
    return [msgpack.unpackb(r[0], raw=False) for r in rows]

# ---------- FastAPI app ----------
app = FastAPI(title="CRS Proxy API")

def _ok(payload: dict = None) -> JSONResponse:
    return JSONResponse(payload or {"ok": True})

@app.on_event("startup")
def _startup():
    init_db()

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
        # passthrough to receiver inbox; body must be JSON-serializable and use *_b64 for bytes
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
        receiving_pk  = PublicKey.from_bytes(b64d(body["receiver_public_key_b64"]))

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
            kf.verify(delegating_pk=delegating_pk,
                      receiving_pk=receiving_pk,
                      verifying_pk=verifying_pk)
            for kf in kfrags
        ]
        cfrags = [reencrypt(capsule=capsule, kfrag=vkf) for vkf in verified_kfrags]

        return {
            "action": "RESPONSE_SECRET",
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
        # body already has receiver_public_key_b64
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

if __name__ == "__main__":
    init_db()
    uvicorn.run("proxy:app", host=PROXY_HOST, port=PROXY_PORT, reload=False)
