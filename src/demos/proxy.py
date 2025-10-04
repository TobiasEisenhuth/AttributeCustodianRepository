# proxy.py
import os
import socket
import threading
import msgpack
import psycopg
from umbral import Capsule, KeyFrag, reencrypt
from umbral.keys import PublicKey
from protocol import *

PROXY_ID = "ursula"

# ---- DB config (env-overridable) ----
DB_HOST = os.getenv("PGHOST", "localhost")
DB_PORT = int(os.getenv("PGPORT", "5432"))
DB_USER = os.getenv("PGUSER", "postgres")
DB_PASS = os.getenv("PGPASSWORD", "abc123")
DB_NAME = os.getenv("PGDATABASE", "postgres")

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
    print("[Proxy] DB initialized.")

# ---------- Persistence helpers (2 tables; flattened kfrags via MsgPack) ----------

def upsert_secret(payload: dict) -> None:
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

def load_grant_kfrags(sender_id: str, receiver_id: str, secret_id: str) -> list[KeyFrag]:
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

# ---------- Network handlers (wire protocol unchanged) ----------

def handle_client(conn, addr):
    try:
        data = recv_msg(conn)
        if not data:
            return
        msg = decode_msg(data)
        action = msg["action"]
        payload = msg["payload"]

        if action == ADD_OR_UPDATE_SECRET:
            handle_secret(payload)
        elif action == DELETE_SECRET:
            handle_delete_secret(payload)
        elif action == GRANT_ACCESS_PROXY:
            handle_grant_access(payload)
        elif action == REVOKE_ACCESS:
            handle_revoke_access(payload)
        elif action == REQUEST_SECRET:
            handle_request_secret(payload, conn)
        else:
            print(f"[Proxy] Unknown action: {action}")
    except Exception as e:
        try:
            send_msg(conn, make_error(f"Proxy error: {e}"))
        except Exception:
            pass
        print(f"[Proxy] Error: {e}")
    finally:
        conn.close()

def handle_secret(payload):
    upsert_secret(payload)
    print(f"[Proxy] Stored secret '{payload['secret_id']}' from '{payload['sender_id']}'.")

def handle_delete_secret(payload):
    delete_secret(payload["sender_id"], payload["secret_id"])
    print(f"[Proxy] Deleted secret '{payload['secret_id']}' from '{payload['sender_id']}'.")

def handle_grant_access(payload):
    sender_id   = payload["sender_id"]
    receiver_id = payload["receiver_id"]
    secret_id   = payload["secret_id"]
    # payload["kfrags"] is list[bytes]; keep as-is and flatten for storage
    insert_or_replace_grant(sender_id, receiver_id, secret_id, payload["kfrags"])
    print(f"[Proxy] Stored GRANT_ACCESS: {receiver_id} -> {secret_id} ({sender_id})")

def handle_revoke_access(payload):
    revoke_grant(payload["sender_id"], payload["receiver_id"], payload["secret_id"])
    print(f"[Proxy] Revoked access: {payload['receiver_id']} -> {payload['secret_id']} ({payload['sender_id']})")

def handle_request_secret(payload, conn):
    receiver_id = payload["receiver_id"]
    sender_id   = payload["sender_id"]
    secret_id   = payload["secret_id"]
    receiver_public_key_bytes = payload["receiver_public_key"]

    secret = load_secret(sender_id, secret_id)
    if not secret:
        send_msg(conn, make_error(f"Unknown secret '{secret_id}'"))
        return

    kfrags = load_grant_kfrags(sender_id, receiver_id, secret_id)
    if not kfrags:
        send_msg(conn, make_error(f"No grant for {receiver_id} -> {secret_id}"))
        return

    capsule       = secret["capsule"]
    ciphertext    = secret["ciphertext"]
    delegating_pk = secret["sender_public_key"]
    verifying_pk  = secret["sender_verifying_key"]
    receiving_pk  = PublicKey.from_bytes(receiver_public_key_bytes)

    try:
        verified_kfrags = [
            kf.verify(delegating_pk=delegating_pk,
                      receiving_pk=receiving_pk,
                      verifying_pk=verifying_pk)
            for kf in kfrags
        ]
    except Exception as e:
        send_msg(conn, make_error(f"Failed to verify the kfrag signature: {e}"))
        return

    cfrags = [ reencrypt(capsule=capsule, kfrag=vkf) for vkf in verified_kfrags ]

    response = {
        "capsule": bytes(capsule),
        "ciphertext": ciphertext,
        "cfrags": [bytes(c) for c in cfrags]
    }
    send_msg(conn, encode_msg(RESPONSE_SECRET, response))
    print(f"[Proxy] Served secret '{secret_id}' for '{receiver_id}' from '{sender_id}'.")

def run_server():
    init_db()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('0.0.0.0', PROXY_PORT))
        server_sock.listen()
        print(f"[Proxy] Listening on {PROXY_HOST}:{PROXY_PORT}...")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    run_server()
