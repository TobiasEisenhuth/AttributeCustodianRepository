import os
import socket
import threading
import queue
import msgpack
from umbral import SecretKey, Signer, encrypt, generate_kfrags
from umbral.keys import PublicKey
from protocol import *

SENDER_ID = "alice"

# ===== Persistence config =====
SENDER_STORE_FILE = os.getenv("SENDER_STORE_FILE", "sender_store.msgpack")
SENDER_STORE_PASS = os.getenv("SENDER_STORE_PASS")  # optional passphrase (AES-GCM if 'cryptography' is installed)
MAGIC_PLAIN = b"ACSP"  # Alice store plain
MAGIC_ENC   = b"ACSE"  # Alice store encrypted

# State
key_store: dict = {}                         # secret_id -> keys
access_requests_q: "queue.Queue[dict]" = queue.Queue()  # FIFO of pending REQUEST_ACCESS

# ===== Persistence (serialize keys only; signer is reconstructed) =====
def _serialize_sender_store(ks: dict) -> dict:
    out = {}
    for sid, rec in ks.items():
        out[sid] = {
            "secret_key": bytes(rec["secret_key"]),
            "public_key": bytes(rec["public_key"]),
            "signing_key": bytes(rec["signing_key"]),
            "verifying_key": bytes(rec["verifying_key"]),
        }
    return out

def _deserialize_sender_store(obj: dict) -> dict:
    ks = {}
    for sid, rec in (obj or {}).items():
        sk  = SecretKey.from_bytes(rec["secret_key"])
        pk  = PublicKey.from_bytes(rec["public_key"])
        ssk = SecretKey.from_bytes(rec["signing_key"])
        vpk = PublicKey.from_bytes(rec["verifying_key"])
        ks[sid] = {
            "secret_key":    sk,
            "public_key":    pk,
            "signing_key":   ssk,
            "verifying_key": vpk,
            "signer":        Signer(ssk),
        }
    return ks

def save_state():
    try:
        save_store(SENDER_STORE_FILE, _serialize_sender_store(key_store), SENDER_STORE_PASS, MAGIC_PLAIN, MAGIC_ENC)
    except Exception as e:
        print(f"[Sender] Warning: failed to save store: {e}")

def load_state():
    global key_store
    try:
        obj = load_store(SENDER_STORE_FILE, SENDER_STORE_PASS, MAGIC_PLAIN, MAGIC_ENC)
        if obj is not None:
            key_store = _deserialize_sender_store(obj)
            print(f"[Sender] Loaded {len(key_store)} secrets from store.")
    except Exception as e:
        print(f"[Sender] Warning: failed to load store: {e}")

# ===== Crypto key mgmt =====
def key_gen(secret_id: str):
    if secret_id not in key_store:
        secret_key = SecretKey.random()
        public_key = secret_key.public_key()
        signing_key = SecretKey.random()
        verifying_key = signing_key.public_key()
        signer = Signer(signing_key)
        key_store[secret_id] = {
            "secret_key":     secret_key,
            "public_key":     public_key,
            "signing_key":    signing_key,
            "verifying_key":  verifying_key,
            "signer":         signer
        }
        save_state()
    return key_store[secret_id]["public_key"]

def add_or_update_secret(secret_id: str, secret_value: str):
    public_key = key_gen(secret_id)
    capsule, ciphertext = encrypt(public_key, secret_value.encode("utf-8"))
    payload = {
        "sender_id": SENDER_ID,
        "secret_id": secret_id,
        "capsule": bytes(capsule),
        "ciphertext": ciphertext,
        "sender_public_key":    bytes(key_store[secret_id]["public_key"]),
        "sender_verifying_key": bytes(key_store[secret_id]["verifying_key"]),
    }
    outbox.send(PROXY_HOST, PROXY_PORT, encode_msg(ADD_OR_UPDATE_SECRET, payload), expect_reply=False)
    print(f"[Sender] Secret '{secret_id}' sent to Proxy.")

def delete_secret(secret_id: str):
    payload = {"sender_id": SENDER_ID, "secret_id": secret_id}
    outbox.send(PROXY_HOST, PROXY_PORT, encode_msg(DELETE_SECRET, payload), expect_reply=False)
    if key_store.pop(secret_id, None) is not None:
        save_state()
    print(f"[Sender] Requested delete for '{secret_id}'.")

def revoke_access(receiver_id: str, secret_id: str):
    payload = {"sender_id": SENDER_ID, "receiver_id": receiver_id, "secret_id": secret_id}
    outbox.send(PROXY_HOST, PROXY_PORT, encode_msg(REVOKE_ACCESS, payload), expect_reply=False)
    print(f"[Sender] Requested revoke: {receiver_id} -> {secret_id}")

def _grant(receiver_id: str, secret_id: str, recv_pk_b: bytes):
    # Generate & ship kfrags to proxy; notify receiver
    kfrags = generate_kfrags(
        delegating_sk=key_store[secret_id]["secret_key"],
        receiving_pk=PublicKey.from_bytes(recv_pk_b),
        signer=key_store[secret_id]["signer"],
        threshold=1,
        shares=1
    )
    # Notify Bob (fire-and-forget)
    ack_payload = {
        "sender_id": SENDER_ID,
        "secret_id": secret_id,
        "public_key":    bytes(key_store[secret_id]["public_key"]),
        "verifying_key": bytes(key_store[secret_id]["verifying_key"])
    }
    outbox.send(RECEIVER_HOST, RECEIVER_PORT, encode_msg(GRANT_ACCESS_RECEIVER, ack_payload), expect_reply=False)
    # Send to proxy
    payload_proxy = {
        "sender_id": SENDER_ID,
        "receiver_id": receiver_id,
        "secret_id": secret_id,
        "kfrags": [bytes(k) for k in kfrags]
    }
    outbox.send(PROXY_HOST, PROXY_PORT, encode_msg(GRANT_ACCESS_PROXY, payload_proxy), expect_reply=False)
    print(f"[Sender] Granted '{secret_id}' to '{receiver_id}' via Proxy.")

# ===== Server (inbound) =====
def handle_client(conn, addr):
    try:
        data = recv_msg(conn)
        if not data:
            return
        msg = decode_msg(data)
        if msg["action"] == REQUEST_ACCESS:
            req = msg["payload"]  # {receiver_id, secret_id, receiver_public_key}
            access_requests_q.put(req)  # fire-and-forget (no reply)
            print(f"[Sender] Queued access request from {req['receiver_id']} for '{req['secret_id']}'.")
        else:
            print(f"[Sender] Unknown action: {msg['action']}")
    finally:
        conn.close()

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('0.0.0.0', SENDER_PORT))
        server_sock.listen()
        print(f"[Sender] Listening on {SENDER_PORT}...")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# ===== CLI =====
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def menu_loop():
    while True:
        clear()
        print("=== Alice (Sender) ===")
        print("Secrets:", ", ".join(key_store.keys()) or "(none)")
        print(f"Pending access requests: {access_requests_q.qsize()}")
        print()
        print("1) Add/Update secret")
        print("2) Delete secret")
        print("3) Process pending access requests (Y/n per request)")
        print("4) Revoke access (receiver_id, secret_id)")
        print("5) Quit")
        choice = input("> ").strip()

        if choice == "1":
            sid = input("secret_id: ").strip()
            val = input("secret_value: ").strip()
            add_or_update_secret(sid, val)
            input("OK. Enter to continue...")
        elif choice == "2":
            sid = input("secret_id to delete: ").strip()
            delete_secret(sid)
            input("OK. Enter to continue...")
        elif choice == "3":
            process_requests()
            input("Done. Enter to continue...")
        elif choice == "4":
            rid = input("receiver_id: ").strip()
            sid = input("secret_id: ").strip()
            revoke_access(rid, sid)
            input("OK. Enter to continue...")
        elif choice == "5":
            break
        else:
            input("Unknown choice. Enter to continue...")

def process_requests():
    # Drain FIFO and ask user to approve/deny
    drained = []
    while not access_requests_q.empty():
        drained.append(access_requests_q.get_nowait())
    if not drained:
        print("No pending requests.")
        return
    for req in drained:
        rid = req["receiver_id"]
        sid = req["secret_id"]
        yn = input(f"Grant access to receiver '{rid}' for secret '{sid}'? [Y/n]: ").strip().lower()
        if yn in ("", "y", "yes"):
            try:
                _ = key_gen(sid)  # ensure keys exist
                _grant(rid, sid, req["receiver_public_key"])
            except Exception as e:
                print(f"Grant failed for {rid}:{sid} -> {e}")
        else:
            print(f"Denied {rid}:{sid}")
        access_requests_q.task_done()

if __name__ == "__main__":
    print(f"[Sender] Starting sender '{SENDER_ID}'...")
    load_state()

    # (optional) preload
    add_or_update_secret("street", "Dunking Street")
    add_or_update_secret("number", "42")

    threading.Thread(target=run_server, daemon=True).start()
    # CLI in main thread
    menu_loop()
