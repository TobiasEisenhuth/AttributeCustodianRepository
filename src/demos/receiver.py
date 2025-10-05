import os
import socket
import threading
from umbral import SecretKey, pre, decrypt_reencrypted, CapsuleFrag
from umbral.keys import PublicKey
from protocol import *

RECEIVER_ID = "bob"

# ===== Persistence config (encrypted only) =====
RECEIVER_STORE_FILE = os.getenv("RECEIVER_STORE_FILE", "receiver_store.msgpack")
MAGIC_ENC = b"ACRE"  # Alice Client Receiver Encrypted

store = {}  # sender_id -> secret_id -> {secret_key, public_key, sender_public_key, verifying_key}
_RECEIVER_PASS: str = ""  # set at startup

# ===== Util =====
def fp(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()[:10]

# ===== Persistence =====
def _serialize_receiver_store(st: dict) -> dict:
    out = {}
    for sid, m in st.items():
        out[sid] = {}
        for sec_id, rec in m.items():
            out[sid][sec_id] = {
                "secret_key":        (rec["secret_key"].to_secret_bytes() if rec.get("secret_key") else None),
                "public_key":        (bytes(rec["public_key"]) if rec.get("public_key") else None),
                "sender_public_key": (bytes(rec["sender_public_key"]) if rec.get("sender_public_key") else None),
                "verifying_key":     (bytes(rec["verifying_key"]) if rec.get("verifying_key") else None),
            }
    return out

def _deserialize_receiver_store(obj: dict) -> dict:
    st = {}
    for sid, m in (obj or {}).items():
        st[sid] = {}
        for sec_id, rec in (m or {}).items():
            st[sid][sec_id] = {
                "secret_key":        (SecretKey.from_bytes(rec["secret_key"]) if rec.get("secret_key") else None),
                "public_key":        (PublicKey.from_bytes(rec["public_key"]) if rec.get("public_key") else None),
                "sender_public_key": (PublicKey.from_bytes(rec["sender_public_key"]) if rec.get("sender_public_key") else None),
                "verifying_key":     (PublicKey.from_bytes(rec["verifying_key"]) if rec.get("verifying_key") else None),
            }
    return st

def save_state():
    try:
        save_store_encrypted(RECEIVER_STORE_FILE, _serialize_receiver_store(store), _RECEIVER_PASS, MAGIC_ENC)
    except Exception as e:
        print(f("[Receiver] Warning: failed to save store: {e}"))

def load_state_or_init():
    global store, _RECEIVER_PASS
    _RECEIVER_PASS, obj = require_password_and_load(RECEIVER_STORE_FILE, MAGIC_ENC, role_label="Receiver")
    store = _deserialize_receiver_store(obj)
    total_grants = sum(
        1 for m in store.values() for rec in m.values()
        if rec.get("sender_public_key") and rec.get("verifying_key")
    )
    total_keys = sum(
        1 for m in store.values() for rec in m.values()
        if rec.get("public_key")
    )
    print(f"[Receiver] Loaded store: {total_keys} keypairs, {total_grants} grants.")

# ===== Inbound server (for GRANT_ACCESS_RECEIVER) =====
def handle_client(conn, addr):
    try:
        data = recv_msg(conn)
        if not data:
            return
        msg = decode_msg(data)
        action = msg["action"]
        payload = msg["payload"]

        if action == GRANT_ACCESS_RECEIVER:
            sender_id = payload["sender_id"]
            secret_id = payload["secret_id"]
            sender_public_key_bytes = payload["public_key"]
            verifying_key_bytes     = payload["verifying_key"]

            srow = store.setdefault(sender_id, {}).setdefault(secret_id, {
                "secret_key": None,
                "public_key": None,
                "sender_public_key": None,
                "verifying_key": None
            })

            new_sender_pk = PublicKey.from_bytes(sender_public_key_bytes)
            new_verify_pk = PublicKey.from_bytes(verifying_key_bytes)

            if srow["sender_public_key"] is not None and bytes(srow["sender_public_key"]) != sender_public_key_bytes:
                print(f"[Receiver] Warning: sender_public_key rotated for ({sender_id}, {secret_id}). Overwriting artifact.")
            srow["sender_public_key"] = new_sender_pk

            if srow["verifying_key"] is not None and bytes(srow["verifying_key"]) != verifying_key_bytes:
                print(f"[Receiver] Warning: verifying_key rotated for ({sender_id}, {secret_id}). Overwriting artifact.")
            srow["verifying_key"] = new_verify_pk

            save_state()  # persist grant update
            # fire-and-forget: no reply (avoid Broken pipe)
            print(f"[Receiver] Stored grant for '{secret_id}' from '{sender_id}'.")
        else:
            print(f"[Receiver] Unknown inbound action: {action}")
    finally:
        conn.close()

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('0.0.0.0', RECEIVER_PORT))
        server_sock.listen()
        print(f"[Receiver] Listening on {RECEIVER_PORT}...")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# ===== Actions =====
def key_gen(sender_id, secret_id):
    srow = store.setdefault(sender_id, {}).setdefault(secret_id, {
        "secret_key": None,
        "public_key": None,
        "sender_public_key": None,
        "verifying_key": None
    })

    if srow["public_key"] is not None:
        return srow["public_key"]
    secret_key = SecretKey.random()
    public_key = secret_key.public_key()
    srow["secret_key"] = secret_key
    srow["public_key"] = public_key
    save_state()  # persist key creation
    return public_key

def request_access(sender_id, secret_id):
    public_key = key_gen(sender_id, secret_id)
    payload = {
        "receiver_id": RECEIVER_ID,
        "secret_id": secret_id,
        "receiver_public_key": bytes(public_key)
    }
    outbox.send(SENDER_HOST, SENDER_PORT, encode_msg(REQUEST_ACCESS, payload), expect_reply=False)
    print(f"[Receiver] Requested access to '{secret_id}' from '{sender_id}'.")

def request_and_decrypt(sender_id, secret_id):
    if sender_id not in store or secret_id not in store[sender_id]:
        print("No keypair for that (sender, secret). Request access first.")
        return
    srow = store[sender_id][secret_id]

    if srow["secret_key"] is None or srow["public_key"] is None:
        print("No keypair for that (sender, secret). Request access first.")
        return
    if srow["sender_public_key"] is None or srow["verifying_key"] is None:
        print("No grant stored yet from Alice. Wait for grant before requesting secret.")
        return

    payload = {
        "receiver_id": RECEIVER_ID,
        "sender_id": sender_id,
        "secret_id": secret_id,
        "receiver_public_key": bytes(srow["public_key"])
    }
    resp = outbox.send(PROXY_HOST, PROXY_PORT, encode_msg(REQUEST_SECRET, payload), expect_reply=True)

    data = decode_msg(resp)
    if data["action"] == ERROR:
        print(f"[Receiver] Error: {data['payload']['error']}")
        return

    capsule = pre.Capsule.from_bytes(data["payload"]["capsule"])
    ciphertext = data["payload"]["ciphertext"]
    suspicious_cfrags = [CapsuleFrag.from_bytes(b) for b in data["payload"]["cfrags"]]

    cfrags = [
        cfrag.verify(
            capsule,
            srow["verifying_key"],
            srow["sender_public_key"],
            srow["public_key"]
        )
        for cfrag in suspicious_cfrags
    ]

    plaintext = decrypt_reencrypted(
        srow["secret_key"],
        srow["sender_public_key"],
        capsule,
        cfrags,
        ciphertext
    )
    print(f"[Receiver] Decrypted '{secret_id}' from '{sender_id}': {plaintext.decode()}")

# ===== CLI =====
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def list_grants():
    any_grant = False
    for s_id, m in store.items():
        for sec_id, rec in m.items():
            if rec.get("sender_public_key") is None or rec.get("verifying_key") is None:
                continue
            any_grant = True
            spk = fp(bytes(rec["sender_public_key"]))
            vpk = fp(bytes(rec["verifying_key"]))
            print(f"- sender={s_id} secret={sec_id} sender_pk={spk} verifying_pk={vpk}")
    if not any_grant:
        print("(no grants)")

def list_keys():
    any_key = False
    for s_id, m in store.items():
        for sec_id, rec in m.items():
            if rec.get("public_key") is None:
                continue
            any_key = True
            print(f"- sender={s_id} secret={sec_id} recv_pk={fp(bytes(rec['public_key']))}")
    if not any_key:
        print("(no local keys)")

def menu_loop():
    while True:
        clear()
        total_grants = sum(
            1 for m in store.values() for rec in m.values()
            if rec.get("sender_public_key") is not None and rec.get("verifying_key") is not None
        )
        total_keys = sum(
            1 for m in store.values() for rec in m.values()
            if rec.get("public_key") is not None
        )
        print("=== Bob (Receiver) ===")
        print("Stored grants:", total_grants)
        print("Local keypairs:", total_keys)
        print()
        print("1) Request access (sender_id, secret_id)")
        print("2) Request secret & decrypt (sender_id, secret_id)")
        print("3) Show stored grants")
        print("4) Show my keys")
        print("5) Quit")
        choice = input("> ").strip()
        if choice == "1":
            sid = input("sender_id: ").strip()
            sec = input("secret_id: ").strip()
            request_access(sid, sec)
            input("OK. Enter to continue...")
        elif choice == "2":
            sid = input("sender_id: ").strip()
            sec = input("secret_id: ").strip()
            request_and_decrypt(sid, sec)
            input("Enter to continue...")
        elif choice == "3":
            list_grants()
            input("Enter to continue...")
        elif choice == "4":
            list_keys()
            input("Enter to continue...")
        elif choice == "5":
            break
        else:
            input("Unknown choice. Enter to continue...")

if __name__ == "__main__":
    load_state_or_init()
    threading.Thread(target=run_server, daemon=True).start()
    menu_loop()
