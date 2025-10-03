import os
import socket
import threading
from umbral import SecretKey, pre, decrypt_reencrypted, CapsuleFrag
from umbral.keys import PublicKey
from protocol import *

RECEIVER_ID = "bob"

key_store = {}       # sender_id -> secret_id -> {secret_key, public_key}
artifact_store = {}  # sender_id -> secret_id -> {sender_public_key, verifying_key}

# ===== Util =====
def fp(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()[:10]

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

            artifact_store.setdefault(sender_id, {})[secret_id] = {
                "sender_public_key": PublicKey.from_bytes(sender_public_key_bytes),
                "verifying_key":     PublicKey.from_bytes(verifying_key_bytes)
            }
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
    if sender_id in key_store and secret_id in key_store[sender_id]:
        return key_store[sender_id][secret_id]["public_key"]
    secret_key = SecretKey.random()
    public_key = secret_key.public_key()
    key_store.setdefault(sender_id, {})[secret_id] = {"secret_key": secret_key, "public_key": public_key}
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
    if sender_id not in key_store or secret_id not in key_store[sender_id]:
        print("No keypair for that (sender, secret). Request access first.")
        return
    if sender_id not in artifact_store or secret_id not in artifact_store[sender_id]:
        print("No grant stored yet from Alice. Wait for grant before requesting secret.")
        return

    payload = {
        "receiver_id": RECEIVER_ID,
        "sender_id": sender_id,
        "secret_id": secret_id,
        "receiver_public_key": bytes(key_store[sender_id][secret_id]["public_key"])
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
            artifact_store[sender_id][secret_id]["verifying_key"],
            artifact_store[sender_id][secret_id]["sender_public_key"],
            key_store[sender_id][secret_id]["public_key"]
        )
        for cfrag in suspicious_cfrags
    ]

    plaintext = decrypt_reencrypted(
        key_store[sender_id][secret_id]["secret_key"],
        artifact_store[sender_id][secret_id]["sender_public_key"],
        capsule,
        cfrags,
        ciphertext
    )
    print(f"[Receiver] Decrypted '{secret_id}' from '{sender_id}': {plaintext.decode()}")

# ===== CLI =====
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def list_grants():
    if not artifact_store:
        print("(no grants)")
        return
    for s_id, m in artifact_store.items():
        for sec_id, rec in m.items():
            spk = fp(bytes(rec["sender_public_key"]))
            vpk = fp(bytes(rec["verifying_key"]))
            print(f"- sender={s_id} secret={sec_id} sender_pk={spk} verifying_pk={vpk}")

def list_keys():
    if not key_store:
        print("(no local keys)")
        return
    for s_id, m in key_store.items():
        for sec_id, rec in m.items():
            print(f"- sender={s_id} secret={sec_id} recv_pk={fp(bytes(rec['public_key']))}")

def menu_loop():
    while True:
        clear()
        print("=== Bob (Receiver) ===")
        print("Stored grants:", sum(len(v) for v in artifact_store.values()) or 0)
        print("Local keypairs:", sum(len(v) for v in key_store.values()) or 0)
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
    threading.Thread(target=run_server, daemon=True).start()
    menu_loop()
