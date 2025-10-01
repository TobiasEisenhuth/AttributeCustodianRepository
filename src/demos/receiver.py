import socket
import threading
from umbral import SecretKey, pre, decrypt_reencrypted, CapsuleFrag
from umbral.keys import PublicKey
from protocol import *

RECEIVER_ID = "bob"

key_store = {}
artifact_store = {}

inbox_q = {}

def _get_q(action: str):
    import queue
    if action not in inbox_q:
        inbox_q[action] = queue.Queue()
    return inbox_q[action]

def key_gen(sender_id, secret_id):
    secret_key = SecretKey.random()
    public_key = secret_key.public_key()
    key_store.setdefault(sender_id, {})[secret_id] = {
        "secret_key": secret_key,
        "public_key": public_key
    }
    return public_key

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

            _get_q(GRANT_ACCESS_RECEIVER).put(payload)
            print(f"[Receiver] Stored grant for '{secret_id}' from '{sender_id}'.")
        else:
            send_msg(conn, make_error("Unsupported action for Receiver"))
    except Exception as e:
        try:
            send_msg(conn, make_error(str(e)))
        except Exception:
            pass
        print(f"[Receiver] Error: {e}")
    finally:
        conn.close()

def run_server():
    threading.Thread(target=_server_loop, daemon=True).start()

def _server_loop():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('', RECEIVER_PORT))
        server_sock.listen()
        print(f"[Receiver] Listening on {RECEIVER_PORT}...")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def request_access(sender_id, secret_id):
    public_key = key_store.get(sender_id, {}).get(secret_id, {}).get("public_key") or key_gen(sender_id, secret_id)
    payload = {
        "receiver_id": RECEIVER_ID,
        "secret_id": secret_id,
        "receiver_public_key": bytes(public_key)
    }
    outbox.send(SENDER_HOST, SENDER_PORT, encode_msg(REQUEST_ACCESS, payload), expect_reply=False)
    print(f"[Receiver] Requested access to '{secret_id}' from '{sender_id}'.")

def request_and_decrypt(sender_id, secret_id):
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

if __name__ == "__main__":
    run_server()

    request_access("alice", "street")
    input("[Receiver] Press Enter after Alice grants access...\n")
    request_and_decrypt("alice", "street")
