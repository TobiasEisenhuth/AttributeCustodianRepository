import socket
import threading
from umbral import Capsule, KeyFrag, reencrypt
from umbral.keys import PublicKey
from protocol import *

PROXY_ID = "ursula"

secret_store = {}
grant_store = {}

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
        elif action == GRANT_ACCESS_PROXY:
            handle_grant_access(payload)
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
    sender_id = payload["sender_id"]
    secret_id = payload["secret_id"]

    if sender_id not in secret_store:
        secret_store[sender_id] = {}

    secret_store[sender_id][secret_id] = {
        "capsule": Capsule.from_bytes(payload["capsule"]),
        "ciphertext": payload["ciphertext"]
    }
    print(f"[Proxy] Stored secret '{secret_id}' from '{sender_id}'.")

def handle_grant_access(payload):
    sender_id = payload["sender_id"]
    receiver_id = payload["receiver_id"]
    secret_id = payload["secret_id"]
    kfrags = [KeyFrag.from_bytes(b) for b in payload["kfrags"]]
    if sender_id not in grant_store:
        grant_store[sender_id] = {}
        if receiver_id not in grant_store[sender_id]:
            grant_store[sender_id][receiver_id] = {}
            if secret_id not in grant_store[sender_id][receiver_id]:
                grant_store[sender_id][receiver_id][secret_id]= {
                    "kfrags": kfrags
            }
    print(f"[Proxy] Stored GRANT_ACCESS: {receiver_id} -> {secret_id} ({sender_id})")

def handle_request_secret(payload, conn):
    receiver_id = payload["receiver_id"]
    sender_id = payload["sender_id"]
    secret_id = payload["secret_id"]

    if sender_id not in secret_store or secret_id not in secret_store[sender_id]:
        send_msg(conn, make_error(f"Unknown secret '{secret_id}'"))
        return
    if sender_id not in grant_store or receiver_id not in grant_store[sender_id] or secret_id not in grant_store[sender_id][receiver_id]:
        send_msg(conn, make_error(f"No grant for {receiver_id} -> {secret_id}"))
        return

    capsule = secret_store[sender_id][secret_id]["capsule"]
    ciphertext = secret_store[sender_id][secret_id]["ciphertext"]
    kfrags = grant_store[sender_id][receiver_id][secret_id]["kfrags"]

    cfrags = list()
    for kfrag in kfrags:
        cfrag = reencrypt(capsule=capsule, kfrag=kfrag)
        cfrags.append(cfrag)

    response = {
        "capsule": bytes(capsule),
        "ciphertext": ciphertext,
        "cfrags": [bytes(c) for c in cfrags]
    }
    send_msg(conn, encode_msg(RESPONSE_SECRET, response))
    print(f"[Proxy] Served secret '{secret_id}' for '{receiver_id}' from '{sender_id}'.")

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((PROXY_HOST, PROXY_PORT))
        server_sock.listen()
        print(f"[Proxy] Listening on {PROXY_HOST}:{PROXY_PORT}...")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    run_server()
