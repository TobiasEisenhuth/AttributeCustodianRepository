import socket
import threading
from umbral import SecretKey, Signer, encrypt, generate_kfrags
from umbral.keys import PublicKey
from protocol import *

SENDER_ID = "alice"

key_store = {}

def key_gen(secret_id):
    if secret_id not in key_store:
        secret_key = SecretKey.random()
        public_key = secret_key.public_key()
        signing_key = SecretKey.random()
        verifying_key = signing_key.public_key()
        sender_signer = Signer(signing_key)
        key_store[secret_id] = {
            "secret_key": secret_key,
            "public_key": public_key,
            "signing_key": signing_key,
            "verifying_key": verifying_key,
            "sender_signer": sender_signer
        }
    return key_store[secret_id]["public_key"]

def add_or_update_secret(secret_id, secret_value):
    public_key = key_gen(secret_id)
    capsule, ciphertext = encrypt(public_key, secret_value.encode("utf-8"))
    payload = {
        "sender_id": SENDER_ID,
        "secret_id": secret_id,
        "capsule": bytes(capsule),
        "ciphertext": ciphertext
    }
    msg = encode_msg(ADD_OR_UPDATE_SECRET, payload)
    with socket.create_connection((PROXY_HOST, PROXY_PORT)) as sock:
        send_msg(sock, msg)
    print(f"[Sender] Secret '{secret_id}' sent to Proxy.")

def handle_client(conn, addr):
    try:
        data = recv_msg(conn)
        if not data:
            return
        msg = decode_msg(data)
        if msg["action"] == REQUEST_ACCESS:
            receiver_id = msg["payload"]["receiver_id"]
            secret_id = msg["payload"]["secret_id"]
            receiver_public_key_bytes = msg["payload"]["receiver_public_key"]
            print(f"[Sender] Received access request from {receiver_id} for '{secret_id}'.")

            if secret_id not in key_store:
                print(f"[Sender] Unknown secret_id '{secret_id}'")
                return

            receiver_public_key = PublicKey.from_bytes(receiver_public_key_bytes)
            delegating_secret_key = key_store[secret_id]["secret_key"]
            signer = key_store[secret_id]["signer"]
            verifying_key = key_store[secret_id]["verifying_key"]

            kfrags = generate_kfrags(
                delegating_sk=delegating_secret_key,
                receiving_pk=receiver_public_key,
                signer=signer,
                threshold=1,
                shares=1
            )

            payload_receiver = {
                "sender_id": SENDER_ID,
                "secret_id": secret_id,
                "public_key": bytes(key_store[secret_id]["public_key"]),
                "verifying_key": bytes(key_store[secret_id]["verifying_key"])
            }
            msg_receiver = encode_msg(GRANT_ACCESS_RECEIVER, payload_receiver)
            with socket.create_connection((RECEIVER_HOST, RECEIVER_PORT)) as sock:
                send_msg(sock, msg_receiver) 

            payload_proxy = {
                "sender_id": SENDER_ID,
                "receiver_id": receiver_id,
                "secret_id": secret_id,
                "kfrags": [bytes(k) for k in kfrags]
            }
            msg_proxy = encode_msg(GRANT_ACCESS_PROXY, payload_proxy)
            with socket.create_connection((PROXY_HOST, PROXY_PORT)) as sock:
                send_msg(sock, msg_proxy)
               
            print(f"[Sender] Sent GRANT_ACCESS_PROXY/RECEIVER for '{secret_id}' to Proxy.")
    except Exception as e:
        print(f"[Sender] Error: {e}")
    finally:
        conn.close()

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('', SENDER_PORT))
        server_sock.listen()
        print(f"[Sender] Listening for access requests on {SENDER_PORT}...")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    print(f"[Sender] Starting sender '{SENDER_ID}'...")
    add_or_update_secret("street", "Dunking Street")
    add_or_update_secret("number", "42")
    run_server()
