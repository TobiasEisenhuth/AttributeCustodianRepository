import socket
import threading
import queue
from umbral import SecretKey, Signer, encrypt, generate_kfrags
from umbral.keys import PublicKey
from protocol import *

SENDER_ID = "alice"

# In-memory key store and inbound FIFO for access requests (for future CLI)
key_store: dict = {}
access_requests_q: "queue.Queue[dict]" = queue.Queue()

def key_gen(secret_id):
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
    return key_store[secret_id]["public_key"]

def add_or_update_secret(secret_id, secret_value):
    public_key = key_gen(secret_id)
    capsule, ciphertext = encrypt(public_key, secret_value.encode("utf-8"))
    payload = {
        "sender_id": SENDER_ID,
        "secret_id": secret_id,
        "capsule": bytes(capsule),
        "ciphertext": ciphertext,
        "sender_public_key":   bytes(key_store[secret_id]["public_key"]),
        "sender_verifying_key":bytes(key_store[secret_id]["verifying_key"])
    }
    outbox.send(PROXY_HOST, PROXY_PORT, encode_msg(ADD_OR_UPDATE_SECRET, payload), expect_reply=False)
    print(f"[Sender] Secret '{secret_id}' sent to Proxy.")

def _auto_grant_worker():
    """Consumes REQUEST_ACCESS messages from FIFO and grants immediately (non-blocking).
       Later, the CLI can replace this with interactive approval."""
    while True:
        req = access_requests_q.get()
        try:
            receiver_id = req["receiver_id"]
            secret_id   = req["secret_id"]
            recv_pk_b   = req["receiver_public_key"]

            if secret_id not in key_store:
                print(f"[Sender] Unknown secret_id '{secret_id}'")
                continue

            kfrags = generate_kfrags(
                delegating_sk=key_store[secret_id]["secret_key"],
                receiving_pk=PublicKey.from_bytes(recv_pk_b),
                signer=key_store[secret_id]["signer"],
                threshold=1,
                shares=1
            )

            # Notify Bob via his server (homogeneous pattern)
            ack_payload = {
                "sender_id": SENDER_ID,
                "secret_id": secret_id,
                "public_key":   bytes(key_store[secret_id]["public_key"]),
                "verifying_key":bytes(key_store[secret_id]["verifying_key"])
            }
            outbox.send(RECEIVER_HOST, RECEIVER_PORT, encode_msg(GRANT_ACCESS_RECEIVER, ack_payload), expect_reply=False)
            print(f"[Sender] Notified Receiver '{receiver_id}' for '{secret_id}'.")

            # Send kfrags to Proxy
            payload_proxy = {
                "sender_id": SENDER_ID,
                "receiver_id": receiver_id,
                "secret_id": secret_id,
                "kfrags": [bytes(k) for k in kfrags]
            }
            outbox.send(PROXY_HOST, PROXY_PORT, encode_msg(GRANT_ACCESS_PROXY, payload_proxy), expect_reply=False)
            print(f"[Sender] Granted '{secret_id}' to '{receiver_id}' via Proxy.")

        except Exception as e:
            print(f"[Sender] Grant worker error: {e}")
        finally:
            access_requests_q.task_done()

def handle_client(conn, addr):
    try:
        data = recv_msg(conn)
        if not data:
            return
        msg = decode_msg(data)
        if msg["action"] == REQUEST_ACCESS:
            # enqueue for FIFO processing
            req = msg["payload"]
            access_requests_q.put(req)
            # immediate ack to the TCP caller that we accepted the request (optional)
            send_msg(conn, encode_msg("OK", {"queued": True}))
            print(f"[Sender] Queued access request from {req['receiver_id']} for '{req['secret_id']}'.")
        else:
            send_msg(conn, make_error("Unsupported action for Sender"))
    except Exception as e:
        try:
            send_msg(conn, make_error(str(e)))
        except Exception:
            pass
        print(f"[Sender] Error: {e}")
    finally:
        conn.close()

def run_server():
    threading.Thread(target=_auto_grant_worker, daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('', SENDER_PORT))
        server_sock.listen()
        print(f"[Sender] Listening on {SENDER_PORT}...")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    print(f"[Sender] Starting sender '{SENDER_ID}'...")
    add_or_update_secret("street", "Dunking Street")
    add_or_update_secret("number", "42")
    run_server()
