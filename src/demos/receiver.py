import socket
from umbral import SecretKey, pre, decrypt_reencrypted, CapsuleFrag
from umbral.keys import PublicKey
from protocol import *

RECEIVER_ID = "bob"

key_store = {}
artifact_store = {}

def key_gen(sender_id, secret_id):
    if sender_id not in key_store:
        key_store[sender_id] = {}
        if secret_id not in key_store[sender_id]:
            key_store[sender_id][secret_id] = {}

    secret_key = SecretKey.random()
    public_key = secret_key.public_key()
    key_store[sender_id][secret_id] = {
        "secret_key": secret_key,
        "public_key": public_key
    }
    return key_store[sender_id][secret_id]["public_key"]

def request_access(sender_id, secret_id):
    public_key = key_gen(sender_id, secret_id)
    payload = {
        "receiver": RECEIVER_ID,
        "secret_id": secret_id,
        "receiver_pubkey": bytes(public_key)
    }
    msg = encode_msg(REQUEST_ACCESS, payload)
    with socket.create_connection((SENDER_HOST, SENDER_PORT)) as sock:
        send_msg(sock, msg)
        print(f"[Receiver] Requested access to '{secret_id}' from '{sender_id}'.")
        response = recv_msg(sock)
    
    msg = decode_msg(response)
    if msg["action"] == GRANT_ACCESS_RECEIVER:
        sender_id = msg["payload"]["sender_id"]
        secret_id = msg["payload"]["secret_id"]
        sender_public_key = msg["payload"]["public_key"]
        verifying_key = msg["payload"]["verifying_key"]

        if sender_id not in artifact_store:
            artifact_store[sender_id] = {}
            if secret_id not in artifact_store[secret_id]:
                artifact_store[sender_id][secret_id] = {
                    "sender_public_key": sender_public_key,
                    "verifying_key": verifying_key
                }


        print(f"[Receiver] Access granted to '{secret_id}' from '{sender_id}'.")
    

def request_and_decrypt(sender_id, secret_id):
    receiver_sk = key_store[sender_id][secret_id]
    receiver_pk = receiver_sk.public_key()

    payload = {
        "receiver": RECEIVER_ID,
        "sender": sender_id,
        "secret_id": secret_id
    }
    msg = encode_msg(REQUEST_SECRET, payload)
    with socket.create_connection((PROXY_HOST, PROXY_PORT)) as sock:
        send_msg(sock, msg)
        response = recv_msg(sock)

    data = decode_msg(response)
    if data["action"] == ERROR:
        print(f"[Receiver] Error: {data['payload']['error']}")
        return

    capsule = pre.Capsule.from_bytes(data["payload"]["capsule"])
    ciphertext = data["payload"]["ciphertext"]
    suspicious_cfrags = [CapsuleFrag.from_bytes(b) for b in data["payload"]["cfrags"]]

    cfrags = [cfrag.verify(capsule,
                        artifact_store[sender_id][secret_id]["verifying_key"],
                        artifact_store[sender_id][secret_id]["sender_public_key"],
                        key_store[sender_id][secret_id]["public_key"])
            for cfrag in suspicious_cfrags]

    plaintext = decrypt_reencrypted(
        receiver_sk,
        artifact_store[sender_id][secret_id]["sender_public_key"],
        capsule,
        cfrags,
        ciphertext
    )
    print(f"[Receiver] Decrypted '{secret_id}' from '{sender_id}': {plaintext.decode()}")

if __name__ == "__main__":
    request_access("alice", "street")
    input("[Receiver] Press Enter after Alice grants access...\n")
    request_and_decrypt("alice", "street")
