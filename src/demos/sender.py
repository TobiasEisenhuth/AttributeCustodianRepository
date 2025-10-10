import os
import queue
from umbral import SecretKey, Signer, encrypt, generate_kfrags
from umbral.keys import PublicKey
from protocol import *
from typing import Dict

SENDER_ID: str = ""  # set at startup

# ===== Persistence config (encrypted only) =====
SENDER_STORE_FILE: str = ""  # set after ID prompt
MAGIC_ENC = b"ACSE"  # Alice Client Store Encrypted

# State
key_store: Dict[str, dict] = {}                         # secret_id -> keys
access_requests_q: "queue.Queue[dict]" = queue.Queue()  # retained for UI
_SENDER_PASS: str = ""  # set at startup

# ===== Persistence (serialize keys only; signer is reconstructed) =====
def _serialize_sender_store(ks: dict) -> dict:
    out = {}
    for sid, rec in ks.items():
        out[sid] = {
            "secret_key": rec["secret_key"].to_secret_bytes(),
            "public_key": bytes(rec["public_key"]),
            "signing_key": rec["signing_key"].to_secret_bytes(),
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
        save_store_encrypted(SENDER_STORE_FILE, _serialize_sender_store(key_store), _SENDER_PASS, MAGIC_ENC)
    except Exception as e:
        print(f"[Sender] Warning: failed to save store: {e}")

def load_state_or_init():
    global key_store, _SENDER_PASS
    _SENDER_PASS, obj = require_password_and_load(SENDER_STORE_FILE, MAGIC_ENC, role_label=f"Sender:{SENDER_ID}")
    key_store = _deserialize_sender_store(obj)
    print(f"[Sender {SENDER_ID}] Loaded {len(key_store)} secrets from store.")

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
    body = {
        "sender_id": SENDER_ID,
        "secret_id": secret_id,
        "capsule_b64": b64e(bytes(capsule)),
        "ciphertext_b64": b64e(ciphertext),
        "sender_public_key_b64":    b64e(bytes(key_store[secret_id]["public_key"])),
        "sender_verifying_key_b64": b64e(bytes(key_store[secret_id]["verifying_key"])),
    }
    api_post("/add_or_update_secret", body)
    print(f"[Sender {SENDER_ID}] Secret '{secret_id}' sent to Proxy.")

def delete_secret(secret_id: str):
    body = {"sender_id": SENDER_ID, "secret_id": secret_id}
    api_post("/delete_secret", body)
    if key_store.pop(secret_id, None) is not None:
        save_state()
    print(f"[Sender {SENDER_ID}] Requested delete for '{secret_id}'.")

def revoke_access(receiver_id: str, secret_id: str):
    body = {"sender_id": SENDER_ID, "receiver_id": receiver_id, "secret_id": secret_id}
    api_post("/revoke_access", body)
    print(f"[Sender {SENDER_ID}] Requested revoke: {receiver_id} -> {secret_id}")

def _grant(receiver_id: str, secret_id: str, recv_pk_b64: str):
    recv_pk_b = b64d(recv_pk_b64)
    kfrags = generate_kfrags(
        delegating_sk=key_store[secret_id]["secret_key"],
        receiving_pk=PublicKey.from_bytes(recv_pk_b),
        signer=key_store[secret_id]["signer"],
        threshold=1,
        shares=1
    )
    # Enqueue grant notice FOR receiver via proxy (JSON-safe fields)
    ack_payload = {
        "sender_id": SENDER_ID,
        "receiver_id": receiver_id,
        "secret_id": secret_id,
        "public_key_b64":    b64e(bytes(key_store[secret_id]["public_key"])),
        "verifying_key_b64": b64e(bytes(key_store[secret_id]["verifying_key"]))
    }
    api_post("/grant_access_receiver", ack_payload)

    # Send kfrags to proxy store
    body = {
        "sender_id": SENDER_ID,
        "receiver_id": receiver_id,
        "secret_id": secret_id,
        "kfrags_b64": [b64e(bytes(k)) for k in kfrags]
    }
    api_post("/grant_access_proxy", body)
    print(f"[Sender {SENDER_ID}] Granted '{secret_id}' to '{receiver_id}' via Proxy.")

# ===== NEW: list grants from proxy =====
def list_grants_remote():
    msg = api_post("/list_grants", {"sender_id": SENDER_ID})
    if msg.get("action") == "ERROR":
        print(f"[Sender] Error: {msg['payload']['error']}")
        return
    if msg.get("action") != GRANTS_SUMMARY:
        print(f"[Sender] Unexpected reply: {msg.get('action')}")
        return
    summary = msg["payload"]
    by_secret = summary.get("by_secret", {})
    totals = summary.get("totals", {})
    print(f"=== Grants on Proxy for sender '{SENDER_ID}' ===")
    print(f"Secrets: {totals.get('secrets', 0)} | Grants: {totals.get('grants', 0)}")
    if not by_secret:
        print("(no secrets at proxy)")
        return
    for sid in sorted(by_secret.keys()):
        receivers = by_secret[sid]
        if receivers:
            print(f"- {sid}/")
            for r in receivers:
                print(f"    -> {r}")
        else:
            print(f"- {sid}/  (no receivers)")

# ===== CLI =====
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def menu_loop():
    while True:
        clear()
        print(f"=== Sender: {SENDER_ID} ===")
        print("Secrets:", ", ".join(key_store.keys()) or "(none)")
        print("(Pending requests come from proxy inbox)")
        print()
        print("1) Add/Update secret")
        print("2) Delete secret")
        print("3) Process pending access requests (from proxy)")
        print("4) Revoke access (receiver_id, secret_id)")
        print("5) List my grants (from Proxy)")
        print("6) Quit")
        choice = input("> ").strip()

        if choice == "1":
            sid = input("secret_id: ").strip()
            val = input("secret_value: ").strip()
            add_or_update_secret(sid, val)
            save_state()
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
            list_grants_remote()
            input("Enter to continue...")
        elif choice == "6":
            break
        else:
            input("Unknown choice. Enter to continue...")

def process_requests():
    msg = api_post("/pull_inbox/sender", {"sender_id": SENDER_ID})
    if msg.get("action") == "ERROR":
        print(f"[Sender] Error: {msg['payload']['error']}")
        return
    if msg.get("action") != INBOX_CONTENTS:
        print(f"[Sender] Unexpected reply: {msg.get('action')}")
        return

    messages = msg["payload"].get("messages", [])
    requests = [m["payload"] for m in messages
                if m.get("action") == REQUEST_ACCESS and m["payload"].get("sender_id") == SENDER_ID]

    if not requests:
        print("No pending requests at proxy.")
        return

    for req in requests:
        rid = req["receiver_id"]
        sid = req["secret_id"]
        yn = input(f"Grant access to receiver '{rid}' for secret '{sid}'? [Y/n]: ").strip().lower()
        if yn in ("", "y", "yes"):
            try:
                _ = key_gen(sid)  # ensure keys exist
                _grant(rid, sid, req["receiver_public_key_b64"])
            except Exception as e:
                print(f"Grant failed for {rid}:{sid} -> {e}")
        else:
            print(f"Denied {rid}:{sid}")

if __name__ == "__main__":
    # ---- ID prompt & per-profile store selection ----
    while True:
        SENDER_ID = input("Enter Sender ID (profile name): ").strip()
        if SENDER_ID:
            break
        print("Sender ID cannot be empty.")
    SENDER_STORE_FILE = os.getenv("SENDER_STORE_FILE") or f"sender_store_{SENDER_ID}.msgpack"

    print(f"[Sender {SENDER_ID}] Using store file: {SENDER_STORE_FILE}")
    load_state_or_init()
    menu_loop()
