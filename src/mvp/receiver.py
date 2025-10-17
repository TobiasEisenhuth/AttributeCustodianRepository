import os
from umbral_pre import SecretKey, PublicKey, Capsule, CapsuleFrag, decrypt_reencrypted
from protocol import *
from typing import Dict

RECEIVER_ID: str = ""  # set at startup

# ===== Persistence config (encrypted only) =====
RECEIVER_STORE_FILE: str = ""  # set after ID prompt
MAGIC_ENC = b"ACRE"  # Alice Client Receiver Encrypted

store: Dict[str, Dict[str, dict]] = {}
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
                "secret_key":        (rec["secret_key"].to_be_bytes() if rec.get("secret_key") else None),
                "public_key":        (rec["public_key"].to_compressed_bytes() if rec.get("public_key") else None),
                "sender_public_key": (rec["sender_public_key"].to_compressed_bytes() if rec.get("sender_public_key") else None),
                "verifying_key":     (rec["verifying_key"].to_compressed_bytes() if rec.get("verifying_key") else None),
            }
    return out

def _deserialize_receiver_store(obj: dict) -> dict:
    st = {}
    for sid, m in (obj or {}).items():
        st[sid] = {}
        for sec_id, rec in (m or {}).items():
            st[sid][sec_id] = {
                "secret_key":        (SecretKey.from_be_bytes(rec["secret_key"]) if rec.get("secret_key") else None),
                "public_key":        (PublicKey.from_compressed_bytes(rec["public_key"]) if rec.get("public_key") else None),
                "sender_public_key": (PublicKey.from_compressed_bytes(rec["sender_public_key"]) if rec.get("sender_public_key") else None),
                "verifying_key":     (PublicKey.from_compressed_bytes(rec["verifying_key"]) if rec.get("verifying_key") else None),
            }
    return st

def save_state():
    try:
        save_store_encrypted(RECEIVER_STORE_FILE, _serialize_receiver_store(store), _RECEIVER_PASS, MAGIC_ENC)
    except Exception as e:
        print(f"[Receiver] Warning: failed to save store: {e}")

def load_state_or_init():
    global store, _RECEIVER_PASS
    _RECEIVER_PASS, obj = require_password_and_load(RECEIVER_STORE_FILE, MAGIC_ENC, role_label=f"Receiver:{RECEIVER_ID}")
    store = _deserialize_receiver_store(obj)
    total_grants = sum(
        1 for m in store.values() for rec in m.values()
        if rec.get("sender_public_key") and rec.get("verifying_key")
    )
    total_keys = sum(
        1 for m in store.values() for rec in m.values()
        if rec.get("public_key")
    )
    print(f"[Receiver {RECEIVER_ID}] Loaded store: {total_keys} keypairs, {total_grants} grants.")

# ===== Proxy inbox pull for grants =====
def pull_my_grants():
    msg = api_post("/pull_inbox/receiver", {"receiver_id": RECEIVER_ID})
    if msg.get("action") != INBOX_CONTENTS:
        print(f"[Receiver] Unexpected inbox reply: {msg.get('action')}")
        return
    for m in msg["payload"].get("messages", []):
        if m.get("action") != GRANT_ACCESS_RECEIVER:
            continue
        p = m["payload"]
        if p.get("receiver_id") != RECEIVER_ID:
            continue  # not for me
        sender_id = p["sender_id"]
        secret_id = p["secret_id"]
        srow = store.setdefault(sender_id, {}).setdefault(secret_id, {
            "secret_key": None,
            "public_key": None,
            "sender_public_key": None,
            "verifying_key": None
        })
        try:
            spk = PublicKey.from_compressed_bytes(b64d(p["public_key_b64"]))
            vpk = PublicKey.from_compressed_bytes(b64d(p["verifying_key_b64"]))
            srow["sender_public_key"] = spk
            srow["verifying_key"] = vpk
            print(f"[Receiver {RECEIVER_ID}] Pulled grant for '{secret_id}' from '{sender_id}'.")
        except Exception as e:
            print(f"[Receiver] Bad grant payload: {e}")
    save_state()

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
    save_state()
    return public_key

def request_access(sender_id, secret_id):
    public_key = key_gen(sender_id, secret_id)
    payload = {
        "sender_id": sender_id,
        "receiver_id": RECEIVER_ID,
        "secret_id": secret_id,
        "receiver_public_key_b64": b64e(public_key.to_compressed_bytes())
    }
    api_post("/request_access", payload)
    print(f"[Receiver {RECEIVER_ID}] Requested access to '{secret_id}' from '{sender_id}' (via proxy).")

def request_and_decrypt(sender_id, secret_id):
    # pull any grant notices for me first
    pull_my_grants()

    if sender_id not in store or secret_id not in store[sender_id]:
        print("No keypair for that (sender, secret). Request access first.")
        return
    srow = store[sender_id][secret_id]

    if srow["secret_key"] is None or srow["public_key"] is None:
        print("No keypair for that (sender, secret). Request access first.")
        return
    if srow["sender_public_key"] is None or srow["verifying_key"] is None:
        print("No grant stored yet from sender. Wait for grant before requesting secret.")
        return

    payload = {
        "receiver_id": RECEIVER_ID,
        "sender_id": sender_id,
        "secret_id": secret_id,
        "receiver_public_key_b64": b64e(srow["public_key"].to_compressed_bytes())
    }
    data = api_post("/request_secret", payload)

    if data["action"] == ERROR:
        print(f"[Receiver] Error: {data['payload']['error']}")
        return

    capsule = Capsule.from_bytes(b64d(data["payload"]["capsule_b64"]))
    ciphertext = b64d(data["payload"]["ciphertext_b64"])
    suspicious_cfrags = [CapsuleFrag.from_bytes(b64d(b)) for b in data["payload"]["cfrags_b64"]]

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
    print(f"[Receiver {RECEIVER_ID}] Decrypted '{secret_id}' from '{sender_id}': {plaintext}")

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
            spk = fp(rec["sender_public_key"].to_compressed_bytes())
            vpk = fp(rec["verifying_key"].to_compressed_bytes())
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
            print(f"- sender={s_id} secret={sec_id} recv_pk={fp(rec['public_key'].to_compressed_bytes())}")
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
        print(f"=== Receiver: {RECEIVER_ID} ===")
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
    # ---- ID prompt & per-profile store selection ----
    while True:
        RECEIVER_ID = input("Enter Receiver ID (profile name): ").strip()
        if RECEIVER_ID:
            break
        print("Receiver ID cannot be empty.")
    RECEIVER_STORE_FILE = os.getenv("RECEIVER_STORE_FILE") or f"receiver_store_{RECEIVER_ID}.msgpack"

    print(f"[Receiver {RECEIVER_ID}] Using store file: {RECEIVER_STORE_FILE}")
    load_state_or_init()
    menu_loop()
