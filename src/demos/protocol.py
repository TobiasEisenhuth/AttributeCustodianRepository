import os
import sys
import msgpack
import tempfile
import getpass
import base64
import requests
from typing import Optional

# ===== Ports / Hosts =====
SENDER_HOST = "localhost"
SENDER_PORT = 5000
PROXY_HOST = "localhost"
PROXY_PORT = 6000
RECEIVER_HOST = "localhost"
RECEIVER_PORT = 7000

# ===== Actions =====
# Alice
ADD_OR_UPDATE_SECRET  = "ADD_OR_UPDATE_SECRET"
DELETE_SECRET         = "DELETE_SECRET"
GRANT_ACCESS_PROXY    = "GRANT_ACCESS_PROXY"
GRANT_ACCESS_RECEIVER = "GRANT_ACCESS_RECEIVER"
REVOKE_ACCESS         = "REVOKE_ACCESS"

# Ursula (proxy) -> Bob
RESPONSE_SECRET       = "RESPONSE_SECRET"

# Bob
REQUEST_ACCESS        = "REQUEST_ACCESS"
REQUEST_SECRET        = "REQUEST_SECRET"

# NEW (Sender <-> Proxy)
LIST_GRANTS           = "LIST_GRANTS"
GRANTS_SUMMARY        = "GRANTS_SUMMARY"

# inbox actions
PULL_INBOX_SENDER     = "PULL_INBOX_SENDER"       # sender pulls pending requests
PULL_INBOX_RECEIVER   = "PULL_INBOX_RECEIVER"     # receiver pulls pending grants
INBOX_CONTENTS        = "INBOX_CONTENTS"

ERROR                 = "ERROR"

# ===== Wire helpers (HTTP) =====
BASE_URL = f"http://{PROXY_HOST}:{PROXY_PORT}/api"

def api_post(path: str, payload: dict, timeout: Optional[float] = 15.0) -> dict:
    url = f"{BASE_URL}{path}"
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()

# ===== Base64 helpers (JSON-safe bytes) =====
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# ===== Persistence (STRICT encryption with AES-256-GCM) =====
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:
    AESGCM = None

def _require_crypto_or_exit():
    if AESGCM is None:
        print("[FATAL] 'cryptography' is required for encrypted stores. Install it (pip install cryptography).")
        sys.exit(1)

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    import hashlib
    # scrypt parameters: interactive-safe; tune n if needed
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)

def _save_bytes_atomic(path: str, data: bytes) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def save_store_encrypted(path: str, obj: dict, passphrase: str, magic_enc: bytes):
    """Always encrypt; format: magic(4) + ver(1) + salt(16) + nonce(12) + ct"""
    _require_crypto_or_exit()
    payload = msgpack.packb(obj, use_bin_type=True)
    import os as _os
    salt  = _os.urandom(16)
    key   = _derive_key(passphrase, salt)
    aes   = AESGCM(key)
    nonce = _os.urandom(12)
    ct    = aes.encrypt(nonce, payload, None)
    data  = magic_enc + bytes([1]) + salt + nonce + ct
    _save_bytes_atomic(path, data)

def load_store_encrypted(path: str, passphrase: str, magic_enc: bytes) -> dict:
    """Return dict on success; raise ValueError on auth failure/magic mismatch."""
    _require_crypto_or_exit()
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < (4 + 1 + 16 + 12 + 1):
        raise ValueError("Store file too short or corrupted")
    magic, ver = raw[:4], raw[4]
    if magic != magic_enc or ver != 1:
        raise ValueError("Wrong magic/version (not an encrypted store of expected type)")
    body  = raw[5:]
    salt  = body[:16]
    nonce = body[16:28]
    ct    = body[28:]
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    try:
        payload = aes.decrypt(nonce, ct, None)
    except Exception as e:
        raise ValueError("Decryption failed (bad password or corrupted file)") from e
    return msgpack.unpackb(payload, raw=False)

def require_password_and_load(path: str, magic_enc: bytes, role_label: str) -> tuple[str, dict]:
    """
    If file exists: prompt up to 3 times for password; on failure -> exit(1).
    If file missing: prompt to set a new password (enter twice); create empty dict.
    Returns (passphrase, loaded_obj_dict).
    """
    _require_crypto_or_exit()
    if os.path.exists(path):
        # Existing store: ask for password (3 tries), else exit
        for attempt in range(1, 4):
            pw = getpass.getpass(f"[{role_label}] Password (attempt {attempt}/3): ")
            if not pw:
                print("Empty password not allowed.")
                continue
            try:
                obj = load_store_encrypted(path, pw, magic_enc)
                print(f"[{role_label}] Store unlocked.")
                return pw, obj
            except ValueError as e:
                print(f"[{role_label}] {e}")
        print(f"[{role_label}] Too many failed attempts. Exiting.")
        sys.exit(1)
    else:
        # New store: set password (twice)
        while True:
            pw1 = getpass.getpass(f"[{role_label}] Set new store password: ")
            pw2 = getpass.getpass(f"[{role_label}] Repeat password: ")
            if not pw1:
                print("Empty password not allowed.")
                continue
            if pw1 != pw2:
                print("Passwords do not match, try again.")
                continue
            print(f"[{role_label}] New encrypted store will be created.")
            return pw1, {}
