import os
import sys
import msgpack
import tempfile
import getpass
import base64
import requests
from typing import Optional

# ===== Actions =====
ADD_OR_UPDATE_SECRET  = "ADD_OR_UPDATE_SECRET"
DELETE_SECRET         = "DELETE_SECRET"
GRANT_ACCESS_PROXY    = "GRANT_ACCESS_PROXY"
GRANT_ACCESS_RECEIVER = "GRANT_ACCESS_RECEIVER"
REVOKE_ACCESS         = "REVOKE_ACCESS"
RESPONSE_SECRET       = "RESPONSE_SECRET"
REQUEST_ACCESS        = "REQUEST_ACCESS"
REQUEST_SECRET        = "REQUEST_SECRET"
LIST_GRANTS           = "LIST_GRANTS"
GRANTS_SUMMARY        = "GRANTS_SUMMARY"
PULL_INBOX_SENDER     = "PULL_INBOX_SENDER"
PULL_INBOX_RECEIVER   = "PULL_INBOX_RECEIVER"
INBOX_CONTENTS        = "INBOX_CONTENTS"
ERROR                 = "ERROR"

# ===== HTTP client base =====
# Default to HTTPS through your Caddy proxy
PROXY_BASE_URL = os.getenv("PROXY_BASE_URL", "https://app.localhost").rstrip("/")
API_BASE = PROXY_BASE_URL  # keep naming from your code

# TLS verification:
# - default: True (use system CA store)
# - if PROXY_CA_BUNDLE is set: path to a CA bundle file
# - if PROXY_VERIFY=0: disable verification (DEV ONLY)
_SESSION = requests.Session()
_verify: bool | str = True
_ca = os.getenv("PROXY_CA_BUNDLE")
if _ca:
    _verify = _ca
elif os.getenv("PROXY_VERIFY", "1") == "0":
    _verify = False

def _post(path: str, payload: dict, timeout: Optional[float] = 15.0) -> requests.Response:
    """Raw POST, no /api prefix magic."""
    if not path.startswith("/"):
        path = "/" + path
    url = API_BASE + path
    return _SESSION.post(url, json=payload, timeout=timeout, verify=_verify)

def api_post(path: str, payload: dict, timeout: Optional[float] = 15.0) -> dict:
    """POST to /api/*, maintaining the session cookie."""
    if not path.startswith("/"):
        path = "/" + path
    url = API_BASE + (path if path.startswith("/api/") else "/api" + path)
    r = _SESSION.post(url, json=payload, timeout=timeout, verify=_verify)
    r.raise_for_status()
    return r.json()

def login(email: str, password: str, timeout: Optional[float] = 15.0) -> dict:
    """Authenticate and store the session cookie in the session jar."""
    r = _post("/auth/login", {"email": email, "password": password}, timeout=timeout)
    r.raise_for_status()
    # Cookie is now stored in _SESSION automatically
    return r.json()

def logout(timeout: Optional[float] = 10.0) -> None:
    try:
        _post("/auth/logout", {}, timeout=timeout)
    except Exception:
        pass

# ===== Base64 helpers =====
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
    _require_crypto_or_exit()
    if os.path.exists(path):
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
