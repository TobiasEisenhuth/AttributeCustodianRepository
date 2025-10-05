import os
import sys
import msgpack
import struct
import socket
import threading
import queue
import tempfile
import getpass
from typing import Optional, Tuple, Dict

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

ERROR                 = "ERROR"

# ===== Message codec =====
def encode_msg(action: str, payload: dict) -> bytes:
    return msgpack.packb({"action": action, "payload": payload}, use_bin_type=True)

def decode_msg(data: bytes) -> dict:
    return msgpack.unpackb(data, raw=False)

def make_error(message: str) -> bytes:
    return encode_msg(ERROR, {"error": message})

# ===== Framing (length-prefixed TCP) =====
def send_msg(sock: socket.socket, msg_bytes: bytes) -> None:
    sock.sendall(struct.pack("!I", len(msg_bytes)))
    sock.sendall(msg_bytes)

def recv_msg(sock: socket.socket) -> Optional[bytes]:
    raw_len = _recvall(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    return _recvall(sock, msg_len)

def _recvall(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"Expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)

# ===== Outbound per-endpoint FIFO =====
class _OutboxWorker(threading.Thread):
    def __init__(self, endpoint: Tuple[str, int], q: "queue.Queue[tuple]"):
        super().__init__(daemon=True)
        self.endpoint = endpoint
        self.q = q

    def run(self):
        host, port = self.endpoint
        while True:
            msg_bytes, expect_reply, reply_q = self.q.get()
            try:
                with socket.create_connection((host, port)) as sock:
                    send_msg(sock, msg_bytes)
                    if expect_reply:
                        resp = recv_msg(sock)
                        reply_q.put(resp)
            except Exception as e:
                if expect_reply:
                    reply_q.put(e)
            finally:
                self.q.task_done()

class Outbox:
    def __init__(self):
        self._queues: Dict[Tuple[str, int], queue.Queue] = {}
        self._lock = threading.Lock()

    def _get_or_start(self, endpoint: Tuple[str, int]) -> queue.Queue:
        with self._lock:
            q = self._queues.get(endpoint)
            if q is None:
                q = queue.Queue()
                self._queues[endpoint] = q
                _OutboxWorker(endpoint, q).start()
        return q

    def send(self, host: str, port: int, msg_bytes: bytes, expect_reply: bool = False, timeout: Optional[float] = None):
        q = self._get_or_start((host, port))
        if not expect_reply:
            q.put((msg_bytes, False, queue.Queue()))
            return None
        r_q: "queue.Queue" = queue.Queue(maxsize=1)
        q.put((msg_bytes, True, r_q))
        result = r_q.get(timeout=timeout) if timeout is not None else r_q.get()
        if isinstance(result, Exception):
            raise result
        return result

# shared outbox instance
outbox = Outbox()

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
