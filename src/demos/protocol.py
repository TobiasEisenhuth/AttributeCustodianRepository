import msgpack
import struct
import socket

SENDER_HOST = "localhost"
SENDER_PORT = 5000
PROXY_HOST = "localhost"
PROXY_PORT = 6000
RECEIVER_HOST = "localhost"
RECEIVER_PORT = 7000

# Alice
ADD_OR_UPDATE_SECRET = "ADD_OR_UPDATE_SECRET"
DELETE_SECRET = "DELETE_SECRET"
GRANT_ACCESS_PROXY = "GRANT_ACCESS_PROXY"
GRANT_ACCESS_RECEIVER = "GRANT_ACCESS_RECEIVER"
REVOKE_ACCESS = "REVOKE_ACCESS"

# Ursula (proxy) -> Bob
RESPONSE_SECRET = "RESPONSE_SECRET"

# Bob
REQUEST_ACCESS = "REQUEST_ACCESS"
REQUEST_SECRET = "REQUEST_SECRET"

ERROR = "ERROR"

def encode_msg(action: str, payload: dict) -> bytes:
    return msgpack.packb({"action": action, "payload": payload}, use_bin_type=True)

def decode_msg(data: bytes) -> dict:
    return msgpack.unpackb(data, raw=False)

def make_error(message: str) -> bytes:
    return encode_msg(ERROR, {"error": message})

# ---- Framing helpers (length-prefixed TCP) ----
def send_msg(sock: socket.socket, msg_bytes: bytes) -> None:
    sock.sendall(struct.pack("!I", len(msg_bytes)))
    sock.sendall(msg_bytes)

def recv_msg(sock: socket.socket) -> bytes | None:
    raw_len = _recvall(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    return _recvall(sock, msg_len)

def _recvall(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"Expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)
