import msgpack
import struct
import socket
import threading
import queue
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
ADD_OR_UPDATE_SECRET = "ADD_OR_UPDATE_SECRET"
DELETE_SECRET        = "DELETE_SECRET"
GRANT_ACCESS_PROXY   = "GRANT_ACCESS_PROXY"
GRANT_ACCESS_RECEIVER= "GRANT_ACCESS_RECEIVER"
REVOKE_ACCESS        = "REVOKE_ACCESS"

# Ursula (proxy) -> Bob
RESPONSE_SECRET      = "RESPONSE_SECRET"

# Bob
REQUEST_ACCESS       = "REQUEST_ACCESS"
REQUEST_SECRET       = "REQUEST_SECRET"

ERROR                = "ERROR"

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
    def __init__(self, endpoint: Tuple[str, int], q: "queue.Queue[Tuple[bytes, bool, queue.Queue]]"):
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
