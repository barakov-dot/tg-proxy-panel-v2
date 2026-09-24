#!/usr/bin/env bash
# M1 acceptance on the test stand (after tools/dev/bringup.sh), without a Telegram client:
#   - two test users get relay sessions and streams to their MTProxy ports;
#   - disabling user A closes A's live stream within seconds, B is untouched;
#   - A's new streams are refused while disabled and work again after enabling;
#   - a second concurrent session on one link is refused (max_sessions = 1);
#   - rotating A's link: the old link stops working, the new one works.
# Creates users "verify-A"/"verify-B" and deletes them at the end (their slots
# become dirty and are rotated by the next maintenance).
# Usage: sudo bash /opt/webproxy/src/tools/verify/m1-core.sh
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "FAIL: запустите от root"
	exit 1
fi
src="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d /tmp/wpp-verify-m1.XXXXXX)"
chmod 0755 "$work"
trap 'rm -rf -- "$work"' EXIT

cat > "$work/check.py" <<'PY'
import os
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, sys.argv[1])
from webproxy import config as config_module  # noqa: E402
from webproxy import db, links, system, users  # noqa: E402

results = []


def report(ok, text):
    results.append(ok)
    print(("PASS" if ok else "FAIL") + ": " + text, flush=True)


cfg = config_module.load()
conn = db.open_db(cfg.paths.db)
sys_ = system.System(cfg)
BASE = "/" + cfg.base_path + "/" if cfg.base_path else "/"


def http(method, path, headers=None, body=None, timeout=10):
    request = urllib.request.Request("http://127.0.0.1:8080" + path, data=body, method=method)
    request.add_header("Host", cfg.domain)
    request.add_header("X-Forwarded-For", "198.51.100.23")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()
    except (socket.timeout, TimeoutError, urllib.error.URLError):
        return 0, {}, b""


def frame(kind, stream, payload=b""):
    return struct.pack(">BBHI", kind, stream >> 16, stream & 0xFFFF, len(payload)) + payload


def parse(data):
    out = []
    while len(data) >= 8:
        length = int.from_bytes(data[4:8], "big")
        out.append((data[0], int.from_bytes(data[1:4], "big")))
        data = data[8 + length:]
    return out


class Client:
    def __init__(self, secret_hex):
        self.secret = secret_hex
        self.token = None
        self.seq = 0
        self.cursor = 0
        self.closed = set()

    def connect(self):
        capability = links.capability(cfg.domain, cfg.base_path, bytes.fromhex(self.secret))
        status, _, body = http("GET", BASE + "?bridge=" + capability)
        match = re.search(rb'bootstrap="([A-Za-z0-9_-]{43})"', body)
        if status != 200 or not match:
            return "bridge %d" % status
        status, headers, _ = http("POST", BASE + "api/v1/session",
                                  {"Authorization": "Bearer " + match.group(1).decode(),
                                   "Content-Type": "application/octet-stream"}, frame(0x10, 0, b"\x01"))
        if status != 200:
            return "session %d" % status
        self.token = headers["X-Session-Token"]
        return "ok"

    def up(self, payload):
        self.seq += 1
        status, _, _ = http("POST", BASE + "api/v1/up", {"Authorization": "Bearer " + self.token,
                                                         "X-Up-Seq": str(self.seq),
                                                         "Content-Type": "application/octet-stream"}, payload)
        return status

    def open(self, stream):
        # OPEN plus some bytes: stock MTProxy keeps a bad client connection open.
        return self.up(frame(0x01, stream) + frame(0x02, stream, os.urandom(64)))

    def poll(self, seconds):
        """Collects CLOSE frames for up to ``seconds``."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            status, headers, body = http("POST", BASE + "api/v1/down",
                                         {"Authorization": "Bearer " + self.token,
                                          "X-Down-Cursor": str(self.cursor)},
                                         None, timeout=max(1, end - time.monotonic()))
            if status == 200:
                self.cursor = int(headers.get("X-Down-Cursor", self.cursor))
                self.closed.update(s for kind, s in parse(body) if kind == 0x03)
            elif status not in (0, 204):
                break
        return self.closed

    def close(self):
        if self.token:
            http("DELETE", BASE + "api/v1/session", {"Authorization": "Bearer " + self.token})


def secret_of(user_id):
    return users.devices(conn, user_id)[0]["secret"]


for name in ("verify-A", "verify-B"):
    row = conn.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchone()
    if row:
        users.delete_user(conn, sys_, row["id"])

a_id, a_dev = users.create_user(conn, sys_, name="verify-A")
b_id, _ = users.create_user(conn, sys_, name="verify-B")
clients = []
try:
    a = Client(secret_of(a_id))
    b = Client(secret_of(b_id))
    clients += [a, b]
    report(a.connect() == "ok" and b.connect() == "ok", "сессии A и B созданы через relay")
    report(a.open(1) == 204 and b.open(1) == 204, "потоки A и B открыты")
    a.poll(3)
    b.poll(3)
    report(1 not in a.closed and 1 not in b.closed, "потоки живы через 3 с (MTProxy держит соединения)")

    second = Client(secret_of(b_id))
    clients.append(second)
    report(second.connect() == "session 503", "вторая одновременная сессия по ссылке B отклонена (503)")

    started = time.monotonic()
    users.disable_user(conn, sys_, a_id)
    a.poll(5)
    elapsed = time.monotonic() - started
    report(1 in a.closed, "после выключения A его поток закрыт (%.1f с)" % elapsed)
    b.poll(2)
    report(1 not in b.closed, "поток B не затронут выключением A")
    a.open(2)
    a.poll(3)
    report(2 in a.closed, "новый поток выключенного A сразу закрыт")

    users.enable_user(conn, sys_, a_id)
    a.open(3)
    a.poll(3)
    report(3 not in a.closed, "после включения A новый поток работает")

    old_secret = secret_of(a_id)
    users.rotate_device(conn, sys_, a_dev)
    a.poll(3)
    report(3 in a.closed, "после перевыпуска ссылки поток на старом слоте закрыт")
    fresh = Client(secret_of(a_id))
    clients.append(fresh)
    report(fresh.connect() == "ok" and fresh.open(1) == 204, "новая ссылка A: сессия и поток созданы")
    fresh.poll(3)
    report(1 not in fresh.closed, "поток по новой ссылке жив")
    report(secret_of(a_id) != old_secret, "секрет после перевыпуска другой")
finally:
    for client in clients:
        client.close()
    for user_id in (a_id, b_id):
        try:
            users.delete_user(conn, sys_, user_id)
        except users.UserError:
            pass

print("ИТОГ: " + ("PASS" if results and all(results) else "FAIL"))
sys.exit(0 if results and all(results) else 1)
PY

cd /
runuser -u webproxy -- env PYTHONDONTWRITEBYTECODE=1 python3 "$work/check.py" "$src"
