#!/usr/bin/env bash
# Verifies on a real server (FINDINGS.md, items 2, 3, 4 and 6), against the pinned relay:
#   - -check budget boundary: control reserve x max_sessions_global vs
#     max_pending_global / max_pending_items_global matches our formula;
#   - 1000+ profiles load, max_profiles is enforced;
#   - /readyz is 503 when any profile backend refuses connections, /healthz stays 200;
#   - per-profile limits.max_sessions caps live sessions of one profile;
#   - a stream to a refused backend gets CLOSE while the session stays alive;
#   - per-profile new_streams_* limits keep a failing profile from draining the
#     global stream-creation bucket.
# Builds the relay in a temporary directory (Go is downloaded there if missing)
# and removes everything on exit.
# Usage: sudo bash tools/verify/relay-check.sh
set -euo pipefail

relay_commit=acc252ece3a25c29e9b83f608499a5567a33ab2a
go_version=1.26.5
go_checksum=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053

if [[ "${EUID}" -ne 0 ]]; then
	echo "FAIL: запустите от root"
	exit 1
fi
for required in curl python3 sha256sum tar; do
	if ! command -v "$required" >/dev/null 2>&1; then
		echo "FAIL: нет команды $required"
		exit 1
	fi
done

work="$(mktemp -d /tmp/wpp-verify-relay.XXXXXX)"
cleanup() {
	# Go module cache is read-only by default; make it removable.
	chmod -R u+w "$work" >/dev/null 2>&1 || true
	rm -rf -- "$work"
}
trap cleanup EXIT

go_binary=
for candidate in "$(command -v go 2>/dev/null || true)" /opt/go*/bin/go; do
	if [[ -n "$candidate" && -x "$candidate" ]]; then
		version="$("$candidate" env GOVERSION 2>/dev/null || true)"
		if [[ "$version" =~ ^go1\.([0-9]+) ]] && ((BASH_REMATCH[1] >= 20)); then
			go_binary="$candidate"
			break
		fi
	fi
done
if [[ -z "$go_binary" ]]; then
	echo "INFO: Go >= 1.20 не найден, скачивание go${go_version} во временный каталог"
	curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
		--output "$work/go.tar.gz" "https://go.dev/dl/go${go_version}.linux-amd64.tar.gz"
	if [[ "$(sha256sum "$work/go.tar.gz" | awk '{print $1}')" != "$go_checksum" ]]; then
		echo "FAIL: SHA256 архива Go не совпадает"
		exit 1
	fi
	tar -C "$work" -xzf "$work/go.tar.gz"
	go_binary="$work/go/bin/go"
fi
echo "INFO: Go: $("$go_binary" env GOVERSION)"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
	--output "$work/relay.tar.gz" \
	"https://github.com/telegramdesktop/tproxy-server/archive/${relay_commit}.tar.gz"
echo "INFO: SHA256 архива tproxy-server ${relay_commit}: $(sha256sum "$work/relay.tar.gz" | awk '{print $1}')"
mkdir "$work/src"
tar -C "$work/src" --strip-components=1 -xzf "$work/relay.tar.gz"
export GOPATH="$work/gopath" GOCACHE="$work/gocache" GOMODCACHE="$work/gopath/pkg/mod"
echo "INFO: сборка relay"
if (cd "$work/src" && "$go_binary" build -trimpath -o "$work/tproxy-server" ./cmd/tproxy-server) >"$work/build.log" 2>&1; then
	echo "PASS: relay собран"
else
	tail -n 30 "$work/build.log"
	echo "FAIL: сборка relay не удалась"
	exit 1
fi

cat > "$work/check.py" <<'PY'
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

WORK = sys.argv[1]
BINARY = os.path.join(WORK, "tproxy-server")
HOST = "verify.example.com"
LISTEN = ("127.0.0.1", 29880)
ADMIN = ("127.0.0.1", 29881)
LIVE_BACKEND = 29870
DEAD_BACKEND = 29871
results = []

# Mirrors internal/session/session.go pendingControlReserve with default limits.
QUEUE_ITEM_COST = 256
FRAME_HEADER = 8
RESERVE_ITEMS = 16 + 3 * 128
RESERVE_COST = RESERVE_ITEMS * (QUEUE_ITEM_COST + FRAME_HEADER + 4)


def report(ok, text):
    results.append(ok)
    print(("PASS" if ok else "FAIL") + ": " + text, flush=True)


def info(text):
    print("INFO: " + text, flush=True)


os.makedirs(os.path.join(WORK, "site"), exist_ok=True)
with open(os.path.join(WORK, "site", "index.html"), "w") as handle:
    handle.write("<!doctype html><title>verify</title>\n")
key_path = os.path.join(WORK, "token.key")
with open(key_path, "wb") as handle:
    handle.write(os.urandom(32))
os.chmod(key_path, 0o600)


def write_config(name, limits=None, timeouts=None, profiles=None, profile_count=1):
    config = {
        "public_hostname": HOST,
        "listen": "%s:%d" % LISTEN,
        "admin_listen": "%s:%d" % ADMIN,
        "public_dir": os.path.join(WORK, "site"),
        "static_routes": "exact",
        "token_key_file": key_path,
        "profiles_file": os.path.join(WORK, name + ".profiles.json"),
    }
    if limits:
        config["limits"] = limits
    if timeouts:
        config["timeouts"] = timeouts
    if profiles is None:
        profiles = [{"name": "p%04d" % i, "secret": secrets.token_hex(16),
                     "backend": "127.0.0.1:%d" % (20000 + i % 16)} for i in range(profile_count)]
    path = os.path.join(WORK, name + ".json")
    with open(path, "w") as handle:
        json.dump(config, handle)
    with open(config["profiles_file"], "w") as handle:
        json.dump({"profiles": profiles}, handle)
    os.chmod(config["profiles_file"], 0o600)
    return path


def check(path):
    proc = subprocess.run([BINARY, "-config", path, "-check"], capture_output=True, text=True)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def budget_tests():
    info("резерв на сессию по формуле: %d байт, %d элементов" % (RESERVE_COST, RESERVE_ITEMS))
    items_default = 256 * 1024
    edge = items_default // RESERVE_ITEMS
    ok_edge, _ = check(write_config("items_ok", {"max_sessions_global": edge}))
    ok_over, text = check(write_config("items_over", {"max_sessions_global": edge + 1}))
    report(ok_edge and not ok_over,
           "предел по max_pending_items_global (по умолчанию): %d сессий проходит, %d — нет" % (edge, edge + 1))
    if not ok_over:
        info("сообщение relay: " + text.splitlines()[-1])
    pending = RESERVE_COST * 1000
    limits = {"max_pending_global": pending, "max_pending_items_global": 10 ** 7}
    ok_edge, _ = check(write_config("cost_ok", dict(limits, max_sessions_global=1000)))
    ok_over, _ = check(write_config("cost_over", dict(limits, max_sessions_global=1001)))
    report(ok_edge and not ok_over,
           "предел по max_pending_global = резерв x 1000: 1000 сессий проходит, 1001 — нет")
    started = time.monotonic()
    ok_many, text = check(write_config("profiles_ok", {"max_profiles": 1024}, profile_count=1024))
    elapsed = time.monotonic() - started
    report(ok_many, "1024 профиля при max_profiles=1024 проходят -check (%.2f с)" % elapsed)
    if not ok_many:
        info(text)
    ok_over, _ = check(write_config("profiles_over", {"max_profiles": 1023}, profile_count=1024))
    report(not ok_over, "1024 профиля при max_profiles=1023 отклоняются")


class Listener:
    def __init__(self, port):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self.conns = []
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(conn)

    def close(self):
        self.sock.close()
        for conn in self.conns:
            conn.close()


def http(method, path, headers=None, body=None, admin=False, timeout=10):
    address = ADMIN if admin else LISTEN
    request = urllib.request.Request("http://%s:%d%s" % (address[0], address[1], path),
                                     data=body, method=method)
    if not admin:
        request.add_header("Host", HOST)
        request.add_header("X-Forwarded-For", "198.51.100.7")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def capability(secret_hex):
    import base64
    import hashlib
    import hmac
    digest = hmac.new(bytes.fromhex(secret_hex), ("tdesktop-web-proxy-bridge-v1\n" + HOST).encode(),
                      hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def frame(kind, stream, payload=b""):
    return struct.pack(">BBHI", kind, stream >> 16, stream & 0xFFFF, len(payload)) + payload


def parse_frames(data):
    frames = []
    while len(data) >= 8:
        kind = data[0]
        stream = int.from_bytes(data[1:4], "big")
        length = int.from_bytes(data[4:8], "big")
        frames.append((kind, stream, data[8:8 + length]))
        data = data[8 + length:]
    return frames


def create_session(secret_hex):
    status, _, body = http("GET", "/?bridge=" + capability(secret_hex))
    match = re.search(rb'bootstrap="([A-Za-z0-9_-]{43})"', body)
    if status != 200 or not match:
        return None, "bridge %d" % status
    token = match.group(1).decode()
    status, headers, _ = http("POST", "/api/v1/session",
                              {"Authorization": "Bearer " + token,
                               "Content-Type": "application/octet-stream"},
                              frame(0x10, 0, b"\x01"))
    if status != 200:
        return None, "session %d" % status
    return headers.get("X-Session-Token"), "ok"


def up(session, sequence, payload):
    status, _, _ = http("POST", "/api/v1/up", {"Authorization": "Bearer " + session,
                                               "X-Up-Seq": str(sequence),
                                               "Content-Type": "application/octet-stream"}, payload)
    return status


def down_until(session, want_closed, deadline=15):
    cursor = 0
    closed = set()
    end = time.monotonic() + deadline
    while time.monotonic() < end and not want_closed <= closed:
        status, headers, body = http("POST", "/api/v1/down", {"Authorization": "Bearer " + session,
                                                              "X-Down-Cursor": str(cursor)}, None)
        if status not in (200, 204):
            break
        cursor = int(headers.get("X-Down-Cursor", cursor))
        for kind, stream, _ in parse_frames(body):
            if kind == 0x03:
                closed.add(stream)
    return closed


def metrics():
    _, _, body = http("GET", "/metrics", admin=True)
    values = {}
    for line in body.decode().splitlines():
        name, _, value = line.partition(" ")
        values[name] = int(value)
    return values


def runtime_tests():
    live_secret = secrets.token_hex(16)
    dead_secret = secrets.token_hex(16)
    profiles = [
        {"name": "live", "secret": live_secret, "backend": "127.0.0.1:%d" % LIVE_BACKEND,
         "limits": {"max_sessions": 2}},
        {"name": "dead", "secret": dead_secret, "backend": "127.0.0.1:%d" % DEAD_BACKEND,
         "limits": {"new_streams_per_minute": 6, "new_streams_burst": 5}},
    ]
    path = write_config("runtime", {"new_streams_per_minute": 6, "new_streams_burst": 20},
                        {"long_poll": "2s"}, profiles)
    listener = Listener(LIVE_BACKEND)
    relay = subprocess.Popen([BINARY, "-config", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                if http("GET", "/healthz", admin=True)[0] == 200:
                    break
            except OSError:
                time.sleep(0.1)
        status = http("GET", "/healthz", admin=True)[0]
        report(status == 200, "/healthz = %d при недоступном backend одного профиля" % status)
        status = http("GET", "/readyz", admin=True)[0]
        report(status == 503, "/readyz = %d, когда backend одного профиля отвергает подключения" % status)

        # Per-profile max_sessions.
        first, _ = create_session(live_secret)
        second, _ = create_session(live_secret)
        third, why = create_session(live_secret)
        report(bool(first and second) and third is None and why == "session 503",
               "limits.max_sessions=2: третья сессия профиля получает 503 (%s)" % why)
        status = http("DELETE", "/api/v1/session", {"Authorization": "Bearer " + first})[0]
        third, why = create_session(live_secret)
        report(status == 204 and third is not None, "после DELETE одной сессии новая создаётся")

        # Streams to a refused backend.
        before = metrics()
        dead, why = create_session(dead_secret)
        report(dead is not None, "сессия профиля с недоступным backend создаётся (%s)" % why)
        batch = b"".join(frame(0x01, stream) for stream in range(1, 11))
        status = up(dead, 1, batch)
        closed = down_until(dead, set(range(1, 11)))
        report(status == 204 and closed == set(range(1, 11)),
               "10 OPEN к отвергающему backend: все 10 потоков получили CLOSE")
        status = up(dead, 2, frame(0x01, 11))
        report(status == 204, "сессия жива после отказов: следующий OPEN принят (%d)" % status)
        down_until(dead, {11})
        after = metrics()
        failures = after["tproxy_backend_dial_failures_total"] - before["tproxy_backend_dial_failures_total"]
        rejected = after["tproxy_streams_rejected_total"] - before["tproxy_streams_rejected_total"]
        info("dial_failures +%d, streams_rejected +%d" % (failures, rejected))
        report(failures in (5, 6) and rejected >= 5,
               "лимит профиля new_streams_burst=5: 5 попыток дошли до backend, остальные отклонены relay")

        # The global bucket (burst 20) must have lost only the 5 admitted dials.
        before = metrics()
        status = up(third, 1, b"".join(frame(0x01, stream) for stream in range(1, 15)))
        time.sleep(1)
        after = metrics()
        opened = after["tproxy_streams_opened_total"] - before["tproxy_streams_opened_total"]
        rejected = after["tproxy_streams_rejected_total"] - before["tproxy_streams_rejected_total"]
        report(status == 204 and opened == 14 and rejected == 0,
               "другой профиль открыл 14 потоков из глобального запаса 20-6: отказы профиля не расходуют глобальный лимит (opened=%d, rejected=%d)" % (opened, rejected))

        listener2 = Listener(DEAD_BACKEND)
        status = http("GET", "/readyz", admin=True)[0]
        report(status == 200, "/readyz = %d, когда все backend-ы принимают подключения" % status)
        listener2.close()
    finally:
        relay.terminate()
        try:
            relay.wait(10)
        except subprocess.TimeoutExpired:
            relay.kill()
        listener.close()


try:
    budget_tests()
    runtime_tests()
except Exception as error:
    report(False, "непредвиденная ошибка: %r" % error)
print("ИТОГ: " + ("PASS" if results and all(results) else "FAIL"))
sys.exit(0 if results and all(results) else 1)
PY

python3 "$work/check.py" "$work"
