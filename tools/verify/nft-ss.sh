#!/usr/bin/env bash
# Verifies on a real server (FINDINGS.md, items 1 and 5):
#   - nftables syntax of the planned "inet wpp" table (named counters via map);
#   - per-port byte counters on loopback count each direction exactly once;
#   - "reject with tcp reset" on output refuses new loopback connections at once;
#   - adding counters/map elements to a live table works (pool growth);
#   - "ss -K" destroys established loopback connections of one port only.
# Uses temporary tables inet wpp_verify*, ports 29990-29992; removes everything on exit.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "FAIL: запустите от root"
	exit 1
fi
for required in nft ss python3; do
	if ! command -v "$required" >/dev/null 2>&1; then
		echo "FAIL: нет команды $required (apt-get install -y nftables iproute2 python3)"
		exit 1
	fi
done

work="$(mktemp -d /tmp/wpp-verify-nft.XXXXXX)"
cleanup() {
	nft delete table inet wpp_verify >/dev/null 2>&1 || true
	rm -rf -- "$work"
}
trap cleanup EXIT

cat > "$work/check.py" <<'PY'
import json
import os
import socket
import subprocess
import sys
import threading
import time

TABLE = "wpp_verify"
PORTS = (29990, 29991)
EXTRA_PORT = 29992
results = []


def report(ok, text):
    results.append(ok)
    print(("PASS" if ok else "FAIL") + ": " + text, flush=True)


def info(text):
    print("INFO: " + text, flush=True)


def nft(*args, stdin=None, check=True):
    proc = subprocess.run(["nft", *args], input=stdin, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError("nft %s: %s" % (" ".join(args), proc.stderr.strip()))
    return proc


def port_busy(port):
    out = subprocess.run(["ss", "-Htan", "( sport = :%d or dport = :%d )" % (port, port)],
                         capture_output=True, text=True).stdout
    return bool(out.strip())


# Production-shaped ruleset: syntax check only, never applied.
PRODUCTION = """
table inet wpp_verify_syntax {
  set blocked { type inet_service; }
  map cnt_up { type inet_service : counter; }
  map cnt_down { type inet_service : counter; }
  chain out {
    type filter hook output priority -10; policy accept;
    oifname "lo" tcp dport @blocked reject with tcp reset
    oifname "lo" tcp dport 20000-29999 counter name tcp dport map @cnt_up
  }
  chain in {
    type filter hook input priority -10; policy accept;
    iifname "lo" tcp sport 20000-29999 counter name tcp sport map @cnt_down
    iifname != "lo" tcp dport { 8080, 8081, 8090, 19000-29999 } drop
  }
}
"""

# Fallback from the plan: one rule per port referencing a named counter.
FALLBACK = """
table inet wpp_verify_fallback {
  counter c20000_up { }
  chain out {
    type filter hook output priority -10; policy accept;
    oifname "lo" tcp dport 20000 counter name "c20000_up"
  }
}
"""


def counters():
    data = json.loads(nft("-j", "list", "counters", "table", "inet", TABLE).stdout)
    values = {}
    for item in data.get("nftables", []):
        counter = item.get("counter")
        if counter:
            values[counter["name"]] = counter["bytes"]
    return values


class Server:
    """Loopback listener: mode byte 'C' = read all then send 50000 bytes; 'E' = echo."""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    @staticmethod
    def handle(conn):
        try:
            mode = conn.recv(1)
            if mode == b"C":
                while conn.recv(65536):
                    pass
                conn.sendall(b"d" * 50000)
            elif mode == b"E":
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()


def connect(port, timeout=2.0):
    return socket.create_connection(("127.0.0.1", port), timeout=timeout)


def main():
    proc = nft("--version")
    info("версия nft: " + proc.stdout.strip())
    info("ядро: " + os.uname().release)
    config = "/boot/config-" + os.uname().release
    if os.path.exists(config):
        with open(config) as handle:
            line = [l.strip() for l in handle if l.startswith("CONFIG_INET_DIAG_DESTROY")]
        info("%s: %s" % (config, line[0] if line else "CONFIG_INET_DIAG_DESTROY не найден"))

    for port in PORTS + (EXTRA_PORT,):
        if port_busy(port):
            report(False, "порт %d занят, освободите его и повторите" % port)
            return

    proc = nft("-c", "-f", "-", stdin=PRODUCTION, check=False)
    report(proc.returncode == 0, "синтаксис плановой таблицы (counter name ... map @cnt) принят"
           + ("" if proc.returncode == 0 else ": " + proc.stderr.strip()))
    proc = nft("-c", "-f", "-", stdin=FALLBACK, check=False)
    report(proc.returncode == 0, "запасной синтаксис (правило на порт с counter name) принят"
           + ("" if proc.returncode == 0 else ": " + proc.stderr.strip()))

    elements_up = ", ".join('%d : "c%d_up"' % (p, p) for p in PORTS)
    elements_down = ", ".join('%d : "c%d_down"' % (p, p) for p in PORTS)
    objects = "".join("  counter c%d_up { }\n  counter c%d_down { }\n" % (p, p) for p in PORTS)
    ruleset = """
table inet %(t)s {
%(objects)s
  set blocked { type inet_service; }
  map cnt_up { type inet_service : counter; elements = { %(up)s } }
  map cnt_down { type inet_service : counter; elements = { %(down)s } }
  chain out {
    type filter hook output priority -10; policy accept;
    oifname "lo" tcp dport @blocked reject with tcp reset
    oifname "lo" tcp dport 29990-29992 counter name tcp dport map @cnt_up
  }
  chain in {
    type filter hook input priority -10; policy accept;
    iifname "lo" tcp sport 29990-29992 counter name tcp sport map @cnt_down
  }
}
""" % {"t": TABLE, "objects": objects, "up": elements_up, "down": elements_down}
    nft("delete", "table", "inet", TABLE, check=False)
    proc = nft("-f", "-", stdin=ruleset, check=False)
    report(proc.returncode == 0, "тестовая таблица применена"
           + ("" if proc.returncode == 0 else ": " + proc.stderr.strip()))
    if proc.returncode != 0:
        return

    servers = [Server(p) for p in PORTS]

    # Counters: 100000 bytes up, 50000 bytes down on port 29990.
    before = counters()
    client = connect(PORTS[0])
    client.sendall(b"C" + b"u" * 100000)
    client.shutdown(socket.SHUT_WR)
    received = 0
    while True:
        data = client.recv(65536)
        if not data:
            break
        received += len(data)
    client.close()
    time.sleep(0.3)
    after = counters()
    up = after["c29990_up"] - before["c29990_up"]
    down = after["c29990_down"] - before["c29990_down"]
    info("счётчики 29990: up=%d байт, down=%d байт (полезная нагрузка 100001 / %d)" % (up, down, received))
    report(100001 <= up < 130000, "счётчик up учитывает отправку ровно один раз")
    report(50000 <= down < 80000, "счётчик down учитывает приём ровно один раз")
    other = after["c29991_up"] - before["c29991_up"] + after["c29991_down"] - before["c29991_down"]
    report(other == 0, "соседний порт 29991 не получил чужой трафик")

    # Keep an established connection on 29991 to prove it survives actions on 29990.
    neighbour = connect(PORTS[1])
    neighbour.sendall(b"E")
    victim = connect(PORTS[0])
    victim.sendall(b"Ehello")
    victim.settimeout(3)
    report(victim.recv(16) == b"hello", "установленное соединение на 29990 работает")

    # Block: new connections must be refused at once.
    nft("add", "element", "inet", TABLE, "blocked", "{ 29990 }")
    started = time.monotonic()
    try:
        connect(PORTS[0]).close()
        refused = False
    except ConnectionRefusedError:
        refused = True
    except OSError as error:
        refused = False
        info("ошибка подключения: %r" % error)
    elapsed = time.monotonic() - started
    report(refused and elapsed < 1.0, "новое подключение к заблокированному порту отклонено за %.3f с" % elapsed)

    # ss -K: destroy the established connection of the blocked port only.
    proc = subprocess.run(["ss", "-K", "-tn", "state", "established",
                           "( sport = :29990 or dport = :29990 )"], capture_output=True, text=True)
    info("ss -K завершился с кодом %d" % proc.returncode)
    killed = False
    try:
        victim.sendall(b"x")
        data = victim.recv(16)
        killed = data == b""
    except socket.timeout:
        killed = False
    except OSError as error:
        killed = True
        info("соединение 29990 оборвано: %s" % type(error).__name__)
    report(killed, "ss -K оборвал установленное соединение на 29990")
    victim.close()
    left = subprocess.run(["ss", "-Htn", "state", "established", "( sport = :29990 or dport = :29990 )"],
                          capture_output=True, text=True).stdout.strip()
    report(left == "", "после ss -K на 29990 не осталось установленных сокетов")

    neighbour.settimeout(3)
    neighbour.sendall(b"alive")
    report(neighbour.recv(16) == b"alive", "соединение на соседнем порту 29991 не затронуто")
    neighbour.close()

    # Unblock: new connections work again.
    nft("delete", "element", "inet", TABLE, "blocked", "{ 29990 }")
    try:
        probe = connect(PORTS[0])
        probe.sendall(b"Eok")
        probe.settimeout(3)
        report(probe.recv(16) == b"ok", "после удаления из @blocked подключение снова работает")
        probe.close()
    except OSError as error:
        report(False, "после разблокировки подключение не работает: %r" % error)

    # Deleting a missing element fails: wppctl must treat that case explicitly.
    proc = nft("delete", "element", "inet", TABLE, "blocked", "{ 29990 }", check=False)
    info("удаление отсутствующего элемента: код %d (%s)" % (proc.returncode, proc.stderr.strip()[:120]))

    # Pool growth on a live table: new counters and map elements.
    try:
        nft("add", "counter", "inet", TABLE, "c29992_up")
        nft("add", "counter", "inet", TABLE, "c29992_down")
        nft("add", "element", "inet", TABLE, "cnt_up", '{ 29992 : "c29992_up" }')
        nft("add", "element", "inet", TABLE, "cnt_down", '{ 29992 : "c29992_down" }')
        extra = Server(EXTRA_PORT)
        probe = connect(EXTRA_PORT)
        probe.sendall(b"E" + b"z" * 1000)
        probe.settimeout(3)
        got = 0
        while got < 1000:
            got += len(probe.recv(65536))
        probe.close()
        time.sleep(0.3)
        values = counters()
        report(values.get("c29992_up", 0) >= 1001 and values.get("c29992_down", 0) >= 1000,
               "счётчики, добавленные в живую таблицу, считают трафик")
        extra.sock.close()
    except (RuntimeError, OSError) as error:
        report(False, "добавление счётчиков в живую таблицу: %s" % error)

    for server in servers:
        server.sock.close()


try:
    main()
except Exception as error:  # report instead of a traceback
    report(False, "непредвиденная ошибка: %r" % error)
print("ИТОГ: " + ("PASS" if results and all(results) else "FAIL"))
sys.exit(0 if results and all(results) else 1)
PY

python3 "$work/check.py"
