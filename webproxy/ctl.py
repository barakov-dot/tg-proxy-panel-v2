#!/usr/bin/python3 -I
"""wppctl: the only privileged entry point (run by webproxy through sudo).

Installed as a standalone copy at /usr/local/sbin/wppctl (root:root 0755);
it imports nothing from the webproxy package. Every argument is validated
again here; the database is opened read-only at a fixed path and only port
numbers are taken from it.

Subcommands:
  block PORT...            add to @blocked and destroy established connections
  unblock PORT...          remove from @blocked (only ports that are present)
  sync                     rebuild table inet wpp from the database (boot, pool growth)
  counters                 JSON {port: [up_bytes, down_bytes]}
  restart relay|caddy      systemctl restart
  restart|start|stop|enable|disable shard N
  install-shard-unit N     same as "enable shard N"
  daemon-reload
  status                   JSON {unit: state}
"""

import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys

DB_PATH = "/var/lib/webproxy/wpp.db"
TABLE = "wpp"
PORT_FIRST = 20000
PORT_LAST = 29999
STATS_FIRST = 19000
MAX_SHARDS = 625
PRIVATE_TCP_PORTS = "8080, 8081, 8090, %d-%d" % (STATS_FIRST, PORT_LAST)
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
KILL_CHUNK = 64

# Same rule as webproxy/pool.py BLOCKED_PORTS_SQL.
BLOCKED_PORTS_SQL = """
SELECT s.port FROM slots s
JOIN shards sh ON sh.id = s.shard_id
LEFT JOIN devices d ON d.slot_id = s.id
LEFT JOIN users u ON u.id = d.user_id
WHERE NOT (s.status = 'assigned' AND sh.active = 1 AND u.enabled = 1)
ORDER BY s.port
"""
ALL_PORTS_SQL = "SELECT port FROM slots ORDER BY port"
SHARDS_SQL = "SELECT id FROM shards ORDER BY id"

_PORT_RE = re.compile(r"^[0-9]{5}$")
_SHARD_RE = re.compile(r"^(0|[1-9][0-9]{0,2})$")


class CtlError(Exception):
    pass


def tool(name):
    path = shutil.which(name, path=SAFE_PATH)
    if not path:
        raise CtlError("%s not found" % name)
    return path


def run(argv, stdin=None, check=True):
    proc = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                          env={"PATH": SAFE_PATH, "LC_ALL": "C"}, timeout=120)
    if check and proc.returncode != 0:
        raise CtlError("%s: %s" % (os.path.basename(argv[0]), proc.stderr.strip()[:300]))
    return proc


def parse_port(value):
    if not _PORT_RE.match(value):
        raise CtlError("invalid port")
    port = int(value)
    if not PORT_FIRST <= port <= PORT_LAST:
        raise CtlError("port out of range")
    return port


def parse_shard(value):
    if not _SHARD_RE.match(value) or int(value) >= MAX_SHARDS:
        raise CtlError("invalid shard")
    return int(value)


def parse_ports(values):
    if not values:
        raise CtlError("no ports")
    return sorted(set(parse_port(v) for v in values))


# --- ruleset ----------------------------------------------------------------

def _elements(values):
    return ", ".join(values)


def build_ruleset(ports, blocked):
    """nft script that atomically replaces table inet wpp."""
    ports = sorted(set(ports))
    blocked = sorted(set(blocked) & set(ports))
    lines = ["table inet %s" % TABLE, "delete table inet %s" % TABLE, "table inet %s {" % TABLE]
    for port in ports:
        lines.append("  counter c%d_up { }" % port)
        lines.append("  counter c%d_down { }" % port)
    # Same shapes as verified on nft 1.0.9 by tools/verify/nft-ss.sh.
    set_elements = " elements = { %s }" % _elements(map(str, blocked)) if blocked else ""
    lines.append("  set blocked { type inet_service;%s }" % set_elements)
    for direction in ("up", "down"):
        if ports:
            mapping = _elements('%d : "c%d_%s"' % (port, port, direction) for port in ports)
            lines.append("  map cnt_%s { type inet_service : counter; elements = { %s } }" % (direction, mapping))
        else:
            lines.append("  map cnt_%s { type inet_service : counter; }" % direction)
    lines += [
        "  chain out {",
        "    type filter hook output priority -10; policy accept;",
        '    oifname "lo" tcp dport @blocked reject with tcp reset',
        '    oifname "lo" tcp dport %d-%d counter name tcp dport map @cnt_up' % (PORT_FIRST, PORT_LAST),
        "  }",
        "  chain in {",
        "    type filter hook input priority -10; policy accept;",
        '    iifname "lo" tcp sport %d-%d counter name tcp sport map @cnt_down' % (PORT_FIRST, PORT_LAST),
        '    iifname != "lo" tcp dport { %s } drop' % PRIVATE_TCP_PORTS,
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def parse_counters(data):
    result = {}
    for item in data.get("nftables", []):
        counter = item.get("counter")
        if not counter:
            continue
        match = re.match(r"^c([0-9]{5})_(up|down)$", counter.get("name", ""))
        if not match:
            continue
        pair = result.setdefault(int(match.group(1)), [0, 0])
        pair[0 if match.group(2) == "up" else 1] = int(counter.get("bytes", 0))
    return result


def parse_set_elements(data):
    result = set()
    for item in data.get("nftables", []):
        found = item.get("set")
        if not found or found.get("name") != "blocked":
            continue
        for element in found.get("elem", []) or []:
            if isinstance(element, int):
                result.add(element)
            elif isinstance(element, dict) and "range" in element:
                low, high = element["range"]
                result.update(range(int(low), int(high) + 1))
    return result


def kill_filters(ports):
    """ss filters destroying established TCP sockets on both ends of the ports."""
    ports = sorted(ports)
    for start in range(0, len(ports), KILL_CHUNK):
        chunk = ports[start:start + KILL_CHUNK]
        terms = " or ".join("sport = :%d or dport = :%d" % (p, p) for p in chunk)
        yield "( %s )" % terms


# --- actions ----------------------------------------------------------------

def current_blocked():
    proc = run([tool("nft"), "-j", "list", "set", "inet", TABLE, "blocked"], check=False)
    if proc.returncode != 0:
        return None
    return parse_set_elements(json.loads(proc.stdout))


def kill(ports):
    for expression in kill_filters(ports):
        run([tool("ss"), "-K", "-tn", "state", "established", expression], check=False)


def cmd_block(args):
    ports = parse_ports(args)
    run([tool("nft"), "add", "element", "inet", TABLE, "blocked", "{ %s }" % _elements(map(str, ports))])
    kill(ports)


def cmd_unblock(args):
    ports = parse_ports(args)
    present = current_blocked()
    if present is None:
        raise CtlError("table inet wpp is missing; run sync")
    remove = [p for p in ports if p in present]
    if remove:
        run([tool("nft"), "delete", "element", "inet", TABLE, "blocked", "{ %s }" % _elements(map(str, remove))])


def _query_db(path):
    conn = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=10)
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        ports = [int(r[0]) for r in conn.execute(ALL_PORTS_SQL)]
        blocked = [int(r[0]) for r in conn.execute(BLOCKED_PORTS_SQL)]
        shards = [int(r[0]) for r in conn.execute(SHARDS_SQL)]
    finally:
        conn.close()
    return ports, blocked, shards


def read_db(path=DB_PATH):
    """Reads the database as its owner.

    Opening a WAL database as root could create root-owned -wal/-shm files that
    the webproxy services then cannot write, so the query runs in a child
    process that has dropped to the owner of the database file.
    """
    owner = os.lstat(path)
    if not stat.S_ISREG(owner.st_mode):
        raise CtlError("database is not a regular file")
    if os.geteuid() != 0 or owner.st_uid == 0:
        ports, blocked, shards = _query_db(path)
    else:
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:  # child
            status = 1
            try:
                os.close(read_fd)
                os.setgroups([])
                os.setgid(owner.st_gid)
                os.setuid(owner.st_uid)
                payload = json.dumps(_query_db(path)).encode("ascii")
                with os.fdopen(write_fd, "wb") as handle:
                    handle.write(payload)
                status = 0
            finally:
                os._exit(status)
        os.close(write_fd)
        with os.fdopen(read_fd, "rb") as handle:
            payload = handle.read()
        _, status = os.waitpid(pid, 0)
        if status != 0:
            raise CtlError("cannot read the database")
        ports, blocked, shards = json.loads(payload.decode("ascii"))
    ports = [int(p) for p in ports]
    blocked = [int(p) for p in blocked]
    shards = [int(p) for p in shards]
    for port in ports:
        if not PORT_FIRST <= port <= PORT_LAST:
            raise CtlError("database contains an invalid port")
    for shard in shards:
        if not 0 <= shard < MAX_SHARDS:
            raise CtlError("database contains an invalid shard")
    return ports, blocked, shards


def cmd_sync(args):
    if args:
        raise CtlError("sync takes no arguments")
    if os.path.exists(DB_PATH):
        ports, blocked, _ = read_db()
    else:
        ports, blocked = [], []
    before = current_blocked()
    run([tool("nft"), "-f", "-"], stdin=build_ruleset(ports, blocked))
    # Ports that were open before and are closed now lose their connections.
    if before is not None:
        kill(set(blocked) - before)


def cmd_counters(args):
    if args:
        raise CtlError("counters takes no arguments")
    proc = run([tool("nft"), "-j", "list", "counters", "table", "inet", TABLE])
    print(json.dumps(parse_counters(json.loads(proc.stdout)), sort_keys=True))


def unit_for(kind, rest):
    if kind == "relay" and not rest:
        return "wpp-relay.service"
    if kind == "caddy" and not rest:
        return "wpp-caddy.service"
    if kind == "shard" and len(rest) == 1:
        return "wpp-mtproxy@%d.service" % parse_shard(rest[0])
    raise CtlError("invalid unit")


def cmd_systemctl(verb, args):
    if not args:
        raise CtlError("missing unit")
    unit = unit_for(args[0], args[1:])
    if verb in ("start", "stop", "enable", "disable") and not unit.startswith("wpp-mtproxy@"):
        raise CtlError("only shards can be %sd" % verb)
    run([tool("systemctl"), verb, unit])


def cmd_status(args):
    if args:
        raise CtlError("status takes no arguments")
    units = ["wpp-caddy.service", "wpp-relay.service", "wpp-panel.service", "wpp-bot.service",
             "wpp-worker.timer", "wpp-refresh.timer", "wpp-firewall.service"]
    if os.path.exists(DB_PATH):
        units += ["wpp-mtproxy@%d.service" % shard for shard in read_db()[2]]
    result = {}
    for unit in units:
        proc = run([tool("systemctl"), "is-active", unit], check=False)
        result[unit] = proc.stdout.strip() or "unknown"
    print(json.dumps(result, sort_keys=True))


def main(argv):
    if not argv:
        raise CtlError("usage: wppctl COMMAND [ARGS]")
    command, args = argv[0], argv[1:]
    if command == "block":
        cmd_block(args)
    elif command == "unblock":
        cmd_unblock(args)
    elif command == "sync":
        cmd_sync(args)
    elif command == "counters":
        cmd_counters(args)
    elif command in ("restart", "start", "stop", "enable", "disable"):
        cmd_systemctl(command, args)
    elif command == "install-shard-unit" and len(args) == 1:
        cmd_systemctl("enable", ["shard", args[0]])
    elif command == "daemon-reload" and not args:
        run([tool("systemctl"), "daemon-reload"])
    elif command == "status":
        cmd_status(args)
    else:
        raise CtlError("unknown command")


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.stderr.write("wppctl: must run as root\n")
        sys.exit(1)
    try:
        main(sys.argv[1:])
    except CtlError as error:
        sys.stderr.write("wppctl: %s\n" % error)
        sys.exit(1)
