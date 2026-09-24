"""Shards and slots: assignment, dirty-slot rotation, pool growth, and applying
the generated relay/MTProxy configuration with verification and rollback.

Slot lifecycle: free -> assigned -> dirty -> (new secret, apply) -> free.
New secrets and new shards are *staged* in the database (``pending_secret``,
``shards.active = 0``) and become effective only after ``apply`` succeeds, so a
failed apply never leaves the database describing processes that do not run.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import secrets
import sqlite3
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set

from . import config as config_module
from . import db
from .config import SHARD_SIZE

# Ports that must be closed: every slot except assigned slots of enabled users
# on active shards. ctl.py runs the same query as root (keep them in sync).
BLOCKED_PORTS_SQL = """
SELECT s.port FROM slots s
JOIN shards sh ON sh.id = s.shard_id
LEFT JOIN devices d ON d.slot_id = s.id
LEFT JOIN users u ON u.id = d.user_id
WHERE NOT (s.status = 'assigned' AND sh.active = 1 AND u.enabled = 1)
ORDER BY s.port
"""

ALL_PORTS_SQL = "SELECT port FROM slots ORDER BY port"


class PoolError(RuntimeError):
    """User-facing failure of a pool operation (Russian message)."""


class NoFreeSlots(PoolError):
    pass


def _new_secret(conn: sqlite3.Connection) -> str:
    while True:
        value = secrets.token_hex(16)
        row = conn.execute(
            "SELECT 1 FROM slots WHERE secret = ? OR pending_secret = ?", (value, value)).fetchone()
        if row is None:
            return value


# --- queries ----------------------------------------------------------------

def blocked_ports(conn: sqlite3.Connection) -> List[int]:
    return [row[0] for row in conn.execute(BLOCKED_PORTS_SQL)]


def counts(conn: sqlite3.Connection) -> Dict[str, int]:
    result = {"free": 0, "assigned": 0, "dirty": 0, "pending": 0}
    for row in conn.execute(
            "SELECT s.status, COUNT(*) FROM slots s JOIN shards sh ON sh.id = s.shard_id "
            "WHERE sh.active = 1 GROUP BY s.status"):
        result[row[0]] = row[1]
    result["pending"] = conn.execute("SELECT COUNT(*) FROM slots WHERE pending_secret IS NOT NULL").fetchone()[0]
    result["shards"] = conn.execute("SELECT COUNT(*) FROM shards WHERE active = 1").fetchone()[0]
    result["slots"] = result["shards"] * SHARD_SIZE
    return result


def low_water(conn: sqlite3.Connection) -> int:
    """Clean free slots below this number trigger growth in the maintenance window."""
    return max(SHARD_SIZE, counts(conn)["slots"] // 10)


def needs_maintenance(conn: sqlite3.Connection) -> bool:
    current = counts(conn)
    return current["dirty"] > 0 or current["free"] < low_water(conn)


# --- mutations (call inside db.transaction) ---------------------------------

def create_shards(conn: sqlite3.Connection, count: int) -> List[int]:
    """Adds ``count`` inactive shards with fresh free slots; returns their ids."""
    if count <= 0:
        return []
    row = conn.execute("SELECT MAX(id) FROM shards").fetchone()
    first = 0 if row[0] is None else row[0] + 1
    if first + count > config_module.MAX_SHARDS:
        raise PoolError("Достигнут предел пула: %d шардов." % config_module.MAX_SHARDS)
    created = []
    timestamp = db.now()
    for shard in range(first, first + count):
        conn.execute("INSERT INTO shards(id, stats_port, created_at, active) VALUES(?, ?, ?, 0)",
                     (shard, config_module.stats_port(shard), timestamp))
        for idx in range(SHARD_SIZE):
            conn.execute(
                "INSERT INTO slots(shard_id, idx, port, secret, status) VALUES(?, ?, ?, ?, 'free')",
                (shard, idx, config_module.slot_port(shard, idx), _new_secret(conn)))
        created.append(shard)
    return created


def take_free_slot(conn: sqlite3.Connection, device_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT s.* FROM slots s JOIN shards sh ON sh.id = s.shard_id "
        "WHERE s.status = 'free' AND sh.active = 1 ORDER BY s.id LIMIT 1").fetchone()
    if row is None:
        raise NoFreeSlots("Нет свободных чистых слотов.")
    conn.execute("UPDATE slots SET status = 'assigned', device_id = ? WHERE id = ?", (device_id, row["id"]))
    return conn.execute("SELECT * FROM slots WHERE id = ?", (row["id"],)).fetchone()


def release_slot(conn: sqlite3.Connection, slot_id: int) -> None:
    """The secret may have leaked: the slot is never handed out again as is."""
    conn.execute("UPDATE slots SET status = 'dirty', device_id = NULL WHERE id = ?", (slot_id,))


def stage_dirty(conn: sqlite3.Connection) -> Set[int]:
    """Gives every dirty slot a pending secret; returns the shards to restart."""
    shards = set()
    for row in conn.execute("SELECT id, shard_id, pending_secret FROM slots WHERE status = 'dirty'").fetchall():
        if row["pending_secret"] is None:
            conn.execute("UPDATE slots SET pending_secret = ? WHERE id = ?", (_new_secret(conn), row["id"]))
        shards.add(row["shard_id"])
    return shards


def commit_staged(conn: sqlite3.Connection) -> None:
    conn.execute(
        "UPDATE slots SET secret = pending_secret, pending_secret = NULL, status = 'free' "
        "WHERE pending_secret IS NOT NULL AND status = 'dirty'")
    conn.execute("UPDATE shards SET active = 1 WHERE active = 0")


def abort_staged(conn: sqlite3.Connection) -> None:
    conn.execute("UPDATE slots SET pending_secret = NULL WHERE pending_secret IS NOT NULL")
    conn.execute("DELETE FROM slots WHERE shard_id IN (SELECT id FROM shards WHERE active = 0)")
    conn.execute("DELETE FROM shards WHERE active = 0")


# --- rendering ----------------------------------------------------------------

def render_profiles(conn: sqlite3.Connection, profile_limits: Dict[str, int]) -> Dict[str, Any]:
    profiles = []
    for row in conn.execute("SELECT * FROM slots ORDER BY port"):
        profiles.append({
            "name": config_module.profile_name(row["shard_id"], row["idx"]),
            "secret": row["pending_secret"] or row["secret"],
            "backend": "127.0.0.1:%d" % row["port"],
            "limits": dict(profile_limits),
        })
    return {"profiles": profiles}


def render_shard_env(conn: sqlite3.Connection, cfg: config_module.Config, shard: int) -> str:
    rows = conn.execute("SELECT * FROM slots WHERE shard_id = ? ORDER BY idx", (shard,)).fetchall()
    if len(rows) != SHARD_SIZE:
        raise PoolError("Шард %d неполный." % shard)
    ports = ",".join(str(row["port"]) for row in rows)
    secret_args = " ".join("-S " + (row["pending_secret"] or row["secret"]) for row in rows)
    nat = "--nat-info " + cfg.nat_info if cfg.nat_info else ""
    lines = [
        "# Generated by webproxy; do not edit.",
        "WPP_STATS_PORT=%d" % config_module.stats_port(shard),
        "WPP_PORTS=%s" % ports,
        "WPP_SECRET_ARGS=%s" % secret_args,
        "WPP_NAT_ARGS=%s" % nat,
        "WPP_MAX_CONNECTIONS=%d" % cfg.mtproxy_max_connections,
    ]
    return "\n".join(lines) + "\n"


def render_relay_config(cfg: config_module.Config, sizing: Dict[str, Any], profile_count: int) -> Dict[str, Any]:
    limits = dict(sizing["relay_limits"])
    # The pool may have grown past the installation-time estimate.
    limits["max_profiles"] = max(int(limits.get("max_profiles", 0)), profile_count)
    return {
        "public_hostname": cfg.domain,
        "base_path": cfg.base_path,
        "listen": config_module.RELAY_LISTEN,
        "admin_listen": config_module.RELAY_ADMIN,
        "public_dir": cfg.paths.site_dir,
        "static_routes": "exact",
        "token_key_file": cfg.paths.token_key,
        "profiles_file": cfg.paths.profiles,
        "limits": limits,
        "timeouts": dict(sizing["relay_timeouts"]),
    }


def shard_env_path(cfg: config_module.Config, shard: int) -> str:
    return os.path.join(cfg.paths.shards_dir, "%d.env" % shard)


def load_sizing(cfg: config_module.Config) -> Dict[str, Any]:
    with open(cfg.paths.sizing, "r", encoding="utf-8") as handle:
        return json.load(handle)


# --- apply ------------------------------------------------------------------

@contextlib.contextmanager
def apply_lock(cfg: config_module.Config) -> Iterator[None]:
    path = os.path.join(cfg.paths.lib_dir, "pool.lock")
    with open(path, "a") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _sync_firewall(conn: sqlite3.Connection, system: Any) -> None:
    """Rebuilds the nft table while holding the write lock, so no user operation
    is between its own wppctl call and its COMMIT (ctl reads committed state)."""
    with db.transaction(conn):
        system.sync_firewall()


def apply(conn: sqlite3.Connection, cfg: config_module.Config, system: Any,
          sizing: Dict[str, Any], restart_shards: Iterable[int] = (),
          new_shards: Sequence[int] = ()) -> None:
    """Writes staged state to relay/MTProxy files, restarts, verifies, commits.

    Steps: render -> relay -check on candidates -> save old files -> write ->
    (new shards: firewall sync, enable units) -> restart shards and relay ->
    wait for /healthz and shard /stats -> commit staged DB state.
    Any failure restores the previous files, restarts again, aborts the staged
    state and raises PoolError. Every relay restart drops all carrier sessions:
    callers decide when that is allowed.
    """
    paths = cfg.paths
    new_shards = list(new_shards)
    shards = sorted(set(restart_shards) | set(new_shards))
    profiles = render_profiles(conn, sizing["profile_limits"])
    relay_config = render_relay_config(cfg, sizing, len(profiles["profiles"]))
    envs = {shard: render_shard_env(conn, cfg, shard).encode("utf-8") for shard in shards}

    candidate_profiles = paths.profiles + ".new"
    candidate_config = paths.relay_config + ".new"
    system.write_file(candidate_profiles, _dump(profiles))
    system.write_file(candidate_config, _dump(relay_config))
    try:
        ok, message = system.relay_check(candidate_config, candidate_profiles)
    finally:
        system.remove_file(candidate_profiles)
        system.remove_file(candidate_config)
    if not ok:
        with db.transaction(conn):
            abort_staged(conn)
        raise PoolError("Проверка конфигурации relay не прошла: %s" % message)

    targets = {paths.profiles: _dump(profiles), paths.relay_config: _dump(relay_config)}
    for shard, data in envs.items():
        targets[shard_env_path(cfg, shard)] = data
    previous = {path: system.read_file(path) for path in targets}

    def restore() -> None:
        for path, data in previous.items():
            if data is None:
                system.remove_file(path)
            else:
                system.write_file(path, data)

    try:
        for path, data in targets.items():
            system.write_file(path, data)
        if new_shards:
            _sync_firewall(conn, system)
            for shard in new_shards:
                system.enable_shard(shard)
        for shard in shards:
            system.restart_shard(shard)
        system.restart_relay()
        if not system.wait_healthy(shards, relay=True):
            raise PoolError("Relay или шарды не поднялись после применения конфигурации.")
    except Exception as error:
        # Best effort from here on: one failing step must not skip the rest.
        try:
            restore()
        except Exception:
            pass
        for shard in new_shards:
            try:
                system.stop_shard(shard)
                system.disable_shard(shard)
            except Exception:
                pass
        with db.transaction(conn):
            abort_staged(conn)
        try:
            for shard in shards:
                if shard not in new_shards:
                    system.restart_shard(shard)
            system.restart_relay()
        except Exception:
            pass
        if new_shards:
            try:
                _sync_firewall(conn, system)
            except Exception:
                pass
        if isinstance(error, PoolError):
            raise
        raise PoolError("Не удалось применить конфигурацию: %s" % error) from None

    with db.transaction(conn):
        commit_staged(conn)
        db.log_event(conn, "pool_applied", details="shards=%s new=%s" % (
            ",".join(map(str, shards)) or "-", ",".join(map(str, new_shards)) or "-"))


def maintain(conn: sqlite3.Connection, cfg: config_module.Config, system: Any,
             sizing: Dict[str, Any], grow_shards: Optional[int] = None) -> Dict[str, int]:
    """Rotates dirty slots and grows the pool if clean free slots are low.

    ``grow_shards`` forces the number of shards to add (None = automatic).
    Returns a small report for the admin notification.
    """
    with apply_lock(cfg):
        with db.transaction(conn):
            # Leftovers of an apply interrupted by a crash: inactive shards were
            # never started, so discard them and stage everything again.
            abort_staged(conn)
            restart = stage_dirty(conn)
            current = counts(conn)
            free_after = current["free"] + current["dirty"]
            if grow_shards is None:
                missing = max(0, low_water(conn) - free_after)
                grow_shards = (missing + SHARD_SIZE - 1) // SHARD_SIZE
            new = create_shards(conn, grow_shards)
        if not restart and not new:
            return {"rotated": 0, "new_shards": 0}
        rotated = conn.execute("SELECT COUNT(*) FROM slots WHERE pending_secret IS NOT NULL").fetchone()[0]
        apply(conn, cfg, system, sizing, restart_shards=restart, new_shards=new)
        return {"rotated": rotated, "new_shards": len(new)}
