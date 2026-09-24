"""SQLite connection, schema migrations, transactions, settings and events."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from typing import Any, Dict, Iterator, List, Optional

from . import config as config_module

MIGRATIONS: List[str] = [
    # 1: initial schema (PLAN.md section 4, with devices).
    """
    CREATE TABLE shards(
        id INTEGER PRIMARY KEY,
        stats_port INTEGER NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        -- 0 until its unit and relay profiles are applied successfully.
        active INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE slots(
        id INTEGER PRIMARY KEY,
        shard_id INTEGER NOT NULL REFERENCES shards(id),
        idx INTEGER NOT NULL,
        port INTEGER NOT NULL UNIQUE,
        secret TEXT NOT NULL UNIQUE,
        -- New secret of a dirty slot waiting for a successful apply.
        pending_secret TEXT NULL UNIQUE,
        status TEXT NOT NULL CHECK(status IN ('free', 'assigned', 'dirty')),
        device_id INTEGER NULL,
        UNIQUE(shard_id, idx)
    );
    CREATE TABLE users(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        tg_id INTEGER UNIQUE NULL,
        tg_username TEXT NULL,
        tg_bot_started INTEGER NOT NULL DEFAULT 0,
        tg_blocked_bot INTEGER NOT NULL DEFAULT 0,
        max_devices INTEGER NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        disabled_reason TEXT NULL CHECK(disabled_reason IN ('manual', 'expired', 'traffic_limit')),
        created_at INTEGER NOT NULL,
        created_by TEXT NOT NULL CHECK(created_by IN ('panel', 'bot_manual', 'bot_auto')),
        expires_at INTEGER NULL,
        traffic_limit_bytes INTEGER NULL,
        traffic_reset TEXT NOT NULL DEFAULT 'never' CHECK(traffic_reset IN ('never', 'monthly')),
        period_start INTEGER NOT NULL,
        period_up INTEGER NOT NULL DEFAULT 0,
        period_down INTEGER NOT NULL DEFAULT 0,
        total_up INTEGER NOT NULL DEFAULT 0,
        total_down INTEGER NOT NULL DEFAULT 0,
        last_seen_traffic_at INTEGER NULL,
        note TEXT NOT NULL DEFAULT '',
        notified_flags TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE devices(
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        slot_id INTEGER NOT NULL UNIQUE REFERENCES slots(id),
        created_at INTEGER NOT NULL,
        created_by TEXT NOT NULL CHECK(created_by IN ('panel', 'bot')),
        total_up INTEGER NOT NULL DEFAULT 0,
        total_down INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE requests(
        id INTEGER PRIMARY KEY,
        tg_id INTEGER NOT NULL,
        tg_username TEXT NULL,
        tg_name TEXT NOT NULL DEFAULT '',
        comment TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
        decided_at INTEGER NULL,
        decided_by TEXT NULL,
        admin_msg_ids TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE bans(
        tg_id INTEGER PRIMARY KEY,
        reason TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
    );
    CREATE TABLE traffic_hourly(
        user_id INTEGER NOT NULL,
        device_id INTEGER NOT NULL,
        hour INTEGER NOT NULL,
        up INTEGER NOT NULL DEFAULT 0,
        down INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(device_id, hour)
    );
    CREATE TABLE counters_last(
        port INTEGER PRIMARY KEY,
        up INTEGER NOT NULL,
        down INTEGER NOT NULL
    );
    CREATE TABLE settings(
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE events(
        id INTEGER PRIMARY KEY,
        ts INTEGER NOT NULL,
        kind TEXT NOT NULL,
        user_id INTEGER NULL,
        details TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE maintenance(
        id INTEGER PRIMARY KEY,
        ts INTEGER NOT NULL,
        kind TEXT NOT NULL,
        result TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX users_enabled ON users(enabled);
    CREATE INDEX users_expires ON users(expires_at);
    CREATE INDEX users_name ON users(name);
    CREATE INDEX devices_user ON devices(user_id);
    CREATE INDEX traffic_user_hour ON traffic_hourly(user_id, hour);
    CREATE INDEX requests_status ON requests(status);
    CREATE INDEX slots_status ON slots(status);
    CREATE INDEX events_ts ON events(ts);
    """,
]

SCHEMA_VERSION = len(MIGRATIONS)


def now() -> int:
    return int(time.time())


def connect(path: str, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        conn = sqlite3.connect("file:%s?mode=ro" % path, uri=True, isolation_level=None, timeout=5)
    else:
        conn = sqlite3.connect(path, isolation_level=None, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    if not readonly:
        conn.execute("PRAGMA journal_mode=WAL")
    return conn


def migrate(conn: sqlite3.Connection) -> int:
    """Applies pending migrations; returns the resulting schema version."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError("database schema %d is newer than this code (%d)" % (version, SCHEMA_VERSION))
    while version < SCHEMA_VERSION:
        script = MIGRATIONS[version]
        version += 1
        # executescript commits implicitly; the version bump is part of the script.
        conn.executescript("BEGIN IMMEDIATE;\n%s\nPRAGMA user_version=%d;\nCOMMIT;" % (script, version))
    return version


def open_db(path: str) -> sqlite3.Connection:
    conn = connect(path)
    migrate(conn)
    return conn


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE ... COMMIT; nested use joins the outer transaction."""
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def get_setting(conn: sqlite3.Connection, key: str) -> Any:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row is None:
        if key not in config_module.SETTINGS_DEFAULTS:
            raise KeyError(key)
        return config_module.SETTINGS_DEFAULTS[key]
    return json.loads(row["value"])


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    if key not in config_module.SETTINGS_DEFAULTS:
        raise KeyError(key)
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )


def all_settings(conn: sqlite3.Connection) -> Dict[str, Any]:
    result = dict(config_module.SETTINGS_DEFAULTS)
    for row in conn.execute("SELECT key, value FROM settings"):
        result[row["key"]] = json.loads(row["value"])
    return result


def log_event(conn: sqlite3.Connection, kind: str, user_id: Optional[int] = None, details: str = "") -> None:
    """Journal entry. Never pass secrets or links in ``details``."""
    conn.execute(
        "INSERT INTO events(ts, kind, user_id, details) VALUES(?, ?, ?, ?)",
        (now(), kind, user_id, details),
    )
