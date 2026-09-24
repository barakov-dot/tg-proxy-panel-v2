"""User and device business logic shared by the panel, the bot and the worker.

Knows nothing about HTTP or Telegram. Each operation runs in one database
transaction; firewall changes are made just before COMMIT, so if ``wppctl``
fails the transaction rolls back and the database keeps matching the firewall.
(If COMMIT itself fails after a successful block, the port stays closed — the
safe direction; ``wppctl sync`` restores the exact state from the database.)

Messages of ``UserError`` are shown to people as is (Russian).
"""

from __future__ import annotations

import contextlib
import sqlite3
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import config as config_module
from . import db, links, pool

DAY = 86400
MAX_NAME = 64
CREATED_BY = ("panel", "bot_manual", "bot_auto")
DISABLED_REASONS = ("manual", "expired", "traffic_limit")
RESETS = ("never", "monthly")


class UserError(ValueError):
    pass


@contextlib.contextmanager
def _change(conn: sqlite3.Connection, system: Any) -> Iterator[None]:
    """A transaction whose firewall calls are undone on failure.

    wppctl calls happen before COMMIT. If anything fails after one of them
    (a later wppctl call, COMMIT itself), the database rolls back and the
    firewall is rebuilt from the committed state.
    """
    if conn.in_transaction:
        yield
        return
    calls_before = _firewall_calls(system)
    try:
        with db.transaction(conn):
            yield
    except BaseException:
        if _firewall_calls(system) != calls_before:
            try:
                system.sync_firewall()
            except Exception:
                pass
        raise


def _firewall_calls(system: Any) -> int:
    return getattr(system, "firewall_calls", 0)


def _user(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise UserError("Пользователь не найден.")
    return row


def _device(conn: sqlite3.Connection, device_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT d.*, s.port, s.secret FROM devices d JOIN slots s ON s.id = d.slot_id WHERE d.id = ?",
        (device_id,)).fetchone()
    if row is None:
        raise UserError("Устройство не найдено.")
    return row


def _device_ports(conn: sqlite3.Connection, user_id: int) -> List[int]:
    return [row[0] for row in conn.execute(
        "SELECT s.port FROM devices d JOIN slots s ON s.id = d.slot_id WHERE d.user_id = ? ORDER BY s.port",
        (user_id,))]


def _clean_name(name: str) -> str:
    name = " ".join((name or "").split())
    if not name:
        raise UserError("Имя не может быть пустым.")
    if len(name) > MAX_NAME:
        raise UserError("Имя длиннее %d символов." % MAX_NAME)
    return name


def max_devices(conn: sqlite3.Connection, user: sqlite3.Row) -> int:
    if user["max_devices"] is not None:
        return int(user["max_devices"])
    return int(db.get_setting(conn, "default_max_devices"))


def _attach_device(conn: sqlite3.Connection, user_id: int, name: Optional[str], created_by: str) -> Tuple[int, int]:
    """Creates a device on a clean free slot. Returns (device_id, port)."""
    slot = pool.take_free_slot(conn, device_id=None)
    count = conn.execute("SELECT COUNT(*) FROM devices WHERE user_id = ?", (user_id,)).fetchone()[0]
    device_name = _clean_name(name) if name else "Устройство %d" % (count + 1)
    cursor = conn.execute(
        "INSERT INTO devices(user_id, name, slot_id, created_at, created_by) VALUES(?, ?, ?, ?, ?)",
        (user_id, device_name, slot["id"], db.now(), created_by))
    device_id = cursor.lastrowid
    conn.execute("UPDATE slots SET device_id = ? WHERE id = ?", (device_id, slot["id"]))
    return device_id, slot["port"]


def create_user(conn: sqlite3.Connection, system: Any, *, name: str, created_by: str = "panel",
                tg_id: Optional[int] = None, tg_username: Optional[str] = None,
                expires_at: Optional[int] = None, traffic_limit_bytes: Optional[int] = None,
                traffic_reset: str = "never", note: str = "", max_devices_value: Optional[int] = None,
                device_name: Optional[str] = None) -> Tuple[int, int]:
    """Creates a user with the first device. Returns (user_id, device_id).

    Raises pool.NoFreeSlots when no clean slot is available (the caller offers
    an immediate expansion or queues the request, PLAN.md section 2).
    """
    name = _clean_name(name)
    if created_by not in CREATED_BY:
        raise ValueError("created_by")
    if traffic_reset not in RESETS:
        raise UserError("Неизвестный тип сброса трафика.")
    if traffic_limit_bytes is not None and traffic_limit_bytes <= 0:
        raise UserError("Лимит трафика должен быть положительным.")
    if max_devices_value is not None and max_devices_value < 1:
        raise UserError("Лимит устройств должен быть не меньше 1.")
    timestamp = db.now()
    with _change(conn, system):
        if tg_id is not None and conn.execute("SELECT 1 FROM users WHERE tg_id = ?", (tg_id,)).fetchone():
            raise UserError("Пользователь с таким Telegram ID уже есть.")
        cursor = conn.execute(
            "INSERT INTO users(name, tg_id, tg_username, max_devices, enabled, created_at, created_by, "
            "expires_at, traffic_limit_bytes, traffic_reset, period_start, note) "
            "VALUES(?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
            (name, tg_id, tg_username, max_devices_value, timestamp, created_by, expires_at,
             traffic_limit_bytes, traffic_reset, timestamp, note or ""))
        user_id = cursor.lastrowid
        device_id, port = _attach_device(conn, user_id, device_name, "bot" if created_by != "panel" else "panel")
        db.log_event(conn, "user_created", user_id, "by=%s device=%d" % (created_by, device_id))
        system.unblock([port])
    return user_id, device_id


def add_device(conn: sqlite3.Connection, system: Any, user_id: int, created_by: str = "panel",
               name: Optional[str] = None) -> int:
    if created_by not in ("panel", "bot"):
        raise ValueError("created_by")
    with _change(conn, system):
        user = _user(conn, user_id)
        if created_by == "bot" and not user["enabled"]:
            raise UserError("Доступ отключён: новое устройство добавить нельзя.")
        limit = max_devices(conn, user)
        count = conn.execute("SELECT COUNT(*) FROM devices WHERE user_id = ?", (user_id,)).fetchone()[0]
        if count >= limit:
            raise UserError("Достигнут лимит устройств: %d." % limit)
        device_id, port = _attach_device(conn, user_id, name, created_by)
        db.log_event(conn, "device_added", user_id, "device=%d by=%s" % (device_id, created_by))
        if user["enabled"]:
            system.unblock([port])
    return device_id


def delete_device(conn: sqlite3.Connection, system: Any, device_id: int, by: str = "panel") -> None:
    with _change(conn, system):
        device = _device(conn, device_id)
        pool.release_slot(conn, device["slot_id"])
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        db.log_event(conn, "device_deleted", device["user_id"], "device=%d by=%s" % (device_id, by))
        system.block([device["port"]])


def rotate_device(conn: sqlite3.Connection, system: Any, device_id: int) -> None:
    """New link: the device moves to a clean slot, the old one becomes dirty."""
    with _change(conn, system):
        device = _device(conn, device_id)
        user = _user(conn, device["user_id"])
        slot = pool.take_free_slot(conn, device_id=device_id)
        pool.release_slot(conn, device["slot_id"])
        conn.execute("UPDATE devices SET slot_id = ? WHERE id = ?", (slot["id"], device_id))
        db.log_event(conn, "device_rotated", device["user_id"], "device=%d" % device_id)
        system.block([device["port"]])
        if user["enabled"]:
            system.unblock([slot["port"]])


def rename_device(conn: sqlite3.Connection, device_id: int, name: str) -> None:
    with db.transaction(conn):
        _device(conn, device_id)
        conn.execute("UPDATE devices SET name = ? WHERE id = ?", (_clean_name(name), device_id))


def disable_user(conn: sqlite3.Connection, system: Any, user_id: int, reason: str = "manual") -> bool:
    """Returns False if the user was already disabled."""
    if reason not in DISABLED_REASONS:
        raise ValueError("reason")
    with _change(conn, system):
        user = _user(conn, user_id)
        if not user["enabled"]:
            return False
        conn.execute("UPDATE users SET enabled = 0, disabled_reason = ? WHERE id = ?", (reason, user_id))
        db.log_event(conn, "user_disabled", user_id, "reason=%s" % reason)
        system.block(_device_ports(conn, user_id))
    return True


def enable_user(conn: sqlite3.Connection, system: Any, user_id: int) -> bool:
    """Returns False if the user was already enabled."""
    with _change(conn, system):
        user = _user(conn, user_id)
        if user["enabled"]:
            return False
        conn.execute("UPDATE users SET enabled = 1, disabled_reason = NULL WHERE id = ?", (user_id,))
        db.log_event(conn, "user_enabled", user_id)
        system.unblock(_device_ports(conn, user_id))
    return True


def _limit_reached(user: sqlite3.Row) -> bool:
    limit = user["traffic_limit_bytes"]
    return limit is not None and user["period_up"] + user["period_down"] >= limit


def _expired(user: sqlite3.Row, timestamp: int) -> bool:
    return user["expires_at"] is not None and user["expires_at"] <= timestamp


def _maybe_reenable(conn: sqlite3.Connection, system: Any, user_id: int, reason: str) -> None:
    user = _user(conn, user_id)
    if user["enabled"] or user["disabled_reason"] != reason:
        return
    if _expired(user, db.now()) or _limit_reached(user):
        return
    conn.execute("UPDATE users SET enabled = 1, disabled_reason = NULL WHERE id = ?", (user_id,))
    db.log_event(conn, "user_enabled", user_id, "after=%s" % reason)
    system.unblock(_device_ports(conn, user_id))


def set_expiry(conn: sqlite3.Connection, system: Any, user_id: int, expires_at: Optional[int],
               enable_now: bool = True) -> None:
    with _change(conn, system):
        _user(conn, user_id)
        conn.execute("UPDATE users SET expires_at = ? WHERE id = ?", (expires_at, user_id))
        db.log_event(conn, "user_expiry_set", user_id, "expires_at=%s" % (expires_at or "never"))
        if enable_now:
            _maybe_reenable(conn, system, user_id, "expired")


def extend(conn: sqlite3.Connection, system: Any, user_id: int, days: int, enable_now: bool = True) -> int:
    """Adds ``days`` from max(now, current expiry). Returns the new expiry."""
    if days <= 0:
        raise UserError("Число дней должно быть положительным.")
    with _change(conn, system):
        user = _user(conn, user_id)
        base = max(db.now(), user["expires_at"] or 0)
        expires_at = base + days * DAY
        set_expiry(conn, system, user_id, expires_at, enable_now)
    return expires_at


def set_traffic_limit(conn: sqlite3.Connection, system: Any, user_id: int, limit_bytes: Optional[int],
                      reset: str = "never", enable_now: bool = True) -> None:
    if reset not in RESETS:
        raise UserError("Неизвестный тип сброса трафика.")
    if limit_bytes is not None and limit_bytes <= 0:
        raise UserError("Лимит трафика должен быть положительным.")
    with _change(conn, system):
        _user(conn, user_id)
        conn.execute("UPDATE users SET traffic_limit_bytes = ?, traffic_reset = ? WHERE id = ?",
                     (limit_bytes, reset, user_id))
        db.log_event(conn, "user_limit_set", user_id, "limit=%s reset=%s" % (limit_bytes or "none", reset))
        if enable_now:
            _maybe_reenable(conn, system, user_id, "traffic_limit")


def update_profile(conn: sqlite3.Connection, user_id: int, *, name: Optional[str] = None,
                   tg_id: Any = ..., tg_username: Any = ..., note: Optional[str] = None,
                   max_devices_value: Any = ...) -> None:
    """Changes descriptive fields. ``...`` means "leave as is"; None clears."""
    with db.transaction(conn):
        _user(conn, user_id)
        if name is not None:
            conn.execute("UPDATE users SET name = ? WHERE id = ?", (_clean_name(name), user_id))
        if tg_id is not ...:
            if tg_id is not None and conn.execute(
                    "SELECT 1 FROM users WHERE tg_id = ? AND id != ?", (tg_id, user_id)).fetchone():
                raise UserError("Пользователь с таким Telegram ID уже есть.")
            conn.execute("UPDATE users SET tg_id = ?, tg_bot_started = 0, tg_blocked_bot = 0 WHERE id = ?",
                         (tg_id, user_id))
        if tg_username is not ...:
            conn.execute("UPDATE users SET tg_username = ? WHERE id = ?", (tg_username, user_id))
        if note is not None:
            conn.execute("UPDATE users SET note = ? WHERE id = ?", (note, user_id))
        if max_devices_value is not ...:
            if max_devices_value is not None and max_devices_value < 1:
                raise UserError("Лимит устройств должен быть не меньше 1.")
            conn.execute("UPDATE users SET max_devices = ? WHERE id = ?", (max_devices_value, user_id))
        db.log_event(conn, "user_updated", user_id)


def delete_user(conn: sqlite3.Connection, system: Any, user_id: int) -> None:
    with _change(conn, system):
        _user(conn, user_id)
        ports = _device_ports(conn, user_id)
        for row in conn.execute("SELECT slot_id FROM devices WHERE user_id = ?", (user_id,)).fetchall():
            pool.release_slot(conn, row["slot_id"])
        conn.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.log_event(conn, "user_deleted", user_id)
        system.block(ports)


def devices(conn: sqlite3.Connection, user_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT d.*, s.port, s.secret FROM devices d JOIN slots s ON s.id = d.slot_id "
        "WHERE d.user_id = ? ORDER BY d.id", (user_id,)).fetchall()


def device_link(cfg: config_module.Config, device: sqlite3.Row) -> Dict[str, str]:
    """Link and manual-entry fields for one device. Show to the owner/admin only."""
    return {
        "link": links.build(cfg.domain, cfg.base_path, device["secret"]),
        "server": links.client_server(cfg.domain, cfg.base_path),
        "secret": links.client_secret(device["secret"], cfg.base_path),
    }
