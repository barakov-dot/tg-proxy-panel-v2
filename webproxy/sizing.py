"""Relay and pool sizing from CPU/RAM (PLAN.md section 9, FINDINGS.md item 3)."""

from __future__ import annotations

import math
import os
from typing import Any, Dict, List

from .config import SHARD_SIZE

MIB = 1024 * 1024

# Mirrors tproxy-server internal/session/session.go pendingControlReserve.
QUEUE_ITEM_COST = 256
FRAME_HEADER = 8
MAX_STREAMS_PER_SESSION = 128
RESERVE_ITEMS = 16 + 3 * MAX_STREAMS_PER_SESSION
RESERVE_COST = RESERVE_ITEMS * (QUEUE_ITEM_COST + FRAME_HEADER + 4)
DEFAULT_PENDING_ITEMS = 256 * 1024
MAX_PENDING_PER_SESSION = 32 * MIB

DEVICES_PER_USER = 1.2
STREAMS_PER_SESSION_ESTIMATE = 32
SHARD_RSS_ESTIMATE = 12 * MIB  # measured 8.2 MiB idle with -M 0; margin for load (M6)
RELAY_BASE_RSS_ESTIMATE = 64 * MIB
RECONNECT_GRACE = "60s"


def reserve_ok(sessions: int, pending_bytes: int, pending_items: int) -> bool:
    """Same inequality as tproxy-server ValidateBudget."""
    return RESERVE_COST <= pending_bytes // sessions and RESERVE_ITEMS <= pending_items // sessions


def pool_slots(users_target: int, devices_per_user: float = DEVICES_PER_USER) -> int:
    return int(math.ceil(users_target * devices_per_user * 1.1 / SHARD_SIZE)) * SHARD_SIZE


def compute(users_target: int, cpus: int, mem_bytes: int,
            profile_streams_per_minute: int = 300, profile_streams_burst: int = 64) -> Dict[str, Any]:
    if users_target <= 0:
        raise ValueError("Ожидаемое число пользователей должно быть положительным.")
    warnings: List[str] = []
    slots = pool_slots(users_target)
    shards = slots // SHARD_SIZE
    sessions = slots  # every slot allows at most one session
    pending = min(512 * MIB, mem_bytes // 4)
    pending = max(pending, MAX_PENDING_PER_SESSION)
    # Keep at least half of the byte budget for data.
    if sessions * RESERVE_COST * 2 > pending:
        fitting = max(1, pending // (RESERVE_COST * 2))
        warnings.append(
            "Памяти мало для %d устройств: relay рассчитан на %d одновременных сессий." % (sessions, fitting))
        sessions = fitting
    items = sessions * RESERVE_ITEMS + DEFAULT_PENDING_ITEMS
    streams = min(sessions * STREAMS_PER_SESSION_ESTIMATE, 65536)
    streams = max(streams, MAX_STREAMS_PER_SESSION)
    dials = min(256, streams)
    new_sessions_burst = max(128, sessions)
    new_bootstraps_burst = max(256, 2 * sessions)
    new_streams_burst = max(512, 4 * sessions, profile_streams_burst)
    limits = {
        "max_sessions_global": sessions,
        "max_streams_global": streams,
        "max_backend_dials_in_flight": dials,
        "max_pending_global": pending,
        "max_pending_items_global": items,
        "max_profiles": slots + SHARD_SIZE,
        "new_sessions_burst": new_sessions_burst,
        "new_sessions_per_minute": 5 * new_sessions_burst,
        "new_bootstraps_burst": new_bootstraps_burst,
        "new_bootstraps_per_minute": 5 * new_bootstraps_burst,
        "max_bootstraps_global": max(512, 2 * sessions),
        "new_streams_burst": new_streams_burst,
        "new_streams_per_minute": max(5 * new_streams_burst, profile_streams_per_minute),
    }
    if not reserve_ok(sessions, pending, items):  # pragma: no cover - guarded above
        raise AssertionError("sizing violates relay budget")
    estimated = RELAY_BASE_RSS_ESTIMATE + pending + shards * SHARD_RSS_ESTIMATE
    if estimated > mem_bytes * 0.7:
        suggested = max(16, int(users_target * (mem_bytes * 0.7) / estimated))
        warnings.append(
            "Оценка памяти %d МиБ из %d МиБ: рекомендуется не больше ~%d пользователей."
            % (estimated // MIB, mem_bytes // MIB, suggested))
    if cpus < 2 and users_target > 100:
        warnings.append("Для более чем 100 пользователей рекомендуется от 2 vCPU.")
    return {
        "users_target": users_target,
        "cpus": cpus,
        "mem_bytes": mem_bytes,
        "pool_slots": slots,
        "shards": shards,
        "relay_limits": limits,
        "relay_timeouts": {"reconnect_grace": RECONNECT_GRACE},
        "profile_limits": {
            "max_sessions": 1,
            "new_streams_per_minute": profile_streams_per_minute,
            "new_streams_burst": profile_streams_burst,
        },
        # Per-shard MTProxy -C: 16 slots, one session each, up to 128 streams.
        "mtproxy_max_connections": 4096,
        "warnings": warnings,
    }


def detect() -> Dict[str, int]:
    """CPU count and MemTotal of this Linux host."""
    mem = 0
    with open("/proc/meminfo", "r", encoding="ascii") as handle:
        for line in handle:
            if line.startswith("MemTotal:"):
                mem = int(line.split()[1]) * 1024
                break
    return {"cpus": os.cpu_count() or 1, "mem_bytes": mem}
