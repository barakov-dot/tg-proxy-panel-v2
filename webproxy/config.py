"""Installation config (paths, domain) and panel settings defaults.

The installation config is a JSON file written by the installer
(/etc/webproxy/config.json). Every path can be overridden there, which is how
tests point everything at temporary directories. Mutable panel settings live in
the database (``settings`` table); ``SETTINGS_DEFAULTS`` lists them.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

DEFAULT_CONFIG_PATH = "/etc/webproxy/config.json"
CONFIG_ENV = "WPP_CONFIG"

SHARD_SIZE = 16
SLOT_PORT_BASE = 20000
SLOT_PORT_LAST = 29999
STATS_PORT_BASE = 19000
MAX_SHARDS = (SLOT_PORT_LAST - SLOT_PORT_BASE + 1) // SHARD_SIZE

RELAY_LISTEN = "127.0.0.1:8080"
RELAY_ADMIN = "127.0.0.1:8081"
PANEL_LISTEN = "127.0.0.1:8090"

SETTINGS_DEFAULTS: Dict[str, Any] = {
    # Access requests (bot).
    "approval_mode": "manual",
    "requests_enabled": True,
    "request_cooldown_hours": 24,
    "request_ttl_days": 7,
    "requests_per_hour": 30,
    "default_days": 30,
    "default_traffic_limit_bytes": None,
    "default_traffic_reset": "never",
    "default_max_devices": 1,
    "emergency_expand": "ask",
    # Bot.
    "bot_token": "",
    "bot_username": "",
    "admin_tg_ids": [],
    "notify": {},
    # Pool and maintenance.
    "maintenance_time": "04:30",
    # Per-profile stream creation limits (FINDINGS item 6).
    "profile_new_streams_per_minute": 300,
    "profile_new_streams_burst": 64,
}


@dataclass
class Paths:
    etc_dir: str = "/etc/webproxy"
    lib_dir: str = "/var/lib/webproxy"
    opt_dir: str = "/opt/webproxy"

    db: str = ""
    relay_config: str = ""
    profiles: str = ""
    token_key: str = ""
    shards_dir: str = ""
    sizing: str = ""
    site_dir: str = ""
    backups_dir: str = ""
    mtproxy_dir: str = ""
    relay_bin: str = ""
    mtproxy_bin: str = ""
    wppctl: str = "/usr/local/sbin/wppctl"
    sudo: str = "/usr/bin/sudo"
    qrencode: str = "/usr/bin/qrencode"

    def resolve(self) -> "Paths":
        defaults = {
            "db": os.path.join(self.lib_dir, "wpp.db"),
            "relay_config": os.path.join(self.etc_dir, "relay.json"),
            "profiles": os.path.join(self.etc_dir, "profiles.json"),
            "token_key": os.path.join(self.etc_dir, "token.key"),
            "shards_dir": os.path.join(self.etc_dir, "shards"),
            "sizing": os.path.join(self.etc_dir, "sizing.json"),
            "site_dir": os.path.join(self.lib_dir, "site"),
            "backups_dir": os.path.join(self.lib_dir, "backups"),
            "mtproxy_dir": os.path.join(self.lib_dir, "mtproxy"),
            "relay_bin": os.path.join(self.opt_dir, "bin", "tproxy-server"),
            "mtproxy_bin": os.path.join(self.opt_dir, "bin", "mtproto-proxy"),
        }
        for name, value in defaults.items():
            if not getattr(self, name):
                setattr(self, name, value)
        return self


@dataclass
class Config:
    domain: str = ""
    base_path: str = ""
    panel_path: str = ""
    # "--nat-info <local>:<public>" parts, empty on a directly addressed host.
    nat_info: str = ""
    mtproxy_max_connections: int = 4096
    paths: Paths = field(default_factory=Paths)

    @property
    def relay_admin_url(self) -> str:
        return "http://" + RELAY_ADMIN


def load(path: Optional[str] = None) -> Config:
    path = path or os.environ.get(CONFIG_ENV) or DEFAULT_CONFIG_PATH
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return from_dict(data)


def from_dict(data: Dict[str, Any]) -> Config:
    paths_data = dict(data.get("paths") or {})
    known = set(Paths.__dataclass_fields__)
    unknown = set(paths_data) - known
    if unknown:
        raise ValueError("unknown paths: " + ", ".join(sorted(unknown)))
    paths = Paths(**paths_data).resolve()
    return Config(
        domain=str(data.get("domain", "")),
        base_path=str(data.get("base_path", "")),
        panel_path=str(data.get("panel_path", "")),
        nat_info=str(data.get("nat_info", "")),
        mtproxy_max_connections=int(data.get("mtproxy_max_connections", 4096)),
        paths=paths,
    )


def slot_port(shard: int, idx: int) -> int:
    return SLOT_PORT_BASE + shard * SHARD_SIZE + idx


def stats_port(shard: int) -> int:
    return STATS_PORT_BASE + shard


def profile_name(shard: int, idx: int) -> str:
    return "s%03d-%02d" % (shard, idx)
