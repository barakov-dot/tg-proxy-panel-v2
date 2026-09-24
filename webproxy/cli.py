"""wpp: command line for SSH administration and for the installer.

Runs as the webproxy user (``sudo -u webproxy wpp ...``). M1 provides ``init``
(first configuration of the pool, used by the installer) and ``status``; the
remaining commands of PLAN.md section 10 arrive with their stages.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from typing import List, Optional

from . import config as config_module
from . import db, links, pool, sizing, system


_DOMAIN_RE = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
_IPV4 = r"(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])"
_NAT_RE = re.compile(_IPV4 + ":" + _IPV4)


def _write_json(path: str, value: object) -> None:
    system.atomic_write_json(path, value, 0o600)


def cmd_init(args: argparse.Namespace) -> int:
    config_path = args.config
    if os.path.exists(config_path):
        cfg = config_module.load(config_path)
        print("Конфигурация уже есть: %s" % config_path)
    else:
        if not _DOMAIN_RE.fullmatch(args.domain) or "." not in args.domain:
            raise ValueError("Домен должен быть в нижнем регистре ASCII (IDNA), например proxy.example.com.")
        if args.nat_info and not _NAT_RE.fullmatch(args.nat_info):
            raise ValueError("--nat-info: ожидается <локальный IPv4>:<внешний IPv4>.")
        links.validate_base_path(args.base_path)
        data = {
            "domain": args.domain,
            "base_path": args.base_path,
            "panel_path": "p-" + secrets.token_hex(16),
            "nat_info": args.nat_info,
            "mtproxy_max_connections": 4096,
        }
        _write_json(config_path, data)
        cfg = config_module.from_dict(data)
        print("Записана конфигурация: %s" % config_path)
    paths = cfg.paths
    for directory in (paths.shards_dir, paths.backups_dir):
        os.makedirs(directory, mode=0o700, exist_ok=True)

    if os.path.exists(paths.sizing) and not args.resize:
        plan = pool.load_sizing(cfg)
    else:
        host = sizing.detect()
        plan = sizing.compute(args.users, host["cpus"], host["mem_bytes"])
        _write_json(paths.sizing, plan)
    for warning in plan["warnings"]:
        print("Внимание: " + warning)
    print("Пул: %d шардов, %d слотов; сессий relay: %d." % (
        plan["shards"], plan["pool_slots"], plan["relay_limits"]["max_sessions_global"]))

    conn = db.open_db(paths.db)
    os.chmod(paths.db, 0o600)
    current = pool.counts(conn)
    missing = max(0, plan["shards"] - current["shards"])
    if missing or current["dirty"]:
        report = pool.maintain(conn, cfg, system.System(cfg), plan, grow_shards=missing)
        print("Применено: новых шардов %d, обновлено секретов %d." % (report["new_shards"], report["rotated"]))
    else:
        print("Пул уже создан.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config)
    conn = db.open_db(cfg.paths.db)
    sys_ = system.System(cfg)
    current = pool.counts(conn)
    users_total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    users_enabled = conn.execute("SELECT COUNT(*) FROM users WHERE enabled = 1").fetchone()[0]
    devices_total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    print("Домен: %s" % cfg.domain)
    print("Пользователи: %d (включено %d), устройств: %d" % (users_total, users_enabled, devices_total))
    print("Слоты: свободно %d, занято %d, dirty %d; шардов %d" % (
        current["free"], current["assigned"], current["dirty"], current["shards"]))
    print("Relay /healthz: %s" % ("ok" if sys_.relay_healthy() else "НЕ ОТВЕЧАЕТ"))
    metrics = sys_.relay_metrics()
    if metrics:
        print("Сессий relay: %d, потоков: %d" % (
            metrics.get("tproxy_sessions_live", 0), metrics.get("tproxy_streams_live", 0)))
    try:
        states = sys_.unit_status()
    except system.SystemError_ as error:
        print("Статус юнитов недоступен: %s" % error)
        return 1
    bad = {unit: state for unit, state in states.items() if state != "active"}
    print("Юниты: активно %d из %d" % (len(states) - len(bad), len(states)))
    for unit, state in sorted(bad.items()):
        print("  %s: %s" % (unit, state))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wpp", description="Управление WEB Proxy Panel")
    parser.add_argument("--config", default=os.environ.get(config_module.CONFIG_ENV,
                                                           config_module.DEFAULT_CONFIG_PATH))
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="первичная настройка пула (вызывает установщик)")
    init.add_argument("--domain", required=True)
    init.add_argument("--base-path", default="")
    init.add_argument("--nat-info", default="")
    init.add_argument("--users", type=int, default=300)
    init.add_argument("--resize", action="store_true", help="пересчитать sizing.json")
    init.set_defaults(func=cmd_init)

    status = commands.add_parser("status", help="состояние сервиса")
    status.set_defaults(func=cmd_status)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (pool.PoolError, system.SystemError_, ValueError) as error:
        print("Ошибка: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
