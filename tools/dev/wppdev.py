#!/usr/bin/env python3
"""M1 test-stand tool: manage users/devices before the panel (M3) and bot (M4) exist.

Run on the server as the service user:
    sudo -u webproxy python3 /opt/webproxy/src/tools/dev/wppdev.py COMMAND ...
Uses the same business logic (webproxy.users / webproxy.pool) as the panel and bot.
Links and secrets are printed only by the "links" and "qr" commands.
"""

import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from webproxy import config as config_module  # noqa: E402
from webproxy import db, pool, system, users  # noqa: E402


def context(args):
    cfg = config_module.load(args.config)
    return cfg, db.open_db(cfg.paths.db), system.System(cfg)


def fmt_time(value):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(value)) if value else "бессрочно"


def cmd_list(args):
    _, conn, _ = context(args)
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    for user in rows:
        devices = users.devices(conn, user["id"])
        state = "вкл" if user["enabled"] else "выкл (%s)" % user["disabled_reason"]
        print("#%d %s tg=%s %s до %s устройств %d/%d" % (
            user["id"], user["name"], user["tg_id"] or "-", state, fmt_time(user["expires_at"]),
            len(devices), users.max_devices(conn, user)))
        for device in devices:
            print("    устройство #%d %s порт %d" % (device["id"], device["name"], device["port"]))
    print("Слоты: %s" % pool.counts(conn))


def cmd_add(args):
    _, conn, sys_ = context(args)
    expires = int(time.time()) + args.days * 86400 if args.days else None
    user_id, device_id = users.create_user(conn, sys_, name=args.name, tg_id=args.tg_id, expires_at=expires,
                                           max_devices_value=args.max_devices)
    print("Создан пользователь #%d, устройство #%d" % (user_id, device_id))


def cmd_device_add(args):
    _, conn, sys_ = context(args)
    print("Добавлено устройство #%d" % users.add_device(conn, sys_, args.user_id, "panel", args.name))


def cmd_device_del(args):
    _, conn, sys_ = context(args)
    users.delete_device(conn, sys_, args.device_id)
    print("Устройство удалено, слот помечен dirty")


def cmd_rotate(args):
    _, conn, sys_ = context(args)
    users.rotate_device(conn, sys_, args.device_id)
    print("Ссылка перевыпущена")


def cmd_disable(args):
    _, conn, sys_ = context(args)
    print("Выключен" if users.disable_user(conn, sys_, args.user_id) else "Уже выключен")


def cmd_enable(args):
    _, conn, sys_ = context(args)
    print("Включён" if users.enable_user(conn, sys_, args.user_id) else "Уже включён")


def cmd_delete(args):
    _, conn, sys_ = context(args)
    users.delete_user(conn, sys_, args.user_id)
    print("Пользователь удалён")


def cmd_links(args):
    cfg, conn, _ = context(args)
    for device in users.devices(conn, args.user_id):
        info = users.device_link(cfg, device)
        print("Устройство #%d %s" % (device["id"], device["name"]))
        print("  Ссылка: %s" % info["link"])
        print("  Сервер: %s" % info["server"])
        print("  Секрет: %s" % info["secret"])


def cmd_qr(args):
    cfg, conn, _ = context(args)
    row = conn.execute(
        "SELECT d.*, s.port, s.secret FROM devices d JOIN slots s ON s.id = d.slot_id WHERE d.id = ?",
        (args.device_id,)).fetchone()
    if row is None:
        print("Устройство не найдено", file=sys.stderr)
        return 1
    link = users.device_link(cfg, row)["link"]
    subprocess.run([cfg.paths.qrencode, "-t", "ANSIUTF8", "-m", "2", "--", link], check=False)
    return 0


def cmd_maintain(args):
    cfg, conn, sys_ = context(args)
    report = pool.maintain(conn, cfg, sys_, pool.load_sizing(cfg), grow_shards=args.grow)
    print("Обновлено секретов: %d, новых шардов: %d" % (report["rotated"], report["new_shards"]))


def cmd_fill(args):
    """Creates N test users (one device each) to occupy slots."""
    _, conn, sys_ = context(args)
    for index in range(args.count):
        users.create_user(conn, sys_, name="Тест %d" % (index + 1))
    print("Создано пользователей: %d" % args.count)


def main():
    parser = argparse.ArgumentParser(description="Инструмент тестового стенда M1")
    parser.add_argument("--config", default=os.environ.get(config_module.CONFIG_ENV,
                                                           config_module.DEFAULT_CONFIG_PATH))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list").set_defaults(func=cmd_list)
    p = sub.add_parser("add")
    p.add_argument("name")
    p.add_argument("--tg-id", type=int)
    p.add_argument("--days", type=int, default=0)
    p.add_argument("--max-devices", type=int)
    p.set_defaults(func=cmd_add)
    p = sub.add_parser("device-add")
    p.add_argument("user_id", type=int)
    p.add_argument("--name")
    p.set_defaults(func=cmd_device_add)
    for name, func in (("device-del", cmd_device_del), ("rotate", cmd_rotate), ("qr", cmd_qr)):
        p = sub.add_parser(name)
        p.add_argument("device_id", type=int)
        p.set_defaults(func=func)
    for name, func in (("disable", cmd_disable), ("enable", cmd_enable), ("delete", cmd_delete),
                       ("links", cmd_links)):
        p = sub.add_parser(name)
        p.add_argument("user_id", type=int)
        p.set_defaults(func=func)
    p = sub.add_parser("maintain")
    p.add_argument("--grow", type=int, default=None)
    p.set_defaults(func=cmd_maintain)
    p = sub.add_parser("fill")
    p.add_argument("count", type=int)
    p.set_defaults(func=cmd_fill)
    args = parser.parse_args()
    try:
        return args.func(args) or 0
    except (users.UserError, pool.PoolError, system.SystemError_) as error:
        print("Ошибка: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
