"""Test doubles: an in-memory System and helpers for temporary installations."""

import json
import os
import shutil
import tempfile

from webproxy import config as config_module
from webproxy import db, sizing


class FakeSystem:
    """Records calls and models the firewall (@blocked) and files in memory.

    ``fail_on`` = set of method names that raise ``system.SystemError_``;
    ``check_result`` = (ok, message) returned by relay_check;
    ``healthy`` = value returned by wait_healthy.
    """

    def __init__(self, cfg=None):
        self.cfg = cfg
        self.calls = []
        self.blocked = set()
        self.files = {}
        self.fail_on = set()
        self.check_result = (True, "configuration is valid")
        self.checked = []
        self.healthy = True
        self.counter_values = {}
        self.enabled_shards = set()
        self.firewall_calls = 0

    def _record(self, name, *args):
        self.calls.append((name,) + args)
        if name in self.fail_on:
            from webproxy.system import SystemError_
            raise SystemError_("%s failed (fake)" % name)

    def names(self):
        return [call[0] for call in self.calls]

    def block(self, ports):
        ports = sorted(set(ports))
        if ports:
            self.firewall_calls += 1
            self._record("block", tuple(ports))
            self.blocked.update(ports)

    def unblock(self, ports):
        ports = sorted(set(ports))
        if ports:
            self.firewall_calls += 1
            self._record("unblock", tuple(ports))
            self.blocked.difference_update(ports)

    def sync_firewall(self):
        self._record("sync_firewall")

    def counters(self):
        self._record("counters")
        return dict(self.counter_values)

    def restart_relay(self):
        self._record("restart_relay")

    def restart_shard(self, shard):
        self._record("restart_shard", shard)

    def start_shard(self, shard):
        self._record("start_shard", shard)

    def stop_shard(self, shard):
        self._record("stop_shard", shard)

    def enable_shard(self, shard):
        self._record("enable_shard", shard)
        self.enabled_shards.add(shard)

    def disable_shard(self, shard):
        self._record("disable_shard", shard)
        self.enabled_shards.discard(shard)

    def daemon_reload(self):
        self._record("daemon_reload")

    def unit_status(self):
        self._record("unit_status")
        return {}

    def write_file(self, path, data, mode=0o600):
        self._record("write_file", path)
        self.files[path] = bytes(data)

    def read_file(self, path):
        return self.files.get(path)

    def remove_file(self, path):
        self.files.pop(path, None)

    def relay_check(self, config_path, profiles_path):
        self._record("relay_check", config_path, profiles_path)
        self.checked.append((json.loads(self.files[config_path]), json.loads(self.files[profiles_path])))
        return self.check_result

    def relay_healthy(self):
        return self.healthy

    def relay_metrics(self):
        return {}

    def shard_healthy(self, shard):
        return self.healthy

    def wait_healthy(self, shards, relay=True, timeout=30):
        self._record("wait_healthy", tuple(sorted(shards)))
        return self.healthy

    def qrencode(self, text, fmt="PNG"):
        self._record("qrencode", fmt)
        return b"QR"


class TempInstall:
    """A throwaway installation layout in a temporary directory."""

    def __init__(self, domain="proxy.example.com", base_path=""):
        self.root = tempfile.mkdtemp(prefix="wpp-test-")
        paths = {
            "etc_dir": os.path.join(self.root, "etc"),
            "lib_dir": os.path.join(self.root, "lib"),
            "opt_dir": os.path.join(self.root, "opt"),
        }
        for directory in paths.values():
            os.makedirs(directory)
        self.cfg = config_module.from_dict({"domain": domain, "base_path": base_path, "paths": paths})
        os.makedirs(self.cfg.paths.shards_dir)
        self.conn = db.open_db(self.cfg.paths.db)
        self.system = FakeSystem(self.cfg)
        self.sizing = sizing.compute(100, 2, 2 * 1024 ** 3)

    def close(self):
        self.conn.close()
        shutil.rmtree(self.root, ignore_errors=True)
