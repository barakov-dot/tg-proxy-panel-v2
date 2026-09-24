"""Everything that touches the OS. Tests replace ``System`` with a fake.

All subprocess calls use argument lists (never a shell). Privileged actions go
through ``sudo -n wppctl`` only.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Dict, Iterable, List, Optional, Tuple

from . import config as config_module


class SystemError_(RuntimeError):
    """A system action failed. The message never contains secrets."""


def atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    """Writes via a temporary file in the same directory, fsync, rename."""
    directory = os.path.dirname(path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def atomic_write_json(path: str, value: object, mode: int = 0o600) -> None:
    atomic_write(path, (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8"), mode)


class System:
    def __init__(self, cfg: config_module.Config):
        self.cfg = cfg
        self.paths = cfg.paths
        # Incremented before every block/unblock attempt (see users._change).
        self.firewall_calls = 0

    # --- privileged (wppctl) -------------------------------------------------

    def _ctl(self, *args: str, timeout: float = 60) -> str:
        argv = [self.paths.sudo, "-n", self.paths.wppctl] + list(args)
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SystemError_("wppctl %s: %s" % (args[0], type(error).__name__)) from None
        if proc.returncode != 0:
            raise SystemError_("wppctl %s: %s" % (args[0], proc.stderr.strip()[:300]))
        return proc.stdout

    def block(self, ports: Iterable[int]) -> None:
        ports = sorted(set(int(p) for p in ports))
        if ports:
            self.firewall_calls += 1
            self._ctl("block", *map(str, ports), timeout=10)

    def unblock(self, ports: Iterable[int]) -> None:
        ports = sorted(set(int(p) for p in ports))
        if ports:
            self.firewall_calls += 1
            self._ctl("unblock", *map(str, ports), timeout=10)

    def sync_firewall(self) -> None:
        self._ctl("sync")

    def counters(self) -> Dict[int, Tuple[int, int]]:
        data = json.loads(self._ctl("counters"))
        return {int(port): (int(v[0]), int(v[1])) for port, v in data.items()}

    def restart_relay(self) -> None:
        self._ctl("restart", "relay", timeout=120)

    def restart_shard(self, shard: int) -> None:
        self._ctl("restart", "shard", str(shard))

    def start_shard(self, shard: int) -> None:
        self._ctl("start", "shard", str(shard))

    def stop_shard(self, shard: int) -> None:
        self._ctl("stop", "shard", str(shard))

    def enable_shard(self, shard: int) -> None:
        self._ctl("enable", "shard", str(shard))

    def disable_shard(self, shard: int) -> None:
        self._ctl("disable", "shard", str(shard))

    def daemon_reload(self) -> None:
        self._ctl("daemon-reload")

    def unit_status(self) -> Dict[str, str]:
        return json.loads(self._ctl("status"))

    # --- unprivileged --------------------------------------------------------

    def write_file(self, path: str, data: bytes, mode: int = 0o600) -> None:
        atomic_write(path, data, mode)

    def read_file(self, path: str) -> Optional[bytes]:
        try:
            with open(path, "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            return None

    def remove_file(self, path: str) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

    def relay_check(self, config_path: str, profiles_path: str) -> Tuple[bool, str]:
        argv = [self.paths.relay_bin, "-config", config_path, "-profiles-file", profiles_path, "-check"]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as error:
            return False, type(error).__name__
        # Relay errors name fields and profiles, never secret values.
        message = (proc.stderr or proc.stdout).strip().splitlines()
        return proc.returncode == 0, message[-1] if message else ""

    def _http_get(self, url: str, timeout: float = 3) -> Tuple[int, bytes]:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, b""
        except (OSError, ValueError):
            return 0, b""

    def relay_healthy(self) -> bool:
        # /readyz dials every profile backend and is always 503 with blocked
        # slots (FINDINGS item 2): use /healthz only.
        return self._http_get(self.cfg.relay_admin_url + "/healthz")[0] == 200

    def relay_metrics(self) -> Dict[str, int]:
        status, body = self._http_get(self.cfg.relay_admin_url + "/metrics")
        result: Dict[str, int] = {}
        if status == 200:
            for line in body.decode("ascii", "replace").splitlines():
                name, _, value = line.partition(" ")
                if value.strip().isdigit():
                    result[name] = int(value)
        return result

    def shard_healthy(self, shard: int) -> bool:
        url = "http://127.0.0.1:%d/stats" % config_module.stats_port(shard)
        status, body = self._http_get(url)
        return status == 200 and b"total_special_connections" in body

    def wait_healthy(self, shards: Iterable[int], relay: bool = True, timeout: float = 30) -> bool:
        pending = set(shards)
        deadline = time.monotonic() + timeout
        relay_ok = not relay
        while time.monotonic() < deadline:
            if not relay_ok:
                relay_ok = self.relay_healthy()
            pending = {s for s in pending if not self.shard_healthy(s)}
            if relay_ok and not pending:
                return True
            time.sleep(1)
        return False

    def qrencode(self, text: str, fmt: str = "PNG") -> bytes:
        if fmt not in ("PNG", "SVG"):
            raise ValueError("unsupported QR format")
        # The link goes through stdin: command lines are visible to every local user.
        argv = [self.paths.qrencode, "-t", fmt, "-o", "-", "-s", "8", "-m", "2"]
        try:
            proc = subprocess.run(argv, input=text.encode("utf-8"), capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SystemError_("qrencode: %s" % type(error).__name__) from None
        if proc.returncode != 0:
            raise SystemError_("qrencode failed")
        return proc.stdout


def run_checked(argv: List[str], timeout: float = 60) -> str:
    """Helper for non-privileged tools; raises without echoing arguments."""
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise SystemError_("%s failed: %s" % (os.path.basename(argv[0]), proc.stderr.strip()[:300]))
    return proc.stdout
