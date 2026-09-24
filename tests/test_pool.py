import json
import re
import unittest

from webproxy import config as config_module
from webproxy import db, pool
from tests.fakes import TempInstall

HEX32 = re.compile(r"^[0-9a-f]{32}$")


class PoolTestBase(unittest.TestCase):
    def setUp(self):
        self.inst = TempInstall()
        self.conn = self.inst.conn
        self.cfg = self.inst.cfg
        self.system = self.inst.system
        self.sizing = self.inst.sizing

    def tearDown(self):
        self.inst.close()

    def make_active(self, count=1):
        with db.transaction(self.conn):
            created = pool.create_shards(self.conn, count)
            pool.commit_staged(self.conn)
        return created

    def add_user(self, enabled=True):
        """Assigns a free slot to a new user's device; returns (user_id, slot row)."""
        with db.transaction(self.conn):
            now = db.now()
            user_id = self.conn.execute(
                "INSERT INTO users(name, enabled, disabled_reason, created_at, created_by, period_start) "
                "VALUES('u', ?, ?, ?, 'panel', ?)",
                (1 if enabled else 0, None if enabled else "manual", now, now)).lastrowid
            slot = pool.take_free_slot(self.conn, device_id=None)
            device_id = self.conn.execute(
                "INSERT INTO devices(user_id, name, slot_id, created_at, created_by) VALUES(?, 'd', ?, ?, 'panel')",
                (user_id, slot["id"], now)).lastrowid
            self.conn.execute("UPDATE slots SET device_id = ? WHERE id = ?", (device_id, slot["id"]))
        return user_id, slot

    def slot(self, port):
        return self.conn.execute("SELECT * FROM slots WHERE port = ?", (port,)).fetchone()

    def shard_ids(self, active=None):
        sql = "SELECT id FROM shards"
        if active is not None:
            sql += " WHERE active = %d" % (1 if active else 0)
        return [r[0] for r in self.conn.execute(sql + " ORDER BY id")]


class CreateShardsTest(PoolTestBase):
    def test_layout(self):
        with db.transaction(self.conn):
            created = pool.create_shards(self.conn, 2)
        self.assertEqual(created, [0, 1])
        rows = self.conn.execute("SELECT * FROM slots ORDER BY port").fetchall()
        self.assertEqual(len(rows), 32)
        for row in rows:
            self.assertEqual(row["port"], 20000 + row["shard_id"] * 16 + row["idx"])
            self.assertEqual(row["status"], "free")
            self.assertIsNone(row["pending_secret"])
            self.assertRegex(row["secret"], HEX32)
        self.assertEqual(len({row["secret"] for row in rows}), 32)
        for shard in (0, 1):
            idxs = [r["idx"] for r in rows if r["shard_id"] == shard]
            self.assertEqual(idxs, list(range(16)))
        stats = [r[0] for r in self.conn.execute("SELECT stats_port FROM shards ORDER BY id")]
        self.assertEqual(stats, [19000, 19001])

    def test_inactive_until_commit(self):
        with db.transaction(self.conn):
            pool.create_shards(self.conn, 1)
        self.assertEqual(self.shard_ids(active=False), [0])
        self.assertEqual(pool.counts(self.conn)["slots"], 0)
        with db.transaction(self.conn):
            pool.commit_staged(self.conn)
        self.assertEqual(self.shard_ids(active=True), [0])
        self.assertEqual(pool.counts(self.conn)["free"], 16)

    def test_continues_numbering(self):
        self.make_active(1)
        with db.transaction(self.conn):
            self.assertEqual(pool.create_shards(self.conn, 1), [1])
        self.assertIsNotNone(self.slot(20016))

    def test_zero_count(self):
        with db.transaction(self.conn):
            self.assertEqual(pool.create_shards(self.conn, 0), [])
        self.assertEqual(self.shard_ids(), [])

    def test_max_shards(self):
        self.conn.execute("INSERT INTO shards(id, stats_port, created_at, active) VALUES(?, ?, 0, 1)",
                          (config_module.MAX_SHARDS - 1, 19000 + config_module.MAX_SHARDS - 1))
        with self.assertRaises(pool.PoolError):
            with db.transaction(self.conn):
                pool.create_shards(self.conn, 1)


class SlotTest(PoolTestBase):
    def test_take_ignores_inactive_shards(self):
        with db.transaction(self.conn):
            pool.create_shards(self.conn, 1)
        with self.assertRaises(pool.NoFreeSlots):
            with db.transaction(self.conn):
                pool.take_free_slot(self.conn, device_id=None)
        self.assertTrue(issubclass(pool.NoFreeSlots, pool.PoolError))

    def test_take_until_exhausted(self):
        self.make_active(1)
        ports = []
        with db.transaction(self.conn):
            for _ in range(16):
                ports.append(pool.take_free_slot(self.conn, device_id=None)["port"])
        self.assertEqual(ports, list(range(20000, 20016)))
        self.assertEqual(self.slot(20000)["status"], "assigned")
        with self.assertRaises(pool.NoFreeSlots):
            with db.transaction(self.conn):
                pool.take_free_slot(self.conn, device_id=None)

    def test_take_sets_device(self):
        self.make_active(1)
        with db.transaction(self.conn):
            row = pool.take_free_slot(self.conn, device_id=42)
        self.assertEqual(row["device_id"], 42)
        self.assertEqual(row["status"], "assigned")

    def test_release_makes_dirty(self):
        self.make_active(1)
        _, slot = self.add_user()
        with db.transaction(self.conn):
            self.conn.execute("DELETE FROM devices")
            pool.release_slot(self.conn, slot["id"])
        row = self.slot(slot["port"])
        self.assertEqual(row["status"], "dirty")
        self.assertIsNone(row["device_id"])
        self.assertEqual(row["secret"], slot["secret"])
        # Dirty slots are never handed out again.
        with db.transaction(self.conn):
            self.assertNotEqual(pool.take_free_slot(self.conn, None)["port"], slot["port"])


class StagingTest(PoolTestBase):
    def dirty_slot(self):
        _, slot = self.add_user()
        with db.transaction(self.conn):
            self.conn.execute("DELETE FROM devices")
            pool.release_slot(self.conn, slot["id"])
        return slot

    def test_stage_commit(self):
        self.make_active(2)
        slot = self.dirty_slot()
        with db.transaction(self.conn):
            restart = pool.stage_dirty(self.conn)
        self.assertEqual(restart, {0})
        staged = self.slot(slot["port"])
        self.assertRegex(staged["pending_secret"], HEX32)
        self.assertNotEqual(staged["pending_secret"], slot["secret"])
        self.assertEqual(staged["secret"], slot["secret"])
        self.assertEqual(staged["status"], "dirty")
        # Staging again keeps the same pending secret.
        with db.transaction(self.conn):
            pool.stage_dirty(self.conn)
        self.assertEqual(self.slot(slot["port"])["pending_secret"], staged["pending_secret"])
        with db.transaction(self.conn):
            pool.commit_staged(self.conn)
        done = self.slot(slot["port"])
        self.assertEqual(done["status"], "free")
        self.assertEqual(done["secret"], staged["pending_secret"])
        self.assertIsNone(done["pending_secret"])

    def test_stage_nothing(self):
        self.make_active(1)
        with db.transaction(self.conn):
            self.assertEqual(pool.stage_dirty(self.conn), set())

    def test_abort(self):
        self.make_active(1)
        slot = self.dirty_slot()
        with db.transaction(self.conn):
            pool.stage_dirty(self.conn)
            pool.create_shards(self.conn, 2)
        self.assertEqual(self.shard_ids(), [0, 1, 2])
        with db.transaction(self.conn):
            pool.abort_staged(self.conn)
        row = self.slot(slot["port"])
        self.assertIsNone(row["pending_secret"])
        self.assertEqual(row["status"], "dirty")
        self.assertEqual(row["secret"], slot["secret"])
        self.assertEqual(self.shard_ids(), [0])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM slots").fetchone()[0], 16)


class BlockedPortsTest(PoolTestBase):
    def test_rules(self):
        self.make_active(1)
        _, enabled_slot = self.add_user(enabled=True)
        _, disabled_slot = self.add_user(enabled=False)
        _, dirty_slot = self.add_user(enabled=True)
        with db.transaction(self.conn):
            self.conn.execute("DELETE FROM devices WHERE slot_id = ?", (dirty_slot["id"],))
            pool.release_slot(self.conn, dirty_slot["id"])
            pool.create_shards(self.conn, 1)  # inactive shard 1
        blocked = pool.blocked_ports(self.conn)
        self.assertNotIn(enabled_slot["port"], blocked)
        self.assertIn(disabled_slot["port"], blocked)
        self.assertIn(dirty_slot["port"], blocked)
        for port in range(20003, 20016):  # free
            self.assertIn(port, blocked)
        for port in range(20016, 20032):  # inactive shard
            self.assertIn(port, blocked)
        self.assertEqual(blocked, sorted(blocked))
        self.assertEqual(len(blocked), 31)

    def test_assigned_on_inactive_shard_blocked(self):
        self.make_active(1)
        _, slot = self.add_user(enabled=True)
        self.conn.execute("UPDATE shards SET active = 0")
        self.assertIn(slot["port"], pool.blocked_ports(self.conn))

    def test_empty(self):
        self.assertEqual(pool.blocked_ports(self.conn), [])


class RenderTest(PoolTestBase):
    def test_profiles(self):
        self.make_active(2)
        self.conn.execute("UPDATE slots SET pending_secret = ? WHERE port = 20017", ("ab" * 16,))
        limits = self.sizing["profile_limits"]
        result = pool.render_profiles(self.conn, limits)
        profiles = result["profiles"]
        self.assertEqual(len(profiles), 32)
        self.assertEqual(profiles[0]["name"], "s000-00")
        self.assertEqual(profiles[17]["name"], "s001-01")
        self.assertEqual(profiles[15]["name"], "s000-15")
        self.assertEqual(profiles[17]["backend"], "127.0.0.1:20017")
        self.assertEqual(profiles[17]["secret"], "ab" * 16)
        self.assertEqual(profiles[0]["secret"], self.slot(20000)["secret"])
        for profile in profiles:
            self.assertRegex(profile["name"], r"^s[0-9]{3}-[0-9]{2}$")
            self.assertEqual(profile["limits"], limits)
            self.assertEqual(profile["limits"]["max_sessions"], 1)
            self.assertIsNot(profile["limits"], limits)
        self.assertEqual(len({p["name"] for p in profiles}), 32)

    def test_shard_env(self):
        self.make_active(2)
        self.conn.execute("UPDATE slots SET pending_secret = ? WHERE port = 20018", ("cd" * 16,))
        env = pool.render_shard_env(self.conn, self.cfg, 1)
        values = dict(line.split("=", 1) for line in env.splitlines() if not line.startswith("#"))
        self.assertEqual(values["WPP_STATS_PORT"], "19001")
        self.assertEqual(values["WPP_PORTS"], ",".join(str(p) for p in range(20016, 20032)))
        secret_args = values["WPP_SECRET_ARGS"].split(" ")
        self.assertEqual(secret_args[0::2], ["-S"] * 16)
        secrets_ = secret_args[1::2]
        self.assertEqual(len(secrets_), 16)
        self.assertEqual(secrets_[2], "cd" * 16)
        self.assertEqual(secrets_[0], self.slot(20016)["secret"])
        self.assertEqual(values["WPP_NAT_ARGS"], "")
        self.assertEqual(values["WPP_MAX_CONNECTIONS"], str(self.cfg.mtproxy_max_connections))
        self.assertTrue(env.endswith("\n"))

    def test_shard_env_nat(self):
        self.make_active(1)
        self.cfg.nat_info = "10.0.0.5:203.0.113.7"
        env = pool.render_shard_env(self.conn, self.cfg, 0)
        self.assertIn("WPP_NAT_ARGS=--nat-info 10.0.0.5:203.0.113.7\n", env)

    def test_shard_env_incomplete(self):
        with self.assertRaises(pool.PoolError):
            pool.render_shard_env(self.conn, self.cfg, 5)

    def test_relay_config(self):
        base = self.sizing["relay_limits"]["max_profiles"]
        small = pool.render_relay_config(self.cfg, self.sizing, 16)
        self.assertEqual(small["limits"]["max_profiles"], base)
        big = pool.render_relay_config(self.cfg, self.sizing, base + 48)
        self.assertEqual(big["limits"]["max_profiles"], base + 48)
        self.assertEqual(self.sizing["relay_limits"]["max_profiles"], base)  # not mutated
        self.assertEqual(big["timeouts"]["reconnect_grace"], "60s")
        self.assertEqual(big["token_key_file"], self.cfg.paths.token_key)
        self.assertEqual(big["profiles_file"], self.cfg.paths.profiles)
        self.assertEqual(big["public_hostname"], "proxy.example.com")
        self.assertEqual(big["listen"], "127.0.0.1:8080")
        self.assertEqual(big["admin_listen"], "127.0.0.1:8081")
        self.assertEqual(big["public_dir"], self.cfg.paths.site_dir)
        for key, value in self.sizing["relay_limits"].items():
            if key != "max_profiles":
                self.assertEqual(big["limits"][key], value)


class ApplyTest(PoolTestBase):
    def paths(self):
        p = self.cfg.paths
        return p.profiles, p.relay_config

    def stage_new(self, count=1):
        with db.transaction(self.conn):
            return pool.create_shards(self.conn, count)

    def test_success_new_shard(self):
        new = self.stage_new(1)
        pool.apply(self.conn, self.cfg, self.system, self.sizing, new_shards=new)
        profiles_path, config_path = self.paths()
        # Candidates were checked and removed.
        check = [c for c in self.system.calls if c[0] == "relay_check"]
        self.assertEqual(check, [("relay_check", config_path + ".new", profiles_path + ".new")])
        self.assertNotIn(config_path + ".new", self.system.files)
        self.assertNotIn(profiles_path + ".new", self.system.files)
        checked_config, checked_profiles = self.system.checked[0]
        self.assertEqual(len(checked_profiles["profiles"]), 16)
        self.assertEqual(checked_config["profiles_file"], profiles_path)
        # Final files.
        final_profiles = json.loads(self.system.files[profiles_path])
        self.assertEqual(final_profiles, checked_profiles)
        self.assertEqual(json.loads(self.system.files[config_path]), checked_config)
        env = self.system.files[pool.shard_env_path(self.cfg, 0)].decode("utf-8")
        self.assertEqual(env, pool.render_shard_env(self.conn, self.cfg, 0))
        # Order of system actions.
        names = self.system.names()
        self.assertLess(names.index("relay_check"), names.index("sync_firewall"))
        self.assertLess(names.index("sync_firewall"), names.index("enable_shard"))
        self.assertLess(names.index("enable_shard"), names.index("restart_shard"))
        self.assertLess(names.index("restart_shard"), names.index("restart_relay"))
        self.assertLess(names.index("restart_relay"), names.index("wait_healthy"))
        self.assertIn(("enable_shard", 0), self.system.calls)
        self.assertIn(("restart_shard", 0), self.system.calls)
        self.assertIn(("wait_healthy", (0,)), self.system.calls)
        self.assertEqual(self.system.enabled_shards, {0})
        # Committed.
        self.assertEqual(self.shard_ids(active=True), [0])
        kinds = [r[0] for r in self.conn.execute("SELECT kind FROM events")]
        self.assertIn("pool_applied", kinds)

    def test_success_rotation_only(self):
        self.make_active(2)
        self.conn.execute("UPDATE slots SET status = 'dirty' WHERE port = 20020")
        old = self.slot(20020)["secret"]
        with db.transaction(self.conn):
            restart = pool.stage_dirty(self.conn)
        pending = self.slot(20020)["pending_secret"]
        pool.apply(self.conn, self.cfg, self.system, self.sizing, restart_shards=restart)
        names = self.system.names()
        self.assertNotIn("sync_firewall", names)
        self.assertNotIn("enable_shard", names)
        self.assertIn(("restart_shard", 1), self.system.calls)
        self.assertNotIn(("restart_shard", 0), self.system.calls)
        self.assertIn("restart_relay", names)
        profiles = json.loads(self.system.files[self.cfg.paths.profiles])["profiles"]
        self.assertEqual(profiles[20]["secret"], pending)
        row = self.slot(20020)
        self.assertEqual((row["status"], row["secret"]), ("free", pending))
        self.assertNotEqual(row["secret"], old)
        self.assertNotIn(pool.shard_env_path(self.cfg, 0), self.system.files)
        self.assertIn(pool.shard_env_path(self.cfg, 1), self.system.files)

    def test_relay_check_fails(self):
        self.make_active(1)
        self.conn.execute("UPDATE slots SET status = 'dirty' WHERE port = 20001")
        with db.transaction(self.conn):
            restart = pool.stage_dirty(self.conn)
        new = self.stage_new(1)
        self.system.check_result = (False, "bad limits")
        with self.assertRaises(pool.PoolError) as ctx:
            pool.apply(self.conn, self.cfg, self.system, self.sizing, restart_shards=restart, new_shards=new)
        self.assertIn("bad limits", str(ctx.exception))
        names = self.system.names()
        for name in ("restart_relay", "restart_shard", "enable_shard", "sync_firewall", "wait_healthy"):
            self.assertNotIn(name, names)
        self.assertEqual(self.system.files, {})
        self.assertEqual(self.shard_ids(), [0])
        row = self.slot(20001)
        self.assertIsNone(row["pending_secret"])
        self.assertEqual(row["status"], "dirty")

    def test_unhealthy_restores(self):
        self.make_active(1)
        profiles_path, config_path = self.paths()
        self.system.files[profiles_path] = b"old profiles"
        self.system.files[pool.shard_env_path(self.cfg, 0)] = b"old env 0"
        self.conn.execute("UPDATE slots SET status = 'dirty' WHERE port = 20003")
        old_secret = self.slot(20003)["secret"]
        with db.transaction(self.conn):
            restart = pool.stage_dirty(self.conn)
        new = self.stage_new(1)
        self.system.healthy = False
        with self.assertRaises(pool.PoolError):
            pool.apply(self.conn, self.cfg, self.system, self.sizing, restart_shards=restart, new_shards=new)
        # Previous files restored, absent ones removed.
        self.assertEqual(self.system.files[profiles_path], b"old profiles")
        self.assertEqual(self.system.files[pool.shard_env_path(self.cfg, 0)], b"old env 0")
        self.assertNotIn(config_path, self.system.files)
        self.assertNotIn(pool.shard_env_path(self.cfg, 1), self.system.files)
        # New shard stopped and disabled.
        self.assertIn(("stop_shard", 1), self.system.calls)
        self.assertIn(("disable_shard", 1), self.system.calls)
        self.assertEqual(self.system.enabled_shards, set())
        self.assertNotIn(("stop_shard", 0), self.system.calls)
        # Staged state aborted.
        self.assertEqual(self.shard_ids(), [0])
        row = self.slot(20003)
        self.assertIsNone(row["pending_secret"])
        self.assertEqual((row["status"], row["secret"]), ("dirty", old_secret))
        self.assertNotIn("pool_applied", [r[0] for r in self.conn.execute("SELECT kind FROM events")])

    def test_write_failure_is_pool_error(self):
        new = self.stage_new(1)
        self.system.fail_on = {"enable_shard"}
        with self.assertRaises(pool.PoolError):
            pool.apply(self.conn, self.cfg, self.system, self.sizing, new_shards=new)
        self.assertEqual(self.shard_ids(), [])
        self.assertEqual(self.system.files, {})


class MaintainTest(PoolTestBase):
    def test_empty_pool_grows(self):
        report = pool.maintain(self.conn, self.cfg, self.system, self.sizing)
        self.assertEqual(report, {"rotated": 0, "new_shards": 1})
        self.assertEqual(self.shard_ids(active=True), [0])

    def test_noop(self):
        self.make_active(1)
        report = pool.maintain(self.conn, self.cfg, self.system, self.sizing)
        self.assertEqual(report, {"rotated": 0, "new_shards": 0})
        self.assertEqual(self.system.calls, [])

    def test_rotates_dirty(self):
        self.make_active(1)
        _, slot = self.add_user()
        with db.transaction(self.conn):
            self.conn.execute("DELETE FROM devices")
            pool.release_slot(self.conn, slot["id"])
        report = pool.maintain(self.conn, self.cfg, self.system, self.sizing)
        # 15 free + 1 rotated = 16 = low water: no growth.
        self.assertEqual(report, {"rotated": 1, "new_shards": 0})
        row = self.slot(slot["port"])
        self.assertEqual(row["status"], "free")
        self.assertNotEqual(row["secret"], slot["secret"])
        self.assertIn(("restart_shard", 0), self.system.calls)

    def test_grows_below_low_water(self):
        self.make_active(1)
        self.add_user()
        report = pool.maintain(self.conn, self.cfg, self.system, self.sizing)
        self.assertEqual(report, {"rotated": 0, "new_shards": 1})
        self.assertEqual(self.shard_ids(active=True), [0, 1])
        self.assertIn(("enable_shard", 1), self.system.calls)

    def test_forced_growth(self):
        self.make_active(1)
        report = pool.maintain(self.conn, self.cfg, self.system, self.sizing, grow_shards=2)
        self.assertEqual(report["new_shards"], 2)
        self.assertEqual(self.shard_ids(active=True), [0, 1, 2])

    def test_failed_apply_aborts(self):
        self.system.healthy = False
        with self.assertRaises(pool.PoolError):
            pool.maintain(self.conn, self.cfg, self.system, self.sizing)
        self.assertEqual(self.shard_ids(), [])

    def test_low_water(self):
        self.assertEqual(pool.low_water(self.conn), 16)
        self.make_active(1)
        self.assertEqual(pool.low_water(self.conn), 16)
        self.make_active(19)
        self.assertEqual(pool.counts(self.conn)["slots"], 320)
        self.assertEqual(pool.low_water(self.conn), 32)

    def test_needs_maintenance(self):
        self.assertTrue(pool.needs_maintenance(self.conn))
        self.make_active(2)
        self.assertFalse(pool.needs_maintenance(self.conn))
        self.conn.execute("UPDATE slots SET status = 'dirty' WHERE port = 20000")
        self.assertTrue(pool.needs_maintenance(self.conn))


if __name__ == "__main__":
    unittest.main()
