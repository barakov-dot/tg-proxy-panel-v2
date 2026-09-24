import unittest

from webproxy import db, links, pool, users
from webproxy.system import SystemError_
from tests.fakes import TempInstall

DAY = 86400


class UsersTestBase(unittest.TestCase):
    base_path = ""
    shards = 1

    def setUp(self):
        self.inst = TempInstall(base_path=self.base_path)
        self.conn = self.inst.conn
        self.system = self.inst.system
        if self.shards:
            with db.transaction(self.conn):
                pool.create_shards(self.conn, self.shards)
                pool.commit_staged(self.conn)
        # The firewall starts in sync with the database.
        self.system.blocked = set(pool.blocked_ports(self.conn))

    def tearDown(self):
        self.inst.close()

    def assertFirewallInSync(self):
        self.assertEqual(self.system.blocked, set(pool.blocked_ports(self.conn)))

    def user(self, user_id):
        return self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def port_of(self, device_id):
        return self.conn.execute(
            "SELECT s.port FROM devices d JOIN slots s ON s.id = d.slot_id WHERE d.id = ?",
            (device_id,)).fetchone()[0]

    def slot(self, port):
        return self.conn.execute("SELECT * FROM slots WHERE port = ?", (port,)).fetchone()

    def count(self, table):
        return self.conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0]


class CreateUserTest(UsersTestBase):
    def test_first_device(self):
        user_id, device_id = users.create_user(self.conn, self.system, name="  Иван   Петров ")
        user = self.user(user_id)
        self.assertEqual(user["name"], "Иван Петров")
        self.assertEqual(user["enabled"], 1)
        self.assertEqual(user["created_by"], "panel")
        port = self.port_of(device_id)
        slot = self.slot(port)
        self.assertEqual((slot["status"], slot["device_id"]), ("assigned", device_id))
        self.assertNotIn(port, self.system.blocked)
        self.assertIn(("unblock", (port,)), self.system.calls)
        device = users.devices(self.conn, user_id)[0]
        self.assertEqual(device["name"], "Устройство 1")
        self.assertEqual(device["created_by"], "panel")
        self.assertFirewallInSync()
        kinds = [r[0] for r in self.conn.execute("SELECT kind FROM events")]
        self.assertIn("user_created", kinds)

    def test_bot_device_created_by(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a", created_by="bot_auto", tg_id=5,
                                       device_name="Телефон")
        device = users.devices(self.conn, user_id)[0]
        self.assertEqual((device["created_by"], device["name"]), ("bot", "Телефон"))

    def test_duplicate_tg_id(self):
        users.create_user(self.conn, self.system, name="a", tg_id=100)
        with self.assertRaises(users.UserError):
            users.create_user(self.conn, self.system, name="b", tg_id=100)
        self.assertEqual(self.count("users"), 1)
        self.assertEqual(self.count("devices"), 1)
        self.assertFirewallInSync()

    def test_bad_names(self):
        for bad in ("", "   ", "x" * 65):
            with self.assertRaises(users.UserError):
                users.create_user(self.conn, self.system, name=bad)
        users.create_user(self.conn, self.system, name="x" * 64)
        self.assertEqual(self.count("users"), 1)

    def test_bad_arguments(self):
        with self.assertRaises(users.UserError):
            users.create_user(self.conn, self.system, name="a", traffic_limit_bytes=0)
        with self.assertRaises(users.UserError):
            users.create_user(self.conn, self.system, name="a", max_devices_value=0)
        with self.assertRaises(users.UserError):
            users.create_user(self.conn, self.system, name="a", traffic_reset="weekly")
        with self.assertRaises(ValueError):
            users.create_user(self.conn, self.system, name="a", created_by="someone")
        self.assertEqual(self.count("users"), 0)

    def test_unblock_failure_rolls_back(self):
        self.system.fail_on = {"unblock"}
        with self.assertRaises(SystemError_):
            users.create_user(self.conn, self.system, name="a")
        self.assertEqual(self.count("users"), 0)
        self.assertEqual(self.count("devices"), 0)
        self.assertEqual(self.slot(20000)["status"], "free")
        self.assertIsNone(self.slot(20000)["device_id"])
        self.assertFalse(self.conn.in_transaction)
        self.assertFirewallInSync()


class NoSlotsTest(UsersTestBase):
    shards = 0

    def test_no_free_slots(self):
        with self.assertRaises(pool.NoFreeSlots):
            users.create_user(self.conn, self.system, name="a", tg_id=1)
        self.assertEqual(self.count("users"), 0)
        self.assertEqual(self.system.calls, [])

    def test_inactive_shard_not_used(self):
        with db.transaction(self.conn):
            pool.create_shards(self.conn, 1)
        with self.assertRaises(pool.NoFreeSlots):
            users.create_user(self.conn, self.system, name="a")
        self.assertEqual(self.count("users"), 0)


class DevicesTest(UsersTestBase):
    def test_default_limit_one(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a")
        with self.assertRaises(users.UserError):
            users.add_device(self.conn, self.system, user_id)
        self.assertEqual(self.count("devices"), 1)
        self.assertEqual(self.count("slots WHERE status = 'assigned'"), 1)

    def test_setting_limit(self):
        db.set_setting(self.conn, "default_max_devices", 3)
        user_id, _ = users.create_user(self.conn, self.system, name="a")
        second = users.add_device(self.conn, self.system, user_id)
        users.add_device(self.conn, self.system, user_id, created_by="bot", name="Ноутбук")
        with self.assertRaises(users.UserError):
            users.add_device(self.conn, self.system, user_id)
        names = [d["name"] for d in users.devices(self.conn, user_id)]
        self.assertEqual(names, ["Устройство 1", "Устройство 2", "Ноутбук"])
        self.assertNotIn(self.port_of(second), self.system.blocked)
        self.assertFirewallInSync()

    def test_user_limit_overrides_setting(self):
        db.set_setting(self.conn, "default_max_devices", 5)
        user_id, _ = users.create_user(self.conn, self.system, name="a", max_devices_value=2)
        users.add_device(self.conn, self.system, user_id)
        with self.assertRaises(users.UserError):
            users.add_device(self.conn, self.system, user_id)
        self.assertEqual(users.max_devices(self.conn, self.user(user_id)), 2)

    def test_disabled_user(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a", max_devices_value=3)
        users.disable_user(self.conn, self.system, user_id)
        with self.assertRaises(users.UserError):
            users.add_device(self.conn, self.system, user_id, created_by="bot")
        self.assertEqual(self.count("devices"), 1)
        calls = len(self.system.calls)
        device_id = users.add_device(self.conn, self.system, user_id, created_by="panel")
        port = self.port_of(device_id)
        self.assertIn(port, self.system.blocked)
        self.assertEqual(self.system.calls[calls:], [])  # no unblock
        self.assertFirewallInSync()

    def test_unknown_user(self):
        with self.assertRaises(users.UserError):
            users.add_device(self.conn, self.system, 999)
        with self.assertRaises(ValueError):
            users.add_device(self.conn, self.system, 1, created_by="bot_auto")

    def test_delete_device(self):
        db.set_setting(self.conn, "default_max_devices", 2)
        user_id, first = users.create_user(self.conn, self.system, name="a")
        second = users.add_device(self.conn, self.system, user_id)
        port = self.port_of(second)
        users.delete_device(self.conn, self.system, second)
        self.assertEqual(self.slot(port)["status"], "dirty")
        self.assertIsNone(self.slot(port)["device_id"])
        self.assertIn(port, self.system.blocked)
        self.assertIn(("block", (port,)), self.system.calls)
        self.assertEqual([d["id"] for d in users.devices(self.conn, user_id)], [first])
        self.assertFirewallInSync()
        with self.assertRaises(users.UserError):
            users.delete_device(self.conn, self.system, second)

    def test_delete_device_block_failure(self):
        user_id, device_id = users.create_user(self.conn, self.system, name="a")
        port = self.port_of(device_id)
        self.system.fail_on = {"block"}
        with self.assertRaises(SystemError_):
            users.delete_device(self.conn, self.system, device_id)
        self.assertEqual(self.slot(port)["status"], "assigned")
        self.assertEqual(self.count("devices"), 1)
        self.assertFirewallInSync()

    def test_rotate_device(self):
        user_id, device_id = users.create_user(self.conn, self.system, name="a")
        old_port = self.port_of(device_id)
        old_secret = self.slot(old_port)["secret"]
        users.rotate_device(self.conn, self.system, device_id)
        new_port = self.port_of(device_id)
        self.assertNotEqual(new_port, old_port)
        self.assertNotIn(new_port, self.system.blocked)
        self.assertIn(old_port, self.system.blocked)
        self.assertEqual(self.slot(old_port)["status"], "dirty")
        new_slot = self.slot(new_port)
        self.assertEqual((new_slot["status"], new_slot["device_id"]), ("assigned", device_id))
        self.assertNotEqual(new_slot["secret"], old_secret)
        self.assertFirewallInSync()

    def test_rotate_disabled_device_stays_blocked(self):
        user_id, device_id = users.create_user(self.conn, self.system, name="a")
        users.disable_user(self.conn, self.system, user_id)
        users.rotate_device(self.conn, self.system, device_id)
        self.assertIn(self.port_of(device_id), self.system.blocked)
        self.assertFirewallInSync()

    def test_rotate_no_free_slot(self):
        db.set_setting(self.conn, "default_max_devices", 16)
        user_id, device_id = users.create_user(self.conn, self.system, name="a")
        for _ in range(15):
            users.add_device(self.conn, self.system, user_id)
        port = self.port_of(device_id)
        with self.assertRaises(pool.NoFreeSlots):
            users.rotate_device(self.conn, self.system, device_id)
        self.assertEqual(self.port_of(device_id), port)
        self.assertEqual(self.slot(port)["status"], "assigned")

    def test_rename_device(self):
        _, device_id = users.create_user(self.conn, self.system, name="a")
        users.rename_device(self.conn, device_id, " Мой  телефон ")
        self.assertEqual(self.conn.execute("SELECT name FROM devices").fetchone()[0], "Мой телефон")
        with self.assertRaises(users.UserError):
            users.rename_device(self.conn, device_id, "")


class EnableDisableTest(UsersTestBase):
    def setUp(self):
        super().setUp()
        db.set_setting(self.conn, "default_max_devices", 3)
        self.user_id, first = users.create_user(self.conn, self.system, name="a")
        users.add_device(self.conn, self.system, self.user_id)
        users.add_device(self.conn, self.system, self.user_id)
        self.ports = sorted(d["port"] for d in users.devices(self.conn, self.user_id))

    def test_disable_enable(self):
        self.assertTrue(users.disable_user(self.conn, self.system, self.user_id))
        self.assertIn(("block", tuple(self.ports)), self.system.calls)
        user = self.user(self.user_id)
        self.assertEqual((user["enabled"], user["disabled_reason"]), (0, "manual"))
        for port in self.ports:
            self.assertIn(port, self.system.blocked)
        self.assertFirewallInSync()
        calls = len(self.system.calls)
        self.assertFalse(users.disable_user(self.conn, self.system, self.user_id, "expired"))
        self.assertEqual(len(self.system.calls), calls)
        self.assertEqual(self.user(self.user_id)["disabled_reason"], "manual")

        self.assertTrue(users.enable_user(self.conn, self.system, self.user_id))
        self.assertIn(("unblock", tuple(self.ports)), self.system.calls)
        user = self.user(self.user_id)
        self.assertEqual((user["enabled"], user["disabled_reason"]), (1, None))
        self.assertFirewallInSync()
        calls = len(self.system.calls)
        self.assertFalse(users.enable_user(self.conn, self.system, self.user_id))
        self.assertEqual(len(self.system.calls), calls)

    def test_bad_reason(self):
        with self.assertRaises(ValueError):
            users.disable_user(self.conn, self.system, self.user_id, "whatever")

    def test_block_failure_rolls_back(self):
        self.system.fail_on = {"block"}
        with self.assertRaises(SystemError_):
            users.disable_user(self.conn, self.system, self.user_id)
        self.assertEqual(self.user(self.user_id)["enabled"], 1)
        self.assertFirewallInSync()

    def test_unblock_failure_rolls_back(self):
        users.disable_user(self.conn, self.system, self.user_id)
        self.system.fail_on = {"unblock"}
        with self.assertRaises(SystemError_):
            users.enable_user(self.conn, self.system, self.user_id)
        self.assertEqual(self.user(self.user_id)["enabled"], 0)
        self.assertFirewallInSync()


class ExpiryTest(UsersTestBase):
    def test_extend_from_now(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a")
        before = db.now()
        result = users.extend(self.conn, self.system, user_id, 30)
        self.assertGreaterEqual(result, before + 30 * DAY)
        self.assertLessEqual(result, db.now() + 30 * DAY)
        self.assertEqual(self.user(user_id)["expires_at"], result)

    def test_extend_from_future_expiry(self):
        future = db.now() + 10 * DAY
        user_id, _ = users.create_user(self.conn, self.system, name="a", expires_at=future)
        self.assertEqual(users.extend(self.conn, self.system, user_id, 5), future + 5 * DAY)

    def test_extend_from_past_expiry(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a", expires_at=1000)
        before = db.now()
        result = users.extend(self.conn, self.system, user_id, 1)
        self.assertGreaterEqual(result, before + DAY)

    def test_extend_bad_days(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a")
        for bad in (0, -1):
            with self.assertRaises(users.UserError):
                users.extend(self.conn, self.system, user_id, bad)

    def test_reenables_expired(self):
        user_id, device_id = users.create_user(self.conn, self.system, name="a", expires_at=1000)
        users.disable_user(self.conn, self.system, user_id, "expired")
        users.extend(self.conn, self.system, user_id, 30)
        user = self.user(user_id)
        self.assertEqual((user["enabled"], user["disabled_reason"]), (1, None))
        self.assertNotIn(self.port_of(device_id), self.system.blocked)
        self.assertFirewallInSync()

    def test_no_reenable_without_enable_now(self):
        user_id, device_id = users.create_user(self.conn, self.system, name="a", expires_at=1000)
        users.disable_user(self.conn, self.system, user_id, "expired")
        users.extend(self.conn, self.system, user_id, 30, enable_now=False)
        self.assertEqual(self.user(user_id)["enabled"], 0)
        self.assertIn(self.port_of(device_id), self.system.blocked)
        self.assertFirewallInSync()

    def test_no_reenable_other_reason(self):
        for reason in ("manual", "traffic_limit"):
            user_id, _ = users.create_user(self.conn, self.system, name=reason)
            users.disable_user(self.conn, self.system, user_id, reason)
            users.extend(self.conn, self.system, user_id, 30)
            self.assertEqual(self.user(user_id)["enabled"], 0)
            self.assertEqual(self.user(user_id)["disabled_reason"], reason)
        self.assertFirewallInSync()

    def test_no_reenable_when_still_over_traffic(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a", expires_at=1000,
                                       traffic_limit_bytes=100)
        self.conn.execute("UPDATE users SET period_up = 100 WHERE id = ?", (user_id,))
        users.disable_user(self.conn, self.system, user_id, "expired")
        users.extend(self.conn, self.system, user_id, 30)
        self.assertEqual(self.user(user_id)["enabled"], 0)

    def test_set_expiry_in_past_does_not_reenable(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a", expires_at=1000)
        users.disable_user(self.conn, self.system, user_id, "expired")
        users.set_expiry(self.conn, self.system, user_id, 2000)
        self.assertEqual(self.user(user_id)["enabled"], 0)
        users.set_expiry(self.conn, self.system, user_id, None)
        self.assertEqual(self.user(user_id)["enabled"], 1)
        self.assertIsNone(self.user(user_id)["expires_at"])

    def test_unblock_failure_rolls_back_extend(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a", expires_at=1000)
        users.disable_user(self.conn, self.system, user_id, "expired")
        self.system.fail_on = {"unblock"}
        with self.assertRaises(SystemError_):
            users.extend(self.conn, self.system, user_id, 30)
        user = self.user(user_id)
        self.assertEqual((user["enabled"], user["expires_at"]), (0, 1000))
        self.assertFirewallInSync()


class TrafficLimitTest(UsersTestBase):
    def setUp(self):
        super().setUp()
        self.user_id, self.device_id = users.create_user(self.conn, self.system, name="a",
                                                         traffic_limit_bytes=1000)
        self.conn.execute("UPDATE users SET period_up = 600, period_down = 500 WHERE id = ?", (self.user_id,))
        users.disable_user(self.conn, self.system, self.user_id, "traffic_limit")

    def test_still_over_limit(self):
        users.set_traffic_limit(self.conn, self.system, self.user_id, 1100)
        user = self.user(self.user_id)
        self.assertEqual((user["enabled"], user["traffic_limit_bytes"]), (0, 1100))
        self.assertFirewallInSync()

    def test_under_new_limit(self):
        users.set_traffic_limit(self.conn, self.system, self.user_id, 2000, reset="monthly")
        user = self.user(self.user_id)
        self.assertEqual((user["enabled"], user["traffic_reset"]), (1, "monthly"))
        self.assertNotIn(self.port_of(self.device_id), self.system.blocked)
        self.assertFirewallInSync()

    def test_no_limit(self):
        users.set_traffic_limit(self.conn, self.system, self.user_id, None)
        self.assertEqual(self.user(self.user_id)["enabled"], 1)

    def test_enable_now_false(self):
        users.set_traffic_limit(self.conn, self.system, self.user_id, 2000, enable_now=False)
        self.assertEqual(self.user(self.user_id)["enabled"], 0)

    def test_other_reason_untouched(self):
        users.enable_user(self.conn, self.system, self.user_id)
        users.disable_user(self.conn, self.system, self.user_id, "manual")
        users.set_traffic_limit(self.conn, self.system, self.user_id, None)
        self.assertEqual(self.user(self.user_id)["enabled"], 0)

    def test_validation(self):
        with self.assertRaises(users.UserError):
            users.set_traffic_limit(self.conn, self.system, self.user_id, 0)
        with self.assertRaises(users.UserError):
            users.set_traffic_limit(self.conn, self.system, self.user_id, 10, reset="daily")
        self.assertEqual(self.user(self.user_id)["traffic_limit_bytes"], 1000)


class UpdateProfileTest(UsersTestBase):
    def setUp(self):
        super().setUp()
        self.a, _ = users.create_user(self.conn, self.system, name="a", tg_id=1)
        self.b, _ = users.create_user(self.conn, self.system, name="b", tg_id=2)

    def test_tg_id_unique(self):
        with self.assertRaises(users.UserError):
            users.update_profile(self.conn, self.b, name="new b", tg_id=1)
        user = self.user(self.b)
        self.assertEqual((user["name"], user["tg_id"]), ("b", 2))  # whole update rolled back
        users.update_profile(self.conn, self.a, tg_id=1)  # own id is fine
        users.update_profile(self.conn, self.a, tg_id=None)
        self.assertIsNone(self.user(self.a)["tg_id"])
        users.update_profile(self.conn, self.b, tg_id=1)
        self.assertEqual(self.user(self.b)["tg_id"], 1)

    def test_tg_id_change_resets_flags(self):
        self.conn.execute("UPDATE users SET tg_bot_started = 1, tg_blocked_bot = 1 WHERE id = ?", (self.a,))
        users.update_profile(self.conn, self.a, tg_id=10)
        user = self.user(self.a)
        self.assertEqual((user["tg_bot_started"], user["tg_blocked_bot"]), (0, 0))

    def test_ellipsis_keeps_fields(self):
        self.conn.execute("UPDATE users SET tg_username = 'x', max_devices = 3 WHERE id = ?", (self.a,))
        users.update_profile(self.conn, self.a, note="hello")
        user = self.user(self.a)
        self.assertEqual((user["tg_id"], user["tg_username"], user["max_devices"], user["note"]),
                         (1, "x", 3, "hello"))

    def test_max_devices(self):
        for bad in (0, -2):
            with self.assertRaises(users.UserError):
                users.update_profile(self.conn, self.a, max_devices_value=bad)
        users.update_profile(self.conn, self.a, max_devices_value=4)
        self.assertEqual(self.user(self.a)["max_devices"], 4)
        users.update_profile(self.conn, self.a, max_devices_value=None)
        self.assertIsNone(self.user(self.a)["max_devices"])

    def test_bad_name_and_unknown_user(self):
        with self.assertRaises(users.UserError):
            users.update_profile(self.conn, self.a, name="  ")
        with self.assertRaises(users.UserError):
            users.update_profile(self.conn, 999, name="x")


class DeleteUserTest(UsersTestBase):
    def test_delete_releases_all(self):
        db.set_setting(self.conn, "default_max_devices", 3)
        user_id, _ = users.create_user(self.conn, self.system, name="a")
        users.add_device(self.conn, self.system, user_id)
        users.add_device(self.conn, self.system, user_id)
        ports = sorted(d["port"] for d in users.devices(self.conn, user_id))
        other, other_device = users.create_user(self.conn, self.system, name="b")
        users.delete_user(self.conn, self.system, user_id)
        self.assertIsNone(self.user(user_id))
        self.assertEqual(self.count("devices"), 1)
        for port in ports:
            self.assertEqual(self.slot(port)["status"], "dirty")
            self.assertIsNone(self.slot(port)["device_id"])
            self.assertIn(port, self.system.blocked)
        self.assertIn(("block", tuple(ports)), self.system.calls)
        self.assertNotIn(self.port_of(other_device), self.system.blocked)
        self.assertFirewallInSync()
        with self.assertRaises(users.UserError):
            users.delete_user(self.conn, self.system, user_id)

    def test_block_failure_rolls_back(self):
        user_id, device_id = users.create_user(self.conn, self.system, name="a")
        self.system.fail_on = {"block"}
        with self.assertRaises(SystemError_):
            users.delete_user(self.conn, self.system, user_id)
        self.assertIsNotNone(self.user(user_id))
        self.assertEqual(self.slot(self.port_of(device_id))["status"], "assigned")
        self.assertFirewallInSync()


class LinksTest(UsersTestBase):
    base_path = "abc/def"

    def test_device_link_base_path(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a")
        device = users.devices(self.conn, user_id)[0]
        result = users.device_link(self.inst.cfg, device)
        marked = links.marked_secret(device["secret"])
        self.assertEqual(result["secret"], marked)
        self.assertEqual(result["server"], "proxy.example.com/abc/def")
        self.assertEqual(result["link"], links.build("proxy.example.com", "abc/def", device["secret"]))
        self.assertIn("secret=" + marked, result["link"])
        self.assertNotIn(device["secret"], result["link"])


class RootLinkTest(UsersTestBase):
    def test_device_link_root(self):
        user_id, _ = users.create_user(self.conn, self.system, name="a")
        device = users.devices(self.conn, user_id)[0]
        result = users.device_link(self.inst.cfg, device)
        self.assertEqual(result["secret"], device["secret"])
        self.assertEqual(result["server"], "proxy.example.com")


class EventsNoSecretsTest(UsersTestBase):
    base_path = "p"

    def test_events_have_no_secrets(self):
        db.set_setting(self.conn, "default_max_devices", 3)
        user_id, device_id = users.create_user(self.conn, self.system, name="a", tg_id=1)
        second = users.add_device(self.conn, self.system, user_id, created_by="bot")
        users.rotate_device(self.conn, self.system, device_id)
        users.disable_user(self.conn, self.system, user_id, "expired")
        users.extend(self.conn, self.system, user_id, 10)
        users.set_traffic_limit(self.conn, self.system, user_id, 10 ** 9)
        users.update_profile(self.conn, user_id, name="b", note="n")
        users.delete_device(self.conn, self.system, second)
        sensitive = set()
        for device in users.devices(self.conn, user_id):
            sensitive.update(users.device_link(self.inst.cfg, device).values())
        users.delete_user(self.conn, self.system, user_id)
        for row in self.conn.execute("SELECT secret, pending_secret FROM slots"):
            sensitive.add(row["secret"])
            sensitive.add(links.marked_secret(row["secret"]))
        details = [r[0] for r in self.conn.execute("SELECT details FROM events")]
        self.assertGreater(len(details), 5)
        for text in details:
            self.assertNotIn("t.me", text)
            self.assertNotIn("secret", text)
            for value in sensitive:
                if value and value != "proxy.example.com/p":
                    self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
