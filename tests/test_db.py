import os
import shutil
import sqlite3
import tempfile
import unittest

from webproxy import config as config_module
from webproxy import db


class DbTestBase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="wpp-db-test-")
        self.path = os.path.join(self.root, "wpp.db")
        self.conn = db.open_db(self.path)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.root, ignore_errors=True)


class MigrateTest(DbTestBase):
    def test_sets_user_version(self):
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(version, db.SCHEMA_VERSION)
        self.assertEqual(db.SCHEMA_VERSION, len(db.MIGRATIONS))

    def test_idempotent(self):
        tables = sorted(r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        self.assertEqual(db.migrate(self.conn), db.SCHEMA_VERSION)
        self.assertEqual(db.migrate(self.conn), db.SCHEMA_VERSION)
        again = sorted(r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        self.assertEqual(tables, again)
        for name in ("shards", "slots", "users", "devices", "settings", "events"):
            self.assertIn(name, tables)

    def test_reopen_keeps_data(self):
        db.set_setting(self.conn, "default_days", 10)
        self.conn.close()
        self.conn = db.open_db(self.path)
        self.assertEqual(db.get_setting(self.conn, "default_days"), 10)

    def test_refuses_newer_schema(self):
        self.conn.execute("PRAGMA user_version=%d" % (db.SCHEMA_VERSION + 1))
        with self.assertRaises(RuntimeError):
            db.migrate(self.conn)
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION + 1)

    def test_wal_mode(self):
        self.assertEqual(self.conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")

    def test_foreign_keys_on(self):
        self.assertEqual(self.conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO slots(shard_id, idx, port, secret, status) VALUES(99, 0, 20000, 'x', 'free')")

    def test_readonly_connection(self):
        ro = db.connect(self.path, readonly=True)
        try:
            self.assertEqual(ro.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
            with self.assertRaises(sqlite3.OperationalError):
                ro.execute("INSERT INTO settings(key, value) VALUES('a', '1')")
        finally:
            ro.close()


class TransactionTest(DbTestBase):
    def _count(self):
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def test_commit(self):
        with db.transaction(self.conn):
            db.log_event(self.conn, "a")
        self.assertFalse(self.conn.in_transaction)
        self.assertEqual(self._count(), 1)

    def test_rollback_on_exception(self):
        with self.assertRaises(ValueError):
            with db.transaction(self.conn):
                db.log_event(self.conn, "a")
                raise ValueError("boom")
        self.assertFalse(self.conn.in_transaction)
        self.assertEqual(self._count(), 0)

    def test_nested_joins_outer(self):
        with self.assertRaises(ValueError):
            with db.transaction(self.conn):
                with db.transaction(self.conn):
                    db.log_event(self.conn, "inner")
                # The inner block did not commit.
                self.assertTrue(self.conn.in_transaction)
                raise ValueError("outer fails")
        self.assertEqual(self._count(), 0)

    def test_nested_exception_rolls_back_outer(self):
        with self.assertRaises(KeyError):
            with db.transaction(self.conn):
                db.log_event(self.conn, "outer")
                with db.transaction(self.conn):
                    db.log_event(self.conn, "inner")
                    raise KeyError("x")
        self.assertEqual(self._count(), 0)
        self.assertFalse(self.conn.in_transaction)

    def test_nested_success(self):
        with db.transaction(self.conn):
            db.log_event(self.conn, "outer")
            with db.transaction(self.conn):
                db.log_event(self.conn, "inner")
        self.assertEqual(self._count(), 2)


class SettingsTest(DbTestBase):
    def test_defaults(self):
        for key, value in config_module.SETTINGS_DEFAULTS.items():
            self.assertEqual(db.get_setting(self.conn, key), value)
        self.assertEqual(db.get_setting(self.conn, "default_max_devices"), 1)

    def test_set_and_get(self):
        db.set_setting(self.conn, "approval_mode", "auto")
        db.set_setting(self.conn, "admin_tg_ids", [1, 2])
        db.set_setting(self.conn, "default_traffic_limit_bytes", 5)
        self.assertEqual(db.get_setting(self.conn, "approval_mode"), "auto")
        self.assertEqual(db.get_setting(self.conn, "admin_tg_ids"), [1, 2])
        db.set_setting(self.conn, "default_traffic_limit_bytes", None)
        self.assertIsNone(db.get_setting(self.conn, "default_traffic_limit_bytes"))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0], 3)

    def test_unknown_key(self):
        with self.assertRaises(KeyError):
            db.get_setting(self.conn, "no_such_key")
        with self.assertRaises(KeyError):
            db.set_setting(self.conn, "no_such_key", 1)

    def test_all_settings(self):
        db.set_setting(self.conn, "default_days", 90)
        result = db.all_settings(self.conn)
        self.assertEqual(set(result), set(config_module.SETTINGS_DEFAULTS))
        self.assertEqual(result["default_days"], 90)
        self.assertEqual(result["approval_mode"], config_module.SETTINGS_DEFAULTS["approval_mode"])
        # The defaults dict itself is not modified.
        self.assertEqual(config_module.SETTINGS_DEFAULTS["default_days"], 30)


class EventsTest(DbTestBase):
    def test_log_event(self):
        before = db.now()
        db.log_event(self.conn, "user_created", 7, "by=panel")
        db.log_event(self.conn, "pool_applied")
        rows = self.conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual((rows[0]["kind"], rows[0]["user_id"], rows[0]["details"]), ("user_created", 7, "by=panel"))
        self.assertIsNone(rows[1]["user_id"])
        self.assertEqual(rows[1]["details"], "")
        self.assertGreaterEqual(rows[0]["ts"], before)
        self.assertLessEqual(rows[0]["ts"], db.now())


if __name__ == "__main__":
    unittest.main()
