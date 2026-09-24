"""Regression tests for the M1 section-13 audit fixes."""

import sqlite3
import unittest
from unittest import mock

from tests.fakes import TempInstall
from webproxy import db, pool, users
from webproxy.system import SystemError_


class AuditFixesTest(unittest.TestCase):
    def setUp(self):
        self.inst = TempInstall()
        self.conn = self.inst.conn
        self.system = self.inst.system
        pool.maintain(self.conn, self.inst.cfg, self.system, self.inst.sizing, grow_shards=2)
        self.system.calls.clear()

    def tearDown(self):
        self.inst.close()

    def test_rotate_resyncs_firewall_when_unblock_fails(self):
        _, device_id = users.create_user(self.conn, self.system, name="A")
        self.system.calls.clear()
        self.system.fail_on = {"unblock"}
        with self.assertRaises(SystemError_):
            users.rotate_device(self.conn, self.system, device_id)
        # The old port was blocked before the failure: the table is rebuilt from the DB.
        self.assertEqual(self.system.names(), ["block", "unblock", "sync_firewall"])
        self.assertEqual(pool.counts(self.conn)["dirty"], 0)

    def test_no_resync_when_nothing_touched_firewall(self):
        with self.assertRaises(users.UserError):
            users.disable_user(self.conn, self.system, 999)
        self.assertNotIn("sync_firewall", self.system.names())

    def test_maintain_discards_shards_of_interrupted_apply(self):
        with db.transaction(self.conn):
            leftover = pool.create_shards(self.conn, 1)
        report = pool.maintain(self.conn, self.inst.cfg, self.system, self.inst.sizing, grow_shards=1)
        self.assertEqual(report["new_shards"], 1)
        # The leftover shard was discarded and its id reused by a shard that really started.
        self.assertIn(("enable_shard", leftover[0]), self.system.calls)
        self.assertEqual(pool.counts(self.conn)["shards"], 3)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM shards WHERE active = 0").fetchone()[0], 0)

    def test_apply_syncs_inside_transaction(self):
        seen = []
        self.system.sync_firewall = lambda: seen.append(self.conn.in_transaction)
        pool.maintain(self.conn, self.inst.cfg, self.system, self.inst.sizing, grow_shards=1)
        self.assertEqual(seen, [True])

    def test_commit_failure_rolls_back(self):
        conn = mock.MagicMock(wraps=self.conn)
        state = {"in": False}

        def execute(sql, *args):
            if sql == "COMMIT":
                raise sqlite3.OperationalError("database is locked")
            if sql == "BEGIN IMMEDIATE":
                state["in"] = True
            if sql == "ROLLBACK":
                state["in"] = False
            return self.conn.execute(sql, *args)

        conn.execute.side_effect = execute
        type(conn).in_transaction = mock.PropertyMock(side_effect=lambda: state["in"])
        with self.assertRaises(sqlite3.OperationalError):
            with db.transaction(conn):
                pass
        self.assertFalse(self.conn.in_transaction)


if __name__ == "__main__":
    unittest.main()
