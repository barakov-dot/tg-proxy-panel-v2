import contextlib
import io
import json
import unittest
from unittest import mock

from webproxy import ctl, db, pool, users
from tests.fakes import TempInstall


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _norm(sql):
    return " ".join(sql.split())


class ParseTest(unittest.TestCase):
    def test_parse_port(self):
        self.assertEqual(ctl.parse_port("20000"), 20000)
        self.assertEqual(ctl.parse_port("29999"), 29999)
        for bad in ("2000", "030000", "19999", "30000", "abc", "-1", "", "2000a", " 20000", "+2000",
                    "２００００"):
            with self.assertRaises(ctl.CtlError, msg=bad):
                ctl.parse_port(bad)

    def test_parse_shard(self):
        self.assertEqual(ctl.parse_shard("0"), 0)
        self.assertEqual(ctl.parse_shard("3"), 3)
        self.assertEqual(ctl.parse_shard("624"), 624)
        for bad in ("625", "01", "-1", "abc", "", "1000", "1.0"):
            with self.assertRaises(ctl.CtlError, msg=bad):
                ctl.parse_shard(bad)

    def test_parse_ports(self):
        self.assertEqual(ctl.parse_ports(["20002", "20000", "20002"]), [20000, 20002])
        with self.assertRaises(ctl.CtlError):
            ctl.parse_ports([])
        with self.assertRaises(ctl.CtlError):
            ctl.parse_ports(["20000", "30000"])


class RulesetTest(unittest.TestCase):
    def test_ruleset(self):
        text = ctl.build_ruleset([20001, 20000, 20017], [20001, 25000, 20017])
        lines = text.splitlines()
        self.assertEqual(lines[:3], ["table inet wpp", "delete table inet wpp", "table inet wpp {"])
        for port in (20000, 20001, 20017):
            self.assertIn("  counter c%d_up { }" % port, lines)
            self.assertIn("  counter c%d_down { }" % port, lines)
            self.assertIn('%d : "c%d_up"' % (port, port), text)
            self.assertIn('%d : "c%d_down"' % (port, port), text)
        self.assertIn("  set blocked { type inet_service; elements = { 20001, 20017 } }", lines)
        self.assertNotIn("25000", text)
        self.assertIn('    oifname "lo" tcp dport @blocked reject with tcp reset', lines)
        self.assertIn('    iifname != "lo" tcp dport { 8080, 8081, 8090, 19000-29999 } drop', lines)
        self.assertIn("counter name tcp dport map @cnt_up", text)
        self.assertIn("counter name tcp sport map @cnt_down", text)
        self.assertTrue(text.endswith("}\n"))
        self.assertEqual(text.count("{"), text.count("}"))

    def test_nothing_blocked(self):
        text = ctl.build_ruleset([20000], [])
        self.assertIn("  set blocked { type inet_service; }", text.splitlines())

    def test_empty(self):
        text = ctl.build_ruleset([], [20000])
        lines = text.splitlines()
        self.assertEqual(lines[:2], ["table inet wpp", "delete table inet wpp"])
        self.assertIn("  map cnt_up { type inet_service : counter; }", lines)
        self.assertIn("  map cnt_down { type inet_service : counter; }", lines)
        self.assertIn("  set blocked { type inet_service; }", lines)
        self.assertNotIn("elements", text)
        self.assertNotIn("counter c", text)
        self.assertIn("reject with tcp reset", text)
        self.assertEqual(text.count("{"), text.count("}"))


class ParseNftTest(unittest.TestCase):
    def test_parse_counters(self):
        data = {"nftables": [
            {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
            {"counter": {"family": "inet", "name": "c20000_up", "table": "wpp", "handle": 1,
                         "packets": 3, "bytes": 100}},
            {"counter": {"family": "inet", "name": "c20000_down", "table": "wpp", "handle": 2,
                         "packets": 4, "bytes": 200}},
            {"counter": {"family": "inet", "name": "c20016_down", "table": "wpp", "handle": 3,
                         "packets": 1, "bytes": 7}},
            {"counter": {"family": "inet", "name": "other", "table": "wpp", "bytes": 5}},
            {"counter": {"family": "inet", "name": "c2000_up", "table": "wpp", "bytes": 5}},
        ]}
        self.assertEqual(ctl.parse_counters(data), {20000: [100, 200], 20016: [0, 7]})
        self.assertEqual(ctl.parse_counters({}), {})

    def test_parse_set_elements(self):
        data = {"nftables": [
            {"metainfo": {"version": "1.0.9"}},
            {"set": {"family": "inet", "name": "blocked", "table": "wpp", "type": "inet_service",
                     "handle": 3, "elem": [20001, {"range": [20005, 20007]}, 20010]}},
            {"set": {"family": "inet", "name": "other", "table": "wpp", "elem": [20100]}},
        ]}
        self.assertEqual(ctl.parse_set_elements(data), {20001, 20005, 20006, 20007, 20010})
        empty = {"nftables": [{"set": {"family": "inet", "name": "blocked", "table": "wpp",
                                       "type": "inet_service", "handle": 3}}]}
        self.assertEqual(ctl.parse_set_elements(empty), set())

    def test_kill_filters(self):
        ports = list(range(20000, 20130))
        filters = list(ctl.kill_filters(reversed(ports)))
        self.assertEqual(len(filters), 3)
        seen = []
        for expression in filters:
            self.assertTrue(expression.startswith("( ") and expression.endswith(" )"))
            terms = expression[2:-2].split(" or ")
            chunk = sorted({int(t.split(":")[1]) for t in terms})
            for port in chunk:
                self.assertIn("sport = :%d" % port, terms)
                self.assertIn("dport = :%d" % port, terms)
            self.assertLessEqual(len(chunk), 64)
            seen += chunk
        self.assertEqual(seen, ports)
        self.assertEqual(list(ctl.kill_filters([])), [])


class MainTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.responses = {}

        def fake_run(argv, stdin=None, check=True):
            self.calls.append((list(argv), stdin, check))
            return self.responses.get(argv[1] if len(argv) > 1 else "", FakeProc())

        patches = [
            mock.patch.object(ctl, "run", side_effect=fake_run),
            mock.patch.object(ctl, "tool", side_effect=lambda name: "/usr/sbin/" + name),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def argvs(self):
        return [call[0] for call in self.calls]

    def test_block(self):
        ctl.main(["block", "20001", "20000"])
        argvs = self.argvs()
        self.assertEqual(argvs[0], ["/usr/sbin/nft", "add", "element", "inet", "wpp", "blocked",
                                    "{ 20000, 20001 }"])
        self.assertEqual(argvs[1][:5], ["/usr/sbin/ss", "-K", "-tn", "state", "established"])
        self.assertIn("sport = :20000", argvs[1][5])
        self.assertIn("dport = :20001", argvs[1][5])
        self.assertEqual(len(argvs), 2)
        self.assertFalse(self.calls[1][2])  # ss failures are not fatal

    def test_block_invalid(self):
        for args in (["block"], ["block", "19999"], ["block", "20000", "x"]):
            with self.assertRaises(ctl.CtlError):
                ctl.main(args)
        self.assertEqual(self.calls, [])

    def test_unblock_only_present(self):
        with mock.patch.object(ctl, "current_blocked", return_value={20000, 20005}):
            ctl.main(["unblock", "20000", "20001", "20005"])
        self.assertEqual(self.argvs(), [["/usr/sbin/nft", "delete", "element", "inet", "wpp", "blocked",
                                         "{ 20000, 20005 }"]])

    def test_unblock_nothing_present(self):
        with mock.patch.object(ctl, "current_blocked", return_value=set()):
            ctl.main(["unblock", "20000"])
        self.assertEqual(self.calls, [])

    def test_unblock_table_missing(self):
        with mock.patch.object(ctl, "current_blocked", return_value=None):
            with self.assertRaises(ctl.CtlError):
                ctl.main(["unblock", "20000"])
        self.assertEqual(self.calls, [])

    def test_current_blocked(self):
        payload = {"nftables": [{"set": {"name": "blocked", "elem": [20003]}}]}
        self.responses["-j"] = FakeProc(0, json.dumps(payload))
        self.assertEqual(ctl.current_blocked(), {20003})
        self.assertEqual(self.argvs()[0], ["/usr/sbin/nft", "-j", "list", "set", "inet", "wpp", "blocked"])
        self.responses["-j"] = FakeProc(1, "", "No such file")
        self.assertIsNone(ctl.current_blocked())

    def test_restart_relay(self):
        ctl.main(["restart", "relay"])
        self.assertEqual(self.argvs(), [["/usr/sbin/systemctl", "restart", "wpp-relay.service"]])

    def test_restart_caddy_and_shard(self):
        ctl.main(["restart", "caddy"])
        ctl.main(["restart", "shard", "12"])
        self.assertEqual(self.argvs(), [["/usr/sbin/systemctl", "restart", "wpp-caddy.service"],
                                        ["/usr/sbin/systemctl", "restart", "wpp-mtproxy@12.service"]])

    def test_non_shard_verbs_rejected(self):
        for args in (["stop", "relay"], ["start", "relay"], ["disable", "caddy"], ["enable", "relay"]):
            with self.assertRaises(ctl.CtlError, msg=args):
                ctl.main(args)
        self.assertEqual(self.calls, [])

    def test_shard_verbs(self):
        ctl.main(["enable", "shard", "3"])
        ctl.main(["stop", "shard", "3"])
        ctl.main(["install-shard-unit", "4"])
        self.assertEqual(self.argvs(), [["/usr/sbin/systemctl", "enable", "wpp-mtproxy@3.service"],
                                        ["/usr/sbin/systemctl", "stop", "wpp-mtproxy@3.service"],
                                        ["/usr/sbin/systemctl", "enable", "wpp-mtproxy@4.service"]])

    def test_invalid_units(self):
        for args in (["restart"], ["restart", "panel"], ["restart", "relay", "x"], ["restart", "shard"],
                     ["restart", "shard", "625"], ["enable", "shard", "01"], ["restart", "shard", "1", "2"],
                     ["install-shard-unit", "abc"]):
            with self.assertRaises(ctl.CtlError, msg=args):
                ctl.main(args)
        self.assertEqual(self.calls, [])

    def test_daemon_reload(self):
        ctl.main(["daemon-reload"])
        self.assertEqual(self.argvs(), [["/usr/sbin/systemctl", "daemon-reload"]])

    def test_unknown_commands(self):
        for args in ([], ["foo"], ["daemon-reload", "x"], ["install-shard-unit"], ["sync", "x"],
                     ["counters", "x"], ["status", "x"]):
            with self.assertRaises(ctl.CtlError, msg=args):
                ctl.main(args)
        self.assertEqual(self.calls, [])

    def test_counters(self):
        payload = {"nftables": [{"counter": {"name": "c20000_up", "bytes": 5}},
                                {"counter": {"name": "c20000_down", "bytes": 6}}]}
        self.responses["-j"] = FakeProc(0, json.dumps(payload))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ctl.main(["counters"])
        self.assertEqual(json.loads(out.getvalue()), {"20000": [5, 6]})
        self.assertEqual(self.argvs(), [["/usr/sbin/nft", "-j", "list", "counters", "table", "inet", "wpp"]])


class DatabaseTest(unittest.TestCase):
    def setUp(self):
        self.inst = TempInstall()
        self.conn = self.inst.conn
        self.system = self.inst.system
        with db.transaction(self.conn):
            pool.create_shards(self.conn, 2)
            pool.commit_staged(self.conn)
        db.set_setting(self.conn, "default_max_devices", 2)
        enabled, _ = users.create_user(self.conn, self.system, name="a")
        users.add_device(self.conn, self.system, enabled)
        disabled, _ = users.create_user(self.conn, self.system, name="b")
        users.disable_user(self.conn, self.system, disabled)
        _, gone = users.create_user(self.conn, self.system, name="c")
        users.rotate_device(self.conn, self.system, gone)
        with db.transaction(self.conn):
            pool.create_shards(self.conn, 1)  # inactive

    def tearDown(self):
        self.inst.close()

    def test_sql_in_sync(self):
        self.assertEqual(_norm(ctl.BLOCKED_PORTS_SQL), _norm(pool.BLOCKED_PORTS_SQL))
        self.assertEqual(_norm(ctl.ALL_PORTS_SQL), _norm(pool.ALL_PORTS_SQL))

    def test_read_db(self):
        ports, blocked, shards = ctl.read_db(self.inst.cfg.paths.db)
        self.assertEqual(blocked, pool.blocked_ports(self.conn))
        self.assertEqual(ports, list(range(20000, 20048)))
        self.assertEqual(shards, [0, 1, 2])
        self.assertEqual(len(blocked), 48 - 3)

    def test_sync(self):
        calls = []

        def fake_run(argv, stdin=None, check=True):
            calls.append((list(argv), stdin))
            return FakeProc()

        with mock.patch.object(ctl, "DB_PATH", self.inst.cfg.paths.db), \
                mock.patch.object(ctl, "run", side_effect=fake_run), \
                mock.patch.object(ctl, "tool", side_effect=lambda name: "/usr/sbin/" + name), \
                mock.patch.object(ctl, "current_blocked", return_value=set(range(20000, 20016))):
            ctl.main(["sync"])
        argv, stdin = calls[0]
        self.assertEqual(argv, ["/usr/sbin/nft", "-f", "-"])
        blocked = pool.blocked_ports(self.conn)
        self.assertEqual(stdin, ctl.build_ruleset(list(range(20000, 20048)), blocked))
        # Newly blocked ports (outside the previous set) lose their connections.
        killed = " ".join(c[0][5] for c in calls[1:])
        for port in blocked:
            if port >= 20016:
                self.assertIn("dport = :%d " % port, killed + " ")
        self.assertNotIn("dport = :20000 ", killed + " ")


if __name__ == "__main__":
    unittest.main()
