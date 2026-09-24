import unittest

from webproxy import sizing

GIB = 1024 ** 3
MIB = 1024 ** 2


class SizingTest(unittest.TestCase):
    def test_pool_slots_rounding(self):
        self.assertEqual(sizing.pool_slots(1), 16)
        self.assertEqual(sizing.pool_slots(240), 320)
        self.assertEqual(sizing.pool_slots(243), 336)
        for users in (1, 17, 300, 999):
            self.assertEqual(sizing.pool_slots(users) % 16, 0)

    def test_reserve_matches_relay(self):
        # FINDINGS item 3, confirmed on VPS by tools/verify/relay-check.sh.
        self.assertEqual(sizing.RESERVE_ITEMS, 400)
        self.assertEqual(sizing.RESERVE_COST, 107200)
        self.assertTrue(sizing.reserve_ok(655, 512 * MIB, 256 * 1024))
        self.assertFalse(sizing.reserve_ok(656, 512 * MIB, 256 * 1024))
        self.assertTrue(sizing.reserve_ok(1000, 107200 * 1000, 10 ** 7))
        self.assertFalse(sizing.reserve_ok(1001, 107200 * 1000, 10 ** 7))

    def test_300_users_on_2gib(self):
        plan = sizing.compute(300, 2, 2 * GIB)
        limits = plan["relay_limits"]
        sessions = limits["max_sessions_global"]
        self.assertEqual(sessions, plan["pool_slots"])
        self.assertEqual(plan["shards"] * 16, plan["pool_slots"])
        self.assertTrue(sizing.reserve_ok(sessions, limits["max_pending_global"], limits["max_pending_items_global"]))
        self.assertGreaterEqual(limits["max_pending_items_global"], sessions * 400 + 262144)
        # At least half of the byte budget stays for data.
        self.assertLessEqual(sessions * sizing.RESERVE_COST * 2, limits["max_pending_global"])
        self.assertEqual(limits["max_profiles"], plan["pool_slots"] + 16)
        self.assertEqual(plan["relay_timeouts"]["reconnect_grace"], "60s")
        self.assertEqual(plan["profile_limits"]["max_sessions"], 1)
        self.assertEqual(plan["warnings"], [])

    def test_relay_validate_rules(self):
        # internal/config/config.go validate(): globals not below per-session values.
        for users, cpus, mem in ((1, 1, 512 * MIB), (300, 2, 2 * GIB), (1000, 4, 8 * GIB), (3000, 8, 4 * GIB)):
            plan = sizing.compute(users, cpus, mem)
            limits = plan["relay_limits"]
            profile = plan["profile_limits"]
            self.assertGreaterEqual(limits["max_pending_global"], 32 * MIB)
            self.assertGreaterEqual(limits["max_pending_items_global"], 16 * 1024)
            self.assertGreaterEqual(limits["max_streams_global"], 128)
            self.assertGreaterEqual(limits["max_streams_global"], limits["max_backend_dials_in_flight"])
            self.assertLessEqual(profile["new_streams_per_minute"], limits["new_streams_per_minute"])
            self.assertLessEqual(profile["new_streams_burst"], limits["new_streams_burst"])
            self.assertLessEqual(profile["max_sessions"], limits["max_sessions_global"])
            self.assertTrue(sizing.reserve_ok(limits["max_sessions_global"], limits["max_pending_global"],
                                              limits["max_pending_items_global"]))
            for value in limits.values():
                self.assertGreater(value, 0)

    def test_low_memory_warns_and_lowers_sessions(self):
        plan = sizing.compute(1000, 1, 512 * MIB)
        limits = plan["relay_limits"]
        self.assertLess(limits["max_sessions_global"], plan["pool_slots"])
        self.assertTrue(plan["warnings"])
        self.assertTrue(any("Памяти мало" in w for w in plan["warnings"]))
        self.assertTrue(any("vCPU" in w for w in plan["warnings"]))

    def test_invalid_target(self):
        for bad in (0, -5):
            with self.assertRaises(ValueError):
                sizing.compute(bad, 2, 2 * GIB)


if __name__ == "__main__":
    unittest.main()
