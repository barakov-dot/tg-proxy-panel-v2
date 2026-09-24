import unittest

from webproxy import links

HOST = "proxy.example.com"
SECRET = "000102030405060708090a0b0c0d0e0f"


class LinksTest(unittest.TestCase):
    def test_marked_secret_vector(self):
        # tproxy-server README.md / BASE_PATH.md.
        self.assertEqual(links.marked_secret("8561944064fc730cbfa4473562d8ec59"), "cIVhlEBk_HMMv6RHNWLY7Fk")

    def test_root_link(self):
        self.assertEqual(
            links.build(HOST, "", SECRET),
            "https://t.me/webproxy?server=proxy.example.com&secret=000102030405060708090a0b0c0d0e0f",
        )

    def test_base_path_link(self):
        self.assertEqual(
            links.build(HOST, "phcf2vfe7zgbrslg", "8561944064fc730cbfa4473562d8ec59"),
            "https://t.me/webproxy?server=proxy.example.com%2Fphcf2vfe7zgbrslg&secret=cIVhlEBk_HMMv6RHNWLY7Fk",
        )

    def test_client_fields(self):
        self.assertEqual(links.client_server(HOST, "a/b"), "proxy.example.com/a/b")
        self.assertEqual(links.client_secret(SECRET, ""), SECRET)
        self.assertEqual(links.build(HOST, "a/b", SECRET).split("server=")[1].split("&")[0], "proxy.example.com%2Fa%2Fb")

    def test_capability_vectors(self):
        # BASE_PATH.md section 1 table.
        plain = bytes.fromhex(SECRET)
        padded = bytes.fromhex("dd" + SECRET)
        self.assertEqual(links.capability(HOST, "", plain), "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk")
        self.assertEqual(links.capability(HOST, "", padded), "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA")
        self.assertEqual(links.capability(HOST, "dobry-cola-super-app", plain),
                         "hHz99Xs93EN1j91G9gpNepXwGNNt5YdAFkEVk_LlqdQ")
        self.assertEqual(links.capability(HOST, "dobry-cola-super-app", padded),
                         "TGUkZaevsavLbHvlNWipnRoYxgzZ51ioWvbxgGT3wHo")

    def test_validation(self):
        for bad in ("", "00", SECRET.upper(), SECRET + "00", "zz" * 16):
            with self.assertRaises(ValueError):
                links.build(HOST, "", bad)
        for bad in ("/a", "a/", "a//b", "-a", "a.b", "a%2Fb", "x" * 129, "Ü"):
            with self.assertRaises(ValueError):
                links.build(HOST, bad, SECRET)


if __name__ == "__main__":
    unittest.main()
