import base64
import json
import unittest

import services_manager as services


class ServiceManagerTests(unittest.TestCase):
    def test_vless_link_contains_uuid_tls_domain_and_port(self):
        link = services.client_link("vless", "alice", "id-value", "vpn.example.com")
        self.assertTrue(link.startswith("vless://id-value@vpn.example.com:443?"))
        self.assertIn("security=tls", link)

    def test_trojan_link_contains_password_and_tls(self):
        link = services.client_link("trojan", "alice", "secret", "vpn.example.com")
        self.assertTrue(link.startswith("trojan://secret@vpn.example.com:2053?"))
        self.assertIn("security=tls", link)

    def test_vmess_link_is_parseable_client_json(self):
        link = services.client_link("vmess", "alice", "uuid-value", "vpn.example.com")
        data = json.loads(base64.b64decode(link.removeprefix("vmess://")))
        self.assertEqual(data["add"], "vpn.example.com")
        self.assertEqual(data["port"], "8443")
        self.assertEqual(data["id"], "uuid-value")
        self.assertEqual(data["tls"], "tls")

    def test_protocol_ports_are_distinct(self):
        self.assertEqual(len(set(services.XRAY_PORTS.values())), 3)


if __name__ == "__main__":
    unittest.main()
