import base64
import json
import unittest

import services_manager as services
from unittest.mock import patch
from types import SimpleNamespace


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

    @patch.object(services, "_run")
    @patch.object(services, "open_ports")
    @patch.object(services.subprocess, "run")
    @patch.object(services.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("203.0.113.8", 0))])
    def test_tls_certificate_uses_email_free_registration(self, _dns, run, allow, command):
        run.return_value = SimpleNamespace(stdout="", returncode=1)
        with patch.object(services.shutil, "which", return_value=None):
            services.acquire_tls_certificate("vpn.example.com")
        certbot = [call.args[0] for call in command.mock_calls]
        self.assertTrue(any("--register-unsafely-without-email" in args for args in certbot))


if __name__ == "__main__":
    unittest.main()
