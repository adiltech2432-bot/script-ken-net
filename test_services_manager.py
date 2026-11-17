import base64
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

import services_manager as services
from unittest.mock import patch
from types import SimpleNamespace


class ServiceManagerTests(unittest.TestCase):
    def test_ssh_password_prompt_rejects_short_password_before_confirmation(self):
        with patch.object(services.getpass, "getpass", side_effect=["short", "correct-horse", "correct-horse"]) as prompt:
            self.assertEqual(services._prompt_ssh_password(), "correct-horse")
        self.assertEqual(prompt.call_count, 3)

    def test_xray_installer_validates_and_starts_service(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(services, "XRAY_CONFIG", __import__("pathlib").Path(temp) / "config.json"), \
             patch("builtins.input", return_value="YES"), patch.object(services.shutil, "which", return_value="/usr/bin/xray"), \
             patch.object(services, "_run") as run, patch.object(services.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as subprocess_run:
            services.xray_install()
        self.assertTrue(any(call.args[0] == ["systemctl", "enable", "xray"] for call in run.mock_calls))
        self.assertTrue(any(call.args[0] == ["systemctl", "start", "xray"] for call in run.mock_calls))
        self.assertIn("-test", subprocess_run.call_args_list[0].args[0])

    def test_vless_link_contains_uuid_tls_domain_and_port(self):
        link = services.client_link("vless", "alice", "id-value", "vpn.example.com")
        self.assertTrue(link.startswith("vless://id-value@vpn.example.com:443?"))
        self.assertIn("security=tls", link)

    def test_trojan_link_contains_password_and_tls(self):
        link = services.client_link("trojan", "alice", "secret", "vpn.example.com")
        self.assertTrue(link.startswith("trojan://secret@vpn.example.com:443?"))
        self.assertIn("security=tls", link)
        self.assertIn("type=ws", link)

    def test_vmess_link_is_parseable_client_json(self):
        link = services.client_link("vmess", "alice", "uuid-value", "vpn.example.com")
        data = json.loads(base64.b64decode(link.removeprefix("vmess://")))
        self.assertEqual(data["add"], "vpn.example.com")
        self.assertEqual(data["port"], "443")
        self.assertEqual(data["id"], "uuid-value")
        self.assertEqual(data["tls"], "tls")
        self.assertEqual(data["net"], "ws")
        self.assertEqual(data["path"], "/vmess")

    def test_xray_protocols_share_the_public_tls_port_and_use_distinct_local_backends(self):
        self.assertEqual(set(services.XRAY_PORTS.values()), {443})
        local_ports = [item[0] for layout in services.XRAY_LAYOUT.values() for item in layout]
        self.assertEqual(len(local_ports), len(set(local_ports)))

    def test_xray_shared_inbounds_use_loopback_ws_and_grpc_transports(self):
        clients = [{"id": "id-1", "email": "alice"}]
        inbounds = services._managed_protocol_inbounds("vless", clients)
        self.assertEqual([item["port"] for item in inbounds], [10001, 10005])
        self.assertTrue(all(item["listen"] == "127.0.0.1" for item in inbounds))
        self.assertEqual(inbounds[0]["streamSettings"]["wsSettings"]["path"], "/vless")
        self.assertEqual(inbounds[1]["streamSettings"]["grpcSettings"]["serviceName"], "vless-grpc")

    def test_legacy_trojan_tls_account_migrates_to_shared_inbounds(self):
        config = {"inbounds": [{
            "tag": "kennet-trojan-ADIL", "protocol": "trojan", "port": 443,
            "settings": {"clients": [{"password": "secret", "email": "ADIL"}]},
            "streamSettings": {"network": "tcp", "security": "tls",
                               "tlsSettings": {"certificates": [{"keyFile": "/etc/letsencrypt/live/x/privkey.pem"}]}},
        }, {"tag": "external-inbound", "protocol": "socks", "port": 1080}]}
        migrated = services._migrate_legacy_xray_inbounds(config)
        self.assertEqual(migrated, ["ADIL"])
        self.assertEqual([item["tag"] for item in config["inbounds"]], [
            "external-inbound", "kennet-trojan-ws", "kennet-trojan-grpc"])
        self.assertTrue(all(item["listen"] == "127.0.0.1" for item in config["inbounds"][1:]))
        self.assertTrue(all(item["settings"]["clients"][0]["password"] == "secret"
                            for item in config["inbounds"][1:]))

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

    def test_created_xray_account_prints_protocol_specific_details_and_link(self):
        output = StringIO()
        with patch.object(services, "state", return_value={"domain": "vpn.example.com"}), redirect_stdout(output):
            services.show_created_account("vless", "alice", "uuid-123", 30)
        text = output.getvalue()
        self.assertIn("VLESS ACCOUNT", text)
        self.assertIn("Port TLS", text)
        self.assertIn("443/TCP", text)
        self.assertIn("vless://uuid-123@vpn.example.com:443", text)


if __name__ == "__main__":
    unittest.main()
