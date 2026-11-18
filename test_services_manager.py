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
    def test_ssh_session_counts_are_per_account_tcp_sessions(self):
        sockets = """ESTAB 0 0 192.0.2.10:22 198.51.100.7:41001 users:((\"sshd\",pid=120,fd=3))
ESTAB 0 0 192.0.2.10:22 198.51.100.7:41002 users:((\"sshd\",pid=121,fd=3))
ESTAB 0 0 192.0.2.10:22 198.51.100.8:41003 users:((\"sshd\",pid=122,fd=3))
"""
        processes = """alice 120 sshd: alice@notty
alice 121 sshd: alice@pts/0
bob 122 sshd: bob@notty
"""
        def run(command, **_kwargs):
            return SimpleNamespace(stdout=sockets if command[0] == "ss" else processes)

        with patch.object(services, "ssh_list", return_value=["alice", "bob"]), \
             patch.object(services.subprocess, "run", side_effect=run):
            counts = services.ssh_session_counts()
            sources = services.ssh_session_ips()

        self.assertEqual(counts, {"alice": 2, "bob": 1})
        self.assertEqual(sources, {"alice": ["198.51.100.7"], "bob": ["198.51.100.8"]})

    def test_expiry_purge_locks_and_removes_expired_ssh_account_and_archives_it(self):
        from datetime import date, timedelta
        from pathlib import Path

        old = (date.today() - timedelta(days=1)).isoformat()
        data = {"accounts": {"alice": {"protocol": "ssh", "expires_at": old, "max_ips": 2}}}
        with patch.object(services, "state", return_value=data), \
             patch.object(services, "_expire_linux_user") as expire_user, \
             patch.object(services, "_archive_expired") as archive, \
             patch.object(services, "_atomic") as atomic, \
             patch("wireguard_manager.list_peers", return_value={}), \
             patch("wireguard_manager.purge_expired", return_value=[]), \
             patch("dnstt_manager.list_accounts", return_value={}), \
             patch("dnstt_manager.purge_expired", return_value=[]), \
             patch("openvpn_manager._account_state", return_value={"accounts": {}}), \
             patch("openvpn_manager.purge_expired", return_value=[]):
            expired = services.purge_expired()

        self.assertEqual(expired, ["alice"])
        expire_user.assert_called_once_with("alice")
        archive.assert_called_once_with("ssh", "alice", data["accounts"].get("alice", {"protocol": "ssh", "expires_at": old, "max_ips": 2}))
        self.assertFalse(data["accounts"])
        self.assertEqual(atomic.call_args.args[0], services.STATE)

    def test_expiry_timer_checks_accounts_every_minute(self):
        captured = {}

        def remember(path, contents, mode=0o600):
            captured[str(path)] = contents

        with patch.object(services, "_atomic", side_effect=remember), patch.object(services, "_run"):
            services.install_expiry_timer()

        timer = next(text for path, text in captured.items() if path.endswith("kennet-account-expiry.timer"))
        self.assertIn("OnUnitActiveSec=1min", timer)

    def test_expired_linux_login_is_locked_and_sessions_are_terminated_before_deletion(self):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(services.subprocess, "run", side_effect=run), \
             patch.object(services.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"):
            services._expire_linux_user("alice")

        commands = [command for command, _kwargs in calls]
        self.assertEqual(commands, [
            ["id", "-u", "alice"], ["usermod", "--lock", "alice"],
            ["chage", "--expiredate", "0", "alice"],
            ["loginctl", "terminate-user", "alice"], ["pkill", "-KILL", "-u", "alice"],
            ["userdel", "-r", "alice"],
        ])
        self.assertTrue(all(kwargs.get("check") is True for _command, kwargs in calls[1:3] + calls[-1:]))

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

    def test_xray_installer_repairs_empty_outbounds_and_restarts_service(self):
        from pathlib import Path

        initial = {"log": {"loglevel": "warning"}, "inbounds": [{"tag": "keep-me"}],
                   "outbounds": [], "routing": {"rules": []}}
        with tempfile.TemporaryDirectory() as temp, patch.object(services, "XRAY_CONFIG", Path(temp) / "config.json"), \
             patch("builtins.input", return_value="YES"), patch.object(services.shutil, "which", return_value="/usr/bin/xray"), \
             patch.object(services, "_run") as run, patch.object(services.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")):
            services.XRAY_CONFIG.write_text(json.dumps(initial))
            services.xray_install()
            saved = json.loads(services.XRAY_CONFIG.read_text())

        self.assertEqual(saved["outbounds"], [{"protocol": "freedom", "tag": "direct"}])
        self.assertEqual(saved["inbounds"], initial["inbounds"])
        self.assertIn(["systemctl", "restart", "xray"], [call.args[0] for call in run.mock_calls])

    def test_default_outbound_repair_preserves_existing_custom_outbounds(self):
        config = {"outbounds": [{"tag": "proxy", "protocol": "socks"}]}
        self.assertFalse(services._ensure_default_xray_outbound(config))
        self.assertEqual(config["outbounds"], [{"tag": "proxy", "protocol": "socks"}])

    def test_vless_link_matches_working_legacy_ws_profile(self):
        link = services.client_link("vless", "alice", "alice", "vpn.example.com")
        self.assertTrue(link.startswith("vless://alice@vpn.example.com:443?"))
        self.assertIn("security=tls", link)
        self.assertIn("sni=Google.com", link)
        self.assertIn("path=%2Fvless", link)
        self.assertIn("allowInsecure=1", link)

    def test_trojan_link_contains_password_and_tls(self):
        link = services.client_link("trojan", "alice", "alice", "vpn.example.com")
        self.assertTrue(link.startswith("trojan://alice@vpn.example.com:443?"))
        self.assertIn("security=tls", link)
        self.assertIn("type=ws", link)
        self.assertIn("sni=Google.com", link)
        self.assertIn("path=%2Fwhatever%2Ftrojan-ws", link)
        self.assertIn("allowInsecure=1", link)

    def test_vmess_link_is_parseable_client_json(self):
        link = services.client_link("vmess", "alice", "alice", "vpn.example.com")
        data = json.loads(base64.b64decode(link.removeprefix("vmess://")))
        self.assertEqual(data["add"], "vpn.example.com")
        self.assertEqual(data["port"], "443")
        self.assertEqual(data["id"], "alice")
        self.assertEqual(data["tls"], "tls")
        self.assertEqual(data["net"], "ws")
        self.assertEqual(data["path"], "/vmess")
        self.assertEqual(data["sni"], "Google.com")
        self.assertTrue(data["allowInsecure"])

    def test_custom_xray_client_ids_match_account_names(self):
        self.assertEqual(services._xray_client("vless", "alice", "alice")["id"], "alice")
        self.assertEqual(services._xray_client("vmess", "alice", "alice")["id"], "alice")
        self.assertEqual(services._xray_client("trojan", "alice", "alice")["password"], "alice")

    def test_trojan_path_change_refreshes_existing_manager_inbound(self):
        config = {"inbounds": [{
            "tag": "kennet-trojan-ws", "protocol": "trojan", "listen": "127.0.0.1",
            "port": 10003, "settings": {"clients": [{"password": "alice", "email": "alice"}]},
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/trojan-ws"}},
        }]}
        self.assertTrue(services._refresh_managed_transports(config))
        self.assertEqual(config["inbounds"][0]["streamSettings"]["wsSettings"]["path"], "/whatever/trojan-ws")
        self.assertEqual(config["inbounds"][0]["settings"]["clients"][0]["password"], "alice")

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
