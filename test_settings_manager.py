"""Safe unit coverage for system-settings actions and menu navigation."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import dnstt_manager
import panel
import service_catalog
import settings_manager
import terminal_ui
import websocket_tunnel


class SettingsMenuTests(unittest.TestCase):
    def test_all_numbered_cards_dispatch_to_their_action_and_zero_returns(self):
        action_paths = {
            "panel.show_status": "1",
            "service_catalog.show": "2",
            "settings_manager.restart_services": "3",
            "settings_manager.change_domain": "4",
            "settings_manager.change_nameserver": "5",
            "settings_manager.rotate_dnstt_keys": "6",
            "settings_manager.change_banner": "7",
            "settings_manager.speed_test": "8",
            "settings_manager.change_ws_response": "9",
            "settings_manager.restart_or_reboot": "10",
        }
        mockers = {}
        choices = [value for number in action_paths.values() for value in (number, "")] + ["0"]
        with ExitStack() as stack:
            stack.enter_context(patch.object(settings_manager.os, "geteuid", return_value=0, create=True))
            cards = stack.enter_context(patch.object(terminal_ui, "option_cards"))
            stack.enter_context(patch.object(terminal_ui, "heading"))
            stack.enter_context(patch("builtins.input", side_effect=choices))
            for path in action_paths:
                mockers[path] = stack.enter_context(patch(path))
            settings_manager.menu()

        for action in mockers.values():
            action.assert_called_once()
        self.assertEqual(cards.call_count, 11)
        first_options = cards.call_args_list[0].args[1]
        self.assertTrue(cards.call_args_list[0].kwargs["colorful"])
        self.assertIn(("9", "≋  WebSocket response banner"), first_options)
        self.assertIn(("0", "←  Back to dashboard"), first_options)

    def test_root_requirement_exits_before_showing_settings(self):
        output = io.StringIO()
        with patch.object(settings_manager.os, "geteuid", return_value=1000, create=True), \
             patch.object(terminal_ui, "option_cards") as cards, redirect_stdout(output):
            settings_manager.menu()

        self.assertIn("require root", output.getvalue())
        cards.assert_not_called()

    def test_domain_action_uses_current_domain_as_prompt_default(self):
        with patch("services_manager.state", return_value={"domain": "old.example.net"}), \
             patch("services_manager.set_domain") as set_domain, \
             patch("builtins.input", return_value="new.example.net"):
            settings_manager.change_domain()

        set_domain.assert_called_once_with("new.example.net")

    def test_nameserver_action_saves_valid_external_nameserver(self):
        config = {"base_domain": "tunnel.example.net", "nameserver_host": "ns.example.org"}
        with patch.object(dnstt_manager, "_read_json", return_value=config), \
             patch.object(dnstt_manager, "_atomic") as atomic, \
             patch.object(terminal_ui, "detail_card"), \
             patch("builtins.input", return_value="ns2.example.org"):
            settings_manager.change_nameserver()

        self.assertEqual(config["nameserver_host"], "ns2.example.org")
        atomic.assert_called_once()

    def test_nameserver_action_rejects_names_inside_delegated_zone(self):
        config = {"base_domain": "tunnel.example.net", "nameserver_host": "ns.example.org"}
        with patch.object(dnstt_manager, "_read_json", return_value=config), \
             patch.object(dnstt_manager, "_atomic") as atomic, \
             patch.object(terminal_ui, "detail_card"), \
             patch("builtins.input", return_value="ns.tunnel.example.net"), \
             self.assertRaisesRegex(ValueError, "outside the delegated tunnel zone"):
            settings_manager.change_nameserver()
        atomic.assert_not_called()

    def test_key_rotation_explains_when_there_are_no_endpoints(self):
        output = io.StringIO()
        with patch.object(dnstt_manager, "list_accounts", return_value={}), redirect_stdout(output):
            settings_manager.rotate_dnstt_keys()
        self.assertIn("No DNSTT endpoints", output.getvalue())

    def test_key_rotation_updates_server_key_and_client_profile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            account_dir = Path(temp_dir) / "alice"
            client_dir = account_dir / "client"
            client_dir.mkdir(parents=True)
            key_file = account_dir / "server.key"
            pub_file = account_dir / "server.pub"
            profile = client_dir / "client.txt"
            client_pub_file = client_dir / "server.pub"
            key_file.write_text("old-private", encoding="utf-8")
            pub_file.write_text("old-public\n", encoding="utf-8")
            profile.write_text("server key: old-public\n", encoding="utf-8")
            client_pub_file.write_text("old-public\n", encoding="utf-8")
            record = {"domain": "alice.tunnel.example.net", "key_dir": str(account_dir),
                      "service": "kennet-dnstt-alice.service", "service_user": "kennet-dnstt-alice"}

            def fake_run(args):
                if args[0] == "id":
                    return "1001"
                if "-gen-key" in args:
                    Path(args[args.index("-privkey-file") + 1]).write_text("new-private", encoding="utf-8")
                    Path(args[args.index("-pubkey-file") + 1]).write_text("new-public\n", encoding="utf-8")
                return ""

            with patch.object(dnstt_manager, "list_accounts", return_value={"alice": record}), \
                 patch.object(dnstt_manager, "account_details", return_value=record), \
                 patch.object(dnstt_manager, "_configuration", return_value={"server_binary": "/usr/bin/dnstt-server"}), \
                 patch.object(settings_manager, "_run", side_effect=fake_run), \
                 patch.object(settings_manager.os, "chown", return_value=None, create=True), \
                 patch.object(terminal_ui, "detail_card"), \
                 patch("builtins.input", side_effect=["alice", "YES"]):
                settings_manager.rotate_dnstt_keys()

            self.assertEqual(key_file.read_text(encoding="utf-8"), "new-private")
            self.assertEqual(pub_file.read_text(encoding="utf-8").strip(), "new-public")
            self.assertIn("new-public", profile.read_text(encoding="utf-8"))
            self.assertEqual(client_pub_file.read_text(encoding="utf-8").strip(), "new-public")

    def test_restart_services_only_restarts_active_units_after_confirmation(self):
        calls = []

        def systemctl(args, **kwargs):
            calls.append(args)
            if args[1] == "is-active":
                return CompletedProcess(args, 0 if args[-1] == "active.service" else 3, "", "")
            return CompletedProcess(args, 0, "", "")

        with patch.object(settings_manager, "RESTART_UNITS", ("active.service", "inactive.service")), \
             patch.object(settings_manager.subprocess, "run", side_effect=systemctl), \
             patch("builtins.input", return_value="RESTART"):
            settings_manager.restart_services()

        self.assertIn(["systemctl", "restart", "active.service"], calls)
        self.assertNotIn(["systemctl", "restart", "inactive.service"], calls)

    def test_cancelled_restart_does_not_restart_units(self):
        check = CompletedProcess([], 0, "", "")
        with patch.object(settings_manager, "RESTART_UNITS", ("active.service",)), \
             patch.object(settings_manager.subprocess, "run", return_value=check) as run, \
             patch("builtins.input", return_value="no"):
            settings_manager.restart_services()

        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], ["systemctl", "is-active", "--quiet", "active.service"])

    def test_ssh_banner_change_writes_config_and_reloads_ssh(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            banner = Path(temp_dir) / "issue.net"
            config = Path(temp_dir) / "sshd_config.d" / "99-kennet-banner.conf"
            with patch.object(settings_manager, "SSH_BANNER", banner), \
                 patch.object(settings_manager, "SSH_BANNER_CONFIG", config), \
                 patch.object(settings_manager.subprocess, "run", return_value=CompletedProcess([], 0, "", "")), \
                 patch.object(settings_manager, "_run") as run, \
                 patch("builtins.input", return_value="Welcome to KEN-NET"):
                settings_manager.change_banner()

            self.assertEqual(banner.read_text(encoding="utf-8"), "Welcome to KEN-NET\n")
            self.assertEqual(config.read_text(encoding="utf-8"), "Banner " + str(banner) + "\n")
            run.assert_called_once_with(["systemctl", "reload", "ssh"])

    def test_ssh_banner_validation_failure_restores_previous_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            banner = Path(temp_dir) / "issue.net"
            banner.write_text("Previous banner\n", encoding="utf-8")
            config_dir = Path(temp_dir) / "sshd_config.d"
            config_dir.mkdir()
            config = config_dir / "99-kennet-banner.conf"
            config.write_text("Banner /etc/issue.net\n", encoding="utf-8")
            invalid = CompletedProcess([], 1, "", "bad sshd configuration")
            with patch.object(settings_manager, "SSH_BANNER", banner), \
                 patch.object(settings_manager, "SSH_BANNER_CONFIG", config), \
                 patch.object(settings_manager.subprocess, "run", side_effect=[invalid, CompletedProcess([], 0, "", "")]), \
                 patch.object(settings_manager, "_run"), \
                 patch("builtins.input", return_value="New banner"), \
                 self.assertRaisesRegex(RuntimeError, "bad sshd configuration"):
                settings_manager.change_banner()

            self.assertEqual(banner.read_text(encoding="utf-8"), "Previous banner\n")
            self.assertEqual(config.read_text(encoding="utf-8"), "Banner /etc/issue.net\n")

    def test_speed_test_runs_installed_cli_and_reports_failure(self):
        completed = CompletedProcess([], 0, "Download: 100 Mbps", "")
        version = CompletedProcess([], 0, "speedtest-cli 2.1.3", "")
        with patch.object(settings_manager.shutil, "which", side_effect=lambda name: "speedtest-cli" if name == "speedtest-cli" else None), \
             patch.object(settings_manager.subprocess, "run", side_effect=[version, completed]) as run, \
             redirect_stdout(io.StringIO()):
            settings_manager.speed_test()
        self.assertEqual(run.call_args_list[-1].args[0], ["speedtest-cli", "--simple"])

        failed = CompletedProcess([], 2, "", "measurement failed")
        with patch.object(settings_manager.shutil, "which", side_effect=lambda name: "speedtest-cli" if name == "speedtest-cli" else None), \
             patch.object(settings_manager.subprocess, "run", side_effect=[version, failed]), \
             redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, "measurement failed"):
            settings_manager.speed_test()

    def test_speed_test_uses_ookla_acceptance_flags_only_for_ookla_cli(self):
        version = CompletedProcess([], 0, "Speedtest by Ookla 1.2.0", "")
        completed = CompletedProcess([], 0, "Download: 100 Mbps", "")
        with patch.object(settings_manager.shutil, "which", side_effect=lambda name: "speedtest" if name == "speedtest" else None), \
             patch.object(settings_manager.subprocess, "run", side_effect=[version, completed]) as run, \
             redirect_stdout(io.StringIO()):
            settings_manager.speed_test()
        self.assertEqual(run.call_args_list[-1].args[0],
                         ["speedtest", "--accept-license", "--accept-gdpr"])

    def test_power_menu_reboots_only_after_exact_confirmation_and_reports_invalid_choice(self):
        with patch.object(terminal_ui, "option_cards"), \
             patch("builtins.input", return_value="4"), \
             patch.object(settings_manager, "_run") as run, redirect_stdout(io.StringIO()) as output:
            settings_manager.restart_or_reboot()
        run.assert_not_called()
        self.assertIn("Invalid selection", output.getvalue())

        with patch.object(terminal_ui, "option_cards"), \
             patch("builtins.input", side_effect=["2", "REBOOT"]), \
             patch.object(settings_manager, "_run") as run:
            settings_manager.restart_or_reboot()
        run.assert_called_once_with(["systemctl", "reboot"])

    def test_websocket_response_setting_is_safe_and_applies_to_next_handshake(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "websocket-response.json"
            with patch.object(settings_manager, "WS_RESPONSE_CONFIG", config), \
                 patch.object(websocket_tunnel, "WS_RESPONSE_CONFIG", config), \
                 patch.object(terminal_ui, "detail_card"), \
                 patch("builtins.input", return_value="KEN-NET Gateway 2"):
                settings_manager.change_ws_response()
                self.assertEqual(json.loads(config.read_text(encoding="utf-8")),
                                 {"banner": "KEN-NET Gateway 2"})
                response = websocket_tunnel.switching_protocols_response("accept-token")
                self.assertIn(b"HTTP/1.1 101 Switching Protocols", response)
                self.assertIn(b"X-KEN-NET-Banner: KEN-NET Gateway 2", response)
                self.assertIn(b"Sec-WebSocket-Accept: accept-token", response)

    def test_websocket_response_rejects_header_injection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "websocket-response.json"
            with patch.object(settings_manager, "WS_RESPONSE_CONFIG", config), \
                 patch.object(terminal_ui, "detail_card"), \
                 patch("builtins.input", return_value="KEN-NET\r\nUpgrade: no"), \
                 self.assertRaisesRegex(ValueError, "1–64 letters"):
                settings_manager.change_ws_response()
            self.assertFalse(config.exists())

    def test_websocket_response_uses_default_when_config_is_invalid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "websocket-response.json"
            config.write_text('{"banner":"safe\r\nX-Injected: yes"}', encoding="utf-8")
            with patch.object(websocket_tunnel, "WS_RESPONSE_CONFIG", config):
                self.assertEqual(websocket_tunnel.response_banner(), "KEN-NET")


if __name__ == "__main__":
    unittest.main()
