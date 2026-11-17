import unittest
from unittest.mock import patch

import panel
import udp_custom_manager
import gateway_manager


class PanelTests(unittest.TestCase):
    def test_expected_protocols_are_listed(self):
        self.assertEqual(
            {p.key for p in panel.PROTOCOLS},
            {"ssh", "dropbear", "tls", "vless", "trojan", "vmess", "shadowsocks", "openvpn", "udp", "wireguard", "slowdns", "dnstt"},
        )

    def test_account_protocols_are_managed_by_local_manager(self):
        self.assertIsNone(next(p for p in panel.PROTOCOLS if p.key == "ssh").add)
        self.assertIsNone(next(p for p in panel.PROTOCOLS if p.key == "vless").add)

    def test_xray_state_reports_installed_service(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "vless")
        with patch.object(panel, "systemd_active", return_value=True), patch.object(
            panel.Path, "is_file", return_value=True
        ):
            state, _ = panel.protocol_state(p)
        self.assertEqual(state, "Active")

    def test_dnstt_is_not_reported_as_ready_without_detected_services(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "dnstt")
        state, _ = panel.protocol_state(p)
        self.assertEqual(state, "Not ready")

    def test_udp_custom_is_not_reported_ready_without_installed_binary(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "udp")
        with patch.object(udp_custom_manager, "ready", return_value=(False, "UDP-Custom binary/configuration is missing")):
            state, detail = panel.protocol_state(p)
        self.assertEqual(state, "Not ready")
        self.assertIn("UDP-Custom binary/configuration is missing", detail)

    def test_slowdns_and_dnstt_share_detected_server_services(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "slowdns")
        with patch.object(panel, "systemd_active", side_effect=lambda service: service in {"server", "client"}), patch.object(
            panel.Path, "is_file", return_value=True
        ):
            state, detail = panel.protocol_state(p)
        self.assertEqual(state, "Active")
        self.assertIn("dnstt-server", detail)

    def test_slowdns_explains_its_dnstd_manager_setup(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "slowdns")
        state, detail = panel.protocol_state(p)
        self.assertEqual(state, "Not ready")
        self.assertIn("DNSTT manager in option 11", detail)

    def test_tls_status_does_not_claim_gateway_ready_from_certificate_alone(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "tls")
        with patch.object(panel.Path, "is_file", return_value=True), patch.object(
            panel.Path, "read_text", return_value='{"domain":"vpn.example.com"}'
        ), patch.object(gateway_manager, "is_ready", return_value=(False, "Inactive gateway services: haproxy, nginx")):
            state, detail = panel.protocol_state(p)
        self.assertEqual(state, "Partially configured")
        self.assertIn("Request / renew certificate", detail)

    @patch.object(panel.subprocess, "run")
    @patch.object(panel.Path, "is_file", return_value=True)
    @patch.object(panel.os, "access", return_value=True)
    def test_helper_is_invoked_without_shell(self, _access, _is_file, run):
        run.return_value.returncode = 0
        self.assertEqual(panel.run_helper("/usr/bin/add-ssh"), 0)
        run.assert_called_once_with(["/usr/bin/add-ssh"], check=False)


if __name__ == "__main__":
    unittest.main()
