import unittest
from unittest.mock import patch

import panel


class PanelTests(unittest.TestCase):
    def test_expected_protocols_are_listed(self):
        self.assertEqual(
            {p.key for p in panel.PROTOCOLS},
            {"ssh", "tls", "vless", "trojan", "vmess", "udp", "wireguard", "slowdns", "dnstt"},
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

    def test_udp_is_not_misreported_as_a_standard_account_protocol(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "udp")
        state, detail = panel.protocol_state(p)
        self.assertEqual(state, "Not ready")
        self.assertIn("not a standard account protocol", detail)

    def test_slowdns_and_dnstt_share_detected_server_services(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "slowdns")
        with patch.object(panel, "systemd_active", side_effect=lambda service: service in {"server", "client"}), patch.object(
            panel.Path, "is_file", return_value=True
        ):
            state, detail = panel.protocol_state(p)
        self.assertEqual(state, "Active")
        self.assertIn("dnstt-server", detail)

    @patch.object(panel.subprocess, "run")
    @patch.object(panel.Path, "is_file", return_value=True)
    @patch.object(panel.os, "access", return_value=True)
    def test_helper_is_invoked_without_shell(self, _access, _is_file, run):
        run.return_value.returncode = 0
        self.assertEqual(panel.run_helper("/usr/bin/add-ssh"), 0)
        run.assert_called_once_with(["/usr/bin/add-ssh"], check=False)


if __name__ == "__main__":
    unittest.main()
