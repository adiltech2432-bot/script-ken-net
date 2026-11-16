import unittest
from unittest.mock import patch

import panel


class PanelTests(unittest.TestCase):
    def test_expected_protocols_are_listed(self):
        self.assertEqual(
            {p.key for p in panel.PROTOCOLS},
            {"ssh", "tls", "vless", "trojan", "vmess", "udp", "wireguard", "slowdns", "dnstt"},
        )

    def test_known_protocols_have_expected_existing_helpers(self):
        by_key = {p.key: p for p in panel.PROTOCOLS}
        self.assertEqual(by_key["ssh"].add, "/usr/bin/add-ssh")
        self.assertEqual(by_key["vless"].add, "/usr/bin/add-vless")
        self.assertEqual(by_key["trojan"].add, "/usr/bin/add-tr")
        self.assertEqual(by_key["vmess"].add, "/usr/bin/add-ws")

    def test_xray_state_reports_ready_only_when_service_and_helpers_exist(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "vless")
        with patch.object(panel, "systemd_active", return_value=True), patch.object(
            panel.Path, "is_file", return_value=True
        ):
            state, _ = panel.protocol_state(p)
        self.assertEqual(state, "Ready via server tools")

    def test_dnstt_is_not_reported_as_ready_without_detected_services(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "dnstt")
        state, _ = panel.protocol_state(p)
        self.assertEqual(state, "Not ready")

    def test_detected_udp_service_is_reported_active_without_claiming_account_support(self):
        p = next(x for x in panel.PROTOCOLS if x.key == "udp")
        with patch.object(panel, "systemd_active", return_value=True), patch.object(
            panel.Path, "is_file", return_value=True
        ):
            state, detail = panel.protocol_state(p)
        self.assertEqual(state, "Active")
        self.assertIn("account management is not mapped yet", detail)

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
