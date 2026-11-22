"""Focused tests for the read-only curses dashboard data layer."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dashboard_tui


class DashboardDataTests(unittest.TestCase):
    def test_release_version_is_available_for_dashboard_and_installer(self):
        expected = Path(dashboard_tui.__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
        self.assertTrue(expected)
        self.assertEqual(dashboard_tui._release_version(), expected)

    def test_protocol_groups_cover_each_menu_number_once(self):
        keys = [key for _group, _color, group_keys in dashboard_tui.GROUPS for key in group_keys]
        self.assertEqual(keys, list(dashboard_tui.PROTOCOL_ORDER))
        self.assertEqual(len(keys), 12)
        self.assertEqual(len(set(keys)), 12)

    def test_original_protocol_numbers_keep_their_backend_mapping(self):
        self.assertEqual(dashboard_tui._legacy_protocol_key(2), "vmess")
        self.assertEqual(dashboard_tui._legacy_protocol_key(3), "vless")
        self.assertEqual(dashboard_tui._legacy_protocol_key(6), "dropbear")
        with self.assertRaises(ValueError):
            dashboard_tui._legacy_protocol_key(13)

    def test_rgb_palette_maps_to_xterm_color_range(self):
        for rgb in dashboard_tui.RGB.values():
            self.assertGreaterEqual(dashboard_tui._xterm_index(rgb), 16)
            self.assertLessEqual(dashboard_tui._xterm_index(rgb), 255)

    def test_server_geolocation_accepts_public_ip_facts_and_rejects_private_ips(self):
        facts = dashboard_tui._parse_server_geolocation({
            "success": True, "ip": "57.131.20.244", "city": "Milan",
            "connection": {"isp": "OVH SAS"},
        })
        self.assertEqual(facts, {"ip": "57.131.20.244", "city": "Milan", "isp": "OVH SAS"})
        self.assertEqual(dashboard_tui._parse_server_geolocation({
            "success": True, "ip": "10.0.0.1", "city": "Internal", "connection": {"isp": ""},
        }), {})

    def test_server_geolocation_retry_backoff_uses_monotonic_clock(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             patch.object(dashboard_tui, "SERVER_GEO_CACHE_FILE", Path(temp_dir) / "missing.json"), \
             patch.object(dashboard_tui, "_server_geo_cache", None), \
             patch.object(dashboard_tui, "_server_geo_refreshing", False), \
             patch.object(dashboard_tui, "_server_geo_retry_at", 1500.0), \
             patch("dashboard_tui.time.time", return_value=2_000_000_000.0), \
             patch("dashboard_tui.time.monotonic", return_value=1000.0), \
             patch("dashboard_tui.threading.Thread") as thread:
            facts, state = dashboard_tui._server_geolocation()

        self.assertEqual(facts, {})
        self.assertEqual(state, "unavailable")
        thread.assert_not_called()

    def test_server_information_card_combines_local_and_detected_server_facts(self):
        import dnstt_manager
        import services_manager

        with patch.object(services_manager, "state", return_value={
                 "server_info": {"expiration": "2027-12-01", "owner": "Admin"}}), \
             patch.object(dnstt_manager, "_read_json", return_value={"nameserver_host": "ns.example.org"}), \
             patch.object(dashboard_tui, "_local_public_ip", return_value="57.131.20.244"), \
             patch.object(dashboard_tui, "_server_geolocation", return_value=(
                 {"ip": "57.131.20.244", "city": "Milan", "isp": "OVH SAS"}, "ready")), \
             patch.object(dashboard_tui, "_server_provider", return_value=""):
            info = dashboard_tui._server_info_card("example.org")

        self.assertEqual(info["ip"], "57.131.20.244")
        self.assertEqual(info["city"], "Milan")
        self.assertEqual(info["isp"], "OVH SAS")
        self.assertEqual(info["nameserver"], "ns.example.org")
        self.assertEqual(info["expiration"], "2027-12-01")
        self.assertEqual(info["owner"], "Admin")

    def test_dashboard_layout_grows_protocol_cards_without_overlapping_tools_or_footer(self):
        layouts = [dashboard_tui._main_grid_layout(height, width)
                   for height, width in ((24, 72), (36, 100), (44, 120), (60, 150))]
        for layout in layouts:
            self.assertLess(int(layout["tools_y"]) + 2, int(layout["footer_y"]))
        self.assertEqual(layouts[0]["card_height"], 1)
        self.assertGreater(layouts[-1]["card_height"], layouts[1]["card_height"])
        self.assertTrue(layouts[-1]["detailed"])

    def test_narrow_detailed_status_card_uses_protocol_active_total_and_connection_columns(self):
        dashboard = dashboard_tui.Dashboard.__new__(dashboard_tui.Dashboard)
        dashboard.ascii = False
        dashboard.snapshot = {
            "domain": "it.example.org",
            "counts": {key: 1 for key in dashboard_tui.PROTOCOL_ORDER},
            "online": {key: 0 for key in dashboard_tui.PROTOCOL_ORDER},
        }
        dashboard.rows = [dashboard_tui.Row(key, key.title(), "GROUP", "blue", "Active",
                                            "active", "1 account", "xray", "TCP/443")
                          for key in ("ssh", "vmess", "vless", "trojan", "wireguard", "dnstt")]
        calls = []
        dashboard.put = lambda y, x, text, *args, **kwargs: calls.append((y, x, str(text)))
        dashboard._box = lambda y, x, height, width, title, color: calls.append((y, x, f"BOX:{height}:{width}:{title}"))

        dashboard._summary(4, 94, detailed=True, box_width=45)

        self.assertTrue(any("BOX:12:45:SERVER & ACCOUNT STATUS" in item[2] for item in calls))
        for header in ("PROTOCOL", "ACTIVE", "TOTAL ACC", "ONLINE"):
            self.assertIn(header, [item[2] for item in calls])
        self.assertIn("WIREGUARD", [item[2] for item in calls])
        self.assertIn("1 peers", [item[2] for item in calls])
        self.assertIn("0 online", [item[2] for item in calls])
        self.assertNotIn("● RUNNING   ·   STOPPED", [item[2] for item in calls])

    def test_wide_detailed_status_card_shows_full_connection_table_labels(self):
        dashboard = dashboard_tui.Dashboard.__new__(dashboard_tui.Dashboard)
        dashboard.ascii = False
        dashboard.snapshot = {
            "domain": "it.example.org",
            "counts": {key: 1 for key in dashboard_tui.PROTOCOL_ORDER},
            "online": {key: 2 for key in dashboard_tui.PROTOCOL_ORDER},
        }
        dashboard.rows = [dashboard_tui.Row(key, key.title(), "GROUP", "blue", "Active",
                                            "active", "1 account", "xray", "TCP/443")
                          for key in ("ssh", "vmess", "vless", "trojan", "wireguard", "dnstt")]
        calls = []
        dashboard.put = lambda y, x, text, *args, **kwargs: calls.append((y, x, str(text)))
        dashboard._box = lambda y, x, height, width, title, color: calls.append((y, x,
                            f"BOX:{height}:{width}:{title}"))

        dashboard._summary(4, 120, detailed=True, box_width=62)

        rendered = [item[2] for item in calls]
        for header in ("PROTOCOL", "ACTIVE", "TOTAL ACCOUNTS", "CONNECTIONS"):
            self.assertIn(header, rendered)
        self.assertIn("2 online", rendered)

    def test_header_uses_a_prominent_title_and_version_badge(self):
        dashboard = dashboard_tui.Dashboard.__new__(dashboard_tui.Dashboard)
        dashboard.ascii = False
        calls = []
        dashboard.put = lambda y, x, text, *args, **kwargs: calls.append((y, x, str(text), kwargs))

        dashboard._header(100)

        rendered = [item[2] for item in calls]
        self.assertIn("KEN-NET  •  SERVER MANAGEMENT PANEL", rendered)
        self.assertIn("v" + dashboard_tui._release_version(), rendered)
        self.assertIn("LIVE SERVER CONTROL  •  HOST STATUS & NETWORK SERVICES", rendered)

    @patch("subprocess.run")
    def test_listener_display_checks_all_catalog_ports(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0,
                "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
                "LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*\n"
                "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        self.assertEqual(dashboard_tui._configured_listeners("ssh"), "TCP/22, TCP/80, TCP/443")
        self.assertEqual(run.call_count, 2)

    @patch("subprocess.run")
    def test_listener_display_uses_dash_if_catalog_ports_are_absent(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertEqual(dashboard_tui._configured_listeners("vmess"), "—")

    @patch("subprocess.run")
    def test_listener_probe_failure_is_not_reported_as_a_port(self, run):
        run.side_effect = FileNotFoundError("ss")
        self.assertEqual(dashboard_tui._configured_listeners("ssh"), "—")


if __name__ == "__main__":
    unittest.main()
