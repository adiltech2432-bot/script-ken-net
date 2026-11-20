"""Focused tests for the read-only curses dashboard data layer."""

from __future__ import annotations

import subprocess
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
