import io
import unittest
from contextlib import redirect_stdout
from subprocess import CompletedProcess
from unittest.mock import patch

import service_catalog


class ServiceCatalogTests(unittest.TestCase):
    def test_requested_services_are_documented(self):
        names = {item[0] for item in service_catalog.SERVICES}
        self.assertTrue({"OpenSSH", "Dropbear", "SSH WebSocket", "OpenVPN TCP", "OpenVPN UDP", "Nginx Webserver",
                         "HAProxy Loadbalancer", "Xray VLESS TLS / WS / gRPC", "Xray VMess TLS / WS / gRPC",
                         "Trojan WS / gRPC", "Shadowsocks WS / gRPC", "DNSTT / SlowDNS", "UDP Custom", "WireGuard"}.issubset(names))

    def test_public_port_matrix_matches_requested_transport_ports(self):
        by_name = {name: (proto, ports, note) for name, proto, ports, note in service_catalog.SERVICES}
        self.assertEqual(by_name["OpenSSH"][:2], ("tcp", (22,)))
        self.assertEqual(by_name["OpenVPN TCP"][:2], ("tcp", (443, 1194)))
        self.assertEqual(by_name["OpenVPN UDP"][:2], ("udp", (2200,)))
        self.assertEqual(by_name["DNSTT / SlowDNS"][:2], ("udp", (53,)))
        self.assertEqual(by_name["WireGuard"][:2], ("udp", (51820,)))
        self.assertIn("excludes UDP/53", by_name["UDP Custom"][2])

    def test_shared_ports_are_explicitly_flagged(self):
        self.assertIn(("tcp", 443), service_catalog.conflicts())
        self.assertIn(("tcp", 80), service_catalog.conflicts())

    @patch("service_catalog.shutil.which", return_value="/usr/bin/ss")
    @patch("service_catalog.subprocess.run")
    def test_live_listener_parser_reads_ipv4_ipv6_tcp_and_udp(self, run, _which):
        run.return_value = CompletedProcess([], 0,
            "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
            "tcp LISTEN 0 4096 [::]:443 [::]:*\n"
            "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n", "")

        self.assertEqual(service_catalog.listening_ports(),
                         {("tcp", 22), ("tcp", 443), ("udp", 53)})
        run.assert_called_once_with(["/usr/bin/ss", "-H", "-lntu"], capture_output=True,
                                    text=True, check=False, timeout=5)

    def test_live_port_report_distinguishes_listening_partial_and_range_plans(self):
        output = io.StringIO()
        live = {("tcp", 22), ("tcp", 443)}
        with patch.object(service_catalog, "listening_ports", return_value=live), \
             redirect_stdout(output):
            service_catalog.show()

        rendered = output.getvalue()
        self.assertIn("LISTENING", rendered)
        self.assertIn("OpenSSH", rendered)
        self.assertIn("PARTIAL", rendered)
        self.assertIn("OpenVPN TCP", rendered)
        self.assertIn("RANGE PLAN", rendered)
        self.assertIn("provider firewall", rendered)

    @patch("service_catalog.shutil.which", return_value=None)
    def test_live_port_probe_explains_missing_ss_tool(self, _which):
        with self.assertRaisesRegex(RuntimeError, "iproute2"):
            service_catalog.listening_ports()


if __name__ == "__main__":
    unittest.main()
