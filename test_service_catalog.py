import unittest

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


if __name__ == "__main__":
    unittest.main()
