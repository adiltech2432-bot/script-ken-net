import unittest

import service_catalog


class ServiceCatalogTests(unittest.TestCase):
    def test_requested_services_are_documented(self):
        names = {item[0] for item in service_catalog.SERVICES}
        self.assertTrue({"Dropbear", "SSH WebSocket", "OpenVPN TCP", "OpenVPN", "Nginx WebSocket / Web",
                         "HAProxy", "VLESS TLS / WebSocket / gRPC", "VMess TLS / WebSocket / gRPC",
                         "Trojan WebSocket / gRPC", "Shadowsocks WebSocket / gRPC", "DNSTT / SlowDNS"}.issubset(names))

    def test_shared_ports_are_explicitly_flagged(self):
        self.assertIn(("tcp", 443), service_catalog.conflicts())
        self.assertIn(("tcp", 80), service_catalog.conflicts())


if __name__ == "__main__":
    unittest.main()
