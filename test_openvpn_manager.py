import unittest

import openvpn_manager


class OpenVPNConfigTests(unittest.TestCase):
    def test_tcp443_and_udp2200_server_configs_are_separate_tunnels(self):
        tcp = openvpn_manager.render_server_config("tcp-server", 1194, "10.8.0.0 255.255.255.0", "ens3")
        udp = openvpn_manager.render_server_config("udp", 2200, "10.9.0.0 255.255.255.0", "ens3")
        self.assertIn("port 1194\nproto tcp-server\ndev tun0", tcp)
        self.assertIn("port 2200\nproto udp\ndev tun1", udp)
        self.assertIn("tls-crypt", tcp)
        self.assertIn("crl-verify", udp)

    def test_nat_rules_are_idempotent_and_per_interface(self):
        up, down = openvpn_manager._nat_script("tun1", "10.9.0.0/24", "ens3")
        self.assertIn("-s 10.9.0.0/24 -o ens3", up)
        self.assertIn("-i tun1", up)
        self.assertIn("-D FORWARD -i tun1", down)

    def test_invalid_protocol_subnet_or_interface_is_rejected(self):
        with self.assertRaises(ValueError):
            openvpn_manager.render_server_config("tcp-server", 1194, "10.7.0.0 255.255.255.0", "ens3")
        with self.assertRaises(ValueError):
            openvpn_manager.render_server_config("udp", 70000, "10.9.0.0 255.255.255.0", "ens3")
        with self.assertRaises(ValueError):
            openvpn_manager._nat_script("tun2", "10.10.0.0/24", "ens3")


if __name__ == "__main__":
    unittest.main()
