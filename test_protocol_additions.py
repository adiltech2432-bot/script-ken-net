import asyncio
import unittest

import dnstt_manager
import dnstt_mux
import wireguard_manager


def dns_query(name):
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"


class WireGuardTests(unittest.TestCase):
    def test_allocates_unused_address_from_interface_subnet(self):
        address = wireguard_manager.allocate_client_ip("10.44.0.1/24", ["10.44.0.2/32", "10.44.0.3/32"])
        self.assertEqual(address, "10.44.0.4/32")

    def test_adds_and_removes_peer_without_touching_other_peer(self):
        original = "[Interface]\nAddress = 10.44.0.1/24\n\n[Peer]\nPublicKey = KEEP\nAllowedIPs = 10.44.0.2/32\n"
        with_peer = wireguard_manager.replace_or_append_peer(original, "NEW", "10.44.0.3/32")
        self.assertIn("PublicKey = KEEP", with_peer)
        self.assertIn("PublicKey = NEW", with_peer)
        removed = wireguard_manager.replace_or_append_peer(with_peer, "NEW", None)
        self.assertIn("PublicKey = KEEP", removed)
        self.assertNotIn("PublicKey = NEW", removed)

    def test_client_profile_rejects_line_break_injection(self):
        with self.assertRaises(ValueError):
            wireguard_manager.client_profile("priv", "10.44.0.2/32", "1.1.1.1\nPostUp=bad", "pub",
                                             "vpn.example.com:51820", "0.0.0.0/0")

    def test_server_setup_config_contains_nat_and_forwarding_rules(self):
        text = wireguard_manager.render_server_config("wg0", "10.44.0.1/24", 51820, "private", "eth0")
        self.assertIn("ListenPort = 51820", text)
        self.assertIn("iptables -t nat -A POSTROUTING", text)
        self.assertIn("iptables -t nat -D POSTROUTING", text)

    def test_server_setup_rejects_shell_metacharacters_in_interface(self):
        with self.assertRaises(ValueError):
            wireguard_manager.render_server_config("wg0;touch", "10.44.0.1/24", 51820, "private", "eth0")


class DnsttTests(unittest.TestCase):
    def test_routes_dns_question_to_most_specific_domain(self):
        packet = dns_query("abc.alice.tunnel.example.com")
        question = dnstt_mux.dns_question_name(packet)
        port = dnstt_mux.choose_backend(question, {
            "tunnel.example.com": 5401,
            "alice.tunnel.example.com": 5402,
        })
        self.assertEqual(question, "abc.alice.tunnel.example.com")
        self.assertEqual(port, 5402)

    def test_drops_unmatched_domains(self):
        self.assertIsNone(dnstt_mux.choose_backend("abc.other.example.com", {"tunnel.example.com": 5401}))

    def test_rejects_truncated_or_non_query_packets(self):
        with self.assertRaises(ValueError):
            dnstt_mux.dns_question_name(b"\x00" * 12)

    def test_accounts_use_dns_safe_names(self):
        self.assertIsNone(dnstt_manager.NAME_RE.fullmatch("client_one"))
        self.assertIsNotNone(dnstt_manager.NAME_RE.fullmatch("client-one"))


class _EchoDns(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


class _Capture(asyncio.DatagramProtocol):
    def __init__(self):
        self.response = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, _addr):
        if not self.response.done():
            self.response.set_result(data)


class DnsttRouterIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_router_forwards_and_returns_datagrams(self):
        loop = asyncio.get_running_loop()
        backend, _ = await loop.create_datagram_endpoint(
            _EchoDns, local_addr=("127.0.0.1", 0)
        )
        backend_port = backend.get_extra_info("sockname")[1]
        router, _ = await loop.create_datagram_endpoint(
            lambda: dnstt_mux.DnsRouter({"tunnel.example.com": backend_port}),
            local_addr=("127.0.0.1", 0),
        )
        capture = _Capture()
        client, _ = await loop.create_datagram_endpoint(
            lambda: capture, local_addr=("127.0.0.1", 0)
        )
        try:
            packet = dns_query("x.tunnel.example.com")
            client.sendto(packet, router.get_extra_info("sockname"))
            response = await asyncio.wait_for(capture.response, timeout=2)
            self.assertEqual(response, packet)
        finally:
            client.close()
            router.close()
            backend.close()


if __name__ == "__main__":
    unittest.main()

