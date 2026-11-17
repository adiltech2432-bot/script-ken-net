import asyncio
import base64
import os
import struct
import unittest
from unittest.mock import patch

import gateway_manager
import udp_custom_manager
import websocket_tunnel


class GatewayRenderingTests(unittest.TestCase):
    def test_haproxy_claims_public_http_and_routes_openvpn_before_tls(self):
        config = gateway_manager.render_haproxy()
        self.assertIn("bind :80", config)
        self.assertIn("bind :443", config)
        self.assertLess(config.index("use_backend kennet_openvpn_tcp"), config.index("use_backend kennet_nginx_tls"))
        self.assertIn("127.0.0.1:1194", config)

    def test_nginx_routes_xray_websocket_grpc_and_tunnel_bridge(self):
        config = gateway_manager.render_nginx("vpn.example.org")
        for item in ("/vless", "127.0.0.1:10001", "/vmess", "127.0.0.1:10002",
                     "/trojan-grpc", "grpc://127.0.0.1:10007", "/ssh-ws", "127.0.0.1:10015"):
            self.assertIn(item, config)
        self.assertIn("listen 127.0.0.1:8443 ssl http2", config)
        self.assertIn("listen 127.0.0.1:8080 http2", config)
        self.assertIn("location ^~ /trojan-grpc/", config)
        with self.assertRaises(ValueError):
            gateway_manager.render_nginx("invalid domain")

    def test_udp_exclusions_preserve_other_protocol_ports(self):
        self.assertEqual(udp_custom_manager._unit_text([53, 2200, 51820]).count("--exclude 53,2200,51820"), 1)

    def test_haproxy_config_merge_removes_unsupported_include_and_is_idempotent(self):
        base = "global\n    daemon\ndefaults\n    mode http\n# Include Ken-net public listener configuration\n    .include /etc/haproxy/conf.d/*.cfg\n"
        once = gateway_manager.merge_haproxy_config(base, gateway_manager.render_haproxy())
        twice = gateway_manager.merge_haproxy_config(once, gateway_manager.render_haproxy())
        self.assertNotIn(".include", twice)
        self.assertEqual(twice.count("frontend kennet_http"), 1)
        self.assertIn("# BEGIN KEN-NET MANAGED FRONTENDS", twice)
        self.assertIn("# END KEN-NET MANAGED FRONTENDS", twice)
        self.assertIn("global\n    daemon", twice)


class WebSocketTunnelTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def echo(reader, writer):
            try:
                while data := await reader.read(4096):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        self.backend = await asyncio.start_server(echo, "127.0.0.1", 0)
        self.backend_port = self.backend.sockets[0].getsockname()[1]
        self.target_patch = patch.object(websocket_tunnel, "TARGETS", {self.backend_port})
        self.path_patch = patch.dict(websocket_tunnel.PATH_TARGETS, {"/test": self.backend_port})
        self.target_patch.start(); self.path_patch.start()
        self.bridge = await asyncio.start_server(websocket_tunnel.handle, "127.0.0.1", 0)
        self.bridge_port = self.bridge.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.bridge.close(); self.backend.close()
        await self.bridge.wait_closed(); await self.backend.wait_closed()
        self.target_patch.stop(); self.path_patch.stop()

    async def test_websocket_upgrade_and_masked_payload_tunnel_to_backend(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.bridge_port)
        key = base64.b64encode(os.urandom(16)).decode()
        writer.write((f"GET /test HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                      f"Connection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                      "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        await writer.drain()
        response = await reader.readuntil(b"\r\n\r\n")
        self.assertIn(b"101 Switching Protocols", response)
        payload = b"real websocket test"
        mask = os.urandom(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        writer.write(bytes((0x82, 0x80 | len(payload))) + mask + masked)
        await writer.drain()
        first, second = await asyncio.wait_for(reader.readexactly(2), 2)
        self.assertEqual(first & 0x0F, 2)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", await reader.readexactly(2))[0]
        self.assertEqual(await asyncio.wait_for(reader.readexactly(length), 2), payload)
        writer.close(); await writer.wait_closed()

    async def test_backend_selection_never_accepts_remote_host(self):
        self.assertEqual(websocket_tunnel.target_port("/test", {"x-real-host": f"outside.example:{self.backend_port}"}), self.backend_port)
        with self.assertRaises(ValueError):
            websocket_tunnel.target_port("/other", {"x-real-host": "attacker.example:8080"})


if __name__ == "__main__":
    unittest.main()
