#!/usr/bin/env python3
"""Small UDP DNS router for per-domain DNSTT server instances."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
from typing import Mapping


def dns_question_name(packet: bytes) -> str:
    """Read and validate the first QNAME from a DNS packet."""
    if len(packet) < 13:
        raise ValueError("DNS packet is too short")
    if packet[2] & 0x80 or (packet[2] & 0x78):
        raise ValueError("expected a standard DNS query")
    qdcount = int.from_bytes(packet[4:6], "big")
    if qdcount < 1:
        raise ValueError("DNS packet has no questions")
    pos = 12
    labels: list[str] = []
    visited: set[int] = set()
    jumped = False
    consumed_end: int | None = None
    total = 0
    while True:
        if pos >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[pos]
        if length == 0:
            if not jumped:
                consumed_end = pos + 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[pos + 1]
            if pointer >= len(packet) or pointer in visited:
                raise ValueError("invalid DNS compression pointer")
            visited.add(pointer)
            if not jumped:
                consumed_end = pos + 2
            pos = pointer
            jumped = True
            continue
        if length & 0xC0:
            raise ValueError("invalid DNS label type")
        end = pos + 1 + length
        if end > len(packet):
            raise ValueError("truncated DNS label")
        try:
            label = packet[pos + 1:end].decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise ValueError("DNS label is not ASCII") from exc
        if not label or any(ord(c) < 33 or ord(c) > 126 for c in label):
            raise ValueError("invalid DNS label")
        labels.append(label)
        total += length + 1
        if total > 254 or len(labels) > 127:
            raise ValueError("DNS name is too long")
        pos = end
    assert consumed_end is not None
    if consumed_end + 4 > len(packet):
        raise ValueError("DNS question is truncated")
    return ".".join(labels)


def choose_backend(question: str, routes: Mapping[str, int]) -> int | None:
    """Return the most specific matching route for a DNS name."""
    name = question.rstrip(".").lower()
    matches = []
    for domain, port in routes.items():
        suffix = domain.rstrip(".").lower()
        if name == suffix or name.endswith("." + suffix):
            matches.append((len(suffix), int(port)))
    return max(matches)[1] if matches else None


class _Backend(asyncio.DatagramProtocol):
    def __init__(self, public_transport, client_address, on_close, timeout: float = 8.0):
        self.public_transport = public_transport
        self.client_address = client_address
        self.on_close = on_close
        self.timeout = timeout
        self.transport = None
        self.timeout_handle = None
        self.closed = False

    def connection_made(self, transport):
        self.transport = transport
        loop = asyncio.get_running_loop()
        self.timeout_handle = loop.call_later(self.timeout, self._close)

    def datagram_received(self, data, _addr):
        self.public_transport.sendto(data, self.client_address)
        self._close()

    def error_received(self, exc):
        logging.debug("DNSTT backend UDP error: %s", exc)
        self._close()

    def _close(self):
        if self.closed:
            return
        self.closed = True
        if self.timeout_handle:
            self.timeout_handle.cancel()
            self.timeout_handle = None
        if self.transport:
            self.transport.close()
            self.transport = None
        self.on_close()


class DnsRouter(asyncio.DatagramProtocol):
    def __init__(self, routes: Mapping[str, int]):
        self.routes = dict(routes)
        self.transport = None
        self.pending = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        try:
            name = dns_question_name(data)
            port = choose_backend(name, self.routes)
        except (ValueError, TypeError):
            logging.info("Dropped malformed DNS packet from %s", addr)
            return
        if port is None or not 1 <= port <= 65535:
            logging.info("No DNSTT route for %s", name)
            return
        if self.pending >= 1024:
            logging.warning("Dropping DNS request: backend limit reached")
            return
        self.pending += 1
        loop = asyncio.get_running_loop()
        protocol = _Backend(self.transport, addr, self._backend_closed)
        async def forward():
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: protocol, remote_addr=("127.0.0.1", port)
                )
                transport.sendto(data)
            except OSError as exc:
                logging.info("Could not forward DNS request for %s: %s", name, exc)
                protocol._close()
        asyncio.create_task(forward())

    def _backend_closed(self):
        self.pending = max(0, self.pending - 1)


async def serve(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    listen = config.get("listen", "0.0.0.0:5300")
    host, raw_port = listen.rsplit(":", 1)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    routes = config.get("routes", {})
    if not isinstance(routes, dict):
        raise ValueError("routes must be a domain-to-port object")
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DnsRouter(routes), local_addr=(host or "0.0.0.0", int(raw_port))
    )
    logging.info("DNSTT DNS router listening on %s", listen)
    try:
        await asyncio.Future()
    finally:
        transport.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/kennet-panel/dnstt-routes.json"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(serve(args.config))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        logging.error("DNSTT router failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
