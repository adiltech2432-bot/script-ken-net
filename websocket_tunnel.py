#!/usr/bin/env python3
"""Small RFC 6455 bridge to a fixed allow-list of local tunnel services."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import re
import struct
from pathlib import Path
from urllib.parse import urlsplit

MAX_HEADER = 16 * 1024
MAX_FRAME = 16 * 1024 * 1024
TARGETS = {22, 2109, 1194, 143}
PATH_TARGETS = {"/": 22, "/ssh-ws": 22, "/dropbear-ws": 2109, "/openvpn-ws": 1194}
LEGACY_PORTS = {22: 22, 109: 2109, 143: 143, 1194: 1194}
LEGACY_ACL_BACKEND_PORT = 22
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_RESPONSE_CONFIG = Path("/etc/kennet-panel/websocket-response.json")
DEFAULT_RESPONSE_BANNER = "KEN-NET"
RESPONSE_BANNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,63}$")


def response_banner() -> str:
    """Read a safe optional response banner; invalid config falls back harmlessly."""
    try:
        config = json.loads(WS_RESPONSE_CONFIG.read_text(encoding="utf-8"))
        value = config.get("banner", DEFAULT_RESPONSE_BANNER) if isinstance(config, dict) else ""
        if isinstance(value, str) and RESPONSE_BANNER_RE.fullmatch(value.strip()):
            return value.strip()
    except (OSError, ValueError, TypeError):
        pass
    return DEFAULT_RESPONSE_BANNER


def switching_protocols_response(accept: str | None = None) -> bytes:
    """Build a compliant 101 response with the configurable safe KEN-NET banner."""
    lines = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade",
             f"X-KEN-NET-Banner: {response_banner()}"]
    if accept is not None:
        lines.append(f"Sec-WebSocket-Accept: {accept}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def target_port(path: str, headers: dict[str, str]) -> int:
    """Select a local backend; X-Real-Host may select a port but never a host."""
    port = PATH_TARGETS.get(urlsplit(path).path)
    real_host = headers.get("x-real-host", "").strip()
    if real_host:
        candidate = real_host.rsplit(":", 1)[-1]
        if candidate.isdigit() and int(candidate) in LEGACY_PORTS:
            port = LEGACY_PORTS[int(candidate)]
    if port not in TARGETS:
        raise ValueError("Unknown WebSocket tunnel path or backend port")
    return port


def connect_target_port(authority: str) -> int:
    parts = authority.rsplit(":", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        raise ValueError("CONNECT requires an allowed local service port")
    requested = int(parts[1])
    port = LEGACY_PORTS.get(requested, requested)
    if port not in TARGETS:
        raise ValueError("CONNECT is limited to local SSH, Dropbear, and OpenVPN ports")
    return port


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes, opcode: int = 2) -> None:
    length = len(payload)
    if length < 126:
        header = bytes((0x80 | opcode, length))
    elif length <= 0xFFFF:
        header = bytes((0x80 | opcode, 126)) + struct.pack("!H", length)
    else:
        header = bytes((0x80 | opcode, 127)) + struct.pack("!Q", length)
    writer.write(header + payload)
    await writer.drain()


async def _read_frame(reader: asyncio.StreamReader) -> tuple[bool, int, bytes]:
    first, second = await reader.readexactly(2)
    fin, opcode = bool(first & 0x80), first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
    if length > MAX_FRAME or not masked:
        raise ValueError("Invalid or oversized WebSocket frame")
    mask = await reader.readexactly(4)
    payload = bytearray(await reader.readexactly(length))
    for index in range(length):
        payload[index] ^= mask[index & 3]
    return fin, opcode, bytes(payload)


async def _copy_raw(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()


async def _relay_raw(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                     backend_reader: asyncio.StreamReader, backend_writer: asyncio.StreamWriter) -> None:
    tasks = [asyncio.create_task(_copy_raw(reader, backend_writer)),
             asyncio.create_task(_copy_raw(backend_reader, writer))]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*done, *pending, return_exceptions=True)


async def _ws_to_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while True:
        _, opcode, payload = await _read_frame(reader)
        if opcode == 8:
            await _write_frame(writer, payload[:125], opcode=8)
            return
        if opcode == 9:
            await _write_frame(writer, payload[:125], opcode=10)
        elif opcode in (0, 1, 2):
            writer.write(payload)
            await writer.drain()


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    backend: asyncio.StreamWriter | None = None
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        if len(raw) > MAX_HEADER:
            raise ValueError("HTTP request headers are too large")
        lines = raw.decode("latin-1").split("\r\n")
        method, path, _version = lines[0].split(" ", 2)
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        # HTTP Custom's legacy "ACL / ... Upgrade: Websocket" payload is a
        # raw TCP tunnel, not RFC 6455 framing. Keep it restricted to the root
        # path and the local SSH daemon; all standard WS paths remain framed.
        if method.upper() == "ACL":
            if path != "/" or headers.get("upgrade", "").lower() != "websocket":
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return
            backend_reader, backend = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", LEGACY_ACL_BACKEND_PORT), timeout=5)
            writer.write(switching_protocols_response())
            await writer.drain()
            await _relay_raw(reader, writer, backend_reader, backend)
            return

        if method.upper() == "CONNECT":
            port = connect_target_port(path)
            backend_reader, backend = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=5)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(_copy_raw(reader, backend), _copy_raw(backend_reader, writer))
            return

        if headers.get("upgrade", "").lower() != "websocket" or "upgrade" not in headers.get("connection", "").lower():
            writer.write(b"HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        key = headers.get("sec-websocket-key", "")
        try:
            if len(base64.b64decode(key, validate=True)) != 16:
                raise ValueError
        except (ValueError, TypeError):
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        port = target_port(path, headers)
        backend_reader, backend = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=5)
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
        writer.write(switching_protocols_response(accept))
        await writer.drain()
        async def tcp_to_ws() -> None:
            while data := await backend_reader.read(65536):
                await _write_frame(writer, data)
        await asyncio.gather(_ws_to_tcp(reader, backend), tcp_to_ws())
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ValueError, UnicodeError):
        pass
    finally:
        if backend is not None:
            backend.close()
            try:
                await backend.wait_closed()
            except OSError:
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def serve(address: str) -> None:
    host, port_text = address.rsplit(":", 1)
    server = await asyncio.start_server(handle, host, int(port_text), limit=MAX_HEADER + 1)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1:10015")
    args = parser.parse_args()
    asyncio.run(serve(args.listen))


if __name__ == "__main__":
    main()
