"""Reference service and listener matrix from the requested legacy panel layout."""

from __future__ import annotations

SERVICES = (
    ("Dropbear", "tcp", (109, 143), "SSH-compatible account backend; avoid binding 443 directly"),
    ("Dropbear WebSocket", "tcp", (109, 443), "WebSocket access needs an HTTP bridge in front of Dropbear"),
    ("SSH WebSocket", "tcp", (80, 443), "Requires an HTTP WebSocket bridge and TLS certificate on 443"),
    ("OpenVPN TCP", "tcp", (443, 1194), "TCP/1194 is direct; TCP/443 needs compatible TLS demultiplexing"),
    ("OpenVPN", "udp", (2200,), "UDP profile"),
    ("OpenVPN SSL / WebSocket", "tcp", (443,), "Shares the TLS front door; requires a compatible WebSocket bridge"),
    ("Nginx WebSocket / Web", "tcp", (80, 81, 443), "Port 81 must not be exposed unless an authenticated admin site uses it"),
    ("HAProxy", "tcp", (80, 443), "Must be the only public listener on each bound address and port"),
    ("VLESS TLS / WebSocket / gRPC", "tcp", (443,), "Xray backends need a TLS/SNI or HTTP path multiplexer to share 443"),
    ("VMess TLS / WebSocket / gRPC", "tcp", (443,), "Xray backends need a TLS/SNI or HTTP path multiplexer to share 443"),
    ("VLESS / VMess without TLS", "tcp", (80,), "Cleartext; use only behind an intentional HTTP proxy route"),
    ("Trojan WebSocket / gRPC", "tcp", (443,), "Xray backends need an HTTP/TLS multiplexer to share 443"),
    ("Shadowsocks WebSocket / gRPC", "tcp", (443,), "Xray stream transports need an HTTP/TLS multiplexer to share 443"),
    ("BadVPN UDP gateway", "udp", (7100, 7200, 7300), "Optional UDP-over-TCP gateway; not a standalone authenticated VPN account protocol"),
    ("DNSTT / SlowDNS", "udp", (53,), "Requires delegated DNS zone and an authoritative DNS route"),
)


def port_owners() -> dict[tuple[str, int], list[str]]:
    owners: dict[tuple[str, int], list[str]] = {}
    for name, proto, ports, _ in SERVICES:
        for port in ports:
            owners.setdefault((proto, port), []).append(name)
    return owners


def conflicts() -> dict[tuple[str, int], list[str]]:
    return {key: value for key, value in port_owners().items() if len(set(value)) > 1}


def show() -> None:
    print("\nRequested service and port plan")
    for name, proto, ports, note in SERVICES:
        ports_text = ", ".join(map(str, ports))
        print(f"- {name:<34} {proto.upper():<4} {ports_text:<18} {note}")
    shared = conflicts()
    if shared:
        print("\nShared listener ports require a compatible multiplexer; daemons cannot all bind these ports independently:")
        for (proto, port), owners in sorted(shared.items()):
            print(f"- {proto.upper()}/{port}: {', '.join(dict.fromkeys(owners))}")
    print("\nOnly enable a port after its service is configured. Provider firewall rules must be added in the VPS control panel.")

