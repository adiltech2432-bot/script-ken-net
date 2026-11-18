"""Implemented listener plan and intentional shared-port routing."""

from __future__ import annotations

SERVICES = (
    ("OpenSSH", "tcp", (22,), "Direct SSH login and SSH account backend"),
    ("UDP Custom", "udp", (1, 65535), "ePro UDP-Custom DNAT range; excludes UDP/53, UDP/2200 and the configured WireGuard port"),
    ("Dropbear", "tcp", (109, 143), "TCP/109 is HAProxy-multiplexed; TCP/143 is direct"),
    ("Dropbear WebSocket", "tcp", (109, 443), "WS path /dropbear-ws on shared TCP/109 and TLS/443 front doors"),
    ("SSH WebSocket", "tcp", (80, 443, 8080), "RFC WebSocket path /ssh-ws plus legacy HTTP Custom proxy on public TCP/8080"),
    ("OpenVPN SSL", "tcp", (443,), "OpenVPN control packets are identified by HAProxy on shared TCP/443"),
    ("OpenVPN WebSocket SSL", "tcp", (443,), "WS path /openvpn-ws, then local bridge to OpenVPN TCP/1194"),
    ("OpenVPN TCP", "tcp", (443, 1194), "TCP/1194 direct; TCP/443 via HAProxy packet demultiplexing"),
    ("OpenVPN UDP", "udp", (2200,), "Dedicated UDP listener"),
    ("Nginx Webserver", "tcp", (81,), "HAProxy sends HTTP to loopback Nginx TCP/8081; TCP/81 is public health page"),
    ("HAProxy Loadbalancer", "tcp", (80, 443, 8080), "Sole public TCP owner for HTTP, legacy proxy, TLS, and multiplexed backends"),
    ("Xray VMess TLS / WS / gRPC", "tcp", (443,), "TLS WebSocket /vmess and gRPC /vmess-grpc through Nginx"),
    ("Xray VMess None TLS", "tcp", (80,), "Cleartext WebSocket /vmess through HTTP frontend"),
    ("Xray VLESS TLS / WS / gRPC", "tcp", (443,), "TLS WebSocket /vless and gRPC /vless-grpc through Nginx"),
    ("Xray VLESS None TLS", "tcp", (80,), "Cleartext WebSocket /vless through HTTP frontend"),
    ("Trojan WS / gRPC", "tcp", (443,), "TLS WebSocket /whatever/trojan-ws (with /trojan-ws alias) and gRPC /trojan-grpc through Nginx"),
    ("Shadowsocks WS / gRPC", "tcp", (443,), "TLS WebSocket /ss-ws and gRPC /ss-grpc through Nginx"),
    ("WireGuard", "udp", (51820,), "Default; configured port is reserved from UDP-Custom's broad NAT rule"),
    ("DNSTT / SlowDNS", "udp", (53,), "DNSTT router uses delegated DNS zone and per-endpoint server keys"),
    ("WebSocket bridge", "tcp", (10015,), "Loopback-only backend; not a public listener"),
)


def port_owners() -> dict[tuple[str, int], list[str]]:
    owners: dict[tuple[str, int], list[str]] = {}
    for name, proto, ports, _ in SERVICES:
        if name == "UDP Custom":
            continue  # Range represented separately; exclusions are described above.
        for port in ports:
            owners.setdefault((proto, port), []).append(name)
    return owners


def conflicts() -> dict[tuple[str, int], list[str]]:
    return {key: value for key, value in port_owners().items() if len(set(value)) > 1}


def show() -> None:
    print("\nImplemented service and port plan")
    for name, proto, ports, note in SERVICES:
        ports_text = "1–65535 (with listed exclusions)" if name == "UDP Custom" else ", ".join(map(str, ports))
        print(f"- {name:<34} {proto.upper():<4} {ports_text:<30} {note}")
    shared = conflicts()
    if shared:
        print("\nIntentional shared listeners are routed by HAProxy/Nginx/WebSocket path:")
        for (proto, port), owners in sorted(shared.items()):
            print(f"- {proto.upper()}/{port}: {', '.join(dict.fromkeys(owners))}")
    print("\nUDP-Custom's range must exclude UDP/53, UDP/2200 and the configured WireGuard port. Provider firewall rules are separate.")
