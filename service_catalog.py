"""Implemented listener plan and intentional shared-port routing."""

from __future__ import annotations

import shutil
import subprocess

import terminal_ui

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


def listening_ports() -> set[tuple[str, int]]:
    """Read the live TCP/UDP listener table from the local host."""
    ss = shutil.which("ss")
    if not ss:
        raise RuntimeError("The ss command is unavailable; install iproute2 to inspect live listeners")
    result = subprocess.run([ss, "-H", "-lntu"], capture_output=True, text=True,
                            check=False, timeout=5)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "Could not read live listeners").strip())

    listeners: set[tuple[str, int]] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0].lower() not in {"tcp", "udp"}:
            continue
        try:
            port = int(fields[4].rsplit(":", 1)[1])
        except (ValueError, IndexError):
            continue
        if 1 <= port <= 65535:
            listeners.add((fields[0].lower(), port))
    return listeners


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
    live = listening_ports()
    print("\nLIVE SOCKET / PORT REPORT")
    print(f"{terminal_ui.CYAN}{'SOCKET':<14} {'SERVICE':<34} {'PROTO':<6} PORTS{terminal_ui.RESET}")
    for name, proto, ports, note in SERVICES:
        ports_text = "1–65535 (with listed exclusions)" if name == "UDP Custom" else ", ".join(map(str, ports))
        if name == "UDP Custom":
            state, color = "RANGE PLAN", terminal_ui.YELLOW
            observed_text = "NAT-managed range; listener check is not applicable"
        else:
            observed = [port for port in ports if (proto, port) in live]
            if len(observed) == len(ports):
                state, color = "LISTENING", terminal_ui.GREEN
            elif observed:
                state, color = "PARTIAL", terminal_ui.YELLOW
            else:
                state, color = "NOT LISTENING", terminal_ui.MAGENTA
            actual = ", ".join(str(port) for port in observed) or "none"
            missing = [port for port in ports if port not in observed]
            observed_text = f"live {actual}" + (f"; missing {', '.join(map(str, missing))}" if missing else "")
        print(f"{color}{state:<14}{terminal_ui.RESET} {name:<34} {proto.upper():<6} {ports_text}")
        print(f"  {terminal_ui.BLUE}{observed_text}{terminal_ui.RESET}  {note}")
    shared = conflicts()
    if shared:
        print("\nIntentional shared listeners are routed by HAProxy/Nginx/WebSocket path:")
        for (proto, port), owners in sorted(shared.items()):
            print(f"- {proto.upper()}/{port}: {', '.join(dict.fromkeys(owners))}")
    print("\nA listening socket does not prove backend health or public reachability; check the provider firewall separately.")
    print("UDP-Custom's range must exclude UDP/53, UDP/2200 and the configured WireGuard port.")
