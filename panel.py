#!/usr/bin/env python3
"""Editable terminal manager for VPN and tunnel services."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Protocol:
    key: str
    title: str
    service: str | None
    add: str | None = None
    delete: str | None = None
    renew: str | None = None
    note: str = ""


PROTOCOLS = (
    Protocol("ssh", "SSH", "ssh"),
    Protocol("dropbear", "Dropbear", "kennet-dropbear"),
    Protocol("tls", "TLS certificates / domain", "xray", note="TLS is a certificate transport setting used by Xray accounts."),
    Protocol("vless", "VLESS", "xray"),
    Protocol("trojan", "Trojan", "xray"),
    Protocol("vmess", "VMess", "xray"),
    Protocol("shadowsocks", "Shadowsocks", "xray"),
    Protocol("openvpn", "OpenVPN", "openvpn-server@server-tcp", note="Install the certificate-based OpenVPN manager first."),
    Protocol("udp", "UDP Custom", "kennet-udp-custom", note="Install the upstream UDP-Custom backend first."),
    Protocol("wireguard", "WireGuard", "wg-quick"),
    Protocol("slowdns", "SlowDNS", "server", note="SlowDNS endpoints use the DNSTT manager in option 11; configure its DNS zone and router first."),
    Protocol("dnstt", "DNSTT", "server", note="Configure the DNSTT tools, delegated domain, DNS router, and endpoint first."),
)

ACCOUNT_KEYS = ("ssh", "vmess", "vless", "trojan", "shadowsocks", "dropbear", "openvpn", "udp", "wireguard", "slowdns", "dnstt", "tls")


def _managed_accounts():
    try:
        data = json.loads(Path("/etc/kennet-panel/services.json").read_text())
        return data.get("accounts", {})
    except (OSError, ValueError):
        return {}


def _system_metrics() -> tuple[str, str, str]:
    cpu = "n/a"
    try:
        loads = os.getloadavg()
        cpu = f"load {loads[0]:.2f}"
    except (AttributeError, OSError):
        pass
    ram = "n/a"
    try:
        mem = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1); mem[key] = int(value.strip().split()[0])
        total = mem["MemTotal"]; used = total - mem.get("MemAvailable", total)
        ram = f"RAM {used * 100 // total}%"
    except (OSError, KeyError, ValueError):
        pass
    disk = "n/a"
    try:
        usage = shutil.disk_usage("/"); disk = f"DISK {usage.used * 100 // usage.total}%"
    except OSError:
        pass
    uptime = "n/a"
    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0])); days, rem = divmod(seconds, 86400); hours, rem = divmod(rem, 3600); minutes = rem // 60
        uptime = f"UP {days}d {hours}h {minutes}m"
    except (OSError, ValueError, IndexError):
        pass
    return cpu, ram, disk + "  " + uptime


def dashboard() -> None:
    try:
        import services_manager
        data = services_manager.state()
        accounts = data.get("accounts", {})
        domain = data.get("domain") or "domain not configured"
    except (ImportError, OSError, ValueError):
        accounts, domain = {}, "domain not configured"
    cpu, ram, disk_uptime = _system_metrics()
    import terminal_ui
    width = max(58, min(shutil.get_terminal_size((80, 24)).columns, 100))
    terminal_ui.heading("KEN-NET  •  SERVER MANAGEMENT PANEL")
    print(f"{cpu}   {ram}   {disk_uptime}")
    print(f"DOMAIN  {domain}")
    totals = {key: sum(1 for rec in accounts.values() if rec.get("protocol") == key) for key in ("ssh", "vless", "vmess", "trojan", "shadowsocks")}
    wg_total = dnstt_total = wg_online = dnstt_ready = 0
    try:
        import wireguard_manager
        peers = wireguard_manager.list_peers()
        wg_total = len(peers)
        wg_online = sum(bool(wireguard_manager.peer_details(record.get("interface", "wg0"), name).get("connected")) for name, record in peers.items())
    except (ImportError, OSError, ValueError, subprocess.SubprocessError):
        pass
    try:
        import dnstt_manager
        dnstt_accounts = dnstt_manager.list_accounts()
        dnstt_total = len(dnstt_accounts)
        dnstt_ready = sum(systemd_active(record.get("service", "")) for record in dnstt_accounts.values())
    except (ImportError, OSError, ValueError, subprocess.SubprocessError):
        pass
    try:
        import services_manager
        live_ssh = len(services_manager.active_connections("ssh"))
    except (ImportError, OSError, ValueError):
        live_ssh = 0
    try:
        import services_manager
        xray_online = {key: services_manager.active_connections(key).get("active connections (not unique users)", 0) for key in ("vless", "vmess", "trojan")}
    except (ImportError, OSError, ValueError):
        xray_online = {key: 0 for key in ("vless", "vmess", "trojan")}
    for key, label in (("ssh", "SSH"), ("vmess", "VMESS"), ("vless", "VLESS"), ("trojan", "TROJAN")):
        online = live_ssh if key == "ssh" else xray_online.get(key, 0)
        qualifier = "sessions" if key in {"vmess", "vless", "trojan"} else "online"
        print(f"  {label:<8} {online:>3} {qualifier:<8} • {totals.get(key, 0):>3} accounts")
    print(f"  {'WIREGUARD':<8} {wg_online:>3} peers    • {wg_total:>3} accounts")
    print(f"  {'DNSTT':<8} {dnstt_ready:>3} services • {dnstt_total:>3} endpoints")
    protocol_options = [("01", "SSH"), ("02", "VMESS"), ("03", "VLESS"), ("04", "TROJAN"),
                        ("05", "SHADOWSOCKS"), ("06", "DROPBEAR"), ("07", "OPENVPN"),
                        ("08", "UDP CUSTOM"), ("09", "WIREGUARD"), ("10", "SLOWDNS"),
                        ("11", "DNSTT"), ("12", "TLS / DOMAIN")]
    terminal_ui.option_cards("PROTOCOLS  •  ACCOUNT MANAGEMENT", protocol_options, columns=2)
    terminal_ui.option_cards("SETTINGS & TOOLS", [("13", "System settings"), ("14", "Protocol status"),
                           ("15", "Services / ports"), ("0", "Exit")], columns=2, color=terminal_ui.YELLOW)
    print("\n" + "─ " * (width // 2))
    print("Select option [0-15]: ", end="", flush=True)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def systemd_active(service: str) -> bool:
    if not shutil.which("systemctl"):
        return False
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def protocol_state(protocol: Protocol) -> tuple[str, str]:
    if protocol.key == "wireguard":
        if not shutil.which("wg"):
            return "Not configured", "The wg tool is not installed"
        configs = sorted(Path("/etc/wireguard").glob("*.conf")) if Path("/etc/wireguard").is_dir() else []
        if not configs:
            return "Not configured", "No /etc/wireguard/*.conf files found"
        active = [p.stem for p in configs if systemd_active(f"wg-quick@{p.stem}.service")]
        if active:
            return "Active", "WireGuard interfaces: " + ", ".join(active)
        return "Configured", f"WireGuard is installed; configuration files: {len(configs)}"
    if protocol.key == "udp":
        try:
            import udp_custom_manager
            ready, detail = udp_custom_manager.ready()
            return ("Active" if ready else "Not ready"), detail
        except (ImportError, OSError, ValueError, RuntimeError):
            return "Not ready", "UDP-Custom has not been installed and configured"
    if protocol.key == "openvpn":
        active = all(systemd_active(f"openvpn-server@server-{mode}.service") for mode in ("tcp", "udp"))
        if active:
            return "Active", "OpenVPN TCP/1194, TCP/443 multiplexed, UDP/2200"
        return "Not ready", "Install/configure the certificate-based OpenVPN service first"
    if protocol.key == "dropbear":
        if systemd_active("kennet-dropbear.service") and systemd_active("haproxy.service"):
            return "Active", "Dropbear TCP/109 via the shared SSH/WebSocket mux; TCP/143 direct"
        if systemd_active("kennet-dropbear.service"):
            return "Partially active", "Dropbear backend is active but the HAProxy public-port gateway is not"
        return "Not ready", "Install Dropbear and the shared HAProxy gateway"
    if protocol.key in {"slowdns", "dnstt"}:
        if systemd_active("kennet-dnstt-router.service"):
            return "Active", "The multi-domain DNSTT router is running; each account has its own key and service"
        server_up = systemd_active("server") and Path("/etc/slowdns/dnstt-server").is_file()
        client_up = systemd_active("client") and Path("/etc/slowdns/dnstt-client").is_file()
        if server_up and client_up:
            return "Active", "dnstt-server and dnstt-client are running; no per-account management tool was found"
        if server_up:
            return "Partially active", "dnstt-server is running; check the dnstt-client service"
        return "Not ready", protocol.note
    if protocol.key == "tls":
        data_path = Path("/etc/kennet-panel/services.json")
        if data_path.is_file():
            try:
                import json
                domain = json.loads(data_path.read_text()).get("domain", "")
                if domain and Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").is_file():
                    import gateway_manager
                    ready, detail = gateway_manager.is_ready()
                    if ready:
                        return "Active", f"TLS certificate and shared gateway are active for {domain}"
                    return "Partially configured", f"Certificate exists for {domain}; gateway is not ready: {detail}. Use TLS/Domain > Request / renew certificate"
            except (OSError, ValueError):
                pass
        return "Not ready", "Set a domain with DNS pointing to this VPS, then request its TLS certificate"
    if protocol.service and systemd_active(protocol.service):
        if protocol.key in {"vless", "vmess", "trojan", "shadowsocks"}:
            if not systemd_active("haproxy.service") or not systemd_active("nginx.service"):
                return "Partially active", "Xray is running but the public TLS/WebSocket/gRPC gateway is not active"
        missing = [p for p in (protocol.add, protocol.delete, protocol.renew) if p and not Path(p).is_file()]
        if missing:
            return "Service active", "Missing management tools: " + ", ".join(missing)
        return "Active", f"Service {protocol.service} is active"
    return "Stopped or not installed", f"Service {protocol.service} is not active"


def run_helper(path: str | None) -> int:
    if not path or not Path(path).is_file():
        print("The management tool is not installed on this server.")
        return 1
    if not os.access(path, os.X_OK):
        print(f"The tool is not executable: {path}")
        return 1
    try:
        return subprocess.run([path], check=False).returncode
    except OSError as exc:
        print(f"Could not run the tool: {exc}")
        return 1


def show_status() -> None:
    print("\nProtocol status")
    for p in PROTOCOLS:
        state, detail = protocol_state(p)
        print(f"- {p.title}: {state} — {detail}")


def choose_protocol() -> Protocol | None:
    for i, p in enumerate(PROTOCOLS, 1):
        print(f"{i}. {p.title}")
    raw = input("Select a protocol (0 to return): ").strip()
    if raw == "0":
        return None
    try:
        index = int(raw) - 1
        return PROTOCOLS[index] if 0 <= index < len(PROTOCOLS) else None
    except ValueError:
        return None


def manage_protocol(p: Protocol) -> None:
    state, detail = protocol_state(p)
    print(f"\n{p.title}: {state} — {detail}")
    if not is_root():
        print("Account management requires running this program as root.")
        return
    if p.key == "wireguard":
        import wireguard_manager
        wireguard_manager.menu()
        return
    if p.key == "dropbear":
        import dropbear_manager
        dropbear_manager.menu()
        return
    if p.key in {"slowdns", "dnstt"}:
        import dnstt_manager
        dnstt_manager.menu()
        return
    if p.key == "udp":
        import udp_custom_manager
        udp_custom_manager.menu()
        return
    if p.key in {"ssh", "tls", "vless", "vmess", "trojan", "shadowsocks"}:
        import services_manager
        services_manager.menu(p.key)
        return
    if p.key == "openvpn":
        import openvpn_manager
        openvpn_manager.menu()
        return
    actions: tuple[tuple[str, str | None], ...] = (("Create account", p.add), ("Delete account", p.delete), ("Renew account", p.renew))
    available = [(label, path) for label, path in actions if path]
    if not available:
        print("No documented create/delete/renew tool is available for this protocol yet.")
        return
    for i, (label, _) in enumerate(available, 1):
        print(f"{i}. {label}")
    print("0. Return")
    try:
        selected = int(input("Select an action: ").strip())
    except ValueError:
        print("Invalid selection.")
        return
    if selected == 0:
        return
    if not 1 <= selected <= len(available):
        print("Invalid selection.")
        return
    label, helper = available[selected - 1]
    print(f"The request will be passed to the server tool: {label}.")
    run_helper(helper)


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("This program is intended for Ubuntu/Linux servers.")
        return 2
    while True:
        dashboard()
        choice = input().strip()
        if choice == "0":
            return 0
        if choice == "14":
            show_status()
        elif choice == "15":
            import service_catalog
            service_catalog.show()
        elif choice == "13":
            import settings_manager
            settings_manager.menu()
        elif choice.isdigit() and 1 <= int(choice) <= 12:
            ordered = ("ssh", "vmess", "vless", "trojan", "shadowsocks", "dropbear", "openvpn", "udp", "wireguard", "slowdns", "dnstt", "tls")
            p = next(item for item in PROTOCOLS if item.key == ordered[int(choice) - 1])
            manage_protocol(p)
        else:
            print("Invalid selection.")


if __name__ == "__main__":
    raise SystemExit(main())
