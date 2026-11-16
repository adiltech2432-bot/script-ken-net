#!/usr/bin/env python3
"""Editable terminal manager for VPN and tunnel services."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


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
    Protocol("tls", "TLS certificates / domain", "xray", note="TLS is a certificate transport setting used by Xray accounts."),
    Protocol("vless", "VLESS", "xray"),
    Protocol("trojan", "Trojan", "xray"),
    Protocol("vmess", "VMess", "xray"),
    Protocol("udp", "UDP tunnel", "udp", note="Active service detected; account management commands still need to be mapped."),
    Protocol("wireguard", "WireGuard", "wg-quick", note="Detected/configured WireGuard interfaces can be inspected; peer provisioning is not yet configured."),
    Protocol("slowdns", "SlowDNS", "server", note="This server runs SlowDNS through dnstt-server; no per-user account helper was identified."),
    Protocol("dnstt", "DNSTT", "server", note="The server runs dnstt-server and dnstt-client; this appears to be the SlowDNS transport instance."),
)


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
        return "Not ready", "UDP is a transport, not a standard account protocol; select a compatible service and client before enabling it"
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
                    return "Configured", f"TLS certificate exists for {domain}"
            except (OSError, ValueError):
                pass
        return "Not ready", "Set a domain with DNS pointing to this VPS, then request its TLS certificate"
    if protocol.service and systemd_active(protocol.service):
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
    if p.key in {"slowdns", "dnstt"}:
        import dnstt_manager
        dnstt_manager.menu()
        return
    if p.key in {"ssh", "tls", "vless", "vmess", "trojan"}:
        import services_manager
        services_manager.menu(p.key)
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
        print("\n=== Private Account Manager ===")
        print("1. Protocol status")
        print("2. Manage a protocol")
        print("3. Show requested services and ports")
        print("0. Exit")
        choice = input("Select: ").strip()
        if choice == "0":
            return 0
        if choice == "1":
            show_status()
        elif choice == "2":
            p = choose_protocol()
            if p:
                manage_protocol(p)
        elif choice == "3":
            import service_catalog
            service_catalog.show()
        else:
            print("Invalid selection.")


if __name__ == "__main__":
    raise SystemExit(main())
