#!/usr/bin/env python3
"""Create and revoke named peers on an already configured WireGuard server."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
ENDPOINT_RE = re.compile(r"^(?:\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):[0-9]{1,5}$")
ROOT = Path("/etc/kennet-panel/wireguard")


def allocate_client_ip(interface_addresses: str, peer_addresses=()) -> str:
    """Pick a free IPv4 host address from an interface CIDR."""
    networks = [ipaddress.ip_interface(x.strip()) for x in interface_addresses.split(",") if x.strip()]
    iface = next((x for x in networks if isinstance(x.ip, ipaddress.IPv4Address)), None)
    if iface is None:
        raise ValueError("WireGuard interface must have an IPv4 address")
    network = iface.network
    used_networks = [ipaddress.ip_network(f"{iface.ip}/32")]
    for value in peer_addresses:
        for token in str(value).split(","):
            token = token.strip()
            if not token:
                continue
            try:
                peer_network = ipaddress.ip_network(token, strict=False)
                if isinstance(peer_network, ipaddress.IPv4Network):
                    used_networks.append(peer_network)
            except ValueError:
                continue
    start = int(network.network_address) + 2
    end = int(network.broadcast_address)
    for integer in range(start, end):
        candidate = ipaddress.IPv4Address(integer)
        if not any(candidate in network for network in used_networks):
            return f"{candidate}/32"
    raise ValueError(f"No available client IP addresses in {network}")


def replace_or_append_peer(config_text: str, public_key: str, client_ip: str | None) -> str:
    """Update/remove a single peer block, preserving other config text."""
    lines = config_text.splitlines()
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip().lower() == "[peer]":
            if current:
                blocks.append(current)
            current = [line]
        elif current:
            current.append(line)
        else:
            blocks.append([line])
    if current:
        blocks.append(current)
    retained = []
    found = False
    for block in blocks:
        is_target = any(
            line.strip().lower().startswith("publickey")
            and line.split("=", 1)[-1].strip() == public_key
            for line in block
        )
        if is_target:
            found = True
        else:
            retained.extend(block)
    if client_ip is not None:
        if found:
            raise ValueError("That public key already exists in the interface configuration")
        if retained and retained[-1].strip():
            retained.append("")
        retained.extend(("[Peer]", f"PublicKey = {public_key}", f"AllowedIPs = {client_ip}"))
    elif not found:
        raise ValueError("Peer was not found in the interface configuration")
    return "\n".join(retained).rstrip() + "\n"


def client_profile(private_key: str, address: str, dns: str, server_public_key: str,
                   endpoint: str, allowed_ips: str) -> str:
    if not ENDPOINT_RE.fullmatch(endpoint) or not 1 <= int(endpoint.rsplit(":", 1)[1]) <= 65535:
        raise ValueError("Endpoint must be host:port or [IPv6]:port")
    if any(c in dns for c in "\r\n") or any(c in allowed_ips for c in "\r\n"):
        raise ValueError("DNS and AllowedIPs cannot contain line breaks")
    for token in allowed_ips.split(","):
        ipaddress.ip_network(token.strip(), strict=False)
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {address}\n"
        f"DNS = {dns}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {allowed_ips}\n"
        "PersistentKeepalive = 25\n"
    )


def _atomic_text(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _run(args, *, input_text=None):
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result.stdout.strip()


def render_server_config(interface: str, address: str, port: int, private_key: str, egress: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", egress):
        raise ValueError("Invalid interface name")
    network = ipaddress.ip_interface(address).network
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("The initial server setup currently uses an IPv4 tunnel subnet")
    if not 1 <= int(port) <= 65535:
        raise ValueError("Invalid listen port")
    subnet = str(network)
    return (
        "[Interface]\n"
        f"Address = {address}\n"
        f"ListenPort = {int(port)}\n"
        f"PrivateKey = {private_key}\n"
        f"PostUp = iptables -t nat -A POSTROUTING -s {subnet} -o {egress} -j MASQUERADE; iptables -A FORWARD -i {interface} -j ACCEPT; iptables -A FORWARD -o {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
        f"PreDown = iptables -t nat -D POSTROUTING -s {subnet} -o {egress} -j MASQUERADE; iptables -D FORWARD -i {interface} -j ACCEPT; iptables -D FORWARD -o {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
    )


def setup_server(interface: str = "wg0") -> None:
    """Install WireGuard and configure a basic IPv4 NAT server after confirmation."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Run as root")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        raise ValueError("Invalid interface name")
    config_path = Path("/etc/wireguard") / f"{interface}.conf"
    if config_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing config: {config_path}")
    address = input("Interface address [10.66.66.1/24]: ").strip() or "10.66.66.1/24"
    try:
        parsed_address = ipaddress.ip_interface(address)
        port = int(input("UDP port [51820]: ").strip() or "51820")
    except ValueError as exc:
        raise ValueError("Invalid interface address or UDP port") from exc
    if not isinstance(parsed_address, ipaddress.IPv4Interface):
        raise ValueError("Initial setup currently supports an IPv4 tunnel address")
    if not 1 <= port <= 65535:
        raise ValueError("UDP port must be in 1..65535")
    sysctl_path = Path("/etc/sysctl.d/99-kennet-wireguard.conf")
    if sysctl_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing sysctl file: {sysctl_path}")
    route = _run(["ip", "-o", "route", "get", "1.1.1.1"])
    match = re.search(r"\bdev\s+([A-Za-z0-9_.-]+)", route)
    if not match:
        raise RuntimeError("Could not detect the VPS egress interface")
    egress = match.group(1)
    print(f"WireGuard will be installed and {interface} configured at {address} on UDP port {port} via {egress}.")
    print("IPv4 forwarding and NAT will be configured. You may also need to open this port in your VPS provider firewall.")
    if input("Type YES to continue: ").strip() != "YES":
        return
    _run(["apt-get", "update"])
    _run(["apt-get", "install", "-y", "wireguard-tools", "iptables"])
    private_key = _run(["wg", "genkey"])
    public_key = _run(["wg", "pubkey"], input_text=private_key + "\n")
    _atomic_text(config_path, render_server_config(interface, address, port, private_key, egress))
    _atomic_text(sysctl_path, "net.ipv4.ip_forward=1\n", 0o644)
    try:
        _run(["sysctl", "--system"])
        _run(["systemctl", "enable", "--now", f"wg-quick@{interface}.service"])
    except Exception:
        config_path.unlink(missing_ok=True)
        sysctl_path.unlink(missing_ok=True)
        raise
    print(f"Interface {interface} is configured. Server public key: {public_key}")
    print(f"Open UDP/{port} in your VPS provider control panel before testing an external client.")


def _interface_config(interface: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        raise ValueError("Invalid WireGuard interface name")
    path = Path("/etc/wireguard") / f"{interface}.conf"
    if not path.is_file():
        raise FileNotFoundError(f"WireGuard config not found: {path}")
    return path


def add_peer(interface: str, username: str, endpoint: str, dns: str = "1.1.1.1",
             allowed_ips: str = "0.0.0.0/0, ::/0") -> Path:
    if not NAME_RE.fullmatch(username):
        raise ValueError("Username must contain 3-32 letters, digits, or underscores")
    if not shutil.which("wg"):
        raise RuntimeError("Install wireguard-tools and configure a server interface first")
    config_path = _interface_config(interface)
    config_text = config_path.read_text(encoding="utf-8")
    interface_block = config_text.split("[Peer]", 1)[0]
    match = re.search(r"(?im)^\s*Address\s*=\s*(.+?)\s*$", interface_block)
    if not match:
        raise ValueError("Interface config has no Address setting")
    used = re.findall(r"(?im)^\s*AllowedIPs\s*=\s*(.+?)\s*$", config_text)
    client_address = allocate_client_ip(match.group(1), used)
    port_match = re.search(r"(?im)^\s*ListenPort\s*=\s*([0-9]+)\s*$", interface_block)
    if not port_match or not 1 <= int(port_match.group(1)) <= 65535:
        raise ValueError("Interface config must define a valid ListenPort")
    server_public = _run(["wg", "show", interface, "public-key"])
    peer_state = ROOT / "peers.json"
    state = json.loads(peer_state.read_text(encoding="utf-8")) if peer_state.exists() else {}
    if username in state:
        raise ValueError("A WireGuard peer with that name already exists")
    private_key = _run(["wg", "genkey"])
    public_key = _run(["wg", "pubkey"], input_text=private_key + "\n")
    profile = client_profile(private_key, client_address, dns, server_public, endpoint, allowed_ips)
    new_text = replace_or_append_peer(config_text, public_key, client_address)
    _atomic_text(config_path, new_text)
    try:
        _run(["wg", "set", interface, "peer", public_key, "allowed-ips", client_address])
    except Exception:
        _atomic_text(config_path, config_text)
        raise
    profile_path = ROOT / "clients" / f"{username}.conf"
    try:
        _atomic_text(profile_path, profile)
        state[username] = {
            "public_key": public_key,
            "address": client_address,
            "profile": str(profile_path),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_text(peer_state, json.dumps(state, indent=2) + "\n")
    except Exception:
        _run(["wg", "set", interface, "peer", public_key, "remove"])
        _atomic_text(config_path, config_text)
        profile_path.unlink(missing_ok=True)
        raise
    return profile_path


def remove_peer(interface: str, username: str) -> None:
    if not NAME_RE.fullmatch(username):
        raise ValueError("Invalid username")
    config_path = _interface_config(interface)
    peer_state = ROOT / "peers.json"
    if not peer_state.exists():
        raise ValueError("No managed WireGuard peers found")
    state = json.loads(peer_state.read_text(encoding="utf-8"))
    if username not in state:
        raise ValueError("Managed WireGuard peer not found")
    public_key = state[username]["public_key"]
    old_text = config_path.read_text(encoding="utf-8")
    new_text = replace_or_append_peer(old_text, public_key, None)
    _atomic_text(config_path, new_text)
    try:
        _run(["wg", "set", interface, "peer", public_key, "remove"])
    except Exception:
        _atomic_text(config_path, old_text)
        raise
    profile_path = Path(state.pop(username)["profile"])
    profile_path.unlink(missing_ok=True)
    _atomic_text(peer_state, json.dumps(state, indent=2) + "\n")


def menu() -> None:
    interface = input("WireGuard interface name [wg0]: ").strip() or "wg0"
    while True:
        print("\nWireGuard — manage peers on a configured interface")
        print("1. Install and configure a WireGuard server")
        print("2. Create a client profile and add a peer")
        print("3. Remove a peer and its profile")
        print("0. Return")
        choice = input("Select: ").strip()
        try:
            if choice == "0":
                return
            if choice == "1":
                setup_server(interface)
            elif choice == "2":
                name = input("Username: ").strip()
                endpoint = input("Server address and port, e.g. vpn.example.com:51820: ").strip()
                dns = input("DNS [1.1.1.1]: ").strip() or "1.1.1.1"
                path = add_peer(interface, name, endpoint, dns)
                print(f"Client profile created: {path}")
                print("Transfer this file securely; it contains the client's private key.")
            elif choice == "3":
                name = input("Username: ").strip()
                if input(f"Confirm removal of peer {name}? Type YES: ").strip() == "YES":
                    remove_peer(interface, name)
                    print("Peer and client profile removed.")
            else:
                print("Invalid selection")
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            print(f"Could not complete the operation: {exc}")
