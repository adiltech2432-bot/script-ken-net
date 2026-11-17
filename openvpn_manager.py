#!/usr/bin/env python3
"""Certificate-based OpenVPN service and per-account .ovpn profile manager."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

import services_manager

ROOT = Path("/etc/openvpn/server")
PKI = Path("/etc/kennet-panel/openvpn/pki")
ACCOUNTS_DIR = Path("/etc/kennet-panel/openvpn/accounts")
STATE = services_manager.STATE
EASYRSA = "/usr/share/easy-rsa/easyrsa"
PROFILES = {"tcp443": ("tcp-client", 443), "tcp1194": ("tcp-client", 1194), "udp2200": ("udp", 2200)}


def _run(args: list[str], *, env: dict | None = None, input_text: str | None = None) -> str:
    result = subprocess.run(args, text=True, capture_output=True, check=False, env=env, input=input_text)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result.stdout.strip()


def _atomic(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush(); os.fsync(handle.fileno())
        os.chmod(temp, mode); os.replace(temp, path)
    except Exception:
        Path(temp).unlink(missing_ok=True)
        raise


def _env(cn: str = "") -> dict:
    import os
    env = os.environ.copy()
    env.update(EASYRSA_PKI=str(PKI), EASYRSA_BATCH="1", EASYRSA_REQ_CN=cn or "Kennet VPN CA")
    return env


def render_server_config(protocol: str, port: int, subnet: str, egress: str) -> str:
    if protocol not in {"tcp-server", "udp"} or not 1 <= int(port) <= 65535:
        raise ValueError("Invalid OpenVPN transport or port")
    if subnet not in {"10.8.0.0 255.255.255.0", "10.9.0.0 255.255.255.0"}:
        raise ValueError("Unexpected OpenVPN tunnel subnet")
    if not egress.replace("-", "").replace("_", "").isalnum():
        raise ValueError("Invalid network interface")
    tun = "tun0" if subnet.startswith("10.8.") else "tun1"
    tag = "tcp" if protocol == "tcp-server" else "udp"
    return f"""port {int(port)}
proto {protocol}
dev {tun}
topology subnet
server {subnet}
ca {PKI}/ca.crt
cert {PKI}/issued/server.crt
key {PKI}/private/server.key
dh none
tls-crypt {ROOT}/tls-crypt.key
crl-verify {PKI}/crl.pem
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
status /run/openvpn-server/kennet-{port}.status 10
verb 3
"""


def _nat_script(interface: str, subnet: str, egress: str) -> tuple[str, str]:
    if interface not in {"tun0", "tun1"}:
        raise ValueError("Invalid OpenVPN interface")
    up = f"""#!/bin/sh
set -eu
iptables -t nat -C POSTROUTING -s {subnet} -o {egress} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {subnet} -o {egress} -j MASQUERADE
iptables -C FORWARD -i {interface} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i {interface} -j ACCEPT
iptables -C FORWARD -o {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -o {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
"""
    down = f"""#!/bin/sh
set -eu
iptables -t nat -D POSTROUTING -s {subnet} -o {egress} -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i {interface} -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
"""
    return up, down

def install() -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Run as root")
    domain = services_manager.state().get("domain", "")
    if not services_manager.DOMAIN_RE.fullmatch(domain):
        raise ValueError("Set the shared domain first")
    if not Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").is_file():
        raise FileNotFoundError("Obtain the domain TLS certificate before installing the shared gateway")
    if input("Install certificate-based OpenVPN TCP/1194, TCP/443 mux, and UDP/2200? Type YES: ").strip() != "YES":
        return
    if not shutil.which("openvpn") or not Path(EASYRSA).is_file():
        _run(["apt-get", "update"])
        _run(["apt-get", "install", "-y", "openvpn", "easy-rsa", "iptables"])
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o750)
    PKI.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not (PKI / "ca.crt").is_file():
        _run([EASYRSA, "init-pki"], env=_env())
        _run([EASYRSA, "build-ca", "nopass"], env=_env())
        _run([EASYRSA, "build-server-full", "server", "nopass"], env=_env("server"))
        _run([EASYRSA, "gen-crl"], env=_env())
        _run(["openvpn", "--genkey", "secret", str(ROOT / "tls-crypt.key")])
        os.chmod(ROOT / "tls-crypt.key", 0o600)
    _atomic(PKI / "crl.pem", (PKI / "crl.pem").read_text(encoding="utf-8"), 0o644)
    route = _run(["ip", "-o", "route", "get", "1.1.1.1"])
    match = re.search(r"\bdev\s+([A-Za-z0-9_.-]+)", route)
    if not match:
        raise RuntimeError("Could not detect VPS egress interface for OpenVPN NAT")
    egress = match.group(1)
    for tag, interface, subnet in (("tcp", "tun0", "10.8.0.0/24"), ("udp", "tun1", "10.9.0.0/24")):
        nat_up, nat_down = _nat_script(interface, subnet, egress)
        _atomic(ROOT / f"kennet-nat-up-{tag}.sh", nat_up, 0o755)
        _atomic(ROOT / f"kennet-nat-down-{tag}.sh", nat_down, 0o755)
    nat_unit = """[Unit]
Description=Ken-net OpenVPN forwarding and NAT rules
Before=openvpn-server@server-tcp.service openvpn-server@server-udp.service
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/etc/openvpn/server/kennet-nat-up-tcp.sh && /etc/openvpn/server/kennet-nat-up-udp.sh'
ExecStop=/bin/sh -c '/etc/openvpn/server/kennet-nat-down-tcp.sh; /etc/openvpn/server/kennet-nat-down-udp.sh'
[Install]
WantedBy=multi-user.target
"""
    _atomic(Path("/etc/systemd/system/kennet-openvpn-nat.service"), nat_unit, 0o644)
    _atomic(Path("/etc/sysctl.d/99-kennet-openvpn.conf"), "net.ipv4.ip_forward=1\n", 0o644)
    _run(["sysctl", "--system"])
    _atomic(ROOT / "server-tcp.conf", render_server_config("tcp-server", 1194, "10.8.0.0 255.255.255.0", egress), 0o644)
    _atomic(ROOT / "server-udp.conf", render_server_config("udp", 2200, "10.9.0.0 255.255.255.0", egress), 0o644)
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", "--now", "kennet-openvpn-nat.service"])
    for unit in ("openvpn-server@server-tcp.service", "openvpn-server@server-udp.service"):
        _run(["systemctl", "enable", "--now", unit])
    try:
        import udp_custom_manager
        udp_custom_manager.refresh_exclusions()
    except (ImportError, RuntimeError):
        pass
    services_manager.open_ports([("tcp", 1194), ("udp", 2200)])


def _account_state() -> dict:
    return services_manager.state()


def _profile(domain: str, cn: str, protocol: str, port: int) -> str:
    cert = (PKI / "issued" / f"{cn}.crt").read_text(encoding="utf-8")
    key = (PKI / "private" / f"{cn}.key").read_text(encoding="utf-8")
    ca = (PKI / "ca.crt").read_text(encoding="utf-8")
    tls = (ROOT / "tls-crypt.key").read_text(encoding="utf-8")
    remote = f"remote {domain} {int(port)} {protocol}\n"
    return ("client\ndev tun\nproto " + protocol + "\n" + remote + "resolv-retry infinite\n"
            "nobind\npersist-key\npersist-tun\nremote-cert-tls server\nverb 3\n"
            "<ca>\n" + ca + "</ca>\n<cert>\n" + cert + "</cert>\n<key>\n" + key + "</key>\n"
            "<tls-crypt>\n" + tls + "</tls-crypt>\n")


def _issue_client(username: str) -> tuple[str, Path]:
    domain = services_manager.state().get("domain", "")
    cn = f"{username}-{secrets.token_hex(4)}"
    _run([EASYRSA, "build-client-full", cn, "nopass"], env=_env(cn))
    profiles = ACCOUNTS_DIR / username
    profiles.mkdir(parents=True, exist_ok=True, mode=0o700)
    for key, (proto, port) in PROFILES.items():
        _atomic(profiles / f"{key}.ovpn", _profile(domain, cn, proto, port))
    return cn, profiles


def add_account(username: str, days: int = 30, *, trial: bool = False) -> dict:
    if not services_manager.NAME_RE.fullmatch(username) or not 1 <= int(days) <= 3650:
        raise ValueError("Invalid OpenVPN username or validity period")
    data = _account_state()
    if username in data.get("accounts", {}):
        raise ValueError("Username already exists")
    cn, profile_dir = _issue_client(username)
    data.setdefault("accounts", {})[username] = {"protocol": "openvpn", "cert_cn": cn,
        "profile_dir": str(profile_dir), "expires_at": (dt.date.today() + dt.timedelta(days=int(days))).isoformat(), "trial": trial}
    services_manager._atomic(STATE, json.dumps(data, indent=2) + "\n")
    services_manager.install_expiry_timer()
    return data["accounts"][username]


def _revoke(cn: str) -> None:
    _run([EASYRSA, "revoke", cn], env=_env(cn), input_text="yes\n")
    _run([EASYRSA, "gen-crl"], env=_env())
    _atomic(PKI / "crl.pem", (PKI / "crl.pem").read_text(encoding="utf-8"), 0o644)
    for mode in ("tcp", "udp"):
        unit = f"openvpn-server@server-{mode}.service"
        result = subprocess.run(["systemctl", "restart", unit], text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout or f"Could not restart {unit}").strip())


def delete_account(username: str) -> None:
    record = services_manager.account_details("openvpn", username)
    _revoke(record["cert_cn"])
    shutil.rmtree(record["profile_dir"], ignore_errors=True)
    data = _account_state(); data["accounts"].pop(username, None)
    services_manager._atomic(STATE, json.dumps(data, indent=2) + "\n")


def renew_account(username: str, days: int = 30) -> dict:
    if not 1 <= int(days) <= 3650:
        raise ValueError("Validity must be from 1 to 3650 days")
    record = services_manager.account_details("openvpn", username)
    old_cn = record["cert_cn"]
    new_cn, profile_dir = _issue_client(username)
    _revoke(old_cn)
    data = _account_state(); item = data["accounts"][username]
    item.update(cert_cn=new_cn, profile_dir=str(profile_dir),
                expires_at=(dt.date.today() + dt.timedelta(days=int(days))).isoformat(), trial=False)
    services_manager._atomic(STATE, json.dumps(data, indent=2) + "\n")
    return item


def purge_expired(today: dt.date | None = None) -> list[str]:
    today = today or dt.date.today()
    data = _account_state(); expired = []
    for username, record in list(data.get("accounts", {}).items()):
        if record.get("protocol") != "openvpn":
            continue
        try:
            if dt.date.fromisoformat(record["expires_at"]) >= today:
                continue
        except (KeyError, ValueError):
            continue
        try:
            _revoke(record["cert_cn"])
        except (OSError, RuntimeError):
            continue
        shutil.rmtree(record.get("profile_dir", ""), ignore_errors=True)
        data["accounts"].pop(username, None); expired.append(username)
    if expired:
        services_manager._atomic(STATE, json.dumps(data, indent=2) + "\n")
    return expired


def connected_sessions() -> list[str]:
    sessions = set()
    for path in (Path("/run/openvpn-server/status-server-tcp.log"), Path("/run/openvpn-server/status-server-udp.log")):
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("CLIENT_LIST,"):
                fields = line.split(",")
                if len(fields) > 1:
                    sessions.add(fields[1])
    mapping = {record.get("cert_cn"): username for username, record in _account_state().get("accounts", {}).items()
               if record.get("protocol") == "openvpn"}
    return sorted(mapping[cn] for cn in sessions if cn in mapping)


def menu() -> None:
    import terminal_ui
    while True:
        terminal_ui.option_cards("OPENVPN ACCOUNT MANAGER", [("01", "Install / configure service"),
            ("02", "Create account"), ("03", "Renew account"), ("04", "Delete account"),
            ("05", "Account details"), ("06", "Create trial account"),
            ("07", "List accounts"), ("08", "Connected sessions"), ("00", "Return")])
        choice = input("Select: ").strip()
        try:
            if choice in {"0", "00"}: return
            if choice == "1": install()
            elif choice in {"2", "6"}:
                trial = choice == "6"
                name = "trial" + secrets.token_hex(3) if trial else input("Username: ").strip()
                days = 1 if trial else int(input("Validity days [30]: ").strip() or "30")
                record = add_account(name, days, trial=trial)
                print(json.dumps({"username": name, **record}, indent=2))
                print("Client profiles:", record["profile_dir"])
            elif choice == "3":
                name = input("Username: ").strip(); days = int(input("Extend validity by days [30]: ").strip() or "30")
                print("New client profiles:", renew_account(name, days)["profile_dir"])
            elif choice == "4":
                name = input("Username: ").strip()
                if input(f"Revoke and delete {name}? Type YES: ").strip() == "YES": delete_account(name)
            elif choice == "5":
                name = input("Username: ").strip(); print(json.dumps(services_manager.account_details("openvpn", name), indent=2))
            elif choice == "7":
                for name, record in _account_state().get("accounts", {}).items():
                    if record.get("protocol") == "openvpn": print(f"{name} | {record.get('expires_at')} | {record.get('profile_dir')}")
            elif choice == "8": print("Connected:", ", ".join(connected_sessions()) or "none")
            else: print("Invalid selection")
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(f"Operation failed: {exc}")


if __name__ == "__main__":
    menu()
