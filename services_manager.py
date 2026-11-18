#!/usr/bin/env python3
"""Manage local SSH and Xray accounts on Ubuntu without legacy helper scripts."""

from __future__ import annotations

import datetime as dt
import base64
import getpass
import ipaddress
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import socket
import tempfile
from pathlib import Path
from urllib.parse import quote

STATE = Path("/etc/kennet-panel/services.json")
EXPIRED_STATE = Path("/etc/kennet-panel/expired-accounts.json")
XRAY_CONFIG = Path("/usr/local/etc/xray/config.json")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
NAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
XRAY_PORTS = {"vless": 443, "vmess": 443, "trojan": 443, "shadowsocks": 443}
XRAY_LAYOUT = {
    "vless": ((10001, "ws", "/vless"), (10005, "grpc", "vless-grpc")),
    "vmess": ((10002, "ws", "/vmess"), (10006, "grpc", "vmess-grpc")),
    "trojan": ((10003, "ws", "/whatever/trojan-ws"), (10007, "grpc", "trojan-grpc")),
    "shadowsocks": ((10004, "ws", "/ss-ws"), (10008, "grpc", "ss-grpc")),
}
XRAY_WS_PROFILE = {
    "vless": {"path": "/vless", "sni": "Google.com"},
    "vmess": {"path": "/vmess", "sni": "Google.com"},
    "trojan": {"path": "/whatever/trojan-ws", "sni": "Google.com"},
    "shadowsocks": {"path": "/ss-ws", "sni": "domain"},
}


def _run(args: list[str], input_text: str | None = None) -> str:
    p = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout or "Command failed").strip())
    return p.stdout.strip()


def _atomic(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise


def state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {"domain": "", "accounts": {}}


def _archive_expired(protocol: str, username: str, record: dict) -> None:
    """Keep non-secret expiry metadata so lists can continue to show EXPIRED."""
    try:
        archived = json.loads(EXPIRED_STATE.read_text(encoding="utf-8")) if EXPIRED_STATE.exists() else {}
    except (OSError, ValueError):
        archived = {}
    key = f"{protocol}:{username}"
    archived[key] = {"protocol": protocol, "username": username,
                     "expires_at": record.get("expires_at", "unknown"),
                     "expired_at": dt.date.today().isoformat(),
                     "trial": bool(record.get("trial"))}
    _atomic(EXPIRED_STATE, json.dumps(archived, indent=2) + "\n")


def expired_accounts(protocol: str) -> list[dict]:
    try:
        archived = json.loads(EXPIRED_STATE.read_text(encoding="utf-8")) if EXPIRED_STATE.exists() else {}
    except (OSError, ValueError):
        return []
    return sorted((record for record in archived.values()
                   if record.get("protocol") == protocol), key=lambda item: item.get("username", "").casefold())


def account_roster_rows(protocol: str, names: list[str], *, connections: dict[str, int] | None = None,
                        connection_unknown: str = "") -> list[dict[str, object]]:
    """Build truthful per-account rows, including retained expiry history."""
    import terminal_ui
    data = state().get("accounts", {})
    active_names = set(names)
    rows: list[dict[str, object]] = []
    for username in sorted(active_names, key=str.casefold):
        record = data.get(username, {})
        count = (connections or {}).get(username)
        connection = f"{count} SESSIONS" if count else ("OFFLINE" if connections is not None else "UNKNOWN")
        details = "TRIAL account" if record.get("trial") else "Regular account"
        if record.get("max_ips"):
            details += f" · IP limit {record['max_ips']}"
        if connection_unknown:
            details = connection_unknown
        rows.append({"name": username, "connection": connection,
                     "status": terminal_ui.expiry_status(record.get("expires_at")),
                     "expires": record.get("expires_at", "unknown"), "details": details})
    for record in expired_accounts(protocol):
        username = str(record.get("username", ""))
        if username in active_names:
            continue
        rows.append({"name": username, "connection": "OFFLINE", "status": "EXPIRED",
                     "expires": record.get("expires_at", "unknown"),
                     "details": "Access revoked automatically"})
    return sorted(rows, key=lambda row: str(row["name"]).casefold())


def _expire_linux_user(username: str) -> None:
    """Lock a managed Unix login and terminate its existing sessions before removal."""
    if not NAME_RE.fullmatch(username):
        raise ValueError("Invalid managed Linux username in expiry state")
    exists = subprocess.run(["id", "-u", username], capture_output=True, check=False)
    if exists.returncode:
        return
    # Lock and expire first. If either command fails, keep the record so the
    # timer retries instead of silently reporting a live account as revoked.
    subprocess.run(["usermod", "--lock", username], capture_output=True, check=True)
    subprocess.run(["chage", "--expiredate", "0", username], capture_output=True, check=True)
    if shutil.which("loginctl"):
        subprocess.run(["loginctl", "terminate-user", username], capture_output=True, check=False)
    if shutil.which("pkill"):
        subprocess.run(["pkill", "-KILL", "-u", username], capture_output=True, check=False)
    subprocess.run(["userdel", "-r", username], capture_output=True, check=True)


def set_domain(domain: str, *, issue_certificate: bool = True) -> None:
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Enter a fully qualified domain name, e.g. vpn.example.com")
    data = state()
    data["domain"] = domain
    _atomic(STATE, json.dumps(data, indent=2) + "\n")
    print(f"Domain saved: {domain}. Checking DNS and requesting its TLS certificate.")
    if issue_certificate:
        import gateway_manager
        gateway_manager.install()
        acquire_tls_certificate(domain)
        gateway_manager.install()


def open_ports(ports: list[tuple[str, int]]) -> None:
    """Add narrow host-firewall allowances; cannot change a VPS provider firewall."""
    ufw = shutil.which("ufw")
    if not ufw or subprocess.run([ufw, "status"], capture_output=True, text=True).stdout.lower().find("status: active") < 0:
        print("Host UFW is not active; no host firewall rules were changed.")
        print("If your VPS provider has a network firewall, allow these ports there as well:")
        for proto, port in ports:
            print(f"  {proto.upper()}/{port}")
        return
    print("The following UFW allow rules will be added:")
    for proto, port in ports:
        print(f"  {proto.upper()}/{port}")
    if input("Type YES to apply these host-firewall rules: ").strip() != "YES":
        return
    for proto, port in ports:
        _run([ufw, "allow", f"{port}/{proto}"])


def install_ssh() -> None:
    if not shutil.which("sshd"):
        _run(["apt-get", "update"])
        _run(["apt-get", "install", "-y", "openssh-server"])
    _run(["systemctl", "enable", "--now", "ssh"])
    probe = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=False)
    if probe.returncode == 0 and "passwordauthentication no" in probe.stdout.lower():
        print("SSH password authentication is currently disabled. Enabling it increases exposure to password guessing.")
        if input("Type YES to enable password-based SSH logins for managed accounts: ").strip() == "YES":
            _atomic(Path("/etc/ssh/sshd_config.d/00-kennet-password-auth.conf"), "PasswordAuthentication yes\n", 0o644)
            _run(["sshd", "-t"])
            _run(["systemctl", "restart", "ssh"])
        else:
            print("SSH accounts can still use authorized keys; password login was not enabled.")
    open_ports([("tcp", 22)])


def install_ssh_ip_limit() -> None:
    """Install a fail-open PAM hook that enforces distinct remote IP limits."""
    source = Path(__file__).resolve().with_name("ssh_ip_limit.py")
    if not source.is_file():
        raise FileNotFoundError(f"SSH IP-limit helper is missing: {source}")
    pam_modules = list(Path("/usr/lib").glob("*/security/pam_exec.so")) + list(Path("/lib").glob("*/security/pam_exec.so"))
    if not pam_modules:
        raise RuntimeError("pam_exec.so is unavailable; cannot safely enable SSH IP limits")
    target = Path("/usr/local/lib/kennet-panel/ssh_ip_limit.py")
    target.parent.mkdir(parents=True, exist_ok=True)
    _atomic(target, source.read_text(encoding="utf-8"), 0o755)

    pam_file = Path("/etc/pam.d/sshd")
    if not pam_file.is_file():
        raise FileNotFoundError("/etc/pam.d/sshd is missing")
    original_pam = pam_file.read_text(encoding="utf-8")
    marker = "# BEGIN KEN-NET SSH DISTINCT-IP LIMIT"
    end_marker = "# END KEN-NET SSH DISTINCT-IP LIMIT"
    managed = f"{marker}\naccount requisite pam_exec.so quiet {target}\n{end_marker}"
    if marker in original_pam and end_marker in original_pam:
        before, rest = original_pam.split(marker, 1)
        _old, after = rest.split(end_marker, 1)
        updated_pam = before.rstrip() + "\n" + managed + after
    else:
        include = re.search(r"(?m)^\s*@include\s+common-account\s*$", original_pam)
        if include:
            updated_pam = original_pam[:include.start()] + managed + "\n" + original_pam[include.start():]
        else:
            account_line = re.search(r"(?m)^\s*account\s+", original_pam)
            if account_line:
                updated_pam = original_pam[:account_line.start()] + managed + "\n" + original_pam[account_line.start():]
            else:
                updated_pam = original_pam.rstrip() + "\n" + managed + "\n"

    pam_exec = Path("/etc/ssh/sshd_config.d/00-kennet-ip-limit.conf")
    original_ssh = pam_exec.read_text(encoding="utf-8") if pam_exec.exists() else None
    try:
        _atomic(pam_file, updated_pam, 0o644)
        effective = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=False)
        if effective.returncode:
            raise RuntimeError(effective.stderr.strip() or "Could not inspect sshd configuration")
        if "usepam yes" not in effective.stdout.lower():
            _atomic(pam_exec, "UsePAM yes\n", 0o644)
            _run(["sshd", "-t"])
            verified = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=False)
            if verified.returncode or "usepam yes" not in verified.stdout.lower():
                raise RuntimeError("SSH IP limits require UsePAM yes, but the effective SSH configuration did not enable it")
            _run(["systemctl", "restart", "ssh"])
    except Exception:
        _atomic(pam_file, original_pam, 0o644)
        if original_ssh is None:
            pam_exec.unlink(missing_ok=True)
        else:
            _atomic(pam_exec, original_ssh, 0o644)
        raise


def ssh_add(username: str, days: int, *, trial: bool = False,
            password: str | None = None, max_ips: int = 0) -> str:
    if not NAME_RE.fullmatch(username) or not 1 <= days <= 3650:
        raise ValueError("Use a 3-32 character username and expiry from 1 to 3650 days")
    if not 0 <= int(max_ips) <= 128:
        raise ValueError("Allowed IP count must be from 0 (unlimited) to 128")
    if password is not None and (len(password) < 8 or any(char in password for char in "\r\n:")):
        raise ValueError("Password must be at least 8 characters and contain no line breaks or ':'")
    if subprocess.run(["id", "-u", username], capture_output=True).returncode == 0:
        raise ValueError("Username already exists")
    if max_ips:
        install_ssh_ip_limit()
    password = password or "".join(secrets.choice(string.ascii_letters + string.digits + "!@#%") for _ in range(20))
    expiry = (dt.date.today() + dt.timedelta(days=days)).isoformat()
    _run(["useradd", "--create-home", "--shell", "/bin/sh", "--expiredate", expiry, username])
    try:
        _run(["chpasswd"], f"{username}:{password}\n")
    except Exception:
        subprocess.run(["userdel", "-r", username], capture_output=True)
        raise
    data = state()
    data["accounts"][username] = {"protocol": "ssh", "expires_at": expiry,
                                  "trial": trial, "max_ips": int(max_ips)}
    _atomic(STATE, json.dumps(data, indent=2) + "\n")
    install_expiry_timer()
    return password


def udp_add(username: str, days: int = 30, *, trial: bool = False) -> str:
    """Create a password-backed account for ePro UDP-Custom's system auth."""
    if not NAME_RE.fullmatch(username) or not 1 <= int(days) <= 3650:
        raise ValueError("Use a 3-32 character username and validity from 1 to 3650 days")
    if subprocess.run(["id", "-u", username], capture_output=True, check=False).returncode == 0:
        raise ValueError("Username already exists")
    password = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#%") for _ in range(20))
    expiry = (dt.date.today() + dt.timedelta(days=int(days))).isoformat()
    _run(["useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", "--expiredate", expiry, username])
    try:
        _run(["chpasswd"], f"{username}:{password}\n")
    except Exception:
        subprocess.run(["userdel", username], capture_output=True, check=False)
        raise
    data = state()
    data["accounts"][username] = {"protocol": "udp", "expires_at": expiry, "trial": trial}
    _atomic(STATE, json.dumps(data, indent=2) + "\n")
    install_expiry_timer()
    return password


def udp_list() -> list[str]:
    return sorted(name for name, record in state().get("accounts", {}).items()
                  if record.get("protocol") == "udp")


def udp_remove(username: str) -> None:
    if username not in udp_list():
        raise ValueError("Managed UDP-Custom account not found")
    _run(["userdel", username])
    data = state(); data["accounts"].pop(username, None)
    _atomic(STATE, json.dumps(data, indent=2) + "\n")


def udp_renew(username: str, days: int) -> None:
    if username not in udp_list() or not 1 <= int(days) <= 3650:
        raise ValueError("Invalid UDP-Custom username or validity period")
    expiry = (dt.date.today() + dt.timedelta(days=int(days))).isoformat()
    _run(["chage", "-E", expiry, username])
    data = state(); data["accounts"][username]["expires_at"] = expiry
    data["accounts"][username]["trial"] = False
    _atomic(STATE, json.dumps(data, indent=2) + "\n")


def ssh_list() -> list[str]:
    d = state()
    return sorted(u for u, a in d["accounts"].items() if a.get("protocol") == "ssh")


def ssh_remove(username: str) -> None:
    if username not in ssh_list():
        raise ValueError("Managed SSH account not found")
    _run(["userdel", "-r", username])
    d = state(); del d["accounts"][username]
    _atomic(STATE, json.dumps(d, indent=2) + "\n")


def ssh_renew(username: str, days: int) -> None:
    if username not in ssh_list(): raise ValueError("Managed SSH account not found")
    if not 1 <= days <= 3650: raise ValueError("Validity must be from 1 to 3650 days")
    expiry=(dt.date.today()+dt.timedelta(days=days)).isoformat()
    _run(["chage","-E",expiry,username])
    data=state(); data["accounts"][username]["expires_at"]=expiry; data["accounts"][username]["trial"]=False
    _atomic(STATE,json.dumps(data,indent=2)+"\n")


def _server_public_ip() -> str:
    if shutil.which("curl"):
        result = subprocess.run(["curl", "-4fsS", "--max-time", "3", "https://api.ipify.org"],
                                capture_output=True, text=True, check=False)
        if result.returncode == 0 and re.fullmatch(r"[0-9.]+", result.stdout.strip()):
            return result.stdout.strip()
    result = subprocess.run(["ip", "-o", "-4", "addr", "show", "scope", "global"],
                            capture_output=True, text=True, check=False)
    match = re.search(r"\binet\s+([0-9.]+)/", result.stdout)
    return match.group(1) if match else "Unknown"


def _ssh_account_fields(username: str, record: dict, password: str | None = None) -> list[tuple[str, object]]:
    """Return the SSH account fields, showing only services actually configured here."""
    server_ip = _server_public_ip()
    domain = state().get("domain") or server_ip
    expiry = record.get("expires_at", "unknown")
    try:
        parsed = dt.date.fromisoformat(expiry)
        expiry = parsed.strftime("%b %d, %Y")
    except (TypeError, ValueError):
        pass
    ssh_service = subprocess.run(["systemctl", "is-active", "--quiet", "ssh.service"], check=False).returncode == 0
    try:
        sshd = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=False)
        ssh_ports = (", ".join(re.findall(r"(?m)^port\s+(\d+)$", sshd.stdout)) or "22/TCP") if ssh_service else "Not active"
    except OSError:
        ssh_ports = "22/TCP" if ssh_service else "Not active"
    dropbear = subprocess.run(["systemctl", "is-active", "--quiet", "kennet-dropbear.service"], check=False).returncode == 0
    try:
        import gateway_manager
        gateway_ready = gateway_manager.is_ready()[0]
        websocket_ready = gateway_manager.websocket_bridge_ready()[0]
    except (ImportError, OSError, ValueError):
        gateway_ready = websocket_ready = False
    try:
        import udp_custom_manager
        udp_ready = udp_custom_manager.ready()[0]
    except (ImportError, OSError, ValueError, RuntimeError):
        udp_ready = False
    try:
        import dnstt_manager
        dns_config = json.loads(dnstt_manager.CONFIG.read_text(encoding="utf-8"))
        dnstt_host = dns_config.get("nameserver_host", "Not configured")
        key_files = list(Path(dnstt_manager.ACCOUNT_DIR).glob("*/server.pub"))
        dns_public_key = key_files[0].read_text(encoding="utf-8").strip() if key_files else "Not configured"
    except (ImportError, OSError, ValueError, json.JSONDecodeError):
        dnstt_host = dns_public_key = "Not configured"
    ovpn_tcp = subprocess.run(["systemctl", "is-active", "--quiet", "openvpn-server@server-tcp.service"], check=False).returncode == 0
    ovpn_udp = subprocess.run(["systemctl", "is-active", "--quiet", "openvpn-server@server-udp.service"], check=False).returncode == 0
    squid = subprocess.run(["systemctl", "is-active", "--quiet", "squid.service"], check=False).returncode == 0
    badvpn = [str(port) for unit, port in (("badvpn1.service", 7100), ("badvpn2.service", 7200), ("badvpn3.service", 7300))
              if subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0]
    return [
        ("Username", username),
        ("Password", password if password is not None else "Not retrievable after creation; renew/reset it"),
        ("IP", server_ip),
        ("Host", domain),
        ("Host SlowDNS", "Not configured"),
        ("DNSTT nameserver", dnstt_host),
        ("Location", state().get("location") or "Not configured"),
        ("Port OpenSSH", ssh_ports),
        ("Port UDP SSH", "Not configured"),
        ("Port Dropbear", "109, 143/TCP" if dropbear else "Not installed"),
        ("Port Dropbear WS", "443, 109/TCP" if dropbear and gateway_ready and websocket_ready else "Not configured"),
        ("Port SSH WS SSL", "443/TCP" if gateway_ready and websocket_ready else "Not configured"),
        ("Port SSH WS / HTTP Custom proxy", "80, 8080/TCP" if gateway_ready and websocket_ready else "Not configured"),
        ("Port SSL/TLS", "443/TCP" if gateway_ready else "Not configured"),
        ("Port OpenVPN WS SSL", "443/TCP" if ovpn_tcp and gateway_ready and websocket_ready else "Not configured"),
        ("Port OpenVPN SSL", "443/TCP" if ovpn_tcp and gateway_ready else "Not configured"),
        ("Port OpenVPN TCP", "443, 1194/TCP" if ovpn_tcp else "Not installed"),
        ("Port OpenVPN UDP", "2200/UDP" if ovpn_udp else "Not installed"),
        ("Proxy Squid", "3128/TCP" if squid else "Not installed"),
        ("BadVPN UDP", ", ".join(badvpn) if badvpn else "Not installed"),
        ("DNSTT public key", dns_public_key),
        ("UDP Custom", f"{domain}:1-65535@{username}:{password or '<password not retrievable>'}" if udp_ready else "Not installed"),
        ("SSH WebSocket", f"{domain}:80@{username}:{password or '<password not retrievable>'}" if gateway_ready and websocket_ready else "Not configured"),
        ("Payload WSS", f"GET /ssh-ws HTTP/1.1[crlf]Host: {domain}[crlf]Upgrade: websocket[crlf][crlf]" if gateway_ready and websocket_ready else "Not configured"),
        ("Allowed IPs", "Unlimited" if not int(record.get("max_ips", 0)) else str(record.get("max_ips"))),
        ("Expired", expiry),
    ]


def _prompt_ssh_password() -> str:
    print("SSH password rules: at least 8 characters; ':' and line breaks are not allowed.")
    while True:
        first = getpass.getpass("Password (input hidden): ")
        if len(first) < 8 or any(char in first for char in "\r\n:"):
            print("Invalid password. Use at least 8 characters and avoid ':' or line breaks.")
            continue
        second = getpass.getpass("Confirm password: ")
        if first == second:
            return first
        print("Passwords do not match. Please try again.")


def install_expiry_timer() -> None:
    service = """[Unit]
Description=Expire Kennet managed accounts
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/kennet-panel/services_manager.py --expire
"""
    timer = """[Unit]
Description=Periodic Kennet account expiry check
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Persistent=true
[Install]
WantedBy=timers.target
"""
    _atomic(Path("/etc/systemd/system/kennet-account-expiry.service"), service, 0o644)
    _atomic(Path("/etc/systemd/system/kennet-account-expiry.timer"), timer, 0o644)
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", "--now", "kennet-account-expiry.timer"])


def purge_expired(today: dt.date | None = None) -> list[str]:
    today = today or dt.date.today()
    data = state()
    expired = []
    xray_expired = []
    for username, record in list(data.get("accounts", {}).items()):
        value = record.get("expires_at")
        if not value:
            continue
        try:
            is_expired = dt.date.fromisoformat(value) < today
        except ValueError:
            continue
        if not is_expired:
            continue
        if record.get("protocol") in {"ssh", "udp"}:
            _expire_linux_user(username)
        elif record.get("protocol") in XRAY_PORTS:
            xray_expired.append((username, record["protocol"]))
        else:
            continue
        expired.append(username)
    if xray_expired:
        cfg = get_xray_config()
        expired_by_protocol: dict[str, set[str]] = {}
        for username, protocol in xray_expired:
            expired_by_protocol.setdefault(protocol, set()).add(username)
        for item in cfg.get("inbounds", []):
            tag = item.get("tag", "")
            for protocol, usernames in expired_by_protocol.items():
                if tag in _managed_tags(protocol):
                    item.setdefault("settings", {})["clients"] = [
                        client for client in item.get("settings", {}).get("clients", [])
                        if client.get("email") not in usernames]
        _write_xray(cfg)
    for username in expired:
        record = dict(data["accounts"].get(username, {}))
        _archive_expired(record.get("protocol", "unknown"), username, record)
        data["accounts"].pop(username, None)
    if expired:
        _atomic(STATE, json.dumps(data, indent=2) + "\n")
    try:
        import wireguard_manager
        peers = wireguard_manager.list_peers()
        removed = wireguard_manager.purge_expired(today)
        for name in removed:
            _archive_expired("wireguard", name, peers.get(name, {}))
        expired.extend("wireguard:" + name for name in removed)
    except (ImportError, FileNotFoundError, RuntimeError, ValueError):
        pass
    try:
        import dnstt_manager
        accounts = dnstt_manager.list_accounts()
        removed = dnstt_manager.purge_expired(today)
        for name in removed:
            _archive_expired("dnstt", name, accounts.get(name, {}))
        expired.extend("dnstt:" + name for name in removed)
    except (ImportError, FileNotFoundError, RuntimeError, ValueError):
        pass
    try:
        import openvpn_manager
        accounts = openvpn_manager._account_state().get("accounts", {})
        removed = openvpn_manager.purge_expired(today)
        for name in removed:
            _archive_expired("openvpn", name, accounts.get(name, {}))
        expired.extend("openvpn:" + name for name in removed)
    except (ImportError, FileNotFoundError, RuntimeError, ValueError):
        pass
    return expired


def account_details(protocol: str, username: str) -> dict:
    record = state().get("accounts", {}).get(username)
    if not record or record.get("protocol") != protocol:
        raise ValueError("Managed account not found")
    return {"username": username, **record}


def active_connections(protocol: str) -> dict[str, int]:
    if protocol in {"ssh", "udp"}:
        return ssh_session_counts() if protocol == "ssh" else {}
    if protocol in XRAY_PORTS:
        rows = set()
        for port, _network, _path in XRAY_LAYOUT[protocol]:
            result = subprocess.run(["ss", "-Htn", "state", "established", "sport", "=", f":{port}"], capture_output=True, text=True, check=False)
            rows.update(result.stdout.splitlines())
        return {"active connections (not unique users)": len(rows)}
    raise ValueError(f"Connection counting is not implemented for {protocol}")


def ssh_session_ips() -> dict[str, list[str]]:
    sessions = ssh_session_sources()
    result: dict[str, list[str]] = {}
    for username, peers in sessions.items():
        hosts = set()
        for peer in peers:
            if peer.startswith("[") and "]:" in peer:
                hosts.add(peer[1:peer.rfind("]:")])
            else:
                hosts.add(peer.rpartition(":")[0] or peer)
        result[username] = sorted(hosts)
    return result


def ssh_session_sources() -> dict[str, list[str]]:
    """Map established SSH TCP sessions to login users and remote endpoints."""
    sessions: dict[str, set[str]] = {}
    managed = set(ssh_list())
    if not managed:
        return {}
    sockets = subprocess.run(["ss", "-Htnp", "state", "established"], capture_output=True, text=True, check=False)
    processes = subprocess.run(["ps", "-eo", "user=,pid=,args="], capture_output=True, text=True, check=False)
    pid_users: dict[str, str] = {}
    for line in processes.stdout.splitlines():
        match = re.match(r"\s*(\S+)\s+(\d+)\s+.*?sshd:\s+([A-Za-z0-9_]{3,32})@", line)
        if match:
            pid_users[match.group(2)] = match.group(3)
        else:
            match = re.match(r"\s*(\S+)\s+(\d+)\s+", line)
            if match:
                pid_users[match.group(2)] = match.group(1)
    for line in sockets.stdout.splitlines():
        pids = re.findall(r"pid=(\d+)", line)
        user = next((pid_users.get(pid) for pid in pids if pid_users.get(pid) in managed), None)
        if not user:
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        peer = fields[4]
        if peer.startswith("[") and "]:" in peer:
            host = peer[1:peer.rfind("]:")]
        else:
            host = peer.rpartition(":")[0]
        # Keep the remote source port: two devices behind one NAT share an IP,
        # but have distinct TCP sessions and therefore distinct source ports.
        sessions.setdefault(user, set()).add(peer or host)
    return {username: sorted(hosts) for username, hosts in sessions.items()}


def ssh_session_counts() -> dict[str, int]:
    """Count established SSH sessions per account (not unique physical devices)."""
    return {username: len(sources) for username, sources in ssh_session_sources().items()}


def xray_renew(protocol: str, username: str, days: int) -> None:
    if protocol not in XRAY_PORTS or not 1 <= int(days) <= 3650:
        raise ValueError("Invalid protocol or validity period")
    record = account_details(protocol, username)
    record["expires_at"] = (dt.date.today() + dt.timedelta(days=days)).isoformat()
    record["trial"] = False
    if protocol in {"vless", "vmess", "trojan"} and record.get("credential") != username:
        # Apply the legacy account-name credential convention on renewal too.
        cfg = get_xray_config()
        for inbound in cfg.get("inbounds", []):
            if inbound.get("tag") in _managed_tags(protocol):
                for client in inbound.get("settings", {}).get("clients", []):
                    if client.get("email") == username:
                        if protocol in {"vless", "vmess"}:
                            client["id"] = username
                        else:
                            client["password"] = username
        _write_xray(cfg)
        record["credential"] = username
    data = state(); data["accounts"][username] = {k:v for k,v in record.items() if k != "username"}
    _atomic(STATE, json.dumps(data, indent=2) + "\n")


def xray_install() -> None:
    if input("This will install the official Xray-core service from XTLS/Xray-install. Type YES to continue: ").strip() != "YES":
        return
    if not shutil.which("xray"):
        _run(["apt-get", "update"])
        _run(["apt-get", "install", "-y", "curl", "ca-certificates"])
        script = subprocess.run(["curl", "-fsSL", "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"], capture_output=True, text=True, check=True).stdout
        p = subprocess.run(["bash", "-s", "--", "install"], input=script, text=True, capture_output=True)
        if p.returncode:
            raise RuntimeError((p.stderr or p.stdout).strip())
    if not XRAY_CONFIG.exists():
        _atomic(XRAY_CONFIG, json.dumps({"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[]}}, indent=2)+"\n", 0o644)
    original = XRAY_CONFIG.read_text(encoding="utf-8")
    config = json.loads(original)
    migrated = _migrate_legacy_xray_inbounds(config)
    transport_updated = _refresh_managed_transports(config)
    outbound_updated = _ensure_default_xray_outbound(config)
    if migrated or transport_updated or outbound_updated:
        _atomic(XRAY_CONFIG, json.dumps(config, indent=2) + "\n", 0o644)
    check = subprocess.run(["xray", "run", "-test", "-config", str(XRAY_CONFIG)], capture_output=True, text=True)
    if check.returncode:
        if migrated or transport_updated or outbound_updated:
            _atomic(XRAY_CONFIG, original, 0o644)
        raise RuntimeError((check.stderr or check.stdout or "Xray configuration validation failed").strip())
    _run(["systemctl", "enable", "xray"])
    _run(["systemctl", "restart" if migrated or transport_updated or outbound_updated else "start", "xray"])
    active = subprocess.run(["systemctl", "is-active", "--quiet", "xray"], capture_output=True, check=False)
    if active.returncode:
        raise RuntimeError("Xray was installed, but xray.service did not become active; inspect: journalctl -u xray -n 80 --no-pager")
    if migrated:
        print("Migrated legacy TLS accounts to the shared WebSocket/gRPC inbounds: " + ", ".join(migrated))
    if transport_updated:
        print("Updated managed WebSocket/gRPC transport paths to match the current client profiles.")
    if outbound_updated:
        print("Repaired the missing Xray freedom outbound; client traffic now has a direct route.")
    print("Xray Core is installed and running. Create an account in each protocol menu to add its WS/gRPC inbounds.")


def get_xray_config() -> dict:
    if not XRAY_CONFIG.exists():
        raise FileNotFoundError("Xray is not installed. Run Install Xray first.")
    return json.loads(XRAY_CONFIG.read_text())


def _ensure_default_xray_outbound(cfg: dict) -> bool:
    """Ensure an otherwise empty Xray config can forward accepted client traffic."""
    outbounds = cfg.get("outbounds")
    if not isinstance(outbounds, list):
        outbounds = []
        cfg["outbounds"] = outbounds
    if outbounds:
        return False
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    return True


def ensure_xray_default_outbound() -> bool:
    """Repair an installed Xray config with no outbound and restart it safely."""
    if not XRAY_CONFIG.is_file():
        return False
    config = get_xray_config()
    if not _ensure_default_xray_outbound(config):
        return False
    _write_xray(config)
    return True


def _write_xray(cfg: dict) -> None:
    _ensure_default_xray_outbound(cfg)
    original = XRAY_CONFIG.read_text(encoding="utf-8") if XRAY_CONFIG.exists() else None
    _atomic(XRAY_CONFIG, json.dumps(cfg, indent=2) + "\n", 0o644)
    check = subprocess.run(["xray", "run", "-test", "-config", str(XRAY_CONFIG)], capture_output=True, text=True)
    if check.returncode:
        if original is not None: _atomic(XRAY_CONFIG, original, 0o644)
        raise RuntimeError((check.stderr or check.stdout).strip())
    try:
        _run(["systemctl", "restart", "xray"])
    except Exception:
        if original is not None: _atomic(XRAY_CONFIG, original, 0o644)
        subprocess.run(["systemctl", "restart", "xray"], capture_output=True)
        raise


def xray_add(protocol: str, username: str, days: int = 30, *, trial: bool = False) -> str:
    if protocol not in XRAY_PORTS or not NAME_RE.fullmatch(username):
        raise ValueError("Invalid protocol or username")
    if not 1 <= int(days) <= 3650:
        raise ValueError("Validity must be between 1 and 3650 days")
    if protocol in {"vless", "vmess"} and len(username.encode("utf-8")) >= 30:
        raise ValueError("VLESS/VMess account names used as client IDs must be shorter than 30 bytes")
    data = state(); domain = data.get("domain", "")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Configure the TLS domain before creating Xray accounts")
    if username in data["accounts"]:
        raise ValueError("Username already exists")
    cfg = get_xray_config()
    port = XRAY_PORTS[protocol]
    if not Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").is_file() or not Path(f"/etc/letsencrypt/live/{domain}/privkey.pem").is_file():
        raise FileNotFoundError(f"TLS certificate for {domain} is missing; request it from the TLS menu first")
    import gateway_manager
    gateway_ready, gateway_detail = gateway_manager.is_ready()
    if not gateway_ready:
        raise RuntimeError("Shared HAProxy/Nginx gateway is not ready: " + gateway_detail + ". Use TLS/Domain > Request / renew certificate first")
    # Xray supports custom string IDs for VLESS/VMess and maps them to UUIDv5.
    # This matches the working legacy profiles, which use the account name.
    credential = (username if protocol in {"vless", "vmess", "trojan"}
                  else secrets.token_urlsafe(24))
    client = _xray_client(protocol, username, credential)
    cfg.setdefault("inbounds", [])
    for inbound in _managed_protocol_inbounds(protocol, [client]):
        existing = next((item for item in cfg["inbounds"] if item.get("tag") == inbound["tag"]), None)
        if existing is None:
            cfg["inbounds"].append(inbound)
        else:
            current_clients = (existing.setdefault("settings", {}).setdefault("clients", []))
            if not any(item.get("email") == username for item in current_clients):
                current_clients.append(client)
    _write_xray(cfg)
    expires = (dt.date.today() + dt.timedelta(days=days)).isoformat()
    data["accounts"][username] = {"protocol":protocol,"credential":credential,"port":port,"expires_at":expires,"trial":trial}
    _atomic(STATE,json.dumps(data,indent=2)+"\n")
    install_expiry_timer()
    return credential


def xray_list(protocol: str) -> list[str]:
    return sorted(u for u,a in state()["accounts"].items() if a.get("protocol")==protocol)


def xray_remove(protocol: str, username: str) -> None:
    data=state(); account=data["accounts"].get(username)
    if not account or account.get("protocol")!=protocol: raise ValueError("Account not found")
    cfg=get_xray_config()
    for inbound in cfg.get("inbounds", []):
        if inbound.get("tag") in _managed_tags(protocol):
            inbound.setdefault("settings", {})["clients"] = [
                item for item in inbound.get("settings", {}).get("clients", []) if item.get("email") != username]
    _write_xray(cfg); del data["accounts"][username]
    _atomic(STATE,json.dumps(data,indent=2)+"\n")


def _managed_tags(protocol: str) -> set[str]:
    return {f"kennet-{protocol}-{network}" for _, network, _ in XRAY_LAYOUT[protocol]}


def _migrate_legacy_xray_inbounds(config: dict) -> list[str]:
    """Move this manager's old per-user TLS inbounds behind the shared TLS gateway."""
    legacy_tag = re.compile(r"^kennet-(vless|vmess|trojan|shadowsocks)-([A-Za-z0-9_]{3,32})$")
    clients: dict[str, list[dict]] = {protocol: [] for protocol in XRAY_LAYOUT}
    kept = []
    migrated = []
    for inbound in config.get("inbounds", []):
        match = legacy_tag.fullmatch(str(inbound.get("tag", "")))
        if not match or inbound.get("protocol") != match.group(1):
            kept.append(inbound)
            continue
        protocol, username = match.groups()
        if inbound.get("tag") in _managed_tags(protocol):
            kept.append(inbound)
            continue
        entries = (inbound.get("settings") or {}).get("clients", [])
        if not isinstance(entries, list):
            kept.append(inbound)
            continue
        valid = [dict(item) for item in entries if isinstance(item, dict) and item.get("email")]
        if not valid:
            kept.append(inbound)
            continue
        clients[protocol].extend(valid)
        migrated.append(username)
    if not migrated:
        return []

    config["inbounds"] = kept
    for protocol, entries in clients.items():
        if not entries:
            continue
        generated = _managed_protocol_inbounds(protocol, entries)
        for inbound in generated:
            existing = next((item for item in config["inbounds"] if item.get("tag") == inbound["tag"]), None)
            if existing is None:
                config["inbounds"].append(inbound)
                continue
            current = existing.setdefault("settings", {}).setdefault("clients", [])
            known = {item.get("email") for item in current if isinstance(item, dict)}
            current.extend(item for item in inbound["settings"]["clients"] if item.get("email") not in known)
    return sorted(set(migrated))


def _xray_client(protocol: str, username: str, credential: str) -> dict:
    if protocol in {"vless", "vmess"}:
        client = {"id": credential, "email": username}
        if protocol == "vmess":
            client["alterId"] = 0
        return client
    if protocol == "trojan":
        return {"password": credential, "email": username}
    return {"method": "chacha20-ietf-poly1305", "password": credential, "email": username}


def _managed_protocol_inbounds(protocol: str, clients: list[dict]) -> list[dict]:
    inbounds = []
    for port, network, path_or_service in XRAY_LAYOUT[protocol]:
        settings = {"clients": [dict(c) for c in clients]}
        if protocol == "vless":
            settings["decryption"] = "none"
        if protocol == "shadowsocks":
            settings["network"] = "tcp"
        stream = {"network": network, "security": "none"}
        if network == "ws":
            stream["wsSettings"] = {"path": path_or_service}
        else:
            stream["grpcSettings"] = {"serviceName": path_or_service}
        inbounds.append({"tag": f"kennet-{protocol}-{network}", "listen": "127.0.0.1",
                         "port": port, "protocol": protocol, "settings": settings,
                         "streamSettings": stream})
    return inbounds


def _refresh_managed_transports(config: dict) -> bool:
    """Refresh transport settings on existing manager-owned Xray inbounds."""
    changed = False
    for protocol in XRAY_LAYOUT:
        for expected in _managed_protocol_inbounds(protocol, []):
            current = next((item for item in config.get("inbounds", [])
                            if item.get("tag") == expected["tag"]), None)
            if current is None:
                continue
            for key in ("listen", "port", "streamSettings"):
                if current.get(key) != expected[key]:
                    current[key] = expected[key]
                    changed = True
    return changed


def client_link(protocol: str, username: str, credential: str, domain: str) -> str:
    port = XRAY_PORTS[protocol]
    label = username.replace(" ", "_")
    profile = XRAY_WS_PROFILE[protocol]
    sni = domain if profile["sni"] == "domain" else profile["sni"]
    encoded_path = quote(profile["path"], safe="")
    if protocol == "vless":
        return f"vless://{quote(credential, safe='')}@{domain}:{port}?encryption=none&security=tls&sni={sni}&type=ws&host={domain}&path={encoded_path}&allowInsecure=1#{label}"
    if protocol == "trojan":
        return f"trojan://{quote(credential, safe='')}@{domain}:{port}?security=tls&sni={sni}&type=ws&host={domain}&path={encoded_path}&allowInsecure=1#{label}"
    if protocol == "shadowsocks":
        userinfo = base64.urlsafe_b64encode(f"chacha20-ietf-poly1305:{credential}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{domain}:{port}/?plugin=v2ray-plugin%3Btls%3Bhost%3D{domain}%3Bpath%3D%2Fss-ws#{label}"
    raw = json.dumps({"v":"2","ps":label,"add":domain,"port":str(port),"id":credential,"aid":"0","scy":"auto","net":"ws","type":"none","host":domain,"path":profile["path"],"tls":"tls","sni":sni,"allowInsecure":True}, separators=(",", ":")).encode()
    return "vmess://" + base64.b64encode(raw).decode()


def grpc_client_link(protocol: str, username: str, credential: str, domain: str) -> str:
    """Build a shareable gRPC URI for the account's parallel Xray inbound."""
    label = username.replace(" ", "_")
    service = {"vless": "vless-grpc", "vmess": "vmess-grpc",
               "trojan": "trojan-grpc", "shadowsocks": "ss-grpc"}[protocol]
    if protocol == "vmess":
        raw = json.dumps({"v": "2", "ps": label, "add": domain, "port": "443",
                          "id": credential, "aid": "0", "scy": "auto", "net": "grpc",
                          "type": "gun", "host": domain, "path": service,
                          "tls": "tls", "sni": domain}, separators=(",", ":")).encode()
        return "vmess://" + base64.b64encode(raw).decode()
    if protocol == "shadowsocks":
        userinfo = base64.urlsafe_b64encode(f"chacha20-ietf-poly1305:{credential}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{domain}:443/?plugin=v2ray-plugin%3Btls%3Bmode%3Dgrpc%3Bhost%3D{domain}%3Bpath%3D%2F{service}#{label}-gRPC"
    if protocol == "trojan":
        return f"trojan://{credential}@{domain}:443?security=tls&sni={domain}&type=grpc&serviceName={service}#{label}-gRPC"
    return f"vless://{credential}@{domain}:443?encryption=none&security=tls&sni={domain}&type=grpc&serviceName={service}#{label}-gRPC"


def xray_account_fields(protocol: str, username: str, record: dict, domain: str) -> list[tuple[str, object]]:
    """Protocol-aware shared detail layout used after creation and from Show details."""
    credential = str(record.get("credential", ""))
    ws_profile = XRAY_WS_PROFILE[protocol]
    ws_path = ws_profile["path"]
    ws_sni = domain if ws_profile["sni"] == "domain" else ws_profile["sni"]
    grpc_service = {"vless": "vless-grpc", "vmess": "vmess-grpc",
                    "trojan": "trojan-grpc", "shadowsocks": "ss-grpc"}[protocol]
    credential_label = "Password" if protocol in {"trojan", "shadowsocks"} else "Client ID"
    return [
        ("Remarks", username),
        ("Host server", domain),
        ("Server name (SNI)", ws_sni),
        ("Port TLS", "443/TCP"),
        ("Protocol", protocol.upper()),
        ("Transport", "WebSocket / gRPC"),
        ("Security", "TLS"),
        ("WS path", ws_path),
        ("Allow insecure TLS", "Yes (legacy profile compatibility)"),
        ("gRPC service", grpc_service),
        (credential_label, credential),
        ("Link WS", client_link(protocol, username, credential, domain)),
        ("Link gRPC", grpc_client_link(protocol, username, credential, domain)),
        ("Valid until", record.get("expires_at", "unknown")),
        ("Account type", "TRIAL" if record.get("trial") else "REGULAR"),
    ]


def show_account_details(protocol: str, username: str) -> None:
    import terminal_ui
    record = account_details("ssh" if protocol == "dropbear" else protocol, username)
    if protocol in {"ssh", "dropbear", "udp"}:
        if protocol == "ssh":
            terminal_ui.detail_card("SSH OVPN ACCOUNT", _ssh_account_fields(username, record))
            return
        if protocol == "udp":
            port_text = "UDP destination ports 1-65535 (reserved VPN/DNS ports excluded)"
            title = "UDP CUSTOM ACCOUNT"
        else:
            port_text = "22/TCP (OpenSSH)" + (", 109/TCP and 143/TCP (Dropbear)" if protocol == "dropbear" else "")
            title = f"{protocol.upper()} ACCOUNT"
        terminal_ui.detail_card(title, [
            ("Remarks", username), ("Host server", state().get("domain") or "VPS public IP"),
            ("Access ports", port_text), ("Protocol", protocol.upper()),
            ("Valid until", record.get("expires_at", "unknown")),
            ("Account type", "TRIAL" if record.get("trial") else "REGULAR"),
        ], note="Passwords are not stored in recoverable form. Renew the account to set a new password.")
        return
    domain = state().get("domain", "")
    terminal_ui.detail_card(f"XRAY/{protocol.upper()} ACCOUNT",
                            xray_account_fields(protocol, username, record, domain))
    terminal_ui.copy_prompt([("WebSocket link", client_link(protocol, username, record["credential"], domain)),
                             ("gRPC link", grpc_client_link(protocol, username, record["credential"], domain))])


def show_created_account(protocol: str, username: str, credential: str, days: int, *, trial: bool = False) -> None:
    import terminal_ui
    expires = (dt.date.today() + dt.timedelta(days=days)).isoformat()
    current = state()
    domain = current.get("domain") or "Use the VPS public IP or configured domain"
    if protocol in {"ssh", "dropbear", "udp"}:
        if protocol == "ssh":
            ssh_host = current.get("domain") or _server_public_ip()
            terminal_ui.detail_card("SSH OVPN ACCOUNT", _ssh_account_fields(username,
                                    {"expires_at": expires, "trial": trial,
                                     "max_ips": state().get("accounts", {}).get(username, {}).get("max_ips", 0)},
                                    password=credential))
            copy_items = [("OpenSSH command", f"ssh {username}@{ssh_host} -p 22")]
            try:
                import gateway_manager
                if gateway_manager.is_ready()[0]:
                    copy_items.append(("SSH WebSocket endpoint", f"{ssh_host}:80@{username}:{credential}"))
            except (ImportError, OSError, ValueError):
                pass
            try:
                import udp_custom_manager
                if udp_custom_manager.ready()[0]:
                    copy_items.append(("UDP Custom endpoint", f"{ssh_host}:1-65535@{username}:{credential}"))
            except (ImportError, OSError, ValueError, RuntimeError):
                pass
            terminal_ui.copy_prompt(copy_items)
            return
        dropbear_active = subprocess.run(["systemctl", "is-active", "--quiet", "kennet-dropbear.service"], capture_output=True, check=False).returncode == 0
        access = ("UDP Custom: UDP ports 1-65535, excluding UDP/53 and configured VPN ports" if protocol == "udp"
                  else "22/TCP (OpenSSH)" + (", 109/TCP and 143/TCP (Dropbear)" if dropbear_active else ""))
        fields = [("Username", username), ("Password", credential), ("Host", domain),
                  ("Access ports", access), ("Valid until", expires),
                  ("Account type", "TRIAL" if trial else "REGULAR")]
        terminal_ui.detail_card(f"{protocol.upper()} ACCOUNT", fields, note="Password is displayed once. Save it securely.")
        return
    record = {"credential": credential, "expires_at": expires, "trial": trial}
    terminal_ui.detail_card(f"XRAY/{protocol.upper()} ACCOUNT",
                            xray_account_fields(protocol, username, record, current.get("domain", "")),
                            note="VLESS/VMess authenticate with a UUID client ID; Trojan authenticates with the account-name password.")
    terminal_ui.copy_prompt([("WebSocket link", client_link(protocol, username, credential, current.get("domain", ""))),
                             ("gRPC link", grpc_client_link(protocol, username, credential, current.get("domain", "")))])


def configure_tls() -> None:
    data=state(); domain=data.get("domain", "")
    if not DOMAIN_RE.fullmatch(domain): raise ValueError("Set the domain first")
    import gateway_manager
    gateway_manager.install()
    acquire_tls_certificate(domain)
    gateway_manager.install()


def install_ubuntu_package(package: str) -> None:
    """Install an Ubuntu package normally, falling back to official archives without changing APT sources."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", package):
        raise ValueError("Invalid Ubuntu package name")
    if shutil.which(package):
        return
    try:
        _run(["apt-get", "update"])
        _run(["apt-get", "install", "-y", package])
        return
    except RuntimeError as exc:
        original_error = str(exc)

    os_release = Path("/etc/os-release")
    if not os_release.is_file():
        raise RuntimeError(f"Could not install {package} using configured APT sources: {original_error}")
    values = {}
    for line in os_release.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    codename = values.get("VERSION_CODENAME", "")
    if values.get("ID") != "ubuntu" or not re.fullmatch(r"[a-z]+", codename):
        raise RuntimeError(f"Could not install {package} using configured APT sources: {original_error}")

    architecture = _run(["dpkg", "--print-architecture"])
    archive = "https://ports.ubuntu.com/ubuntu-ports" if architecture in {"arm64", "armhf", "ppc64el", "riscv64", "s390x"} else "https://archive.ubuntu.com/ubuntu"
    source_text = (
        f"deb {archive} {codename} main universe\n"
        f"deb {archive} {codename}-updates main universe\n"
        f"deb https://security.ubuntu.com/ubuntu {codename}-security main universe\n"
    )
    fd, source_file = tempfile.mkstemp(prefix="kennet-ubuntu-", suffix=".list")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(source_text)
        apt_options = ["-o", f"Dir::Etc::sourcelist={source_file}", "-o", "Dir::Etc::sourceparts=-", "-o", "APT::Get::List-Cleanup=0"]
        print(f"Configured APT mirrors failed. Retrying {package} installation against official Ubuntu archives without editing the server's APT source files.")
        _run(["apt-get", *apt_options, "update"])
        _run(["apt-get", *apt_options, "install", "-y", package])
    except RuntimeError as fallback_error:
        raise RuntimeError(f"Configured APT sources failed ({original_error}); official Ubuntu archive fallback for {package} failed ({fallback_error})") from fallback_error
    finally:
        Path(source_file).unlink(missing_ok=True)


def install_certbot() -> None:
    install_ubuntu_package("certbot")


def acquire_tls_certificate(domain: str) -> None:
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)})
    except OSError as exc:
        raise ValueError(f"DNS lookup failed for {domain}; add an A/AAAA record pointing to this VPS first") from exc
    if not addresses:
        raise ValueError(f"No A/AAAA DNS records found for {domain}")
    public_ip = ""
    if shutil.which("curl"):
        public_ip = subprocess.run(["curl", "-4fsS", "--max-time", "8", "https://api.ipify.org"], capture_output=True, text=True, check=False).stdout.strip()
    if public_ip and public_ip not in addresses:
        print(f"Warning: {domain} resolves to {', '.join(addresses)}, while this VPS reports {public_ip}. Certificate validation may fail unless a DNS proxy forwards HTTP/80 here.")
    gateway_ready = all(subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0
                        for unit in ("haproxy.service", "nginx.service"))
    listener = subprocess.run(["ss", "-Hltn", "sport", "=", ":80"], capture_output=True, text=True, check=False)
    if listener.stdout.strip() and not gateway_ready:
        raise RuntimeError("TCP/80 is occupied by another service; free it or configure HTTP-01 webroot routing first")
    open_ports([("tcp",80)])
    install_certbot()
    if gateway_ready:
        webroot = Path("/var/www/letsencrypt") / ".well-known/acme-challenge"
        webroot.mkdir(parents=True, exist_ok=True)
        challenge = ["--webroot", "-w", "/var/www/letsencrypt"]
    else:
        challenge = ["--standalone"]
    _run(["certbot", "certonly", *challenge, "--non-interactive", "--agree-tos",
          "--register-unsafely-without-email", "--preferred-challenges", "http", "-d", domain])
    haproxy_cert = f"/etc/haproxy/certs/{domain}.pem"
    hook = ("#!/bin/sh\nset -eu\n"
            f"install -d -m 0750 /etc/haproxy/certs\n"
            f"cat /etc/letsencrypt/live/{domain}/fullchain.pem /etc/letsencrypt/live/{domain}/privkey.pem > {haproxy_cert}\n"
            f"chmod 0600 {haproxy_cert}\n"
            "haproxy -c -f /etc/haproxy/haproxy.cfg\n"
            "nginx -t\n"
            "systemctl reload haproxy.service\n"
            "systemctl reload nginx.service\n")
    _atomic(Path("/etc/letsencrypt/renewal-hooks/deploy/kennet-gateway-tls.sh"), hook, 0o755)
    print(f"TLS certificate installed for {domain}. DNS addresses: {', '.join(addresses)}. TCP/80 must remain reachable for renewal.")


def menu(protocol: str) -> None:
    if protocol in {"ssh", "vless", "vmess", "trojan", "shadowsocks"}:
        account_menu(protocol)
        return
    while True:
        import terminal_ui
        if protocol == "tls":
            terminal_ui.option_cards("TLS CERTIFICATE / DOMAIN", [("1", "Set domain + request certificate"),
                ("2", "Request / renew certificate"), ("0", "Return")])
            choice=input("Select: ").strip()
            try:
                if choice=="0": return
                if choice=="1": set_domain(input("Domain name: "))
                elif choice=="2": configure_tls()
                else: print("Invalid selection")
            except (OSError,ValueError,RuntimeError,json.JSONDecodeError,subprocess.CalledProcessError) as exc: print(f"Operation failed: {exc}")
            continue
        terminal_ui.heading(f"{protocol.upper()} ACCOUNT MANAGER")
        print("1. Install / configure service")
        print("2. Set shared domain")
        if protocol in {"vless","vmess","trojan","shadowsocks"}: print("3. Check TLS certificate"); print("4. Create account"); print("5. List accounts"); print("6. Delete account")
        elif protocol == "ssh": print("3. Create account"); print("4. List accounts"); print("5. Delete account"); print("6. Renew account")
        print("0. Return")
        choice=input("Select: ").strip()
        try:
            if choice=="0": return
            if choice=="1":
                if protocol=="ssh": install_ssh()
                elif protocol in {"vless","vmess","trojan","shadowsocks"}: xray_install()
                else: print("This service does not yet have an independent installer.")
            elif choice=="2": set_domain(input("Domain name: "))
            elif protocol in {"vless","vmess","trojan","shadowsocks"} and choice=="3":
                d=state(); domain=d.get("domain", "")
                cert=Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
                if cert.is_file(): print(f"TLS certificate is present for {domain}")
                else: print("Select TLS certificates / domain from the main protocol list to obtain a certificate first")
            elif protocol in {"vless","vmess","trojan","shadowsocks"} and choice=="4":
                username=input("Username: ").strip(); credential=xray_add(protocol,username)
                print("Client connection:")
                print(client_link(protocol,username,credential,state().get("domain","")))
            elif protocol in {"vless","vmess","trojan","shadowsocks"} and choice=="5": print("Accounts:", ", ".join(xray_list(protocol)) or "none")
            elif protocol in {"vless","vmess","trojan","shadowsocks"} and choice=="6": xray_remove(protocol,input("Username: ").strip())
            elif protocol=="ssh" and choice=="3":
                username=input("Username: ").strip(); days=int(input("Validity in days: ")); pwd=ssh_add(username,days); print(f"Password (shown once): {pwd}")
            elif protocol=="ssh" and choice=="4": print("Accounts:", ", ".join(ssh_list()) or "none")
            elif protocol=="ssh" and choice=="5": ssh_remove(input("Username: ").strip())
            elif protocol=="ssh" and choice=="6":
                username=input("Username: ").strip(); days=int(input("Extend validity by days: ")); ssh_renew(username,days)
            else: print("Invalid selection")
        except (OSError,ValueError,RuntimeError,json.JSONDecodeError,subprocess.CalledProcessError) as exc: print(f"Operation failed: {exc}")


def account_menu(protocol: str) -> None:
    import terminal_ui
    titles = {"ssh": "SSH VIP", "vless": "VLESS", "vmess": "VMESS", "trojan": "TROJAN", "shadowsocks": "SHADOWSOCKS"}
    title = titles[protocol]
    while True:
        terminal_ui.option_cards(f"{title} ACCOUNT MANAGER", [("01", "Install / configure service"),
            ("02", "Create account"), ("03", "Renew account"), ("04", "Delete account"),
            ("05", "Show account details"), ("06", "Create trial account"),
            ("07", "List accounts"), ("08", "Show connected sessions"),
            ("09", "Set domain / TLS certificate"), ("00", "Return")])
        choice = input("Select option [00-09]: ").strip()
        try:
            if choice in {"0", "00"}:
                return
            if choice == "1":
                if protocol == "ssh": install_ssh()
                else: xray_install()
            elif choice == "9":
                if protocol == "ssh":
                    print("A domain is optional for standard SSH. Use the TLS / Domain menu for TLS setup.")
                else:
                    current = state().get("domain", "")
                    value = input(f"Domain name [{current}]: ").strip() or current
                    set_domain(value)
            elif choice in {"2", "6"}:
                trial = choice == "6"
                username = ("trial" + secrets.token_hex(3)) if trial else input("Username: ").strip()
                days = 1 if trial else int(input("Validity in days [30]: ").strip() or "30")
                if protocol == "ssh":
                    password = _prompt_ssh_password()
                    try:
                        max_ips = int(input("Maximum simultaneous connected IPs [1, 0=unlimited]: ").strip() or "1")
                    except ValueError as exc:
                        raise ValueError("Allowed IP count must be a number") from exc
                    password = ssh_add(username, days, trial=trial, password=password, max_ips=max_ips)
                    show_created_account(protocol, username, password, days, trial=trial)
                elif protocol == "shadowsocks":
                    credential = xray_add(protocol, username, days, trial=trial)
                    show_created_account(protocol, username, credential, days, trial=trial)
                else:
                    credential = xray_add(protocol, username, days, trial=trial)
                    show_created_account(protocol, username, credential, days, trial=trial)
            elif choice == "3":
                names = ssh_list() if protocol == "ssh" else xray_list(protocol)
                username = terminal_ui.select_account(title, names)
                if username is None: continue
                days = int(input("Extend validity by days [30]: ").strip() or "30")
                if protocol == "ssh": ssh_renew(username, days)
                else: xray_renew(protocol, username, days)
                print("Account renewed.")
            elif choice == "4":
                names = ssh_list() if protocol == "ssh" else xray_list(protocol)
                username = terminal_ui.select_account(title, names)
                if username is None: continue
                if input(f"Delete {username} and revoke its access? Type YES: ").strip() == "YES":
                    if protocol == "ssh": ssh_remove(username)
                    else: xray_remove(protocol, username)
                    print("Account deleted.")
            elif choice == "5":
                names = ssh_list() if protocol == "ssh" else xray_list(protocol)
                username = terminal_ui.select_account(title, names)
                if username is None: continue
                show_account_details(protocol, username)
            elif choice == "7":
                purge_expired()
                names = ssh_list() if protocol == "ssh" else xray_list(protocol)
                connections = active_connections("ssh") if protocol == "ssh" else None
                rows = account_roster_rows(protocol, names, connections=connections,
                    connection_unknown=("Per-account device sessions are unavailable through the shared Xray gateway"
                                         if protocol != "ssh" else ""))
                import terminal_ui
                terminal_ui.account_roster(f"{title} ACCOUNTS", rows,
                    note="SSH rows count live TCP sessions; Xray user sessions are not exposed per account by the current gateway.")
            elif choice == "8":
                purge_expired()
                names = ssh_list() if protocol == "ssh" else xray_list(protocol)
                import terminal_ui
                if protocol == "ssh":
                    connections = active_connections("ssh")
                    ip_sessions = ssh_session_ips()
                    rows = account_roster_rows(protocol, names, connections=connections)
                    for row in rows:
                        row["details"] = "Remote IPs: " + (", ".join(ip_sessions.get(str(row["name"]), [])) or "none")
                    terminal_ui.account_roster(f"{title} LIVE CONNECTIONS", rows,
                        note="The count is concurrent authenticated TCP sessions, not physical devices; one device may open multiple sessions.")
                else:
                    sessions = active_connections(protocol)
                    rows = account_roster_rows(protocol, names, connection_unknown="Not attributable per account via shared gateway")
                    terminal_ui.account_roster(f"{title} LIVE CONNECTIONS", rows,
                        note=f"Xray reports {sessions.get('active connections (not unique users)', 0)} shared inbound connections total; it cannot identify the account/device for each connection in this gateway layout.")
            else:
                print("Invalid selection.")
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
            print(f"Operation failed: {exc}")


def _expire_cli() -> int:
    expired = purge_expired()
    print("Expired accounts removed: " + (", ".join(expired) if expired else "none"))
    return 0


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--expire"]:
        raise SystemExit(_expire_cli())

