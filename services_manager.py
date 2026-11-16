#!/usr/bin/env python3
"""Manage local SSH and Xray accounts on Ubuntu without legacy helper scripts."""

from __future__ import annotations

import datetime as dt
import base64
import ipaddress
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import tempfile
import uuid
from pathlib import Path

STATE = Path("/etc/kennet-panel/services.json")
XRAY_CONFIG = Path("/usr/local/etc/xray/config.json")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
NAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
XRAY_PORTS = {"vless": 443, "vmess": 8443, "trojan": 2053}


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


def set_domain(domain: str) -> None:
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Enter a fully qualified domain name, e.g. vpn.example.com")
    data = state()
    data["domain"] = domain
    _atomic(STATE, json.dumps(data, indent=2) + "\n")
    print(f"Domain saved: {domain}. Point its A/AAAA record to this VPS public IP.")


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


def ssh_add(username: str, days: int) -> str:
    if not NAME_RE.fullmatch(username) or not 1 <= days <= 3650:
        raise ValueError("Use a 3-32 character username and expiry from 1 to 3650 days")
    if subprocess.run(["id", "-u", username], capture_output=True).returncode == 0:
        raise ValueError("Username already exists")
    password = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#%") for _ in range(20))
    expiry = (dt.date.today() + dt.timedelta(days=days)).isoformat()
    _run(["useradd", "--create-home", "--shell", "/bin/sh", "--expiredate", expiry, username])
    try:
        _run(["chpasswd"], f"{username}:{password}\n")
    except Exception:
        subprocess.run(["userdel", "-r", username], capture_output=True)
        raise
    return password


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
    _run(["systemctl", "enable", "xray"])


def get_xray_config() -> dict:
    if not XRAY_CONFIG.exists():
        raise FileNotFoundError("Xray is not installed. Run Install Xray first.")
    return json.loads(XRAY_CONFIG.read_text())


def _write_xray(cfg: dict) -> None:
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


def xray_add(protocol: str, username: str) -> str:
    if protocol not in XRAY_PORTS or not NAME_RE.fullmatch(username):
        raise ValueError("Invalid protocol or username")
    data = state(); domain = data.get("domain", "")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Configure the TLS domain before creating Xray accounts")
    if username in data["accounts"]:
        raise ValueError("Username already exists")
    cfg = get_xray_config()
    port = XRAY_PORTS[protocol]
    if any(int(i.get("port", 0)) == port for i in cfg.get("inbounds", [])):
        raise ValueError(f"Xray port {port} is already used; resolve the inbound conflict first")
    if protocol == "vless":
        credential = str(uuid.uuid4()); client = {"id": credential, "email": username}
        settings = {"clients": [client], "decryption": "none"}
        security = "tls"; network = "tcp"
    elif protocol == "vmess":
        credential = str(uuid.uuid4()); client = {"id": credential, "email": username, "alterId": 0}
        settings = {"clients": [client]}; security = "tls"; network = "tcp"
    else:
        credential = secrets.token_urlsafe(24); client = {"password": credential, "email": username}
        settings = {"clients": [client]}; security = "tls"; network = "tcp"
    tls = {"certificates": [{"certificateFile": f"/etc/letsencrypt/live/{domain}/fullchain.pem", "keyFile": f"/etc/letsencrypt/live/{domain}/privkey.pem"}]}
    if not Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").is_file() or not Path(f"/etc/letsencrypt/live/{domain}/privkey.pem").is_file():
        raise FileNotFoundError(f"TLS certificate for {domain} is missing; request it from the TLS menu first")
    cfg.setdefault("inbounds", []).append({"tag": f"kennet-{protocol}-{username}", "listen":"0.0.0.0", "port":port,
        "protocol":protocol,"settings":settings,"streamSettings":{"network":network,"security":security,"tlsSettings":tls}})
    _write_xray(cfg)
    data["accounts"][username] = {"protocol":protocol,"credential":credential,"port":port}
    _atomic(STATE,json.dumps(data,indent=2)+"\n")
    open_ports([("tcp",port)])
    return credential


def xray_list(protocol: str) -> list[str]:
    return sorted(u for u,a in state()["accounts"].items() if a.get("protocol")==protocol)


def xray_remove(protocol: str, username: str) -> None:
    data=state(); account=data["accounts"].get(username)
    if not account or account.get("protocol")!=protocol: raise ValueError("Account not found")
    cfg=get_xray_config(); tag=f"kennet-{protocol}-{username}"
    cfg["inbounds"]=[i for i in cfg.get("inbounds",[]) if i.get("tag")!=tag]
    _write_xray(cfg); del data["accounts"][username]
    _atomic(STATE,json.dumps(data,indent=2)+"\n")


def client_link(protocol: str, username: str, credential: str, domain: str) -> str:
    port = XRAY_PORTS[protocol]
    label = username.replace(" ", "_")
    if protocol == "vless":
        return f"vless://{credential}@{domain}:{port}?encryption=none&security=tls&sni={domain}&type=tcp#{label}"
    if protocol == "trojan":
        return f"trojan://{credential}@{domain}:{port}?security=tls&sni={domain}&type=tcp#{label}"
    raw = json.dumps({"v":"2","ps":label,"add":domain,"port":str(port),"id":credential,"aid":"0","scy":"auto","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":domain}, separators=(",", ":")).encode()
    return "vmess://" + base64.b64encode(raw).decode()


def configure_tls() -> None:
    data=state(); domain=data.get("domain", "")
    if not DOMAIN_RE.fullmatch(domain): raise ValueError("Set the domain first")
    email=input("Email address for Let's Encrypt expiry notices: ").strip()
    if not email or "@" not in email: raise ValueError("A valid email address is required")
    open_ports([("tcp",80)])
    _run(["apt-get","update"]); _run(["apt-get","install","-y","certbot"])
    _run(["certbot","certonly","--standalone","--non-interactive","--agree-tos","--email",email,"-d",domain])
    if shutil.which("getent") and subprocess.run(["getent", "group", "ssl-cert"], capture_output=True).returncode == 0:
        subprocess.run(["usermod", "-a", "-G", "ssl-cert", "nobody"], check=True)
        archive = Path(f"/etc/letsencrypt/archive/{domain}")
        for key in archive.glob("privkey*.pem"):
            _run(["chgrp", "ssl-cert", str(key)])
            _run(["chmod", "0640", str(key)])
        _atomic(Path("/etc/systemd/system/xray.service.d/kennet-tls.conf"), "[Service]\nSupplementaryGroups=ssl-cert\n", 0o644)
        hook = "#!/bin/sh\nset -eu\nfor key in /etc/letsencrypt/archive/*/privkey*.pem; do [ -f \"$key\" ] || continue; chgrp ssl-cert \"$key\"; chmod 0640 \"$key\"; done\nsystemctl restart xray\n"
        _atomic(Path("/etc/letsencrypt/renewal-hooks/deploy/kennet-xray-tls.sh"), hook, 0o755)
        _run(["systemctl", "daemon-reload"])
        subprocess.run(["systemctl", "restart", "xray"], capture_output=True)
    print(f"TLS certificate installed for {domain}. Ensure DNS points here and TCP/80 is reachable for renewal.")


def menu(protocol: str) -> None:
    while True:
        print(f"\n=== {protocol.upper()} account manager ===")
        if protocol == "tls":
            print("1. Set shared domain")
            print("2. Request / renew TLS certificate")
            print("0. Return")
            choice=input("Select: ").strip()
            try:
                if choice=="0": return
                if choice=="1": set_domain(input("Domain name: "))
                elif choice=="2": configure_tls()
                else: print("Invalid selection")
            except (OSError,ValueError,RuntimeError,json.JSONDecodeError,subprocess.CalledProcessError) as exc: print(f"Operation failed: {exc}")
            continue
        print("1. Install / configure service")
        print("2. Set shared domain")
        if protocol in {"vless","vmess","trojan"}: print("3. Check TLS certificate"); print("4. Create account"); print("5. List accounts"); print("6. Delete account")
        elif protocol == "ssh": print("3. Create account"); print("4. List accounts"); print("5. Delete account"); print("6. Renew account")
        print("0. Return")
        choice=input("Select: ").strip()
        try:
            if choice=="0": return
            if choice=="1":
                if protocol=="ssh": install_ssh()
                elif protocol in {"vless","vmess","trojan"}: xray_install()
                else: print("This service does not yet have an independent installer.")
            elif choice=="2": set_domain(input("Domain name: "))
            elif protocol in {"vless","vmess","trojan"} and choice=="3":
                d=state(); domain=d.get("domain", "")
                cert=Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
                if cert.is_file(): print(f"TLS certificate is present for {domain}")
                else: print("Select TLS certificates / domain from the main protocol list to obtain a certificate first")
            elif protocol in {"vless","vmess","trojan"} and choice=="4":
                username=input("Username: ").strip(); credential=xray_add(protocol,username)
                print("Client connection:")
                print(client_link(protocol,username,credential,state().get("domain","")))
            elif protocol in {"vless","vmess","trojan"} and choice=="5": print("Accounts:", ", ".join(xray_list(protocol)) or "none")
            elif protocol in {"vless","vmess","trojan"} and choice=="6": xray_remove(protocol,input("Username: ").strip())
            elif protocol=="ssh" and choice=="3":
                username=input("Username: ").strip(); days=int(input("Validity in days: ")); pwd=ssh_add(username,days); d=state(); d["accounts"][username]={"protocol":"ssh"}; _atomic(STATE,json.dumps(d,indent=2)+"\n"); print(f"Password (shown once): {pwd}")
            elif protocol=="ssh" and choice=="4": print("Accounts:", ", ".join(ssh_list()) or "none")
            elif protocol=="ssh" and choice=="5": ssh_remove(input("Username: ").strip())
            elif protocol=="ssh" and choice=="6":
                username=input("Username: ").strip(); days=int(input("Extend validity by days: ")); ssh_renew(username,days)
            else: print("Invalid selection")
        except (OSError,ValueError,RuntimeError,json.JSONDecodeError,subprocess.CalledProcessError) as exc: print(f"Operation failed: {exc}")

