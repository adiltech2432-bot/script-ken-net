#!/usr/bin/env python3
"""Interactive host and server settings for the Ken-net terminal manager."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import terminal_ui

RESTART_UNITS = (
    "ssh.service", "kennet-dropbear.service", "kennet-websocket.service", "kennet-udp-custom.service",
    "xray.service", "nginx.service", "haproxy.service",
    "openvpn-server@server-tcp.service", "openvpn-server@server-udp.service", "udp.service",
    "kennet-dnstt-router.service", "server.service", "client.service", "badvpn1.service",
    "badvpn2.service", "badvpn3.service", "squid.service", "dropbear.service",
)
SSH_BANNER = Path("/etc/issue.net")
SSH_BANNER_CONFIG = Path("/etc/ssh/sshd_config.d/99-kennet-banner.conf")


def _run(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "Command failed").strip())
    return result.stdout.strip()


def restart_services() -> None:
    active = []
    for unit in RESTART_UNITS:
        result = subprocess.run(["systemctl", "is-active", "--quiet", unit], capture_output=True, check=False)
        if result.returncode == 0:
            active.append(unit)
    if not active:
        print("No managed services are currently running.")
        return
    print("Services to restart:\n  " + "\n  ".join(active))
    if input("Type RESTART to continue (active connections may drop): ").strip() != "RESTART":
        print("Cancelled.")
        return
    failures = []
    for unit in active:
        result = subprocess.run(["systemctl", "restart", unit], capture_output=True, text=True, check=False)
        if result.returncode:
            failures.append(f"{unit}: {(result.stderr or result.stdout).strip()}")
    if failures:
        print("Some services could not be restarted:\n  " + "\n  ".join(failures))
    else:
        print(f"Restarted {len(active)} active managed services.")


def change_domain() -> None:
    import services_manager
    current = services_manager.state().get("domain", "")
    value = input(f"Server domain [{current}]: ").strip() or current
    services_manager.set_domain(value)


def change_nameserver() -> None:
    import dnstt_manager
    config = dnstt_manager._read_json(dnstt_manager.CONFIG, {})
    base = config.get("base_domain", "")
    old = config.get("nameserver_host", "")
    if not base or not dnstt_manager.DOMAIN_RE.fullmatch(base):
        raise ValueError("Configure a valid DNSTT tunnel domain from the DNSTT menu first")
    terminal_ui.detail_card("DNSTT NAMESERVER", [("Tunnel zone", base), ("Current NS host", old)],
                            note="This changes the setup instructions only. Update the NS/A records at your DNS provider too.")
    host = input(f"New authoritative nameserver hostname [{old}]: ").strip().lower().rstrip(".") or old
    if not dnstt_manager.DOMAIN_RE.fullmatch(host):
        raise ValueError("Enter a valid fully qualified hostname")
    if host == base or host.endswith("." + base):
        raise ValueError("The nameserver hostname must be outside the delegated tunnel zone")
    config["nameserver_host"] = host
    dnstt_manager._atomic(dnstt_manager.CONFIG, json.dumps(config, indent=2) + "\n")
    terminal_ui.detail_card("DNS PROVIDER RECORDS", [("NS target", f"{base}. -> {host}."),
        ("Address", f"{host}. -> this VPS public IPv4/IPv6")], note="Apply these records at your DNS provider.")


def rotate_dnstt_keys() -> None:
    import dnstt_manager
    accounts = dnstt_manager.list_accounts()
    if not accounts:
        print("No DNSTT endpoints have keys to rotate.")
        return
    print("DNSTT endpoint keys (each endpoint has its own key pair):")
    for name, record in sorted(accounts.items()):
        print(f"  {name}: {record['domain']}")
    username = input("Endpoint name: ").strip()
    record = dnstt_manager.account_details(username)
    if input(f"Rotate keys for {record['domain']}? Clients must receive the new public key. Type YES: ").strip() != "YES":
        print("Cancelled.")
        return
    config = dnstt_manager._configuration()
    account_dir = Path(record["key_dir"])
    key_file, pub_file = account_dir / "server.key", account_dir / "server.pub"
    profile = account_dir / "client" / "client.txt"
    client_pub_file = account_dir / "client" / "server.pub"
    old_key, old_pub = key_file.read_bytes(), pub_file.read_text(encoding="utf-8").strip()
    old_profile = profile.read_text(encoding="utf-8") if profile.is_file() else None
    old_client_pub = client_pub_file.read_bytes() if client_pub_file.is_file() else None
    fd, temporary_key = tempfile.mkstemp(prefix="server-key-", dir=account_dir)
    os.close(fd)
    temporary_pub = temporary_key + ".pub"
    user = record.get("service_user", f"kennet-dnstt-{username}")
    gid = int(_run(["id", "-g", user]))
    try:
        Path(temporary_key).unlink(missing_ok=True)
        _run([config["server_binary"], "-gen-key", "-privkey-file", temporary_key, "-pubkey-file", temporary_pub])
        os.chmod(temporary_key, 0o640); os.chown(temporary_key, 0, gid)
        os.chmod(temporary_pub, 0o644)
        new_pub = Path(temporary_pub).read_text(encoding="utf-8").strip()
        _run(["systemctl", "stop", record["service"]])
        os.replace(temporary_key, key_file)
        os.replace(temporary_pub, pub_file)
        if profile.is_file():
            text = profile.read_text(encoding="utf-8").replace(old_pub, new_pub)
            dnstt_manager._atomic(profile, text, 0o600)
        if client_pub_file.is_file():
            dnstt_manager._atomic(client_pub_file, new_pub + "\n", 0o644)
        _run(["systemctl", "start", record["service"]])
    except Exception:
        dnstt_manager._atomic(key_file, old_key.decode("utf-8"), 0o640)
        os.chown(key_file, 0, gid)
        dnstt_manager._atomic(pub_file, old_pub + "\n", 0o644)
        if old_profile is not None:
            dnstt_manager._atomic(profile, old_profile, 0o600)
        if old_client_pub is not None:
            dnstt_manager._atomic(client_pub_file, old_client_pub.decode("utf-8"), 0o644)
        subprocess.run(["systemctl", "start", record["service"]], capture_output=True, check=False)
        raise
    finally:
        Path(temporary_key).unlink(missing_ok=True)
        Path(temporary_pub).unlink(missing_ok=True)
    terminal_ui.detail_card("DNSTT KEYS ROTATED", [("Endpoint", record["domain"]), ("New public key", new_pub),
        ("Client profile", str(profile))], note="Private key remains on the server. Replace the old public key in every client profile.")


def change_banner() -> None:
    message = input("New SSH login banner (single line; blank clears it): ").strip()
    content = (message + "\n") if message else ""
    previous_banner = SSH_BANNER.read_text(encoding="utf-8") if SSH_BANNER.exists() else None
    previous_config = SSH_BANNER_CONFIG.read_text(encoding="utf-8") if SSH_BANNER_CONFIG.exists() else None
    SSH_BANNER.parent.mkdir(parents=True, exist_ok=True)
    SSH_BANNER.write_text(content, encoding="utf-8")
    SSH_BANNER_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    SSH_BANNER_CONFIG.write_text(f"Banner {SSH_BANNER}\n", encoding="utf-8")
    check = subprocess.run(["sshd", "-t"], capture_output=True, text=True, check=False)
    try:
        if check.returncode:
            raise RuntimeError((check.stderr or check.stdout).strip())
        _run(["systemctl", "reload", "ssh"])
    except Exception:
        if previous_banner is None: SSH_BANNER.unlink(missing_ok=True)
        else: SSH_BANNER.write_text(previous_banner, encoding="utf-8")
        if previous_config is None: SSH_BANNER_CONFIG.unlink(missing_ok=True)
        else: SSH_BANNER_CONFIG.write_text(previous_config, encoding="utf-8")
        subprocess.run(["systemctl", "reload", "ssh"], capture_output=True, check=False)
        raise
    print("SSH login banner updated.")


def speed_test() -> None:
    command = shutil.which("speedtest") or shutil.which("speedtest-cli")
    if not command:
        if input("speedtest-cli is not installed. Install it from Ubuntu packages now? Type YES: ").strip() != "YES":
            print("Cancelled.")
            return
        import services_manager
        services_manager.install_ubuntu_package("speedtest-cli")
        command = shutil.which("speedtest-cli")
        if not command:
            raise RuntimeError("speedtest-cli package installed but its command was not found")
    print("Running VPS speed test; this may take a minute...")
    args = [command]
    if Path(command).name == "speedtest":
        args.extend(["--accept-license", "--accept-gdpr"])
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=180)
    print(result.stdout or result.stderr or "Speed test completed without output.")
    if result.returncode:
        print(f"Speed test exited with status {result.returncode}.")


def restart_or_reboot() -> None:
    terminal_ui.option_cards("SERVER POWER", [("1", "Restart managed services"), ("2", "Reboot VPS"), ("0", "Return")], columns=1, color=terminal_ui.YELLOW)
    choice = input("Select: ").strip()
    if choice == "1":
        restart_services()
    elif choice == "2":
        if input("The VPS will disconnect and reboot. Type REBOOT: ").strip() == "REBOOT":
            _run(["systemctl", "reboot"])
        else:
            print("Cancelled.")


def change_ws_response() -> None:
    print("WebSocket handshakes use the RFC 6455 response required by clients. The status text is not customizable because changing it would break compliant clients.")


def menu() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("System settings require root. Start the panel with sudo.")
        return
    actions = {
        "1": ("Check running system", lambda: __import__("panel").show_status()),
        "2": ("Information port", lambda: __import__("service_catalog").show()),
        "3": ("Restart all managed services", restart_services),
        "4": ("Change server domain", change_domain),
        "5": ("Change DNSTT nameserver", change_nameserver),
        "6": ("Rotate DNSTT Pub/Priv key", rotate_dnstt_keys),
        "7": ("Change SSH banner", change_banner),
        "8": ("VPS speed test", speed_test),
        "9": ("Change WebSocket response", change_ws_response),
        "10": ("Restart / reboot server", restart_or_reboot),
    }
    while True:
        terminal_ui.option_cards("SYSTEM SETTINGS", [(key, label) for key, (label, _) in actions.items()] + [("0", "Exit settings")], columns=2, color=terminal_ui.YELLOW)
        choice = input("Select setting [0-10]: ").strip()
        if choice == "0":
            return
        action = actions.get(choice)
        if not action:
            print("Invalid selection.")
            continue
        try:
            action[1]()
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
            print(f"Operation failed: {exc}")

