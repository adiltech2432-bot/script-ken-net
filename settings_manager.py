#!/usr/bin/env python3
"""Interactive host and server settings for the Ken-net terminal manager."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unicodedata
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
MAX_SSH_BANNER_BYTES = 32 * 1024
WS_RESPONSE_CONFIG = Path("/etc/kennet-panel/websocket-response.json")
DEFAULT_WS_RESPONSE_BANNER = "KEN-NET"
WS_RESPONSE_BANNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,63}$")
WS_LOG_COLORS = {
    "1": ("green", "\033[92m"), "2": ("cyan", "\033[96m"),
    "3": ("yellow", "\033[93m"), "4": ("blue", "\033[94m"),
    "5": ("magenta", "\033[95m"), "6": ("white", "\033[97m"),
}
WS_LOG_CARD_STYLES = {
    "1": ("\033[102m", "\033[30m"), "2": ("\033[106m", "\033[30m"),
    "3": ("\033[103m", "\033[30m"), "4": ("\033[104m", "\033[97m"),
    "5": ("\033[105m", "\033[30m"), "6": ("\033[107m", "\033[30m"),
}
AUTO_REBOOT_SERVICE = Path("/etc/systemd/system/kennet-auto-reboot.service")
AUTO_REBOOT_TIMER = Path("/etc/systemd/system/kennet-auto-reboot.timer")


def _run(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "Command failed").strip())
    return result.stdout.strip()


def _atomic_text(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def _optional_text(path: Path) -> str | None:
    return path.read_text(encoding="utf-8") if path.exists() else None


def _restore_optional_text(path: Path, content: str | None) -> None:
    if content is None:
        path.unlink(missing_ok=True)
    else:
        _atomic_text(path, content)


def _set_ssh_login_banner(message: str) -> tuple[str | None, str | None, bool]:
    """Apply and verify the SSH pre-auth banner, restoring old files on failure."""
    content = message + "\n" if message else ""
    config = f"Banner {SSH_BANNER}\n"
    previous_banner = _optional_text(SSH_BANNER)
    previous_config = _optional_text(SSH_BANNER_CONFIG)
    changed = previous_banner != content or previous_config != config

    try:
        _atomic_text(SSH_BANNER, content)
        _atomic_text(SSH_BANNER_CONFIG, config)
        check = subprocess.run(["sshd", "-t"], capture_output=True, text=True, check=False)
        if check.returncode:
            raise RuntimeError((check.stderr or check.stdout or "OpenSSH configuration validation failed.").strip())
        effective = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=False)
        if effective.returncode:
            raise RuntimeError((effective.stderr or effective.stdout or "Could not read effective OpenSSH configuration.").strip())
        banner_line = next((line.strip() for line in effective.stdout.splitlines()
                            if line.strip().lower().startswith("banner ")), "")
        if banner_line.casefold() != f"banner {SSH_BANNER}".casefold():
            raise RuntimeError("OpenSSH did not load the KEN-NET login banner setting.")
        if changed:
            _run(["systemctl", "reload", "ssh"])
    except Exception as error:
        try:
            _restore_optional_text(SSH_BANNER, previous_banner)
            _restore_optional_text(SSH_BANNER_CONFIG, previous_config)
            subprocess.run(["systemctl", "reload", "ssh"], capture_output=True, check=False)
        except Exception as rollback_error:
            raise RuntimeError(f"{error}; restoring the previous SSH banner also failed: {rollback_error}") from error
        raise
    return previous_banner, previous_config, changed


def _restore_ssh_login_banner(snapshot: tuple[str | None, str | None, bool]) -> None:
    previous_banner, previous_config, changed = snapshot
    _restore_optional_text(SSH_BANNER, previous_banner)
    _restore_optional_text(SSH_BANNER_CONFIG, previous_config)
    if changed:
        _run(["systemctl", "reload", "ssh"])


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
        raise RuntimeError(f"{len(failures)} managed service(s) failed to restart")
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
    print("Paste the SSH banner below. HTML is accepted as text; standard SSH clients show its tags literally.")
    print("Submit an empty first line to clear the banner. Finish a multi-line banner with END on its own line.")
    first_line = input("Banner: ")
    first_line_size = len(first_line.encode("utf-8"))
    too_large = first_line_size > MAX_SSH_BANNER_BYTES
    has_content = first_line != ""
    lines = [first_line] if first_line and not too_large else []
    banner_size = first_line_size
    if has_content:
        while True:
            line = input()
            if line == "END":
                break
            if not too_large:
                banner_size += 1 + len(line.encode("utf-8"))
                if banner_size > MAX_SSH_BANNER_BYTES:
                    too_large = True
                    lines.clear()
                else:
                    lines.append(line)
    if too_large:
        raise ValueError(f"SSH banner exceeds the {MAX_SSH_BANNER_BYTES // 1024} KiB limit.")
    message = "\n".join(lines)
    if any((ord(char) < 0x20 and char not in "\n\t") or ord(char) == 0x7F for char in message):
        raise ValueError("SSH banners may contain line breaks and tabs, but not terminal control characters.")
    _set_ssh_login_banner(message)
    print("SSH login banner updated. New SSH connections will receive the saved text.")


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
    version = subprocess.run([command, "--version"], capture_output=True, text=True,
                             check=False, timeout=10)
    version_text = f"{version.stdout}\n{version.stderr}".casefold()
    version_label = (version.stdout or version.stderr).strip().splitlines()
    if version.returncode or not version_label:
        raise RuntimeError(((version.stderr or version.stdout or
                             "Could not verify the installed speed-test CLI version.")).strip())
    args = [command]
    if "ookla" in version_text:
        args.extend(["--accept-license", "--accept-gdpr"])
    else:
        # Ubuntu's speedtest-cli package also installs a `speedtest` command.
        # Detect the implementation instead of assuming that name means Ookla.
        args.append("--simple")
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=180)
    output = (result.stdout or result.stderr).strip()
    if result.returncode:
        raise RuntimeError((output or
                            f"Speed test exited with status {result.returncode}.").strip())
    if not output:
        raise RuntimeError("The speed test command returned no measurement output; check the installed CLI.")
    print(f"Measurement source: {Path(command).name} ({version_label[0]})")
    print("Measured VPS network results:")
    print(output)


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
    elif choice != "0":
        print("Invalid selection. Choose 1, 2, or 0.")


def change_ws_response() -> None:
    import websocket_tunnel
    current = websocket_tunnel.response_banner()
    current_color = websocket_tunnel.response_log_color()
    terminal_ui.detail_card("WEBSOCKET RESPONSE BANNER", [
        ("Required handshake", "101 Switching Protocols"),
        ("Current KEN-NET banner", current),
        ("Handshake log color", current_color.upper()),
    ], note="The response text is also used as the OpenSSH pre-login banner shown by clients such as HTTP Custom as Server Message. It applies to all SSH logins. The selected color affects successful WebSocket 101 entries in the systemd service log.", color=terminal_ui.BLUE)
    value = input("New response banner [Enter keeps current; DEFAULT resets]: ")
    value = unicodedata.normalize("NFKC", value)
    value = "".join("-" if unicodedata.category(char) == "Pd" or char == "\u2212" else char
                    for char in value).strip()
    if not value:
        value = current
    if value.upper() == "DEFAULT":
        value = DEFAULT_WS_RESPONSE_BANNER
    if value != current and not WS_RESPONSE_BANNER_RE.fullmatch(value):
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._/-")
        invalid = list(dict.fromkeys(
            f"U+{ord(char):04X}" for index, char in enumerate(value)
            if char not in allowed or (index == 0 and not (char.isascii() and char.isalnum()))
        ))
        detail = f" Unsupported character code(s): {', '.join(invalid)}." if invalid else ""
        raise ValueError("Use 1–64 letters, numbers, spaces, dots, underscores, slashes, or hyphens." + detail)
    choices = [(key, f"{name.title()} log") for key, (name, _ansi) in WS_LOG_COLORS.items()]
    terminal_ui.option_cards("WEBSOCKET HANDSHAKE LOG COLOR", choices, columns=3,
                             color=terminal_ui.BLUE, card_styles=WS_LOG_CARD_STYLES)
    selected = input(f"Log color [1-6; Enter keeps {current_color}]: ").strip()
    if not selected:
        color_name = current_color
    else:
        by_name = {name: name for name, _ansi in WS_LOG_COLORS.values()}
        if selected in WS_LOG_COLORS:
            color_name = WS_LOG_COLORS[selected][0]
        elif selected.casefold() in by_name:
            color_name = selected.casefold()
        else:
            raise ValueError("Choose a WebSocket log color from 1 to 6, or press Enter to keep the current color.")
    ssh_snapshot = _set_ssh_login_banner(value)
    if value == current and color_name == current_color and not ssh_snapshot[2]:
        print("No change made.")
        return
    try:
        _atomic_text(WS_RESPONSE_CONFIG, json.dumps({"banner": value, "log_color": color_name}) + "\n")
    except Exception:
        _restore_ssh_login_banner(ssh_snapshot)
        raise
    ansi = next(code for name, code in WS_LOG_COLORS.values() if name == color_name)
    print(f"{ansi}WebSocket handshake log preview: {value}\033[0m")
    print("The response text is active in the SSH login banner; new SSH logins will display it. WebSocket log color applies immediately.")


def _server_timezone() -> str:
    try:
        result = subprocess.run(["timedatectl", "show", "-p", "Timezone", "--value"],
                                capture_output=True, text=True, check=False, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return "Etc/UTC"
    zone = result.stdout.strip()
    if result.returncode or not zone or not re.fullmatch(r"[A-Za-z0-9_+./-]+", zone):
        return "Etc/UTC"
    return zone


def daily_auto_reboot() -> None:
    zone = _server_timezone()
    current = "Not scheduled"
    if AUTO_REBOOT_TIMER.is_file():
        match = re.search(r"(?m)^OnCalendar=\*-\*-\* (\d{2}:\d{2}:\d{2})(?: ([^\s]+))?$",
                          AUTO_REBOOT_TIMER.read_text(encoding="utf-8"))
        if match:
            current = f"Daily at {match.group(1)[:5]} {match.group(2) or zone}"
    terminal_ui.detail_card("DAILY VPS AUTO REBOOT", [
        ("Current schedule", current), ("Server timezone", zone),
    ], note="The schedule uses the selected server timezone and is armed daily with 1-second systemd timer accuracy.", color=terminal_ui.YELLOW)
    terminal_ui.option_cards("DAILY VPS AUTO REBOOT", [
        ("1", "Set / change daily time"), ("2", "Disable schedule"), ("0", "Return"),
    ], columns=2, color=terminal_ui.YELLOW)
    choice = input("Select: ").strip()
    if choice == "0":
        return
    if choice == "1":
        scheduled = input(f"Daily reboot time HH:MM [{zone}]: ").strip()
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", scheduled):
            raise ValueError("Enter a 24-hour time in HH:MM format, for example 03:30.")
        service = """[Unit]
Description=Daily scheduled KEN-NET VPS reboot
DefaultDependencies=yes

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl reboot
"""
        timer = ("[Unit]\nDescription=Daily KEN-NET VPS reboot schedule\n\n"
                 "[Timer]\n"
                 f"OnCalendar=*-*-* {scheduled}:00 {zone}\n"
                 "AccuracySec=1s\nRandomizedDelaySec=0\nPersistent=false\n"
                 "Unit=kennet-auto-reboot.service\n\n"
                 "[Install]\nWantedBy=timers.target\n")
        _atomic_text(AUTO_REBOOT_SERVICE, service)
        _atomic_text(AUTO_REBOOT_TIMER, timer)
        try:
            _run(["systemctl", "daemon-reload"])
            _run(["systemctl", "enable", "--now", "kennet-auto-reboot.timer"])
        except Exception:
            AUTO_REBOOT_SERVICE.unlink(missing_ok=True)
            AUTO_REBOOT_TIMER.unlink(missing_ok=True)
            subprocess.run(["systemctl", "disable", "--now", "kennet-auto-reboot.timer"],
                           capture_output=True, check=False)
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, check=False)
            raise
        print(f"Daily VPS reboot scheduled for {scheduled} ({zone}).")
    elif choice == "2":
        if input("This removes the daily reboot schedule. Type DISABLE: ").strip() != "DISABLE":
            print("Cancelled.")
            return
        if AUTO_REBOOT_TIMER.exists() or AUTO_REBOOT_SERVICE.exists():
            result = subprocess.run(["systemctl", "disable", "--now", "kennet-auto-reboot.timer"],
                                    capture_output=True, text=True, check=False)
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout or
                                    "Could not disable the daily reboot timer.").strip())
        AUTO_REBOOT_TIMER.unlink(missing_ok=True)
        AUTO_REBOOT_SERVICE.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        print("Daily VPS auto reboot disabled.")
    else:
        print("Invalid selection. Choose 1, 2, or 0.")


def delete_expired_accounts() -> None:
    import services_manager
    removed = services_manager.purge_expired(strict=True)
    print(f"Expired accounts removed: {len(removed)}")
    print(", ".join(removed) if removed else "No expired accounts found.")


def menu() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("System settings require root. Start the panel with sudo.")
        return
    actions = {
        "1": ("◉  Check running system", lambda: __import__("panel").show_status()),
        "2": ("▤  Live port status", lambda: __import__("service_catalog").show()),
        "3": ("↻  Restart managed services", restart_services),
        "4": ("◎  Change server domain", change_domain),
        "5": ("⌁  Change DNSTT nameserver", change_nameserver),
        "6": ("⚿  Rotate DNSTT keys", rotate_dnstt_keys),
        "7": ("▣  Change SSH banner (text / HTML)", change_banner),
        "8": ("↗  VPS network speed test", speed_test),
        "10": ("⏻  Server restart / reboot", restart_or_reboot),
        "11": ("◷  Daily VPS auto reboot", daily_auto_reboot),
        "12": ("⌫  Delete all expired accounts", delete_expired_accounts),
    }
    while True:
        terminal_ui.option_cards(
            "SYSTEM SETTINGS",
            [(key, label) for key, (label, _) in actions.items()] + [("0", "←  Back to dashboard")],
            columns=2, color=terminal_ui.YELLOW, colorful=True,
        )
        print(f"\n{terminal_ui.BLUE}Enter a card number to open | 0 returns to the dashboard{terminal_ui.RESET}")
        choice = input("Select setting [0-8, 10-12]: ").strip()
        if choice == "0":
            return
        action = actions.get(choice)
        if not action:
            print("Invalid selection. Choose one of the numbered settings.")
            input("Press Enter to return to System Settings...")
            continue
        terminal_ui.clear_screen()
        terminal_ui.heading(f"SYSTEM SETTINGS  /  {action[0]}", terminal_ui.YELLOW)
        succeeded = False
        try:
            action[1]()
            succeeded = True
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
            print(f"Operation failed: {exc}")
        if succeeded:
            print("\nReturned from this setting. Review the result above.")
        input("\nPress Enter to return to System Settings...")

