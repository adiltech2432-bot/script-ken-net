#!/usr/bin/env python3
"""Manage ePro UDP Custom and reserve UDP ports owned by other services."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

import services_manager

ROOT = Path("/opt/kennet-udp")
BIN = ROOT / "udp-custom"
CONFIG = ROOT / "config.json"
UNIT = Path("/etc/systemd/system/kennet-udp-custom.service")
STATE = Path("/etc/kennet-panel/udp-custom.json")
UPSTREAM = "https://raw.githubusercontent.com/http-custom/udp-custom/main/bin/udp-custom-linux-amd64"
BASE_EXCLUSIONS = {53, 2200, 51820}


def _run(args: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result.stdout.strip()


def _atomic(path: Path, content: str, mode: int = 0o600) -> None:
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    except Exception:
        Path(temp).unlink(missing_ok=True)
        raise


def exclusions() -> list[int]:
    """Return reserved ports; DNSTT, OpenVPN UDP and WireGuard must bypass UDP-Custom DNAT."""
    ports = set(BASE_EXCLUSIONS)
    path = Path("/etc/wireguard")
    if path.is_dir():
        for cfg in path.glob("*.conf"):
            for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip().lower().startswith("listenport") and "=" in line:
                    try:
                        port = int(line.split("=", 1)[1].strip())
                    except ValueError:
                        continue
                    if 1 <= port <= 65535:
                        ports.add(port)
    return sorted(ports)


def _unit_text(ports: list[int]) -> str:
    exclude = ",".join(map(str, ports))
    return (
        "[Unit]\nDescription=Kennet UDP Custom tunnel\nAfter=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=simple\nUser=root\n"
        f"ExecStart={BIN} server --config {CONFIG} --exclude {exclude}\n"
        "Restart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nPrivateTmp=true\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def install() -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Run as root")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError("The upstream UDP-Custom binary is published for x86_64 only")
    if not shutil.which("curl"):
        services_manager.install_ubuntu_package("curl")
    if input("Install the upstream ePro UDP-Custom binary and reserve UDP ports 53, 2200, and WireGuard's port? Type YES: ").strip() != "YES":
        return
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o750)
    downloaded = subprocess.run(["curl", "-fL", "--retry", "3", UPSTREAM, "-o", str(BIN)], capture_output=True, text=True, check=False)
    if downloaded.returncode:
        raise RuntimeError(downloaded.stderr.strip() or "Could not download UDP-Custom binary")
    os.chmod(BIN, 0o755)
    _atomic(CONFIG, json.dumps({"listen": ":2100", "stream_buffer": 33554432,
        "receive_buffer": 83886080, "auth": {"mode": "passwords"}}, indent=2) + "\n")
    ports = exclusions()
    _atomic(UNIT, _unit_text(ports), 0o644)
    _atomic(STATE, json.dumps({"exclusions": ports, "upstream": UPSTREAM}, indent=2) + "\n")
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", "--now", "kennet-udp-custom.service"])
    print("UDP-Custom redirects UDP destination ports through its tunnel listener, except: " + ", ".join(map(str, ports)))
    print("Allow UDP/1-65535 in the VPS provider firewall if you need the full advertised range.")


def refresh_exclusions() -> None:
    if not UNIT.is_file():
        raise RuntimeError("Install UDP-Custom first")
    ports = exclusions()
    _atomic(UNIT, _unit_text(ports), 0o644)
    _atomic(STATE, json.dumps({"exclusions": ports, "upstream": UPSTREAM}, indent=2) + "\n")
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "restart", "kennet-udp-custom.service"])


def ready() -> tuple[bool, str]:
    if not BIN.is_file() or not CONFIG.is_file():
        return False, "UDP-Custom binary/configuration is missing"
    if subprocess.run(["systemctl", "is-active", "--quiet", "kennet-udp-custom.service"], check=False).returncode:
        return False, "kennet-udp-custom.service is not active"
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    return True, f"UDP-Custom active on internal {cfg.get('listen', 'unknown')}; excluded UDP ports: {', '.join(map(str, exclusions()))}"


def menu() -> None:
    import terminal_ui
    while True:
        terminal_ui.option_cards("UDP CUSTOM ACCOUNT MANAGER", [
            ("01", "Install / configure UDP Custom"), ("02", "Create account"),
            ("03", "Renew account"), ("04", "Delete account"),
            ("05", "Show account details"), ("06", "Create trial account"),
            ("07", "List accounts"), ("08", "Connected sessions"), ("00", "Return")])
        choice = input("Select: ").strip()
        try:
            if choice in {"0", "00"}:
                return
            if choice == "1":
                install()
            elif choice in {"2", "6"}:
                trial = choice == "6"
                name = "trial" + __import__("secrets").token_hex(3) if trial else input("Username: ").strip()
                days = 1 if trial else int(input("Validity days [30]: ").strip() or "30")
                password = services_manager.local_user_add("udp", name, days, trial=trial, create_home=False)
                services_manager.show_created_account("udp", name, password, days, trial=trial)
            elif choice == "3":
                name = terminal_ui.select_account("UDP CUSTOM", services_manager.local_user_list("udp"))
                if name is None: continue
                days = int(input("Extend validity by days [30]: ").strip() or "30")
                services_manager.local_user_renew("udp", name, days); print("Account renewed.")
            elif choice == "4":
                name = terminal_ui.select_account("UDP CUSTOM", services_manager.local_user_list("udp"))
                if name is None: continue
                if input(f"Delete {name}? Type YES: ").strip() == "YES":
                    services_manager.local_user_remove("udp", name)
            elif choice == "5":
                name = input("Username: ").strip(); services_manager.show_account_details("udp", name)
            elif choice == "7":
                for name in services_manager.local_user_list("udp"):
                    print(services_manager.account_details("udp", name))
            elif choice == "8":
                sessions = services_manager.active_connections("udp")
                names = services_manager.local_user_list("udp")
                print("Registered UDP-Custom accounts and sessions:")
                for name in names: print(f"- {name}: {sessions.get(name, 0)}")
                if not names: print("- none")
            else:
                print("Invalid selection")
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(f"Operation failed: {exc}")


if __name__ == "__main__":
    menu()
