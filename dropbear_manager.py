#!/usr/bin/env python3
"""Install and inspect a dedicated Dropbear SSH daemon."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import services_manager


def install() -> None:
    if input("Install Dropbear on TCP/109 and TCP/143 using the existing Linux SSH accounts? Type YES: ").strip() != "YES":
        return
    if not shutil.which("dropbear"):
        subprocess.run(["apt-get", "update"], check=True)
        subprocess.run(["apt-get", "install", "-y", "dropbear-bin"], check=True)
    unit = """[Unit]
Description=Kennet Dropbear SSH service
After=network.target ssh.service
[Service]
Type=simple
ExecStart=/usr/sbin/dropbear -F -E -p 109 -p 143
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=full
[Install]
WantedBy=multi-user.target
"""
    path = Path("/etc/systemd/system/kennet-dropbear.service")
    if path.exists() and "Kennet Dropbear SSH service" not in path.read_text():
        raise FileExistsError(f"Refusing to overwrite unrelated unit: {path}")
    path.write_text(unit, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "kennet-dropbear.service"], check=True)
    services_manager.open_ports([("tcp", 109), ("tcp", 143)])


def menu() -> None:
    while True:
        print("\n=== Dropbear SSH ===\n1. Install on TCP/109 and TCP/143\n2. List shared SSH accounts\n0. Return")
        choice = input("Select: ").strip()
        try:
            if choice == "0": return
            if choice == "1": install()
            elif choice == "2": print("Accounts:", ", ".join(services_manager.ssh_list()) or "none")
            else: print("Invalid selection")
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            print(f"Operation failed: {exc}")
