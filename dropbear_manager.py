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
        print("\n=== DROPBEAR ACCOUNT MANAGER ===")
        print("[01] Install service                  [06] Create trial account")
        print("[02] Create account                   [07] List accounts")
        print("[03] Renew account                    [08] Show connected sessions")
        print("[04] Delete account                   [09] Account details")
        print("[05] Service status                   [00] Return")
        choice = input("Select: ").strip()
        try:
            if choice == "0": return
            if choice == "1": install()
            elif choice == "5":
                result = subprocess.run(["systemctl", "is-active", "kennet-dropbear.service"], capture_output=True, text=True)
                print("Dropbear:", result.stdout.strip() or "inactive", "(TCP/109, TCP/143)")
            elif choice in {"2", "6"}:
                trial = choice == "6"
                username = "trial" + __import__("secrets").token_hex(3) if trial else input("Username: ").strip()
                days = 1 if trial else int(input("Validity in days [30]: ").strip() or "30")
                password = services_manager.ssh_add(username, days, trial=trial)
                print(f"Username: {username}\nPassword (shown once): {password}")
            elif choice == "3":
                username=input("Username: ").strip(); days=int(input("Extend validity by days [30]: ").strip() or "30")
                services_manager.ssh_renew(username,days); print("Account renewed.")
            elif choice == "4":
                username=input("Username: ").strip()
                if input(f"Delete {username}? Type YES: ").strip()=="YES": services_manager.ssh_remove(username)
            elif choice == "7": print("Accounts:", ", ".join(services_manager.ssh_list()) or "none")
            elif choice == "8": print("Connected sessions:", services_manager.active_connections("ssh"))
            elif choice == "9":
                name=input("Username: ").strip(); print(services_manager.account_details("ssh",name))
            else: print("Invalid selection")
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            print(f"Operation failed: {exc}")
