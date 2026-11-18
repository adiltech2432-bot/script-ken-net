#!/usr/bin/env python3
"""Install and inspect a dedicated Dropbear SSH daemon."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import services_manager


def install() -> None:
    if input("Install Dropbear on TCP/109 (shared SSH/WebSocket mux) and TCP/143 using existing Linux accounts? Type YES: ").strip() != "YES":
        return
    if not shutil.which("dropbear"):
        subprocess.run(["apt-get", "update"], check=True)
        subprocess.run(["apt-get", "install", "-y", "dropbear-bin"], check=True)
    unit = """[Unit]
Description=Kennet Dropbear SSH service
After=network.target ssh.service
[Service]
Type=simple
ExecStart=/usr/sbin/dropbear -F -E -p 2109 -p 143
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
    services_manager.open_ports([("tcp", 109), ("tcp", 143), ("tcp", 443)])


def menu() -> None:
    import terminal_ui
    while True:
        terminal_ui.option_cards("DROPBEAR ACCOUNT MANAGER", [("01", "Install service"),
            ("02", "Create account"), ("03", "Renew account"), ("04", "Delete account"),
            ("05", "Service status"), ("06", "Create trial account"),
            ("07", "List accounts"), ("08", "Show connected sessions"),
            ("09", "Account details"), ("00", "Return")])
        choice = input("Select: ").strip()
        try:
            if choice == "0": return
            if choice == "1": install()
            elif choice == "5":
                result = subprocess.run(["systemctl", "is-active", "kennet-dropbear.service"], capture_output=True, text=True)
                print("Dropbear:", result.stdout.strip() or "inactive", "(TCP/109 mux, TCP/143; WebSocket paths via 80/443)")
            elif choice in {"2", "6"}:
                trial = choice == "6"
                username = "trial" + __import__("secrets").token_hex(3) if trial else input("Username: ").strip()
                trial_minutes = services_manager.prompt_trial_minutes() if trial else None
                days = 1 if trial else int(input("Validity in days [30]: ").strip() or "30")
                password = services_manager.ssh_add(username, days, trial=trial, trial_minutes=trial_minutes)
                services_manager.show_created_account("dropbear", username, password, days, trial=trial)
            elif choice == "3":
                username=terminal_ui.select_account("DROPBEAR", services_manager.ssh_list())
                if username is None: continue
                days=int(input("Extend validity by days [30]: ").strip() or "30")
                services_manager.ssh_renew(username,days); print("Account renewed.")
            elif choice == "4":
                username=terminal_ui.select_account("DROPBEAR", services_manager.ssh_list())
                if username is None: continue
                if input(f"Delete {username}? Type YES: ").strip()=="YES": services_manager.ssh_remove(username)
            elif choice == "7":
                services_manager.purge_expired()
                names = services_manager.ssh_list()
                rows = services_manager.account_roster_rows("ssh", names,
                    connections=services_manager.active_connections("ssh"))
                terminal_ui.account_roster("DROPBEAR / SSH ACCOUNTS", rows,
                    note="SSH and Dropbear share Linux accounts; the online count includes both daemons.")
            elif choice == "8":
                sessions = services_manager.active_connections("ssh")
                names = services_manager.ssh_list()
                rows = services_manager.account_roster_rows("ssh", names, connections=sessions)
                terminal_ui.account_roster("DROPBEAR / SSH LIVE CONNECTIONS", rows,
                    note="Counts are established SSH TCP sessions, including both OpenSSH and Dropbear.")
            elif choice == "9":
                name=terminal_ui.select_account("DROPBEAR", services_manager.ssh_list())
                if name is not None: services_manager.show_account_details("dropbear", name)
            else: print("Invalid selection")
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            print(f"Operation failed: {exc}")
