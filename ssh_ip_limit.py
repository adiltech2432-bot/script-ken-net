#!/usr/bin/env python3
"""PAM auth hook limiting concurrent distinct remote IPs for managed SSH users."""

from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import sys
from pathlib import Path

STATE = Path("/etc/kennet-panel/services.json")
LOCK = Path("/run/kennet-ssh-ip-limit.lock")


def _remote_hosts(username: str) -> set[str]:
    result = subprocess.run(["who", "-u"], capture_output=True, text=True, check=False)
    hosts = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if not fields or fields[0] != username:
            continue
        match = re.search(r"\(([^()]*)\)\s*$", line)
        host = match.group(1).strip() if match else ""
        if host and not host.startswith(":"):
            hosts.add(host)
    if not hosts:
        sessions = subprocess.run(["loginctl", "list-sessions", "--no-legend", "--no-pager"],
                                  capture_output=True, text=True, check=False)
        for row in sessions.stdout.splitlines():
            fields = row.split()
            if not fields or len(fields) < 3 or fields[2] != username:
                continue
            remote = subprocess.run(["loginctl", "show-session", fields[0], "-p", "RemoteHost", "--value"],
                                    capture_output=True, text=True, check=False).stdout.strip()
            is_remote = subprocess.run(["loginctl", "show-session", fields[0], "-p", "Remote", "--value"],
                                      capture_output=True, text=True, check=False).stdout.strip()
            if remote and is_remote.lower() == "yes":
                hosts.add(remote)
    return hosts


def allowed(username: str, remote: str) -> bool:
    try:
        state = json.loads(STATE.read_text(encoding="utf-8"))
        account = state.get("accounts", {}).get(username, {})
        if account.get("protocol") != "ssh":
            return True
        limit = int(account.get("max_ips", 0))
        if limit <= 0:
            return True
        if not remote or remote in {"unknown", "localhost"}:
            return False
        LOCK.parent.mkdir(parents=True, exist_ok=True)
        with LOCK.open("w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            current = _remote_hosts(username)
            return remote in current or len(current) < limit
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        # A broken optional guard must not lock the administrator out of SSH.
        return True


if __name__ == "__main__":
    user = os.environ.get("PAM_USER", "")
    host = os.environ.get("PAM_RHOST", "")
    if allowed(user, host):
        raise SystemExit(0)
    print("This SSH account has reached its allowed number of connected IP addresses.", file=sys.stderr)
    raise SystemExit(1)
