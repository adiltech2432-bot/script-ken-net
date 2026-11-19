#!/usr/bin/env python3
"""Keyboard-driven KEN-NET dashboard; backend operations remain in existing managers."""

from __future__ import annotations

try:
    import curses
except ImportError:  # Windows development hosts can still run the plain fallback.
    curses = None
import locale
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from collections import deque
from dataclasses import dataclass


GROUPS = (
    ("TUNNELS", "blue", ("ssh", "dropbear", "udp")),
    ("PROXIES", "violet", ("vmess", "vless", "trojan", "shadowsocks")),
    ("VPN", "mint", ("openvpn", "wireguard")),
    ("DNS TUNNELS", "amber", ("slowdns", "dnstt")),
    ("DOMAIN & SECURITY", "rose", ("tls",)),
)

PROTOCOL_META = {
    "ssh": ("SSH", "ssh"), "dropbear": ("Dropbear", "kennet-dropbear"),
    "udp": ("UDP Custom", "kennet-udp-custom"), "vmess": ("VMess", "xray"),
    "vless": ("VLESS", "xray"), "trojan": ("Trojan", "xray"),
    "shadowsocks": ("Shadowsocks", "xray"),
    "openvpn": ("OpenVPN", "openvpn-server@server-tcp"),
    "wireguard": ("WireGuard", "wg-quick"),
    "slowdns": ("SlowDNS", "kennet-dnstt-router"),
    "dnstt": ("DNSTT", "kennet-dnstt-router"), "tls": ("TLS / Domain", "gateway"),
}

CATALOG_SERVICES = {
    "ssh": ("OpenSSH", "SSH WebSocket", "HAProxy Loadbalancer"),
    "dropbear": ("Dropbear", "Dropbear WebSocket"),
    "udp": ("UDP Custom",),
    "vmess": ("Xray VMess TLS / WS / gRPC", "Xray VMess None TLS"),
    "vless": ("Xray VLESS TLS / WS / gRPC", "Xray VLESS None TLS"),
    "trojan": ("Trojan WS / gRPC",), "shadowsocks": ("Shadowsocks WS / gRPC",),
    "openvpn": ("OpenVPN SSL", "OpenVPN WebSocket SSL", "OpenVPN TCP", "OpenVPN UDP"),
    "wireguard": ("WireGuard",), "slowdns": ("DNSTT / SlowDNS",),
    "dnstt": ("DNSTT / SlowDNS",),
    "tls": ("Nginx Webserver", "HAProxy Loadbalancer"),
}

PROTOCOL_ORDER = tuple(key for _group, _color, keys in GROUPS for key in keys)
# Stable numeric menu IDs retained from the original panel.py interface.
LEGACY_ORDER = ("ssh", "vmess", "vless", "trojan", "shadowsocks", "dropbear",
                "openvpn", "udp", "wireguard", "slowdns", "dnstt", "tls")
TOOLS = (("13", "System settings"), ("14", "Protocol status"),
         ("15", "Services / ports"), ("0", "Exit"))
RGB = {
    "ink": (10, 15, 28), "line": (38, 50, 76), "text": (207, 216, 234),
    "dim": (104, 119, 154), "blue": (92, 184, 255), "violet": (180, 156, 255),
    "mint": (79, 227, 176), "amber": (255, 180, 84), "rose": (255, 122, 156),
    "ok": (79, 227, 176), "off": (74, 86, 117), "error": (255, 107, 107),
}
SPARK = "▁▂▃▄▅▆▇█"
_activity = deque(maxlen=10)


def _legacy_protocol_key(number: int) -> str:
    """Resolve the original numbered protocol menu without depending on card order."""
    if number < 1 or number > len(LEGACY_ORDER):
        raise ValueError(f"Protocol option must be between 1 and {len(LEGACY_ORDER)}")
    return LEGACY_ORDER[number - 1]


@dataclass
class Row:
    key: str
    title: str
    group: str
    color: str
    state: str
    detail: str
    count: str
    engine: str
    ports: str


def _xterm_index(rgb: tuple[int, int, int]) -> int:
    """Map an RGB palette color to the nearest xterm-256 cube or gray."""
    def level(v: int) -> int:
        return min(5, max(0, round(v / 255 * 5)))
    r, g, b = (level(value) for value in rgb)
    cube = (16 + 36 * r + 6 * g + b,)
    grays = range(232, 256)
    candidates = list(cube) + list(grays)
    def color(index: int) -> tuple[int, int, int]:
        if index >= 232:
            value = 8 + (index - 232) * 10
            return value, value, value
        value = index - 16
        return (0 if value // 36 == 0 else 55 + (value // 36) * 40,
                0 if (value % 36) // 6 == 0 else 55 + ((value % 36) // 6) * 40,
                0 if value % 6 == 0 else 55 + (value % 6) * 40)
    return min(candidates, key=lambda index: sum((a - b) ** 2 for a, b in zip(color(index), rgb)))


def collect_rows() -> tuple[list[Row], dict[str, object]]:
    """Read current protocol and account state through existing project providers."""
    import panel
    try:
        import services_manager
        state = services_manager.state()
        accounts = state.get("accounts", {})
        domain = str(state.get("domain") or "—")
    except (ImportError, OSError, ValueError, RuntimeError):
        services_manager = None
        accounts, domain = {}, "—"

    counts: dict[str, int | None] = {key: sum(1 for value in accounts.values()
                       if isinstance(value, dict) and value.get("protocol") == key)
              for key in PROTOCOL_ORDER}
    if services_manager is None:
        counts = {key: None for key in PROTOCOL_ORDER}
    if services_manager is not None:
        try:
            counts["ssh"] = len(services_manager.ssh_list())
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            counts["ssh"] = None
    try:
        import dropbear_manager
        if hasattr(dropbear_manager, "list_accounts"):
            counts["dropbear"] = len(dropbear_manager.list_accounts())
        else:
            counts["dropbear"] = counts.get("ssh", 0)
    except (ImportError, OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        counts["dropbear"] = None
    try:
        import wireguard_manager
        counts["wireguard"] = len(wireguard_manager.list_peers())
    except (ImportError, OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        counts["wireguard"] = None
    try:
        import dnstt_manager
        dnstt_accounts = dnstt_manager.list_accounts()
        counts["dnstt"] = len(dnstt_accounts)
        counts["slowdns"] = len(dnstt_accounts)
    except (ImportError, OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        counts["dnstt"] = counts["slowdns"] = None

    # These SSH-compatible transports share Linux accounts; UDP Custom has its
    # own service but authenticates the same account database.
    counts["udp"] = counts.get("ssh")
    try:
        import openvpn_manager
        counts["openvpn"] = len(openvpn_manager._account_state().get("accounts", {}))
    except (ImportError, AttributeError, OSError, ValueError, RuntimeError):
        counts["openvpn"] = None

    rows: list[Row] = []
    for group, color, keys in GROUPS:
        for key in keys:
            title, engine = PROTOCOL_META[key]
            ports = _configured_listeners(key)
            protocol = next(item for item in panel.PROTOCOLS if item.key == key)
            status, detail = panel.protocol_state(protocol)
            if key == "tls":
                cert_count = 0
                try:
                    cert_count = sum(1 for path in Path("/etc/letsencrypt/live").iterdir()
                                     if path.is_dir() and (path / "fullchain.pem").is_file())
                except OSError:
                    pass
                count = f"{cert_count} certificates" if cert_count else "—"
            elif key == "wireguard":
                count = f"{counts[key]} peers" if counts[key] is not None else "—"
            elif key in {"dnstt", "slowdns"}:
                count = f"{counts[key]} endpoints" if counts[key] is not None else "—"
            elif counts.get(key) is None:
                count = "—"
            else:
                count = f"{counts[key]} accounts"
            rows.append(Row(key, title, group, color, status, detail, count, engine, ports))
    active_services = sum(1 for row in rows if row.state in {"Active", "Service active"})
    _activity.append(active_services)
    return rows, {"domain": domain, "accounts": accounts, "counts": counts,
                  "load": _load_percent(), "ram": _ram_percent(), "disk": _disk_percent(),
                  "uptime": _uptime(), "os": _ubuntu_release(), "active": active_services}


def _configured_listeners(protocol: str) -> str:
    """Intersect the documented service catalog with the machine's live listeners."""
    try:
        import service_catalog
        services = {name: (transport, ports) for name, transport, ports, _note in service_catalog.SERVICES}
    except (ImportError, AttributeError, ValueError):
        return "—"
    try:
        listeners = set()
        import re
        for transport, args in (("tcp", ["ss", "-H", "-lnt"]), ("udp", ["ss", "-H", "-lnu"])):
            result = subprocess.run(args, capture_output=True, text=True, timeout=2, check=False)
            for line in result.stdout.splitlines():
                fields = line.split()
                if len(fields) < 2:
                    continue
                # The local endpoint is immediately before the remote endpoint
                # in both standard `ss -H` output layouts.
                match = re.search(r":(\d+)$", fields[-2])
                if match:
                    listeners.add((transport, int(match.group(1))))
    except (OSError, subprocess.SubprocessError, ValueError):
        return "—"
    present = set()
    for name in CATALOG_SERVICES.get(protocol, ()):
        item = services.get(name)
        if not item:
            continue
        transport, ports = item
        if name == "UDP Custom":
            try:
                import udp_custom_manager
                import json
                config = json.loads(udp_custom_manager.CONFIG.read_text(encoding="utf-8"))
                port = int(str(config.get("listen", "")).rsplit(":", 1)[1])
                if ("udp", port) in listeners:
                    present.add(f"UDP/{port}")
            except (OSError, ValueError, KeyError, IndexError, TypeError):
                pass
            continue
        if name == "WireGuard":
            try:
                result = subprocess.run(["wg", "show", "all", "listen-port"], capture_output=True,
                                        text=True, timeout=2, check=False)
                for line in result.stdout.splitlines():
                    port = int(line.rsplit("\t", 1)[-1])
                    if ("udp", port) in listeners:
                        present.add(f"UDP/{port}")
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            continue
        for port in ports:
            if not isinstance(port, int) or port < 1 or port > 65535:
                continue
            if (transport, port) in listeners:
                present.add(f"{transport.upper()}/{port}")
    return ", ".join(sorted(present, key=lambda value: (value.split("/")[0], int(value.split("/")[1])))) or "—"


def _load_percent() -> int | None:
    try:
        return min(100, int(os.getloadavg()[0] * 100 / max(1, os.cpu_count() or 1)))
    except (AttributeError, OSError):
        return None


def _ram_percent() -> int | None:
    try:
        values = {}
        for line in open("/proc/meminfo", encoding="ascii"):
            name, value = line.split(":", 1)
            values[name] = int(value.strip().split()[0])
        total = values["MemTotal"]
        return (total - values.get("MemAvailable", total)) * 100 // total
    except (OSError, ValueError, KeyError, ZeroDivisionError):
        return None


def _disk_percent() -> int | None:
    try:
        usage = shutil.disk_usage("/")
        return usage.used * 100 // usage.total
    except (OSError, ZeroDivisionError):
        return None


def _uptime() -> str:
    try:
        seconds = int(float(open("/proc/uptime", encoding="ascii").read().split()[0]))
        days, rest = divmod(seconds, 86400)
        hours, rest = divmod(rest, 3600)
        return f"up {days}d {hours}h {rest // 60}m"
    except (OSError, ValueError, IndexError):
        return "uptime —"


def _ubuntu_release() -> str:
    try:
        for line in open("/etc/os-release", encoding="utf-8"):
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.system()


class Dashboard:
    def __init__(self, stdscr, force_plain: bool = False):
        self.stdscr = stdscr
        self.force_plain = force_plain or bool(os.environ.get("NO_COLOR")) or os.environ.get("TERM") == "dumb"
        encoding = locale.getpreferredencoding(False).lower().replace("-", "")
        self.ascii = force_plain or os.environ.get("TERM") == "linux" or "utf8" not in encoding
        self.selected = 0
        self.tool_selected = 0
        self.in_tools = False
        self.numeric = ""
        self.toast = ""
        self.toast_until = 0.0
        self.last_draw = None
        self.rows: list[Row] = []
        self.snapshot: dict[str, object] = {}
        self.pairs: dict[str, int] = {}
        self._setup_terminal()

    def _setup_terminal(self) -> None:
        self.stdscr.keypad(True)
        self.stdscr.timeout(2000)
        curses.curs_set(0)
        try:
            curses.start_color()
            curses.use_default_colors()
            if not self.force_plain and curses.has_colors():
                for idx, (name, rgb) in enumerate(RGB.items(), 1):
                    color = _xterm_index(rgb) if curses.COLORS >= 256 else {
                        "blue": curses.COLOR_BLUE, "violet": curses.COLOR_MAGENTA,
                        "mint": curses.COLOR_GREEN, "amber": curses.COLOR_YELLOW,
                        "rose": curses.COLOR_RED, "ok": curses.COLOR_GREEN,
                        "off": curses.COLOR_WHITE, "error": curses.COLOR_RED,
                        "text": curses.COLOR_WHITE, "dim": curses.COLOR_CYAN,
                        "line": curses.COLOR_BLUE, "ink": -1,
                    }.get(name, curses.COLOR_WHITE)
                    if idx < curses.COLOR_PAIRS:
                        curses.init_pair(idx, color, -1)
                        self.pairs[name] = idx
        except curses.error:
            self.pairs = {}

    def color(self, name: str, *, bold: bool = False, reverse: bool = False) -> int:
        style = curses.color_pair(self.pairs[name]) if name in self.pairs else curses.A_NORMAL
        if bold:
            style |= curses.A_BOLD
        if reverse:
            style |= curses.A_REVERSE
        return style

    def put(self, y: int, x: int, text: object, color: str = "text", *, bold: bool = False,
            reverse: bool = False, width: int | None = None) -> None:
        height, columns = self.stdscr.getmaxyx()
        if y < 0 or y >= height or x >= columns:
            return
        available = max(0, columns - x - 1)
        limit = available if width is None else min(available, width)
        value = str(text).replace("\n", " ").replace("\r", " ")[:limit]
        try:
            self.stdscr.addnstr(y, x, value, limit, self.color(color, bold=bold, reverse=reverse))
        except curses.error:
            pass

    def _box(self, y: int, x: int, height: int, width: int, title: str, color: str) -> None:
        if height < 2 or width < 4:
            return
        if self.ascii:
            tl, tr, bl, br, h, v, join = "+", "+", "+", "+", "-", "|", "+"
        else:
            tl, tr, bl, br, h, v, join = "╭", "╮", "╰", "╯", "─", "│", "├"
        self.put(y, x, tl + h * (width - 2) + tr, color)
        label = f" {title} "
        if len(label) < width - 4:
            self.put(y, x + max(2, (width - len(label)) // 2), label, color, bold=True)
        for row in range(1, height - 1):
            self.put(y + row, x, v, color)
            self.put(y + row, x + width - 1, v, color)
        self.put(y + height - 1, x, bl + h * (width - 2) + br, color)

    def _header(self, width: int) -> None:
        if self.ascii:
            self.put(0, 1, "KEN-NET  |  SERVER MANAGEMENT", "text", bold=True)
            domain = str(self.snapshot.get("domain", "—"))
            self.put(0, max(1, width - len(domain) - 3), domain, "blue", bold=True)
            self.put(1, 1, f"{self.snapshot.get('os', 'Linux')}  |  {self.snapshot.get('uptime', '—')}", "dim")
        else:
            self.put(0, 1, "KEN", "text", bold=True)
            self.put(0, 4, "-", "blue", bold=True)
            self.put(0, 5, "NET", "text", bold=True)
            self.put(0, 10, "SERVER MANAGEMENT PANEL", "dim")
            domain = str(self.snapshot.get("domain", "—"))
            self.put(0, max(1, width - len(domain) - 3), domain, "rose", bold=True)
            self.put(1, 1, f"{self.snapshot.get('os', 'Linux')}  ·  {self.snapshot.get('uptime', '—')}", "dim")

    def _metric_line(self, width: int) -> None:
        items = (("LOAD", self.snapshot.get("load")), ("RAM", self.snapshot.get("ram")),
                 ("DISK", self.snapshot.get("disk")), ("ACTIVE SERVICES", self.snapshot.get("active")))
        gap = max(1, (width - 4) // 4)
        x = 1
        for label, value in items:
            shown = "—" if value is None else f"{value}%" if label != "ACTIVE SERVICES" else str(value)
            if label == "ACTIVE SERVICES":
                sample = list(_activity)
                spark = "".join(SPARK[min(7, n * 8 // max(1, max(sample)))] for n in sample) if sample and not self.ascii else ""
                shown = shown + (f"  {spark}" if spark else "")
                color = "amber"
            else:
                pct = int(value or 0)
                color = "error" if pct > 90 else "amber" if pct > 70 else "mint"
                fill = max(0, min(8, pct * 8 // 100))
                bar = ("#" * fill + "." * (8 - fill)) if self.ascii else ("█" * fill + "░" * (8 - fill))
                shown = f"{shown:<4} {bar}"
            self.put(2, x, label, "dim", bold=True)
            self.put(2, x + len(label) + 1, shown, color, bold=True, width=max(12, gap - len(label) - 2))
            x += gap
        self.put(3, 1, ("-" if self.ascii else "─") * max(1, width - 2), "line")

    def _protocol_list(self, top: int, height: int, width: int) -> None:
        self.put(top, 1, "PROTOCOLS", "blue", bold=True)
        self.put(top, 12, "ACCOUNT MANAGEMENT", "dim")
        columns = 2 if width >= 48 else 1
        card_width = max(18, (width - (columns - 1) * 2) // columns)
        card_height = 2
        rows_per_column = (len(PROTOCOL_ORDER) + columns - 1) // columns
        selected_key = PROTOCOL_ORDER[self.selected]
        short_number = {key: f"{index:02}" for index, key in enumerate(LEGACY_ORDER, 1)}
        for index, key in enumerate(PROTOCOL_ORDER):
            row = next(item for item in self.rows if item.key == key)
            column, card_row = divmod(index, rows_per_column)
            x = 1 + column * (card_width + 2)
            y = top + 1 + card_row * card_height
            selected = not self.in_tools and key == selected_key
            self._card(y, x, card_width, row, short_number[key], selected)

        # On a narrow terminal, put the selected card's operational summary in
        # the space below the grid; wide terminals use the full detail pane.
        if width < 100:
            row = next(item for item in self.rows if item.key == selected_key)
            summary_y = top + 1 + rows_per_column * card_height
            self.put(summary_y, 2, f"SELECTED  {row.title}  |  {row.state}  |  {row.count}",
                     row.color, bold=True, width=width - 4)
            self.put(summary_y + 1, 2, row.detail, "dim", width=width - 4)

    def _card(self, y: int, x: int, width: int, row: Row, number: str, selected: bool) -> None:
        if width < 12:
            return
        if self.ascii:
            horizontal, vertical, left, right = "-", "|", "+", "+"
            dot = "*"
        else:
            horizontal, vertical, left, right = "─", "│", "╭", "╮"
            dot = "●"
        border = row.color if selected else "line"
        title = f" {number}  {row.title} "
        top_line = left + horizontal * (width - 2) + right
        self.put(y, x, top_line, border, bold=selected)
        self.put(y, x + 2, title, row.color, bold=True, reverse=selected,
                 width=max(1, width - 4))
        active = row.state in {"Active", "Service active"}
        state = "ACTIVE" if active else "CHECK" if "Partial" in row.state else "OFFLINE"
        count = row.count.replace(" accounts", " acc").replace(" certificates", " cert")
        count = count.replace(" endpoints", " endp").replace(" peers", " peers")
        detail = f"{dot} {state}  {count}"
        self.put(y + 1, x, vertical, border)
        self.put(y + 1, x + 2, detail, "ok" if active else "amber" if state == "CHECK" else "dim",
                 bold=selected, reverse=selected, width=max(1, width - 4))
        self.put(y + 1, x + width - 1, vertical, border)

    def _detail(self, row: Row, y: int, x: int, height: int, width: int) -> None:
        self._box(y, x, height, width, row.title.upper(), row.color)
        inner_y = y + 1
        self.put(inner_y, x + 2, f"{row.group.title()}  ·  option {self.selected + 1:02}", "dim")
        inner_y += 2
        state_color = "ok" if row.state in {"Active", "Service active"} else "amber" if "Partial" in row.state else "error"
        details = (("STATUS", row.state), ("SERVICE", row.engine), ("PORTS", row.ports), ("ACCOUNTS", row.count))
        label_width = min(12, max(7, width // 4))
        for name, value in details:
            if inner_y >= y + height - 6:
                break
            self.put(inner_y, x + 2, name, "dim", bold=True, width=label_width)
            color = state_color if name == "STATUS" else "text"
            self.put(inner_y, x + 3 + label_width, value, color, width=width - label_width - 7)
            inner_y += 1
        inner_y = max(inner_y + 1, y + height - 6)
        line = "-" if self.ascii else "─"
        self.put(inner_y, x + 1, line * (width - 2), "line")
        inner_y += 1
        self.put(inner_y, x + 2, "ACTIONS", row.color, bold=True)
        inner_y += 1
        for text in ("Enter / A  Open protocol manager", "Tab  Settings & tools"):
            if inner_y >= y + height - 1:
                break
            self.put(inner_y, x + 2, text, "text")
            inner_y += 1
        if row.detail and inner_y < y + height - 1:
            self.put(inner_y, x + 2, row.detail, "dim", width=width - 5)

    def _tools(self, y: int, width: int) -> None:
        self.put(y, 1, "SETTINGS & TOOLS", "amber", bold=True)
        columns = 2
        card_width = max(20, (width - 4) // columns)
        for index, (number, label) in enumerate(TOOLS):
            column, row = index % columns, index // columns
            x = 1 + column * (card_width + 2)
            card_y = y + 1 + row
            selected = self.in_tools and index == self.tool_selected
            text = f" [{number}] {label} "
            if self.ascii:
                left, right, line = "+", "+", "-"
            else:
                left, right, line = "╭", "╮", "─"
            self.put(card_y, x, left + text + line * max(0, card_width - len(text) - 2) + right,
                     "amber", bold=selected, reverse=selected, width=card_width)

    def draw(self, force: bool = False) -> None:
        height, width = self.stdscr.getmaxyx()
        if height < 24 or width < 80:
            self.stdscr.erase()
            self.put(0, 1, "Please enlarge the terminal (80x24 minimum)", "amber", bold=True)
            self.stdscr.refresh()
            return
        try:
            self.rows, self.snapshot = collect_rows()
        except Exception as exc:
            self.toast = f"State refresh failed: {exc}"
            self.toast_until = time.monotonic() + 4
        fingerprint = (width, height, self.selected, self.tool_selected, self.in_tools,
                       tuple((row.key, row.state, row.count, row.detail) for row in self.rows),
                       tuple(self.snapshot.items()), self.toast if time.monotonic() < self.toast_until else "")
        if not force and fingerprint == self.last_draw:
            return
        self.last_draw = fingerprint
        self.stdscr.erase()
        self._header(width)
        self._metric_line(width)
        main_top = 4
        tools_y = height - 4
        main_bottom = tools_y - 1
        main_height = max(2, main_bottom - main_top)
        if width >= 100:
            left_width = int(width * 0.54)
            self._protocol_list(main_top, main_height, left_width)
            row = next(item for item in self.rows if item.key == PROTOCOL_ORDER[self.selected])
            self._detail(row, main_top, left_width + 1, main_height, width - left_width - 2)
        else:
            self._protocol_list(main_top, max(2, main_height - 3), width - 1)
            row = next(item for item in self.rows if item.key == PROTOCOL_ORDER[self.selected])
            self.put(main_bottom - 2, 2, f"Selected: {row.title}  |  {row.state}  |  {row.count}", row.color, width=width - 4)
            self.put(main_bottom - 1, 2, row.detail, "dim", width=width - 4)
        self._tools(tools_y, width)
        prompt = f"Select option [0-15]: {self.numeric}{' ' if self.ascii else '▌'}"
        hint = "Up/Down move · Enter open · Esc back"
        hint_x = max(1, width - len(hint) - 2)
        self.put(height - 1, 1, prompt, "mint", bold=True, width=max(16, hint_x - 3))
        self.put(height - 1, hint_x, hint, "dim", width=len(hint))
        if self.toast and time.monotonic() < self.toast_until:
            color = "ok" if self.toast.startswith("OK") else "error"
            self.put(tools_y - 1, 2, self.toast, color, bold=True, width=width - 4)
        self.stdscr.refresh()

    def _confirm_quit(self) -> bool:
        height, width = self.stdscr.getmaxyx()
        message = "Quit KEN-NET?  y / N"
        self.put(height - 1, max(1, (width - len(message)) // 2), message, "amber", bold=True)
        self.stdscr.refresh()
        key = self.stdscr.get_wch()
        return key in {"y", "Y"}

    def _open_backend(self, key: str | None = None) -> None:
        import panel
        try:
            self.stdscr.clear()
            curses.curs_set(1)
            curses.echo()
            curses.nocbreak()
            curses.endwin()
            if key is None:
                import settings_manager
                settings_manager.menu()
            elif key == "14":
                panel.show_status()
                input("\nPress Enter to return...")
            elif key == "15":
                import service_catalog
                service_catalog.show()
                input("\nPress Enter to return...")
            elif key == "13":
                import settings_manager
                settings_manager.menu()
            elif key == "0":
                raise SystemExit(0)
            else:
                protocol_key = key if key in PROTOCOL_META else _legacy_protocol_key(int(key))
                protocol = next(item for item in panel.PROTOCOLS if item.key == protocol_key)
                panel.manage_protocol(protocol)
                input("\nPress Enter to return to the dashboard...")
            self.toast = "OK  Returned to dashboard"
        except KeyboardInterrupt:
            self.toast = "OK  Returned to dashboard"
        except SystemExit:
            raise
        except Exception as exc:
            self.toast = f"ERROR  {exc}"
        finally:
            try:
                curses.reset_prog_mode()
                self.stdscr.keypad(True)
                curses.noecho()
                curses.cbreak()
                curses.curs_set(0)
                self.stdscr.clearok(True)
                self.stdscr.refresh()
                self.stdscr.timeout(2000)
            except curses.error:
                pass
        self.toast_until = time.monotonic() + 4
        self.last_draw = None

    def _open_selected(self) -> bool:
        if self.in_tools:
            number = TOOLS[self.tool_selected][0]
            if number == "0":
                return self._confirm_quit()
            self._open_backend(number)
        else:
            self._open_backend(PROTOCOL_ORDER[self.selected])
        return False

    def _number_action(self) -> bool:
        if not self.numeric:
            return False
        raw = self.numeric
        self.numeric = ""
        if raw in {"0", "00"}:
            self.in_tools = True
            self.tool_selected = 3
            return self._open_selected()
        try:
            value = int(raw)
        except ValueError:
            return False
        if 1 <= value <= 12:
            protocol_key = _legacy_protocol_key(value)
            self.selected = PROTOCOL_ORDER.index(protocol_key)
            self.in_tools = False
            self._open_backend(protocol_key)
            return False
        if value in {13, 14, 15}:
            self.in_tools = True
            self.tool_selected = value - 13
            return self._open_selected()
        self.toast = f"ERROR  Option {raw} is outside 0-15"
        self.toast_until = time.monotonic() + 3
        return False

    def run(self) -> int:
        self.draw(force=True)
        while True:
            try:
                key = self.stdscr.get_wch()
            except curses.error:
                self.draw()
                continue
            if key == curses.KEY_RESIZE:
                self.stdscr.clearok(True)
                self.last_draw = None
            elif key in {curses.KEY_UP, "k"}:
                if self.in_tools:
                    self.in_tools = False
                else:
                    self.selected = (self.selected - 1) % len(PROTOCOL_ORDER)
                self.last_draw = None
            elif key in {curses.KEY_DOWN, "j"}:
                if self.in_tools:
                    self.in_tools = False
                else:
                    self.selected = (self.selected + 1) % len(PROTOCOL_ORDER)
                self.last_draw = None
            elif key == curses.KEY_HOME:
                self.selected, self.in_tools = 0, False
                self.last_draw = None
            elif key == curses.KEY_END:
                self.selected, self.in_tools = len(PROTOCOL_ORDER) - 1, False
                self.last_draw = None
            elif key in {"\t", curses.KEY_BTAB}:
                self.in_tools = not self.in_tools
                self.last_draw = None
            elif self.in_tools and key in {curses.KEY_LEFT, curses.KEY_RIGHT}:
                direction = -1 if key == curses.KEY_LEFT else 1
                self.tool_selected = (self.tool_selected + direction) % len(TOOLS)
                self.last_draw = None
            elif key in {"\n", "\r", curses.KEY_ENTER}:
                if self.numeric:
                    if self._number_action():
                        return 0
                elif self._open_selected():
                    return 0
                self.last_draw = None
            elif key in {"\x1b", "\x08", "\x7f", curses.KEY_BACKSPACE}:
                if self.numeric:
                    self.numeric = self.numeric[:-1]
                elif self.in_tools:
                    self.in_tools = False
                self.last_draw = None
            elif key in {"q", "Q"}:
                if self._confirm_quit():
                    return 0
                self.last_draw = None
            elif key in {"a", "A"} and not self.in_tools:
                self._open_backend(PROTOCOL_ORDER[self.selected])
            elif isinstance(key, str) and key.isdigit() and len(self.numeric) < 2:
                self.numeric += key
                self.last_draw = None
            self.draw()


def _plain_dashboard() -> int:
    """Safe no-curses fallback for TERM=dumb and non-interactive diagnostics."""
    import panel
    while True:
        rows, _snapshot = collect_rows()
        if os.isatty(1) and os.environ.get("TERM") != "dumb":
            import terminal_ui
            terminal_ui.clear_screen()
        print("\nKEN-NET | SERVER MANAGEMENT PANEL")
        print("=" * 36)
        for group, _color, keys in GROUPS:
            print(f"\n{group}")
            for key in keys:
                row = next(item for item in rows if item.key == key)
                number = LEGACY_ORDER.index(key) + 1
                print(f" [{number:02}] {row.title:<16} {row.state:<18} {row.count}")
        for number, name in TOOLS:
            print(f" [{number:>2}] {name}")
        try:
            choice = input("Select option [0-15]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        if choice == "0":
            return 0
        if choice in {"13", "14", "15"}:
            _dispatch_backend(choice)
            continue
        if choice.isdigit() and 1 <= int(choice) <= 12:
            _dispatch_backend(choice)
        else:
            print("Invalid selection.")


def _dispatch_backend(key: str) -> None:
    """Call the existing manager, status, or tools screen without changing its logic."""
    import panel
    if key == "13":
        import settings_manager
        settings_manager.menu()
    elif key == "14":
        panel.show_status()
        input("\nPress Enter to return...")
    elif key == "15":
        import service_catalog
        service_catalog.show()
        input("\nPress Enter to return...")
    elif key == "0":
        raise SystemExit(0)
    else:
        protocol_key = LEGACY_ORDER[int(key) - 1]
        protocol = next(item for item in panel.PROTOCOLS if item.key == protocol_key)
        panel.manage_protocol(protocol)
        input("\nPress Enter to return to the dashboard...")


def run(force_plain: bool = False) -> int:
    """Run the full-screen TUI, falling back to plain navigation when necessary."""
    if curses is None or os.environ.get("TERM") == "dumb" or not (os.isatty(0) and os.isatty(1)):
        return _plain_dashboard()
    try:
        return curses.wrapper(lambda screen: Dashboard(screen, force_plain).run())
    except curses.error as exc:
        print(f"Terminal UI unavailable ({exc}); starting the plain menu.")
        return _plain_dashboard()
