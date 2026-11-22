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
import ipaddress
import secrets
import getpass
import json
import socket
import threading
import urllib.error
import urllib.request
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
VERSION_FILE = Path(__file__).with_name("VERSION")


def _release_version() -> str:
    try:
        value = VERSION_FILE.read_text(encoding="utf-8").strip()
        return value if value else "dev"
    except OSError:
        return "dev"


RGB = {
    "ink": (10, 15, 28), "line": (38, 50, 76), "text": (207, 216, 234),
    "dim": (104, 119, 154), "blue": (92, 184, 255), "violet": (180, 156, 255),
    "mint": (79, 227, 176), "amber": (255, 180, 84), "rose": (255, 122, 156),
    "ok": (79, 227, 176), "off": (74, 86, 117), "error": (255, 107, 107),
    # Restrained translucent-style fills: dark enough to keep text readable.
    "fill_red": (63, 39, 55), "fill_yellow": (65, 52, 32),
    "fill_blue": (30, 48, 70), "fill_green": (28, 55, 49),
    "fill_selected": (41, 70, 100),
    "fill_banner": (231, 158, 48), "fill_header": (31, 48, 70),
    "fill_brand": (15, 150, 156),
}
CARD_FILLS = ("fill_blue", "fill_blue", "fill_blue", "fill_blue")
SPARK = "▁▂▃▄▅▆▇█"
_activity = deque(maxlen=10)
SERVER_GEO_CACHE_FILE = Path("/var/cache/kennet-panel/server-geolocation.json")
SERVER_GEO_CACHE_TTL = 6 * 60 * 60
_server_geo_lock = threading.Lock()
_server_geo_cache: tuple[float, dict[str, str]] | None = None
_server_geo_refreshing = False
_server_geo_retry_at = 0.0


def _main_grid_layout(height: int, width: int) -> dict[str, int | bool]:
    """Fit the protocol grid and tool cards to the terminal without overlap."""
    detailed = height >= 44 and width >= 90
    summary_width = min(62, max(44, (width - 4) // 2)) if detailed else width - 2
    grid_top = 16 if detailed else 10
    columns = 2 if width >= 72 else 1
    rows_per_column = (len(PROTOCOL_ORDER) + columns - 1) // columns
    footer_y = height - 3
    card_height = max(1, min(6, (footer_y - grid_top - 5) // rows_per_column))
    grid_bottom = grid_top + 1 + rows_per_column * card_height
    return {"detailed": detailed, "summary_width": summary_width,
            "grid_top": grid_top, "rows_per_column": rows_per_column,
            "footer_y": footer_y, "card_height": card_height, "grid_bottom": grid_bottom,
            "tools_y": grid_bottom + 1}


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

    online: dict[str, int | None] = {key: None for key in PROTOCOL_ORDER}
    if services_manager is not None:
        services_manager.refresh_xray_online_ip_counts_async()
        for key in ("ssh", "vmess", "vless", "trojan"):
            try:
                if key == "ssh":
                    online[key] = sum(services_manager.ssh_session_counts().values())
                else:
                    per_account = services_manager.cached_xray_online_ip_counts(key)
                    online[key] = sum(per_account.values()) if per_account is not None else None
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                online[key] = None
    try:
        server_card = _server_info_card(domain)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        server_card = {"expiration": "Provider account required", "isp": "Unavailable",
                       "city": "Unavailable", "ip": "Unavailable", "nameserver": "Not set",
                       "owner": "Not exposed locally"}

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
    return rows, {"domain": domain, "accounts": accounts, "counts": counts, "online": online,
                  "server_info": server_card,
                  "load": _load_percent(), "ram": _ram_percent(), "disk": _disk_percent(),
                  "uptime": _uptime(), "os": _ubuntu_release(), "active": active_services}


def _server_info_card(domain: str) -> dict[str, str]:
    """Collect local host facts and enrich the public IP in a cached background lookup."""
    result = {"expiration": "Provider account required", "isp": "Unavailable",
              "city": "Unavailable", "ip": "Unavailable", "nameserver": "Not set",
              "owner": "Not exposed locally"}
    try:
        import services_manager
        state = services_manager.state()
        metadata = state.get("server_info", {}) if isinstance(state, dict) else {}
        if isinstance(metadata, dict):
            result["expiration"] = str(metadata.get("expiration") or result["expiration"])
            result["owner"] = str(metadata.get("owner") or result["owner"])
    except (ImportError, OSError, ValueError, RuntimeError):
        pass
    try:
        import dnstt_manager
        cfg = dnstt_manager._read_json(dnstt_manager.CONFIG, {})
        result["nameserver"] = str(cfg.get("nameserver_host") or result["nameserver"])
    except (ImportError, AttributeError, OSError, ValueError, RuntimeError):
        pass

    local_ip = _local_public_ip()
    geo, lookup_state = _server_geolocation()
    result["ip"] = geo.get("ip") or local_ip or ("Detecting…" if lookup_state == "loading" else "Unavailable")
    result["isp"] = geo.get("isp") or _server_provider() or ("Detecting…" if lookup_state == "loading" else "Unavailable")
    result["city"] = geo.get("city") or ("Detecting…" if lookup_state == "loading" else "Unavailable")
    return result


def _parse_server_geolocation(payload: object) -> dict[str, str]:
    """Validate the small public-IP lookup response before caching its display fields."""
    if not isinstance(payload, dict) or payload.get("success") is not True:
        return {}
    try:
        address = ipaddress.ip_address(str(payload.get("ip", "")).strip())
    except ValueError:
        return {}
    if not address.is_global:
        return {}
    connection = payload.get("connection")
    connection = connection if isinstance(connection, dict) else {}
    city = str(payload.get("city") or "").strip()
    isp = str(connection.get("isp") or connection.get("org") or "").strip()
    return {"ip": address.compressed, "city": city[:80], "isp": isp[:100]}


def _server_geolocation() -> tuple[dict[str, str], str]:
    """Return cached public-IP facts immediately and refresh them off the UI thread."""
    global _server_geo_cache, _server_geo_refreshing, _server_geo_retry_at
    now = time.time()
    monotonic_now = time.monotonic()
    with _server_geo_lock:
        if _server_geo_cache is None:
            try:
                cached = json.loads(SERVER_GEO_CACHE_FILE.read_text(encoding="utf-8"))
                parsed = _parse_server_geolocation({
                    "success": True, "ip": cached.get("ip"), "city": cached.get("city"),
                    "connection": {"isp": cached.get("isp")},
                })
                fetched = float(cached.get("fetched_at", 0))
                if parsed and fetched > 0:
                    _server_geo_cache = (fetched, parsed)
            except (OSError, ValueError, TypeError, AttributeError):
                pass

        if (not _server_geo_refreshing and monotonic_now >= _server_geo_retry_at and
                (_server_geo_cache is None or now - _server_geo_cache[0] >= SERVER_GEO_CACHE_TTL)):
            _server_geo_refreshing = True
            thread = threading.Thread(target=_refresh_server_geolocation, name="kennet-server-geo", daemon=True)
            thread.start()

        if _server_geo_cache is not None:
            return dict(_server_geo_cache[1]), "ready"
        return {}, "loading" if _server_geo_refreshing else "unavailable"


def _refresh_server_geolocation() -> None:
    """Fetch public IP/ISP/city once per cache interval without blocking curses."""
    global _server_geo_cache, _server_geo_refreshing, _server_geo_retry_at
    try:
        request = urllib.request.Request(
            "https://ipwho.is/",
            headers={"Accept": "application/json", "User-Agent": "KEN-NET server dashboard"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = json.loads(response.read(65536).decode("utf-8"))
        facts = _parse_server_geolocation(payload)
        if not facts:
            raise ValueError("Public IP lookup returned no usable server details")
        fetched = time.time()
        with _server_geo_lock:
            _server_geo_cache = (fetched, facts)
            _server_geo_retry_at = time.monotonic() + SERVER_GEO_CACHE_TTL
        try:
            SERVER_GEO_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            temporary = SERVER_GEO_CACHE_FILE.with_name(SERVER_GEO_CACHE_FILE.name + ".tmp")
            temporary.write_text(json.dumps({"fetched_at": fetched, **facts}), encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, SERVER_GEO_CACHE_FILE)
        except OSError:
            pass
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        with _server_geo_lock:
            _server_geo_retry_at = time.monotonic() + 15 * 60
    finally:
        with _server_geo_lock:
            _server_geo_refreshing = False


def _local_public_ip() -> str:
    """Find a globally routable source address without making a network request."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(0.5)
            probe.connect(("1.1.1.1", 53))
            address = ipaddress.ip_address(probe.getsockname()[0])
            if address.is_global:
                return address.compressed
    except (OSError, ValueError, IndexError):
        pass
    try:
        route = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True,
                               text=True, timeout=0.75, check=False).stdout.split()
        if "src" in route:
            address = ipaddress.ip_address(route[route.index("src") + 1])
            if address.is_global:
                return address.compressed
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        pass
    return ""


def _server_provider() -> str:
    """Use a provider name exposed by the VM's DMI data when available."""
    for path in (Path("/sys/class/dmi/id/sys_vendor"), Path("/sys/class/dmi/id/board_vendor"),
                 Path("/sys/class/dmi/id/product_name")):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        normalized = value.casefold()
        for marker, provider in (("ovh", "OVH SAS"), ("hetzner", "Hetzner"),
                                 ("digitalocean", "DigitalOcean"), ("amazon", "Amazon Web Services"),
                                 ("google", "Google Cloud"), ("microsoft", "Microsoft Azure"),
                                 ("vultr", "Vultr"), ("linode", "Akamai / Linode"), ("oracle", "Oracle Cloud")):
            if marker in normalized:
                return provider
    return ""


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
        self.protocol_view_key: str | None = None
        self.protocol_tab = 0
        self.protocol_subview = "main"
        self.account_index = 0
        self.account_scroll = 0
        self.account_name: str | None = None
        self.account_action_index = 0
        self.service_action_index = 0
        self.protocol_numeric = ""
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
                        "fill_red": curses.COLOR_BLACK, "fill_yellow": curses.COLOR_BLACK,
                        "fill_blue": curses.COLOR_BLACK, "fill_green": curses.COLOR_BLACK,
                        "fill_selected": curses.COLOR_BLUE,
                        "fill_banner": curses.COLOR_YELLOW, "fill_header": curses.COLOR_BLUE,
                        "fill_brand": curses.COLOR_CYAN,
                    }.get(name, curses.COLOR_WHITE)
                    if idx < curses.COLOR_PAIRS:
                        if name.startswith("fill_"):
                            foreground = (curses.COLOR_BLACK if name in {"fill_banner", "fill_brand"} else
                                          _xterm_index(RGB["text"]) if curses.COLORS >= 256 else curses.COLOR_WHITE)
                            background = color
                        else:
                            foreground, background = color, -1
                        curses.init_pair(idx, foreground, background)
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
        title = "KEN-NET  •  SERVER MANAGEMENT PANEL"
        bar_x, bar_width = 1, width - 2
        self.put(0, bar_x, " " * bar_width, "fill_brand", width=bar_width)
        ubuntu = "[●] UBUNTU" if self.ascii else "◉ UBUNTU"
        self.put(0, 2, ubuntu, "fill_brand", bold=True, width=14)
        version = f"v{_release_version()}"
        version_x = max(2, width - len(version) - 3)
        title_x = max(16, (width - len(title)) // 2)
        self.put(0, title_x, title, "fill_brand", bold=True,
                 width=max(8, version_x - title_x - 2))
        self.put(0, version_x, version, "fill_brand", bold=True, width=len(version))
        # Use the second row as a subtitle so the title reads as a deliberate
        # brand card instead of a thin terminal label.
        self.put(1, bar_x, " " * bar_width, "fill_brand", width=bar_width)
        subtitle = "LIVE SERVER CONTROL  •  HOST STATUS & NETWORK SERVICES"
        self.put(1, max(2, (width - len(subtitle)) // 2), subtitle,
                 "fill_brand", bold=True, width=width - 4)

    def _server_details(self, y: int, width: int, summary_width: int = 62) -> None:
        """Show the requested host/account inventory without fabricated values."""
        x = summary_width + 3
        pane_width = width - x - 1
        if pane_width < 28:
            return
        self._box(y, x, 12, pane_width, "SERVER INFORMATION", "mint")
        info = self.snapshot.get("server_info", {})
        details = (
            ("SYS OS", self.snapshot.get("os", "Not configured")),
            ("EXPIRATION", info.get("expiration", "Provider account required")),
            ("RAM", f"{self.snapshot.get('ram', '—')}%"),
            ("UP", self.snapshot.get("uptime", "Not configured")),
            ("ISP", info.get("isp", "Unavailable")),
            ("CITY", info.get("city", "Unavailable")),
            ("IP", info.get("ip", "Unavailable")),
            ("DOMAIN", self.snapshot.get("domain", "—")),
            ("NS", info.get("nameserver", "Not set")),
            ("OWNER", info.get("owner", "Not exposed locally")),
        )
        if pane_width >= 80:
            column_width = (pane_width - 4) // 2
            for index, (label, value) in enumerate(details):
                column, item = divmod(index, 5)
                item_x = x + 2 + column * (column_width + 1)
                item_y = y + 1 + item * 2
                self.put(item_y, item_x, label, "dim", bold=True, width=column_width - 2)
                self.put(item_y + 1, item_x, str(value), "text", bold=True, width=column_width - 2)
        else:
            value_width = max(8, pane_width - 18)
            for line, (label, value) in enumerate(details, 1):
                self.put(y + line, x + 2, label, "dim", bold=True, width=14)
                self.put(y + line, x + 17, str(value), "text", bold=True, width=value_width)

    def _metric_line(self, width: int) -> None:
        items = (("LOAD", self.snapshot.get("load")), ("RAM", self.snapshot.get("ram")),
                 ("DISK", self.snapshot.get("disk")), ("UPTIME", self.snapshot.get("uptime")))
        gap = max(1, (width - 4) // 4)
        for index, (label, value) in enumerate(items):
            x = 1 + index * gap
            if label == "LOAD":
                shown = "—" if value is None else f"{value:.2f}"
                color = "mint"
            elif label == "UPTIME":
                shown = str(value or "—").removeprefix("up ")
                color = "blue"
            else:
                shown = "—" if value is None else f"{value}%"
                color = "error" if int(value or 0) > 90 else "amber" if int(value or 0) > 70 else "mint"
            self.put(2, x, label, "dim", bold=True)
            self.put(2, x + len(label) + 1, shown, color, bold=True,
                     width=max(8, gap - len(label) - 2))

    def _summary(self, y: int, width: int, *, detailed: bool = False,
                 box_width: int | None = None) -> None:
        if detailed:
            box_width = min(width - 2, box_width or 62)
            self._box(y, 1, 12, box_width, "SERVER & ACCOUNT STATUS", "blue")
            self.put(y + 1, 3, "DOMAIN", "dim", bold=True)
            self.put(y + 1, 11, self.snapshot.get("domain", "—"), "text", bold=True,
                     width=box_width - 13)
            self.put(y + 2, 2, ("-" if self.ascii else "─") * (box_width - 2), "line")
            inner_width = box_width - 4
            if box_width < 56:
                column_widths = (9, 8, 9, inner_width - 9 - 8 - 9 - 3)
                headers = ("PROTOCOL", "ACTIVE", "TOTAL ACC", "ONLINE")
            else:
                column_widths = (13, 10, 15, inner_width - 13 - 10 - 15 - 3)
                headers = ("PROTOCOL", "ACTIVE", "TOTAL ACCOUNTS", "CONNECTIONS")
            column_x = [3]
            for column_width in column_widths[:-1]:
                column_x.append(column_x[-1] + column_width + 1)
            for x, label, column_width in zip(column_x, headers, column_widths):
                self.put(y + 3, x, label, "blue", bold=True, width=column_width)
            self.put(y + 4, 2, ("-" if self.ascii else "─") * (box_width - 2), "line")
            summary_keys = ("ssh", "vmess", "vless", "trojan", "wireguard", "dnstt")
            by_key = {row.key: row for row in self.rows}
            for line, key in enumerate(summary_keys):
                row = by_key.get(key)
                if row is None:
                    continue
                active = row.state in {"Active", "Service active"}
                state = "ACTIVE" if active else "CHECK" if "Partial" in row.state else "OFFLINE"
                status_color = "ok" if active else "amber" if state == "CHECK" else "dim"
                noun = "peers" if key == "wireguard" else "services" if key == "dnstt" else "acc"
                count = str(self.snapshot.get("counts", {}).get(key, "—"))
                connected = self.snapshot.get("online", {}).get(key)
                connection_text = "—" if connected is None else f"{connected} online"
                row_y = y + 5 + line
                self.put(row_y, column_x[0], row.title.upper(), "text", bold=True,
                         width=column_widths[0])
                self.put(row_y, column_x[1], state, status_color, bold=True,
                         width=column_widths[1])
                self.put(row_y, column_x[2], f"{count} {noun}", "text",
                         width=column_widths[2])
                self.put(row_y, column_x[3], connection_text, "mint" if connected else "dim",
                         width=column_widths[3])
            return

        self._box(y, 1, 6, width - 2, "SERVER & ACCOUNT STATUS", "blue")
        self.put(y + 1, 3, "DOMAIN", "dim", bold=True)
        self.put(y + 1, 11, self.snapshot.get("domain", "—"), "text", bold=True,
                 width=max(12, width - 15))
        summary_keys = ("ssh", "vmess", "vless", "trojan", "wireguard", "dnstt")
        by_key = {row.key: row for row in self.rows}
        half = max(20, (width - 6) // 2)
        for index, key in enumerate(summary_keys):
            column, line = index % 2, index // 2
            row = by_key.get(key)
            if row is None:
                continue
            x = 3 + column * half
            active = row.state in {"Active", "Service active"}
            state = "UP" if active else "CHK" if "Partial" in row.state else "OFF"
            color = "ok" if active else "amber" if state == "CHK" else "dim"
            noun = "peer" if key == "wireguard" else "svc" if key == "dnstt" else "acc"
            count = str(self.snapshot.get("counts", {}).get(key, "—"))
            connected = self.snapshot.get("online", {}).get(key)
            connection_text = "—" if connected is None else f"{connected} online"
            self.put(y + 2 + line, x, "●" if not self.ascii else "*", color, bold=True)
            status = f"{row.title.upper()}  {count} {noun} · {connection_text}"
            self.put(y + 2 + line, x + 2, status, color, bold=True, width=half - 2)

    def _protocol_grid(self, top: int, width: int, *, compact: bool) -> None:
        section = "◈  PROTOCOLS  •  ACCOUNT MANAGEMENT  ◈" if not self.ascii else "== PROTOCOLS / ACCOUNT MANAGEMENT =="
        self.put(top, max(2, (width - len(section)) // 2), section, "blue", bold=True)
        card_columns = 2 if width >= 72 else 1
        gap = 2 if card_columns == 2 else 0
        card_width = max(18, (width - 2 - gap) // card_columns)
        card_height = getattr(self, "protocol_card_height", 1 if getattr(self, "single_line_cards", False) else 2 if compact else 3)
        icons = {"ssh": ">_", "vmess": "<>" , "vless": "<>" , "trojan": "<>" ,
                 "shadowsocks": "~", "dropbear": "*", "openvpn": "O", "udp": "#",
                 "wireguard": "W", "slowdns": "~", "dnstt": "@", "tls": "*"}
        short_number = {key: f"{index:02}" for index, key in enumerate(LEGACY_ORDER, 1)}
        by_key = {row.key: row for row in self.rows}
        # Keep the visual order identical to the public numeric menu. Grouped
        # service order is still used by the collectors and status model.
        for index, key in enumerate(LEGACY_ORDER):
            row = by_key.get(key)
            if row is None:
                continue
            line, column = divmod(index, card_columns)
            x = 1 + column * (card_width + gap)
            y = top + 1 + line * card_height
            selected = not self.in_tools and index == self.selected
            active = row.state in {"Active", "Service active"}
            state = "ACTIVE" if active else "CHECK" if "Partial" in row.state else "OFFLINE"
            count = row.count.replace(" accounts", " acc").replace(" endpoints", " endp")
            icon = icons.get(key, "*")
            border = ("violet" if selected else "blue") if compact else (row.color if selected else "blue")
            left, right, vertical, horizontal = ("+", "+", "|", "-") if self.ascii else ("╭", "╮", "│", "─")
            bottom_left, bottom_right = ("+", "+") if self.ascii else ("╰", "╯")
            title = f" [{short_number[key]}] {row.title}  {icon} "
            if card_height == 1:
                inside = title[:max(0, card_width - 2)].ljust(card_width - 2)
                self.put(y, x, left + inside + right, border, bold=selected, width=card_width)
                self.put(y, x + 2, title, row.color, bold=True, width=card_width - 4)
                continue

            self.put(y, x, left + horizontal * (card_width - 2) + right, border, bold=selected)
            self.put(y, x + 2, title, row.color, bold=True, width=card_width - 4)
            status_color = "ok" if active else "amber" if state == "CHECK" else "dim"
            status = f"{'●' if not self.ascii else '*'}  {state}   {count}"
            for inner_row in range(1, card_height - 1):
                self.put(y + inner_row, x, vertical, border)
                self.put(y + inner_row, x + card_width - 1, vertical, border)
            self.put(y + 1, x + 2, status, status_color, bold=True, width=card_width - 4)
            if card_height >= 4:
                online = self.snapshot.get("online", {}).get(key)
                online_label = "ONLINE  —" if online is None else f"ONLINE  {online}"
                self.put(y + 2, x + 2, online_label, "mint" if online else "dim",
                         bold=True, width=card_width - 4)
            if card_height >= 5:
                ports = row.ports if row.ports and row.ports != "—" else "No public listener detected"
                self.put(y + 3, x + 2, f"PORTS  {ports}", "dim", width=card_width - 4)
            if card_height >= 6:
                self.put(y + 4, x + 2, f"ENGINE  {row.engine}", "dim", width=card_width - 4)
            if card_height >= 3:
                self.put(y + card_height - 1, x,
                         bottom_left + horizontal * (card_width - 2) + bottom_right,
                         border, bold=selected)

    def _protocol_list(self, top: int, height: int, width: int) -> None:
        self.put(top, 1, "PROTOCOLS", "blue", bold=True)
        self.put(top, 12, "ACCOUNT MANAGEMENT", "dim")
        columns = 2 if width >= 48 else 1
        card_width = max(18, (width - (columns - 1) * 2) // columns)
        card_height = 3
        rows_per_column = (len(LEGACY_ORDER) + columns - 1) // columns
        selected_key = LEGACY_ORDER[self.selected]
        short_number = {key: f"{index:02}" for index, key in enumerate(LEGACY_ORDER, 1)}
        for index, key in enumerate(LEGACY_ORDER):
            row = next(item for item in self.rows if item.key == key)
            card_row, column = divmod(index, columns)
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
        # Keep card outlines consistent; selected cards receive a brighter
        # accent while category color remains visible in the card title.
        border = "violet" if selected else "blue"
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
        self.put(y + 2, x, left + horizontal * (width - 2) + right, border,
                 bold=selected)

    def _detail(self, row: Row, y: int, x: int, height: int, width: int) -> None:
        self._box(y, x, height, width, row.title.upper(), row.color)
        inner_y = y + 1
        option_number = LEGACY_ORDER.index(row.key) + 1
        self.put(inner_y, x + 2, f"{row.group.title()}  ·  option {option_number:02}", "dim")
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
        for text in ("Enter  Open protocol screen", "A  Open account manager", "Tab  Settings & tools"):
            if inner_y >= y + height - 1:
                break
            self.put(inner_y, x + 2, text, "text")
            inner_y += 1
        if row.detail and inner_y < y + height - 1:
            self.put(inner_y, x + 2, row.detail, "dim", width=width - 5)

    def _protocol_accounts(self, key: str) -> list[dict[str, object]] | None:
        """Read account rows from existing backend providers; never synthesize records."""
        try:
            import services_manager
            if key in {"ssh", "dropbear"}:
                names = services_manager.selectable_account_names("ssh")
                connections = services_manager.active_connections("ssh")
                return services_manager.account_roster_rows("ssh", names, connections=connections)
            if key == "udp":
                names = services_manager.udp_list()
                return services_manager.account_roster_rows("udp", names)
            if key in {"vmess", "vless", "trojan", "shadowsocks"}:
                names = services_manager.selectable_account_names(key)
                services_manager.refresh_xray_online_ip_counts_async()
                connections = services_manager.cached_xray_online_ip_counts(key)
                return services_manager.account_roster_rows(
                    key, names, connections=connections, connection_unit="IP")
            def expiry(record: dict) -> str:
                try:
                    import terminal_ui
                    return terminal_ui.expiry_status(record.get("expires_at"))
                except (ImportError, TypeError, ValueError):
                    return "—"

            if key == "wireguard":
                import wireguard_manager
                peers = wireguard_manager.list_peers()
                rows = []
                for name, record in sorted(peers.items(), key=lambda item: item[0].casefold()):
                    rows.append({"name": name, "connection": "—", "status": expiry(record),
                                 "expires": record.get("expires_at", "unknown"), "details": "WireGuard peer"})
                return rows
            if key in {"dnstt", "slowdns"}:
                import dnstt_manager
                rows = []
                for name, record in sorted(dnstt_manager.list_accounts().items(), key=lambda item: item[0].casefold()):
                    rows.append({"name": name, "connection": "SERVICE", "status": expiry(record),
                                 "expires": record.get("expires_at", "unknown"), "details": "DNSTT endpoint"})
                return rows
            if key == "openvpn":
                import openvpn_manager
                accounts = openvpn_manager._account_state().get("accounts", {})
                return [{"name": name, "connection": "—", "status": expiry(record),
                         "expires": record.get("expires_at", "unknown"), "details": "OpenVPN certificate"}
                        for name, record in sorted(accounts.items(), key=lambda item: item[0].casefold())
                        if record.get("protocol") == "openvpn"]
        except (ImportError, OSError, ValueError, RuntimeError, KeyError, TypeError):
            return None
        return None

    def _draw_protocol_screen(self, width: int, height: int) -> None:
        key = self.protocol_view_key
        row = next(item for item in self.rows if item.key == key)
        number = LEGACY_ORDER.index(key) + 1
        tabs = (("1", "Accounts"), ("2", "Create"), ("3", "Trial"), ("4", "Service"))
        self.stdscr.erase()
        self._header(width)
        self._metric_line(width)
        self._box(4, 1, height - 8, width - 2, f"{row.title.upper()}  /  OPTION {number:02}", row.color)
        self.put(5, 3, f"{row.group}   •   {row.engine}   •   {row.ports}", "dim", width=width - 6)
        card_width = max(14, (width - 8) // 4)
        for index, (digit, label) in enumerate(tabs):
            x = 3 + index * (card_width + 1)
            selected = index == self.protocol_tab and self.protocol_subview == "main"
            self._box(6, x, 3, card_width, f"[{digit}] {label.upper()}",
                      row.color if selected else "line")
            if selected:
                self.put(7, x + 1, "ACTIVE VIEW", row.color, bold=True, reverse=True,
                         width=card_width - 2)
        body_top = 10
        body_bottom = height - 5
        accounts = self._protocol_accounts(key) if self.protocol_tab == 0 or self.protocol_subview == "account" else []
        if self.protocol_subview == "account":
            self._draw_account_actions(row, width, body_top, body_bottom, accounts or [])
        elif self.protocol_tab == 0:
            self._draw_account_list(row, width, body_top, body_bottom, accounts)
        elif self.protocol_tab in {1, 2}:
            action = "CREATE ACCOUNT" if self.protocol_tab == 1 else "CREATE TRIAL ACCOUNT"
            self._box(body_top, 3, min(8, body_bottom - body_top), width - 6, action, row.color)
            self.put(body_top + 2, 6, f"[{2 if self.protocol_tab == 1 else 3}] Start {action.lower()}", row.color, bold=True)
            self.put(body_top + 4, 6, "The workflow runs directly here; the legacy protocol menu is not opened.", "dim", width=width - 12)
            self.put(body_top + 5, 6, "Trial duration: choose from 1 minute to 24 hours.", "amber", width=width - 12) if self.protocol_tab == 2 else None
            self.put(body_top + 6, 6, "Press the matching number or Enter to continue.", "mint", width=width - 12)
        else:
            self._draw_service_panel(row, width, body_top, body_bottom)
        help_text = ("←/→ tabs  ·  Enter open  ·  1-4 direct select  ·  0 dashboard" if self.protocol_subview == "main"
                     else "↑/↓ select account  ·  Enter actions  ·  number direct select  ·  0 menu" if self.protocol_subview == "accounts"
                     else "↑/↓←/→ choose action  ·  Enter open  ·  1-4 direct select  ·  0 accounts" if self.protocol_subview == "account"
                     else "↑/↓←/→ choose  ·  Enter run  ·  1-3 direct select  ·  0 menu")
        self.put(height - 2, 2, help_text, "dim", width=width - 4)
        prompt = f"Select option: {self.protocol_numeric}{' ' if self.ascii else '▌'}"
        hint = "Enter select · Esc back"
        hint_x = max(1, width - len(hint) - 2)
        self.put(height - 1, 2, prompt, "mint", bold=True, width=max(16, hint_x - 4))
        self.put(height - 1, hint_x, hint, "dim", width=len(hint))
        self.stdscr.refresh()

    def _draw_account_list(self, row: Row, width: int, top: int, bottom: int,
                           accounts: list[dict[str, object]] | None) -> None:
        box_height = max(6, bottom - top)
        self._box(top, 3, box_height, width - 6, f"{row.title.upper()}  /  ACCOUNTS", row.color)
        name_x = 11
        connection_x = max(31, width * 45 // 100)
        status_x = max(connection_x + 13, width * 63 // 100)
        expiry_x = max(status_x + 11, width * 79 // 100)
        self.put(top + 1, 5, "NO.", "dim", bold=True, width=5)
        self.put(top + 1, name_x, "ACCOUNT", "blue", bold=True,
                 width=max(12, connection_x - name_x - 2))
        self.put(top + 1, connection_x, "CONNECTION", "blue", bold=True,
                 width=max(10, status_x - connection_x - 2))
        self.put(top + 1, status_x, "STATUS", "blue", bold=True,
                 width=max(8, expiry_x - status_x - 2))
        self.put(top + 1, expiry_x, "VALID UNTIL", "blue", bold=True,
                 width=max(10, width - expiry_x - 7))
        self.put(top + 2, 4, "─" * (width - 8), "line")
        if accounts is None:
            self.put(top + 4, 6, "Account data is unavailable from the protocol manager.", "amber")
            return
        if not accounts:
            self.put(top + 4, 6, f"No {row.title} accounts are registered.", "dim")
            self.put(top + 5, 6, "Press 2 to create an account or 3 to create a trial.", "mint")
            return
        max_rows = max(1, box_height - 4)
        self.account_scroll = min(self.account_scroll, max(0, len(accounts) - max_rows))
        if self.account_index < self.account_scroll:
            self.account_scroll = self.account_index
        elif self.account_index >= self.account_scroll + max_rows:
            self.account_scroll = self.account_index - max_rows + 1
        visible = accounts[self.account_scroll:self.account_scroll + max_rows]
        for offset, account in enumerate(visible):
            index = self.account_scroll + offset
            y = top + 3 + offset
            status = str(account.get("status", "—"))
            status_color = "error" if status == "EXPIRED" else "ok" if status in {"ACTIVE", "RUNNING"} else "amber"
            selected = index == self.account_index
            self.put(y, 5, f"[{index + 1:02}]", row.color, bold=selected, reverse=selected, width=5)
            self.put(y, name_x, account.get("name", "—"), "text", bold=selected,
                     reverse=selected, width=max(12, connection_x - name_x - 2))
            self.put(y, connection_x, account.get("connection", "—"), "amber",
                     width=max(10, status_x - connection_x - 2))
            self.put(y, status_x, status, status_color, bold=True,
                     width=max(8, expiry_x - status_x - 2))
            self.put(y, expiry_x, account.get("expires", "—"), "dim",
                     width=max(10, width - expiry_x - 7))
        if len(accounts) > max_rows and bottom < self.stdscr.getmaxyx()[0] - 2:
            self.put(bottom, 6, f"Showing {self.account_scroll + 1}-{self.account_scroll + len(visible)} of {len(accounts)} · Up/Down to scroll",
                     "dim", width=width - 12)

    def _draw_account_actions(self, row: Row, width: int, top: int, bottom: int,
                              accounts: list[dict[str, object]]) -> None:
        selected = next((item for item in accounts if item.get("name") == self.account_name), None)
        if selected is None:
            self.protocol_subview, self.account_name = "main", None
            return
        box_height = max(8, bottom - top)
        self._box(top, 3, box_height, width - 6,
                  f"ACCOUNT  /  {str(selected.get('name', '')).upper()}", row.color)
        self.put(top + 2, 6, "CONNECTION", "dim", bold=True)
        self.put(top + 2, 20, selected.get("connection", "—"), "amber", bold=True,
                 width=max(12, width // 2 - 22))
        status = str(selected.get("status", "—"))
        self.put(top + 2, width // 2, "STATUS", "dim", bold=True)
        self.put(top + 2, width // 2 + 10, status,
                 "error" if status == "EXPIRED" else "ok", bold=True,
                 width=max(10, width // 2 - 18))
        self.put(top + 3, 6, "VALID UNTIL", "dim", bold=True)
        self.put(top + 3, 20, selected.get("expires", "—"), "text", width=24)
        self.put(top + 4, 6, "ACCOUNT INFO", "dim", bold=True)
        self.put(top + 4, 20, selected.get("details", "—"), "text", width=width - 26)
        actions = (("1", "View details"), ("2", "Renew account"),
                   ("3", "Delete account"), ("4", "Edit account"), ("0", "Back to list"))
        columns = 2 if width >= 72 else 1
        tile_width = max(20, (width - 14 - (columns - 1) * 2) // columns)
        action_top = top + 5
        compact = bottom - action_top < 11
        for index, (digit, label) in enumerate(actions):
            action_row, column = divmod(index, columns)
            x = 6 + column * (tile_width + 2)
            y = action_top + action_row * (1 if compact else 3)
            is_selected = index == self.account_action_index
            color = "amber" if is_selected else "error" if digit == "3" else row.color
            if compact:
                self.put(y, x, f"[{digit}]  {label}", color,
                         bold=True, reverse=is_selected, width=tile_width)
            else:
                self._box(y, x, 3, tile_width, f"[{digit}]  {label}", color)
                self.put(y + 1, x + 2, "ENTER TO OPEN" if is_selected else "SELECT",
                         "mint" if is_selected else "dim", bold=is_selected,
                         width=tile_width - 4)

    def _draw_service_panel(self, row: Row, width: int, top: int, bottom: int) -> None:
        self._box(top, 3, max(8, bottom - top), width - 6, f"{row.title.upper()}  /  SERVICE", row.color)
        self.put(top + 2, 6, f"STATUS   {row.state}", "ok" if row.state in {"Active", "Service active"} else "amber", bold=True)
        self.put(top + 3, 6, f"ENGINE   {row.engine}", "text")
        self.put(top + 4, 6, f"PORTS    {row.ports}", "text", width=width - 12)
        self.put(top + 5, 6, row.detail, "dim", width=width - 12)
        actions = (("1", "Restart service"), ("2", "Start service"),
                   ("3", "Stop service"), ("0", "Back to protocol"))
        tile_width = max(20, (width - 14) // 2)
        compact = bottom - (top + 6) < 8
        for index, (digit, label) in enumerate(actions):
            action_row, column = divmod(index, 2)
            x = 6 + column * (tile_width + 2)
            y = top + 6 + action_row * (1 if compact else 3)
            is_selected = index == self.service_action_index
            color = "amber" if is_selected else "error" if digit == "3" else row.color
            if compact:
                self.put(y, x, f"[{digit}]  {label}", color,
                         bold=True, reverse=is_selected, width=tile_width)
            else:
                self._box(y, x, 3, tile_width, f"[{digit}]  {label}", color)
                self.put(y + 1, x + 2, "ENTER TO RUN" if is_selected else "SELECT",
                         "mint" if is_selected else "dim", bold=is_selected,
                         width=tile_width - 4)

    def _terminal_action(self, title: str, action) -> None:
        """Temporarily leave curses for secure prompts and manager detail cards."""
        try:
            curses.curs_set(1)
            curses.echo()
            curses.nocbreak()
            curses.endwin()
            print(f"\n=== {title} ===")
            action()
            input("\nPress Enter to return...")
            self.toast = "OK  " + title
        except (KeyboardInterrupt, EOFError):
            self.toast = "OK  Action cancelled"
        except Exception as exc:
            # The previous toast vanished as soon as the curses screen was
            # restored, hiding account-manager failures from the operator.
            try:
                print(f"\nOperation failed: {exc}")
                input("Press Enter to return...")
            except (EOFError, KeyboardInterrupt):
                pass
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
            self.toast_until = time.monotonic() + 5
            self.last_draw = None

    @staticmethod
    def _validity_days() -> int:
        while True:
            raw = input("Validity in days [30]: ").strip() or "30"
            try:
                days = int(raw)
            except ValueError:
                print("Enter a whole number from 1 to 3650.")
                continue
            if 1 <= days <= 3650:
                return days
            print("Validity must be between 1 and 3650 days.")

    @staticmethod
    def _new_username(protocol: str, trial: bool) -> str:
        default = f"trial{secrets.token_hex(3)}" if trial else ""
        prompt = f"Username [{default}]: " if default else "Username: "
        return (input(prompt).strip() or default)

    def _create_protocol_account(self, key: str, trial: bool = False) -> None:
        import services_manager as sm
        name = self._new_username(key, trial)
        if not name:
            raise ValueError("Username is required")
        trial_minutes = sm.prompt_trial_minutes() if trial else None
        days = 1 if trial else self._validity_days()
        if key in {"ssh", "dropbear"}:
            password = getpass.getpass("Password: ")
            if not password:
                raise ValueError("Password is required")
            max_ips = int(input("Maximum simultaneous connected IPs [1, 0=unlimited]: ").strip() or "1")
            credential = sm.ssh_add(name, days, trial=trial, trial_minutes=trial_minutes,
                                    password=password, max_ips=max_ips)
            sm.show_created_account("ssh", name, credential, days, trial=trial)
        elif key == "udp":
            credential = sm.udp_add(name, days, trial=trial)
            sm.show_created_account("udp", name, credential, days, trial=trial)
        elif key in {"vmess", "vless", "trojan", "shadowsocks"}:
            credential = sm.xray_add(key, name, days, trial=trial, trial_minutes=trial_minutes)
            sm.show_created_account(key, name, credential, days, trial=trial)
        elif key == "openvpn":
            import openvpn_manager
            record = openvpn_manager.add_account(name, days, trial=trial, trial_minutes=trial_minutes)
            import terminal_ui
            terminal_ui.detail_card("OPENVPN ACCOUNT", [
                ("Username", name), ("Host", sm.state().get("domain") or "Set a domain"),
                ("Profiles", record.get("profile_dir", "—")), ("Valid until", record.get("expires_at", "unknown")),
                ("Account type", "TRIAL" if trial else "REGULAR"),
            ], note="Client profiles contain private keys. Transfer them securely.")
        elif key == "wireguard":
            import wireguard_manager
            interface = "wg0"
            endpoint = input("Public endpoint host:port: ").strip()
            profile = wireguard_manager.add_peer(interface, name, endpoint, days=days,
                                                  trial=trial, trial_minutes=trial_minutes)
            print(f"WireGuard client profile: {profile}")
        elif key in {"dnstt", "slowdns"}:
            import dnstt_manager
            port = int(input("Local client port [7000]: ").strip() or "7000")
            profile, records = dnstt_manager.add_account(name, local_port=port, days=days,
                                                          trial=trial, trial_minutes=trial_minutes)
            print(records)
            print(f"DNSTT client profile: {profile}")
        else:
            raise ValueError("TLS is a shared transport setting. Configure its domain and certificate in TLS / Domain.")
        self.protocol_subview = "main"
        self.protocol_tab = 0

    def _show_protocol_account(self, key: str, name: str) -> None:
        import services_manager as sm
        if key in {"ssh", "dropbear", "udp", "vmess", "vless", "trojan", "shadowsocks"}:
            sm.show_account_details(key, name)
        elif key == "openvpn":
            import terminal_ui
            record = sm.account_details("openvpn", name)
            terminal_ui.detail_card("OPENVPN ACCOUNT", [
                ("Username", name), ("Host", sm.state().get("domain") or "Set a domain"),
                ("Certificate CN", record.get("cert_cn", "—")),
                ("Profiles", record.get("profile_dir", "—")), ("Valid until", record.get("expires_at", "unknown")),
            ], note="Client profiles contain private keys. Transfer them securely.")
        elif key == "wireguard":
            import terminal_ui, wireguard_manager
            record = wireguard_manager.peer_details("wg0", name)
            terminal_ui.detail_card("WIREGUARD PEER", [(label, record.get(field, "—")) for label, field in
                (("Address", "address"), ("Public key", "public_key"), ("Interface", "interface"),
                 ("Valid until", "expires_at"), ("Last handshake", "last_handshake_epoch"),
                 ("Client profile", "profile"))])
        elif key in {"dnstt", "slowdns"}:
            import terminal_ui, dnstt_manager
            record = dnstt_manager.account_details(name)
            terminal_ui.detail_card("DNSTT ENDPOINT", [(label, record.get(field, "—")) for label, field in
                (("Endpoint", "domain"), ("Local port", "local_port"), ("Service", "service"),
                 ("Valid until", "expires_at"), ("Profile", "key_dir"))],
                note="DNSTT does not authenticate clients; protect endpoint details.")

    def _renew_protocol_account(self, key: str, name: str, *, is_edit: bool = False) -> None:
        import services_manager as sm
        days = self._validity_days()
        if key in {"ssh", "dropbear"}:
            if name in sm.ssh_list():
                sm.ssh_renew(name, days)
                if is_edit:
                    limit = int(input("Maximum simultaneous connected IPs [0=unlimited]: ").strip() or "0")
                    if not 0 <= limit <= 128:
                        raise ValueError("Allowed IP count must be from 0 to 128")
                    if limit:
                        sm.install_ssh_ip_limit()
                    data = sm.state(); data["accounts"][name]["max_ips"] = limit
                    sm._atomic(sm.STATE, json.dumps(data, indent=2) + "\n")
            else:
                sm.restore_expired_account("ssh", name, days)
        elif key == "udp":
            sm.udp_renew(name, days)
        elif key in {"vmess", "vless", "trojan", "shadowsocks"}:
            if name in sm.xray_list(key):
                sm.xray_renew(key, name, days)
            else:
                sm.restore_expired_account(key, name, days)
        elif key == "openvpn":
            import openvpn_manager
            record = openvpn_manager.renew_account(name, days)
            print("New client profiles:", record.get("profile_dir", "—"))
        elif key == "wireguard":
            import wireguard_manager
            wireguard_manager.renew_peer(name, days)
        elif key in {"dnstt", "slowdns"}:
            import dnstt_manager
            dnstt_manager.renew_account(name, days)

    def _delete_protocol_account(self, key: str, name: str) -> None:
        import services_manager as sm
        live = True
        if key in {"ssh", "dropbear"}:
            live = name in sm.ssh_list()
            if live: sm.ssh_remove(name)
        elif key == "udp":
            live = name in sm.udp_list()
            if live: sm.udp_remove(name)
        elif key in {"vmess", "vless", "trojan", "shadowsocks"}:
            live = name in sm.xray_list(key)
            if live: sm.xray_remove(key, name)
        elif key == "openvpn":
            import openvpn_manager
            live = name in openvpn_manager._account_state().get("accounts", {})
            if live: openvpn_manager.delete_account(name)
        elif key == "wireguard":
            import wireguard_manager
            live = name in wireguard_manager.list_peers()
            if live: wireguard_manager.remove_peer("wg0", name)
        elif key in {"dnstt", "slowdns"}:
            import dnstt_manager
            live = name in dnstt_manager.list_accounts()
            if live: dnstt_manager.remove_account(name)
        if not live and key in {"ssh", "dropbear", "vmess", "vless", "trojan", "shadowsocks"}:
            sm.forget_expired_account("ssh" if key in {"ssh", "dropbear"} else key, name)

    def _run_service_action(self, key: str, action: str) -> None:
        units = {
            "ssh": ["ssh.service"], "dropbear": ["kennet-dropbear.service"],
            "udp": ["kennet-udp-custom.service"],
            "vmess": ["xray.service"], "vless": ["xray.service"],
            "trojan": ["xray.service"], "shadowsocks": ["xray.service"],
            "openvpn": ["openvpn-server@server-tcp.service", "openvpn-server@server-udp.service"],
            "wireguard": ["wg-quick@wg0.service"],
            "dnstt": ["kennet-dnstt-router.service"], "slowdns": ["kennet-dnstt-router.service"],
        }.get(key)
        if not units:
            raise ValueError("TLS / Domain services are managed from System settings > TLS / Domain.")
        errors = []
        for unit in units:
            result = subprocess.run(["systemctl", action, unit], capture_output=True, text=True, check=False)
            if result.returncode:
                errors.append((result.stderr or result.stdout or f"{action} {unit} failed").strip())
        if errors:
            raise RuntimeError("; ".join(errors))

    def _protocol_operation(self, key: str, tab: int, account_name: str | None = None,
                            action: int | None = None) -> None:
        if tab == 1:
            self._terminal_action(f"Create {key} account", lambda: self._create_protocol_account(key))
        elif tab == 2:
            self._terminal_action(f"Create {key} trial account", lambda: self._create_protocol_account(key, True))
        elif tab == 3 and action in {1, 2, 3}:
            labels = {1: "restart", 2: "start", 3: "stop"}
            self._terminal_action(f"{labels[action].title()} {key} service",
                                  lambda: self._run_service_action(key, labels[action]))
        elif action == 1 and account_name:
            self._terminal_action(f"Details for {account_name}", lambda: self._show_protocol_account(key, account_name))
        elif action == 2 and account_name:
            self._terminal_action(f"Renew {account_name}", lambda: self._renew_protocol_account(key, account_name))
        elif action == 3 and account_name:
            def confirm_delete():
                if input(f"Delete {account_name}? Type YES: ").strip() == "YES":
                    self._delete_protocol_account(key, account_name)
                    print("Account deleted.")
                else:
                    print("Deletion cancelled.")
            self._terminal_action(f"Delete {account_name}", confirm_delete)
        elif action == 4 and account_name:
            self._terminal_action(f"Edit {account_name}", lambda: self._renew_protocol_account(key, account_name, is_edit=True))
        self.last_draw = None

    def _select_account(self, accounts: list[dict[str, object]]) -> None:
        if not accounts:
            self.toast = "ERROR  No accounts to select"
            self.toast_until = time.monotonic() + 3
            return
        if not 0 <= self.account_index < len(accounts):
            self.account_index = 0
        self.account_name = str(accounts[self.account_index].get("name", ""))
        self.protocol_subview = "account"
        self.account_action_index = 0
        self.protocol_numeric = ""

    def _protocol_number_action(self) -> None:
        """Dispatch the numeric controls shown on the current protocol screen."""
        raw = self.protocol_numeric
        self.protocol_numeric = ""
        try:
            value = int(raw)
        except ValueError:
            self.toast = "ERROR  Choose one of the numbered options on screen"
            self.toast_until = time.monotonic() + 3
            return
        key = self.protocol_view_key
        if key is None:
            return
        if self.protocol_subview == "account":
            if value not in {0, 1, 2, 3, 4}:
                self.toast = "ERROR  Choose a numbered account action"
                self.toast_until = time.monotonic() + 3
                return
            if value == 0:
                self.protocol_subview, self.account_name = "accounts", None
                return
            self._protocol_operation(key, 0, self.account_name, value)
            return
        if self.protocol_subview == "accounts":
            if value == 0:
                self.protocol_subview = "main"
                return
            accounts = self._protocol_accounts(key) or []
            if value < 1 or value > len(accounts):
                self.toast = f"ERROR  Account number must be 1-{len(accounts)} (or 0 to return)"
                self.toast_until = time.monotonic() + 3
                return
            self.account_index = value - 1
            self._select_account(accounts)
            return
        if self.protocol_subview == "service":
            if value not in {0, 1, 2, 3}:
                self.toast = "ERROR  Choose restart, start, stop, or back"
                self.toast_until = time.monotonic() + 3
                return
            if value == 0:
                self.protocol_subview = "main"
            elif value in {1, 2, 3}:
                self._protocol_operation(key, 3, action=value)
            return
        if value not in {0, 1, 2, 3, 4}:
            self.toast = "ERROR  Choose an option from 0 to 4"
            self.toast_until = time.monotonic() + 3
            return
        if value == 0:
            self.protocol_view_key = None
            self.protocol_subview, self.account_name = "main", None
        elif value == 1:
            self.protocol_tab, self.protocol_subview = 0, "accounts"
            self.account_index = 0
        elif value == 2:
            self.protocol_tab = 1
            self._protocol_operation(key, 1)
        elif value == 3:
            self.protocol_tab = 2
            self._protocol_operation(key, 2)
        elif value == 4:
            self.protocol_tab = 3
            self.protocol_subview = "service"

    def _tools(self, y: int, width: int) -> None:
        banner = " SETTINGS & TOOLS "
        # The gold section strip is the one intentional filled region; protocol
        # and action cards stay transparent so terminals with limited palettes
        # do not turn them into opaque grey blocks.
        self.put(y, 1, " " * (width - 2), "fill_banner", width=width - 2)
        banner_x = max(2, (width - len(banner)) // 2)
        self.put(y, banner_x, banner, "fill_banner", bold=True, width=len(banner))
        columns = 2 if width >= 64 else 1
        card_width = max(20, (width - 2 - (columns - 1) * 2) // columns)
        # Tool cards use one complete row each. The previous two-row form
        # advanced only one row per card and let borders overwrite neighbors.
        for index, (number, label) in enumerate(TOOLS):
            row, column = divmod(index, columns)
            x = 1 + column * (card_width + 2)
            card_y = y + 1 + row
            selected = self.in_tools and index == self.tool_selected
            text = f" [{number}] {label} "
            if self.ascii:
                left, right, line, vertical = "+", "+", "-", "|"
            else:
                left, right, line, vertical = "╭", "╮", "─", "│"
            border = "amber" if selected else "blue"
            self.put(card_y, x, left + text[:card_width - 2].ljust(card_width - 2) + right,
                     border, bold=selected, width=card_width)
            self.put(card_y, x + 2, text, "amber" if selected else "text", bold=selected,
                     width=card_width - 4)
            self.put(card_y, x, left, border, bold=True)
            self.put(card_y, x + card_width - 1, right, border, bold=True)

    def draw(self, force: bool = False) -> None:
        height, width = self.stdscr.getmaxyx()
        if height < 24 or width < 72:
            self.stdscr.erase()
            self.put(0, 1, "Please enlarge the terminal (72x24 minimum)", "amber", bold=True)
            self.stdscr.refresh()
            return
        try:
            self.rows, self.snapshot = collect_rows()
        except Exception as exc:
            self.toast = f"State refresh failed: {exc}"
            self.toast_until = time.monotonic() + 4
        if self.protocol_view_key:
            self._draw_protocol_screen(width, height)
            return
        fingerprint = (width, height, self.selected, self.tool_selected, self.in_tools,
                       tuple((row.key, row.state, row.count, row.detail) for row in self.rows),
                       tuple(self.snapshot.items()), self.toast if time.monotonic() < self.toast_until else "")
        if not force and fingerprint == self.last_draw:
            return
        self.last_draw = fingerprint
        self.stdscr.erase()
        self._header(width)
        self._metric_line(width)
        layout = _main_grid_layout(height, width)
        detailed_summary = bool(layout["detailed"])
        summary_width = int(layout["summary_width"])
        self._summary(4, width, detailed=detailed_summary, box_width=summary_width)
        if detailed_summary:
            self._server_details(4, width, summary_width=summary_width)
        # Distribute the real terminal height into the protocol cards instead
        # of pinning them to three rows and leaving a large empty lower pane.
        grid_top = int(layout["grid_top"])
        footer_y = int(layout["footer_y"])
        card_height = int(layout["card_height"])
        self.protocol_card_height = card_height
        self.single_line_cards = card_height == 1
        compact = card_height <= 2
        self._protocol_grid(grid_top, width, compact=compact)
        tools_y = int(layout["tools_y"])
        self._tools(tools_y, width)
        self.put(footer_y, 1, ("-" if self.ascii else "─") * (width - 2), "line")
        prompt = f"Select option [0-15]: {self.numeric}{' ' if self.ascii else '▌'}"
        hint = "Up/Down move · Enter open · Esc back"
        hint_x = max(1, width - len(hint) - 2)
        self.put(height - 2, 1, prompt, "mint", bold=True, width=max(16, hint_x - 3))
        self.put(height - 2, hint_x, hint, "dim", width=len(hint))
        if self.toast and time.monotonic() < self.toast_until and tools_y + 3 < footer_y:
            color = "ok" if self.toast.startswith("OK") else "error"
            self.put(tools_y + 3, 2, self.toast, color, bold=True, width=width - 4)
        self.stdscr.refresh()

    def _confirm_quit(self) -> bool:
        height, width = self.stdscr.getmaxyx()
        message = "Quit KEN-NET?  y / N"
        self.put(height - 1, max(1, (width - len(message)) // 2), message, "amber", bold=True)
        self.stdscr.refresh()
        key = self.stdscr.get_wch()
        return key in {"y", "Y"}

    def _open_backend(self, key: str | None = None) -> None:
        if key in PROTOCOL_ORDER:
            self.protocol_view_key = key
            self.protocol_tab = 0
            self.protocol_subview = "main"
            self.protocol_numeric = ""
            self.last_draw = None
            return
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
                raise ValueError(f"Unsupported dashboard action: {key}")
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
            self.protocol_view_key = LEGACY_ORDER[self.selected]
            self.protocol_tab = 0
            self.last_draw = None
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
            self.selected = LEGACY_ORDER.index(protocol_key)
            self.in_tools = False
            self.protocol_view_key = protocol_key
            self.protocol_tab = 0
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
            # Re-read dimensions before spatial navigation so the layout
            # remains correct after the terminal is resized.
            _height, width = self.stdscr.getmaxyx()
            try:
                key = self.stdscr.get_wch()
            except curses.error:
                self.draw()
                continue
            if self.protocol_view_key:
                key_name = self.protocol_view_key
                if key == curses.KEY_RESIZE:
                    self.stdscr.clearok(True)
                elif key in {curses.KEY_LEFT, "h", curses.KEY_RIGHT, "l"}:
                    direction = -1 if key in {curses.KEY_LEFT, "h"} else 1
                    if self.protocol_subview == "main":
                        self.protocol_tab = (self.protocol_tab + direction) % 4
                    elif self.protocol_subview == "account":
                        self.account_action_index = max(0, min(4, self.account_action_index + direction))
                    elif self.protocol_subview == "service":
                        self.service_action_index = max(0, min(3, self.service_action_index + direction))
                elif key in {"\t", curses.KEY_BTAB} and self.protocol_subview == "main":
                    direction = -1 if key == curses.KEY_BTAB else 1
                    self.protocol_tab = (self.protocol_tab + direction) % 4
                elif key in {curses.KEY_UP, "k"} and self.protocol_subview in {"accounts", "account"}:
                    accounts = self._protocol_accounts(key_name) or []
                    if accounts and self.protocol_subview == "accounts":
                        self.account_index = (self.account_index - 1) % len(accounts)
                    elif self.protocol_subview == "account":
                        self.account_action_index = max(0, self.account_action_index - (2 if width >= 72 else 1))
                elif key in {curses.KEY_UP, "k"} and self.protocol_subview == "service":
                    self.service_action_index = max(0, self.service_action_index - 2)
                elif key in {curses.KEY_DOWN, "j"} and self.protocol_subview in {"accounts", "account"}:
                    accounts = self._protocol_accounts(key_name) or []
                    if accounts and self.protocol_subview == "accounts":
                        self.account_index = (self.account_index + 1) % len(accounts)
                    elif self.protocol_subview == "account":
                        self.account_action_index = min(4, self.account_action_index + (2 if width >= 72 else 1))
                elif key in {curses.KEY_DOWN, "j"} and self.protocol_subview == "service":
                    self.service_action_index = min(3, self.service_action_index + 2)
                elif key in {"\n", "\r", curses.KEY_ENTER}:
                    if self.protocol_numeric:
                        self._protocol_number_action()
                    elif self.protocol_subview == "main":
                        if self.protocol_tab == 0:
                            self.protocol_subview = "accounts"
                        elif self.protocol_tab in {1, 2}:
                            self._protocol_operation(key_name, self.protocol_tab)
                        else:
                            self.protocol_subview = "service"
                    elif self.protocol_subview == "accounts":
                        self._select_account(self._protocol_accounts(key_name) or [])
                    elif self.protocol_subview == "account":
                        self.protocol_numeric = ("1", "2", "3", "4", "0")[self.account_action_index]
                        self._protocol_number_action()
                    elif self.protocol_subview == "service":
                        self.protocol_numeric = ("1", "2", "3", "0")[self.service_action_index]
                        self._protocol_number_action()
                elif key in {"\x1b", "\x08", "\x7f", curses.KEY_BACKSPACE, "q", "Q"}:
                    if self.protocol_numeric:
                        self.protocol_numeric = self.protocol_numeric[:-1]
                    elif self.protocol_subview == "account":
                        self.protocol_subview, self.account_name = "accounts", None
                        self.account_action_index = 0
                    elif self.protocol_subview != "main":
                        self.protocol_subview = "main"
                    else:
                        self.protocol_view_key = None
                    self.last_draw = None
                elif isinstance(key, str) and key.isdigit() and len(self.protocol_numeric) < 2:
                    self.protocol_numeric += key
                self.last_draw = None
                self.draw(force=True)
                continue
            if key == curses.KEY_RESIZE:
                self.stdscr.clearok(True)
                self.last_draw = None
            elif key in {curses.KEY_UP, "k", curses.KEY_DOWN, "j",
                         curses.KEY_LEFT, "h", curses.KEY_RIGHT, "l"}:
                direction = (-1 if key in {curses.KEY_UP, "k"} else
                             1 if key in {curses.KEY_DOWN, "j"} else
                             -1 if key in {curses.KEY_LEFT, "h"} else 1)
                horizontal = key in {curses.KEY_LEFT, "h", curses.KEY_RIGHT, "l"}
                columns = 2 if width >= 76 else 1
                if self.in_tools:
                    tool_columns = 2 if width >= 64 else 1
                    step = direction if horizontal else direction * tool_columns
                    target = self.tool_selected + step
                    if 0 <= target < len(TOOLS):
                        self.tool_selected = target
                    elif not horizontal:
                        # Moving up from the tools returns to the protocol
                        # cards; moving down at the last row stays in tools.
                        if direction < 0:
                            self.in_tools = False
                            self.selected = len(LEGACY_ORDER) - 1
                else:
                    if horizontal and columns == 2:
                        col = self.selected % columns
                        target_col = col + direction
                        if 0 <= target_col < columns:
                            self.selected = (self.selected // columns) * columns + target_col
                    elif horizontal:
                        # One-column layout: left/right have no adjacent card.
                        pass
                    else:
                        target = self.selected + direction * columns
                        if 0 <= target < len(LEGACY_ORDER):
                            self.selected = target
                        elif direction > 0:
                            self.in_tools = True
                            self.tool_selected = 0
                self.last_draw = None
            elif key == curses.KEY_HOME:
                self.selected, self.in_tools = 0, False
                self.last_draw = None
            elif key == curses.KEY_END:
                self.selected, self.in_tools = len(LEGACY_ORDER) - 1, False
                self.last_draw = None
            elif key in {"\t", curses.KEY_BTAB}:
                self.in_tools = not self.in_tools
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
                self._open_backend(LEGACY_ORDER[self.selected])
            elif isinstance(key, str) and key.isdigit() and len(self.numeric) < 2:
                self.numeric += key
                self.last_draw = None
            self.draw()


def _plain_dashboard() -> int:
    """Safe no-curses fallback for TERM=dumb and non-interactive diagnostics."""
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


def _plain_protocol_manager(protocol_key: str) -> None:
    """Numbered non-curses protocol flow using the same operations as the full TUI."""
    manager = Dashboard.__new__(Dashboard)
    manager.protocol_subview = "main"
    manager.protocol_tab = 0
    manager.account_name = None
    manager.account_index = 0
    label = dict((row.key, row.title) for row in collect_rows()[0]).get(protocol_key, protocol_key.title())
    while True:
        print(f"\n=== {label.upper()} ===")
        print("[1] Accounts   [2] Create   [3] Trial   [4] Service   [0] Dashboard")
        try:
            choice = input("Select option: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        try:
            if choice == "0":
                return
            if choice in {"2", "3"}:
                manager._create_protocol_account(protocol_key, trial=choice == "3")
                continue
            if choice == "4":
                print("[1] Restart   [2] Start   [3] Stop   [0] Back")
                action = input("Select service action: ").strip()
                if action in {"1", "2", "3"}:
                    manager._run_service_action(protocol_key, {"1": "restart", "2": "start", "3": "stop"}[action])
                    print("Service action completed.")
                continue
            if choice != "1":
                print("Choose an option from 0 to 4.")
                continue
            accounts = manager._protocol_accounts(protocol_key) or []
            if not accounts:
                print("No accounts are registered.")
                continue
            print("\n#   ACCOUNT                         CONNECTION       STATUS       VALID UNTIL")
            for index, account in enumerate(accounts, 1):
                print(f"{index:02}  {account.get('name', '—'):<30} {account.get('connection', '—'):<15} "
                      f"{account.get('status', '—'):<12} {account.get('expires', '—')}")
            selected = input("Select account number (0 to return): ").strip()
            if selected == "0":
                continue
            if not selected.isdigit() or not 1 <= int(selected) <= len(accounts):
                print("Invalid account number.")
                continue
            name = str(accounts[int(selected) - 1].get("name", ""))
            while True:
                print(f"\n=== {name} ===")
                print("[1] Details   [2] Renew   [3] Delete   [4] Edit settings   [0] Accounts")
                action = input("Select account action: ").strip()
                if action == "0":
                    break
                if action == "1":
                    manager._show_protocol_account(protocol_key, name)
                elif action == "2":
                    manager._renew_protocol_account(protocol_key, name)
                elif action == "3":
                    if input(f"Delete {name}? Type YES: ").strip() == "YES":
                        manager._delete_protocol_account(protocol_key, name)
                        print("Account deleted.")
                    else:
                        print("Deletion cancelled.")
                    break
                elif action == "4":
                    manager._renew_protocol_account(protocol_key, name, is_edit=True)
                else:
                    print("Choose an option from 0 to 4.")
        except (EOFError, KeyboardInterrupt):
            print("Action cancelled.")
        except Exception as exc:
            print(f"Operation failed: {exc}")


def _dispatch_backend(key: str) -> None:
    """Open a numbered protocol flow, status, or tools screen."""
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
        _plain_protocol_manager(protocol_key)


def run(force_plain: bool = False) -> int:
    """Run the full-screen TUI, falling back to plain navigation when necessary."""
    if curses is None or os.environ.get("TERM") == "dumb" or not (os.isatty(0) and os.isatty(1)):
        return _plain_dashboard()
    try:
        return curses.wrapper(lambda screen: Dashboard(screen, force_plain).run())
    except curses.error as exc:
        print(f"Terminal UI unavailable ({exc}); starting the plain menu.")
        return _plain_dashboard()
