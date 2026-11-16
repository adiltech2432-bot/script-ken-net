#!/usr/bin/env python3
"""Manage isolated DNSTT endpoints and client profiles on a prepared Ubuntu VPS."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ETC = Path("/etc/kennet-panel")
CONFIG = ETC / "dnstt-manager.json"
ROUTES = ETC / "dnstt-routes.json"
ACCOUNTS = ETC / "dnstt-accounts.json"
SYSTEMD = Path("/etc/systemd/system")
ACCOUNT_DIR = ETC / "dnstt"
MUX_UNIT = "kennet-dnstt-router.service"
NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{1,30}[A-Za-z0-9])$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
ADDR_RE = re.compile(r"^[A-Za-z0-9_.:\[\]-]+:[0-9]{1,5}$")


def _atomic(path: Path, content: str, mode=0o600) -> None:
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
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def _run(args, env=None):
    result = subprocess.run(args, text=True, capture_output=True, check=False, env=env)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result.stdout.strip()


def install_tools() -> bool:
    """Build the upstream DNSTT server and client into /usr/local/bin."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Run as root")
    if input("Go may be installed if needed, then dnstt-server and dnstt-client will be built from the official source. Type YES: ").strip() != "YES":
        return False
    if not shutil.which("go"):
        _run(["apt-get", "update"])
        _run(["apt-get", "install", "-y", "golang-go"])
    env = os.environ.copy()
    env["GOBIN"] = "/usr/local/bin"
    _run(["go", "install", "www.bamsoftware.com/git/dnstt.git/dnstt-server@latest"], env=env)
    _run(["go", "install", "www.bamsoftware.com/git/dnstt.git/dnstt-client@latest"], env=env)
    for name in ("dnstt-server", "dnstt-client"):
        path = Path("/usr/local/bin") / name
        if not path.is_file():
            raise RuntimeError(f"Build completed without expected binary: {path}")
        os.chmod(path, 0o755)
    return True


def _read_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def _configuration() -> dict:
    if not CONFIG.is_file():
        raise FileNotFoundError(f"DNSTT configuration is missing: {CONFIG}")
    config = _read_json(CONFIG, {})
    domain = str(config.get("base_domain", "")).strip().lower().rstrip(".")
    ns_host = str(config.get("nameserver_host", "")).strip().lower().rstrip(".")
    doh_url = str(config.get("doh_url", "")).strip()
    forward = str(config.get("forward_address", "127.0.0.1:443")).strip()
    if not DOMAIN_RE.fullmatch(domain) or not DOMAIN_RE.fullmatch(ns_host):
        raise ValueError("Set valid base_domain and nameserver_host in dnstt-manager.json")
    if ns_host == domain or ns_host.endswith("." + domain):
        raise ValueError("nameserver_host must be outside the delegated DNSTT zone")
    if not doh_url.startswith("https://") or any(c.isspace() for c in doh_url):
        raise ValueError("doh_url must be an HTTPS resolver URL")
    if not ADDR_RE.fullmatch(forward) or not 1 <= int(forward.rsplit(":", 1)[1]) <= 65535:
        raise ValueError("forward_address must be a valid host:port")
    binary = str(config.get("server_binary", "/usr/local/bin/dnstt-server"))
    if not Path(binary).is_absolute() or any(c.isspace() for c in binary) or not Path(binary).is_file():
        raise FileNotFoundError(f"DNSTT server binary is missing: {binary}")
    listen = str(config.get("dns_listen", "0.0.0.0:53"))
    if not ADDR_RE.fullmatch(listen) or not 1 <= int(listen.rsplit(":", 1)[1]) <= 65535:
        raise ValueError("dns_listen must be a valid host:port")
    return {**config, "base_domain": domain, "nameserver_host": ns_host,
            "doh_url": doh_url, "forward_address": forward, "server_binary": binary}


def configure() -> None:
    old = _read_json(CONFIG, {})
    try:
        import services_manager
        shared_domain = services_manager.state().get("domain", "")
    except (ImportError, OSError, ValueError):
        shared_domain = ""
    default_base = old.get("base_domain", shared_domain)
    values = {
        "base_domain": input(f"DNSTT base domain [{default_base}]: ").strip() or default_base,
        "nameserver_host": input(f"DNS nameserver hostname [{old.get('nameserver_host', '')}]: ").strip() or old.get("nameserver_host", ""),
        "doh_url": input(f"DoH URL [{old.get('doh_url', 'https://cloudflare-dns.com/dns-query')}]: ").strip() or old.get("doh_url", "https://cloudflare-dns.com/dns-query"),
        "forward_address": input(f"Server tunnel destination [{old.get('forward_address', '127.0.0.1:443')}]: ").strip() or old.get("forward_address", "127.0.0.1:443"),
        "server_binary": input(f"Path to dnstt-server [{old.get('server_binary', '/usr/local/bin/dnstt-server')}]: ").strip() or old.get("server_binary", "/usr/local/bin/dnstt-server"),
        "dns_listen": input(f"DNS listen address [{old.get('dns_listen', '0.0.0.0:53')}]: ").strip() or old.get("dns_listen", "0.0.0.0:53"),
    }
    if not DOMAIN_RE.fullmatch(values["base_domain"].lower().rstrip(".")):
        raise ValueError("Invalid DNSTT base domain")
    if not DOMAIN_RE.fullmatch(values["nameserver_host"].lower().rstrip(".")):
        raise ValueError("Invalid DNS nameserver hostname")
    if (values["nameserver_host"].lower().rstrip(".") == values["base_domain"].lower().rstrip(".")
            or values["nameserver_host"].lower().rstrip(".").endswith("." + values["base_domain"].lower().rstrip("."))):
        raise ValueError("Nameserver hostname must be outside the delegated tunnel zone")
    if not values["doh_url"].startswith("https://") or any(c.isspace() for c in values["doh_url"]):
        raise ValueError("DoH URL must begin with https://")
    if not Path(values["server_binary"]).is_absolute() or any(c.isspace() for c in values["server_binary"]) or not Path(values["server_binary"]).is_file():
        raise FileNotFoundError(f"DNSTT server binary not found: {values['server_binary']}")
    if not ADDR_RE.fullmatch(values["forward_address"]) or not 1 <= int(values["forward_address"].rsplit(":", 1)[1]) <= 65535:
        raise ValueError("forward_address must be host:port")
    if not ADDR_RE.fullmatch(values["dns_listen"]) or not 1 <= int(values["dns_listen"].rsplit(":", 1)[1]) <= 65535:
        raise ValueError("dns_listen must be host:port")
    values["base_domain"] = values["base_domain"].lower().rstrip(".")
    values["nameserver_host"] = values["nameserver_host"].lower().rstrip(".")
    _atomic(CONFIG, json.dumps(values, indent=2) + "\n")


def _routes(config: dict) -> dict[str, int]:
    routes = _read_json(ROUTES, {"listen": "0.0.0.0:53", "routes": {}})
    if not isinstance(routes.get("routes"), dict):
        raise ValueError("DNSTT routes file has an invalid routes map")
    return routes


def _write_routes(config: dict, routes: dict) -> None:
    routes["listen"] = str(config.get("dns_listen", routes.get("listen", "0.0.0.0:53")))
    ETC.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(ETC, 0o755)
    _atomic(ROUTES, json.dumps(routes, indent=2) + "\n", 0o644)
    # The router reads its own configuration; keep a single canonical copy.
    _atomic(ETC / "dnstt-router.json", json.dumps(routes, indent=2) + "\n", 0o644)


def install_router() -> None:
    """Install the DNS multiplexer service. Does not stop existing DNS services."""
    config = _configuration()
    if subprocess.run(["systemctl", "is-active", "--quiet", "server.service"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0:
        raise RuntimeError("An existing server.service is active; migrate only on a separate test VPS to avoid disrupting it")
    if subprocess.run(["systemctl", "is-active", "--quiet", MUX_UNIT],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0:
        raise RuntimeError("DNSTT router is already active")
    if (SYSTEMD / MUX_UNIT).exists():
        raise FileExistsError(f"Refusing to replace an existing unit: {SYSTEMD / MUX_UNIT}")
    source = Path(__file__).resolve().with_name("dnstt_mux.py")
    if not source.is_file():
        raise FileNotFoundError(f"Router source not found beside manager: {source}")
    app_dir = Path("/opt/kennet-panel")
    app_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    shutil.copyfile(source, app_dir / "dnstt_mux.py")
    route_data = _routes(config)
    route_data["listen"] = str(config.get("dns_listen", "0.0.0.0:53"))
    _write_routes(config, route_data)
    unit = (
        "[Unit]\nDescription=Kennet DNSTT DNS router\nAfter=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=simple\nUser=nobody\nGroup=nogroup\n"
        f"ExecStart=/usr/bin/python3 {app_dir}/dnstt_mux.py --config {ETC}/dnstt-router.json\n"
        "Restart=on-failure\nRestartSec=2\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\n"
        "ProtectHome=true\nReadOnlyPaths=/etc/kennet-panel\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\n"
    )
    _atomic(SYSTEMD / MUX_UNIT, unit, 0o644)
    try:
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "--now", MUX_UNIT])
        try:
            import services_manager
            services_manager.open_ports([("udp", int(config.get("dns_listen", "0.0.0.0:53").rsplit(":", 1)[1]))])
        except ImportError:
            pass
    except Exception:
        subprocess.run(["systemctl", "disable", "--now", MUX_UNIT], capture_output=True, check=False)
        (SYSTEMD / MUX_UNIT).unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, check=False)
        raise


def _account_unit(username: str, service_user: str, domain: str, port: int, keyfile: Path, config: dict) -> str:
    return (
        "[Unit]\nDescription=DNSTT account " + username + "\nAfter=network-online.target\nWants=network-online.target\n\n"
        f"[Service]\nType=simple\nUser={service_user}\nGroup={service_user}\n"
        f"ExecStart={config['server_binary']} -udp 127.0.0.1:{port} -privkey-file {keyfile} {domain} {config['forward_address']}\n"
        "Restart=on-failure\nRestartSec=2\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\n"
        "ProtectHome=true\nCapabilityBoundingSet=\n\n[Install]\nWantedBy=multi-user.target\n"
    )


def _next_port(routes: dict) -> int:
    used = {int(p) for p in routes["routes"].values()}
    return next((port for port in range(5301, 65000) if port not in used), 0)


def add_account(username: str, local_port: int = 7000) -> tuple[Path, str]:
    if not NAME_RE.fullmatch(username):
        raise ValueError("Username must contain 3-32 letters, digits, or underscores")
    if not 1 <= int(local_port) <= 65535:
        raise ValueError("Client local port must be in 1..65535")
    config = _configuration()
    domain = f"{username.lower()}.{config['base_domain']}"
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Generated account domain is invalid")
    if not shutil.which("systemctl"):
        raise RuntimeError("systemd is required")
    routes = _routes(config)
    route_map = routes["routes"]
    accounts = _read_json(ACCOUNTS, {})
    if username in accounts or domain in route_map:
        raise ValueError("DNSTT username or domain already exists")
    if not Path("/etc/systemd/system").is_dir():
        raise RuntimeError("systemd unit directory is unavailable")
    if not (SYSTEMD / MUX_UNIT).is_file():
        raise RuntimeError("Install/start the DNSTT router before adding accounts")
    port = _next_port(routes)
    if not port:
        raise RuntimeError("No DNSTT backend ports are available")
    account_dir = ACCOUNT_DIR / username
    account_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    keyfile = account_dir / "server.key"
    pubfile = account_dir / "server.pub"
    service_name = f"kennet-dnstt-{username}.service"
    service_user = f"kennet-dnstt-{username}"
    unit_path = SYSTEMD / service_name
    if unit_path.exists():
        raise FileExistsError(f"Refusing to replace an existing unit: {unit_path}")
    if subprocess.run(["systemctl", "is-active", "--quiet", MUX_UNIT],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode != 0:
        raise RuntimeError("DNSTT router must be active before adding accounts")
    user_created = False
    try:
        _run(["useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
              "--shell", "/usr/sbin/nologin", service_user])
        user_created = True
        service_gid = int(_run(["id", "-g", service_user]))
        ACCOUNT_DIR.mkdir(parents=True, exist_ok=True, mode=0o711)
        os.chmod(ACCOUNT_DIR, 0o711)
        os.chown(account_dir, 0, service_gid)
        os.chmod(account_dir, 0o750)
        _run([config["server_binary"], "-gen-key", "-privkey-file", str(keyfile), "-pubkey-file", str(pubfile)])
        os.chmod(keyfile, 0o640)
        os.chown(keyfile, 0, service_gid)
        os.chmod(pubfile, 0o644)
        unit = _account_unit(username, service_user, domain, port, keyfile, config)
        _atomic(unit_path, unit, 0o644)
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "--now", service_name])
        route_map[domain] = port
        _write_routes(config, routes)
        _run(["systemctl", "restart", MUX_UNIT])
        accounts[username] = {"domain": domain, "port": port, "service": service_name,
                              "service_user": service_user,
                              "key_dir": str(account_dir), "local_port": int(local_port)}
        _atomic(ACCOUNTS, json.dumps(accounts, indent=2) + "\n")
    except Exception:
        route_map.pop(domain, None)
        try:
            _write_routes(config, routes)
            subprocess.run(["systemctl", "disable", "--now", service_name], capture_output=True, check=False)
            unit_path.unlink(missing_ok=True)
            shutil.rmtree(account_dir, ignore_errors=True)
            if user_created:
                subprocess.run(["userdel", service_user], capture_output=True, check=False)
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, check=False)
        except OSError:
            pass
        raise
    client_dir = account_dir / "client"
    client_dir.mkdir(mode=0o755)
    shutil.copyfile(pubfile, client_dir / "server.pub")
    os.chmod(client_dir / "server.pub", 0o644)
    profile = client_dir / "client.txt"
    public_key = pubfile.read_text(encoding="utf-8").strip()
    text = (
        f"DNSTT endpoint: {domain}\n"
        f"Resolver: {config['doh_url']}\n"
        f"Server public key: {public_key}\n\n"
        "Security note: vanilla DNSTT authenticates the server, not the client. Anyone with these connection details can use this endpoint.\n"
        "Client command (use the included server.pub file):\n"
        f"dnstt-client -doh {config['doh_url']} -pubkey-file server.pub {domain} 127.0.0.1:{local_port}\n"
    )
    _atomic(profile, text, 0o600)
    records = (
        f"DNS records to add for {domain}:\n"
        f"  NS  {domain}.  -> {config['nameserver_host']}.\n"
        f"  A/AAAA {config['nameserver_host']}. -> this VPS public address\n"
        "The nameserver must be authoritative for the delegated account zone and UDP/53 must reach the router.\n"
    )
    return profile, records


def remove_account(username: str) -> None:
    if not NAME_RE.fullmatch(username):
        raise ValueError("Invalid username")
    config = _configuration()
    accounts = _read_json(ACCOUNTS, {})
    if username not in accounts:
        raise ValueError("DNSTT account not found")
    record = accounts[username]
    service_name = record["service"]
    _run(["systemctl", "disable", "--now", service_name])
    old_routes = _routes(config)
    old_value = old_routes["routes"].pop(record["domain"], None)
    try:
        _write_routes(config, old_routes)
        _run(["systemctl", "restart", MUX_UNIT])
        (SYSTEMD / service_name).unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        shutil.rmtree(record["key_dir"])
        subprocess.run(["userdel", record.get("service_user", f"kennet-dnstt-{username}")],
                       capture_output=True, check=False)
        del accounts[username]
        _atomic(ACCOUNTS, json.dumps(accounts, indent=2) + "\n")
    except Exception:
        if old_value is not None:
            old_routes["routes"][record["domain"]] = old_value
            _write_routes(config, old_routes)
            subprocess.run(["systemctl", "restart", MUX_UNIT], capture_output=True, check=False)
        subprocess.run(["systemctl", "enable", "--now", service_name], capture_output=True, check=False)
        raise


def menu() -> None:
    while True:
        print("\nDNSTT — a separate domain and service for each name (DNSTT does not authenticate clients)")
        print("1. Build the official DNSTT tools")
        print("2. Configure the domain and DNSTT server")
        print("3. Install the multi-domain DNS router")
        print("4. Create an account/tunnel")
        print("5. Revoke and remove an account/tunnel")
        print("0. Return")
        choice = input("Select: ").strip()
        try:
            if choice == "0":
                return
            if choice == "1":
                if install_tools():
                    print("Installed dnstt-server and dnstt-client in /usr/local/bin")
            elif choice == "2":
                configure()
                print(f"Configuration saved: {CONFIG}")
            elif choice == "3":
                if input("The DNS router will start. Make sure the selected port is available. Type YES to continue: ").strip() == "YES":
                    install_router()
                    print("DNS router installed.")
            elif choice == "4":
                username = input("Username: ").strip()
                try:
                    port = int(input("Local client port [7000]: ").strip() or "7000")
                except ValueError:
                    print("Invalid port")
                    continue
                profile, records = add_account(username, port)
                print(f"Profile created: {profile}\n{records}")
                print("The account directory contains the server private key; do not share it with the client.")
            elif choice == "5":
                username = input("Username: ").strip()
                if input(f"Endpoint {username} will be stopped for everyone using its details. Type YES: ").strip() == "YES":
                    remove_account(username)
                    print("Tunnel stopped; key and service removed.")
            else:
                print("Invalid selection")
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            print(f"Could not complete the operation: {exc}")
