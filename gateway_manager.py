#!/usr/bin/env python3
"""Install the shared public TCP gateway used by Xray and tunnel transports."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import services_manager

NGINX_SITE = Path("/etc/nginx/sites-available/kennet-panel")
NGINX_LINK = Path("/etc/nginx/sites-enabled/kennet-panel")
HAPROXY_CFG = Path("/etc/haproxy/conf.d/kennet-panel.cfg")
WS_SOURCE = Path("/opt/kennet-panel/websocket_tunnel.py")
WS_UNIT = Path("/etc/systemd/system/kennet-websocket.service")
WS_SCRIPT = Path("/usr/local/lib/kennet-panel/websocket_tunnel.py")
HAPROXY_BEGIN = "# BEGIN KEN-NET MANAGED FRONTENDS"
HAPROXY_END = "# END KEN-NET MANAGED FRONTENDS"


def render_haproxy(tls_cert: str | None = None) -> str:
    """Multiplex raw OpenVPN/SSH, legacy TLS-wrapped SSH, and HTTP/TLS services."""
    tls_termination = ""
    tls_backend = "    use_backend kennet_tls_termination if tls_client_hello\n    default_backend kennet_tls_termination"
    if tls_cert:
        tls_termination = f"""
frontend kennet_tls_terminated
    mode tcp
    bind 127.0.0.1:8444 ssl crt {tls_cert} alpn h2,http/1.1
    tcp-request inspect-delay 2s
    acl ssh_banner payload(0,7) -m str SSH-2.0
    acl http_request req.proto_http
    acl http2_preface payload(0,14) -m str "PRI * HTTP/2.0"
    tcp-request content accept if ssh_banner or http_request or http2_preface
    use_backend kennet_ssh_raw if ssh_banner
    use_backend kennet_nginx_http if http_request or http2_preface
    default_backend kennet_ssh_raw
"""
        tls_backend = "    use_backend kennet_tls_termination if tls_client_hello\n    default_backend kennet_tls_termination"
    else:
        tls_backend = "    use_backend kennet_nginx_tls if tls_client_hello\n    default_backend kennet_nginx_tls"
    return f"""# Managed by Ken-net. HAProxy is the public owner of shared tunnel ports.
frontend kennet_http
    mode tcp
    bind :80
    default_backend kennet_nginx_http

frontend kennet_http_custom_proxy
    mode tcp
    bind :8080
    default_backend kennet_nginx_http

frontend kennet_dropbear_mux
    mode tcp
    bind :109
    tcp-request inspect-delay 2s
    acl ssh_banner payload(0,7) -m str SSH-2.0
    acl http_request req.proto_http
    tcp-request content accept if ssh_banner or http_request
    use_backend kennet_nginx_http if http_request
    default_backend kennet_dropbear

frontend kennet_tls_mux
    mode tcp
    bind :443
    tcp-request inspect-delay 2s
    acl tls_client_hello req.ssl_hello_type 1
    acl ovpn_v2 payload(0,1) -m bin 38
    acl ovpn_v1 payload(0,1) -m bin 28
    acl ssh_banner payload(0,7) -m str SSH-2.0
    tcp-request content accept if tls_client_hello or ovpn_v2 or ovpn_v1 or ssh_banner
    use_backend kennet_openvpn_tcp if ovpn_v2 or ovpn_v1
    use_backend kennet_ssh_raw if ssh_banner
{tls_backend}

backend kennet_nginx_http
    mode tcp
    server nginx_http 127.0.0.1:8081 check

backend kennet_nginx_tls
    mode tcp
    server nginx_tls 127.0.0.1:8443 check

backend kennet_openvpn_tcp
    mode tcp
    server openvpn_tcp 127.0.0.1:1194 check

backend kennet_ssh_raw
    mode tcp
    server ssh 127.0.0.1:22 check

backend kennet_dropbear
    mode tcp
    server dropbear 127.0.0.1:2109 check
{tls_termination.rstrip()}
"""


def merge_haproxy_config(current: str, managed: str) -> str:
    """Append our frontends to haproxy.cfg, replacing prior Ken-net content idempotently."""
    lines = current.splitlines()
    kept = []
    skipping = False
    for line in lines:
        if line.strip() == HAPROXY_BEGIN:
            skipping = True
            continue
        if skipping:
            if line.strip() == HAPROXY_END:
                skipping = False
            continue
        if line.strip() == ".include /etc/haproxy/conf.d/*.cfg":
            continue
        if line.strip() == "# Include Ken-net public listener configuration":
            continue
        kept.append(line)
    if skipping:
        raise RuntimeError("Unterminated Ken-net HAProxy config marker; refusing to modify it")
    base = "\n".join(kept).rstrip()
    return f"{base}\n\n{HAPROXY_BEGIN}\n{managed.rstrip()}\n{HAPROXY_END}\n"


def render_nginx(domain: str, *, include_tls: bool = True) -> str:
    if not services_manager.DOMAIN_RE.fullmatch(domain):
        raise ValueError("Configure a valid domain and TLS certificate first")
    cert = f"/etc/letsencrypt/live/{domain}"
    # The old published Trojan profile uses /whatever/trojan-ws. Keep the
    # previous /trojan-ws URL as an alias and normalize both for Xray.
    ws_locations = {
        "/ssh-ws": (10015, "/ssh-ws"),
        "/dropbear-ws": (10015, "/dropbear-ws"),
        "/openvpn-ws": (10015, "/openvpn-ws"),
        "/vless": (10001, "/vless"),
        "/vmess": (10002, "/vmess"),
        "/trojan-ws": (10003, "/whatever/trojan-ws"),
        "/whatever/trojan-ws": (10003, "/whatever/trojan-ws"),
        "/ss-ws": (10004, "/ss-ws"),
    }
    ws = "\n".join(
        f"    location = {path} {{\n"
        "        proxy_pass http://127.0.0.1:" + str(port) + upstream_path + ";\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        "        proxy_set_header Connection \"upgrade\";\n"
        "        proxy_set_header X-Real-Host $http_x_real_host;\n"
        "        proxy_read_timeout 1h;\n"
        "    }"
        for path, (port, upstream_path) in ws_locations.items()
    )
    legacy_root = """    location = / {
        proxy_pass http://127.0.0.1:10015;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1h;
    }
"""
    grpc_locations = "\n".join(
        f"    location ^~ /{name}-grpc/ {{\n"
        f"        grpc_pass grpc://127.0.0.1:{port};\n"
        "        grpc_read_timeout 1h;\n"
        "    }"
        for name, port in (("vless", 10005), ("vmess", 10006), ("trojan", 10007), ("ss", 10008))
    )
    tls_server = f"""server {{
    listen 127.0.0.1:8443 ssl http2;
    server_name {domain};
    ssl_certificate {cert}/fullchain.pem;
    ssl_certificate_key {cert}/privkey.pem;
{ws}
{grpc_locations}
    location / {{ return 404; }}
}}
""" if include_tls else ""
    return f"""# Managed by Ken-net.
server {{
    listen 127.0.0.1:8081 http2;
    server_name {domain};
    location ^~ /.well-known/acme-challenge/ {{ root /var/www/letsencrypt; }}
{legacy_root}
{ws}
{grpc_locations}
    location / {{ return 404; }}
}}
{tls_server}
server {{
    listen 0.0.0.0:81;
    server_name _;
    location / {{ return 200 'KEN-NET service gateway\\n'; add_header Content-Type text/plain; }}
}}
"""


def _run(args: list[str]) -> str:
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result.stdout.strip()


def _atomic(path: Path, text: str, mode: int = 0o644) -> None:
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    except Exception:
        Path(temp).unlink(missing_ok=True)
        raise


def install_websocket_service(source_dir: Path | None = None) -> None:
    if source_dir is None:
        source_dir = Path(__file__).resolve().parent
    source = source_dir / "websocket_tunnel.py"
    if not source.is_file():
        raise FileNotFoundError(f"WebSocket tunnel source is missing: {source}")
    WS_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, WS_SCRIPT)
    os.chmod(WS_SCRIPT, 0o755)
    unit = """[Unit]
Description=Ken-net restricted WebSocket TCP tunnel
After=network-online.target ssh.service
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/lib/kennet-panel/websocket_tunnel.py --listen 127.0.0.1:10015
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
[Install]
WantedBy=multi-user.target
"""
    _atomic(WS_UNIT, unit)
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", "--now", "kennet-websocket.service"])


def install() -> None:
    """Install on a clean staging host after the shared domain certificate exists."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Run as root")
    state = services_manager.state()
    domain = state.get("domain", "")
    if not domain:
        raise ValueError("Set the shared domain and install its TLS certificate first")
    for package, executable in (("haproxy", "haproxy"), ("nginx", "nginx")):
        if not shutil.which(executable):
            services_manager.install_ubuntu_package(package)
    # Keep distro defaults disabled so there is a single intentional owner of 80/443.
    default_site = Path("/etc/nginx/sites-enabled/default")
    default_site.unlink(missing_ok=True)
    cert_available = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").is_file() and Path(f"/etc/letsencrypt/live/{domain}/privkey.pem").is_file()
    site_text = render_nginx(domain, include_tls=cert_available)
    _atomic(NGINX_SITE, site_text)
    NGINX_LINK.parent.mkdir(parents=True, exist_ok=True)
    if NGINX_LINK.is_symlink() or NGINX_LINK.exists():
        NGINX_LINK.unlink()
    NGINX_LINK.symlink_to(NGINX_SITE)
    HAPROXY_CFG.parent.mkdir(parents=True, exist_ok=True)
    cert_available = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").is_file() and Path(f"/etc/letsencrypt/live/{domain}/privkey.pem").is_file()
    haproxy_cert = Path(f"/etc/haproxy/certs/{domain}.pem")
    if cert_available:
        haproxy_cert.parent.mkdir(parents=True, exist_ok=True)
        _atomic(haproxy_cert, Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").read_text(encoding="utf-8") +
                Path(f"/etc/letsencrypt/live/{domain}/privkey.pem").read_text(encoding="utf-8"), 0o600)
    managed_config = render_haproxy(str(haproxy_cert) if cert_available else None)
    _atomic(HAPROXY_CFG, managed_config)
    config = Path("/etc/haproxy/haproxy.cfg")
    current = config.read_text(encoding="utf-8") if config.exists() else ""
    if "global\n" not in current or "defaults\n" not in current:
        raise RuntimeError("Unexpected HAProxy configuration; refusing to replace it")
    merged = merge_haproxy_config(current, managed_config)
    _atomic(config, merged)
    # Validate both complete configs before restarting either public daemon.
    try:
        _run(["nginx", "-t"])
        _run(["haproxy", "-c", "-f", str(config)])
    except Exception:
        _atomic(config, current)
        raise
    install_websocket_service()
    _run(["systemctl", "enable", "nginx.service", "haproxy.service"])
    _run(["systemctl", "restart", "nginx.service", "haproxy.service"])
    services_manager.open_ports([("tcp", 80), ("tcp", 81), ("tcp", 443), ("tcp", 8080)])


def is_ready() -> tuple[bool, str]:
    """Check the public HTTP/TLS gateway used by Xray, OpenVPN, and Dropbear.

    The optional WebSocket bridge serves SSH-style tunnels on a separate local
    port; Xray WebSocket and gRPC are proxied directly by Nginx to Xray. Do not
    let a stopped bridge mark the Xray TLS gateway unavailable.
    """
    missing = [unit for unit in ("haproxy", "nginx")
               if subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode]
    ports = {80, 443, 8080, 8081, 8443}
    try:
        domain = services_manager.state().get("domain", "")
        if domain and Path(f"/etc/haproxy/certs/{domain}.pem").is_file():
            ports.add(8444)
    except (OSError, ValueError):
        pass
    if missing:
        return False, "Inactive gateway services: " + ", ".join(missing)
    listeners = subprocess.run(["ss", "-Hlnt"], text=True, capture_output=True, check=False).stdout
    missing_ports = [p for p in ports if not any(line.split()[3].endswith(f":{p}") for line in listeners.splitlines() if len(line.split()) > 3)]
    if missing_ports:
        return False, "Expected listeners missing: " + ", ".join(map(str, sorted(missing_ports)))
    return True, "HAProxy/Nginx public HTTP/TLS gateway and expected listeners are active"


def websocket_bridge_ready() -> tuple[bool, str]:
    """Report the standalone SSH/OpenVPN WebSocket TCP bridge independently."""
    if subprocess.run(["systemctl", "is-active", "--quiet", "kennet-websocket"], check=False).returncode:
        return False, "kennet-websocket service is inactive"
    listeners = subprocess.run(["ss", "-Hlnt"], text=True, capture_output=True, check=False).stdout
    if not any(line.split()[3].endswith(":10015") for line in listeners.splitlines() if len(line.split()) > 3):
        return False, "Expected WebSocket bridge listener 127.0.0.1:10015 is missing"
    return True, "WebSocket bridge is active on 127.0.0.1:10015"
