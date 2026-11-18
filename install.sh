#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh" >&2
  exit 1
fi

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/opt/kennet-panel"
REQUIRED=(panel.py services_manager.py service_catalog.py terminal_ui.py settings_manager.py dropbear_manager.py wireguard_manager.py dnstt_manager.py dnstt_mux.py udp_custom_manager.py gateway_manager.py websocket_tunnel.py openvpn_manager.py ssh_ip_limit.py)

for file in "${REQUIRED[@]}"; do
  if [[ ! -f "${SOURCE_DIR}/${file}" ]]; then
    echo "Missing project file: ${file}" >&2
    exit 1
  fi
done

(cd "${SOURCE_DIR}" && python3 -m unittest -v)
python3 -m py_compile "${SOURCE_DIR}/panel.py" "${SOURCE_DIR}/services_manager.py" "${SOURCE_DIR}/service_catalog.py" "${SOURCE_DIR}/terminal_ui.py" "${SOURCE_DIR}/settings_manager.py" "${SOURCE_DIR}/dropbear_manager.py" "${SOURCE_DIR}/wireguard_manager.py" \
  "${SOURCE_DIR}/dnstt_manager.py" "${SOURCE_DIR}/dnstt_mux.py" "${SOURCE_DIR}/udp_custom_manager.py" \
  "${SOURCE_DIR}/gateway_manager.py" "${SOURCE_DIR}/websocket_tunnel.py" "${SOURCE_DIR}/openvpn_manager.py" "${SOURCE_DIR}/ssh_ip_limit.py"

install -d -o root -g root -m 0755 "${DEST_DIR}"
for file in "${REQUIRED[@]}"; do
  install -o root -g root -m 0644 "${SOURCE_DIR}/${file}" "${DEST_DIR}/${file}"
done

# The public gateway runs a separate copy of the WebSocket bridge. Keep that
# runtime copy in sync during upgrades; updating /opt alone leaves the old
# daemon running (which rejects the legacy HTTP Custom ACL handshake).
if command -v systemctl >/dev/null 2>&1 && systemctl cat kennet-websocket.service >/dev/null 2>&1; then
  install -d -o root -g root -m 0755 /usr/local/lib/kennet-panel
  install -o root -g root -m 0755 "${SOURCE_DIR}/websocket_tunnel.py" \
    /usr/local/lib/kennet-panel/websocket_tunnel.py
  systemctl restart kennet-websocket.service

  # Re-render the existing managed gateway so transport fixes reach Nginx and
  # HAProxy too. Skip clean hosts or installations without a domain certificate.
  python3 - "${DEST_DIR}" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import gateway_manager
import services_manager

domain = services_manager.state().get("domain", "")
certificate = Path(f"/etc/letsencrypt/live/{domain}") if domain else None
if certificate and (certificate / "fullchain.pem").is_file() and (certificate / "privkey.pem").is_file():
    gateway_manager.install()
PY
fi

install -o root -g root -m 0644 "${SOURCE_DIR}/README.md" "${DEST_DIR}/README.md"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_panel.py" "${DEST_DIR}/test_panel.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_protocol_additions.py" "${DEST_DIR}/test_protocol_additions.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_services_manager.py" "${DEST_DIR}/test_services_manager.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_service_catalog.py" "${DEST_DIR}/test_service_catalog.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_gateway_manager.py" "${DEST_DIR}/test_gateway_manager.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_openvpn_manager.py" "${DEST_DIR}/test_openvpn_manager.py"

cat > /usr/local/bin/kennet-panel <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /opt/kennet-panel/panel.py
EOF
chown root:root /usr/local/bin/kennet-panel
chmod 0750 /usr/local/bin/kennet-panel

echo "Installed. Start the terminal menu with: sudo kennet-panel"
echo "SSH, Dropbear, Xray, OpenVPN, UDP Custom, WireGuard, DNSTT, TLS, and WebSocket managers are included."
echo "Configure the shared domain/TLS gateway before creating Xray, Dropbear WebSocket, or OpenVPN TCP/443 accounts."
