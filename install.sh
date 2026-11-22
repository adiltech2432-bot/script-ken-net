#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh" >&2
  exit 1
fi

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/opt/kennet-panel"
BUILD_ID="${KENNET_BUILD_ID:-}"
if [[ -z "${BUILD_ID}" ]]; then
  BUILD_ID="$(git -C "${SOURCE_DIR}" rev-parse --verify HEAD 2>/dev/null || true)"
fi
if [[ -z "${BUILD_ID}" ]]; then
  BUILD_ID="local-$(date -u +%Y%m%dT%H%M%SZ)"
fi
REQUIRED=(VERSION panel.py dashboard_tui.py services_manager.py service_catalog.py terminal_ui.py settings_manager.py dropbear_manager.py wireguard_manager.py dnstt_manager.py dnstt_mux.py udp_custom_manager.py gateway_manager.py websocket_tunnel.py openvpn_manager.py ssh_ip_limit.py)

for file in "${REQUIRED[@]}"; do
  if [[ ! -f "${SOURCE_DIR}/${file}" ]]; then
    echo "Missing project file: ${file}" >&2
    exit 1
  fi
done

(cd "${SOURCE_DIR}" && python3 -m unittest -v)
python3 -m py_compile "${SOURCE_DIR}/panel.py" "${SOURCE_DIR}/dashboard_tui.py" "${SOURCE_DIR}/services_manager.py" "${SOURCE_DIR}/service_catalog.py" "${SOURCE_DIR}/terminal_ui.py" "${SOURCE_DIR}/settings_manager.py" "${SOURCE_DIR}/dropbear_manager.py" "${SOURCE_DIR}/wireguard_manager.py" \
  "${SOURCE_DIR}/dnstt_manager.py" "${SOURCE_DIR}/dnstt_mux.py" "${SOURCE_DIR}/udp_custom_manager.py" \
  "${SOURCE_DIR}/gateway_manager.py" "${SOURCE_DIR}/websocket_tunnel.py" "${SOURCE_DIR}/openvpn_manager.py" "${SOURCE_DIR}/ssh_ip_limit.py"

install -d -o root -g root -m 0755 "${DEST_DIR}"
if [[ -f "${DEST_DIR}/panel.py" ]] && ! cmp -s "${SOURCE_DIR}/panel.py" "${DEST_DIR}/panel.py"; then
  backup="${DEST_DIR}/panel.py.bak.$(date +%F-%H%M%S)"
  cp -a "${DEST_DIR}/panel.py" "${backup}"
  echo "Saved previous panel to ${backup}"
fi
GATEWAY_CHANGED=0
BRIDGE_CHANGED=0
if [[ -f "${DEST_DIR}/gateway_manager.py" ]] && ! cmp -s "${SOURCE_DIR}/gateway_manager.py" "${DEST_DIR}/gateway_manager.py"; then
  GATEWAY_CHANGED=1
fi
if [[ -f /usr/local/lib/kennet-panel/websocket_tunnel.py ]] && ! cmp -s "${SOURCE_DIR}/websocket_tunnel.py" /usr/local/lib/kennet-panel/websocket_tunnel.py; then
  BRIDGE_CHANGED=1
elif [[ ! -f /usr/local/lib/kennet-panel/websocket_tunnel.py ]] && systemctl cat kennet-websocket.service >/dev/null 2>&1; then
  BRIDGE_CHANGED=1
fi
for file in "${REQUIRED[@]}"; do
  install -o root -g root -m 0644 "${SOURCE_DIR}/${file}" "${DEST_DIR}/${file}"
done
RELEASE_VERSION="$(tr -d '[:space:]' < "${SOURCE_DIR}/VERSION")"
printf '%s (%s)\n' "${RELEASE_VERSION}" "${BUILD_ID:0:12}" > "${DEST_DIR}/BUILD"
chown root:root "${DEST_DIR}/BUILD"
chmod 0644 "${DEST_DIR}/BUILD"

# Make sure expiry enforcement is enabled on existing installations and fresh
# hosts, including hosts that already have managed accounts.
python3 - "${DEST_DIR}" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import services_manager
services_manager.install_expiry_timer()
PY

# Restart the WebSocket bridge only when its runtime code changed. This keeps
# unrelated account-manager updates from interrupting working SSH transports.
if command -v systemctl >/dev/null 2>&1 && systemctl cat kennet-websocket.service >/dev/null 2>&1; then
  if [[ "${BRIDGE_CHANGED}" -eq 1 ]]; then
    install -d -o root -g root -m 0755 /usr/local/lib/kennet-panel
    install -o root -g root -m 0755 "${SOURCE_DIR}/websocket_tunnel.py" \
      /usr/local/lib/kennet-panel/websocket_tunnel.py
    systemctl restart kennet-websocket.service
  fi

  # Re-render only when the gateway implementation itself changed. Account
  # expiry/UI updates leave existing SSH-WS/TLS/Trojan/VLESS routing untouched.
  if [[ "${GATEWAY_CHANGED}" -eq 1 ]]; then
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
fi

# An Xray daemon can be healthy while forwarding nowhere if its existing
# configuration has an empty outbounds list. Repair only that empty case and
# preserve every configured inbound/account and any existing outbound setup.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray.service && \
   [[ -f /usr/local/etc/xray/config.json ]]; then
  python3 - "${DEST_DIR}" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
import services_manager

try:
    outbound_updated, stats_updated, transport_updated = services_manager.configure_xray_online_stats()
    if outbound_updated:
        print("Repaired Xray: added the missing direct freedom outbound.")
    if stats_updated:
        print("Enabled Xray per-account online IP statistics through a loopback-only API.")
    if transport_updated:
        print("Updated Xray WebSocket/gRPC transports to trust client IPs forwarded by the local gateway.")
except Exception as exc:
    print(f"Warning: Xray per-account online statistics were not enabled: {exc}", file=sys.stderr)
PY
fi

install -o root -g root -m 0644 "${SOURCE_DIR}/README.md" "${DEST_DIR}/README.md"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_panel.py" "${DEST_DIR}/test_panel.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_dashboard_tui.py" "${DEST_DIR}/test_dashboard_tui.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_protocol_additions.py" "${DEST_DIR}/test_protocol_additions.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_services_manager.py" "${DEST_DIR}/test_services_manager.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_service_catalog.py" "${DEST_DIR}/test_service_catalog.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_gateway_manager.py" "${DEST_DIR}/test_gateway_manager.py"
install -o root -g root -m 0644 "${SOURCE_DIR}/test_openvpn_manager.py" "${DEST_DIR}/test_openvpn_manager.py"

cat > /usr/local/bin/kennet-panel <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--version" ]; then
  printf 'KEN-NET build: '
  cat /opt/kennet-panel/BUILD
  exit 0
fi
exec /usr/bin/python3 /opt/kennet-panel/panel.py "$@"
EOF
chown root:root /usr/local/bin/kennet-panel
chmod 0750 /usr/local/bin/kennet-panel

echo "Installed KEN-NET v${RELEASE_VERSION} build ${BUILD_ID:0:12}. Verify with: sudo kennet-panel --version"
echo "Start the terminal menu with: sudo kennet-panel"
echo "SSH, Dropbear, Xray, OpenVPN, UDP Custom, WireGuard, DNSTT, TLS, and WebSocket managers are included."
echo "Configure the shared domain/TLS gateway before creating Xray, Dropbear WebSocket, or OpenVPN TCP/443 accounts."
