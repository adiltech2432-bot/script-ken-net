#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh" >&2
  exit 1
fi

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/opt/kennet-panel"
REQUIRED=(panel.py services_manager.py service_catalog.py terminal_ui.py settings_manager.py dropbear_manager.py wireguard_manager.py dnstt_manager.py dnstt_mux.py udp_custom_manager.py gateway_manager.py websocket_tunnel.py openvpn_manager.py)

for file in "${REQUIRED[@]}"; do
  if [[ ! -f "${SOURCE_DIR}/${file}" ]]; then
    echo "Missing project file: ${file}" >&2
    exit 1
  fi
done

(cd "${SOURCE_DIR}" && python3 -m unittest -v)
python3 -m py_compile "${SOURCE_DIR}/panel.py" "${SOURCE_DIR}/services_manager.py" "${SOURCE_DIR}/service_catalog.py" "${SOURCE_DIR}/terminal_ui.py" "${SOURCE_DIR}/settings_manager.py" "${SOURCE_DIR}/dropbear_manager.py" "${SOURCE_DIR}/wireguard_manager.py" \
  "${SOURCE_DIR}/dnstt_manager.py" "${SOURCE_DIR}/dnstt_mux.py" "${SOURCE_DIR}/udp_custom_manager.py" \
  "${SOURCE_DIR}/gateway_manager.py" "${SOURCE_DIR}/websocket_tunnel.py" "${SOURCE_DIR}/openvpn_manager.py"

install -d -o root -g root -m 0755 "${DEST_DIR}"
for file in "${REQUIRED[@]}"; do
  install -o root -g root -m 0644 "${SOURCE_DIR}/${file}" "${DEST_DIR}/${file}"
done
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
