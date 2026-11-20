# Ken-net Terminal Manager

An editable English terminal manager for Ubuntu 24.04. The default home screen is a keyboard-driven colored dashboard with live system metrics, domain, protocol status, listener ports, and account counts. The presentation layer opens the existing protocol managers, so account and service operations continue to use the same backend logic. Protocol numbers retain the original menu IDs even though the dashboard groups cards by service type.

The **System settings** cards include running-service status, the port catalog, confirmed restart of active managed services, domain/certificate setup, DNSTT nameserver and per-endpoint key rotation, SSH banner editing, VPS speed test, WebSocket capability status, and confirmed VPS reboot.

## Managed features

- **SSH:** create one Linux account with a manually entered password and an optional maximum number of simultaneous distinct remote IPs. The same Linux credentials are automatically accepted by whichever compatible SSH transports are installed and active: OpenSSH, Dropbear, the SSH WebSocket/TLS gateway, and UDP Custom. No duplicate per-transport account is created; expiry or deletion of the SSH account therefore revokes those shared logins together. OpenVPN remains certificate-authenticated, while Xray and DNSTT use their own account managers. Renew, delete, inspect, create trials from 1 minute to 24 hours, list accounts, view live SSH TCP sessions/IPs, and automatic expiry are supported. Trial expiry is checked by the one-minute timer, so revocation can occur up to one minute after its selected deadline. The session count is not a physical-device count: one device may open multiple sessions. IP limits are enforced by a managed PAM account hook for OpenSSH logins; `0` means unlimited. Passwords are stored only as Linux password hashes and cannot be re-displayed after creation.
- **Dropbear:** install a separate Dropbear service on TCP/143 and an internal backend on TCP/2109. HAProxy multiplexes raw SSH and WebSocket HTTP on TCP/109; manage Dropbear logins through the shared SSH account store, including 1-minute to 24-hour trials.
- **VLESS, VMess, Trojan, Shadowsocks:** install Xray-core; create accounts and client links, renew, delete, inspect, create trials from 1 minute to 24 hours, list accounts, and automatically expire accounts. Trial expiry is checked by the one-minute timer, so revocation can occur up to one minute after its selected deadline. The current shared Nginx gateway does not expose Xray connections by username, so per-account connection rows are marked unknown rather than presenting a misleading device count. The dashboard's aggregate Xray figures count established inbound TCP sockets, not users or physical devices. TLS WebSocket and gRPC share TCP/443 through HAProxy and Nginx; VLESS/VMess cleartext WebSocket uses TCP/80. Verified legacy profiles use the account name as VLESS/VMess ID and Trojan password; VLESS/VMess IDs must be under 30 bytes. The WebSocket paths are `/vless`, `/vmess`, and `/whatever/trojan-ws` (the previous `/trojan-ws` URL remains an alias). Xray listens only on loopback ports 10001–10008.
- **Shared TCP gateway and WebSocket:** HAProxy owns public TCP/80, TCP/443, TCP/8080, and TCP/109. It routes HTTP Custom's legacy `ACL /` raw SSH tunnel, standard WebSocket, TLS-wrapped raw SSH, Xray HTTP/2/WebSocket, and OpenVPN TCP handshakes. TLS is terminated at HAProxy when a certificate is available; the decrypted HTTP traffic goes to Nginx on loopback TCP/8081. TCP/8080 supports the legacy HTTP Custom remote-proxy profile. TCP/81 exposes a health response. TCP/143 is direct Dropbear.
- **OpenVPN:** install certificate-authenticated TCP/1194, TCP/443 via the shared handshake multiplexer, and UDP/2200. Each account receives three embedded-certificate client profiles and can be renewed, revoked, listed, inspected, or expired; trial certificates can last from 1 minute to 24 hours. The TCP/443 profile uses the domain certificate only at the frontend where applicable; OpenVPN itself authenticates with its own CA.
- **UDP Custom:** install the upstream ePro UDP-Custom server and manage individual Linux username/password accounts. Its UDP/1–65535 DNAT rule explicitly excludes UDP/53, UDP/2200 and WireGuard's configured port. It requires a compatible HTTP Custom client; the project does not implement that client protocol.
- **TLS/domain:** setting a domain checks DNS and requests/installs a Let's Encrypt certificate using Certbot's no-email registration mode. The DNS A/AAAA record must already point to this VPS. Certificate HTTP-01 issuance and renewal require inbound TCP/80. If configured APT mirrors fail, the manager retries official Ubuntu archives without editing the server's APT source files. DNS provider records are not edited.
- **WireGuard:** configure a server and create peers/client profiles; renew, delete, inspect, create trials from 1 minute to 24 hours, list accounts, view recent-handshake status, and automatically remove expired peers. WireGuard has no persistent session; “recent” means a handshake occurred within the last three minutes, not a live device count.
- **DNSTT:** configure a delegated DNS zone and router, create isolated endpoints with their own server keys and services, renew/delete/inspect/list endpoints, create trials from 1 minute to 24 hours, view service state, and automatically remove expired endpoints.

The **Services / Ports** screen describes the implemented public ports and the listeners that share them. HAProxy/Nginx path and handshake routing is required because several protocols share TCP/80 and TCP/443.

## Important protocol limits

- **UDP Custom** downloads the upstream ePro x86_64 binary. Its wire protocol is proprietary; use a compatible client. The broad UDP range is implemented with exclusions for DNSTT, OpenVPN and WireGuard.
- **TLS** is a certificate transport used by Xray accounts, not a standalone account protocol.
- VLESS, Trojan, and VMess legacy links use `Google.com` as SNI and disable certificate verification to match the supplied working profiles. This compatibility setting weakens TLS server identity verification; use domain SNI with verification enabled when the client profile supports it.
- **UDP Custom** is not one standard protocol; the compatible server and client format have to be selected before implementing its account lifecycle.
- **SlowDNS** implementations often use proprietary client formats. This project offers the separate-endpoint DNSTT manager, not a drop-in SlowDNS replacement.
- Vanilla DNSTT authenticates the server, not the client. Anyone with endpoint details can use that endpoint. Removing it stops the endpoint for all users. [DNSTT authentication documentation](https://github.com/Mygod/dnstt/blob/plugin/README#encryption-and-authentication).
- Expired accounts are checked by a systemd timer every minute. Minute-based trials may therefore be revoked up to one minute after their selected deadline. SSH accounts are locked, active sessions terminated, and the Linux login removed; Xray clients are removed from the active config; WireGuard peers are removed; DNSTT endpoints are stopped; and OpenVPN certificates are revoked.
- Xray's shared gateway cannot attribute live connections to an individual account, so per-account connection counts are unavailable. The aggregate Xray count is TCP sockets, not unique users or devices. DNSTT status reports endpoint service state; DNSTT does not authenticate or count individual clients.
- Public DNS records, provider firewalls, and domain ownership are external prerequisites. The manager cannot configure them.
- Local unit/integration tests validate generated configs, menus and the WebSocket bridge. They do not prove external client connectivity. Each service must still be exercised on a clean Ubuntu 24.04 VPS after DNS and provider firewall setup.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/adiltech2432-bot/script-ken-net/main/install-remote.sh | sudo bash
sudo kennet-panel --version
sudo kennet-panel
```

The installer runs the local test suite, backs up the previous `panel.py` when it changes, and copies the manager to `/opt/kennet-panel`. The installer prints the release version and short commit ID; `sudo kennet-panel --version` displays the installed build again. The dashboard uses Python's standard-library `curses`; no third-party TUI package is required.

### Dashboard controls

- **Up/Down** or **J/K:** move through protocol cards.
- **Enter:** open the selected protocol screen. Its tabs show real account rows, route Create/Trial to the existing manager, and report live service/listener details.
- **A:** open the selected existing protocol manager directly.
- On a protocol screen, **Left/Right** or **H/L** changes tabs; **A** shows Accounts, **C** opens Create, **T** opens Trial, **S** shows Service, and **Enter** opens the manager workflow from Create/Trial/Service.
- **Tab:** move focus to Settings & Tools; **Left/Right** selects a tool.
- **1–15:** open the original numbered protocol/tool option directly; **0** opens the exit action.
- **Esc/Backspace:** return from a protocol screen, leave tool focus, or clear the current numeric choice; **Q** asks before exiting from the dashboard.
- The view refreshes every two seconds and responds to terminal resize. It requires at least 80×24; smaller terminals show a resize prompt. Missing listener/account values display `—` instead of a guessed value.

Run `sudo kennet-panel --plain` for a no-color ASCII dashboard or `sudo kennet-panel --legacy` for the original menu. Non-interactive sessions and `TERM=dumb` automatically use the plain dashboard.

## Domains and ports

Set the shared domain from the TLS/domain menu; the manager checks DNS and requests a certificate without asking for an email address. Point the domain's A/AAAA record to the VPS first. Certificate issuance needs inbound TCP/80. OpenSSH uses TCP/22; legacy HTTP Custom proxy profiles also need TCP/8080 reachable through the selected DNS proxy. SSH WebSocket uses TCP/80 and 8080; TLS-wrapped SSH and Xray TLS WebSocket/gRPC use TCP/443. VLESS/VMess cleartext WebSocket uses TCP/80. OpenVPN uses TCP/1194, TCP/443 and UDP/2200. Dropbear uses TCP/143 plus TCP/109 multiplexing. WireGuard uses its configured UDP port (51820 by default). DNSTT uses UDP/53.

UDP Custom claims UDP/1–65535 using DNAT, excluding UDP/53, UDP/2200 and WireGuard's configured port. HAProxy is the sole public listener on TCP/80, TCP/109, TCP/443, and TCP/8080; Nginx and Xray use loopback backends. DNSTT and OpenVPN UDP are separate public UDP listeners.

When UFW is active, the manager asks before adding narrow firewall allowances. It does not enable UFW, since doing so without reviewing SSH access can lock out the server. Provider-side firewall rules must be configured in the VPS control panel.

Run local tests with `python3 -m unittest -v`.
