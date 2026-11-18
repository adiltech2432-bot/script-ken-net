# Ken-net Terminal Manager

An editable English terminal manager for Ubuntu 24.04. The home screen is a colored server dashboard with system metrics, domain, account/session counts, and separate card menus for protocols and settings. Account creation immediately displays protocol-specific connection details.

The **System settings** cards include running-service status, the port catalog, confirmed restart of active managed services, domain/certificate setup, DNSTT nameserver and per-endpoint key rotation, SSH banner editing, VPS speed test, WebSocket capability status, and confirmed VPS reboot.

## Managed features

- **SSH:** create accounts with manually entered passwords and an optional maximum number of simultaneous distinct remote IPs, renew, delete, view details, create one-day trials, list managed accounts, view connected login sessions/IPs, and automatically remove expired accounts. IP limits are enforced by a managed PAM account hook for SSH logins; `0` means unlimited. Passwords are stored only as Linux password hashes and cannot be re-displayed after creation.
- **Dropbear:** install a separate Dropbear service on TCP/143 and an internal backend on TCP/2109. HAProxy multiplexes raw SSH and WebSocket HTTP on TCP/109; manage Dropbear logins through the shared SSH account store.
- **VLESS, VMess, Trojan, Shadowsocks:** install Xray-core; create accounts and client links, renew, delete, inspect, create one-day trials, list accounts, view aggregate established connection counts, and automatically expire accounts. TLS WebSocket and gRPC share TCP/443 through HAProxy and Nginx; VLESS/VMess cleartext WebSocket uses TCP/80. Verified legacy profiles use the account name as VLESS/VMess ID and Trojan password; VLESS/VMess IDs must be under 30 bytes. The WebSocket paths are `/vless`, `/vmess`, and `/whatever/trojan-ws` (the previous `/trojan-ws` URL remains an alias). Xray listens only on loopback ports 10001–10008.
- **Shared TCP gateway and WebSocket:** HAProxy owns public TCP/80, TCP/443, TCP/8080, and TCP/109. It routes HTTP Custom's legacy `ACL /` raw SSH tunnel, standard WebSocket, TLS-wrapped raw SSH, Xray HTTP/2/WebSocket, and OpenVPN TCP handshakes. TLS is terminated at HAProxy when a certificate is available; the decrypted HTTP traffic goes to Nginx on loopback TCP/8081. TCP/8080 supports the legacy HTTP Custom remote-proxy profile. TCP/81 exposes a health response. TCP/143 is direct Dropbear.
- **OpenVPN:** install certificate-authenticated TCP/1194, TCP/443 via the shared handshake multiplexer, and UDP/2200. Each account receives three embedded-certificate client profiles and can be renewed, revoked, listed, inspected, or expired. The TCP/443 profile uses the domain certificate only at the frontend where applicable; OpenVPN itself authenticates with its own CA.
- **UDP Custom:** install the upstream ePro UDP-Custom server and manage individual Linux username/password accounts. Its UDP/1–65535 DNAT rule explicitly excludes UDP/53, UDP/2200 and WireGuard's configured port. It requires a compatible HTTP Custom client; the project does not implement that client protocol.
- **TLS/domain:** setting a domain checks DNS and requests/installs a Let's Encrypt certificate using Certbot's no-email registration mode. The DNS A/AAAA record must already point to this VPS. Certificate HTTP-01 issuance and renewal require inbound TCP/80. If configured APT mirrors fail, the manager retries official Ubuntu archives without editing the server's APT source files. DNS provider records are not edited.
- **WireGuard:** configure a server and create peers/client profiles; renew, delete, inspect, create one-day trial peers, list accounts, view recent-handshake status, and automatically remove expired peers.
- **DNSTT:** configure a delegated DNS zone and router, create isolated endpoints with their own server keys and services, renew/delete/inspect/list endpoints, create one-day trials, view service state, and automatically remove expired endpoints.

The **Services / Ports** screen describes the implemented public ports and the listeners that share them. HAProxy/Nginx path and handshake routing is required because several protocols share TCP/80 and TCP/443.

## Important protocol limits

- **UDP Custom** downloads the upstream ePro x86_64 binary. Its wire protocol is proprietary; use a compatible client. The broad UDP range is implemented with exclusions for DNSTT, OpenVPN and WireGuard.
- **TLS** is a certificate transport used by Xray accounts, not a standalone account protocol.
- VLESS, Trojan, and VMess legacy links use `Google.com` as SNI and disable certificate verification to match the supplied working profiles. This compatibility setting weakens TLS server identity verification; use domain SNI with verification enabled when the client profile supports it.
- **UDP Custom** is not one standard protocol; the compatible server and client format have to be selected before implementing its account lifecycle.
- **SlowDNS** implementations often use proprietary client formats. This project offers the separate-endpoint DNSTT manager, not a drop-in SlowDNS replacement.
- Vanilla DNSTT authenticates the server, not the client. Anyone with endpoint details can use that endpoint. Removing it stops the endpoint for all users. [DNSTT authentication documentation](https://github.com/Mygod/dnstt/blob/plugin/README#encryption-and-authentication).
- Xray connection counts are established TCP sockets, not unique user counts. DNSTT status reports endpoint services; DNSTT does not authenticate or count individual clients.
- Public DNS records, provider firewalls, and domain ownership are external prerequisites. The manager cannot configure them.
- Local unit/integration tests validate generated configs, menus and the WebSocket bridge. They do not prove external client connectivity. Each service must still be exercised on a clean Ubuntu 24.04 VPS after DNS and provider firewall setup.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/adiltech2432-bot/script-ken-net/main/install-remote.sh | sudo bash
sudo kennet-panel
```

The installer runs the local test suite and copies the manager to `/opt/kennet-panel`.

## Domains and ports

Set the shared domain from the TLS/domain menu; the manager checks DNS and requests a certificate without asking for an email address. Point the domain's A/AAAA record to the VPS first. Certificate issuance needs inbound TCP/80. OpenSSH uses TCP/22; legacy HTTP Custom proxy profiles also need TCP/8080 reachable through the selected DNS proxy. SSH WebSocket uses TCP/80 and 8080; TLS-wrapped SSH and Xray TLS WebSocket/gRPC use TCP/443. VLESS/VMess cleartext WebSocket uses TCP/80. OpenVPN uses TCP/1194, TCP/443 and UDP/2200. Dropbear uses TCP/143 plus TCP/109 multiplexing. WireGuard uses its configured UDP port (51820 by default). DNSTT uses UDP/53.

UDP Custom claims UDP/1–65535 using DNAT, excluding UDP/53, UDP/2200 and WireGuard's configured port. HAProxy is the sole public listener on TCP/80, TCP/109, TCP/443, and TCP/8080; Nginx and Xray use loopback backends. DNSTT and OpenVPN UDP are separate public UDP listeners.

When UFW is active, the manager asks before adding narrow firewall allowances. It does not enable UFW, since doing so without reviewing SSH access can lock out the server. Provider-side firewall rules must be configured in the VPS control panel.

Run local tests with `python3 -m unittest -v`.
