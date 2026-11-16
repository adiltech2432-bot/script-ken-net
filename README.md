# Ken-net Terminal Manager

An editable English terminal manager for Ubuntu 24.04. The home screen is a colored server dashboard with system metrics, domain, account/session counts, and a two-column protocol menu.

## Managed features

- **SSH:** create accounts with generated passwords, renew, delete, view details, create one-day trials, list managed accounts, view connected login sessions, and automatically remove expired accounts.
- **Dropbear:** install a separate Dropbear service on TCP/109 and TCP/143 and manage accounts through the shared SSH account store.
- **VLESS, VMess, Trojan:** install Xray-core; create TLS accounts, print client links, renew, delete, view details, create one-day trials, list accounts, view aggregate established connection counts, and automatically expire accounts. Config changes are checked before restarting Xray. Default ports are TCP/443, TCP/8443, and TCP/2053.
- **TLS/domain:** setting a domain immediately checks DNS and requests/installs a Let's Encrypt certificate using Certbot's no-email registration mode. The DNS A/AAAA record must already point to this VPS. TCP/80 must be reachable and unused for standalone issuance, and reachable for renewal. If configured APT mirrors fail, the manager retries using official Ubuntu archives for Certbot without editing the server's APT source files. The manager does not edit DNS provider records.
- **WireGuard:** configure a server and create peers/client profiles; renew, delete, inspect, create one-day trial peers, list accounts, view recent-handshake status, and automatically remove expired peers.
- **DNSTT:** configure a delegated DNS zone and router, create isolated endpoints with their own server keys and services, renew/delete/inspect/list endpoints, create one-day trials, view service state, and automatically remove expired endpoints.

The **Services / Ports** screen catalogs the services and ports shown in the supplied reference images. It also identifies shared-port conflicts. It does not imply that every listed daemon is installed or managed.

## Important protocol limits

- **OpenVPN, legacy UDP Custom, standalone WebSocket bridges, Shadowsocks standalone transport menus, Nginx, and HAProxy** are not implemented as account backends in this build. Their service/port entries are informational, and the terminal reports these protocols as unavailable.
- **TLS** is a certificate transport used by Xray accounts, not a standalone account protocol.
- **UDP Custom** is not one standard protocol; the compatible server and client format have to be selected before implementing its account lifecycle.
- **SlowDNS** implementations often use proprietary client formats. This project offers the separate-endpoint DNSTT manager, not a drop-in SlowDNS replacement.
- Vanilla DNSTT authenticates the server, not the client. Anyone with endpoint details can use that endpoint. Removing it stops the endpoint for all users. [DNSTT authentication documentation](https://github.com/Mygod/dnstt/blob/plugin/README#encryption-and-authentication).
- Xray connection counts are established TCP sockets, not unique user counts. DNSTT status reports endpoint services; DNSTT does not authenticate or count individual clients.
- Public DNS records, provider firewalls, and domain ownership are external prerequisites. The manager cannot configure them.
- This build has not been tested against a live VPS or external VPN clients. Validate each client connection after configuring DNS and provider firewall rules.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/adiltech2432-bot/script-ken-net/main/install-remote.sh | sudo bash
sudo kennet-panel
```

The installer runs the local test suite and copies the manager to `/opt/kennet-panel`.

## Domains and ports

Set the shared domain from the TLS/domain menu; the manager checks DNS and requests a certificate without asking for an email address. Point the domain's A/AAAA record to the VPS first. Certificate issuance needs inbound TCP/80, and standalone issuance cannot proceed while another service is listening on TCP/80. Xray defaults are TCP/443 (VLESS), TCP/8443 (VMess), and TCP/2053 (Trojan). SSH uses TCP/22. WireGuard uses its configured UDP port (51820 by default). DNSTT listens on UDP/53 by default.

The catalog also includes TCP/109 and TCP/143 (Dropbear), TCP/1194 and UDP/2200 (OpenVPN), TCP/80/81/443 (web frontend), and UDP/7100/7200/7300 (BadVPN gateway). OpenVPN and the other informational services are not necessarily enabled. TCP/80 and TCP/443 cannot be independently bound by multiple services; a compatible frontend is required to multiplex them.

When UFW is active, the manager asks before adding narrow firewall allowances. It does not enable UFW, since doing so without reviewing SSH access can lock out the server. Provider-side firewall rules must be configured in the VPS control panel.

Run local tests with `python3 -m unittest -v`.
