# Ken-net Terminal Manager

Editable terminal management for Ubuntu 24.04. The manager has separate menus for SSH, TLS/domain certificates, VLESS, VMess, Trojan, UDP, WireGuard, SlowDNS, and DNSTT.

## Implemented account services

- **SSH:** installs OpenSSH Server, creates expiring Linux users with generated passwords, lists and deletes managed accounts.
- **VLESS, VMess, Trojan:** installs official Xray-core, stores accounts in Xray JSON, validates configuration before service restart, prints client links, and removes accounts. These use TCP+TLS on ports 443, 8443, and 2053.
- **TLS:** stores the shared domain and obtains a Let's Encrypt certificate. The domain's DNS A/AAAA record must point to this VPS. TCP/80 must be reachable for initial issuance and renewal.
- **WireGuard:** creates the server interface, configures IPv4 forwarding/NAT, provisions named peers and mode-0600 client files, and revokes peers.
- **DNSTT:** creates separate endpoints with separate server keys and systemd services, and removes them individually. Requires DNS delegation and UDP/53.

TLS is a transport setting for the Xray accounts, not a standalone account protocol. UDP is not a single standardized account protocol; the current menu reports it as unsupported rather than claiming a working account system. SlowDNS and DNSTT use overlapping DNS-tunnel technology; the DNSTT manager implements isolated account endpoints, but it does not reproduce proprietary client-specific SlowDNS formats.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/adiltech2432-bot/script-ken-net/main/install-remote.sh | sudo bash
sudo kennet-panel
```

The installer runs the local test suite and copies the terminal manager to `/opt/kennet-panel`.

## Domains and ports

Set the shared domain from the TLS/domain menu, then point its DNS A/AAAA record to the VPS. TLS certificate issuance needs inbound TCP/80. Xray account inbounds use TCP/443 (VLESS), TCP/8443 (VMess), and TCP/2053 (Trojan). SSH uses TCP/22 by default. WireGuard uses the UDP port selected during setup (51820 by default). DNSTT listens on UDP/53 by default.

When UFW is already active, the manager asks before adding only the needed host firewall allowances. It does not enable UFW, because enabling a host firewall without reviewing SSH access can lock out the server. A provider-side firewall must be configured separately in the VPS control panel; the script cannot open provider network rules.

## Important limitations

- Account protocols run on the VPS only after their setup menu has installed and configured the service.
- Public DNS records, provider firewalls, and domain ownership are external prerequisites; they cannot be configured automatically by this program.
- The UDP entry requires choosing a specific compatible UDP tunnel implementation and client format before account management can be implemented.
- Vanilla DNSTT authenticates the server, not the client. Anyone who obtains an endpoint's connection details can use it. Removing an endpoint disconnects all users of that endpoint. [Official DNSTT documentation](https://github.com/Mygod/dnstt/blob/plugin/README#encryption-and-authentication).
- No live VPS protocol test is included. Verify each external client connection after configuring DNS and provider firewall rules.

Run local tests with `python3 -m unittest -v`.
