# Ken-net Terminal Manager

An editable terminal manager for Ubuntu servers. This package provides independent setup and account management for WireGuard and DNSTT. SSH and Xray protocol actions delegate to helper commands from the original server installation. Those legacy helpers are not installed by this package, so a fresh Ubuntu server will not get full SSH/Xray account provisioning from it.

## WireGuard

- Installs `wireguard-tools` and `iptables` when server setup is selected.
- Creates an IPv4 interface, configures forwarding and NAT, and starts `wg-quick@<interface>`.
- Creates a unique key, address, and mode `0600` client profile for each peer.
- Removes a peer from the live interface and configuration file, then deletes its client profile.
- You must open the selected UDP port in your VPS provider firewall. The setup does not change the provider firewall.

## DNSTT

- Creates a separate server key, systemd service, and DNS route for each account name.
- Removing an account stops its endpoint and removes its service, key, and route. Everyone using that endpoint will be disconnected.
- Requires a domain you control and a DNS nameserver outside the delegated tunnel zone. The manager can build the official `dnstt-server` and `dnstt-client` tools, but it does not change DNS provider records.
- Prints DNS records to add for each account. UDP/53 must reach the DNS router.
- Refuses to install its router while the old `server.service` is active. Use a separate test VPS so the existing SlowDNS service is not disrupted.

**Security note:** Official DNSTT authenticates the server, not the client. A domain and public key are not a client password. Anyone with an endpoint's connection details can use it; removing that endpoint disconnects all its users. For per-client authentication, forward the tunnel to a backend that requires separate credentials. [Official DNSTT documentation](https://github.com/Mygod/dnstt/blob/plugin/README#encryption-and-authentication).

## Install and run

On Ubuntu, run:

```bash
curl -fsSL https://raw.githubusercontent.com/adiltech2432-bot/script-ken-net/main/install-remote.sh | sudo bash
sudo kennet-panel
```

Alternatively, download the repository and run `sudo bash install.sh` from its directory. Select WireGuard or DNSTT from the terminal menu. WireGuard setup asks before installing packages and changing routing settings. DNSTT setup builds the official tools when requested, then prompts for the domain and forwarding destination. Do not install the DNSTT router on the old server while its existing SlowDNS service is using DNS.

## Verification

The local tests cover WireGuard address allocation, peer configuration updates, client profiles, DNS question parsing and routing, and DNSTT account-name validation. They do not connect to a live VPS or verify an external client connection. Before production use, test WireGuard from a client and configure DNS records and test DNSTT on a separate VPS.

Run the local tests with:

```bash
python3 -m unittest -v
```

Do not share WireGuard client profiles or DNSTT private keys; they contain secret key material.
