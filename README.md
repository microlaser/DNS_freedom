# DNS Leak Test — Quad9 DNS-over-TLS on Linux

A comprehensive bash script that tests every layer of DNS privacy and encryption on any Linux system. Written and tested on Debian Trixie (13), compatible with Ubuntu, Fedora, Arch, and any systemd-based distro.

---

## My Setup

**OS:** Debian GNU/Linux 13 (Trixie)  
**Hostname:** DebianDoesDallas  
**DNS Resolver:** [Stubby](https://dnsprivacy.org/dns_privacy_daemon_-_stubby/) — a DNS Privacy Stub Resolver  
**Upstream DNS:** [Quad9](https://quad9.net) (`9.9.9.9` / `149.112.112.112`) via **DNS-over-TLS (DoT) on port 853**  
**Browser DNS:** Brave configured with Quad9 DoH (`https://dns.quad9.net/dns-query`)  
**Protection:** `/etc/resolv.conf` and `/etc/stubby/stubby.yml` locked with `chattr +i`

### Why Quad9?

- **Privacy:** Quad9 does not log or sell your DNS query data
- **Security:** Blocks known malicious domains using threat intelligence feeds
- **DNSSEC:** Full DNSSEC validation on all queries
- **Non-profit:** Operated by the Quad9 Foundation, a Swiss nonprofit

### Architecture

```
Browser (Brave)
    │
    ├── DoH ──────────────────────────────────► Quad9 (https://dns.quad9.net/dns-query)
    │                                               port 443, TLS encrypted
    │
Applications / OS
    │
    └── UDP port 53 ──► Stubby (127.0.0.1:53)
                            │
                            └── DoT ──────────► Quad9 (9.9.9.9:853 / 149.112.112.112:853)
                                                    port 853, TLS encrypted
                                                    cert: dns.quad9.net (DigiCert)
```

**Comcast/ISP cannot see any DNS queries.** All traffic leaving the machine on port 53 is blocked by design — only encrypted TLS on port 853 (DoT) or 443 (DoH) is used.

---

## Verification Results

### Quad9 Official Test — `https://on.quad9.net`
**Result: ✅ YES, you ARE using Quad9**

### tcpdump — No plaintext DNS leak
```bash
tcpdump -i any 'udp port 53 and not host 127.0.0.1' -n
# 0 packets captured — no plaintext DNS leaving the machine
```

### tcpdump — Encrypted DoT traffic confirmed
```bash
tcpdump -i any port 853 -n
# Shows bidirectional TLS traffic: DebianDoesDallas ↔ 9.9.9.9:853
```

### OpenSSL — TLS certificate verified
```
subject=C=CH, ST=Zurich, L=Zurich, O=Quad9, CN=dns.quad9.net
issuer=C=US, O=DigiCert Inc, CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1
Verify return code: 0 (ok)
```

### dig — Local resolver confirmed
```bash
dig a google.com
# SERVER: 127.0.0.1#53(127.0.0.1)  ← stubby is handling all queries
```

### lsattr — Files locked immutable
```
----i---------e------- /etc/resolv.conf
----i---------e------- /etc/stubby/stubby.yml
```

---

## Installation

### 1. Install Stubby

```bash
# Debian/Ubuntu
sudo apt install stubby

# Fedora
sudo dnf install stubby

# Arch
sudo pacman -S stubby
```

### 2. Configure Stubby for Quad9 DoT

```bash
sudo chattr -i /etc/stubby/stubby.yml 2>/dev/null
sudo tee /etc/stubby/stubby.yml <<'EOF'
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1
round_robin_upstreams: 1
idle_timeout: 10000
listen_addresses:
  - 127.0.0.1@53
  - 0::1@53

upstream_recursive_servers:
  - address_data: 9.9.9.9
    tls_port: 853
    tls_auth_name: "dns.quad9.net"
  - address_data: 149.112.112.112
    tls_port: 853
    tls_auth_name: "dns.quad9.net"
  - address_data: 2620:fe::fe
    tls_port: 853
    tls_auth_name: "dns.quad9.net"
  - address_data: 2620:fe::9
    tls_port: 853
    tls_auth_name: "dns.quad9.net"
EOF
```

### 3. Point resolv.conf at Stubby

```bash
sudo chattr -i /etc/resolv.conf 2>/dev/null
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

### 4. Disable competing DNS managers

```bash
# Stop systemd-resolved if active
sudo systemctl disable --now systemd-resolved

# Stop resolvconf if present
sudo systemctl disable --now resolvconf 2>/dev/null || true

# Tell NetworkManager not to manage DNS
sudo mkdir -p /etc/NetworkManager/conf.d
sudo tee /etc/NetworkManager/conf.d/90-no-dns.conf <<'EOF'
[main]
dns=none
systemd-resolved=false
EOF
sudo systemctl reload NetworkManager 2>/dev/null || true
```

### 5. Enable Stubby and lock files

```bash
sudo systemctl enable --now stubby
sudo systemctl restart stubby

sudo chattr +i /etc/resolv.conf
sudo chattr +i /etc/stubby/stubby.yml
```

### 6. Configure Brave browser

Go to `brave://settings/security`:
- **Use secure DNS:** ON
- **DNS provider:** Custom → `https://dns.quad9.net/dns-query`

For Firefox: `about:preferences#privacy` → Enable DNS over HTTPS → Custom → `https://dns.quad9.net/dns-query`

---

## Running the Test Script

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt install dnsutils openssl tcpdump

# Fedora
sudo dnf install bind-utils openssl tcpdump

# Arch
sudo pacman -S bind openssl tcpdump
```

### Run

```bash
git clone https://github.com/microlaser/DNS_freedom
cd DNS_freedom
sudo bash dns_leak_test.sh
```

> Root is required for `tcpdump` (the plaintext leak detection test). All other tests run as a regular user, though `lsattr` file attribute checks also benefit from root.

### What the Script Tests

| Test | What it checks |
|------|---------------|
| 1 | `/etc/resolv.conf` contents, immutability, systemd-resolved, NetworkManager DNS |
| 2 | Whether stubby/unbound/dnsmasq is running and listening on port 53 |
| 3 | DNS resolution via `127.0.0.1` — confirms local resolver is active |
| 4 | Upstream server identity via Quad9's `id.server.on.quad9.net` TXT record |
| 5 | TLS handshake to port 853 on all four Quad9 endpoints, cert verification |
| 6 | Live `tcpdump` capture — detects any plaintext UDP port 53 traffic leaving the machine |
| 7 | DNSSEC validation — RRSIG records, AD flag, `dnssec-failed.org` blocking |
| 8 | IPv6 Quad9 endpoint reachability |
| 9 | Full TLS certificate details for `dns.quad9.net` |
| 10 | Stubby config audit — TLS mode, transport, upstream servers, file immutability |

### Example Output

```
══════════════════════════════════════════════
  TEST 6: Plaintext DNS Leak Detection (port 53 outbound)
══════════════════════════════════════════════
  [INFO] Capturing 5 seconds of outbound UDP port 53 traffic...
  [PASS] No plaintext DNS leaking on UDP port 53 — all DNS traffic is encrypted

══════════════════════════════════════════════
  TEST 5: DNS-over-TLS (Port 853) Connectivity
══════════════════════════════════════════════
  [PASS] TLS to 9.9.9.9:853 — cert valid (Verify return code: 0 (ok))
  [PASS] TLS to 149.112.112.112:853 — cert valid (Verify return code: 0 (ok))
```

---

## Browser-Based Tests

| Site | What it tests |
|------|--------------|
| https://on.quad9.net | **Official Quad9 test** — definitively confirms Quad9 is your resolver |
| https://dnsleaktest.com | Extended test — shows all DNS servers your queries are reaching |
| https://browserleaks.com/dns | Shows which DNS servers the browser specifically is using |
| https://www.cloudflare.com/ssl/encrypted-sni/ | Checks DNS encryption, DNSSEC, TLS 1.3, and ECH support |

> **Note:** `dnsleaktest.com` may show Comcast's PCH/WoodyNet servers (`74.63.x.x` in Ashburn, VA). These are Comcast's legitimate upstream recursive resolvers used by the test infrastructure itself — not your machine's DNS. The `on.quad9.net` test is definitive.

---

## Troubleshooting

**DNS stops working after running the script**  
Your `/etc/resolv.conf` was set to `127.0.0.1` but stubby wasn't running yet. Fix:
```bash
sudo systemctl start stubby
```

**`dig @127.0.0.1` fails**  
Stubby may not be bound to port 53. Check:
```bash
sudo systemctl status stubby
sudo ss -tlnup 'sport = :53'
```

**Can't edit stubby.yml or resolv.conf**  
Files are `chattr +i` immutable. Unlock first:
```bash
sudo chattr -i /etc/resolv.conf
sudo chattr -i /etc/stubby/stubby.yml
```

**systemd-resolved keeps taking over**  
```bash
sudo systemctl disable --now systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
sudo chattr +i /etc/resolv.conf
```

---

## Security Notes

- `chattr +i` makes files immutable at the filesystem level — even root cannot modify them without explicitly running `chattr -i` first. This prevents DHCP hooks, NetworkManager, and malicious scripts from overwriting your DNS config.
- Your Roku and other IoT devices on the LAN are still using Comcast DNS. Consider a Pi-hole or pfSense with DoT for whole-network coverage.
- Stubby uses `GETDNS_AUTHENTICATION_REQUIRED` — it will refuse to send queries if TLS authentication fails, rather than falling back to plaintext.

---

## License
MIT
