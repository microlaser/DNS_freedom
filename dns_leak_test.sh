#!/usr/bin/env bash
# =============================================================================
# dns_leak_test.sh — Comprehensive DNS leak & encryption test
# Works on any Linux distribution
# Usage: sudo bash dns_leak_test.sh
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pass()  { echo -e "  ${GREEN}[PASS]${RESET} $*"; }
fail()  { echo -e "  ${RED}[FAIL]${RESET} $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${RESET} $*"; }
info()  { echo -e "  ${CYAN}[INFO]${RESET} $*"; }
header(){ echo -e "\n${BOLD}══════════════════════════════════════════════${RESET}"; \
          echo -e "${BOLD}  $*${RESET}"; \
          echo -e "${BOLD}══════════════════════════════════════════════${RESET}"; }

# ── Tool availability check ───────────────────────────────────────────────────
require_tool() {
    if ! command -v "$1" &>/dev/null; then
        warn "'$1' not found — skipping tests that need it"
        return 1
    fi
    return 0
}

# ── Root check (needed for tcpdump/ss -p) ────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root — some tests (tcpdump, ss -p) may be limited"
fi

echo -e "\n${BOLD}${CYAN}DNS LEAK & ENCRYPTION TEST SUITE${RESET}"
echo -e "$(date)"
echo -e "Hostname: $(hostname)"

# =============================================================================
# TEST 1 — System DNS configuration
# =============================================================================
header "TEST 1: System DNS Configuration"

info "--- /etc/resolv.conf ---"
if [[ -f /etc/resolv.conf ]]; then
    cat /etc/resolv.conf | while IFS= read -r line; do
        echo "    $line"
    done
    RESOLV_NS=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    info "Active nameservers: ${RESOLV_NS:-NONE FOUND}"
    if echo "$RESOLV_NS" | grep -qE '127\.|::1'; then
        pass "resolv.conf points to localhost — local resolver (e.g. stubby/unbound) is active"
    else
        warn "resolv.conf points directly to external DNS — no local encrypted resolver detected"
    fi
else
    fail "/etc/resolv.conf not found"
fi

info "--- File attributes (chattr) ---"
if require_tool lsattr; then
    ATTRS=$(lsattr /etc/resolv.conf 2>/dev/null || echo "error")
    echo "    $ATTRS"
    if echo "$ATTRS" | grep -q '\-i\-'; then
        pass "resolv.conf is immutable (chattr +i)"
    else
        warn "resolv.conf is NOT immutable — could be overwritten by DHCP/NetworkManager"
    fi
fi

info "--- systemd-resolved status ---"
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    warn "systemd-resolved is active — it may override /etc/resolv.conf"
    if require_tool resolvectl; then
        resolvectl status 2>/dev/null | grep -E 'DNS Server|DNS Domain|DNSSEC' | while IFS= read -r line; do
            echo "    $line"
        done
    fi
else
    pass "systemd-resolved is NOT active"
fi

info "--- NetworkManager DNS config ---"
if command -v nmcli &>/dev/null; then
    nmcli dev show 2>/dev/null | grep DNS | while IFS= read -r line; do
        echo "    $line"
    done
fi

# =============================================================================
# TEST 2 — Local resolver check
# =============================================================================
header "TEST 2: Local Resolver (Stubby / Unbound / dnsmasq)"

for svc in stubby unbound dnsmasq systemd-resolved kresd; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        pass "$svc is running"
    else
        info "$svc is not running"
    fi
done

info "--- Listening on port 53 ---"
if require_tool ss; then
    ss -tlnup 'sport = :53' 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        echo "    $line"
    done
fi

# =============================================================================
# TEST 3 — DNS resolution via localhost
# =============================================================================
header "TEST 3: DNS Resolution via Localhost"

if require_tool dig; then
    info "Querying quad9.net @127.0.0.1 ..."
    RESULT=$(dig +short quad9.net @127.0.0.1 2>/dev/null || echo "FAILED")
    if [[ "$RESULT" == "FAILED" || -z "$RESULT" ]]; then
        fail "dig @127.0.0.1 failed — local resolver may not be running"
    else
        pass "dig @127.0.0.1 quad9.net returned: $RESULT"
    fi

    info "Query time via localhost:"
    dig quad9.net @127.0.0.1 2>/dev/null | grep 'Query time' | while IFS= read -r line; do
        echo "    $line"
    done
else
    warn "dig not available — install dnsutils/bind-utils"
fi

# =============================================================================
# TEST 4 — Confirm DNS traffic goes to Quad9 (or another known DoT provider)
# =============================================================================
header "TEST 4: Upstream DNS Server Identification"

KNOWN_DOT_SERVERS=(
    "9.9.9.9"           # Quad9
    "149.112.112.112"   # Quad9 secondary
    "1.1.1.1"           # Cloudflare
    "1.0.0.1"           # Cloudflare secondary
    "8.8.8.8"           # Google
    "8.8.4.4"           # Google secondary
    "208.67.222.222"    # OpenDNS
    "94.140.14.14"      # AdGuard
)

if require_tool dig; then
    info "Checking which upstream server is resolving your queries..."

    # Query Quad9's identity TXT record
    Q9_ID=$(dig +short txt id.server.on.quad9.net @127.0.0.1 2>/dev/null || echo "")
    if [[ -n "$Q9_ID" ]]; then
        pass "Quad9 identity confirmed: $Q9_ID"
    else
        warn "Quad9 id.server TXT query returned nothing — may not be using Quad9"
    fi

    # Check DNS server from CHAOS class query
    info "Attempting CHAOS TXT query for server identity..."
    CHAOS=$(dig +short chaos txt version.bind @127.0.0.1 2>/dev/null || echo "not supported")
    echo "    version.bind: $CHAOS"
fi

# =============================================================================
# TEST 5 — Port 853 (DNS-over-TLS) connection check
# =============================================================================
header "TEST 5: DNS-over-TLS (Port 853) Connectivity"

DOT_HOSTS=(
    "9.9.9.9"
    "149.112.112.112"
    "2620:fe::fe"
    "2620:fe::9"
)

for host in "${DOT_HOSTS[@]}"; do
    if require_tool openssl; then
        RESULT=$(timeout 5 openssl s_client -connect "${host}:853" \
            -servername dns.quad9.net </dev/null 2>/dev/null \
            | grep 'Verify return code' || echo "connection failed")
        if echo "$RESULT" | grep -q 'Verify return code: 0'; then
            pass "TLS to ${host}:853 — cert valid (${RESULT})"
        elif echo "$RESULT" | grep -q 'connection failed'; then
            fail "Could not connect to ${host}:853"
        else
            warn "${host}:853 — $RESULT"
        fi
    fi
done

info "--- Active connections to port 853 ---"
if require_tool ss; then
    CONNS=$(ss -tnp 'dport = :853' 2>/dev/null | tail -n +2)
    if [[ -n "$CONNS" ]]; then
        pass "Active DoT connections found:"
        echo "$CONNS" | while IFS= read -r line; do echo "    $line"; done
    else
        info "No active port 853 connections right now (normal — stubby connects on demand)"
    fi
fi

# =============================================================================
# TEST 6 — Plaintext DNS leak detection
# =============================================================================
header "TEST 6: Plaintext DNS Leak Detection (port 53 outbound)"

if require_tool tcpdump; then
    if [[ $EUID -ne 0 ]]; then
        warn "Need root for tcpdump — run with sudo for this test"
    else
        info "Capturing 5 seconds of outbound UDP port 53 traffic (excluding localhost)..."
        # Trigger some DNS in background
        (dig +short google.com @127.0.0.1 &>/dev/null; \
         dig +short github.com @127.0.0.1 &>/dev/null) &
        sleep 1
        LEAK=$(timeout 5 tcpdump -c 50 -n 'udp port 53 and not host 127.0.0.1' \
               2>/dev/null | grep -v '^tcpdump' || echo "")
        if [[ -z "$LEAK" ]]; then
            pass "No plaintext DNS leaking on UDP port 53 — all DNS traffic is encrypted"
        else
            fail "PLAINTEXT DNS LEAK DETECTED:"
            echo "$LEAK" | head -20 | while IFS= read -r line; do echo "    $line"; done
        fi
    fi
else
    warn "tcpdump not available — install it for leak detection"
fi

# =============================================================================
# TEST 7 — DNSSEC validation
# =============================================================================
header "TEST 7: DNSSEC Validation"

if require_tool dig; then
    info "Testing DNSSEC-signed domain (cloudflare.com) ..."
    DNSSEC=$(dig +dnssec cloudflare.com @127.0.0.1 2>/dev/null | grep -E 'RRSIG|flags.*ad' || echo "")
    if echo "$DNSSEC" | grep -q 'RRSIG'; then
        pass "DNSSEC records (RRSIG) returned — DNSSEC is being validated"
    else
        warn "No RRSIG records returned — DNSSEC validation may not be active"
    fi

    info "Checking AD (Authenticated Data) flag ..."
    AD_FLAG=$(dig cloudflare.com @127.0.0.1 2>/dev/null | grep '^;; flags' || echo "")
    if echo "$AD_FLAG" | grep -q ' ad'; then
        pass "AD flag set — DNSSEC authentication confirmed: $AD_FLAG"
    else
        warn "AD flag not set: $AD_FLAG"
    fi

    info "Testing known DNSSEC-failing domain (dnssec-failed.org) ..."
    FAIL_TEST=$(dig +short dnssec-failed.org @127.0.0.1 2>/dev/null || echo "")
    if [[ -z "$FAIL_TEST" ]]; then
        pass "dnssec-failed.org returned no result — DNSSEC validation is blocking bad domains"
    else
        warn "dnssec-failed.org resolved to: $FAIL_TEST — DNSSEC may not be enforcing"
    fi
fi

# =============================================================================
# TEST 8 — IPv6 DNS check
# =============================================================================
header "TEST 8: IPv6 DNS"

if require_tool dig; then
    info "IPv6 Quad9 primary (2620:fe::fe) ..."
    V6=$(timeout 5 dig +short quad9.net @2620:fe::fe 2>/dev/null || echo "unreachable")
    if [[ "$V6" == "unreachable" || -z "$V6" ]]; then
        warn "IPv6 Quad9 unreachable (may not have IPv6 connectivity)"
    else
        pass "IPv6 Quad9 resolves: $V6"
    fi
fi

# =============================================================================
# TEST 9 — TLS certificate details
# =============================================================================
header "TEST 9: TLS Certificate Details for dns.quad9.net"

if require_tool openssl; then
    info "Full cert chain for 9.9.9.9:853 ..."
    CERT=$(timeout 5 openssl s_client -connect 9.9.9.9:853 \
        -servername dns.quad9.net </dev/null 2>/dev/null || echo "")
    if [[ -n "$CERT" ]]; then
        echo "$CERT" | grep -E 'subject|issuer|Verify|Not (Before|After)' | \
            while IFS= read -r line; do echo "    $line"; done
    else
        fail "Could not retrieve TLS certificate"
    fi
fi

# =============================================================================
# TEST 10 — Stubby config audit (if present)
# =============================================================================
header "TEST 10: Stubby Configuration Audit"

STUBBY_CONF="/etc/stubby/stubby.yml"
if [[ -f "$STUBBY_CONF" ]]; then
    pass "stubby.yml found"

    info "--- TLS authentication mode ---"
    grep 'tls_authentication' "$STUBBY_CONF" | while IFS= read -r line; do echo "    $line"; done

    info "--- Transport ---"
    grep -A2 'dns_transport_list' "$STUBBY_CONF" | while IFS= read -r line; do echo "    $line"; done

    info "--- Upstream servers ---"
    grep -E 'address_data|tls_auth_name' "$STUBBY_CONF" | while IFS= read -r line; do echo "    $line"; done

    info "--- File immutability ---"
    if require_tool lsattr; then
        lsattr "$STUBBY_CONF" | while IFS= read -r line; do echo "    $line"; done
    fi
else
    info "No stubby config found at $STUBBY_CONF"
fi

# =============================================================================
# SUMMARY
# =============================================================================
header "SUMMARY"

echo ""
echo -e "  Run ${BOLD}https://on.quad9.net${RESET} in your browser for the official Quad9 confirmation."
echo -e "  Run ${BOLD}https://dnsleaktest.com${RESET} (Extended Test) to cross-check with external eyes."
echo ""
echo -e "  To watch live DoT traffic:  ${CYAN}tcpdump -i any port 853 -n${RESET}"
echo -e "  To confirm no UDP 53 leak:  ${CYAN}tcpdump -i any 'udp port 53 and not host 127.0.0.1' -n${RESET}"
echo ""
