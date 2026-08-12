#!/bin/bash
set -euo pipefail

# firewall entrypoint — runs in the firewall container.
# Responsibilities:
# 1. Enable IP forwarding between interfaces
# 2. Configure nftables for egress filtering (deny-first)
# 3. Start CoreDNS for DNS-level filtering
# 4. Set up SNAT for outbound traffic

# --- IP forwarding ---
# /proc is read-only inside the container; ip_forward is typically already
# enabled on Docker hosts.  Only attempt the write when it isn't set yet.
CURRENT_FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
if [ "$CURRENT_FWD" != "1" ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || \
        echo "WARN: cannot set ip_forward (may already be enabled on host)" >&2
fi

# --- Detect network configuration ---
# On Docker Desktop for Mac, multiple interfaces may share the same name (e.g. both eth0).
# Interface-name-based matching (iifname/oifname) is unreliable in this environment.
# Strategy: detect the inside IP by matching against SUBNET, then use IP-based matching
# in nftables rules (ip saddr/ip daddr) instead of interface names.

# Extract subnet prefix for matching (e.g. "10.130.214" from "10.130.214.0/24")
SUBNET_PREFIX=""
if [ -n "${SUBNET:-}" ]; then
    SUBNET_PREFIX=$(echo "$SUBNET" | cut -d. -f1-3)
fi

# Find the inside IP: any non-loopback IP whose first 3 octets match SUBNET
INSIDE_IP=""
for iface in $(ip -o addr show | awk '{print $2}' | grep -v '^lo$' | sort -u); do
    iface_ip=$(ip -o addr show dev "$iface" 2>/dev/null | awk '/inet /{print $4}' | head -1 | cut -d/ -f1)
    if [ -n "$iface_ip" ] && [ -n "$SUBNET_PREFIX" ]; then
        ip_prefix=$(echo "$iface_ip" | cut -d. -f1-3)
        if [ "$ip_prefix" = "$SUBNET_PREFIX" ]; then
            INSIDE_IP="$iface_ip"
            break
        fi
    fi
done

# Fallback: if SUBNET not set, try to find any non-172.17.x.x IP
if [ -z "$INSIDE_IP" ]; then
    for iface in $(ip -o addr show | awk '{print $2}' | grep -v '^lo$' | sort -u); do
        iface_ip=$(ip -o addr show dev "$iface" 2>/dev/null | awk '/inet /{print $4}' | head -1 | cut -d/ -f1)
        if [ -n "$iface_ip" ]; then
            # Skip the default bridge (172.17.x.x)
            case "$iface_ip" in
                172.17.*) continue ;;
            esac
            INSIDE_IP="$iface_ip"
            break
        fi
    done
fi

if [ -z "$INSIDE_IP" ]; then
    echo "ERROR: Could not detect inside IP (subnet=${SUBNET:-unset})" >&2
    echo "  Routes:" >&2
    ip route show >&2
    echo "  Interfaces:" >&2
    ip -o addr show >&2
    exit 1
fi

echo "Inside IP (agent gateway): $INSIDE_IP"

# --- Add gateway as secondary IP ---
# The network gateway (10.x.x.1) is the agent's default route.
# Docker can't assign the gateway IP to a container, so we add it as a
# secondary IP on the firewall's inside interface. This makes the firewall
# respond to ARP for the gateway IP, so agent traffic routes through it.
if [ -n "${GATEWAY:-}" ] && [ -n "${INSIDE_IP:-}" ]; then
    # Find the inside interface by matching the primary IP
    INSIDE_IF=""
    for iface in $(ip -o addr show | awk '{print $2}' | grep -v '^lo$' | sort -u); do
        iface_ip=$(ip -o addr show dev "$iface" 2>/dev/null | awk '/inet /{print $4}' | head -1 | cut -d/ -f1)
        if [ "$iface_ip" = "$INSIDE_IP" ]; then
            INSIDE_IF="$iface"
            break
        fi
    done
    if [ -n "$INSIDE_IF" ]; then
        # Add /24 from SUBNET if available, otherwise use /24
        MASK="${SUBNET##*/}"
        ip addr add "${GATEWAY}/${MASK:-24}" dev "$INSIDE_IF" 2>/dev/null || \
            echo "WARN: could not add gateway ${GATEWAY} on ${INSIDE_IF} (may already exist)" >&2
        echo "Added gateway ${GATEWAY}/${MASK:-24} on ${INSIDE_IF}"
    fi
fi

# --- Generate nftables config ---
cat > /etc/nftables.conf <<NFTABLES_EOF
#!/usr/sbin/nft -f

flush ruleset

# Main table for egress filtering and DNAT
table ip firewall {
NFTABLES_EOF

# PREROUTING chain — DNAT for host→agent access
if [ -n "${AGENT_IP:-}" ] && [ -n "${AGENT_PORT:-}" ]; then
    # Strip /tcp suffix from port if present
    AGENT_PORT_NUM=$(echo "$AGENT_PORT" | sed 's|/tcp||')
    cat >> /etc/nftables.conf <<NFTABLES_DNAT_EOF
    chain prerouting {
        type nat hook prerouting priority -100;

        # DNAT: forward published port traffic to agent
        tcp dport $AGENT_PORT_NUM dnat to $AGENT_IP comment "dnat-agent"
    }
NFTABLES_DNAT_EOF
fi

cat >> /etc/nftables.conf <<NFTABLES_EOF

    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow established/related connections (return traffic)
        ct state established,related accept

        # Drop invalid connections
        ct state invalid drop

        # --- DENY CIDR rules (checked BEFORE allow — deny wins) ---
        # Generated from config: firewall.network.cidr.deny
NFTABLES_EOF

# Add deny CIDR rules if DENY_CIDRS env var is set
if [ -n "${DENY_CIDRS:-}" ]; then
    IFS=',' read -ra CIDRS <<< "$DENY_CIDRS"
    for cidr in "${CIDRS[@]}"; do
        cidr=$(echo "$cidr" | xargs) # trim whitespace
        if [ -n "$cidr" ]; then
            echo "        ip daddr $cidr drop comment \"deny-cidr\"" >> /etc/nftables.conf
        fi
    done
fi

cat >> /etc/nftables.conf <<NFTABLES_EOF

        # --- ALLOW CIDR rules ---
NFTABLES_EOF

# Add allow CIDR rules
if [ -n "${ALLOW_CIDRS:-}" ]; then
    IFS=',' read -ra CIDRS <<< "$ALLOW_CIDRS"
    for cidr in "${CIDRS[@]}"; do
        cidr=$(echo "$cidr" | xargs)
        if [ -n "$cidr" ]; then
            echo "        ip daddr $cidr accept comment \"allow-cidr\"" >> /etc/nftables.conf
        fi
    done
fi

cat >> /etc/nftables.conf <<NFTABLES_EOF

        # --- Default policy ---
NFTABLES_EOF

# Default policy from env var
DEFAULT_POLICY="${NETWORK_DEFAULT:-drop}"
if [ "$DEFAULT_POLICY" = "allow" ]; then
    echo "        accept comment \"default-allow\"" >> /etc/nftables.conf
else
    echo "        drop comment \"default-deny\"" >> /etc/nftables.conf
fi

cat >> /etc/nftables.conf <<NFTABLES_EOF
    }

    chain postrouting {
        type nat hook postrouting priority 100;

        # SNAT outbound traffic from agent to internet
        ip saddr ${SUBNET:-10.0.0.0/8} masquerade
    }
}
NFTABLES_EOF

echo "Generated nftables config:"
cat /etc/nftables.conf

# --- Load nftables ---
nft -f /etc/nftables.conf

# --- Generate CoreDNS config ---
# Deny domains: immediate NXDOMAIN
# Allow domains: forward to upstream resolvers
# Default policy: NXDOMAIN (deny) or passthrough (allow)

DNS_DEFAULT="${DNS_DEFAULT:-deny}"
DNS_UPSTREAM="${DNS_UPSTREAM:-1.1.1.1,8.8.8.8}"

cat > /etc/coredns/Corefile <<COREDNS_EOF
.:53 {
    errors
    log

    # Deny zones (deny wins — checked first)
COREDNS_EOF

# Add deny domains
if [ -n "${DENY_DOMAINS:-}" ]; then
    IFS=',' read -ra DOMAINS <<< "$DENY_DOMAINS"
    for domain in "${DOMAINS[@]}"; do
        domain=$(echo "$domain" | xargs)
        if [ -n "$domain" ]; then
            cat >> /etc/coredns/Corefile <<COREDNS_DENY
    template IN ANY $domain {
        rcode NXDOMAIN
    }
COREDNS_DENY
        fi
    done
fi

cat >> /etc/coredns/Corefile <<COREDNS_EOF

    # Forward allowed domains to upstream
COREDNS_EOF

# Add allow domains with forward rules
if [ -n "${ALLOW_DOMAINS:-}" ]; then
    IFS=',' read -ra DOMAINS <<< "$ALLOW_DOMAINS"
    # Convert comma-separated upstream to space-separated for CoreDNS forward plugin
    DNS_UPSTREAM_SPACES="${DNS_UPSTREAM//,/ }"
    for domain in "${DOMAINS[@]}"; do
        domain=$(echo "$domain" | xargs)
        if [ -n "$domain" ]; then
            cat >> /etc/coredns/Corefile <<COREDNS_ALLOW
    $domain {
        forward . $DNS_UPSTREAM_SPACES
    }
COREDNS_ALLOW
        fi
    done
fi

# Default policy
if [ "$DNS_DEFAULT" = "allow" ]; then
    # Convert comma-separated upstream to space-separated for CoreDNS forward plugin
    DNS_UPSTREAM_SPACES="${DNS_UPSTREAM//,/ }"
    cat >> /etc/coredns/Corefile <<COREDNS_DEFAULT
    forward . $DNS_UPSTREAM_SPACES
COREDNS_DEFAULT
else
    cat >> /etc/coredns/Corefile <<COREDNS_DEFAULT
    template IN ANY {
        rcode NXDOMAIN
    }
COREDNS_DEFAULT
fi

# Close the server block
echo "}" >> /etc/coredns/Corefile

echo "Generated CoreDNS config:"
cat /etc/coredns/Corefile

# --- Start CoreDNS in background ---
coredns -conf /etc/coredns/Corefile &
COREDNS_PID=$!
echo "CoreDNS started (PID=$COREDNS_PID)"

# --- Health check loop ---
echo "Firewall ready. Monitoring..."

# Keep container alive and forward signals
exec tail -f /dev/null
