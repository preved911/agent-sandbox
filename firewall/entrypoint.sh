#!/bin/bash
set -euo pipefail

# firewall entrypoint — runs in the firewall container.
# Responsibilities:
# 1. Enable IP forwarding between interfaces
# 2. Configure nftables for egress filtering (deny-first)
# 3. Start CoreDNS for DNS-level filtering
# 4. Set up SNAT for outbound traffic

# --- IP forwarding ---
echo 1 > /proc/sys/net/ipv4/ip_forward

# --- Detect interfaces ---
# INSIDE_IF: interface facing the isolated network (agent side)
# OUTSIDE_IF: interface facing the default bridge (internet side)
INSIDE_IF=$(ip route show | grep 'default' | awk '{print $5}' | head -1)
# The inside interface is the second interface (not default route)
ALL_IFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo)
INSIDE_IF=""
OUTSIDE_IF=""
FIRST=true
for iface in $ALL_IFACES; do
    if [ "$FIRST" = true ]; then
        OUTSIDE_IF="$iface"
        FIRST=false
    else
        INSIDE_IF="$iface"
    fi
done

if [ -z "$INSIDE_IF" ] || [ -z "$OUTSIDE_IF" ]; then
    echo "ERROR: Could not detect network interfaces"
    echo "  ALL_IFACES=$ALL_IFACES"
    exit 1
fi

echo "Interfaces: inside=$INSIDE_IF outside=$OUTSIDE_IF"

# Get the inside interface IP (agent's gateway)
INSIDE_IP=$(ip addr show "$INSIDE_IF" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
echo "Inside IP (agent gateway): $INSIDE_IP"

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
        ip saddr 172.20.0.0/16 oifname "$OUTSIDE_IF" masquerade
    }
}

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
    for domain in "${DOMAINS[@]}"; do
        domain=$(echo "$domain" | xargs)
        if [ -n "$domain" ]; then
            cat >> /etc/coredns/Corefile <<COREDNS_ALLOW
    $domain {
        forward . $DNS_UPSTREAM
    }
COREDNS_ALLOW
        fi
    done
fi

# Default policy
if [ "$DNS_DEFAULT" = "allow" ]; then
    cat >> /etc/coredns/Corefile <<COREDNS_DEFAULT
    . {
        forward . $DNS_UPSTREAM
    }
COREDNS_DEFAULT
else
    cat >> /etc/coredns/Corefile <<COREDNS_DEFAULT
    . {
        template IN ANY {
            rcode NXDOMAIN
        }
    }
COREDNS_DEFAULT
fi

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
