#!/bin/bash
set -euo pipefail

# entrypoint.sh — runs in both firewall and proxy containers.
# MODE env var selects behavior:
#   firewall (default) — nftables + CoreDNS for traffic filtering
#   proxy              — nginx reverse proxy for host→agent access

MODE="${MODE:-firewall}"

# ========================================
# FIREWALL MODE — nftables + CoreDNS
# ========================================
if [ "$MODE" = "firewall" ]; then
    # --- IP forwarding ---
    CURRENT_FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
    if [ "$CURRENT_FWD" != "1" ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || \
            echo "WARN: cannot set ip_forward (may already be enabled on host)" >&2
    fi

    # --- Detect network configuration ---
    SUBNET_PREFIX=""
    if [ -n "${SUBNET:-}" ]; then
        SUBNET_PREFIX=$(echo "$SUBNET" | cut -d. -f1-3)
    fi

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

    if [ -z "$INSIDE_IP" ]; then
        for iface in $(ip -o addr show | awk '{print $2}' | grep -v '^lo$' | sort -u); do
            iface_ip=$(ip -o addr show dev "$iface" 2>/dev/null | awk '/inet /{print $4}' | head -1 | cut -d/ -f1)
            if [ -n "$iface_ip" ]; then
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
    if [ -n "${GATEWAY:-}" ] && [ -n "${INSIDE_IP:-}" ]; then
        INSIDE_IF=""
        for iface in $(ip -o addr show | awk '{print $2}' | grep -v '^lo$' | sort -u); do
            iface_ip=$(ip -o addr show dev "$iface" 2>/dev/null | awk '/inet /{print $4}' | head -1 | cut -d/ -f1)
            if [ "$iface_ip" = "$INSIDE_IP" ]; then
                INSIDE_IF="$iface"
                break
            fi
        done
        if [ -n "$INSIDE_IF" ]; then
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

table ip firewall {
NFTABLES_EOF

    cat >> /etc/nftables.conf <<NFTABLES_EOF

    chain forward {
        type filter hook forward priority 0; policy drop;

        ct state established,related accept
        ct state invalid drop

        # --- DENY CIDR rules ---
NFTABLES_EOF

    if [ -n "${DENY_CIDRS:-}" ]; then
        IFS=',' read -ra CIDRS <<< "$DENY_CIDRS"
        for cidr in "${CIDRS[@]}"; do
            cidr=$(echo "$cidr" | xargs)
            if [ -n "$cidr" ]; then
                echo "        ip daddr $cidr drop comment \"deny-cidr\"" >> /etc/nftables.conf
            fi
        done
    fi

    cat >> /etc/nftables.conf <<NFTABLES_EOF

        # --- ALLOW CIDR rules ---
NFTABLES_EOF

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

        ip saddr ${SUBNET:-10.0.0.0/8} ip daddr != ${SUBNET:-10.0.0.0/8} masquerade
    }
}
NFTABLES_EOF

    echo "Generated nftables config:"
    cat /etc/nftables.conf

    nft -f /etc/nftables.conf

    # --- Generate CoreDNS config ---
    DNS_DEFAULT="${DNS_DEFAULT:-deny}"
    DNS_UPSTREAM="${DNS_UPSTREAM:-1.1.1.1,8.8.8.8}"

    cat > /etc/coredns/Corefile <<COREDNS_EOF
.:53 {
    errors
    log
COREDNS_EOF

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

    if [ -n "${ALLOW_DOMAINS:-}" ]; then
        IFS=',' read -ra DOMAINS <<< "$ALLOW_DOMAINS"
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

    if [ "$DNS_DEFAULT" = "allow" ]; then
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

    echo "}" >> /etc/coredns/Corefile

    echo "Generated CoreDNS config:"
    cat /etc/coredns/Corefile

    coredns -conf /etc/coredns/Corefile &
    COREDNS_PID=$!
    echo "CoreDNS started (PID=$COREDNS_PID)"

    echo "Firewall ready. Monitoring..."
    exec tail -f /dev/null
fi

# ========================================
# PROXY MODE — nginx reverse proxy
# ========================================
if [ "$MODE" = "proxy" ]; then
    if [ -z "${AGENT_IP:-}" ] || [ -z "${AGENT_PORT:-}" ]; then
        echo "ERROR: MODE=proxy requires AGENT_IP and AGENT_PORT env vars" >&2
        exit 1
    fi

    AGENT_PORT_NUM=$(echo "$AGENT_PORT" | sed 's|/tcp||')

    # Generate nginx config
    cat > /etc/nginx/nginx.conf <<NGINX_EOF
worker_processes 1;
daemon off;

events {
    worker_connections 1024;
}

http {
    access_log /dev/stdout;
    error_log /dev/stderr;

    server {
        listen ${AGENT_PORT_NUM};

        location / {
            proxy_pass http://${AGENT_IP}:${AGENT_PORT_NUM};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }
    }
}
NGINX_EOF

    echo "Generated nginx config:"
    cat /etc/nginx/nginx.conf

    echo "Starting nginx: 0.0.0.0:${AGENT_PORT_NUM} -> ${AGENT_IP}:${AGENT_PORT_NUM}"
    exec nginx
fi

echo "ERROR: Unknown MODE=$MODE (expected: firewall or proxy)" >&2
exit 1
