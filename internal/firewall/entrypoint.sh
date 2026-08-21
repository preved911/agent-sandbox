#!/bin/bash
set -euo pipefail

# entrypoint.sh — firewall container entrypoint (nftables + CoreDNS + dns-pin).
#
# Environment:
#   FIREWALL_RULES  unified rules, one per line: type|target|protocol|ports|set
#                   (type: allow|block, target: CIDR/IP/DNS name, protocol: tcp|udp|"",
#                    ports: canonical port spec, set: nft named set for DNS allow rules)
#   NETWORK_DEFAULT deny|allow (IP-layer default policy)
#   DNS_DEFAULT     deny|allow (DNS default policy)
#   DNS_UPSTREAM    comma-separated upstream resolvers
#   AUTO_PIN        1 to pin resolved IPs of DNS allow rules into nftables sets
#   SUBNET / GATEWAY  sandbox network parameters
#
# Rule ordering in the forward chain (deny wins): block IP rules, allow IP
# rules, DNS-resolved allow rules (@sets), default policy.

MODE="${MODE:-firewall}"

if [ "$MODE" != "firewall" ]; then
    echo "ERROR: Unknown MODE=$MODE (expected: firewall)" >&2
    exit 1
fi

# --- IP forwarding ---
CURRENT_FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
if [ "$CURRENT_FWD" != "1" ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || \
        echo "WARN: cannot set ip_forward (may already be enabled on host)" >&2
fi

CURRENT_FWD6=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0)
if [ "$CURRENT_FWD6" != "1" ]; then
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || \
        echo "WARN: cannot set ipv6 forwarding (may already be enabled on host)" >&2
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
if [ -n "${GATEWAY:-}" ]; then
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

        # Add IPv6 gateway as secondary address so agent IPv6 traffic routed
        # to the network gateway (::1) arrives at the firewall.
        if [ -n "${GATEWAY6:-}" ] && [ -n "${SUBNET6:-}" ]; then
            MASK6="${SUBNET6##*/}"
            ip -6 addr add "${GATEWAY6}/${MASK6:-64}" dev "$INSIDE_IF" 2>/dev/null || \
                echo "WARN: could not add IPv6 gateway ${GATEWAY6} on ${INSIDE_IF} (may already exist)" >&2
            echo "Added IPv6 gateway ${GATEWAY6}/${MASK6:-64} on ${INSIDE_IF}"
        fi
    fi
fi

# --- Classify unified rules ---
# is_ip_target: CIDR or bare IP (IPv4 or IPv6).
is_ip_target() {
    [[ "$1" == */* ]] || [[ "$1" =~ ^[0-9a-fA-F:.]+$ ]]
}
is_ipv6_target() {
    [[ "$1" == *:* ]]
}

BLOCK_IP=()      # "target|proto|ports"
ALLOW_IP=()      # "target|proto|ports"
BLOCK_IP6=()     # "target|proto|ports"
ALLOW_IP6=()     # "target|proto|ports"
DNS_DENY=()      # "domain"
DNS_ALLOW=()     # "domain|proto|ports|set"
while IFS='|' read -r rtype target proto ports setname; do
    [ -z "${rtype:-}" ] && continue
    if is_ip_target "$target"; then
        if is_ipv6_target "$target"; then
            if [ "$rtype" = "block" ]; then
                BLOCK_IP6+=("$target|$proto|$ports")
            else
                ALLOW_IP6+=("$target|$proto|$ports")
            fi
        else
            if [ "$rtype" = "block" ]; then
                BLOCK_IP+=("$target|$proto|$ports")
            else
                ALLOW_IP+=("$target|$proto|$ports")
            fi
        fi
    else
        if [ "$rtype" = "block" ]; then
            DNS_DENY+=("$target")
        else
            DNS_ALLOW+=("$target|$proto|$ports|$setname")
        fi
    fi
done <<< "${FIREWALL_RULES:-}"

AUTO_PIN="${AUTO_PIN:-1}"

# --- Generate nftables config ---
{
    echo "#!/usr/sbin/nft -f"
    echo
    echo "flush ruleset"
    echo
    echo "table ip firewall {"

    # Named sets for DNS-resolved IPs (populated by dns-pin with TTL timeouts)
    declare -A emitted_sets=()
    if [ "$AUTO_PIN" = "1" ]; then
        for rule in "${DNS_ALLOW[@]+"${DNS_ALLOW[@]}"}"; do
            IFS='|' read -r _domain _proto _ports setname <<< "$rule"
            [ -z "$setname" ] && continue
            [ -n "${emitted_sets[$setname]:-}" ] && continue
            emitted_sets[$setname]=1
            echo "    set $setname {"
            echo "        type ipv4_addr"
            echo "        flags timeout"
            echo "    }"
        done
    fi
    if [ "${#emitted_sets[@]}" -gt 0 ]; then
        echo
    fi

    echo "    chain forward {"
    echo "        type filter hook forward priority 0; policy drop;"
    echo
    echo "        ct state established,related accept"
    echo "        ct state invalid drop"
    echo

    # emit_transport_rules PREFIX PROTO PORTS VERDICT COMMENT
    # Canonical port specs map 1:1 to nftables: "443" → dport 443,
    # "5000-5100" → dport 5000-5100, "80,443" → dport { 80, 443 }.
    emit_transport_rules() {
        local prefix="$1" proto="$2" ports="$3" verdict="$4" comment="$5" dport
        if [ -z "$ports" ]; then
            if [ -n "$proto" ]; then
                printf '        %s meta l4proto %s %s comment "%s"\n' "$prefix" "$proto" "$verdict" "$comment"
            else
                printf '        %s %s comment "%s"\n' "$prefix" "$verdict" "$comment"
            fi
            return
        fi
        if [[ "$ports" == *,* ]]; then
            dport="dport { $ports }"
        else
            dport="dport $ports"
        fi
        if [ -n "$proto" ]; then
            printf '        %s %s %s %s comment "%s"\n' "$prefix" "$proto" "$dport" "$verdict" "$comment"
        else
            printf '        %s tcp %s %s comment "%s"\n' "$prefix" "$dport" "$verdict" "$comment"
            printf '        %s udp %s %s comment "%s"\n' "$prefix" "$dport" "$verdict" "$comment"
        fi
    }

    if [ "${#BLOCK_IP[@]}" -gt 0 ]; then
        echo "        # --- BLOCK IP rules (deny wins: block before allow) ---"
        for rule in "${BLOCK_IP[@]}"; do
            IFS='|' read -r target proto ports <<< "$rule"
            emit_transport_rules "ip daddr $target" "$proto" "$ports" "drop" "block-ip"
        done
        echo
    fi

    if [ "${#ALLOW_IP[@]}" -gt 0 ]; then
        echo "        # --- ALLOW IP rules ---"
        for rule in "${ALLOW_IP[@]}"; do
            IFS='|' read -r target proto ports <<< "$rule"
            emit_transport_rules "ip daddr $target" "$proto" "$ports" "accept" "allow-ip"
        done
        echo
    fi

    if [ "$AUTO_PIN" = "1" ] && [ "${#DNS_ALLOW[@]}" -gt 0 ]; then
        echo "        # --- ALLOW DNS-resolved IPs (sets populated by dns-pin) ---"
        declare -A seen_rules=()
        for rule in "${DNS_ALLOW[@]}"; do
            IFS='|' read -r _domain proto ports setname <<< "$rule"
            [ -z "$setname" ] && continue
            if [ -z "$ports" ]; then
                if [ -n "$proto" ]; then
                    key="@$setname|meta l4proto $proto"
                    [ -n "${seen_rules[$key]:-}" ] && continue
                    seen_rules[$key]=1
                    printf '        ip daddr @%s meta l4proto %s accept comment "allow-dns-resolved"\n' "$setname" "$proto"
                else
                    key="@$setname|"
                    [ -n "${seen_rules[$key]:-}" ] && continue
                    seen_rules[$key]=1
                    printf '        ip daddr @%s accept comment "allow-dns-resolved"\n' "$setname"
                fi
                continue
            fi
            if [[ "$ports" == *,* ]]; then
                dport="dport { $ports }"
            else
                dport="dport $ports"
            fi
            if [ -n "$proto" ]; then
                key="@$setname|$proto $dport"
                [ -n "${seen_rules[$key]:-}" ] && continue
                seen_rules[$key]=1
                printf '        ip daddr @%s %s %s accept comment "allow-dns-resolved"\n' "$setname" "$proto" "$dport"
            else
                for p in tcp udp; do
                    key="@$setname|$p $dport"
                    [ -n "${seen_rules[$key]:-}" ] && continue
                    seen_rules[$key]=1
                    printf '        ip daddr @%s %s %s accept comment "allow-dns-resolved"\n' "$setname" "$p" "$dport"
                done
            fi
        done
        echo
    fi

    echo "        # --- Default policy ---"
    DEFAULT_POLICY="${NETWORK_DEFAULT:-deny}"
    if [ "$DEFAULT_POLICY" = "allow" ]; then
        echo '        accept comment "default-allow"'
    else
        echo '        drop comment "default-deny"'
    fi

    echo "    }"
    echo
    echo "    chain postrouting {"
    echo "        type nat hook postrouting priority 100;"
    echo
    echo "        ip saddr ${SUBNET:-10.0.0.0/8} ip daddr != ${SUBNET:-10.0.0.0/8} masquerade"
    echo "    }"
    echo "}"
    echo

    # --- IPv6 table ---
    has_ip6=false
    [ "${#BLOCK_IP6[@]}" -gt 0 ] && has_ip6=true
    [ "${#ALLOW_IP6[@]}" -gt 0 ] && has_ip6=true
    [ "$has_ip6" = true ] && {
        echo "table ip6 firewall {"

        # IPv6 DNS sets
        if [ "$AUTO_PIN" = "1" ]; then
            for rule in "${DNS_ALLOW[@]+"${DNS_ALLOW[@]}"}"; do
                IFS='|' read -r _domain _proto _ports setname <<< "$rule"
                [ -z "$setname" ] && continue
                echo "    set $setname {"
                echo "        type ipv6_addr"
                echo "        flags timeout"
                echo "    }"
            done
        fi

        echo "    chain forward {"
        echo "        type filter hook forward priority 0; policy drop;"
        echo
        echo "        ct state established,related accept"
        echo "        ct state invalid drop"
        echo

        if [ "${#BLOCK_IP6[@]}" -gt 0 ]; then
            echo "        # --- BLOCK IPv6 rules ---"
            for rule in "${BLOCK_IP6[@]}"; do
                IFS='|' read -r target proto ports <<< "$rule"
                emit_transport_rules "ip6 daddr $target" "$proto" "$ports" "drop" "block-ip6"
            done
            echo
        fi

        if [ "${#ALLOW_IP6[@]}" -gt 0 ]; then
            echo "        # --- ALLOW IPv6 rules ---"
            for rule in "${ALLOW_IP6[@]}"; do
                IFS='|' read -r target proto ports <<< "$rule"
                emit_transport_rules "ip6 daddr $target" "$proto" "$ports" "accept" "allow-ip6"
            done
            echo
        fi

        if [ "$AUTO_PIN" = "1" ] && [ "${#DNS_ALLOW[@]}" -gt 0 ]; then
            echo "        # --- ALLOW DNS-resolved IPv6 IPs ---"
            declare -A seen6_rules=()
            for rule in "${DNS_ALLOW[@]}"; do
                IFS='|' read -r _domain proto ports setname <<< "$rule"
                [ -z "$setname" ] && continue
                if [ -z "$ports" ]; then
                    if [ -n "$proto" ]; then
                        key="@$setname|meta l4proto $proto"
                        [ -n "${seen6_rules[$key]:-}" ] && continue
                        seen6_rules[$key]=1
                        printf '        ip6 daddr @%s meta l4proto %s accept comment "allow-dns-resolved"\n' "$setname" "$proto"
                    else
                        key="@$setname|"
                        [ -n "${seen6_rules[$key]:-}" ] && continue
                        seen6_rules[$key]=1
                        printf '        ip6 daddr @%s accept comment "allow-dns-resolved"\n' "$setname"
                    fi
                    continue
                fi
                if [[ "$ports" == *,* ]]; then
                    dport="dport { $ports }"
                else
                    dport="dport $ports"
                fi
                if [ -n "$proto" ]; then
                    key="@$setname|$proto $dport"
                    [ -n "${seen6_rules[$key]:-}" ] && continue
                    seen6_rules[$key]=1
                    printf '        ip6 daddr @%s %s %s accept comment "allow-dns-resolved"\n' "$setname" "$proto" "$dport"
                else
                    for p in tcp udp; do
                        key="@$setname|$p $dport"
                        [ -n "${seen6_rules[$key]:-}" ] && continue
                        seen6_rules[$key]=1
                        printf '        ip6 daddr @%s %s %s accept comment "allow-dns-resolved"\n' "$setname" "$p" "$dport"
                    done
                fi
            done
            echo
        fi

        echo "        # --- Default policy ---"
        if [ "$DEFAULT_POLICY" = "allow" ]; then
            echo '        accept comment "default-allow"'
        else
            echo '        drop comment "default-deny"'
        fi

        echo "    }"
        echo
        echo "    chain postrouting {"
        echo "        type nat hook postrouting priority 100;"
        echo
        echo "        ip6 saddr fd00::/8 ip6 daddr != fd00::/8 masquerade"
        echo "    }"
        echo "}"
        echo
    }
} > /etc/nftables.conf

echo "Generated nftables config:"
cat /etc/nftables.conf

nft -f /etc/nftables.conf

# --- Generate CoreDNS config ---
# One server block per zone: CoreDNS routes queries to the most specific zone,
# so deny zones win over allow zones and the root block applies the default.
DNS_DEFAULT="${DNS_DEFAULT:-deny}"
DNS_UPSTREAM="${DNS_UPSTREAM:-1.1.1.1,8.8.8.8}"
DNS_UPSTREAM_SPACES="${DNS_UPSTREAM//,/ }"

# format_upstream converts the comma-separated DNS_UPSTREAM list into a
# space-separated list of CoreDNS forward targets.  Entries that already
# carry a scheme (tls://, dns://, https://, …) are forwarded as-is so the
# caller controls the protocol.  Bare IPs / hostnames get no scheme, which
# makes CoreDNS use plain DNS on port 53.
format_upstream() {
    local result=""
    local srv
    while IFS= read -r srv; do
        [ -z "$srv" ] && continue
        result+="$srv "
    done < <(echo "$DNS_UPSTREAM" | tr ',' '\n')
    echo "${result% }"
}

declare -A deny_zones=()
{
    for domain in "${DNS_DENY[@]+"${DNS_DENY[@]}"}"; do
        key="${domain,,}"
        [ -n "${deny_zones[$key]:-}" ] && continue
        deny_zones[$key]=1
        echo "$domain:53 {"
        echo "    errors"
        echo "    template IN ANY . {"
        echo "        rcode NXDOMAIN"
        echo "    }"
        echo "}"
        echo
    done

    declare -A emitted_zones=()
    for rule in "${DNS_ALLOW[@]+"${DNS_ALLOW[@]}"}"; do
        IFS='|' read -r domain _proto _ports _setname <<< "$rule"
        key="${domain,,}"
        # deny wins; duplicate zone blocks are a CoreDNS startup error
        [ -n "${deny_zones[$key]:-}" ] && continue
        [ -n "${emitted_zones[$key]:-}" ] && continue
        emitted_zones[$key]=1
        echo "$domain:53 {"
        echo "    errors"
        echo "    log"
        echo "    forward . $(format_upstream)"
        echo "}"
        echo
    done

    echo ".:53 {"
    echo "    errors"
    echo "    log"
    if [ "$DNS_DEFAULT" = "allow" ]; then
        echo "    forward . $(format_upstream)"
    else
        echo "    template IN ANY . {"
        echo "        rcode NXDOMAIN"
        echo "    }"
    fi
    echo "}"
} > /etc/coredns/Corefile

echo "Generated CoreDNS config:"
cat /etc/coredns/Corefile

# --- Start CoreDNS (+ dns-pin sidecar when pinning DNS allow rules) ---
pin_count=0
if [ "$AUTO_PIN" = "1" ]; then
    for rule in "${DNS_ALLOW[@]+"${DNS_ALLOW[@]}"}"; do
        IFS='|' read -r _domain _proto _ports setname <<< "$rule"
        [ -n "$setname" ] && pin_count=$((pin_count + 1))
    done
fi

if [ "$pin_count" -gt 0 ]; then
    echo "Firewall ready. Starting CoreDNS with dns-pin ($pin_count pinnable rule(s))..."
    # Foreground pipeline: if either side exits the container restarts.
    # dns-pin re-emits CoreDNS log lines to stdout for `docker logs`.
    coredns -conf /etc/coredns/Corefile 2>&1 | dns-pin
else
    echo "Firewall ready. Starting CoreDNS..."
    exec coredns -conf /etc/coredns/Corefile
fi
