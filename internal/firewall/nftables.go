package firewall

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/preved911/agent-sandbox/internal/config"
)

// DNATConfig holds the DNAT target for host→agent forwarding.
type DNATConfig struct {
	AgentIP   string // fixed IP of the agent on the isolated network
	AgentPort string // container port to forward (e.g. "4096/tcp")
}

// GenerateNftablesConfig generates an nftables configuration from the unified
// firewall rules. It expects a config that has passed ValidateFirewall (port
// specs canonicalized).
//
// Rule ordering (deny wins):
//  1. established/related accept, invalid drop
//  2. block rules (CIDR/IP targets) — before any allow, so a blocked CIDR
//     always wins over a DNS-pinned allow
//  3. allow rules (CIDR/IP targets)
//  4. allow rules for DNS-resolved IPs, matching against named sets populated
//     dynamically by the dns-pin daemon
//  5. default policy
//
// Uses IP-based matching (ip saddr/ip daddr) instead of interface names for
// cross-platform compatibility (Docker Desktop for Mac names all interfaces eth0).
func GenerateNftablesConfig(fwCfg *config.FirewallConfig, dnat *DNATConfig, subnet string) string {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n\n")
	b.WriteString("flush ruleset\n\n")
	b.WriteString("table ip firewall {\n")

	writeDNSSets(&b, fwCfg)

	if dnat != nil && dnat.AgentIP != "" && dnat.AgentPort != "" {
		b.WriteString("    chain prerouting {\n")
		b.WriteString("        type nat hook prerouting priority -100;\n\n")
		b.WriteString("        # DNAT: forward published port traffic to agent\n")
		b.WriteString(fmt.Sprintf("        tcp dport %s dnat to %s comment \"dnat-agent\"\n",
			strings.TrimSuffix(dnat.AgentPort, "/tcp"), dnat.AgentIP))
		b.WriteString("    }\n\n")
	}

	b.WriteString("    chain forward {\n")
	b.WriteString("        type filter hook forward priority 0; policy drop;\n\n")
	b.WriteString("        # Allow established/related connections\n")
	b.WriteString("        ct state established,related accept\n\n")
	b.WriteString("        # Drop invalid connections\n")
	b.WriteString("        ct state invalid drop\n\n")

	writeIPRules(&b, fwCfg, true)
	writeIPRules(&b, fwCfg, false)
	writeDNSPinnedRules(&b, fwCfg)

	b.WriteString("        # --- Default policy ---\n")
	if fwCfg != nil && fwCfg.Default == "allow" {
		b.WriteString("        accept comment \"default-allow\"\n")
	} else {
		b.WriteString("        drop comment \"default-deny\"\n")
	}

	b.WriteString("    }\n\n")

	b.WriteString("    chain postrouting {\n")
	b.WriteString("        type nat hook postrouting priority 100;\n\n")
	b.WriteString("        # SNAT outbound traffic from agent to internet\n")
	b.WriteString("        # Exclude intra-subnet traffic (e.g. firewall proxy → agent)\n")
	if subnet != "" {
		b.WriteString(fmt.Sprintf("        ip saddr %s ip daddr != %s masquerade\n", subnet, subnet))
	} else {
		// Fallback for tests — use a generic private range
		b.WriteString("        ip saddr 10.0.0.0/8 ip daddr != 10.0.0.0/8 masquerade\n")
	}
	b.WriteString("    }\n")

	b.WriteString("}\n")

	return b.String()
}

// GenerateNftablesConfigWithReverse generates nftables config with DNAT rules for host→agent access.
func GenerateNftablesConfigWithReverse(fwCfg *config.FirewallConfig, dnat *DNATConfig, subnet string) string {
	return GenerateNftablesConfig(fwCfg, dnat, subnet)
}

// writeDNSSets emits one named set per unique canonical port spec used by DNS
// allow rules (dns_allow_443, dns_allow_8000-8100, dns_allow_any, ...).
// Elements are added at runtime by the dns-pin daemon with per-IP timeouts.
func writeDNSSets(b *strings.Builder, fwCfg *config.FirewallConfig) {
	if fwCfg == nil || !fwCfg.PinResolved() {
		return
	}
	seen := make(map[string]bool)
	var names []string
	for _, r := range fwCfg.Rules {
		if !r.IsAllowed() || r.IsCIDR() || r.Target == "" {
			continue
		}
		name := config.DNSSetName(r.Ports)
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	b.WriteString("    # Named sets for DNS-resolved IPs (populated by dns-pin with TTL timeouts)\n")
	for _, name := range names {
		b.WriteString(fmt.Sprintf("    set %s {\n", name))
		b.WriteString("        type ipv4_addr\n")
		b.WriteString("        flags timeout\n")
		b.WriteString("    }\n")
	}
	b.WriteString("\n")
}

// writeIPRules emits block or allow rules for CIDR/IP targets with protocol
// and port-spec matching. Block rules are emitted before allow rules (deny wins).
func writeIPRules(b *strings.Builder, fwCfg *config.FirewallConfig, blocked bool) {
	if fwCfg == nil {
		return
	}
	var section string
	var verdict string
	if blocked {
		section, verdict = "BLOCK", "drop"
	} else {
		section, verdict = "ALLOW", "accept"
	}
	wrote := false
	for _, r := range fwCfg.Rules {
		if r.Target == "" || r.IsBlocked() != blocked || !r.IsCIDR() {
			continue
		}
		if !wrote {
			b.WriteString(fmt.Sprintf("        # --- %s IP rules (deny wins: block before allow) ---\n", section))
			wrote = true
		}
		for _, match := range nftTransportMatches(r) {
			expr := "ip daddr " + r.Target
			if match != "" {
				expr += " " + match
			}
			b.WriteString(fmt.Sprintf("        %s %s comment \"%s\"\n", expr, verdict, strings.ToLower(section)+"-ip"))
		}
	}
	if wrote {
		b.WriteString("\n")
	}
}

// writeDNSPinnedRules emits accept rules matching DNS-resolved IPs against the
// named sets: `ip daddr @dns_allow_443 tcp dport 443 accept`.
func writeDNSPinnedRules(b *strings.Builder, fwCfg *config.FirewallConfig) {
	if fwCfg == nil || !fwCfg.PinResolved() {
		return
	}
	seen := make(map[string]bool)
	for _, r := range fwCfg.Rules {
		if !r.IsAllowed() || r.IsCIDR() || r.Target == "" {
			continue
		}
		for _, match := range nftTransportMatches(r) {
			expr := "ip daddr @" + config.DNSSetName(r.Ports)
			if match != "" {
				expr += " " + match
			}
			if seen[expr] {
				continue
			}
			seen[expr] = true
			b.WriteString(fmt.Sprintf("        %s accept comment \"allow-dns-resolved\"\n", expr))
		}
	}
	if len(seen) > 0 {
		b.WriteString("\n")
	}
}

// nftTransportMatches returns the nftables transport-layer match expressions
// for a rule's protocol and canonical port spec:
//
//	no protocol, no ports  → [""]
//	protocol only          → ["meta l4proto tcp"]
//	ports only             → ["tcp dport …", "udp dport …"] (both protocols)
//	protocol + ports       → ["tcp dport 443"]
func nftTransportMatches(r config.Rule) []string {
	if r.Ports == "" {
		if r.Protocol == "" {
			return []string{""}
		}
		return []string{"meta l4proto " + r.Protocol}
	}
	dport := "dport " + nftPortSet(r.Ports)
	if r.Protocol == "" {
		return []string{"tcp " + dport, "udp " + dport}
	}
	return []string{r.Protocol + " " + dport}
}

// nftPortSet renders a canonical port spec as an nftables dport operand:
// single port → "443", single range → "5000-5100", multiple items → "{ 80, 443, 8000-8100 }".
func nftPortSet(canonicalSpec string) string {
	if strings.Contains(canonicalSpec, ",") {
		return "{ " + canonicalSpec + " }"
	}
	return canonicalSpec
}

// ValidateCIDRRules checks for conflicts between allow and deny rules with
// CIDR/IP targets. Returns warnings for overlapping CIDRs.
func ValidateCIDRRules(fwCfg *config.FirewallConfig) []string {
	if fwCfg == nil {
		return nil
	}

	var allowCIDRs, denyCIDRs []*net.IPNet
	for _, r := range fwCfg.Rules {
		if !r.IsCIDR() || r.Target == "" {
			continue
		}
		var ipNet *net.IPNet
		if _, network, err := net.ParseCIDR(r.Target); err == nil {
			ipNet = network
		} else if ip := net.ParseIP(r.Target); ip != nil {
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			continue
		}
		if r.IsBlocked() {
			denyCIDRs = append(denyCIDRs, ipNet)
		} else {
			allowCIDRs = append(allowCIDRs, ipNet)
		}
	}

	var warnings []string
	for _, deny := range denyCIDRs {
		for _, allow := range allowCIDRs {
			if cidrsOverlap(deny, allow) {
				warnings = append(warnings,
					fmt.Sprintf("CIDR conflict: %s (allow) overlaps with %s (deny) — deny wins", allow, deny))
			}
		}
	}
	return warnings
}

// cidrsOverlap checks if two CIDR networks overlap.
func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}
