package firewall

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/preved911/agent-sandbox/internal/config"
)

// DNATConfig holds the DNAT target for host→agent forwarding.
type DNATConfig struct {
	AgentIP   string // fixed IP of the agent on the isolated network
	AgentPort string // container port to forward (e.g. "4096/tcp")
}

// GenerateNftablesConfig generates an nftables configuration from network rules.
// Deny rules are emitted BEFORE allow rules (deny wins).
// If dnat is non-nil, a PREROUTING DNAT rule is added to forward traffic to the agent.
// subnet is the sandbox's /24 subnet (e.g. "10.161.0.0/24") for the SNAT rule.
// Uses IP-based matching (ip saddr/ip daddr) instead of interface names for
// cross-platform compatibility (Docker Desktop for Mac names all interfaces eth0).
// Returns the full nftables config as a string.
func GenerateNftablesConfig(fwCfg *config.FirewallConfig, dnat *DNATConfig, subnet string) string {
	var b strings.Builder

	b.WriteString("#!/usr/sbin/nft -f\n\n")
	b.WriteString("flush ruleset\n\n")
	b.WriteString("table ip firewall {\n")

	// PREROUTING chain — DNAT for host→agent access
	if dnat != nil && dnat.AgentIP != "" && dnat.AgentPort != "" {
		b.WriteString("    chain prerouting {\n")
		b.WriteString("        type nat hook prerouting priority -100;\n\n")
		b.WriteString("        # DNAT: forward published port traffic to agent\n")
		b.WriteString(fmt.Sprintf("        tcp dport %s dnat to %s comment \"dnat-agent\"\n",
			strings.TrimSuffix(dnat.AgentPort, "/tcp"), dnat.AgentIP))
		b.WriteString("    }\n\n")
	}

	// FORWARD chain — egress filtering
	b.WriteString("    chain forward {\n")
	b.WriteString("        type filter hook forward priority 0; policy drop;\n\n")

	// Allow established/related (return traffic)
	b.WriteString("        # Allow established/related connections\n")
	b.WriteString("        ct state established,related accept\n\n")

	// Drop invalid
	b.WriteString("        # Drop invalid connections\n")
	b.WriteString("        ct state invalid drop\n\n")

	// DENY CIDR rules first (deny wins)
	if fwCfg != nil && len(fwCfg.CIDR.Deny) > 0 {
		b.WriteString("        # --- DENY CIDR rules (deny wins) ---\n")
		for _, cidr := range fwCfg.CIDR.Deny {
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				b.WriteString(fmt.Sprintf("        ip daddr %s drop comment \"deny-cidr\"\n", cidr))
			}
		}
		b.WriteString("\n")
	}

	// ALLOW CIDR rules second
	if fwCfg != nil && len(fwCfg.CIDR.Allow) > 0 {
		b.WriteString("        # --- ALLOW CIDR rules ---\n")
		for _, cidr := range fwCfg.CIDR.Allow {
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				b.WriteString(fmt.Sprintf("        ip daddr %s accept comment \"allow-cidr\"\n", cidr))
			}
		}
		b.WriteString("\n")
	}

	// Default policy
	b.WriteString("        # --- Default policy ---\n")
	defaultPolicy := "drop"
	if fwCfg != nil && fwCfg.Default == "allow" {
		defaultPolicy = "allow"
	}
	if defaultPolicy == "allow" {
		b.WriteString("        accept comment \"default-allow\"\n")
	} else {
		b.WriteString("        drop comment \"default-deny\"\n")
	}

	b.WriteString("    }\n\n")

	// POSTROUTING chain — SNAT
	b.WriteString("    chain postrouting {\n")
	b.WriteString("        type nat hook postrouting priority 100;\n\n")
	b.WriteString("        # SNAT outbound traffic from agent to internet\n")
	b.WriteString("        # Exclude intra-subnet traffic (e.g. firewall socat → agent)\n")
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

// ValidateCIDRRules checks for conflicts between allow and deny CIDR lists.
// Returns warnings for overlapping CIDRs.
func ValidateCIDRRules(fwCfg *config.FirewallConfig) []string {
	if fwCfg == nil {
		return nil
	}

	var warnings []string

	allowCIDRs := parseCIDRs(fwCfg.CIDR.Allow)
	denyCIDRs := parseCIDRs(fwCfg.CIDR.Deny)

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

// parseCIDRs parses CIDR strings and returns network prefixes.
func parseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Warning: invalid CIDR %q: %v", cidr, err)
			continue
		}
		nets = append(nets, ipNet)
	}
	return nets
}

// cidrsOverlap checks if two CIDR networks overlap.
func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}
