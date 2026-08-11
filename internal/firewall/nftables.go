package firewall

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/preved911/opencode-sandbox/internal/config"
)

// GenerateNftablesConfig generates an nftables configuration from network rules.
// Deny rules are emitted BEFORE allow rules (deny wins).
// Returns the full nftables config as a string.
func GenerateNftablesConfig(network *config.NetworkConfig, outsideIF string) string {
	var b strings.Builder

	b.WriteString("#!/usr/sbin/nft -f\n\n")
	b.WriteString("flush ruleset\n\n")
	b.WriteString("table ip firewall {\n")

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
	if network != nil && len(network.CIDR.Deny) > 0 {
		b.WriteString("        # --- DENY CIDR rules (deny wins) ---\n")
		for _, cidr := range network.CIDR.Deny {
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				b.WriteString(fmt.Sprintf("        ip daddr %s drop comment \"deny-cidr\"\n", cidr))
			}
		}
		b.WriteString("\n")
	}

	// ALLOW CIDR rules second
	if network != nil && len(network.CIDR.Allow) > 0 {
		b.WriteString("        # --- ALLOW CIDR rules ---\n")
		for _, cidr := range network.CIDR.Allow {
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
	if network != nil && network.Default == "allow" {
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
	b.WriteString(fmt.Sprintf("        ip saddr 172.20.0.0/16 oifname \"%s\" masquerade\n", outsideIF))
	b.WriteString("    }\n")

	b.WriteString("}\n")

	return b.String()
}

// GenerateNftablesConfigWithReverse generates nftables config with reverse forwarding rules.
func GenerateNftablesConfigWithReverse(network *config.NetworkConfig, reverseForward *config.ReverseForwardConfig, outsideIF string) string {
	config := GenerateNftablesConfig(network, outsideIF)

	if reverseForward == nil || len(reverseForward.Ports) == 0 {
		return config
	}

	var b strings.Builder
	b.WriteString(config)
	b.WriteString("\n# Reverse forwarding rules\n")

	for _, port := range reverseForward.Ports {
		b.WriteString(fmt.Sprintf("# Reverse forward: host:%d -> container:%d (socat handles forwarding)\n",
			port.Host, port.Container))
	}

	return b.String()
}

// ValidateCIDRRules checks for conflicts between allow and deny CIDR lists.
// Returns warnings for overlapping CIDRs.
func ValidateCIDRRules(network *config.NetworkConfig) []string {
	if network == nil {
		return nil
	}

	var warnings []string

	allowCIDRs := parseCIDRs(network.CIDR.Allow)
	denyCIDRs := parseCIDRs(network.CIDR.Deny)

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
