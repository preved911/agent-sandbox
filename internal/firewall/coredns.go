package firewall

import (
	"fmt"
	"strings"

	"github.com/preved911/agent-sandbox/internal/config"
)

// GenerateCoreDNSConfig generates a CoreDNS Corefile from DNS rules.
// Deny zones return NXDOMAIN and are checked first (deny wins).
// Returns the full Corefile content as a string.
func GenerateCoreDNSConfig(network *config.NetworkConfig) string {
	var b strings.Builder

	dnsDefault := "deny"
	dnsUpstream := "1.1.1.1 8.8.8.8"
	if network != nil {
		if network.DNS.Default != "" {
			dnsDefault = network.DNS.Default
		}
		if len(network.DNS.Upstream) > 0 {
			dnsUpstream = strings.Join(network.DNS.Upstream, " ")
		}
	}

	b.WriteString(".:53 {\n")
	b.WriteString("    errors\n")
	b.WriteString("    log\n\n")

	// Deny zones (deny wins — checked first)
	if network != nil && len(network.DNS.Deny) > 0 {
		b.WriteString("    # Deny zones (deny wins)\n")
		for _, domain := range network.DNS.Deny {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				b.WriteString(fmt.Sprintf("    template IN ANY %s {\n", domain))
				b.WriteString("        rcode NXDOMAIN\n")
				b.WriteString("    }\n")
			}
		}
		b.WriteString("\n")
	}

	// Allow domains — forward to upstream
	if network != nil && len(network.DNS.Allow) > 0 {
		b.WriteString("    # Forward allowed domains to upstream\n")
		for _, domain := range network.DNS.Allow {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				b.WriteString(fmt.Sprintf("    %s {\n", domain))
				b.WriteString(fmt.Sprintf("        forward . %s\n", dnsUpstream))
				b.WriteString("    }\n")
			}
		}
		b.WriteString("\n")
	}

	// Default policy
	b.WriteString("    # Default policy\n")
	if dnsDefault == "allow" {
		b.WriteString("    . {\n")
		b.WriteString(fmt.Sprintf("        forward . %s\n", dnsUpstream))
		b.WriteString("    }\n")
	} else {
		b.WriteString("    . {\n")
		b.WriteString("        template IN ANY {\n")
		b.WriteString("            rcode NXDOMAIN\n")
		b.WriteString("        }\n")
		b.WriteString("    }\n")
	}

	b.WriteString("}\n")

	return b.String()
}

// ValidateDNSRules checks for conflicts between allow and deny DNS rules.
// Returns warnings for overlapping domains.
func ValidateDNSRules(network *config.NetworkConfig) []string {
	if network == nil {
		return nil
	}

	var warnings []string

	for _, deny := range network.DNS.Deny {
		deny = strings.TrimSpace(deny)
		if deny == "" {
			continue
		}
		for _, allow := range network.DNS.Allow {
			allow = strings.TrimSpace(allow)
			if allow == "" {
				continue
			}
			if domainsOverlap(deny, allow) {
				warnings = append(warnings,
					fmt.Sprintf("DNS conflict: %s (allow) overlaps with %s (deny) — deny wins", allow, deny))
			}
		}
	}

	return warnings
}

// domainsOverlap checks if two domain patterns overlap.
// Exact match: "foo.com" overlaps "foo.com".
// Wildcard: "*.foo.com" overlaps "sub.foo.com".
// Subdomain: "foo.com" overlaps "bar.foo.com".
func domainsOverlap(a, b string) bool {
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")

	// Exact match
	if a == b {
		return true
	}

	// Wildcard matching
	if strings.HasPrefix(a, "*.") {
		suffix := a[1:] // ".foo.com"
		if strings.HasSuffix(b, suffix) || b == suffix[1:] {
			return true
		}
	}
	if strings.HasPrefix(b, "*.") {
		suffix := b[1:]
		if strings.HasSuffix(a, suffix) || a == suffix[1:] {
			return true
		}
	}

	// Subdomain matching
	if strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a) {
		return true
	}

	return false
}
