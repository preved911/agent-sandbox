package firewall

import (
	"fmt"
	"strings"

	"github.com/preved911/agent-sandbox/internal/config"
)

// GenerateCoreDNSConfig generates a CoreDNS Corefile from the unified firewall
// rules. It expects a config that has passed ValidateFirewall.
//
// The Corefile uses one server block per zone so CoreDNS routes each query to
// the most specific zone: a deny zone returns NXDOMAIN (template plugin), an
// allow zone forwards to upstream, and the root zone applies the default
// policy. A zone listed in both allow and deny is emitted as deny only
// (duplicate zone blocks are a CoreDNS startup error).
func GenerateCoreDNSConfig(fwCfg *config.FirewallConfig) string {
	dnsDefault := "deny"
	dnsUpstream := "1.1.1.1 8.8.8.8"
	if fwCfg != nil {
		if fwCfg.DNS.Default != "" {
			dnsDefault = fwCfg.DNS.Default
		}
		if len(fwCfg.DNS.Upstream) > 0 {
			dnsUpstream = strings.Join(fwCfg.DNS.Upstream, " ")
		}
	}

	var denyZones, allowZones []string
	if fwCfg != nil {
		for _, r := range fwCfg.Rules {
			r.Target = strings.TrimSpace(r.Target)
			if r.Target == "" || r.IsCIDR() {
				continue
			}
			if r.IsBlocked() {
				denyZones = append(denyZones, r.Target)
			} else {
				allowZones = append(allowZones, r.Target)
			}
		}
	}

	denied := make(map[string]bool, len(denyZones))
	for _, z := range denyZones {
		denied[strings.ToLower(z)] = true
	}

	var b strings.Builder

	for _, zone := range denyZones {
		b.WriteString(fmt.Sprintf("%s:53 {\n", zone))
		b.WriteString("    errors\n")
		b.WriteString("    template IN ANY . {\n")
		b.WriteString("        rcode NXDOMAIN\n")
		b.WriteString("    }\n")
		b.WriteString("}\n\n")
	}

	for _, zone := range allowZones {
		if denied[strings.ToLower(zone)] {
			continue // deny wins; duplicate zone blocks are a CoreDNS error
		}
		b.WriteString(fmt.Sprintf("%s:53 {\n", zone))
		b.WriteString("    errors\n")
		b.WriteString("    log\n")
		b.WriteString(fmt.Sprintf("    forward . %s\n", dnsUpstream))
		b.WriteString("}\n\n")
	}

	b.WriteString(".:53 {\n")
	b.WriteString("    errors\n")
	b.WriteString("    log\n")
	if dnsDefault == "allow" {
		b.WriteString(fmt.Sprintf("    forward . %s\n", dnsUpstream))
	} else {
		b.WriteString("    template IN ANY . {\n")
		b.WriteString("        rcode NXDOMAIN\n")
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")

	return b.String()
}

// ValidateDNSRules checks for conflicts between allow and deny DNS rules.
// Returns warnings for overlapping domains.
func ValidateDNSRules(fwCfg *config.FirewallConfig) []string {
	if fwCfg == nil {
		return nil
	}

	var allows, denies []string
	for _, r := range fwCfg.Rules {
		r.Target = strings.TrimSpace(r.Target)
		if r.Target == "" || r.IsCIDR() {
			continue
		}
		if r.IsBlocked() {
			denies = append(denies, r.Target)
		} else {
			allows = append(allows, r.Target)
		}
	}

	var warnings []string
	for _, deny := range denies {
		for _, allow := range allows {
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
	// DNS names are case-insensitive.
	a = strings.ToLower(strings.TrimSuffix(a, "."))
	b = strings.ToLower(strings.TrimSuffix(b, "."))

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
