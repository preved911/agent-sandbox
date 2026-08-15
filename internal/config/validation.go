package config

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// Validate performs all validation checks on a Config.
// It returns an error if the config is invalid, and logs warnings for
// non-fatal issues like conflicting CIDR rules.
func Validate(c *Config) error {
	if err := validateRun(&c.Run); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if err := validateFirewall(&c.Run.Firewall); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	if err := validateReverseForward(&c.Run.ReverseForward); err != nil {
		return fmt.Errorf("reverse_forward: %w", err)
	}
	return nil
}

// NormalizePort normalizes a container port string.
// "4096" → "4096/tcp", "4096/udp" → "4096/udp", "4096/tcp" → "4096/tcp".
func NormalizePort(port string) string {
	if port == "" {
		return ""
	}
	if !strings.Contains(port, "/") {
		return port + "/tcp"
	}
	return port
}

func validateRun(r *RunConfig) error {
	if r.Port.Container == "" {
		return fmt.Errorf("port.container: required (e.g. \"4096/tcp\")")
	}
	r.Port.Container = NormalizePort(r.Port.Container)
	// Validate port number part is numeric
	numStr := strings.SplitN(r.Port.Container, "/", 2)[0]
	if numStr == "" {
		return fmt.Errorf("port.container: port number required")
	}
	for _, ch := range numStr {
		if ch < '0' || ch > '9' {
			return fmt.Errorf("port.container: port number must be numeric, got %q", numStr)
		}
	}
	return nil
}

// ValidateFirewall validates and normalizes the firewall section of a config:
// legacy CIDR/DNS lists are converted into unified Rules and port specs are
// canonicalized in place. Callers should invoke this before generating
// firewall env vars or nftables/CoreDNS configuration.
func ValidateFirewall(f *FirewallConfig) error {
	return validateFirewall(f)
}

func validateFirewall(f *FirewallConfig) error {
	if err := validateDefaultPolicy(f.Default, "firewall.default"); err != nil {
		return err
	}
	if err := validateDefaultPolicy(f.DNS.Default, "dns.default"); err != nil {
		return err
	}
	// Validate upstream IPs
	for _, ip := range f.DNS.Upstream {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("dns.upstream: invalid IP address %q", ip)
		}
	}
	if len(f.Rules) == 0 {
		// Legacy format: conflict advisories before conversion to unified rules.
		warnCIDRConflicts(&f.CIDR)
		warnDomainConflicts(&f.DNS)
	}
	// Convert legacy lists into unified rules (no-op when Rules is present).
	f.NormalizeRules()
	return validateRules(f.Rules)
}

func validateDefaultPolicy(val, field string) error {
	if val == "" {
		return nil // empty means use default ("deny")
	}
	switch val {
	case "deny", "allow":
		return nil
	default:
		return fmt.Errorf("%s: invalid value %q, must be \"deny\" or \"allow\"", field, val)
	}
}

// warnCIDRConflicts logs warnings for CIDRs appearing in (or overlapping
// between) both legacy allow and deny lists; deny wins.
func warnCIDRConflicts(r *CIDRRules) {
	if err := validateCIDRList(r.Allow, "cidr.allow"); err != nil {
		log.Print("WARNING: ", err)
	}
	if err := validateCIDRList(r.Deny, "cidr.deny"); err != nil {
		log.Print("WARNING: ", err)
	}

	allowSet := make(map[string]*net.IPNet, len(r.Allow))
	for _, cidr := range r.Allow {
		_, network, _ := net.ParseCIDR(cidr)
		allowSet[cidr] = network
	}

	for _, denyCIDR := range r.Deny {
		_, denyNet, _ := net.ParseCIDR(denyCIDR)

		// Exact match
		if _, exists := allowSet[denyCIDR]; exists {
			log.Printf("WARNING: CIDR %q appears in both allow and deny lists; deny wins", denyCIDR)
			continue
		}

		// Overlap check: deny ⊂ allow or allow ⊂ deny
		for allowCIDR, allowNet := range allowSet {
			if denyNet != nil && allowNet != nil {
				if denyNet.Contains(allowNet.IP) || allowNet.Contains(denyNet.IP) {
					log.Printf("WARNING: overlapping CIDRs %q (allow) and %q (deny); deny wins", allowCIDR, denyCIDR)
				}
			}
		}
	}
}

func validateCIDRList(cidrs []string, field string) error {
	for _, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("%s: invalid CIDR %q: %w", field, cidr, err)
		}
	}
	return nil
}

// warnDomainConflicts logs warnings for domains appearing in both legacy
// allow and deny lists; deny wins.
func warnDomainConflicts(r *DNSRules) {
	allowSet := make(map[string]bool, len(r.Allow))
	for _, d := range r.Allow {
		allowSet[strings.ToLower(d)] = true
	}

	for _, d := range r.Deny {
		lower := strings.ToLower(d)
		if allowSet[lower] {
			log.Printf("WARNING: domain %q appears in both allow and deny lists; deny wins", d)
			continue
		}

		// Wildcard + specific deny = info (intentional narrowing)
		if strings.HasPrefix(d, "*.") {
			specific := d[2:]
			if allowSet[specific] {
				log.Printf("INFO: deny wildcard %q narrows specific allow %q (intentional)", d, specific)
			}
		}
	}
}

// validateRules validates the unified rule list and canonicalizes port specs
// in place: after validation, rule.Ports holds the canonical (sorted, deduped,
// disjoint) string form that drives nftables emission and named-set naming.
func validateRules(rules []Rule) error {
	seen := make(map[string]bool, len(rules))
	for i := range rules {
		r := &rules[i]
		r.Type = normalizeRuleType(r.Type)
		if r.Type != "allow" && r.Type != "block" {
			return fmt.Errorf("rules[%d].type: invalid value %q, must be \"allow\" or \"block\"", i, r.Type)
		}
		r.Target = strings.TrimSpace(r.Target)
		if r.Target == "" {
			return fmt.Errorf("rules[%d].target: required", i)
		}

		if r.Protocol != "" {
			switch r.Protocol {
			case "tcp", "udp":
			default:
				return fmt.Errorf("rules[%d].protocol: invalid value %q, must be \"tcp\" or \"udp\"", i, r.Protocol)
			}
		}

		if r.Ports != "" {
			canonical, err := CanonicalPortSpec(r.Ports)
			if err != nil {
				return fmt.Errorf("rules[%d].ports (target %q): %w", i, r.Target, err)
			}
			r.Ports = canonical
		}

		switch {
		case r.IsIPPort():
			ip, port, _ := strings.Cut(r.Target, ":")
			return fmt.Errorf("rules[%d].target: IP:port targets (%q) are not supported — use target %q with ports: %q", i, r.Target, ip, port)
		case r.IsCIDR():
			if err := validateIPRuleTarget(i, r.Target); err != nil {
				return err
			}
		case r.IsDNS():
			// DNS names with globs are valid — no strict validation needed.
			key := r.Type + "\x00" + strings.ToLower(r.Target)
			if seen[key] {
				log.Printf("WARNING: rules[%d]: duplicate %s rule for %q — earlier rule wins", i, r.Type, r.Target)
			}
			seen[key] = true
		default:
			return fmt.Errorf("rules[%d].target: unrecognized format %q (expected CIDR, IP, or DNS name)", i, r.Target)
		}
	}
	return nil
}

// validateIPRuleTarget checks that an IP/CIDR target parses and is IPv4 —
// the nftables ruleset is generated in the `ip` family, so IPv6 targets
// cannot be enforced and fail early with a clear message.
func validateIPRuleTarget(i int, target string) error {
	ip := target
	if _, network, err := net.ParseCIDR(target); err == nil {
		ip = network.IP.String()
	} else if net.ParseIP(target) == nil {
		return fmt.Errorf("rules[%d].target: invalid CIDR or IP %q", i, target)
	}
	if net.ParseIP(ip).To4() == nil {
		return fmt.Errorf("rules[%d].target: IPv6 is not supported (%q)", i, target)
	}
	return nil
}

func validateReverseForward(r *ReverseForwardConfig) error {
	for i, p := range r.Ports {
		if p.Host < 1 || p.Host > 65535 {
			return fmt.Errorf("ports[%d].host: port %d out of range (1-65535)", i, p.Host)
		}
		if p.Container < 1 || p.Container > 65535 {
			return fmt.Errorf("ports[%d].container: port %d out of range (1-65535)", i, p.Container)
		}
	}
	for i, s := range r.Sockets {
		if s.Socket == "" {
			return fmt.Errorf("sockets[%d].socket: path required", i)
		}
		if s.Container < 1 || s.Container > 65535 {
			return fmt.Errorf("sockets[%d].container: port %d out of range (1-65535)", i, s.Container)
		}
	}
	return nil
}
