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

func validateFirewall(f *FirewallConfig) error {
	if err := validateDefaultPolicy(f.Default, "firewall.default"); err != nil {
		return err
	}
	// Validate unified rules if present
	if err := validateRules(f.Rules); err != nil {
		return err
	}
	// Validate legacy fields (only if Rules is empty)
	if len(f.Rules) == 0 {
		if err := validateCIDRRules(&f.CIDR); err != nil {
			return err
		}
		if err := validateDNSRules(&f.DNS); err != nil {
			return err
		}
	}
	return nil
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

func validateCIDRRules(r *CIDRRules) error {
	// Parse and validate all CIDR strings
	if err := validateCIDRList(r.Allow, "cidr.allow"); err != nil {
		return err
	}
	if err := validateCIDRList(r.Deny, "cidr.deny"); err != nil {
		return err
	}

	// Conflict detection: same CIDR in both allow and deny
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

	return nil
}

func validateCIDRList(cidrs []string, field string) error {
	for _, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("%s: invalid CIDR %q: %w", field, cidr, err)
		}
	}
	return nil
}

func validateDNSRules(r *DNSRules) error {
	if err := validateDefaultPolicy(r.Default, "dns.default"); err != nil {
		return err
	}

	// Validate upstream IPs
	for _, ip := range r.Upstream {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("dns.upstream: invalid IP address %q", ip)
		}
	}

	// Domain conflict detection: same domain in allow and deny
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

	return nil
}

func validateRules(rules []Rule) error {
	for i, r := range rules {
		// Normalize type
		r.Type = normalizeRuleType(r.Type)
		if r.Type != "allow" && r.Type != "block" {
			return fmt.Errorf("rules[%d].type: invalid value %q, must be \"allow\" or \"block\"", i, r.Type)
		}
		if r.Target == "" {
			return fmt.Errorf("rules[%d].target: required", i)
		}
		// Validate target format
		switch {
		case r.IsCIDR():
			if _, _, err := net.ParseCIDR(r.Target); err != nil {
				return fmt.Errorf("rules[%d].target: invalid CIDR %q: %w", i, r.Target, err)
			}
		case r.IsIPPort():
			parts := strings.SplitN(r.Target, ":", 2)
			if net.ParseIP(parts[0]) == nil {
				return fmt.Errorf("rules[%d].target: invalid IP %q", i, parts[0])
			}
			// Validate port range
			if r.Port < 1 || r.Port > 65535 {
				return fmt.Errorf("rules[%d].port: %d out of range (1-65535)", i, r.Port)
			}
		case r.IsDNS():
			// DNS names with globs are valid — no strict validation needed
		default:
			return fmt.Errorf("rules[%d].target: unrecognized format %q (expected CIDR, DNS name, or IP:port)", i, r.Target)
		}
		// Validate protocol for IP:port rules
		if r.IsIPPort() && r.Protocol != "" {
			switch r.Protocol {
			case "tcp", "udp":
			default:
				return fmt.Errorf("rules[%d].protocol: invalid value %q, must be \"tcp\" or \"udp\"", i, r.Protocol)
			}
		}
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
