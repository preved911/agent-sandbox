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
	if err := validateFirewall(&c.Firewall); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	if err := validatePermissions(&c.Permissions); err != nil {
		return fmt.Errorf("permissions: %w", err)
	}
	if err := validateReverseForward(&c.Run.ReverseForward); err != nil {
		return fmt.Errorf("reverse_forward: %w", err)
	}
	return nil
}

func validateFirewall(f *FirewallConfig) error {
	if err := validateDefaultPolicy(f.Network.Default, "network.default"); err != nil {
		return err
	}
	if err := validateCIDRRules(&f.Network.CIDR); err != nil {
		return err
	}
	if err := validateDNSRules(&f.Network.DNS); err != nil {
		return err
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

func validatePermissions(p *PermissionsConfig) error {
	if p.Mode == "" {
		return nil // empty means use default ("override")
	}
	switch p.Mode {
	case "override", "merge":
		return nil
	default:
		return fmt.Errorf("mode: invalid value %q, must be \"override\" or \"merge\"", p.Mode)
	}
}
