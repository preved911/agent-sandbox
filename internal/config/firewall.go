package config

import (
	"net"
	"strings"
)

// FirewallConfig holds network filtering rules for the sandbox.
type FirewallConfig struct {
	// Image overrides the default firewall image tag.
	// If empty, uses "agent-sandbox-firewall:latest" and auto-builds if missing.
	Image string `yaml:"image,omitempty"`

	// Default is the IP-layer policy when no rule matches.
	// "deny" (default, secure) drops everything not explicitly allowed.
	// "allow" (permissive) allows everything not explicitly denied.
	Default string `yaml:"default,omitempty"`

	// Rules is the unified firewall rule list. Deny/block rules win over allow.
	// Each rule has a target (CIDR, DNS name with optional glob, or IP:port).
	// When Rules is non-empty, CIDR and DNS fields are ignored.
	Rules []Rule `yaml:"rules,omitempty"`

	// AutoPinResolved auto-allows resolved IPs for DNS-allowed domains.
	AutoPinResolved *bool `yaml:"auto_pin_resolved,omitempty"`

	// DNS rules for domain-layer filtering.
	DNS DNSRules `yaml:"dns,omitempty"`

	// CIDR rules for IP-layer filtering.
	CIDR CIDRRules `yaml:"cidr,omitempty"`
}

// Rule is a single firewall rule. Deny/block rules always win over allow.
type Rule struct {
	// Type is "allow" or "block" (or "deny", alias for "block").
	Type string `yaml:"type"`

	// Target is the rule target. Format depends on the rule type:
	//   - CIDR: "10.0.0.0/8", "192.168.1.0/24", "5.45.192.0/18"
	//   - DNS: "api.example.org", "*.anthropic.com", "evil.com"
	//   - IP:port: "1.2.3.4:443", "10.0.0.1:8080"
	Target string `yaml:"target"`

	// Protocol is "tcp", "udp", or "" (any). Only used with IP:port targets.
	Protocol string `yaml:"protocol,omitempty"`

	// Port is the port number. Only used with IP:port targets.
	Port int `yaml:"port,omitempty"`
}

// IsBlocked returns true if this is a block/deny rule.
func (r Rule) IsBlocked() bool {
	return r.Type == "block" || r.Type == "deny"
}

// IsAllowed returns true if this is an allow rule.
func (r Rule) IsAllowed() bool {
	return r.Type == "allow"
}

// IsCIDR returns true if the target is a CIDR address.
func (r Rule) IsCIDR() bool {
	_, _, err := net.ParseCIDR(r.Target)
	return err == nil
}

// IsDNS returns true if the target is a DNS name (not an IP:port and not CIDR).
func (r Rule) IsDNS() bool {
	if r.IsCIDR() || r.IsIPPort() {
		return false
	}
	// Must contain at least one dot and no colons
	return strings.Contains(r.Target, ".") && !strings.Contains(r.Target, ":")
}

// IsIPPort returns true if the target is in "IP:port" format.
func (r Rule) IsIPPort() bool {
	if !strings.Contains(r.Target, ":") {
		return false
	}
	parts := strings.SplitN(r.Target, ":", 2)
	return net.ParseIP(parts[0]) != nil
}

// CIDRRules holds allow and deny lists in CIDR notation.
// Deny always wins: if the same range appears in both, deny takes precedence.
type CIDRRules struct {
	Allow []string `yaml:"allow,omitempty"`
	Deny  []string `yaml:"deny,omitempty"`
}

// DNSRules holds allow and deny domain lists.
// Deny always wins: deny zones are checked first by CoreDNS.
type DNSRules struct {
	// Default is the DNS policy when no allow/deny rule matches.
	// "deny" (default) returns NXDOMAIN for everything not explicitly allowed.
	// "allow" passes through to upstream for everything not explicitly denied.
	Default string `yaml:"default,omitempty"`

	// Allow domains that resolve (forwarded to upstream).
	Allow []string `yaml:"allow,omitempty"`

	// Deny domains that always return NXDOMAIN, wins over allow (even wildcard matches).
	Deny []string `yaml:"deny,omitempty"`

	// Upstream resolvers the firewall forwards allowlisted queries to.
	Upstream []string `yaml:"upstream,omitempty"`
}

// NormalizeRules converts the unified Rules list into the legacy CIDR/DNS fields.
// When Rules is non-empty, it populates CIDR.Allow, CIDR.Deny, DNS.Allow, DNS.Deny.
// When Rules is empty, legacy fields are used as-is (backward compatible).
func (fwCfg *FirewallConfig) NormalizeRules() {
	if len(fwCfg.Rules) == 0 {
		return // use legacy fields
	}

	// Clear legacy fields and rebuild from Rules
	fwCfg.CIDR = CIDRRules{}
	fwCfg.DNS.Allow = nil
	fwCfg.DNS.Deny = nil

	for _, r := range fwCfg.Rules {
		r.Target = strings.TrimSpace(r.Target)
		if r.Target == "" {
			continue
		}
		r.Type = normalizeRuleType(r.Type)

		switch {
		case r.IsCIDR():
			if r.IsBlocked() {
				fwCfg.CIDR.Deny = append(fwCfg.CIDR.Deny, r.Target)
			} else {
				fwCfg.CIDR.Allow = append(fwCfg.CIDR.Allow, r.Target)
			}
		case r.IsDNS(), r.IsIPPort():
			// DNS names and IP:port targets both go to DNS filtering
			if r.IsBlocked() {
				fwCfg.DNS.Deny = append(fwCfg.DNS.Deny, r.Target)
			} else {
				fwCfg.DNS.Allow = append(fwCfg.DNS.Allow, r.Target)
			}
		default:
			// Default to DNS if it looks like a hostname
			if r.IsBlocked() {
				fwCfg.DNS.Deny = append(fwCfg.DNS.Deny, r.Target)
			} else {
				fwCfg.DNS.Allow = append(fwCfg.DNS.Allow, r.Target)
			}
		}
	}
}

// FilterRules separates rules by type and action.
type FilterRules struct {
	CIDRAllow []string
	CIDRBlock []string
	DNSAllow  []string
	DNSBlock  []string
	PortRules []Rule // IP:port rules
}

// SplitRules separates unified rules by type and action.
func (fwCfg *FirewallConfig) SplitRules() FilterRules {
	fwCfg.NormalizeRules()

	var result FilterRules
	for _, r := range fwCfg.Rules {
		r.Target = strings.TrimSpace(r.Target)
		if r.Target == "" {
			continue
		}
		switch {
		case r.IsCIDR():
			if r.IsBlocked() {
				result.CIDRBlock = append(result.CIDRBlock, r.Target)
			} else {
				result.CIDRAllow = append(result.CIDRAllow, r.Target)
			}
		case r.IsDNS():
			if r.IsBlocked() {
				result.DNSBlock = append(result.DNSBlock, r.Target)
			} else {
				result.DNSAllow = append(result.DNSAllow, r.Target)
			}
		case r.IsIPPort():
			result.PortRules = append(result.PortRules, r)
		default:
			if r.IsBlocked() {
				result.DNSBlock = append(result.DNSBlock, r.Target)
			} else {
				result.DNSAllow = append(result.DNSAllow, r.Target)
			}
		}
	}
	return result
}

// normalizeRuleType normalizes "deny" → "block".
func normalizeRuleType(t string) string {
	if t == "deny" {
		return "block"
	}
	return t
}
