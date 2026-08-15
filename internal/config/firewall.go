package config

import (
	"fmt"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
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
	// Each rule has a target (CIDR, bare IP, or DNS name with optional glob)
	// and optional protocol/port-spec filtering.
	Rules []Rule `yaml:"rules,omitempty"`

	// AutoPinResolved controls whether IPs resolved for DNS-allowed domains are
	// pinned into nftables named sets (two-step DNS enforcement).
	// Default (nil) is true. Set false to resolve DNS allows without opening
	// the IP layer for them.
	AutoPinResolved *bool `yaml:"auto_pin_resolved,omitempty"`

	// DNS holds resolver settings (default policy + upstream servers).
	DNS DNSConfig `yaml:"dns,omitempty"`
}

// Rule is a single firewall rule. Deny/block rules always win over allow.
type Rule struct {
	// Type is "allow" or "block" (or "deny", alias for "block").
	Type string `yaml:"type"`

	// Target is the rule target:
	//   - CIDR: "10.0.0.0/8", "192.168.1.0/24", "5.45.192.0/18"
	//   - bare IP: "1.2.3.4" (treated as a /32 CIDR)
	//   - DNS name: "api.example.org", "*.anthropic.com", "evil.com"
	//
	// CIDR and IP targets are enforced statically by nftables; DNS targets use
	// two-step enforcement (CoreDNS resolution + dynamic nftables pinning).
	Target string `yaml:"target"`

	// Protocol is "tcp" or "udp". Empty means both protocols.
	Protocol string `yaml:"protocol,omitempty"`

	// Ports is a port-spec string: comma-separated single ports and inclusive
	// ranges — "443", "8000-8100", "80,443,8000-8100". Always a quoted string;
	// empty (omitted) means all ports. Canonicalized during Validate.
	Ports string `yaml:"ports,omitempty"`
}

// UnmarshalYAML decodes a Rule and enforces the ports field's uniform type.
// `ports:` must be a quoted string — an unquoted `ports: 443` decodes as a YAML
// int and is rejected here with a "quote the value" hint, because the field
// travels verbatim through YAML → Go structs → env vars → shell and must have
// one stable representation everywhere.
func (r *Rule) UnmarshalYAML(value *yaml.Node) error {
	var fields struct {
		Type     string    `yaml:"type"`
		Target   string    `yaml:"target"`
		Protocol string    `yaml:"protocol,omitempty"`
		Ports    yaml.Node `yaml:"ports,omitempty"`
	}
	if err := value.Decode(&fields); err != nil {
		return err
	}
	r.Type = fields.Type
	r.Target = fields.Target
	r.Protocol = fields.Protocol

	node := fields.Ports
	if node.Kind == 0 {
		return nil // field absent — all ports
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("line %d: ports must be a quoted string like \"443\" or \"80,443,8000-8100\", got %s — quote the value", node.Line, node.ShortTag())
	}
	if node.Value == "" {
		return fmt.Errorf("line %d: ports must not be an empty string — omit the field to match all ports", node.Line)
	}
	r.Ports = node.Value
	return nil
}

// DNSConfig holds resolver settings for DNS filtering.
type DNSConfig struct {
	// Default is the DNS policy when no allow/deny rule matches.
	// "deny" (default) returns NXDOMAIN for everything not explicitly allowed.
	// "allow" passes through to upstream for everything not explicitly denied.
	Default string `yaml:"default,omitempty"`

	// Upstream resolvers the firewall forwards allowlisted queries to.
	Upstream []string `yaml:"upstream,omitempty"`
}

// IsBlocked returns true if this is a block/deny rule.
func (r Rule) IsBlocked() bool {
	return r.Type == "block" || r.Type == "deny"
}

// IsAllowed returns true if this is an allow rule.
func (r Rule) IsAllowed() bool {
	return r.Type == "allow"
}

// IsCIDR returns true if the target is a CIDR or a bare IPv4 address
// (a bare IP behaves as a /32 and matches nftables `ip daddr` directly).
func (r Rule) IsCIDR() bool {
	if strings.Contains(r.Target, "/") {
		_, _, err := net.ParseCIDR(r.Target)
		return err == nil
	}
	// Bare IPv4 (colons would mean IPv6, which is unsupported).
	return !strings.Contains(r.Target, ":") && net.ParseIP(r.Target) != nil
}

// IsDNS returns true if the target is a DNS name (not a CIDR, IP, or IP:port).
// A DNS name never contains "/" or ":".
func (r Rule) IsDNS() bool {
	return !r.IsCIDR() &&
		!strings.Contains(r.Target, "/") &&
		!strings.Contains(r.Target, ":") &&
		strings.Contains(r.Target, ".")
}

// IsIPPort returns true if the target is in the legacy "IP:port" format.
// The unified format rejects these targets in favor of target + ports.
func (r Rule) IsIPPort() bool {
	ip, _, found := strings.Cut(r.Target, ":")
	return found && net.ParseIP(ip) != nil
}

// PinResolved reports whether IPs resolved for DNS-allowed domains should be
// pinned into nftables named sets. Defaults to true when AutoPinResolved is nil.
func (fwCfg *FirewallConfig) PinResolved() bool {
	return fwCfg.AutoPinResolved == nil || *fwCfg.AutoPinResolved
}

// normalizeRuleType normalizes "deny" → "block".
func normalizeRuleType(t string) string {
	if t == "deny" {
		return "block"
	}
	return t
}
