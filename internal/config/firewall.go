package config

// FirewallConfig holds network filtering rules for the sandbox.
type FirewallConfig struct {
	Network NetworkConfig `yaml:"network,omitempty"`
}

// NetworkConfig defines the CIDR and DNS filtering policy.
type NetworkConfig struct {
	// Default is the IP-layer policy when no allow/deny rule matches.
	// "deny" (default, secure) drops everything not explicitly allowed.
	// "allow" (permissive) allows everything not explicitly denied.
	Default string `yaml:"default,omitempty"`

	// CIDR rules for IP-layer filtering.
	CIDR CIDRRules `yaml:"cidr,omitempty"`

	// AutoPinResolved auto-allows resolved IPs for DNS-allowed domains.
	AutoPinResolved *bool `yaml:"auto_pin_resolved,omitempty"`

	// DNS rules for domain-layer filtering.
	DNS DNSRules `yaml:"dns,omitempty"`
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
