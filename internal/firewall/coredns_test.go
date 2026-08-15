package firewall

import (
	"strings"
	"testing"

	"github.com/preved911/agent-sandbox/internal/config"
)

func TestGenerateCoreDNSConfig_DenyBeforeAllow(t *testing.T) {
	network := &config.FirewallConfig{
		DNS: config.DNSRules{
			Allow: []string{"anthropic.com", "*.github.com"},
			Deny:  []string{"evil.anthropic.com"},
		},
	}

	cfg := GenerateCoreDNSConfig(network)

	// Per-zone server blocks: deny zone block must appear before allow zone block
	denyIdx := strings.Index(cfg, "evil.anthropic.com:53 {")
	allowIdx := strings.Index(cfg, "anthropic.com:53 {")

	if denyIdx < 0 {
		t.Error("deny zone server block not found")
	}
	if allowIdx < 0 {
		t.Error("allow zone server block not found")
	}
	if denyIdx >= allowIdx {
		t.Errorf("deny zone (pos=%d) must come before allow zone (pos=%d)", denyIdx, allowIdx)
	}
}

func TestGenerateCoreDNSConfig_DenyReturnsNXDOMAIN(t *testing.T) {
	network := &config.FirewallConfig{
		DNS: config.DNSRules{
			Deny: []string{"blocked.com"},
		},
	}

	cfg := GenerateCoreDNSConfig(network)

	if !strings.Contains(cfg, "blocked.com:53 {") {
		t.Error("expected deny zone server block for blocked.com")
	}
	if !strings.Contains(cfg, "rcode NXDOMAIN") {
		t.Error("expected NXDOMAIN rcode for denied domains")
	}
}

func TestGenerateCoreDNSConfig_AllowForwardsUpstream(t *testing.T) {
	network := &config.FirewallConfig{
		DNS: config.DNSRules{
			Allow:   []string{"api.anthropic.com"},
			Upstream: []string{"1.1.1.1", "8.8.8.8"},
		},
	}

	cfg := GenerateCoreDNSConfig(network)

	if !strings.Contains(cfg, "api.anthropic.com:53 {") {
		t.Error("expected allow zone server block")
	}
	if !strings.Contains(cfg, "forward . 1.1.1.1 8.8.8.8") {
		t.Error("expected forward to upstream resolvers")
	}
}

func TestGenerateCoreDNSConfig_DefaultDeny(t *testing.T) {
	network := &config.FirewallConfig{
		DNS: config.DNSRules{
			Default: "deny",
		},
	}

	cfg := GenerateCoreDNSConfig(network)

	// Default deny = NXDOMAIN for everything not matched
	if !strings.Contains(cfg, "rcode NXDOMAIN") {
		t.Error("expected NXDOMAIN for default deny")
	}
}

func TestGenerateCoreDNSConfig_DefaultAllow(t *testing.T) {
	network := &config.FirewallConfig{
		DNS: config.DNSRules{
			Default:  "allow",
			Upstream: []string{"1.1.1.1"},
		},
	}

	cfg := GenerateCoreDNSConfig(network)

	// Default allow = forward everything to upstream
	if !strings.Contains(cfg, "forward . 1.1.1.1") {
		t.Error("expected forward for default allow")
	}
}

func TestGenerateCoreDNSConfig_NilNetwork(t *testing.T) {
	cfg := GenerateCoreDNSConfig(nil)

	// Should use defaults: deny, upstream 1.1.1.1 8.8.8.8
	if !strings.Contains(cfg, ".:53 {") {
		t.Error("expected listen on :53")
	}
	if !strings.Contains(cfg, "rcode NXDOMAIN") {
		t.Error("expected default deny (NXDOMAIN)")
	}
}

func TestValidateDNSRules_NoConflict(t *testing.T) {
	network := &config.FirewallConfig{
		DNS: config.DNSRules{
			Allow: []string{"anthropic.com"},
			Deny:  []string{"evil.com"},
		},
	}

	warnings := ValidateDNSRules(network)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %d", len(warnings))
	}
}

func TestValidateDNSRules_ExactConflict(t *testing.T) {
	network := &config.FirewallConfig{
		DNS: config.DNSRules{
			Allow: []string{"foo.com"},
			Deny:  []string{"foo.com"},
		},
	}

	warnings := ValidateDNSRules(network)
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(warnings))
	}
}

func TestValidateDNSRules_WildcardConflict(t *testing.T) {
	network := &config.FirewallConfig{
		DNS: config.DNSRules{
			Allow: []string{"*.anthropic.com"},
			Deny:  []string{"evil.anthropic.com"},
		},
	}

	warnings := ValidateDNSRules(network)
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning for wildcard overlap, got %d", len(warnings))
	}
}

func TestDomainsOverlap(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"foo.com", "foo.com", true},
		{"foo.com", "bar.com", false},
		{"*.foo.com", "sub.foo.com", true},
		{"*.foo.com", "foo.com", true},
		{"foo.com", "sub.foo.com", true},
		{"foo.com", "sub.bar.foo.com", true},
		{"*.foo.com", "bar.com", false},
	}

	for _, tt := range tests {
		got := domainsOverlap(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("domainsOverlap(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
