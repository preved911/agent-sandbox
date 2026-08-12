package firewall

import (
	"strings"
	"testing"

	"github.com/preved911/agent-sandbox/internal/config"
)

func TestGenerateNftablesConfig_DenyBeforeAllow(t *testing.T) {
	network := &config.FirewallConfig{
		Default: "deny",
		CIDR: config.CIDRRules{
			Allow: []string{"10.0.0.0/8", "192.168.0.0/16"},
			Deny:  []string{"10.0.0.0/24"},
		},
	}

	cfg := GenerateNftablesConfig(network, "eth0", nil, "10.161.0.0/24")

	// Deny rules must appear before allow rules
	denyIdx := strings.Index(cfg, "ip daddr 10.0.0.0/24 drop")
	allowIdx := strings.Index(cfg, "ip daddr 10.0.0.0/8 accept")

	if denyIdx < 0 {
		t.Error("deny CIDR rule not found")
	}
	if allowIdx < 0 {
		t.Error("allow CIDR rule not found")
	}
	if denyIdx >= allowIdx {
		t.Errorf("deny rule (pos=%d) must come before allow rule (pos=%d)", denyIdx, allowIdx)
	}
}

func TestGenerateNftablesConfig_DefaultDeny(t *testing.T) {
	network := &config.FirewallConfig{
		Default: "deny",
	}

	cfg := GenerateNftablesConfig(network, "eth0", nil, "")

	if !strings.Contains(cfg, "drop comment \"default-deny\"") {
		t.Error("expected default-deny policy")
	}
}

func TestGenerateNftablesConfig_DefaultAllow(t *testing.T) {
	network := &config.FirewallConfig{
		Default: "allow",
	}

	cfg := GenerateNftablesConfig(network, "eth0", nil, "")

	if !strings.Contains(cfg, "accept comment \"default-allow\"") {
		t.Error("expected default-allow policy")
	}
}

func TestGenerateNftablesConfig_SNAT(t *testing.T) {
	cfg := GenerateNftablesConfig(nil, "eth1", nil, "10.161.0.0/24")

	if !strings.Contains(cfg, "ip saddr 10.161.0.0/24") {
		t.Error("expected SNAT rule for agent subnet")
	}
	if !strings.Contains(cfg, "oifname \"eth1\"") {
		t.Error("expected SNAT rule with correct interface")
	}
}

func TestGenerateNftablesConfig_SNATFallback(t *testing.T) {
	cfg := GenerateNftablesConfig(nil, "eth0", nil, "")

	if !strings.Contains(cfg, "ip saddr 10.0.0.0/8") {
		t.Error("expected fallback SNAT rule")
	}
}

func TestGenerateNftablesConfig_Established(t *testing.T) {
	cfg := GenerateNftablesConfig(nil, "eth0", nil, "")

	if !strings.Contains(cfg, "ct state established,related accept") {
		t.Error("expected established/related rule")
	}
	if !strings.Contains(cfg, "ct state invalid drop") {
		t.Error("expected invalid drop rule")
	}
}

func TestGenerateNftablesConfig_DNAT(t *testing.T) {
	dnat := &DNATConfig{
		AgentIP:   "172.20.0.10",
		AgentPort: "4096/tcp",
	}

	cfg := GenerateNftablesConfig(nil, "eth0", dnat, "")

	if !strings.Contains(cfg, "prerouting") {
		t.Error("expected prerouting chain")
	}
	if !strings.Contains(cfg, "tcp dport 4096 dnat to 172.20.0.10") {
		t.Error("expected DNAT rule for agent")
	}
	if !strings.Contains(cfg, "dnat-agent") {
		t.Error("expected dnat-agent comment")
	}
}

func TestGenerateNftablesConfig_NoDNAT(t *testing.T) {
	cfg := GenerateNftablesConfig(nil, "eth0", nil, "")

	if strings.Contains(cfg, "prerouting") {
		t.Error("should not have prerouting chain when dnat is nil")
	}
}

func TestGenerateNftablesConfigWithReverse(t *testing.T) {
	network := &config.FirewallConfig{Default: "deny"}
	dnat := &DNATConfig{
		AgentIP:   "172.20.0.10",
		AgentPort: "4096/tcp",
	}

	cfg := GenerateNftablesConfigWithReverse(network, dnat, "eth0", "10.161.0.0/24")

	if !strings.Contains(cfg, "dnat to 172.20.0.10") {
		t.Error("expected DNAT rule in combined config")
	}
	if !strings.Contains(cfg, "drop comment \"default-deny\"") {
		t.Error("expected default-deny policy in combined config")
	}
}

func TestValidateCIDRRules_NoConflict(t *testing.T) {
	network := &config.FirewallConfig{
		CIDR: config.CIDRRules{
			Allow: []string{"10.0.0.0/8"},
			Deny:  []string{"192.168.0.0/16"},
		},
	}

	warnings := ValidateCIDRRules(network)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %d", len(warnings))
	}
}

func TestValidateCIDRRules_Conflict(t *testing.T) {
	network := &config.FirewallConfig{
		CIDR: config.CIDRRules{
			Allow: []string{"10.0.0.0/8"},
			Deny:  []string{"10.0.0.0/24"},
		},
	}

	warnings := ValidateCIDRRules(network)
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(warnings))
	}
	if !strings.Contains(warnings[0], "overlap") {
		t.Errorf("warning should mention overlap: %s", warnings[0])
	}
}

func TestValidateCIDRRules_NilNetwork(t *testing.T) {
	warnings := ValidateCIDRRules(nil)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for nil network, got %d", len(warnings))
	}
}
