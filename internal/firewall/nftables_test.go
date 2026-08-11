package firewall

import (
	"strings"
	"testing"

	"github.com/preved911/opencode-sandbox/internal/config"
)

func TestGenerateNftablesConfig_DenyBeforeAllow(t *testing.T) {
	network := &config.NetworkConfig{
		Default: "deny",
		CIDR: config.CIDRRules{
			Allow: []string{"10.0.0.0/8", "192.168.0.0/16"},
			Deny:  []string{"10.0.0.0/24"},
		},
	}

	cfg := GenerateNftablesConfig(network, "eth0")

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
	network := &config.NetworkConfig{
		Default: "deny",
	}

	cfg := GenerateNftablesConfig(network, "eth0")

	if !strings.Contains(cfg, "drop comment \"default-deny\"") {
		t.Error("expected default-deny policy")
	}
}

func TestGenerateNftablesConfig_DefaultAllow(t *testing.T) {
	network := &config.NetworkConfig{
		Default: "allow",
	}

	cfg := GenerateNftablesConfig(network, "eth0")

	if !strings.Contains(cfg, "accept comment \"default-allow\"") {
		t.Error("expected default-allow policy")
	}
}

func TestGenerateNftablesConfig_SNAT(t *testing.T) {
	cfg := GenerateNftablesConfig(nil, "eth1")

	if !strings.Contains(cfg, "ip saddr 172.20.0.0/16") {
		t.Error("expected SNAT rule for agent subnet")
	}
	if !strings.Contains(cfg, "oifname \"eth1\"") {
		t.Error("expected SNAT rule with correct interface")
	}
}

func TestGenerateNftablesConfig_Established(t *testing.T) {
	cfg := GenerateNftablesConfig(nil, "eth0")

	if !strings.Contains(cfg, "ct state established,related accept") {
		t.Error("expected established/related rule")
	}
	if !strings.Contains(cfg, "ct state invalid drop") {
		t.Error("expected invalid drop rule")
	}
}

func TestGenerateNftablesConfigWithReverse(t *testing.T) {
	network := &config.NetworkConfig{Default: "deny"}
	reverse := &config.ReverseForwardConfig{
		Ports: []config.PortForward{
			{Host: 3000, Container: 3000},
			{Host: 8080, Container: 80},
		},
	}

	cfg := GenerateNftablesConfigWithReverse(network, reverse, "eth0")

	if !strings.Contains(cfg, "host:3000 -> container:3000") {
		t.Error("expected reverse forward comment for port 3000")
	}
	if !strings.Contains(cfg, "host:8080 -> container:80") {
		t.Error("expected reverse forward comment for port 8080")
	}
}

func TestValidateCIDRRules_NoConflict(t *testing.T) {
	network := &config.NetworkConfig{
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
	network := &config.NetworkConfig{
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
