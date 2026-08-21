package network

import (
	"testing"

	"github.com/preved911/agent-sandbox/internal/sandbox"
)

func TestNetworkName(t *testing.T) {
	hash := "a1b2c3d4"
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)
	expected := "agent-sandbox-a1b2c3d4-net"
	if name != expected {
		t.Errorf("expected %q, got %q", expected, name)
	}
	if len(name) > 63 {
		t.Errorf("network name %q exceeds 63 chars (%d)", name, len(name))
	}
}

func TestSubnetFromHash(t *testing.T) {
	// a1b2c3d4 → a1=161, b2=178 → 10.161.178.0/24, fda1:b200::/64
	subnet, gw, fw, agent, subnet6, fw6, agent6 := SubnetFromHash("a1b2c3d4")

	if subnet != "10.161.178.0/24" {
		t.Errorf("subnet: got %q, want 10.161.178.0/24", subnet)
	}
	if gw != "10.161.178.1" {
		t.Errorf("gateway: got %q, want 10.161.178.1 (secondary IP on firewall)", gw)
	}
	if fw != "10.161.178.2" {
		t.Errorf("firewall IP: got %q, want 10.161.178.2", fw)
	}
	if agent != "10.161.178.10" {
		t.Errorf("agent IP: got %q, want 10.161.178.10", agent)
	}
	if subnet6 != "fda1:b200::/64" {
		t.Errorf("subnet6: got %q, want fda1:b200::/64", subnet6)
	}
	if fw6 != "fda1:b200::2" {
		t.Errorf("firewall IPv6: got %q, want fda1:b200::2", fw6)
	}
	if agent6 != "fda1:b200::a" {
		t.Errorf("agent IPv6: got %q, want fda1:b200::a", agent6)
	}
}

func TestSubnetFromHash_Different(t *testing.T) {
	s1, _, _, _, s1v6, _, _ := SubnetFromHash("aabbccdd")
	s2, _, _, _, s2v6, _, _ := SubnetFromHash("00112233")
	if s1 == s2 {
		t.Errorf("different hashes should produce different IPv4 subnets: both got %q", s1)
	}
	if s1v6 == s2v6 {
		t.Errorf("different hashes should produce different IPv6 subnets: both got %q", s1v6)
	}
}

func TestSubnetFromHash_Deterministic(t *testing.T) {
	s1, _, _, _, s1v6, _, _ := SubnetFromHash("deadbeef")
	s2, _, _, _, s2v6, _, _ := SubnetFromHash("deadbeef")
	if s1 != s2 {
		t.Errorf("same hash should produce same IPv4 subnet: %q vs %q", s1, s2)
	}
	if s1v6 != s2v6 {
		t.Errorf("same hash should produce same IPv6 subnet: %q vs %q", s1v6, s2v6)
	}
}
