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
	// a1b2c3d4 → a1=161, b2=178 → 10.161.178.0/24
	subnet, gw, fw, agent := SubnetFromHash("a1b2c3d4")

	if subnet != "10.161.178.0/24" {
		t.Errorf("subnet: got %q, want 10.161.178.0/24", subnet)
	}
	if gw != "10.161.178.1" {
		t.Errorf("gateway: got %q, want 10.161.178.1", gw)
	}
	if fw != "10.161.178.2" {
		t.Errorf("firewall IP: got %q, want 10.161.178.2", fw)
	}
	if agent != "10.161.178.10" {
		t.Errorf("agent IP: got %q, want 10.161.178.10", agent)
	}
}

func TestSubnetFromHash_Different(t *testing.T) {
	s1, _, _, _ := SubnetFromHash("aabbccdd")
	s2, _, _, _ := SubnetFromHash("00112233")
	if s1 == s2 {
		t.Errorf("different hashes should produce different subnets: both got %q", s1)
	}
}

func TestSubnetFromHash_Deterministic(t *testing.T) {
	s1, _, _, _ := SubnetFromHash("deadbeef")
	s2, _, _, _ := SubnetFromHash("deadbeef")
	if s1 != s2 {
		t.Errorf("same hash should produce same subnet: %q vs %q", s1, s2)
	}
}
