package network

import (
	"testing"

	"github.com/preved911/opencode-sandbox/internal/sandbox"
)

func TestNetworkName(t *testing.T) {
	hash := "a1b2c3d4"
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)
	expected := "opencode-sandbox-a1b2c3d4-net"
	if name != expected {
		t.Errorf("expected %q, got %q", expected, name)
	}
	if len(name) > 63 {
		t.Errorf("network name %q exceeds 63 chars (%d)", name, len(name))
	}
}
