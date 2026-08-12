package stack

import (
	"testing"

	"github.com/preved911/agent-sandbox/internal/config"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

func TestStackResourceNames(t *testing.T) {
	hash := sandbox.HashPath("/Users/bob/projects/myapp")

	tests := []struct {
		suffix string
		want   string
	}{
		{sandbox.SuffixAgent, "agent-sandbox-" + hash + "-agent"},
		{sandbox.SuffixFirewall, "agent-sandbox-" + hash + "-firewall"},
		{sandbox.SuffixSessions, "agent-sandbox-" + hash + "-sessions"},
		{sandbox.SuffixNet, "agent-sandbox-" + hash + "-net"},
	}

	for _, tt := range tests {
		got := sandbox.ResourceName(hash, tt.suffix)
		if got != tt.want {
			t.Errorf("ResourceName(%s, %s) = %q, want %q", hash, tt.suffix, got, tt.want)
		}
	}
}

func TestStackNew(t *testing.T) {
	hash := sandbox.HashPath("/test/path")
	cfg := &config.Config{
		Name: "test",
	}

	// Stack.New doesn't require Docker, so we can test construction.
	// We pass nil for cli since we're not actually calling Docker APIs.
	s := New(nil, hash, "/tmp/test", cfg)
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.hash != hash {
		t.Errorf("hash = %q, want %q", s.hash, hash)
	}
	if s.config != cfg {
		t.Error("config not set correctly")
	}
}

func TestStackStatus(t *testing.T) {
	// Stack status test placeholder
	// Full integration tests require Docker daemon
	t.Skip("integration test — requires Docker daemon")
}
