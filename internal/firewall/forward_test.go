package firewall

import (
	"strings"
	"testing"

	"github.com/preved911/agent-sandbox/internal/config"
)

func TestGenerateReverseForwardNftables(t *testing.T) {
	reverse := &config.ReverseForwardConfig{
		Ports: []config.PortForward{
			{Host: 3000, Container: 3000},
			{Host: 8080, Container: 80},
		},
	}

	rules := GenerateReverseForwardNftables(reverse)

	if !strings.Contains(rules, "host:3000 -> container:3000") {
		t.Error("expected comment for port 3000")
	}
	if !strings.Contains(rules, "host:8080 -> container:80") {
		t.Error("expected comment for port 8080")
	}
	if !strings.Contains(rules, "OUTPUT rules") {
		t.Error("expected OUTPUT rules comment")
	}
}

func TestGenerateReverseForwardNftables_Nil(t *testing.T) {
	rules := GenerateReverseForwardNftables(nil)
	if rules != "" {
		t.Errorf("expected empty string for nil config, got %q", rules)
	}
}

func TestGenerateReverseForwardNftables_Empty(t *testing.T) {
	reverse := &config.ReverseForwardConfig{}
	rules := GenerateReverseForwardNftables(reverse)
	if rules != "" {
		t.Errorf("expected empty string for empty config, got %q", rules)
	}
}

func TestGenerateSocatCommands(t *testing.T) {
	reverse := &config.ReverseForwardConfig{
		Ports: []config.PortForward{
			{Host: 3000, Container: 3000},
			{Host: 8080, Container: 80},
		},
	}

	cmds := GenerateSocatCommands(reverse, "172.20.0.1")

	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}

	if !strings.Contains(cmds[0], "TCP-LISTEN:3000,bind=172.20.0.1") {
		t.Errorf("expected listen on 172.20.0.1:3000, got %s", cmds[0])
	}
	if !strings.Contains(cmds[0], "TCP:host.docker.internal:3000") {
		t.Errorf("expected forward to host.docker.internal:3000, got %s", cmds[0])
	}

	if !strings.Contains(cmds[1], "TCP-LISTEN:80,bind=172.20.0.1") {
		t.Errorf("expected listen on 172.20.0.1:80, got %s", cmds[1])
	}
	if !strings.Contains(cmds[1], "TCP:host.docker.internal:8080") {
		t.Errorf("expected forward to host.docker.internal:8080, got %s", cmds[1])
	}
}

func TestGenerateSocatCommands_Nil(t *testing.T) {
	cmds := GenerateSocatCommands(nil, "172.20.0.1")
	if cmds != nil {
		t.Errorf("expected nil for nil config, got %v", cmds)
	}
}

func TestGenerateSocketForwardSocat(t *testing.T) {
	reverse := &config.ReverseForwardConfig{
		Sockets: []config.SocketForward{
			{Socket: "/var/run/docker.sock", Container: 2375},
		},
	}

	cmds := GenerateSocketForwardSocat(reverse, "172.20.0.1")

	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}

	if !strings.Contains(cmds[0], "TCP-LISTEN:2375,bind=172.20.0.1") {
		t.Errorf("expected listen on 172.20.0.1:2375, got %s", cmds[0])
	}
	if !strings.Contains(cmds[0], "UNIX-CONNECT:/var/run/docker.sock") {
		t.Errorf("expected connect to /var/run/docker.sock, got %s", cmds[0])
	}
}

func TestGenerateSocketForwardSocat_Nil(t *testing.T) {
	cmds := GenerateSocketForwardSocat(nil, "172.20.0.1")
	if cmds != nil {
		t.Errorf("expected nil for nil config, got %v", cmds)
	}
}

func TestGenerateSocatEnv(t *testing.T) {
	reverse := &config.ReverseForwardConfig{
		Ports: []config.PortForward{
			{Host: 3000, Container: 3000},
			{Host: 8080, Container: 80},
		},
		Sockets: []config.SocketForward{
			{Socket: "/var/run/docker.sock", Container: 2375},
		},
	}

	env := GenerateSocatEnv(reverse)

	foundPorts := false
	foundSockets := false
	for _, e := range env {
		if strings.HasPrefix(e, "REVERSE_FORWARD_PORTS=") {
			foundPorts = true
			if !strings.Contains(e, "3000:3000") {
				t.Errorf("expected port pair 3000:3000 in %s", e)
			}
			if !strings.Contains(e, "8080:80") {
				t.Errorf("expected port pair 8080:80 in %s", e)
			}
		}
		if strings.HasPrefix(e, "REVERSE_FORWARD_SOCKETS=") {
			foundSockets = true
			if !strings.Contains(e, "/var/run/docker.sock:2375") {
				t.Errorf("expected socket pair in %s", e)
			}
		}
	}

	if !foundPorts {
		t.Error("expected REVERSE_FORWARD_PORTS env var")
	}
	if !foundSockets {
		t.Error("expected REVERSE_FORWARD_SOCKETS env var")
	}
}

func TestGenerateSocatEnv_Nil(t *testing.T) {
	env := GenerateSocatEnv(nil)
	if env != nil {
		t.Errorf("expected nil for nil config, got %v", env)
	}
}
