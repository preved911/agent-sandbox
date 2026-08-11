package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMinimalConfig(t *testing.T) {
	content := `
default_profile: default
profiles:
  default:
    build:
      dockerfile: ./Dockerfile
      context: .
    run:
      workdir: /workspace
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Name != "default" {
		t.Errorf("Name = %q, want %q", cfg.Name, "default")
	}
	if cfg.Build.Dockerfile != "./Dockerfile" {
		t.Errorf("Build.Dockerfile = %q, want %q", cfg.Build.Dockerfile, "./Dockerfile")
	}
	if cfg.Run.Workdir != "/workspace" {
		t.Errorf("Run.Workdir = %q, want %q", cfg.Run.Workdir, "/workspace")
	}
}

func TestLoadFullConfig(t *testing.T) {
	content := `
default_profile: dev
profiles:
  dev:
    build:
      dockerfile: ./Dockerfile
      context: .
    run:
      workdir: /workspace
      port:
        bind: 0.0.0.0
      reverse_forward:
        ports:
          - host: 3000
            container: 3000
        sockets:
          - socket: /var/run/docker.sock
            container: 2375
    firewall:
      network:
        default: deny
        cidr:
          allow:
            - 10.0.0.0/8
          deny:
            - 10.0.0.0/24
        auto_pin_resolved: true
        dns:
          default: deny
          allow:
            - anthropic.com
            - "*.anthropic.com"
          deny:
            - evil.anthropic.com
          upstream:
            - 1.1.1.1
            - 8.8.8.8
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Firewall
	if cfg.Firewall.Network.Default != "deny" {
		t.Errorf("Firewall.Network.Default = %q, want %q", cfg.Firewall.Network.Default, "deny")
	}
	if len(cfg.Firewall.Network.CIDR.Allow) != 1 || cfg.Firewall.Network.CIDR.Allow[0] != "10.0.0.0/8" {
		t.Errorf("Firewall.Network.CIDR.Allow = %v, want [10.0.0.0/8]", cfg.Firewall.Network.CIDR.Allow)
	}
	if len(cfg.Firewall.Network.CIDR.Deny) != 1 || cfg.Firewall.Network.CIDR.Deny[0] != "10.0.0.0/24" {
		t.Errorf("Firewall.Network.CIDR.Deny = %v, want [10.0.0.0/24]", cfg.Firewall.Network.CIDR.Deny)
	}
	if len(cfg.Firewall.Network.DNS.Allow) != 2 {
		t.Errorf("Firewall.Network.DNS.Allow len = %d, want 2", len(cfg.Firewall.Network.DNS.Allow))
	}
	if len(cfg.Firewall.Network.DNS.Deny) != 1 {
		t.Errorf("Firewall.Network.DNS.Deny len = %d, want 1", len(cfg.Firewall.Network.DNS.Deny))
	}

	// Reverse forward
	if len(cfg.Run.ReverseForward.Ports) != 1 {
		t.Errorf("Run.ReverseForward.Ports len = %d, want 1", len(cfg.Run.ReverseForward.Ports))
	}
	if len(cfg.Run.ReverseForward.Sockets) != 1 {
		t.Errorf("Run.ReverseForward.Sockets len = %d, want 1", len(cfg.Run.ReverseForward.Sockets))
	}

	// Port
	if cfg.Run.Port.Bind != "0.0.0.0" {
		t.Errorf("Run.Port.Bind = %q, want %q", cfg.Run.Port.Bind, "0.0.0.0")
	}
}

func TestLoadProfileSelection(t *testing.T) {
	content := `
default_profile: go
profiles:
  go:
    build:
      dockerfile: ./Dockerfile-go
  node:
    build:
      dockerfile: ./Dockerfile-node
`
	path := writeTempConfig(t, content)

	// Default profile
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Build.Dockerfile != "./Dockerfile-go" {
		t.Errorf("default profile Dockerfile = %q, want ./Dockerfile-go", cfg.Build.Dockerfile)
	}

	// Explicit profile
	cfg, err = Load(path, "node")
	if err != nil {
		t.Fatalf("Load(path, 'node') error = %v", err)
	}
	if cfg.Build.Dockerfile != "./Dockerfile-node" {
		t.Errorf("node profile Dockerfile = %q, want ./Dockerfile-node", cfg.Build.Dockerfile)
	}
}

func TestLoadNoProfiles(t *testing.T) {
	content := `
default_profile: default
`
	path := writeTempConfig(t, content)
	_, err := Load(path, "")
	if err == nil {
		t.Fatal("expected error for config with no profiles")
	}
}

func TestLoadUnknownProfile(t *testing.T) {
	content := `
profiles:
  go:
    build:
      dockerfile: ./Dockerfile
`
	path := writeTempConfig(t, content)
	_, err := Load(path, "python")
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"valid cidr", "10.0.0.0/8", false},
		{"valid small cidr", "192.168.1.0/24", false},
		{"invalid cidr", "10.0.0.0", true},
		{"invalid mask", "10.0.0.0/33", true},
		{"garbage", "not-an-ip", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Run: RunConfig{
					Port: PortConfig{Container: "4096/tcp"},
				},
				Firewall: FirewallConfig{
					Network: NetworkConfig{
						CIDR: CIDRRules{Allow: []string{tt.cidr}},
					},
				},
			}
			err := Validate(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePortRange(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"valid port", 3000, false},
		{"min port", 1, false},
		{"max port", 65535, false},
		{"zero port", 0, true},
		{"too high", 65536, true},
		{"negative", -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Run: RunConfig{
					Port: PortConfig{Container: "4096/tcp"},
					ReverseForward: ReverseForwardConfig{
						Ports: []PortForward{{Host: tt.port, Container: 3000}},
					},
				},
			}
			err := Validate(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDNSUpstream(t *testing.T) {
	cfg := &Config{
		Run: RunConfig{
			Port: PortConfig{Container: "4096/tcp"},
		},
		Firewall: FirewallConfig{
			Network: NetworkConfig{
				DNS: DNSRules{
					Upstream: []string{"1.1.1.1", "not-an-ip"},
				},
			},
		},
	}
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for invalid DNS upstream IP")
	}
}

func TestValidateNetworkDefault(t *testing.T) {
	tests := []struct {
		name    string
		def     string
		wantErr bool
	}{
		{"empty", "", false},
		{"deny", "deny", false},
		{"allow", "allow", false},
		{"invalid", "permissive", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Run: RunConfig{
					Port: PortConfig{Container: "4096/tcp"},
				},
				Firewall: FirewallConfig{
					Network: NetworkConfig{Default: tt.def},
				},
			}
			err := Validate(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSharedPathsCheckDefault(t *testing.T) {
	// When docker.macos.shared_paths_check is not set, default is true
	content := `
profiles:
  default:
    build:
      dockerfile: ./Dockerfile
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.SharedPathsCheck {
		t.Error("SharedPathsCheck should default to true")
	}
}

func TestSharedPathsCheckExplicitFalse(t *testing.T) {
	content := `
docker:
  macos:
    shared_paths_check: false
profiles:
  default:
    build:
      dockerfile: ./Dockerfile
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SharedPathsCheck {
		t.Error("SharedPathsCheck should be false when explicitly set")
	}
}

func TestBaseDir(t *testing.T) {
	content := `
profiles:
  default:
    build:
      dockerfile: ./Dockerfile
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	expected := filepath.Dir(path)
	if cfg.BaseDir() != expected {
		t.Errorf("BaseDir() = %q, want %q", cfg.BaseDir(), expected)
	}
}

// writeTempConfig writes a YAML config file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent-sandbox.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeTempConfig: %v", err)
	}
	return path
}
