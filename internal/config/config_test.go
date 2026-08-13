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
	if cfg.Run.Firewall.Default != "deny" {
		t.Errorf("Firewall.Default = %q, want %q", cfg.Run.Firewall.Default, "deny")
	}
	if len(cfg.Run.Firewall.CIDR.Allow) != 1 || cfg.Run.Firewall.CIDR.Allow[0] != "10.0.0.0/8" {
		t.Errorf("Firewall.CIDR.Allow = %v, want [10.0.0.0/8]", cfg.Run.Firewall.CIDR.Allow)
	}
	if len(cfg.Run.Firewall.CIDR.Deny) != 1 || cfg.Run.Firewall.CIDR.Deny[0] != "10.0.0.0/24" {
		t.Errorf("Firewall.CIDR.Deny = %v, want [10.0.0.0/24]", cfg.Run.Firewall.CIDR.Deny)
	}
	if len(cfg.Run.Firewall.DNS.Allow) != 2 {
		t.Errorf("Firewall.DNS.Allow len = %d, want 2", len(cfg.Run.Firewall.DNS.Allow))
	}
	if len(cfg.Run.Firewall.DNS.Deny) != 1 {
		t.Errorf("Firewall.DNS.Deny len = %d, want 1", len(cfg.Run.Firewall.DNS.Deny))
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
					Firewall: FirewallConfig{
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
			Firewall: FirewallConfig{
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
					Firewall: FirewallConfig{Default: tt.def},
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

func TestLoadUnifiedRules(t *testing.T) {
	content := `
default_profile: default
profiles:
  default:
    build:
      dockerfile: ./Dockerfile
    run:
      workdir: /workspace
      firewall:
        default: deny
        rules:
          - type: allow
            target: "0.0.0.0/0"
          - type: block
            target: "5.45.192.0/18"
          - type: allow
            target: "api.example.org"
          - type: block
            target: "evil.example.org"
          - type: allow
            target: "api.anthropic.com"
            protocol: tcp
            port: 443
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Run.Firewall.Rules) != 5 {
		t.Fatalf("Rules len = %d, want 5", len(cfg.Run.Firewall.Rules))
	}
	// Check rule types
	if cfg.Run.Firewall.Rules[0].Type != "allow" {
		t.Errorf("Rules[0].Type = %q, want %q", cfg.Run.Firewall.Rules[0].Type, "allow")
	}
	if cfg.Run.Firewall.Rules[1].Type != "block" {
		t.Errorf("Rules[1].Type = %q, want %q", cfg.Run.Firewall.Rules[1].Type, "block")
	}
	// Check NormalizeRules
	cfg.Run.Firewall.NormalizeRules()
	if len(cfg.Run.Firewall.CIDR.Allow) != 1 {
		t.Errorf("CIDR.Allow len = %d, want 1", len(cfg.Run.Firewall.CIDR.Allow))
	}
	if len(cfg.Run.Firewall.CIDR.Deny) != 1 {
		t.Errorf("CIDR.Deny len = %d, want 1", len(cfg.Run.Firewall.CIDR.Deny))
	}
	if len(cfg.Run.Firewall.DNS.Allow) != 2 {
		t.Errorf("DNS.Allow len = %d, want 2", len(cfg.Run.Firewall.DNS.Allow))
	}
	if len(cfg.Run.Firewall.DNS.Deny) != 1 {
		t.Errorf("DNS.Deny len = %d, want 1", len(cfg.Run.Firewall.DNS.Deny))
	}
}

func TestValidateRules_InvalidType(t *testing.T) {
	cfg := &Config{
		Run: RunConfig{
			Port: PortConfig{Container: "4096/tcp"},
			Firewall: FirewallConfig{
				Rules: []Rule{
					{Type: "invalid", Target: "10.0.0.0/8"},
				},
			},
		},
	}
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for invalid rule type")
	}
}

func TestValidateRules_EmptyTarget(t *testing.T) {
	cfg := &Config{
		Run: RunConfig{
			Port: PortConfig{Container: "4096/tcp"},
			Firewall: FirewallConfig{
				Rules: []Rule{
					{Type: "allow", Target: ""},
				},
			},
		},
	}
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for empty rule target")
	}
}

func TestValidateRules_IPPortPortRange(t *testing.T) {
	cfg := &Config{
		Run: RunConfig{
			Port: PortConfig{Container: "4096/tcp"},
			Firewall: FirewallConfig{
				Rules: []Rule{
					{Type: "allow", Target: "1.2.3.4:443", Protocol: "tcp", Port: 443},
				},
			},
		},
	}
	err := Validate(cfg)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRules_InvalidProtocol(t *testing.T) {
	cfg := &Config{
		Run: RunConfig{
			Port: PortConfig{Container: "4096/tcp"},
			Firewall: FirewallConfig{
				Rules: []Rule{
					{Type: "allow", Target: "1.2.3.4:443", Protocol: "sctp", Port: 443},
				},
			},
		},
	}
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for invalid protocol")
	}
}

func TestValidateRules_DenyAlias(t *testing.T) {
	r := Rule{Type: "deny", Target: "10.0.0.0/8"}
	if r.IsBlocked() != true {
		t.Error("deny should be blocked")
	}
}

func TestRuleClassification(t *testing.T) {
	tests := []struct {
		target string
		isCIDR bool
		isDNS  bool
		isIP   bool
	}{
		{"10.0.0.0/8", true, false, false},
		{"192.168.1.0/24", true, false, false},
		{"api.example.org", false, true, false},
		{"*.anthropic.com", false, true, false},
		{"1.2.3.4:443", false, false, true},
		{"10.0.0.1:8080", false, false, true},
	}
	for _, tt := range tests {
		r := Rule{Target: tt.target}
		if r.IsCIDR() != tt.isCIDR {
			t.Errorf("IsCIDR(%q) = %v, want %v", tt.target, r.IsCIDR(), tt.isCIDR)
		}
		if r.IsDNS() != tt.isDNS {
			t.Errorf("IsDNS(%q) = %v, want %v", tt.target, r.IsDNS(), tt.isDNS)
		}
		if r.IsIPPort() != tt.isIP {
			t.Errorf("IsIPPort(%q) = %v, want %v", tt.target, r.IsIPPort(), tt.isIP)
		}
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
