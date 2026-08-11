package firewall

import (
	"context"
	"fmt"
	"log"

	"github.com/docker/docker/client"

	"github.com/preved911/agent-sandbox/internal/config"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

// FirewallContainer manages the firewall container for a sandbox.
type FirewallContainer struct {
	cli     *client.Client
	hash    string
	network string
}

// NewFirewallContainer creates a new firewall container manager.
func NewFirewallContainer(cli *client.Client, hash string) *FirewallContainer {
	return &FirewallContainer{
		cli:     cli,
		hash:    hash,
		network: sandbox.ResourceName(hash, sandbox.SuffixNet),
	}
}

// GenerateNftables generates the nftables config for the sandbox.
func (f *FirewallContainer) GenerateNftables(networkCfg *config.NetworkConfig) string {
	return GenerateNftablesConfig(networkCfg, "eth0")
}

// GenerateCoreDNS generates the CoreDNS config for the sandbox.
func (f *FirewallContainer) GenerateCoreDNS(networkCfg *config.NetworkConfig) string {
	return GenerateCoreDNSConfig(networkCfg)
}

// ValidateConfig validates the network configuration and logs warnings.
func (f *FirewallContainer) ValidateConfig(networkCfg *config.NetworkConfig) {
	warnings := ValidateCIDRRules(networkCfg)
	for _, w := range warnings {
		log.Printf("WARNING: %s", w)
	}

	dnsWarnings := ValidateDNSRules(networkCfg)
	for _, w := range dnsWarnings {
		log.Printf("WARNING: %s", w)
	}
}

// FirewallEnv returns environment variables for the firewall container.
func (f *FirewallContainer) FirewallEnv(networkCfg *config.NetworkConfig) []string {
	var env []string

	if networkCfg != nil {
		// CIDR rules
		if len(networkCfg.CIDR.Allow) > 0 {
			env = append(env, fmt.Sprintf("ALLOW_CIDRS=%s", joinStrings(networkCfg.CIDR.Allow)))
		}
		if len(networkCfg.CIDR.Deny) > 0 {
			env = append(env, fmt.Sprintf("DENY_CIDRS=%s", joinStrings(networkCfg.CIDR.Deny)))
		}
		env = append(env, fmt.Sprintf("NETWORK_DEFAULT=%s", defaultStr(networkCfg.Default, "deny")))

		// DNS rules
		if len(networkCfg.DNS.Allow) > 0 {
			env = append(env, fmt.Sprintf("ALLOW_DOMAINS=%s", joinStrings(networkCfg.DNS.Allow)))
		}
		if len(networkCfg.DNS.Deny) > 0 {
			env = append(env, fmt.Sprintf("DENY_DOMAINS=%s", joinStrings(networkCfg.DNS.Deny)))
		}
		env = append(env, fmt.Sprintf("DNS_DEFAULT=%s", defaultStr(networkCfg.DNS.Default, "deny")))
		if len(networkCfg.DNS.Upstream) > 0 {
			env = append(env, fmt.Sprintf("DNS_UPSTREAM=%s", joinStrings(networkCfg.DNS.Upstream)))
		}
	}

	return env
}

// HealthCheck verifies the firewall container is running.
func (f *FirewallContainer) HealthCheck(ctx context.Context) error {
	name := sandbox.ResourceName(f.hash, sandbox.SuffixFirewall)

	resp, err := f.cli.ContainerInspect(ctx, name)
	if err != nil {
		return fmt.Errorf("firewall container inspect failed: %w", err)
	}

	if !resp.State.Running {
		return fmt.Errorf("firewall container %q is not running (status: %s)", name, resp.State.Status)
	}

	return nil
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ","
		}
		result += s
	}
	return result
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
