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
func (f *FirewallContainer) GenerateNftables(fwCfg *config.FirewallConfig) string {
	return GenerateNftablesConfig(fwCfg, nil, "")
}

// GenerateCoreDNS generates the CoreDNS config for the sandbox.
func (f *FirewallContainer) GenerateCoreDNS(fwCfg *config.FirewallConfig) string {
	return GenerateCoreDNSConfig(fwCfg)
}

// ValidateConfig validates the firewall configuration and logs warnings.
func (f *FirewallContainer) ValidateConfig(fwCfg *config.FirewallConfig) {
	warnings := ValidateCIDRRules(fwCfg)
	for _, w := range warnings {
		log.Printf("WARNING: %s", w)
	}

	dnsWarnings := ValidateDNSRules(fwCfg)
	for _, w := range dnsWarnings {
		log.Printf("WARNING: %s", w)
	}
}

// FirewallEnv returns environment variables for the firewall container.
func (f *FirewallContainer) FirewallEnv(fwCfg *config.FirewallConfig) []string {
	var env []string

	if fwCfg != nil {
		// CIDR rules
		if len(fwCfg.CIDR.Allow) > 0 {
			env = append(env, fmt.Sprintf("ALLOW_CIDRS=%s", joinStrings(fwCfg.CIDR.Allow)))
		}
		if len(fwCfg.CIDR.Deny) > 0 {
			env = append(env, fmt.Sprintf("DENY_CIDRS=%s", joinStrings(fwCfg.CIDR.Deny)))
		}
		env = append(env, fmt.Sprintf("NETWORK_DEFAULT=%s", defaultStr(fwCfg.Default, "deny")))

		// DNS rules
		if len(fwCfg.DNS.Allow) > 0 {
			env = append(env, fmt.Sprintf("ALLOW_DOMAINS=%s", joinStrings(fwCfg.DNS.Allow)))
		}
		if len(fwCfg.DNS.Deny) > 0 {
			env = append(env, fmt.Sprintf("DENY_DOMAINS=%s", joinStrings(fwCfg.DNS.Deny)))
		}
		env = append(env, fmt.Sprintf("DNS_DEFAULT=%s", defaultStr(fwCfg.DNS.Default, "deny")))
		if len(fwCfg.DNS.Upstream) > 0 {
			env = append(env, fmt.Sprintf("DNS_UPSTREAM=%s", joinStrings(fwCfg.DNS.Upstream)))
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
