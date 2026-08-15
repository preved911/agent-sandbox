package firewall

import (
	"context"
	"fmt"
	"log"
	"strings"

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
	for _, w := range ValidateCIDRRules(fwCfg) {
		log.Printf("WARNING: %s", w)
	}
	for _, w := range ValidateDNSRules(fwCfg) {
		log.Printf("WARNING: %s", w)
	}
}

// FirewallEnv returns environment variables for the firewall container.
//
// FIREWALL_RULES carries the unified rule list, one rule per line with
// pipe-separated fields, consumed by entrypoint.sh (nftables + CoreDNS
// generation) and the dns-pin daemon:
//
//	<type>|<target>|<protocol>|<canonical ports>|<dns set name>
//
// The dns set name field is non-empty only for DNS allow rules when IP pinning
// is enabled. Port specs must already be canonical (ValidateFirewall does this).
func (f *FirewallContainer) FirewallEnv(fwCfg *config.FirewallConfig) []string {
	var env []string
	if fwCfg == nil {
		return env
	}
	fwCfg.NormalizeRules()

	var b strings.Builder
	for _, r := range fwCfg.Rules {
		if r.Target == "" {
			continue
		}
		set := ""
		if r.IsAllowed() && !r.IsCIDR() && fwCfg.PinResolved() {
			set = config.DNSSetName(r.Ports)
		}
		fmt.Fprintf(&b, "%s|%s|%s|%s|%s\n", r.Type, r.Target, r.Protocol, r.Ports, set)
	}
	if rules := b.String(); rules != "" {
		env = append(env, "FIREWALL_RULES="+rules)
	}

	env = append(env, "NETWORK_DEFAULT="+defaultStr(fwCfg.Default, "deny"))
	env = append(env, "DNS_DEFAULT="+defaultStr(fwCfg.DNS.Default, "deny"))
	if len(fwCfg.DNS.Upstream) > 0 {
		env = append(env, "DNS_UPSTREAM="+strings.Join(fwCfg.DNS.Upstream, ","))
	}
	if fwCfg.PinResolved() {
		env = append(env, "AUTO_PIN=1")
	} else {
		env = append(env, "AUTO_PIN=0")
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

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
