// Package network manages Docker isolated bridge networks for sandboxes.
package network

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/docker/docker/api/types/filters"
	dockernet "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/preved911/agent-sandbox/internal/sandbox"
)

// SubnetFromHash derives a unique /24 IPv4 subnet and a unique /64 IPv6 ULA
// subnet from the sandbox hash.
//
// IPv4: 10.<b1>.<b2>.0/24, gateway .1 (added as secondary IP on firewall),
// firewall primary .2, agent .10.
//
// IPv6: fd<b1>:<b2>00::/64 (ULA, matches the fd00::/8 masquerade rule in
// the firewall's nftables postrouting chain), firewall ::2, agent ::a.
//
// Uses the first 4 hex chars of the hash, giving 65536 possible unique
// subnets per sandbox on each address family.
func SubnetFromHash(hash string) (subnet, gateway, firewallIP, agentIP, subnet6, firewallIP6, agentIP6 string) {
	b1 := hash[0:2]
	b2 := hash[2:4]
	b1i, _ := strconv.ParseInt(b1, 16, 64)
	b2i, _ := strconv.ParseInt(b2, 16, 64)

	prefix4 := fmt.Sprintf("10.%d.%d", b1i, b2i)
	subnet = prefix4 + ".0/24"
	gateway = prefix4 + ".1"
	firewallIP = prefix4 + ".2"
	agentIP = prefix4 + ".10"

	// ULA /64: fd<b1>:<b2>00::/64
	prefix6 := fmt.Sprintf("fd%s:%s00", b1, b2)
	subnet6 = prefix6 + "::/64"
	firewallIP6 = prefix6 + "::2"
	agentIP6 = prefix6 + "::a"
	return
}

// defaultBridgeIPv6 returns true when the Docker default bridge network has
// IPv6 enabled.  Any error (e.g. the network doesn't exist) is treated as
// "not supported" so sandbox creation can still proceed without IPv6.
func defaultBridgeIPv6(ctx context.Context, cli *client.Client) bool {
	resp, err := cli.NetworkInspect(ctx, "bridge", dockernet.InspectOptions{})
	if err != nil {
		return false
	}
	return resp.EnableIPv6
}

// Create creates an isolated Docker bridge network for the sandbox.
// The network has no default gateway to the host bridge — the firewall
// container provides the only path to external networks.
//
// IPv6 is enabled only when the Docker default bridge network has IPv6
// enabled, so the sandbox mirrors the host's networking capabilities.
//
// Network name: agent-sandbox-<hash>-net
//
// Returns the network ID.
func Create(ctx context.Context, cli *client.Client, hash string) (networkID string, err error) {
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)

	// Probe whether Docker has IPv6 support enabled on the default bridge.
	ipv6 := defaultBridgeIPv6(ctx, cli)

	// Check if network already exists with correct subnet.
	networks, err := cli.NetworkList(ctx, dockernet.ListOptions{
		Filters: filters.NewArgs(filters.Arg("name", name)),
	})
	if err != nil {
		return "", fmt.Errorf("list networks: %w", err)
	}
	for _, n := range networks {
		if n.Name == name {
			// Verify subnet matches. If not, remove and recreate.
			if subnetOK, err := hasSubnet(ctx, cli, n.ID, ipv6); err != nil {
				return "", fmt.Errorf("inspect network %s: %w", name, err)
			} else if !subnetOK {
				fmt.Printf("Network %s has wrong subnet, recreating...\n", name)
				if err := cli.NetworkRemove(ctx, n.ID); err != nil {
					return "", fmt.Errorf("remove stale network %s: %w", name, err)
				}
				break // fall through to create
			}
			return n.ID, nil
		}
	}

	subnet, gateway, _, _, subnet6, _, _ := SubnetFromHash(hash)
	_, ipNet, _ := net.ParseCIDR(subnet)

	ipamConfigs := []dockernet.IPAMConfig{
		{Subnet: ipNet.String(), Gateway: gateway},
	}
	if ipv6 {
		_, ipNet6, _ := net.ParseCIDR(subnet6)
		ipamConfigs = append(ipamConfigs, dockernet.IPAMConfig{Subnet: ipNet6.String()})
	}

	opts := dockernet.CreateOptions{
		Driver:     "bridge",
		EnableIPv6: &ipv6,
		IPAM: &dockernet.IPAM{
			Config: ipamConfigs,
		},
		Labels: map[string]string{
			sandbox.Label:     "true",
			sandbox.LabelName: name,
		},
	}

	resp, err := cli.NetworkCreate(ctx, name, opts)
	if err != nil {
		return "", fmt.Errorf("create network %s: %w", name, err)
	}

	return resp.ID, nil
}

// hasSubnet checks if an existing network has the required subnets and is not
// Internal.  When ipv6 is true, the IPv6 subnet must also be present.
func hasSubnet(ctx context.Context, cli *client.Client, networkID string, ipv6 bool) (bool, error) {
	resp, err := cli.NetworkInspect(ctx, networkID, dockernet.InspectOptions{})
	if err != nil {
		return false, err
	}
	// Networks must NOT be Internal (Internal=true prevents default gateway assignment).
	if resp.Internal {
		return false, nil
	}
	// Extract hash from network name to derive expected subnets.
	// Network name format: agent-sandbox-<hash>-net
	name := resp.Name
	const prefix = "agent-sandbox-"
	const suffix = "-net"
	if len(name) <= len(prefix)+len(suffix) {
		return false, nil
	}
	hash := name[len(prefix) : len(name)-len(suffix)]
	expected, _, _, _, expected6, _, _ := SubnetFromHash(hash)
	_, required, err := net.ParseCIDR(expected)
	if err != nil {
		return false, err
	}

	foundV4, foundV6 := false, false
	for _, cfg := range resp.IPAM.Config {
		if cfg.Subnet == "" {
			continue
		}
		_, actual, err := net.ParseCIDR(cfg.Subnet)
		if err != nil {
			continue
		}
		if actual.String() == required.String() {
			foundV4 = true
		}
		if ipv6 {
			_, required6, err := net.ParseCIDR(expected6)
			if err == nil && actual.String() == required6.String() {
				foundV6 = true
			}
		}
	}

	if !foundV4 {
		return false, nil
	}
	if ipv6 && !foundV6 {
		return false, nil
	}
	return true, nil
}

// Remove removes the isolated network by hash.
func Remove(ctx context.Context, cli *client.Client, hash string) error {
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)
	return cli.NetworkRemove(ctx, name)
}

// Exists checks if the network exists.
func Exists(ctx context.Context, cli *client.Client, hash string) (bool, error) {
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)
	networks, err := cli.NetworkList(ctx, dockernet.ListOptions{
		Filters: filters.NewArgs(filters.Arg("name", name)),
	})
	if err != nil {
		return false, err
	}
	for _, n := range networks {
		if n.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// GatewayIP returns the bridge gateway IP for the sandbox network.
// This is the host-side interface that containers use as their default route.
// The host-side proxy goroutines listen on this IP so containers can reach them.
func GatewayIP(ctx context.Context, cli *client.Client, hash string) (string, error) {
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)
	resp, err := cli.NetworkInspect(ctx, name, dockernet.InspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspect network %s: %w", name, err)
	}
	for _, cfg := range resp.IPAM.Config {
		if cfg.Gateway != "" {
			return cfg.Gateway, nil
		}
	}
	return "", fmt.Errorf("network %s: no gateway IP found", name)
}
