// Package network manages Docker isolated bridge networks for sandboxes.
package network

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/preved911/agent-sandbox/internal/sandbox"
)

// SubnetFromHash derives a unique /24 subnet from the sandbox hash.
// Returns subnet, gateway, firewall IP, and agent IP.
// Gateway is 10.x.x.1 (will be added as secondary IP on the firewall).
// Firewall primary IP is 10.x.x.2.
// Uses the first 4 hex chars of the hash as two octets in the 10.x.x.0/24 range,
// giving 65536 possible unique subnets per sandbox.
func SubnetFromHash(hash string) (subnet, gateway, firewallIP, agentIP string) {
	b1, _ := strconv.ParseInt(hash[0:2], 16, 64)
	b2, _ := strconv.ParseInt(hash[2:4], 16, 64)
	prefix := fmt.Sprintf("10.%d.%d", b1, b2)
	return prefix + ".0/24", prefix + ".1", prefix + ".2", prefix + ".10"
}

// Create creates an isolated Docker bridge network for the sandbox.
// The network has no default gateway to the host bridge — the firewall
// container provides the only path to external networks.
//
// Network name: agent-sandbox-<hash>-net
//
// Returns the network ID.
func Create(ctx context.Context, cli *client.Client, hash string) (networkID string, err error) {
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)

	// Check if network already exists with correct subnet.
	networks, err := cli.NetworkList(ctx, network.ListOptions{
		Filters: filters.NewArgs(filters.Arg("name", name)),
	})
	if err != nil {
		return "", fmt.Errorf("list networks: %w", err)
	}
	for _, n := range networks {
		if n.Name == name {
			// Verify subnet matches. If not, remove and recreate.
			if subnetOK, err := hasSubnet(ctx, cli, n.ID); err != nil {
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

	// Derive unique subnet from hash to avoid collisions with other Docker networks.
	subnet, gateway, _, _ := SubnetFromHash(hash)
	_, ipNet, _ := net.ParseCIDR(subnet)

	// Create bridge network with unique subnet.
	// Gateway is set to the firewall IP so agent traffic routes through the firewall.
	resp, err := cli.NetworkCreate(ctx, name, network.CreateOptions{
		Driver: "bridge",
		IPAM: &network.IPAM{
			Config: []network.IPAMConfig{
				{Subnet: ipNet.String(), Gateway: gateway},
			},
		},
		Labels: map[string]string{
			sandbox.Label:     "true",
			sandbox.LabelName: name,
		},
	})
	if err != nil {
		return "", fmt.Errorf("create network %s: %w", name, err)
	}

	return resp.ID, nil
}

// hasSubnet checks if a network has the required subnet and correct Internal flag.
func hasSubnet(ctx context.Context, cli *client.Client, networkID string) (bool, error) {
	resp, err := cli.NetworkInspect(ctx, networkID, network.InspectOptions{})
	if err != nil {
		return false, err
	}
	// Networks must NOT be Internal (Internal=true prevents default gateway assignment).
	if resp.Internal {
		return false, nil
	}
	// Extract hash from network name to derive expected subnet.
	// Network name format: agent-sandbox-<hash>-net
	name := resp.Name
	const prefix = "agent-sandbox-"
	const suffix = "-net"
	if len(name) > len(prefix)+len(suffix) {
		hash := name[len(prefix) : len(name)-len(suffix)]
		expected, _, _, _ := SubnetFromHash(hash)
		_, required, err := net.ParseCIDR(expected)
		if err != nil {
			return false, err
		}
		for _, cfg := range resp.IPAM.Config {
			if cfg.Subnet != "" {
				_, actual, err := net.ParseCIDR(cfg.Subnet)
				if err != nil {
					continue
				}
				if actual.String() == required.String() {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// Remove removes the isolated network by hash.
func Remove(ctx context.Context, cli *client.Client, hash string) error {
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)
	return cli.NetworkRemove(ctx, name)
}

// Exists checks if the network exists.
func Exists(ctx context.Context, cli *client.Client, hash string) (bool, error) {
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)
	networks, err := cli.NetworkList(ctx, network.ListOptions{
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
	resp, err := cli.NetworkInspect(ctx, name, network.InspectOptions{})
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
