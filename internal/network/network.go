// Package network manages Docker isolated bridge networks for sandboxes.
package network

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/preved911/agent-sandbox/internal/sandbox"
)

// Create creates an isolated Docker bridge network for the sandbox.
// The network has no default gateway to the host bridge — the firewall
// container provides the only path to external networks.
//
// Network name: agent-sandbox-<hash>-net
//
// Returns the network ID and the gateway IP (firewall's expected IP).
func Create(ctx context.Context, cli *client.Client, hash string) (networkID string, err error) {
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)

	// Check if network already exists.
	networks, err := cli.NetworkList(ctx, network.ListOptions{
		Filters: filters.NewArgs(filters.Arg("name", name)),
	})
	if err != nil {
		return "", fmt.Errorf("list networks: %w", err)
	}
	for _, n := range networks {
		if n.Name == name {
			return n.ID, nil
		}
	}

	// Create isolated bridge network with fixed subnet.
	// Internal = true means no default gateway to the host — traffic only
	// flows through containers attached to this network.
	// Subnet 172.20.0.0/16 is fixed so the gateway (172.20.0.1) and
	// firewall (172.20.0.2) IPs are predictable.
	resp, err := cli.NetworkCreate(ctx, name, network.CreateOptions{
		Driver:   "bridge",
		Internal: true,
		IPAM: &network.IPAM{
			Config: []network.IPAMConfig{
				{Subnet: "172.20.0.0/16", Gateway: "172.20.0.1"},
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
