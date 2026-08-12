package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"

	"github.com/preved911/agent-sandbox/internal/docker"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

func newRmCmd(rf *rootFlags) *cobra.Command {
	var force, all bool
	cmd := &cobra.Command{
		Use:   "rm [name|id ...]",
		Short: "Remove sandbox containers (label-scoped, never touches unrelated containers)",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case all && len(args) > 0:
				return fmt.Errorf("--all cannot be combined with positional arguments")
			case !all && len(args) == 0:
				return fmt.Errorf("specify one or more containers, or pass --all")
			}

			cli, err := docker.NewClient("")
			if err != nil {
				return err
			}
			defer cli.Close()

			ctx := cmd.Context()
			targets := args
			if all {
				targets, err = listSandboxIDs(ctx, cli)
				if err != nil {
					return err
				}
			}

			var firstErr error
			for _, t := range targets {
				if err := removeOne(ctx, cli, t, force); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "error: %v\n", err)
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				fmt.Fprintln(cmd.OutOrStdout(), t)
			}
			return firstErr
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "stop a running container before removing it")
	cmd.Flags().BoolVar(&all, "all", false, "remove every sandbox container")
	return cmd
}

func listSandboxIDs(ctx context.Context, cli *client.Client) ([]string, error) {
	f := filters.NewArgs()
	f.Add("label", sandbox.Label+"=true")
	list, err := cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(list))
	for _, c := range list {
		ids = append(ids, c.ID)
	}
	return ids, nil
}

func removeOne(ctx context.Context, cli *client.Client, target string, force bool) error {
	// First, try to find by exact container name or ID.
	inspect, err := cli.ContainerInspect(ctx, target)
	if err == nil {
		if inspect.Config != nil && inspect.Config.Labels[sandbox.Label] == "true" {
			hash := inspect.Config.Labels[sandbox.LabelHash]
			if err := cli.ContainerRemove(ctx, inspect.ID, container.RemoveOptions{Force: force}); err != nil {
				return err
			}
			// Also remove the isolated network for this sandbox.
			removeNetwork(ctx, cli, hash)
			return nil
		}
		return fmt.Errorf("%s is not an agent-sandbox container; refusing to remove", target)
	}

	// Not found by exact name — try to find by hash (partial or full).
	// This lets users pass: "82d666cd" or "agent-sandbox-82d666cd" or "agent-sandbox-82d666cd-agent"
	hash := extractHash(target)
	if hash == "" {
		return fmt.Errorf("no container found for %q", target)
	}

	f := filters.NewArgs()
	f.Add("label", sandbox.Label+"=true")
	f.Add("label", sandbox.LabelHash+"="+hash)
	list, err := cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {
		return fmt.Errorf("list containers for hash %s: %w", hash, err)
	}
	if len(list) == 0 {
		return fmt.Errorf("no sandbox containers found for hash %s", hash)
	}

	var firstErr error
	for _, c := range list {
		name := strings.TrimPrefix(strings.Join(c.Names, ","), "/")
		if err := cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: force}); err != nil {
			fmt.Fprintf(os.Stderr, "error: remove %s: %v\n", name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		fmt.Fprintln(os.Stdout, name)
	}

	// Also remove the isolated network for this sandbox.
	removeNetwork(ctx, cli, hash)

	return firstErr
}

// removeNetwork removes the isolated network for a sandbox hash.
func removeNetwork(ctx context.Context, cli *client.Client, hash string) {
	if hash == "" {
		return
	}
	name := sandbox.ResourceName(hash, sandbox.SuffixNet)
	networks, err := cli.NetworkList(ctx, network.ListOptions{
		Filters: filters.NewArgs(filters.Arg("name", name)),
	})
	if err != nil {
		return
	}
	for _, n := range networks {
		if n.Name == name {
			_ = cli.NetworkRemove(ctx, n.ID)
			fmt.Fprintln(os.Stdout, n.Name)
			return
		}
	}
}

// extractHash extracts the 8-char hex hash from various input formats:
// "82d666cd", "agent-sandbox-82d666cd", "agent-sandbox-82d666cd-agent"
func extractHash(input string) string {
	// Try to find 8-hex-char sequence.
	for i := 0; i <= len(input)-8; i++ {
		candidate := input[i : i+8]
		if isHex(candidate) {
			return candidate
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
