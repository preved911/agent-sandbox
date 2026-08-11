package cli

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
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
	inspect, err := cli.ContainerInspect(ctx, target)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", target, err)
	}
	if inspect.Config == nil || inspect.Config.Labels[sandbox.Label] != "true" {
		return fmt.Errorf("%s is not an agent-sandbox container; refusing to remove", target)
	}
	return cli.ContainerRemove(ctx, inspect.ID, container.RemoveOptions{Force: force})
}
