package cli

import (
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/spf13/cobra"

	"github.com/preved911/opencode-sandbox/internal/docker"
	"github.com/preved911/opencode-sandbox/internal/sandbox"
)

func newStartCmd(rf *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start [name|id ...]",
		Short: "Start stopped sandbox containers",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := docker.NewClient("")
			if err != nil {
				return err
			}
			defer cli.Close()

			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			for _, target := range args {
				inspect, err := cli.ContainerInspect(ctx, target)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "error: inspect %s: %v\n", target, err)
					continue
				}
				if inspect.Config == nil || inspect.Config.Labels[sandbox.Label] != "true" {
					fmt.Fprintf(cmd.ErrOrStderr(), "error: %s is not an opencode-sandbox container\n", target)
					continue
				}
				if inspect.State.Running {
					fmt.Fprintf(out, "%s: already running\n", target)
					continue
				}
				if err := cli.ContainerStart(ctx, inspect.ID, container.StartOptions{}); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "error: start %s: %v\n", target, err)
					continue
				}
				fmt.Fprintf(out, "%s\n", target)
			}
			return nil
		},
	}
	return cmd
}
