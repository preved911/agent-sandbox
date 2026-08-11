package cli

import (
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/spf13/cobra"

	"github.com/preved911/agent-sandbox/internal/docker"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

func newStopCmd(rf *rootFlags) *cobra.Command {
	var timeout int
	cmd := &cobra.Command{
		Use:   "stop [name|id ...]",
		Short: "Stop running sandbox containers",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := docker.NewClient("")
			if err != nil {
				return err
			}
			defer cli.Close()

			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			to := time.Duration(timeout) * time.Second

			for _, target := range args {
				inspect, err := cli.ContainerInspect(ctx, target)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "error: inspect %s: %v\n", target, err)
					continue
				}
				if inspect.Config == nil || inspect.Config.Labels[sandbox.Label] != "true" {
					fmt.Fprintf(cmd.ErrOrStderr(), "error: %s is not an agent-sandbox container\n", target)
					continue
				}
				if !inspect.State.Running {
					fmt.Fprintf(out, "%s: already stopped\n", target)
					continue
				}
				secs := int(to.Seconds())
			if err := cli.ContainerStop(ctx, inspect.ID, container.StopOptions{Timeout: &secs}); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "error: stop %s: %v\n", target, err)
					continue
				}
				fmt.Fprintf(out, "%s\n", target)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&timeout, "timeout", 10, "seconds to wait before force-killing")
	return cmd
}
