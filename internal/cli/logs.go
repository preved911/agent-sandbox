package cli

import (
	"fmt"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/spf13/cobra"

	"github.com/preved911/opencode-sandbox/internal/docker"
	"github.com/preved911/opencode-sandbox/internal/sandbox"
)

func newLogsCmd(rf *rootFlags) *cobra.Command {
	var (
		follow bool
		tail   string
	)
	cmd := &cobra.Command{
		Use:   "logs [name|id]",
		Short: "Stream logs from a sandbox container",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := docker.NewClient("")
			if err != nil {
				return err
			}
			defer cli.Close()

			ctx := cmd.Context()

			var name string
			if len(args) > 0 {
				name = args[0]
			} else {
				cwd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("get working directory: %w", err)
				}
				hash := sandbox.HashPath(cwd)
				name = sandbox.ResourceName(hash, sandbox.SuffixAgent)
			}

			inspect, err := cli.ContainerInspect(ctx, name)
			if err != nil {
				return fmt.Errorf("sandbox not found: %s", name)
			}
			if inspect.Config == nil || inspect.Config.Labels[sandbox.Label] != "true" {
				return fmt.Errorf("%s is not an opencode-sandbox container", name)
			}

			opts := container.LogsOptions{
				ShowStdout: true,
				ShowStderr: true,
				Follow:     follow,
				Tail:       tail,
			}

			reader, err := cli.ContainerLogs(ctx, inspect.ID, opts)
			if err != nil {
				return fmt.Errorf("logs: %w", err)
			}
			defer reader.Close()

			out := cmd.OutOrStdout()
			// Docker multiplexed streams: copy stdout/stderr to the same output.
			_, err = stdcopy.StdCopy(out, out, reader)
			return err
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow log output")
	cmd.Flags().StringVar(&tail, "tail", "100", "number of lines to show from the end (use 'all' for all)")
	return cmd
}
