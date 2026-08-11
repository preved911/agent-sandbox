package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/preved911/opencode-sandbox/internal/build"
	"github.com/preved911/opencode-sandbox/internal/config"
	"github.com/preved911/opencode-sandbox/internal/docker"
	"github.com/preved911/opencode-sandbox/internal/run"
	"github.com/preved911/opencode-sandbox/internal/sandbox"
)

func newCreateCmd(rf *rootFlags) *cobra.Command {
	var (
		noBuild bool
		pull    bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a sandbox (volume + container) without attaching",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(rf.configPath, rf.profile)
			if err != nil {
				return err
			}

			ctx := cmd.Context()

			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			hash := sandbox.HashPath(cwd)
			name := sandbox.ResourceName(hash, sandbox.SuffixAgent)

			// Check if sandbox already exists.
			cli, err := docker.NewClient("")
			if err != nil {
				return fmt.Errorf("docker client: %w", err)
			}
			defer cli.Close()

			existing, err := findSandboxByName(ctx, cli, name)
			if err != nil {
				return err
			}
			if existing != nil {
				out := cmd.OutOrStdout()
				status := "unknown"
				if existing.State != nil {
					status = existing.State.Status
				}
				fmt.Fprintf(out, "sandbox already exists: %s (status: %s)\n", name, status)
				return nil
			}

			var image string
			switch {
			case cfg.Build.Image != "":
				image = cfg.Build.Image
			case noBuild:
				image = "opencode-sandbox/" + cfg.Name + ":latest"
			default:
				image, err = build.ImageBuild(ctx, cfg, build.Options{Pull: pull})
				if err != nil {
					return err
				}
			}

			res, err := run.Start(ctx, cli, cfg, image, name)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			for _, b := range res.Binds {
				fmt.Fprintf(out, "mount: %s\n", b)
			}
			fmt.Fprintf(out, "volume: %s\n", res.Volume)
			fmt.Fprintf(out, "container: %s\n", res.Name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&noBuild, "no-build", false, "skip the build step (image must already exist)")
	cmd.Flags().BoolVar(&pull, "pull", false, "pass --pull to docker build")
	return cmd
}
