package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/preved911/opencode-sandbox/internal/build"
	"github.com/preved911/opencode-sandbox/internal/config"
	"github.com/preved911/opencode-sandbox/internal/docker"
	"github.com/preved911/opencode-sandbox/internal/sandbox"
	"github.com/preved911/opencode-sandbox/internal/stack"
)

func newCreateCmd(rf *rootFlags) *cobra.Command {
	var (
		noBuild bool
		pull    bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create sandbox resources without starting or attaching",
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

			cli, err := docker.NewClient("")
			if err != nil {
				return fmt.Errorf("docker client: %w", err)
			}
			defer cli.Close()

			s := stack.New(cli, hash, cfg)

			// Check if sandbox already exists.
			exists, err := s.Exists(ctx)
			if err != nil {
				return fmt.Errorf("check sandbox: %w", err)
			}
			if exists {
				out := cmd.OutOrStdout()
				status, err := s.Status(ctx)
				if err != nil {
					return fmt.Errorf("sandbox status: %w", err)
				}
				fmt.Fprintf(out, "sandbox already exists: %s (status: %s)\n", sandbox.ResourceName(hash, sandbox.SuffixAgent), status.Agent)
				return nil
			}

			// Build image.
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

			// Create stack (does not start).
			if err := s.Create(ctx, image); err != nil {
				return fmt.Errorf("create sandbox: %w", err)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "container: %s\n", sandbox.ResourceName(hash, sandbox.SuffixAgent))
			fmt.Fprintf(out, "firewall: %s\n", sandbox.ResourceName(hash, sandbox.SuffixFirewall))
			fmt.Fprintf(out, "volume:   %s\n", sandbox.ResourceName(hash, sandbox.SuffixSessions))
			return nil
		},
	}
	cmd.Flags().BoolVar(&noBuild, "no-build", false, "skip the build step (image must already exist)")
	cmd.Flags().BoolVar(&pull, "pull", false, "pass --pull to docker build")
	return cmd
}
