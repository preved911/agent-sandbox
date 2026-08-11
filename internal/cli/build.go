package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/preved911/opencode-sandbox/internal/build"
	"github.com/preved911/opencode-sandbox/internal/config"
)

func newBuildCmd(rf *rootFlags) *cobra.Command {
	var pull bool
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the sandbox image without starting a container",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(rf.configPath, rf.profile)
			if err != nil {
				return err
			}
			if cfg.Build.Image != "" {
				return fmt.Errorf("config has build.image set; nothing to build")
			}
			tag, err := build.ImageBuild(cmd.Context(), cfg, build.Options{Pull: pull})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), tag)
			return nil
		},
	}
	cmd.Flags().BoolVar(&pull, "pull", false, "pass --pull to docker build")
	return cmd
}
