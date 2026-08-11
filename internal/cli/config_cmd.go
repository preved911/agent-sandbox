package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/preved911/opencode-sandbox/internal/config"
)

func newConfigCmd(rf *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show the resolved configuration for the current directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(rf.configPath, rf.profile)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			data, err := yaml.Marshal(cfg)
			if err != nil {
				return fmt.Errorf("marshal config: %w", err)
			}
			_, err = out.Write(data)
			return err
		},
	}
	return cmd
}
