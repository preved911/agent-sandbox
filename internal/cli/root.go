// Package cli wires the cobra command tree.
package cli

import (
	"context"

	"github.com/spf13/cobra"
)

// Execute runs the CLI with the given context (which should be signal-aware).
func Execute(ctx context.Context) error {
	return newRootCmd().ExecuteContext(ctx)
}

type rootFlags struct {
	configPath string
	profile    string
}

func newRootCmd() *cobra.Command {
	rf := &rootFlags{}
	cmd := &cobra.Command{
		Use:           "agent-sandbox",
		Short:         "Manage isolated agent containers",
		Long:          "Builds and runs containers that expose an agent endpoint on a random host port, so you can attach a local client to a sandboxed run.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.PersistentFlags().StringVarP(&rf.configPath, "config", "c", "", "config file path (default: ./agent-sandbox.yaml → $HOME/.config/agent-sandbox/config.yaml)")
	cmd.PersistentFlags().StringVarP(&rf.profile, "profile", "p", "", "profile name (overrides default_profile in config)")

	cmd.AddCommand(
		newRunCmd(rf),
		newBuildCmd(rf),
		newCreateCmd(rf),
		newStartCmd(rf),
		newStopCmd(rf),
		newLogsCmd(rf),
		newSessionsCmd(rf),
		newCachesCmd(rf),
		newConfigCmd(rf),
		newPsCmd(rf),
		newRmCmd(rf),
		newVersionCmd(),
	)
	return cmd
}
