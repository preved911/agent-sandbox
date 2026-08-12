// Package cli implements the agent-sandbox CLI commands.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/preved911/agent-sandbox/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			v := version.Get()
			fmt.Printf("agent-sandbox %s (commit %s, built %s)\n", v.Version, v.Commit, v.Date)
			fmt.Printf("go %s %s/%s\n", v.Go, v.OS, v.Arch)
		},
	}
}
