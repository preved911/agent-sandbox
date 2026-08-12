package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/pkg/stringid"
	"github.com/spf13/cobra"

	"github.com/preved911/agent-sandbox/internal/docker"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

func newSessionCmd(rf *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "session",
		Aliases: []string{"sessions"},
		Short:   "Manage sandbox session volumes",
	}
	cmd.AddCommand(
		newSessionLsCmd(rf),
		newSessionRmCmd(rf),
	)
	return cmd
}

func newSessionLsCmd(rf *rootFlags) *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List sandbox session volumes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := docker.NewClient("")
			if err != nil {
				return err
			}
			defer cli.Close()

			ctx := cmd.Context()

			volumes, err := cli.VolumeList(ctx, volume.ListOptions{})
			if err != nil {
				return fmt.Errorf("list volumes: %w", err)
			}

			// Filter to sandbox session volumes (exclude cache volumes).
			var sandboxVolumes []volume.Volume
			for _, v := range volumes.Volumes {
				if v.Labels[sandbox.Label] != "true" {
					continue
				}
				if isCacheVolume(v.Name) {
					continue
				}
				sandboxVolumes = append(sandboxVolumes, *v)
			}

			out := cmd.OutOrStdout()
			if quiet {
				for _, v := range sandboxVolumes {
					fmt.Fprintln(out, stringid.TruncateID(v.Name))
				}
				return nil
			}

			if len(sandboxVolumes) == 0 {
				fmt.Fprintln(out, "No sandbox session volumes found.")
				return nil
			}

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tPATH\tCREATED")
			for _, v := range sandboxVolumes {
				path := v.Labels[sandbox.LabelPath]
				if path == "" {
					path = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", v.Name, path, v.CreatedAt)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "only print volume names")
	return cmd
}

func newSessionRmCmd(rf *rootFlags) *cobra.Command {
	var (
		force bool
		all   bool
	)
	cmd := &cobra.Command{
		Use:   "rm [name ...]",
		Short: "Remove sandbox session volumes",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case all && len(args) > 0:
				return fmt.Errorf("--all cannot be combined with positional arguments")
			case !all && len(args) == 0:
				return fmt.Errorf("specify one or more volume names, or pass --all")
			}

			cli, err := docker.NewClient("")
			if err != nil {
				return err
			}
			defer cli.Close()

			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			targets := args
			if all {
				volumes, err := cli.VolumeList(ctx, volume.ListOptions{})
				if err != nil {
					return fmt.Errorf("list volumes: %w", err)
				}
				for _, v := range volumes.Volumes {
					if v.Labels[sandbox.Label] == "true" && !isCacheVolume(v.Name) {
						targets = append(targets, v.Name)
					}
				}
			}

			if !force && len(targets) > 1 {
				fmt.Fprintf(out, "This will remove %d session volumes. Data will be lost.\n", len(targets))
				fmt.Fprintf(out, "Use --force to confirm.\n")
				return nil
			}

			var firstErr error
			for _, name := range targets {
				if err := cli.VolumeRemove(ctx, name, true); err != nil {
					// Check if it's a sandbox volume.
					if strings.Contains(name, sandbox.Label) {
						fmt.Fprintf(cmd.ErrOrStderr(), "error: remove %s: %v\n", name, err)
						if firstErr == nil {
							firstErr = err
						}
						continue
					}
					fmt.Fprintf(cmd.ErrOrStderr(), "error: %s is not a sandbox volume\n", name)
					continue
				}
				fmt.Fprintln(out, name)
			}
			return firstErr
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "skip confirmation prompt")
	cmd.Flags().BoolVar(&all, "all", false, "remove all sandbox session volumes")
	return cmd
}
