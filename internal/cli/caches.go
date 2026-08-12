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

func newCachesCmd(rf *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "caches",
		Short: "Manage sandbox cache volumes",
	}
	cmd.AddCommand(
		newCachesPsCmd(rf),
		newCachesRmCmd(rf),
	)
	return cmd
}

func newCachesPsCmd(rf *rootFlags) *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{
		Use:   "ps [hash]",
		Short: "List sandbox cache volumes",
		Args:  cobra.MaximumNArgs(1),
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

			// Filter to sandbox cache volumes.
			var cacheVolumes []volume.Volume
			for _, v := range volumes.Volumes {
				if !isCacheVolume(v.Name) {
					continue
				}
				if len(args) > 0 {
					// Filter by hash if provided.
					hash := args[0]
					if !strings.Contains(v.Name, hash) {
						continue
					}
				}
				cacheVolumes = append(cacheVolumes, *v)
			}

			out := cmd.OutOrStdout()
			if quiet {
				for _, v := range cacheVolumes {
					fmt.Fprintln(out, stringid.TruncateID(v.Name))
				}
				return nil
			}

			if len(cacheVolumes) == 0 {
				fmt.Fprintln(out, "No sandbox cache volumes found.")
				return nil
			}

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "HASH\tNAME\tCREATED")
			for _, v := range cacheVolumes {
				hash, name, _ := parseCacheVolume(v.Name)
				fmt.Fprintf(tw, "%s\t%s\t%s\n", hash, name, v.CreatedAt)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "only print volume names")
	return cmd
}

func newCachesRmCmd(rf *rootFlags) *cobra.Command {
	var (
		force bool
		all   bool
	)
	cmd := &cobra.Command{
		Use:   "rm [name ...]",
		Short: "Remove sandbox cache volumes",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case all && len(args) > 0:
				return fmt.Errorf("--all cannot be combined with positional arguments")
			case !all && len(args) == 0:
				return fmt.Errorf("specify one or more cache volume names, or pass --all")
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
					if isCacheVolume(v.Name) {
						targets = append(targets, v.Name)
					}
				}
			}

			if !force && len(targets) > 1 {
				fmt.Fprintf(out, "This will remove %d cache volumes. Data will be lost.\n", len(targets))
				fmt.Fprintf(out, "Use --force to confirm.\n")
				return nil
			}

			var firstErr error
			for _, name := range targets {
				if !isCacheVolume(name) {
					fmt.Fprintf(cmd.ErrOrStderr(), "error: %s is not a cache volume\n", name)
					continue
				}
				if err := cli.VolumeRemove(ctx, name, true); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "error: remove %s: %v\n", name, err)
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				fmt.Fprintln(out, name)
			}
			return firstErr
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "skip confirmation prompt")
	cmd.Flags().BoolVar(&all, "all", false, "remove all sandbox cache volumes")
	return cmd
}

// isCacheVolume checks if a Docker volume name follows the cache naming convention.
// Pattern: agent-sandbox-<hash>-cache-<name>
func isCacheVolume(name string) bool {
	prefix := sandbox.Label + "-"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	return strings.Contains(name, "-cache-")
}

// parseCacheVolume extracts hash, cache name, and path from a cache volume name.
// Returns ("", "", "") if the name doesn't match the pattern.
func parseCacheVolume(name string) (hash, cacheName, path string) {
	prefix := sandbox.Label + "-"
	if !strings.HasPrefix(name, prefix) {
		return "", "", ""
	}
	rest := strings.TrimPrefix(name, prefix)

	// Find "-cache-" separator.
	idx := strings.Index(rest, "-cache-")
	if idx < 0 {
		return "", "", ""
	}
	hash = rest[:idx]
	cacheName = rest[idx+len("-cache-"):]

	// We don't store path in the volume name; return empty.
	// The path is only known from the config.
	return hash, cacheName, ""
}
