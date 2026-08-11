package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/spf13/cobra"

	"github.com/preved911/agent-sandbox/internal/docker"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

func newPsCmd(rf *rootFlags) *cobra.Command {
	var all, quiet bool
	cmd := &cobra.Command{
		Use:   "ps",
		Short: "List sandbox containers (filtered by agent-sandbox label)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := docker.NewClient("")
			if err != nil {
				return err
			}
			defer cli.Close()

			f := filters.NewArgs()
			f.Add("label", sandbox.Label+"=true")
			list, err := cli.ContainerList(cmd.Context(), container.ListOptions{
				All:     all,
				Filters: f,
			})
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if quiet {
				for _, c := range list {
					fmt.Fprintln(out, shortID(c.ID))
				}
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "CONTAINER ID\tNAME\tIMAGE\tSTATUS\tPORTS\tCREATED")
			for _, c := range list {
				name := strings.TrimPrefix(strings.Join(c.Names, ","), "/")
				ports := formatPorts(c.Ports)
				created := time.Unix(c.Created, 0).Format(time.RFC3339)
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					shortID(c.ID), name, c.Image, c.Status, ports, created)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVarP(&all, "all", "a", false, "include stopped sandboxes")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "only print container IDs")
	return cmd
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func formatPorts(ports []types.Port) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.PublicPort == 0 {
			continue
		}
		ip := p.IP
		if ip == "" {
			ip = "0.0.0.0"
		}
		parts = append(parts, fmt.Sprintf("%s:%d->%d/%s", ip, p.PublicPort, p.PrivatePort, p.Type))
	}
	return strings.Join(parts, ", ")
}
