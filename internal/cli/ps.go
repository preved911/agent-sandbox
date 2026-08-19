package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/spf13/cobra"

	"github.com/preved911/agent-sandbox/internal/docker"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

// sandboxInfo is the logical view of a sandbox (grouped by hash).
type sandboxInfo struct {
	hash    string
	path    string
	profile string
	status  string // Running, Degraded, Stopped, Partial
	port    string // host:port→container_port
}

func newPsCmd(rf *rootFlags) *cobra.Command {
	var all, quiet bool
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"ps", "list"},
		Short:   "List sandboxes (one row per sandbox, not per container)",
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

			// Group containers by hash.
			sandboxes := groupByHash(list)

			out := cmd.OutOrStdout()
			if quiet {
				for _, s := range sandboxes {
					fmt.Fprintln(out, s.hash)
				}
				return nil
			}

			if len(sandboxes) == 0 {
				fmt.Fprintln(out, "No sandboxes found.")
				return nil
			}

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "HASH\tSTATUS\tPORT\tPATH")
			for _, s := range sandboxes {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
					s.hash, s.status, s.port, s.path)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVarP(&all, "all", "a", false, "include stopped sandboxes")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "only print sandbox hashes")
	return cmd
}

// groupByHash groups containers by their sandbox hash and computes a single
// status and port for each sandbox.
func groupByHash(containers []types.Container) []sandboxInfo {
	type entry struct {
		agent    *types.Container
		firewall *types.Container
		proxy    *types.Container
	}

	groups := make(map[string]*entry)
	paths := make(map[string]string)
	profiles := make(map[string]string)

	for i := range containers {
		c := &containers[i]
		hash := c.Labels[sandbox.LabelHash]
		if hash == "" {
			continue
		}
		e, ok := groups[hash]
		if !ok {
			e = &entry{}
			groups[hash] = e
		}

		role := c.Labels[sandbox.SandboxRole]
		switch role {
		case "agent":
			e.agent = c
		case "firewall":
			e.firewall = c
		case "proxy":
			e.proxy = c
		default:
			// Legacy containers without role label — try name suffix.
			name := strings.TrimPrefix(strings.Join(c.Names, ","), "/")
			switch {
			case strings.HasSuffix(name, sandbox.SuffixAgent):
				e.agent = c
			case strings.HasSuffix(name, sandbox.SuffixFirewall):
				e.firewall = c
			case strings.HasSuffix(name, sandbox.SuffixProxy):
				e.proxy = c
			}
		}

		if p := c.Labels[sandbox.LabelPath]; p != "" {
			paths[hash] = p
		}
		if p := c.Labels[sandbox.LabelProfile]; p != "" {
			profiles[hash] = p
		}
	}

	result := make([]sandboxInfo, 0, len(groups))
	for hash, e := range groups {
		s := sandboxInfo{
			hash:    hash,
			path:    paths[hash],
			profile: profiles[hash],
		}

		agentUp := e.agent != nil && isRunning(e.agent)
		firewallUp := e.firewall != nil && isRunning(e.firewall)
		proxyUp := e.proxy != nil && isRunning(e.proxy)

		switch {
		case agentUp && firewallUp && proxyUp:
			s.status = "Running"
		case agentUp:
			s.status = "Degraded"
		case !agentUp && !firewallUp && !proxyUp:
			s.status = "Stopped"
		default:
			s.status = "Partial"
		}

		// Extract published port from proxy container (not firewall).
		if e.proxy != nil {
			for _, p := range e.proxy.Ports {
				if p.PublicPort != 0 {
					ip := p.IP
					if ip == "" {
						ip = "0.0.0.0"
					}
					s.port = fmt.Sprintf("%s:%d->%d/%s", ip, p.PublicPort, p.PrivatePort, p.Type)
					break
				}
			}
		}

		result = append(result, s)
	}

	// Sort by hash for deterministic output.
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].hash > result[j].hash {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

func isRunning(c *types.Container) bool {
	return strings.HasPrefix(c.State, "Up")
}
