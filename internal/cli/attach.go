package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"

	"github.com/preved911/opencode-sandbox/internal/docker"
	"github.com/preved911/opencode-sandbox/internal/sandbox"
)

func newAttachCmd(rf *rootFlags) *cobra.Command {
	var attachCmd string
	cmd := &cobra.Command{
		Use:   "attach [name|id]",
		Short: "Attach to a running sandbox (prints and executes the opencode attach URL)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := docker.NewClient("")
			if err != nil {
				return err
			}
			defer cli.Close()

			ctx := cmd.Context()

			var name string
			if len(args) > 0 {
				name = args[0]
			} else {
				// Find sandbox by cwd.
				cwd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("get working directory: %w", err)
				}
				hash := sandbox.HashPath(cwd)
				name = sandbox.ResourceName(hash, sandbox.SuffixAgent)
			}

			inspect, err := cli.ContainerInspect(ctx, name)
			if err != nil {
				return fmt.Errorf("sandbox not found: %s (hint: use 'opencode-sandbox ps' to list sandboxes)", name)
			}
			if inspect.Config == nil || inspect.Config.Labels[sandbox.Label] != "true" {
				return fmt.Errorf("%s is not an opencode-sandbox container", name)
			}
			if !inspect.State.Running {
				return fmt.Errorf("sandbox %s is stopped (hint: use 'opencode-sandbox start %s')", name, name)
			}

			// Extract port from inspect.
			bindings := inspect.NetworkSettings.Ports[agentContainerPort]
			if len(bindings) == 0 || bindings[0].HostPort == "" {
				return fmt.Errorf("sandbox %s has no published port", name)
			}
			port, err := strconv.Atoi(bindings[0].HostPort)
			if err != nil {
				return fmt.Errorf("parse port: %w", err)
			}

			bindIP := inspect.NetworkSettings.Ports[agentContainerPort][0].HostIP
			if bindIP == "" || bindIP == "0.0.0.0" {
				bindIP = "127.0.0.1"
			}

			url := fmt.Sprintf("http://%s:%d", bindIP, port)

			if attachCmd != "" {
				// Use custom attach command with %s replaced by URL.
				cmdStr := strings.ReplaceAll(attachCmd, "%s", url)
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "$ %s\n", cmdStr)
				c := exec.CommandContext(ctx, "sh", "-c", cmdStr)
				c.Stdout = out
				c.Stderr = cmd.ErrOrStderr()
				c.Stdin = os.Stdin
				return c.Run()
			}

			// Default: run opencode attach.
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "opencode attach %s\n", url)

			c := exec.CommandContext(ctx, "opencode", "attach", url)
			c.Stdout = out
			c.Stderr = cmd.ErrOrStderr()
			c.Stdin = os.Stdin
			if err := c.Run(); err != nil {
				// If opencode is not installed, just print the URL.
				if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
					fmt.Fprintf(out, "\nopencode not found in PATH. Connect manually:\n  opencode attach %s\n", url)
					return nil
				}
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&attachCmd, "cmd", "", "custom attach command (use %%s for URL placeholder)")
	return cmd
}

// agentContainerPort is the port opencode serves on inside the container.
const agentContainerPort = "4096/tcp"

// findSandboxByName looks up a container by its LabelName.
func findSandboxByName(ctx context.Context, cli *client.Client, name string) (*types.ContainerJSON, error) {
	f := filters.NewArgs()
	f.Add("label", sandbox.Label+"=true")
	list, err := cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {
		return nil, err
	}
	for _, c := range list {
		inspect, err := cli.ContainerInspect(ctx, c.ID)
		if err != nil {
			continue
		}
		if inspect.Config != nil && inspect.Config.Labels[sandbox.LabelName] == name {
			return &inspect, nil
		}
	}
	return nil, nil
}
