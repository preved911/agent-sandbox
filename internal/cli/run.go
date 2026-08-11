package cli

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/preved911/agent-sandbox/internal/build"
	"github.com/preved911/agent-sandbox/internal/config"
	"github.com/preved911/agent-sandbox/internal/docker"
	"github.com/preved911/agent-sandbox/internal/paths"
	"github.com/preved911/agent-sandbox/internal/preflight"
	"github.com/preved911/agent-sandbox/internal/proxy"
	"github.com/preved911/agent-sandbox/internal/sandbox"
	"github.com/preved911/agent-sandbox/internal/stack"
)

func newRunCmd(rf *rootFlags) *cobra.Command {
	var (
		nameOverride   string
		noBuild        bool
		pull           bool
		envOverrides   []string
		mountOverrides []string
		bindOverride   string
		attachCmd      string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Create (if needed), start, and attach to a sandbox",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(rf.configPath, rf.profile)
			if err != nil {
				return err
			}
			for _, e := range envOverrides {
				k, v, err := parseEnvFlag(e)
				if err != nil {
					return err
				}
				if cfg.Run.Env == nil {
					cfg.Run.Env = make(map[string]string)
				}
				cfg.Run.Env[k] = v
			}
			for _, m := range mountOverrides {
				mount, err := parseMountFlag(m)
				if err != nil {
					return err
				}
				cfg.Run.Mounts = append(cfg.Run.Mounts, mount)
			}
			if bindOverride != "" {
				cfg.Run.Port.Bind = bindOverride
			}

			ctx := cmd.Context()

			// Compute the sandbox hash from the current working directory.
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

			// Pre-flight: verify cwd is in Docker's shared paths (macOS only).
			if cfg.SharedPathsCheck {
				if err := preflight.SharedPathsCheck(cwd); err != nil {
					return err
				}
			}

			s := stack.New(cli, hash, cfg)

			// Check if stack already exists.
			exists, err := s.Exists(ctx)
			if err != nil {
				return fmt.Errorf("check sandbox: %w", err)
			}

			if !exists {
				// Sandbox doesn't exist — build, create, start.
				var image string
				switch {
				case cfg.Build.Image != "":
					image = cfg.Build.Image
				case noBuild:
					image = cfg.Name + ":latest"
				default:
					image, err = build.ImageBuild(ctx, cfg, build.Options{Pull: pull})
					if err != nil {
						return err
					}
				}

				if err := s.Create(ctx, image); err != nil {
					return fmt.Errorf("create sandbox: %w", err)
				}
				if err := s.Start(ctx); err != nil {
					return fmt.Errorf("start sandbox: %w", err)
				}
			} else {
				// Sandbox exists — start if stopped.
				status, err := s.Status(ctx)
				if err != nil {
					return fmt.Errorf("sandbox status: %w", err)
				}
				if status.Agent != "running" {
					if err := s.Start(ctx); err != nil {
						return fmt.Errorf("start sandbox: %w", err)
					}
				}
			}

			// Start reverse forwarding proxies.
			gateway, err := s.GetGatewayIP(ctx)
			if err != nil {
				return fmt.Errorf("get gateway IP: %w", err)
			}
			pm := proxy.NewManager()
			if err := pm.StartProxies(ctx, gateway, &cfg.Run.ReverseForward); err != nil {
				log.Printf("Warning: start proxies: %v", err)
			}
			defer pm.StopAll()

			// Get the published port.
			port, err := s.GetPort(ctx)
			if err != nil {
				return fmt.Errorf("get port: %w", err)
			}

			// Determine the bind IP for the URL.
			bindIP := cfg.Run.Port.Bind
			if bindIP == "" || bindIP == "0.0.0.0" {
				bindIP = "127.0.0.1"
			}

			url := fmt.Sprintf("http://%s:%s", bindIP, port)

			// Execute attach command.
			out := cmd.OutOrStdout()
			if attachCmd != "" {
				cmdStr := strings.ReplaceAll(attachCmd, "%s", url)
				fmt.Fprintf(out, "$ %s\n", cmdStr)
				c := exec.CommandContext(ctx, "sh", "-c", cmdStr)
				c.Stdout = out
				c.Stderr = cmd.ErrOrStderr()
				c.Stdin = os.Stdin
				return c.Run()
			}

			// Use config-defined attach command if available.
			if cfg.Run.AttachCmd != "" {
				cmdStr := strings.ReplaceAll(cfg.Run.AttachCmd, "%s", url)
				fmt.Fprintf(out, "$ %s\n", cmdStr)
				c := exec.CommandContext(ctx, "sh", "-c", cmdStr)
				c.Stdout = out
				c.Stderr = cmd.ErrOrStderr()
				c.Stdin = os.Stdin
				if err := c.Run(); err != nil {
					return fmt.Errorf("attach command: %w", err)
				}
				return nil
			}

			// No attach command configured — print URL for manual connection.
			fmt.Fprintf(out, "\nSandbox ready. Connect manually:\n  %s\n", url)
			return nil
		},
	}
	cmd.Flags().StringVar(&nameOverride, "name", "", "container name (default: <hash>-agent)")
	cmd.Flags().BoolVar(&noBuild, "no-build", false, "skip the build step (image must already exist)")
	cmd.Flags().BoolVar(&pull, "pull", false, "pass --pull to docker build")
	cmd.Flags().StringArrayVarP(&envOverrides, "env", "e", nil, "set or override an env var (KEY=VALUE); repeatable")
	cmd.Flags().StringArrayVarP(&mountOverrides, "mount", "v", nil, "append a mount (source:target[:ro]); repeatable")
	cmd.Flags().StringVar(&bindOverride, "bind", "", "override run.port.bind (e.g. 0.0.0.0)")
	cmd.Flags().StringVar(&attachCmd, "cmd", "", "custom attach command (use %%s for URL placeholder)")
	return cmd
}

// parseEnvFlag parses KEY=VALUE into key and value.
func parseEnvFlag(s string) (string, string, error) {
	idx := strings.IndexByte(s, '=')
	if idx < 1 {
		return "", "", fmt.Errorf("--env %q: expected KEY=VALUE", s)
	}
	return s[:idx], s[idx+1:], nil
}

// parseMountFlag parses source:target[:ro] into a Mount.
// The source is expanded immediately relative to the caller's CWD so that
// relative paths (./subdir, ~/) resolve as the user expects from the command
// line rather than against the config file's directory.
func parseMountFlag(s string) (config.Mount, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 || parts[1] == "" {
		return config.Mount{}, fmt.Errorf("--mount %q: expected source:target[:ro]", s)
	}
	src, err := paths.Expand(parts[0], "") // "" → relative paths resolve against CWD
	if err != nil {
		return config.Mount{}, fmt.Errorf("--mount %q: %w", s, err)
	}
	m := config.Mount{Source: src, Target: parts[1]}
	if len(parts) == 3 {
		if parts[2] != "ro" {
			return config.Mount{}, fmt.Errorf("--mount %q: unsupported modifier %q (only :ro is supported)", s, parts[2])
		}
		m.ReadOnly = true
	}
	return m, nil
}
