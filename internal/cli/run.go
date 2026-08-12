package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/creack/pty"
	"github.com/spf13/cobra"

	"github.com/preved911/agent-sandbox/internal/build"
	"github.com/preved911/agent-sandbox/internal/config"
	"github.com/preved911/agent-sandbox/internal/docker"
	"github.com/preved911/agent-sandbox/internal/paths"
	"github.com/preved911/agent-sandbox/internal/preflight"
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
		attachCmd      []string
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

			s := stack.New(cli, hash, cwd, cfg)

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

			// Get the published port from the firewall container.
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
			out := cmd.OutOrStdout()

			// Wait for the opencode HTTP server to be ready before attaching.
			// A TCP check alone is not sufficient — Docker's port forwarding
			// accepts connections before the HTTP handler is initialized.
			fmt.Fprintf(out, "Waiting for agent to be ready...\n")
			client := &http.Client{Timeout: 2 * time.Second}
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				resp, err := client.Get(url)
				if err == nil {
					resp.Body.Close()
					break
				}
				time.Sleep(time.Second)
			}
			// Final check — if still not ready, proceed anyway (attach will show error).
			resp, err := client.Get(url)
			if err != nil {
				fmt.Fprintf(out, "Warning: agent not ready after 60s, attempting attach anyway...\n")
			} else {
				resp.Body.Close()
				fmt.Fprintf(out, "Agent is ready.\n")
			}

			// Resolve the attach command (flag takes priority over config).
			var cmdArgs []string
			switch {
			case len(attachCmd) > 0:
				cmdArgs = attachCmd
			case len(cfg.Run.Attach) > 0:
				cmdArgs = cfg.Run.Attach
			}

			if cmdArgs != nil {
				// Build the final args with localhost URL — the command runs
				// inside the agent container via docker exec, so it connects
				// to localhost:4096 where the agent service listens.
				localURL := fmt.Sprintf("http://localhost:%s", port)
				args := make([]string, len(cmdArgs))
				for i, a := range cmdArgs {
					args[i] = strings.ReplaceAll(a, "%s", localURL)
				}

				// Run attach inside the agent container via docker exec.
				// This ensures the command connects to the agent's port
				// directly (localhost) rather than through the firewall's
				// published port (which Docker's proxy intercepts).
				agentName := sandbox.ResourceName(hash, sandbox.SuffixAgent)
				execArgs := append([]string{"exec", "-it", agentName}, args...)
				fmt.Fprintf(out, "$ docker %s\n", strings.Join(execArgs, " "))

				c := exec.CommandContext(ctx, "docker", execArgs...)
				f, err := pty.Start(c)
				if err != nil {
					return fmt.Errorf("attach: %w", err)
				}
				// Connect user's terminal to the PTY.
				go io.Copy(f, os.Stdin)
				io.Copy(os.Stdout, f)
				return c.Wait()
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
	cmd.Flags().StringArrayVar(&attachCmd, "cmd", nil, "custom attach command (use %%s for URL placeholder); repeatable")
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
