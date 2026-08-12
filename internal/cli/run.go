package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/preved911/agent-sandbox/internal/build"
	"github.com/preved911/agent-sandbox/internal/config"
	"github.com/preved911/agent-sandbox/internal/docker"
	"github.com/preved911/agent-sandbox/internal/paths"
	"github.com/preved911/agent-sandbox/internal/preflight"
	"github.com/preved911/agent-sandbox/internal/sandbox"
	"github.com/preved911/agent-sandbox/internal/stack"
)

// cancelReader wraps an io.Reader and returns an error when the context is
// cancelled. This allows io.Copy to unblock on SIGINT.
type cancelReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr cancelReader) Read(p []byte) (int, error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	return cr.r.Read(p)
}

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
			out := cmd.OutOrStdout()

			// Check if stack already exists.
			exists, err := s.Exists(ctx)
			if err != nil {
				return fmt.Errorf("check sandbox: %w", err)
			}

			if !exists {
				// Sandbox doesn't exist — build, create, start.
				fmt.Fprintln(out, "Creating new sandbox...")
				var image string
				switch {
				case cfg.Build.Image != "":
					image = cfg.Build.Image
				case noBuild:
					image = cfg.Name + ":latest"
				default:
					fmt.Fprint(out, "Building image...")
					image, err = build.ImageBuild(ctx, cfg, build.Options{Pull: pull})
					if err != nil {
						return err
					}
					fmt.Fprintln(out, " done")
				}

				fmt.Fprint(out, "Creating containers...")
				if err := s.Create(ctx, image); err != nil {
					return fmt.Errorf("create sandbox: %w", err)
				}
				fmt.Fprintln(out, " done")

				fmt.Fprint(out, "Starting containers...")
				if err := s.Start(ctx); err != nil {
					return fmt.Errorf("start sandbox: %w", err)
				}
				fmt.Fprintln(out, " done")
			} else {
				// Sandbox exists — start if stopped.
				status, err := s.Status(ctx)
				if err != nil {
					return fmt.Errorf("sandbox status: %w", err)
				}
				if status.Agent != "running" {
					fmt.Fprint(out, "Starting containers...")
					if err := s.Start(ctx); err != nil {
						return fmt.Errorf("start sandbox: %w", err)
					}
					fmt.Fprintln(out, " done")
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

			agentName := sandbox.ResourceName(hash, sandbox.SuffixAgent)

			dockerCli, err := docker.NewClient("")
			if err != nil {
				return fmt.Errorf("docker client: %w", err)
			}

			const maxRetries = 3
			attempt := 0
		retry:
			for attempt < maxRetries {
				attempt++
				if attempt > 1 {
					fmt.Fprintf(out, "\nRetrying (attempt %d/%d)...\n", attempt, maxRetries)
					time.Sleep(2 * time.Second)
				}

				// Wait for agent container to be ready (HTTP server must be listening).
				fmt.Fprint(out, "Waiting for agent to be ready")
				ready := false
				for i := 0; i < 30; i++ {
					pingCfg := container.ExecOptions{
						Cmd:          []string{"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout", "1", "http://localhost:4096"},
						AttachStdout: true,
						AttachStderr: true,
					}
					pingResp, err := dockerCli.ContainerExecCreate(ctx, agentName, pingCfg)
					if err != nil {
						fmt.Fprint(out, ".")
						time.Sleep(1 * time.Second)
						continue
					}
					pingAttach, err := dockerCli.ContainerExecAttach(ctx, pingResp.ID, container.ExecStartOptions{})
					if err != nil {
						fmt.Fprint(out, ".")
						time.Sleep(1 * time.Second)
						continue
					}
					pingAttach.Close()
					inspect, err := dockerCli.ContainerExecInspect(ctx, pingResp.ID)
					if err == nil && inspect.ExitCode == 0 {
						ready = true
						break
					}
					fmt.Fprint(out, ".")
					time.Sleep(1 * time.Second)
				}
				fmt.Fprintln(out)
				if !ready {
					if attempt < maxRetries {
						fmt.Fprintln(out, "Agent not ready, retrying...")
						goto retry
					}
					return fmt.Errorf("timeout waiting for agent container to be ready")
				}
				fmt.Fprintln(out, "Agent is ready.")

				execCfg := container.ExecOptions{
					AttachStdin:  true,
					AttachStdout: true,
					AttachStderr: true,
					Tty:          true,
					Env:          []string{"TERM=xterm-256color"},
					Cmd:          args,
				}
				resp, err := dockerCli.ContainerExecCreate(ctx, agentName, execCfg)
				if err != nil {
					return fmt.Errorf("exec create: %w", err)
				}

				// Get current terminal size for initial PTY dimensions.
				w, h, err := term.GetSize(int(os.Stdin.Fd()))
				if err != nil {
					w, h = 80, 24
				}
				consoleSize := [2]uint{uint(h), uint(w)}

				attachResp, err := dockerCli.ContainerExecAttach(ctx, resp.ID, container.ExecStartOptions{
					Tty:         true,
					ConsoleSize: &consoleSize,
				})
				if err != nil {
					fmt.Fprintf(out, "exec attach failed: %v\n", err)
					continue
				}

				// Put host terminal into raw mode.
				oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
				if err != nil {
					attachResp.Close()
					return fmt.Errorf("raw mode: %w", err)
				}

				// Propagate terminal resize events to the container PTY.
				sig := make(chan os.Signal, 1)
				signal.Notify(sig, syscall.SIGWINCH)
				go func() {
					for range sig {
						if nw, nh, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
							dockerCli.ContainerExecResize(ctx, resp.ID, container.ResizeOptions{
								Width:  uint(nw),
								Height: uint(nh),
							})
						}
					}
				}()
				sig <- syscall.SIGWINCH

				// Cancellable context for SIGINT handling.
				copyCtx, copyCancel := context.WithCancel(ctx)
				defer copyCancel()

				sigInt := make(chan os.Signal, 1)
				signal.Notify(sigInt, syscall.SIGINT)
				go func() {
					<-sigInt
					copyCancel()
				}()

				// Bidirectional copy with hang detection.
				// stdout uses copyWithTimeout — if no data arrives within
				// 60s, it returns and the loop retries automatically.
				copyDone := make(chan error, 1)
				go func() {
					io.Copy(attachResp.Conn, cancelReader{ctx: copyCtx, r: os.Stdin})
				}()
				go func() {
					copyDone <- copyWithTimeout(os.Stdout, attachResp.Reader, 60*time.Second)
				}()
				<-copyDone

				signal.Stop(sig)
				signal.Stop(sigInt)
				attachResp.Close()
				term.Restore(int(os.Stdin.Fd()), oldState)

				// Wait for exec to finish — with a short deadline.
				waitDeadline := time.After(5 * time.Second)
				for {
					inspect, err := dockerCli.ContainerExecInspect(ctx, resp.ID)
					if err != nil {
						break
					}
					if !inspect.Running {
						if inspect.ExitCode != 0 {
							fmt.Fprintf(out, "Attach exited with code %d\n", inspect.ExitCode)
							if attempt < maxRetries {
								goto retry
							}
							return fmt.Errorf("exec exited with code %d", inspect.ExitCode)
						}
						return nil
					}
					select {
					case <-waitDeadline:
						fmt.Fprintln(out, "Attach timed out, retrying...")
						if attempt < maxRetries {
							goto retry
						}
						return fmt.Errorf("attach timed out after %d attempts", maxRetries)
					default:
						time.Sleep(100 * time.Millisecond)
					}
				}
			}
		} else {
			// No attach command configured — print URL for manual connection.
			fmt.Fprintf(out, "\nSandbox ready. Connect manually:\n  %s\n", url)
		}
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

// copyWithTimeout copies from src to dst, returning nil on EOF or an error if
// no data arrives within timeout. This detects hangs where the remote end
// stops sending data without closing the connection.
func copyWithTimeout(dst io.Writer, src io.Reader, timeout time.Duration) error {
	buf := make([]byte, 32*1024)
	for {
		timer := time.AfterFunc(timeout, func() {})
		n, err := src.Read(buf)
		timer.Stop()
		if n > 0 {
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
