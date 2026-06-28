package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/preved911/opencode-sandbox/internal/build"
	"github.com/preved911/opencode-sandbox/internal/config"
	"github.com/preved911/opencode-sandbox/internal/docker"
	"github.com/preved911/opencode-sandbox/internal/paths"
	"github.com/preved911/opencode-sandbox/internal/run"
)

func newRunCmd(rf *rootFlags) *cobra.Command {
	var (
		nameOverride   string
		noBuild        bool
		pull           bool
		envOverrides   []string
		mountOverrides []string
		bindOverride   string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Build and start a sandbox, then print the opencode attach URL",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(rf.configPath, rf.profile)
			if err != nil {
				return err
			}
			if rf.dockerHost != "" {
				cfg.DockerHost = rf.dockerHost
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

			var image string
			switch {
			case cfg.Build.Image != "":
				image = cfg.Build.Image
			case noBuild:
				image = "opencode-sandbox/" + cfg.Name + ":latest"
			default:
				image, err = build.ImageBuild(ctx, cfg, build.Options{Pull: pull})
				if err != nil {
					return err
				}
			}

			cli, err := docker.NewClient(cfg.DockerHost)
			if err != nil {
				return fmt.Errorf("docker client: %w", err)
			}
			defer cli.Close()

			name := nameOverride
			if name == "" {
				name = generateName(cfg.Name)
			}

			res, err := run.Start(ctx, cli, cfg, image, name)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			for _, b := range res.Binds {
				fmt.Fprintf(out, "mount: %s\n", b)
			}
			fmt.Fprintf(out, "volume: %s\n", res.Volume)

			host := cfg.Docker.AttachHost
			if host == "" {
				host = docker.AttachHost(docker.EffectiveHost(cfg.DockerHost))
			}
			fmt.Fprintf(out, "opencode attach http://%s:%d\n", host, res.HostPort)
			return nil
		},
	}
	cmd.Flags().StringVar(&nameOverride, "name", "", "container name (default: <profile>-<random>)")
	cmd.Flags().BoolVar(&noBuild, "no-build", false, "skip the build step (image must already exist)")
	cmd.Flags().BoolVar(&pull, "pull", false, "pass --pull to docker build")
	cmd.Flags().StringArrayVarP(&envOverrides, "env", "e", nil, "set or override an env var (KEY=VALUE); repeatable")
	cmd.Flags().StringArrayVarP(&mountOverrides, "mount", "v", nil, "append a mount (source:target[:ro]); repeatable")
	cmd.Flags().StringVar(&bindOverride, "bind", "", "override run.port.bind (e.g. 0.0.0.0)")
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

// generateName creates a deterministic-looking container name from a profile
// name and a short random suffix, e.g. "go-dev-a3f7b2".
func generateName(profile string) string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a static suffix if crypto/rand fails.
		return profile + "-sandbox"
	}
	return profile + "-" + hex.EncodeToString(b)
}
