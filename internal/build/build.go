// Package build invokes the local docker CLI to build the sandbox image.
//
// We shell out instead of using the Go SDK's ImageBuild because BuildKit
// secrets require a buildkit session that the SDK does not expose
// ergonomically. docker(1) handles DOCKER_HOST transparently, so remote
// daemons still work.
package build

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/preved911/opencode-sandbox/internal/config"
	"github.com/preved911/opencode-sandbox/internal/paths"
)

// Options tweaks a single build invocation.
type Options struct {
	Tag    string
	Pull   bool
	Stdout io.Writer
	Stderr io.Writer
}

// ImageBuild builds (or skips, if config.Build.Image is set) and returns the
// image reference the caller should run.
func ImageBuild(ctx context.Context, cfg *config.Config, opts Options) (string, error) {
	if cfg.Build.Image != "" {
		return cfg.Build.Image, nil
	}

	tag := opts.Tag
	if tag == "" {
		tag = "opencode-sandbox/" + cfg.Name + ":latest"
	}

	dockerfile := cfg.Build.Dockerfile
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	dockerfileAbs, err := paths.Expand(dockerfile, cfg.BaseDir())
	if err != nil {
		return "", fmt.Errorf("resolve dockerfile: %w", err)
	}
	contextDir := cfg.Build.Context
	if contextDir == "" {
		contextDir = "."
	}
	contextAbs, err := paths.Expand(contextDir, cfg.BaseDir())
	if err != nil {
		return "", fmt.Errorf("resolve build context: %w", err)
	}

	args := []string{
		"build",
		"--file", dockerfileAbs,
		"--tag", tag,
	}
	if cfg.Build.Target != "" {
		args = append(args, "--target", cfg.Build.Target)
	}
	if cfg.Build.Pull || opts.Pull {
		args = append(args, "--pull")
	}
	for k, v := range cfg.Build.Args {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", k, v))
	}
	for _, s := range cfg.Build.Secrets {
		spec, err := secretSpec(s, cfg.BaseDir())
		if err != nil {
			return "", err
		}
		args = append(args, "--secret", spec)
	}
	args = append(args, contextAbs)

	stdout := opts.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker build failed: %w", err)
	}
	return tag, nil
}

func secretSpec(s config.Secret, baseDir string) (string, error) {
	if s.ID == "" {
		return "", fmt.Errorf("build secret: id is required")
	}
	parts := []string{"id=" + s.ID}
	switch {
	case s.Src != "" && s.Env != "":
		return "", fmt.Errorf("build secret %q: src and env are mutually exclusive", s.ID)
	case s.Src != "":
		abs, err := paths.Expand(s.Src, baseDir)
		if err != nil {
			return "", fmt.Errorf("build secret %q src: %w", s.ID, err)
		}
		parts = append(parts, "src="+abs)
	case s.Env != "":
		parts = append(parts, "env="+s.Env)
	default:
		return "", fmt.Errorf("build secret %q: src or env must be set", s.ID)
	}
	return strings.Join(parts, ","), nil
}
