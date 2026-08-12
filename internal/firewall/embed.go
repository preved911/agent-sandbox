package firewall

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/docker/docker/client"
)

// Embedded firewall build context files.
// The //go:embed directive uses paths relative to this source file.
// Files are copied from repo-root firewall/ to this directory at build time.

//go:embed Dockerfile
var dockerfile []byte

//go:embed entrypoint.sh
var entrypoint []byte

//go:embed coredns/Corefile.template
var corednsTemplate []byte

// DefaultFirewallImage is the default firewall image tag if no config override.
const DefaultFirewallImage = "agent-sandbox-firewall:latest"

// EnsureFirewallImage checks if the firewall image exists locally.
// If missing, it writes the embedded build context to a temp directory
// and builds the image. Returns the image tag.
func EnsureFirewallImage(ctx context.Context, cli *client.Client, imageTag string) (string, error) {
	if imageTag == "" {
		imageTag = DefaultFirewallImage
	}

	// Check if image already exists
	if imageExists(ctx, cli, imageTag) {
		log.Printf("Firewall image %s exists, skipping build", imageTag)
		return imageTag, nil
	}

	log.Printf("Firewall image %s not found, building from embedded files...", imageTag)

	// Write embedded files to temp directory
	tmpDir, err := os.MkdirTemp("", "agent-sandbox-firewall-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := writeEmbeddedFiles(tmpDir); err != nil {
		return "", fmt.Errorf("write embedded files: %w", err)
	}

	// Build the image
	if err := buildFirewallImage(ctx, tmpDir, imageTag); err != nil {
		return "", fmt.Errorf("build firewall image: %w", err)
	}

	log.Printf("Firewall image %s built successfully", imageTag)
	return imageTag, nil
}

// imageExists checks if a Docker image exists locally.
func imageExists(ctx context.Context, cli *client.Client, tag string) bool {
	_, _, err := cli.ImageInspectWithRaw(ctx, tag)
	return err == nil
}

// writeEmbeddedFiles writes the embedded build context to a directory.
func writeEmbeddedFiles(dir string) error {
	// Write Dockerfile
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), dockerfile, 0644); err != nil {
		return fmt.Errorf("write Dockerfile: %w", err)
	}

	// Write entrypoint.sh
	entrypointPath := filepath.Join(dir, "entrypoint.sh")
	if err := os.WriteFile(entrypointPath, entrypoint, 0755); err != nil {
		return fmt.Errorf("write entrypoint.sh: %w", err)
	}

	// Write coredns/Corefile.template
	corednsDir := filepath.Join(dir, "coredns")
	if err := os.MkdirAll(corednsDir, 0755); err != nil {
		return fmt.Errorf("create coredns dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(corednsDir, "Corefile.template"), corednsTemplate, 0644); err != nil {
		return fmt.Errorf("write Corefile.template: %w", err)
	}

	return nil
}

// buildFirewallImage runs docker build on the given context directory.
func buildFirewallImage(ctx context.Context, contextDir, tag string) error {
	args := []string{
		"build",
		"--file", filepath.Join(contextDir, "Dockerfile"),
		"--tag", tag,
		contextDir,
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker build failed: %w", err)
	}
	return nil
}
