package firewall

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/docker/docker/client"
)

// Embedded firewall build context files.

//go:embed Dockerfile
var fwDockerfile []byte

//go:embed entrypoint.sh
var fwEntrypoint []byte

//go:embed coredns/Corefile.template
var fwCorednsTemplate []byte

// Embedded proxy build context files.

//go:embed proxy/Dockerfile
var proxyDockerfile []byte

//go:embed proxy/entrypoint.sh
var proxyEntrypoint []byte

// Default image tags.
const (
	DefaultFirewallImage = "agent-sandbox-firewall:latest"
	DefaultProxyImage    = "agent-sandbox-proxy:latest"
)

// buildHash computes a SHA-256 hash of embedded files for cache busting.
func buildHash(files ...[]byte) string {
	h := sha256.New()
	for _, f := range files {
		h.Write(f)
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// imageExists checks if a Docker image exists locally.
func imageExists(ctx context.Context, cli *client.Client, tag string) bool {
	_, _, err := cli.ImageInspectWithRaw(ctx, tag)
	return err == nil
}

// imageHashLabel returns the build hash stored in an image's labels.
func imageHashLabel(ctx context.Context, cli *client.Client, tag string) string {
	info, _, err := cli.ImageInspectWithRaw(ctx, tag)
	if err != nil {
		return ""
	}
	return info.Config.Labels["agent-sandbox.build-hash"]
}

// EnsureFirewallImage checks if the firewall image exists and matches current embedded files.
// If missing or stale, rebuilds from embedded files. Returns the image tag.
func EnsureFirewallImage(ctx context.Context, cli *client.Client, imageTag string) (string, error) {
	if imageTag == "" {
		imageTag = DefaultFirewallImage
	}

	currentHash := buildHash(fwDockerfile, fwEntrypoint, fwCorednsTemplate)

	// Check if image exists and hash matches
	if imageExists(ctx, cli, imageTag) {
		if imageHashLabel(ctx, cli, imageTag) == currentHash {
			log.Printf("Firewall image %s is up to date", imageTag)
			return imageTag, nil
		}
		log.Printf("Firewall image %s is stale, rebuilding...", imageTag)
	}

	log.Printf("Building firewall image %s...", imageTag)

	tmpDir, err := os.MkdirTemp("", "agent-sandbox-firewall-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := writeFirewallFiles(tmpDir); err != nil {
		return "", fmt.Errorf("write firewall files: %w", err)
	}

	if err := buildImage(ctx, tmpDir, imageTag, currentHash); err != nil {
		return "", fmt.Errorf("build firewall image: %w", err)
	}

	log.Printf("Firewall image %s built successfully", imageTag)
	return imageTag, nil
}

// EnsureProxyImage checks if the proxy image exists and matches current embedded files.
// If missing or stale, rebuilds from embedded files. Returns the image tag.
func EnsureProxyImage(ctx context.Context, cli *client.Client, imageTag string) (string, error) {
	if imageTag == "" {
		imageTag = DefaultProxyImage
	}

	currentHash := buildHash(proxyDockerfile, proxyEntrypoint)

	// Check if image exists and hash matches
	if imageExists(ctx, cli, imageTag) {
		if imageHashLabel(ctx, cli, imageTag) == currentHash {
			log.Printf("Proxy image %s is up to date", imageTag)
			return imageTag, nil
		}
		log.Printf("Proxy image %s is stale, rebuilding...", imageTag)
	}

	log.Printf("Building proxy image %s...", imageTag)

	tmpDir, err := os.MkdirTemp("", "agent-sandbox-proxy-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := writeProxyFiles(tmpDir); err != nil {
		return "", fmt.Errorf("write proxy files: %w", err)
	}

	if err := buildImage(ctx, tmpDir, imageTag, currentHash); err != nil {
		return "", fmt.Errorf("build proxy image: %w", err)
	}

	log.Printf("Proxy image %s built successfully", imageTag)
	return imageTag, nil
}

// writeFirewallFiles writes the embedded firewall build context to a directory.
func writeFirewallFiles(dir string) error {
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), fwDockerfile, 0644); err != nil {
		return fmt.Errorf("write Dockerfile: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "entrypoint.sh"), fwEntrypoint, 0755); err != nil {
		return fmt.Errorf("write entrypoint.sh: %w", err)
	}
	corednsDir := filepath.Join(dir, "coredns")
	if err := os.MkdirAll(corednsDir, 0755); err != nil {
		return fmt.Errorf("create coredns dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(corednsDir, "Corefile.template"), fwCorednsTemplate, 0644); err != nil {
		return fmt.Errorf("write Corefile.template: %w", err)
	}
	return nil
}

// writeProxyFiles writes the embedded proxy build context to a directory.
func writeProxyFiles(dir string) error {
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), proxyDockerfile, 0644); err != nil {
		return fmt.Errorf("write Dockerfile: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "entrypoint.sh"), proxyEntrypoint, 0755); err != nil {
		return fmt.Errorf("write entrypoint.sh: %w", err)
	}
	return nil
}

// buildImage runs docker build with a build-hash label for cache busting.
func buildImage(ctx context.Context, contextDir, tag, buildHash string) error {
	args := []string{
		"build",
		"--file", filepath.Join(contextDir, "Dockerfile"),
		"--tag", tag,
		"--label", "agent-sandbox.build-hash=" + buildHash,
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
