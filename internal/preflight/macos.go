//go:build darwin

package preflight

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// dockerDesktopSettingsPath is the standard location of Docker Desktop's
// settings on macOS (Apple silicon and Intel).
var dockerDesktopSettingsPath = filepath.Join(
	os.Getenv("HOME"),
	"Library", "Group Containers", "group.com.docker", "settings.json",
)

// dockerDesktopSettings represents the subset of Docker Desktop's
// settings.json we care about.
type dockerDesktopSettings struct {
	FileSharingDirectories []string `json:"filesharingDirectories"`
}

// sharedPathsCheckPlatform verifies that dir is covered by Docker Desktop's
// or Colima's shared-paths on macOS.
func sharedPathsCheckPlatform(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	// Try Docker Desktop first.
	if err := checkDockerDesktop(absDir); err == nil {
		return nil // covered by Docker Desktop
	}

	// Try Colima.
	if err := checkColima(absDir); err == nil {
		return nil // covered by Colima
	}

	return fmt.Errorf(`%s is not in Docker's shared paths.

Add it: Docker Desktop → Settings → Resources → File Sharing → add:
  %s
  (or a parent like %s)

Then re-run.`, absDir, absDir, filepath.Dir(absDir))
}

// checkDockerDesktop reads Docker Desktop's settings.json and checks if
// dir falls under any of the filesharingDirectories entries.
func checkDockerDesktop(dir string) error {
	data, err := os.ReadFile(dockerDesktopSettingsPath)
	if err != nil {
		return err // file not found or unreadable — skip
	}

	var settings dockerDesktopSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parse %s: %w", dockerDesktopSettingsPath, err)
	}

	for _, shared := range settings.FileSharingDirectories {
		if pathUnder(dir, shared) {
			return nil
		}
	}

	return fmt.Errorf("%s not in Docker Desktop shared paths", dir)
}

// checkColima checks if dir is covered by Colima's mount configuration.
// Colima mounts $HOME by default.
func checkColima(dir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Colima mounts $HOME by default (always covers everything under home).
	if pathUnder(dir, home) {
		return nil
	}

	// Also check common Colima mount points.
	colimaHome := filepath.Join(home, ".colima")
	if pathUnder(dir, colimaHome) {
		return nil
	}

	return fmt.Errorf("%s not in Colima shared paths", dir)
}

// pathUnder returns true if child is the same as parent or nested under it.
func pathUnder(child, parent string) bool {
	child = filepath.Clean(child)
	parent = filepath.Clean(parent)

	if child == parent {
		return true
	}

	// Ensure parent ends with separator for prefix matching.
	if !strings.HasSuffix(parent, string(filepath.Separator)) {
		parent += string(filepath.Separator)
	}

	return strings.HasPrefix(child, parent)
}
