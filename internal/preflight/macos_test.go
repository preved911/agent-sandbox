//go:build darwin

package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathUnder(t *testing.T) {
	tests := []struct {
		child  string
		parent string
		want   bool
	}{
		{"/Users/bob/projects", "/Users/bob/projects", true},
		{"/Users/bob/projects/myapp", "/Users/bob/projects", true},
		{"/Users/bob/projects/myapp/deep", "/Users/bob/projects", true},
		{"/Users/bob/other", "/Users/bob/projects", false},
		{"/Users/alice", "/Users/bob", false},
		{"/", "/Users", false},
		{"/Users/bob/projects", "/Users/bob/projects/", true}, // trailing slash
	}

	for _, tt := range tests {
		got := pathUnder(tt.child, tt.parent)
		if got != tt.want {
			t.Errorf("pathUnder(%q, %q) = %v, want %v", tt.child, tt.parent, got, tt.want)
		}
	}
}

func TestCheckDockerDesktop(t *testing.T) {
	// Create a temporary settings.json.
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	// Write settings with shared paths.
	content := `{"filesharingDirectories": ["/Users/bob/projects", "/tmp"]}`
	if err := os.WriteFile(settingsPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Override the global path for testing.
	orig := dockerDesktopSettingsPath
	dockerDesktopSettingsPath = settingsPath
	defer func() { dockerDesktopSettingsPath = orig }()

	// Should pass for covered path.
	if err := checkDockerDesktop("/Users/bob/projects/myapp"); err != nil {
		t.Errorf("expected nil error for covered path, got: %v", err)
	}

	// Should fail for uncovered path.
	if err := checkDockerDesktop("/Users/bob/secret"); err == nil {
		t.Error("expected error for uncovered path, got nil")
	}
}
