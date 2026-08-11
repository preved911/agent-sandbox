package run

import (
	"strings"
	"testing"

	"github.com/preved911/agent-sandbox/internal/config"
)

func TestBuildMounts_BindMount(t *testing.T) {
	cfg := &config.Config{
		Run: config.RunConfig{
			Mounts: []config.Mount{
				{Source: "/tmp/src", Target: "/dst"},
			},
		},
	}
	binds, mounts, err := buildMounts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 2 binds: auto-mount cwd→/workspace + user mount /tmp/src:/dst
	if len(binds) != 2 {
		t.Fatalf("expected 2 binds, got %d: %v", len(binds), binds)
	}
	if !strings.HasSuffix(binds[0], ":/workspace") {
		t.Errorf("first bind should be auto-mount to /workspace, got: %v", binds[0])
	}
	if binds[1] != "/tmp/src:/dst" {
		t.Errorf("unexpected second bind: %v", binds[1])
	}
	if len(mounts) != 0 {
		t.Errorf("unexpected mounts: %v", mounts)
	}
}

func TestBuildMounts_ReadOnly(t *testing.T) {
	cfg := &config.Config{
		Run: config.RunConfig{
			Mounts: []config.Mount{
				{Source: "/tmp/src", Target: "/dst", ReadOnly: true},
			},
		},
	}
	binds, _, err := buildMounts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 2 binds: auto-mount cwd→/workspace + user mount /tmp/src:/dst:ro
	if len(binds) != 2 {
		t.Fatalf("expected 2 binds, got %d: %v", len(binds), binds)
	}
	if binds[1] != "/tmp/src:/dst:ro" {
		t.Errorf("unexpected second bind: %v", binds[1])
	}
}

func TestBuildMounts_VolumeMount(t *testing.T) {
	cfg := &config.Config{
		Run: config.RunConfig{
			Mounts: []config.Mount{
				{Source: "my-vol", Target: "/dst", Type: "volume"},
			},
		},
	}
	binds, mounts, err := buildMounts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 1 auto-mount bind + 1 volume mount
	if len(binds) != 1 || !strings.HasSuffix(binds[0], ":/workspace") {
		t.Errorf("expected auto-mount bind, got: %v", binds)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	if mounts[0].Type != "volume" || mounts[0].Source != "my-vol" || mounts[0].Target != "/dst" {
		t.Errorf("unexpected mount: %v", mounts[0])
	}
}

func TestBuildMounts_TmpFS(t *testing.T) {
	cfg := &config.Config{
		Run: config.RunConfig{
			Mounts: []config.Mount{
				{Target: "/tmp", Type: "tmpfs"},
			},
		},
	}
	binds, mounts, err := buildMounts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 1 auto-mount bind + 1 tmpfs mount
	if len(binds) != 1 || !strings.HasSuffix(binds[0], ":/workspace") {
		t.Errorf("expected auto-mount bind, got: %v", binds)
	}
	if len(mounts) != 1 || mounts[0].Type != "tmpfs" {
		t.Errorf("unexpected mounts: %v", mounts)
	}
}

func TestBuildMounts_MissingTarget(t *testing.T) {
	cfg := &config.Config{
		Run: config.RunConfig{
			Mounts: []config.Mount{
				{Source: "/tmp/src"},
			},
		},
	}
	_, _, err := buildMounts(cfg)
	if err == nil || !strings.Contains(err.Error(), "target is required") {
		t.Errorf("expected target required error, got: %v", err)
	}
}

func TestBuildMounts_MissingSource(t *testing.T) {
	cfg := &config.Config{
		Run: config.RunConfig{
			Mounts: []config.Mount{
				{Target: "/dst"},
			},
		},
	}
	_, _, err := buildMounts(cfg)
	if err == nil || !strings.Contains(err.Error(), "bind source is required") {
		t.Errorf("expected bind source required error, got: %v", err)
	}
}

func TestBuildMounts_UnknownType(t *testing.T) {
	cfg := &config.Config{
		Run: config.RunConfig{
			Mounts: []config.Mount{
				{Source: "/tmp", Target: "/dst", Type: "nfs"},
			},
		},
	}
	_, _, err := buildMounts(cfg)
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("expected unknown type error, got: %v", err)
	}
}

func TestBuildMounts_Empty(t *testing.T) {
	cfg := &config.Config{}
	binds, mounts, err := buildMounts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Auto-mount cwd→/workspace is always added even with empty mounts list.
	if len(binds) != 1 || !strings.HasSuffix(binds[0], ":/workspace") {
		t.Errorf("expected 1 auto-mount bind to /workspace, got binds=%v", binds)
	}
	if len(mounts) != 0 {
		t.Errorf("expected empty mounts, got %v", mounts)
	}
}

func TestBuildMounts_WorkdirAlreadyMounted(t *testing.T) {
	// When user already mounts /workspace, auto-mount should be skipped.
	cfg := &config.Config{
		Run: config.RunConfig{
			Mounts: []config.Mount{
				{Source: "/custom/project", Target: "/workspace"},
			},
		},
	}
	binds, _, err := buildMounts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(binds) != 1 || binds[0] != "/custom/project:/workspace" {
		t.Errorf("expected only user mount, got: %v", binds)
	}
}
