package run

import (
	"strings"
	"testing"

	"github.com/preved911/opencode-sandbox/internal/config"
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
	if len(binds) != 1 || binds[0] != "/tmp/src:/dst" {
		t.Errorf("unexpected binds: %v", binds)
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
	if len(binds) != 1 || binds[0] != "/tmp/src:/dst:ro" {
		t.Errorf("unexpected binds: %v", binds)
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
	_, mounts, err := buildMounts(cfg)
	if err != nil {
		t.Fatal(err)
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
	_, mounts, err := buildMounts(cfg)
	if err != nil {
		t.Fatal(err)
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
	if len(binds) != 0 || len(mounts) != 0 {
		t.Errorf("expected empty, got binds=%v mounts=%v", binds, mounts)
	}
}
