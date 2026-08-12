// Package version provides build-time version information.
//
// Set via -ldflags at build time for release builds:
//
//	go build -ldflags "-X github.com/preved911/agent-sandbox/internal/version.Version=v1.0.0 \
//	  -X github.com/preved911/agent-sandbox/internal/version.Commit=abc1234 \
//	  -X github.com/preved911/agent-sandbox/internal/version.Date=2026-01-01T00:00:00Z"
//
// When installed via "go install module@version", VCS info is auto-detected
// from Go's embedded build metadata (debug.ReadBuildInfo).
package version

import (
	"runtime"
	"runtime/debug"
)

// Set via -ldflags at build time. Empty string = use auto-detection.
var (
	Version = ""  // semantic version or git tag
	Commit  = ""  // git commit hash (short)
	Date    = ""  // build timestamp (ISO 8601)
)

// Info returns a structured version report.
type Info struct {
	Version string `json:"version" yaml:"version"`
	Commit  string `json:"commit"  yaml:"commit"`
	Date    string `json:"date"    yaml:"date"`
	Go      string `json:"go"      yaml:"go"`
	OS      string `json:"os"      yaml:"os"`
	Arch    string `json:"arch"    yaml:"arch"`
}

// Get returns the current build info.
// Falls back to debug.ReadBuildInfo when ldflags are not set (go install).
func Get() Info {
	v, c, d := Version, Commit, Date

	// Auto-detect from Go build metadata when not set via ldflags.
	if v == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				v = info.Main.Version
			}
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if c == "" && len(s.Value) >= 7 {
						c = s.Value[:7]
					}
				case "vcs.time":
					if d == "" {
						d = s.Value
					}
				}
			}
		}
	}

	if v == "" {
		v = "dev"
	}
	if c == "" {
		c = "unknown"
	}
	if d == "" {
		d = "unknown"
	}

	return Info{
		Version: v,
		Commit:  c,
		Date:    d,
		Go:      runtime.Version(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
}
