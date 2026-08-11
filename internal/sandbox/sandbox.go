// Package sandbox holds constants and naming helpers shared across the tool.
package sandbox

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
)

// Label is attached to every container the tool creates. ps and rm refuse to
// touch any container that does not carry this label, so the tool can never
// list or remove an unrelated container.
const Label = "opencode-sandbox"

// LabelName carries the full resource name (e.g. "opencode-sandbox-a1b2c3d4-agent")
// for display in ps output and debugging.
const LabelName = "opencode-sandbox.name"

// LabelHash carries the 8-character hex hash derived from the working directory.
const LabelHash = "opencode-sandbox.hash"

// LabelPath carries the absolute working directory path for display and cleanup.
const LabelPath = "opencode-sandbox.path"

// LabelProfile carries the config profile name for debugging.
const LabelProfile = "opencode-sandbox.profile"

// Resource suffixes. All sandbox resources share the same hash base plus a
// type suffix:
//
//	Agent container:  opencode-sandbox-<hash>-agent
//	Firewall container: opencode-sandbox-<hash>-firewall
//	Sessions volume:  opencode-sandbox-<hash>-sessions
//	Isolated network: opencode-sandbox-<hash>-net
const (
	SuffixAgent    = "-agent"
	SuffixFirewall = "-firewall"
	SuffixSessions = "-sessions"
	SuffixNet      = "-net"
)

// HashPath returns an 8-character hex hash derived from an absolute path.
// The hash is deterministic: the same path always produces the same hash.
// The path is cleaned (via filepath.Clean) before hashing so that trailing
// slashes and redundant separators are normalized.
func HashPath(absPath string) string {
	cleaned := filepath.Clean(absPath)
	h := sha256.Sum256([]byte(cleaned))
	return fmt.Sprintf("%x", h[:4]) // first 4 bytes = 8 hex chars
}

// ResourceName returns a Docker resource name for the given hash and suffix.
// Example: ResourceName("a1b2c3d4", SuffixAgent) → "opencode-sandbox-a1b2c3d4-agent"
func ResourceName(hash, suffix string) string {
	return Label + "-" + hash + suffix
}

// DefaultLabels returns the label set applied to every sandbox resource.
// hash is the 8-char hex from HashPath; absPath is the original working
// directory; profile is the config profile name (may be empty).
func DefaultLabels(hash, absPath, profile string) map[string]string {
	labels := map[string]string{
		Label:      "true",
		LabelHash:  hash,
		LabelPath:  filepath.Clean(absPath),
	}
	if profile != "" {
		labels[LabelProfile] = profile
	}
	return labels
}
