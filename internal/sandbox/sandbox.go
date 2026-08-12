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
const Label = "agent-sandbox"

// LabelName carries the full resource name (e.g. "agent-sandbox-a1b2c3d4-agent")
// for display in ps output and debugging.
const LabelName = "agent-sandbox.name"

// LabelHash carries the 8-character hex hash derived from the working directory.
const LabelHash = "agent-sandbox.hash"

// LabelPath carries the absolute working directory path for display and cleanup.
const LabelPath = "agent-sandbox.path"

// LabelProfile carries the config profile name for debugging.
const LabelProfile = "agent-sandbox.profile"

// SandboxRole identifies the role of a sandbox container ("agent" or "firewall").
const SandboxRole = "agent-sandbox.role"

// Resource suffixes. All sandbox resources share the same hash base plus a
// type suffix:
//
//	Agent container:  agent-sandbox-<hash>-agent
//	Firewall container: agent-sandbox-<hash>-firewall
//	Sessions volume:  agent-sandbox-<hash>-sessions
//	Isolated network: agent-sandbox-<hash>-net
const (
	SuffixAgent    = "-agent"
	SuffixFirewall = "-firewall"
	SuffixSessions = "-sessions"
	SuffixNet      = "-net"
)

// CacheLabel marks a Docker volume as a sandbox cache.
const CacheLabel = "agent-sandbox.cache"

// CacheName returns a Docker volume name for a cache entry.
// Example: CacheName("a1b2c3d4", "npm") → "agent-sandbox-a1b2c3d4-cache-npm"
func CacheName(hash, cacheName string) string {
	return Label + "-" + hash + "-cache-" + cacheName
}

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
// Example: ResourceName("a1b2c3d4", SuffixAgent) → "agent-sandbox-a1b2c3d4-agent"
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
