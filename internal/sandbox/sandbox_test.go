package sandbox

import (
	"strings"
	"testing"
)

func TestHashPath_Deterministic(t *testing.T) {
	a := HashPath("/Users/bob/projects/myapp")
	b := HashPath("/Users/bob/projects/myapp")
	if a != b {
		t.Errorf("HashPath not deterministic: %s != %s", a, b)
	}
}

func TestHashPath_Length(t *testing.T) {
	h := HashPath("/some/path")
	if len(h) != 8 {
		t.Errorf("HashPath returned %d chars, want 8", len(h))
	}
}

func TestHashPath_HexOnly(t *testing.T) {
	h := HashPath("/some/path")
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("HashPath returned non-hex char: %c", c)
		}
	}
}

func TestHashPath_DifferentPaths(t *testing.T) {
	a := HashPath("/Users/bob/projects/app1")
	b := HashPath("/Users/bob/projects/app2")
	if a == b {
		t.Errorf("Different paths produced same hash: %s", a)
	}
}

func TestHashPath_CleansPath(t *testing.T) {
	a := HashPath("/Users/bob/projects/myapp")
	b := HashPath("/Users/bob/projects/myapp/")
	if a != b {
		t.Errorf("Trailing slash changed hash: %s != %s", a, b)
	}
}

func TestResourceName(t *testing.T) {
	name := ResourceName("a1b2c3d4", SuffixAgent)
	if name != "agent-sandbox-a1b2c3d4-agent" {
		t.Errorf("ResourceName = %s, want agent-sandbox-a1b2c3d4-agent", name)
	}
}

func TestDefaultLabels(t *testing.T) {
	labels := DefaultLabels("a1b2c3d4", "/Users/bob/projects/myapp", "go-dev")
	if labels[Label] != "true" {
		t.Errorf("Label = %s, want true", labels[Label])
	}
	if labels[LabelHash] != "a1b2c3d4" {
		t.Errorf("LabelHash = %s, want a1b2c3d4", labels[LabelHash])
	}
	if labels[LabelPath] != "/Users/bob/projects/myapp" {
		t.Errorf("LabelPath = %s, want /Users/bob/projects/myapp", labels[LabelPath])
	}
	if labels[LabelProfile] != "go-dev" {
		t.Errorf("LabelProfile = %s, want go-dev", labels[LabelProfile])
	}
}

func TestDefaultLabels_EmptyProfile(t *testing.T) {
	labels := DefaultLabels("a1b2c3d4", "/some/path", "")
	if _, ok := labels[LabelProfile]; ok {
		t.Error("empty profile should not set LabelProfile")
	}
}

func TestSuffixConstants(t *testing.T) {
	// All suffixes should start with hyphen and produce valid Docker names
	suffixes := []string{SuffixAgent, SuffixFirewall, SuffixSessions, SuffixNet}
	for _, s := range suffixes {
		if !strings.HasPrefix(s, "-") {
			t.Errorf("Suffix %q should start with hyphen", s)
		}
		name := ResourceName("a1b2c3d4", s)
		if len(name) > 63 {
			t.Errorf("Resource name %q exceeds 63 chars (Docker limit)", name)
		}
	}
}
