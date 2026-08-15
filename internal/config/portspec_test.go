package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []PortRange
		wantErr bool
	}{
		{"single port", "443", []PortRange{{443, 443}}, false},
		{"range", "8000-8100", []PortRange{{8000, 8100}}, false},
		{"single element range", "80-80", []PortRange{{80, 80}}, false},
		{"two ports", "80,443", []PortRange{{80, 80}, {443, 443}}, false},
		{"mixed", "80,443,8000-8100", []PortRange{{80, 80}, {443, 443}, {8000, 8100}}, false},
		{"min port", "1", []PortRange{{1, 1}}, false},
		{"max port", "65535", []PortRange{{65535, 65535}}, false},
		{"max range", "1-65535", []PortRange{{1, 65535}}, false},
		{"whitespace trimmed", " 80,443 ", []PortRange{{80, 80}, {443, 443}}, false},
		{"unsorted ok", "443,80", []PortRange{{443, 443}, {80, 80}}, false},
		{"overlapping ok", "80-90,85-95", []PortRange{{80, 90}, {85, 95}}, false},

		{"empty string", "", nil, true},
		{"whitespace only", "   ", nil, true},
		{"zero port", "0", nil, true},
		{"too high", "65536", nil, true},
		{"negative", "-1", nil, true},
		{"inverted range", "8100-8000", nil, true},
		{"empty item", "80,,443", nil, true},
		{"trailing comma", "80,443,", nil, true},
		{"leading comma", ",80", nil, true},
		{"range missing hi", "8000-", nil, true},
		{"range missing lo", "-8000", nil, true},
		{"double dash", "80--90", nil, true},
		{"two dashes", "8-0-0", nil, true},
		{"letters", "abc", nil, true},
		{"hex", "0x50", nil, true},
		{"space inside item", "80, 443", nil, true},
		{"plus sign", "+80", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParsePortSpec(%q) error = %v, wantErr %v", tt.spec, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePortSpec(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name   string
		in     []PortRange
		want   []PortRange
	}{
		{"nil", nil, nil},
		{"empty", []PortRange{}, nil},
		{"single", []PortRange{{443, 443}}, []PortRange{{443, 443}}},
		{"sorts", []PortRange{{443, 443}, {80, 80}}, []PortRange{{80, 80}, {443, 443}}},
		{"dedupes", []PortRange{{443, 443}, {443, 443}}, []PortRange{{443, 443}}},
		{"subsumed", []PortRange{{80, 90}, {82, 84}}, []PortRange{{80, 90}}},
		{"overlapping merge", []PortRange{{80, 90}, {85, 95}}, []PortRange{{80, 95}}},
		{"adjacent merge", []PortRange{{80, 89}, {90, 99}}, []PortRange{{80, 99}}},
		{"gap kept", []PortRange{{80, 89}, {91, 99}}, []PortRange{{80, 89}, {91, 99}}},
		{"issue example", []PortRange{{443, 443}, {443, 443}, {80, 90}}, []PortRange{{80, 90}, {443, 443}}},
		{"chain merge", []PortRange{{10, 11}, {12, 13}, {14, 20}, {19, 25}, {30, 40}}, []PortRange{{10, 25}, {30, 40}}},
		{"unsorted chain", []PortRange{{14, 20}, {10, 11}, {19, 25}, {12, 13}}, []PortRange{{10, 25}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Canonicalize(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Canonicalize(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormatPortSpec(t *testing.T) {
	tests := []struct {
		name   string
		ranges []PortRange
		want   string
	}{
		{"empty", nil, ""},
		{"single port", []PortRange{{443, 443}}, "443"},
		{"range", []PortRange{{8000, 8100}}, "8000-8100"},
		{"mixed", []PortRange{{80, 80}, {443, 443}, {8000, 8100}}, "80,443,8000-8100"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatPortSpec(tt.ranges); got != tt.want {
				t.Errorf("FormatPortSpec(%v) = %q, want %q", tt.ranges, got, tt.want)
			}
		})
	}
}

func TestCanonicalPortSpec(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"443", "443", false},
		{"443,443,80-90", "80-90,443", false},
		{"8000-8100,8005-8010", "8000-8100", false},
		{"443,80", "80,443", false},
		{"80,443,8000-8100", "80,443,8000-8100", false},
		{"1-65535", "1-65535", false},
		{"", "", true},
		{"8100-8000", "", true},
	}
	for _, tt := range tests {
		got, err := CanonicalPortSpec(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("CanonicalPortSpec(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("CanonicalPortSpec(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDNSSetName(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"", "dns_allow_any"},
		{"443", "dns_allow_443"},
		{"5000-5100", "dns_allow_5000-5100"},
		{"80,443", "dns_allow_80_443"},
		{"80,443,8000-8100", "dns_allow_80_443_8000-8100"},
	}
	for _, tt := range tests {
		if got := DNSSetName(tt.spec); got != tt.want {
			t.Errorf("DNSSetName(%q) = %q, want %q", tt.spec, got, tt.want)
		}
	}
}

func TestDNSSetName_LongSpecHashFallback(t *testing.T) {
	// Build a spec whose canonical name exceeds the 63-char identifier limit.
	// 10 single ports ≈ 4 chars each + 9 commas ≈ 49 chars + "dns_allow_" (10) > 63.
	spec := "1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1011"
	canonical, err := CanonicalPortSpec(spec)
	if err != nil {
		t.Fatalf("CanonicalPortSpec(%q): %v", spec, err)
	}
	name := DNSSetName(canonical)
	if len(name) > dnsSetMaxName {
		t.Errorf("name %q exceeds %d chars", name, dnsSetMaxName)
	}
	if !strings.HasPrefix(name, dnsSetPrefix) {
		t.Errorf("name %q must keep the %q prefix", name, dnsSetPrefix)
	}
	// Deterministic: same spec → same name, different spec → different name.
	if again := DNSSetName(canonical); again != name {
		t.Errorf("DNSSetName not deterministic: %q vs %q", name, again)
	}
	other := DNSSetName("1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1012")
	if other == name {
		t.Errorf("different specs must hash to different names (both %q)", name)
	}
}

// TestParsePortSpecErrorMessages verifies errors name the offending item so
// users can locate the problem without the rule context.
func TestParsePortSpecErrorMessages(t *testing.T) {
	tests := []struct {
		spec       string
		wantSubstr string
	}{
		{"8100-8000", "inverted"},
		{"80,,443", "item 2"},
		{"0", "out of range"},
		{"abc", "not a decimal port number"},
		{"", "omit the field"},
	}
	for _, tt := range tests {
		_, err := ParsePortSpec(tt.spec)
		if err == nil {
			t.Errorf("ParsePortSpec(%q): expected error", tt.spec)
			continue
		}
		if !strings.Contains(err.Error(), tt.wantSubstr) {
			t.Errorf("ParsePortSpec(%q) error = %q, want substring %q", tt.spec, err, tt.wantSubstr)
		}
	}
}
