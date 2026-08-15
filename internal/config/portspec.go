package config

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Port limits for the port-spec format.
const (
	portMin = 1
	portMax = 65535

	// dnsSetPrefix is the prefix for nftables named sets holding IPs resolved
	// from DNS allow rules.
	dnsSetPrefix = "dns_allow_"

	// dnsSetAnySuffix names the set for DNS allow rules without port restriction.
	dnsSetAnySuffix = "any"

	// dnsSetMaxName caps nftables set identifier length; oversized canonical
	// specs fall back to a deterministic hash suffix.
	dnsSetMaxName = 63
)

// PortRange is an inclusive port range [Start, End]. A single port is the
// degenerate range Start == End.
type PortRange struct {
	Start int
	End   int
}

// ParsePortSpec parses a port specification string: comma-separated items,
// each a single port ("443") or an inclusive range ("8000-8100").
//
//	"443"                → [{443, 443}]
//	"8000-8100"          → [{8000, 8100}]
//	"80,443,8000-8100"   → [{80, 80}, {443, 443}, {8000, 8100}]
//
// The result is NOT canonicalized; use Canonicalize for the sorted, deduplicated,
// disjoint form. Leading/trailing whitespace on the whole string is tolerated;
// whitespace inside items is not (the spec travels through env vars verbatim).
func ParsePortSpec(spec string) ([]PortRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("invalid port spec %q: empty string — omit the field to match all ports", spec)
	}

	items := strings.Split(spec, ",")
	ranges := make([]PortRange, 0, len(items))
	for i, item := range items {
		// Explicit check instead of strings.Split semantics: "-" must appear
		// exactly once, in the middle ("80-", "-80", "8-0-0" are all invalid).
		dash := strings.Count(item, "-")
		var pr PortRange
		switch dash {
		case 0:
			port, err := parsePort(item)
			if err != nil {
				return nil, fmt.Errorf("invalid port spec %q: item %d: %w", spec, i+1, err)
			}
			pr = PortRange{Start: port, End: port}
		case 1:
			lo, hi, _ := strings.Cut(item, "-")
			if lo == "" || hi == "" {
				return nil, fmt.Errorf("invalid port spec %q: item %d: %q is not N or N-M", spec, i+1, item)
			}
			start, err := parsePort(lo)
			if err != nil {
				return nil, fmt.Errorf("invalid port spec %q: item %d: %w", spec, i+1, err)
			}
			end, err := parsePort(hi)
			if err != nil {
				return nil, fmt.Errorf("invalid port spec %q: item %d: %w", spec, i+1, err)
			}
			if start > end {
				return nil, fmt.Errorf("invalid port spec %q: item %d: range %d-%d is inverted (start must be <= end)", spec, i+1, start, end)
			}
			pr = PortRange{Start: start, End: end}
		default:
			return nil, fmt.Errorf("invalid port spec %q: item %d: %q is not N or N-M", spec, i+1, item)
		}
		ranges = append(ranges, pr)
	}
	return ranges, nil
}

// Canonicalize returns the canonical form of ranges: sorted by start port,
// deduplicated, with overlapping and adjacent ranges merged into disjoint
// ranges. Two specs with the same port set share the same canonical form.
func Canonicalize(ranges []PortRange) []PortRange {
	if len(ranges) == 0 {
		return nil
	}

	sorted := make([]PortRange, len(ranges))
	copy(sorted, ranges)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End < sorted[j].End
	})

	canonical := make([]PortRange, 0, len(sorted))
	for _, r := range sorted {
		if n := len(canonical); n > 0 && r.Start <= canonical[n-1].End+1 {
			// Overlapping or adjacent (no gap) with the previous range: merge.
			if r.End > canonical[n-1].End {
				canonical[n-1].End = r.End
			}
			continue
		}
		canonical = append(canonical, r)
	}
	return canonical
}

// FormatPortSpec converts ranges back into the canonical string form:
// comma-separated, sorted, single ports as "N" and true ranges as "N-M".
// It is the inverse of ParsePortSpec(Canonicalize(spec)). An empty input
// formats as the empty string (all ports).
func FormatPortSpec(ranges []PortRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		if r.Start == r.End {
			parts = append(parts, strconv.Itoa(r.Start))
		} else {
			parts = append(parts, strconv.Itoa(r.Start)+"-"+strconv.Itoa(r.End))
		}
	}
	return strings.Join(parts, ",")
}

// CanonicalPortSpec parses and canonicalizes a port spec in one step,
// returning the canonical string form.
func CanonicalPortSpec(spec string) (string, error) {
	ranges, err := ParsePortSpec(spec)
	if err != nil {
		return "", err
	}
	return FormatPortSpec(Canonicalize(ranges)), nil
}

// DNSSetName returns the nftables named set identifier for a canonical port
// spec of a DNS allow rule:
//
//	"443"        → dns_allow_443
//	"5000-5100"  → dns_allow_5000-5100
//	"80,443"     → dns_allow_80_443   (commas canonicalize to underscores)
//	""           → dns_allow_any      (no port restriction)
//
// If the canonical name would exceed the identifier limit, the spec is hashed
// into a short deterministic suffix (dns_allow_<8 hex chars>).
func DNSSetName(canonicalSpec string) string {
	if canonicalSpec == "" {
		return dnsSetPrefix + dnsSetAnySuffix
	}
	ident := dnsSetPrefix + strings.ReplaceAll(canonicalSpec, ",", "_")
	if len(ident) > dnsSetMaxName {
		sum := sha256.Sum256([]byte(canonicalSpec))
		ident = fmt.Sprintf("%s%x", dnsSetPrefix, sum[:4])
	}
	return ident
}

// parsePort parses a single decimal port number and enforces the 1-65535 range.
func parsePort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("%q is not a port number", s)
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("%q is not a decimal port number", s)
		}
	}
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number", s)
	}
	if port < portMin || port > portMax {
		return 0, fmt.Errorf("port %d out of range (%d-%d)", port, portMin, portMax)
	}
	return port, nil
}
