package main

import (
	"reflect"
	"testing"
)

func TestParsePinRules(t *testing.T) {
	env := "allow|10.0.0.0/8|tcp|443|\n" +
		"block|evil.example.org|||\n" +
		"allow|api.example.org|tcp|80,443|dns_allow_80_443\n" +
		"allow|*.anthropic.com|||dns_allow_any\n" +
		"\n" +
		"allow|no-set.example.org|||\n"

	rules := parsePinRules(env)
	want := []pinRule{
		{pattern: "api.example.org", set: "dns_allow_80_443"},
		{pattern: "*.anthropic.com", set: "dns_allow_any"},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("parsePinRules() = %+v, want %+v", rules, want)
	}
}

func TestParseQueryLogLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantDom  string
		wantCode string
		wantOK   bool
	}{
		{
			name:     "A query",
			line:     `[INFO] 10.161.0.2:47894 - 0514 "A IN api.anthropic.com. udp 52 false 512" NOERROR qr,rd,ra 71 0.000183636s`,
			wantDom:  "api.anthropic.com",
			wantCode: "NOERROR",
			wantOK:   true,
		},
		{
			name:     "AAAA query",
			line:     `[INFO] [::ffff:10.161.0.2]:40832 - 41176 "AAAA IN cdn.Example.ORG. udp 54 false 1232" NOERROR qr,rd,ra 118 0.001048205s`,
			wantDom:  "cdn.example.org",
			wantCode: "NOERROR",
			wantOK:   true,
		},
		{
			name:     "denied query",
			line:     `[INFO] 10.161.0.2:47895 - 0515 "A IN evil.example.org. udp 40 false 512" NXDOMAIN qr,rd 54 0.0001s`,
			wantDom:  "evil.example.org",
			wantCode: "NXDOMAIN",
			wantOK:   true,
		},
		{
			name:   "not a query log",
			line:   `[INFO] plugin/log: something else`,
			wantOK: false,
		},
		{
			name:   "error line",
			line:   `[ERROR] plugin/errors: 2 evil.com. A: dns: message header invalid`,
			wantOK: false,
		},
		{
			name:   "unquoted line",
			line:   `CoreDNS-1.12.0 linux/arm64, go1.25.0`,
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dom, code, ok := parseQueryLogLine(tt.line)
			if dom != tt.wantDom || code != tt.wantCode || ok != tt.wantOK {
				t.Errorf("parseQueryLogLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.line, dom, code, ok, tt.wantDom, tt.wantCode, tt.wantOK)
			}
		})
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		domain  string
		pattern string
		want    bool
	}{
		{"api.example.org", "api.example.org", true},
		{"sub.api.example.org", "api.example.org", true},
		{"other.example.org", "api.example.org", false},
		{"example.org", "api.example.org", false},
		{"api.anthropic.com", "*.anthropic.com", true},
		{"x.y.anthropic.com", "*.anthropic.com", true},
		{"anthropic.com", "*.anthropic.com", false},
		{"evilanthropic.com", "*.anthropic.com", false},
		{"deep.sub.api.example.org", "api.example.org", true},
	}
	for _, tt := range tests {
		if got := matchesPattern(tt.domain, tt.pattern); got != tt.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.domain, tt.pattern, got, tt.want)
		}
	}
}
