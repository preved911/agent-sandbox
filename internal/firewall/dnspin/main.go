// Command dns-pin implements step 2 of DNS rule enforcement in the agent-sandbox
// firewall container. It is built into the firewall image and runs as a sidecar
// to CoreDNS:
//
//	coredns -conf /etc/coredns/Corefile 2>&1 | dns-pin
//
// Step 1 (CoreDNS) only controls resolution: allow zones forward to upstream,
// deny zones return NXDOMAIN. The IP layer still has to let traffic through for
// allowed domains under a default-deny policy. dns-pin watches CoreDNS's query
// log (piped to stdin), resolves each queried domain that matches a DNS allow
// rule, and pins the resolved IPv4 addresses into nftables named sets with
// element timeouts derived from the DNS TTL:
//
//	nft add element ip firewall dns_allow_443 { 162.159.140.245 timeout 300s }
//
// The forward chain references these sets (ip daddr @dns_allow_443 tcp dport
// 443 accept), which are created by entrypoint.sh at startup.
//
// DNS block targets never resolve (NXDOMAIN), so no IP is ever pinned for them.
//
// This program is intentionally standalone (stdlib only, no imports from the
// parent module): its source is embedded into the firewall image build context
// and compiled inside a multi-stage Docker build.
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	envRules = "FIREWALL_RULES"

	// repinWindow throttles re-resolution of the same domain into the same set
	// (query bursts: A + AAAA + retries within one resolver cycle).
	repinWindow = 30 * time.Second

	// preResolveAttempts / preResolveInterval bound startup pre-resolution
	// while CoreDNS comes up on 127.0.0.1:53.
	preResolveAttempts = 15
	preResolveInterval = 2 * time.Second

	resolverAddr = "127.0.0.1:53"
)

// pinRule is a DNS allow rule relevant to pinning.
type pinRule struct {
	pattern string // domain as written: "api.example.org" or "*.anthropic.com"
	set     string // nftables named set for the rule's canonical port spec
}

// pinEntry is one resolved address with its DNS TTL.
type pinEntry struct {
	ip  string
	ttl int
}

// pinner tracks recently pinned (domain, set) pairs.
type pinner struct {
	rules []pinRule
	mu    sync.Mutex
	last  map[string]time.Time
}

func main() {
	log.SetPrefix("dns-pin: ")
	log.SetFlags(log.LstdFlags | log.LUTC)

	p := &pinner{rules: parsePinRules(os.Getenv(envRules))}
	if len(p.rules) == 0 {
		log.Print("no DNS allow rules with pinning — passing log through")
	} else {
		log.Printf("watching %d DNS allow rule(s)", len(p.rules))
		go p.preResolve()
	}

	// Re-emit CoreDNS log lines so `docker logs` still shows DNS traffic.
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fmt.Fprintln(out, scanner.Text())
		out.Flush()
		p.handleLogLine(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("read stdin: %v", err)
	}
}

// parsePinRules extracts DNS allow rules with a pin set from FIREWALL_RULES
// (one rule per line: type|target|protocol|ports|set).
func parsePinRules(env string) []pinRule {
	var rules []pinRule
	for _, line := range strings.Split(env, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 5 || fields[0] != "allow" {
			continue
		}
		target, set := strings.TrimSpace(fields[1]), strings.TrimSpace(fields[4])
		if target == "" || set == "" {
			continue
		}
		rules = append(rules, pinRule{pattern: strings.ToLower(target), set: set})
	}
	return rules
}

// preResolve pins exact (non-wildcard) allow domains at startup so the first
// agent connection does not have to wait for a query log round-trip. Wildcard
// domains cannot be pre-resolved and are pinned on first query.
func (p *pinner) preResolve() {
	for _, r := range p.rules {
		if strings.Contains(r.pattern, "*") {
			continue
		}
		domain := r.pattern
		var entries []pinEntry
		for attempt := 0; attempt < preResolveAttempts; attempt++ {
			if attempt > 0 {
				time.Sleep(preResolveInterval)
			}
			entries = resolve(domain)
			if len(entries) > 0 {
				break
			}
		}
		if len(entries) == 0 {
			log.Printf("pre-resolve %s: no answer (will pin on first query)", domain)
			continue
		}
		p.pin(domain, r.set, entries)
	}
}

// handleLogLine extracts the queried name from a CoreDNS log line and pins it
// into every matching rule's set.
func (p *pinner) handleLogLine(line string) {
	if len(p.rules) == 0 {
		return
	}
	domain, rcode, ok := parseQueryLogLine(line)
	if !ok || rcode != "NOERROR" {
		return
	}

	sets := make(map[string]bool)
	for _, r := range p.rules {
		if matchesPattern(domain, r.pattern) {
			sets[r.set] = true
		}
	}
	if len(sets) == 0 {
		return
	}

	entries := resolve(domain)
	if len(entries) == 0 {
		return
	}
	for set := range sets {
		p.pin(domain, set, entries)
	}
}

// pin adds entries to the named set unless the same (domain, set) pair was
// pinned within the throttle window.
func (p *pinner) pin(domain, set string, entries []pinEntry) {
	key := domain + "\x00" + set
	p.mu.Lock()
	if t, ok := p.last[key]; ok && time.Since(t) < repinWindow {
		p.mu.Unlock()
		return
	}
	p.last[key] = time.Now()
	p.mu.Unlock()

	for _, e := range entries {
		element := fmt.Sprintf("{ %s timeout %ds }", e.ip, e.ttl)
		cmd := exec.Command("nft", "add", "element", "ip", "firewall", set, element)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("nft add element %s %s: %v: %s", set, element, err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("pinned %s (%s) into %s for %ds", e.ip, domain, set, e.ttl)
		}
	}
}

// parseQueryLogLine parses CoreDNS `log` plugin output:
//
//	[INFO] 10.0.0.2:47894 - 0514 "A IN api.anthropic.com. udp 52 false 512" NOERROR qr,rd,ra 71 0.0002s
func parseQueryLogLine(line string) (domain, rcode string, ok bool) {
	if !strings.Contains(line, "[INFO]") {
		return "", "", false
	}
	start := strings.IndexByte(line, '"')
	end := strings.LastIndexByte(line, '"')
	if start < 0 || end <= start {
		return "", "", false
	}
	// Inside the quotes: QTYPE IN QNAME proto size rd bufsize
	quoted := strings.Fields(line[start+1 : end])
	if len(quoted) < 3 {
		return "", "", false
	}
	domain = strings.TrimSuffix(quoted[2], ".")
	if domain == "" {
		return "", "", false
	}
	// After the quotes: RCODE flags size duration
	rest := strings.Fields(line[end+1:])
	if len(rest) == 0 {
		return "", "", false
	}
	return strings.ToLower(domain), rest[0], true
}

// matchesPattern reports whether a queried name is covered by a rule target.
// CoreDNS zones cover the zone itself and all subdomains; "*." zones cover
// subdomains only. Both arguments must already be lowercase.
func matchesPattern(domain, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(domain, pattern[1:])
	}
	return domain == pattern || strings.HasSuffix(domain, "."+pattern)
}

// resolve looks up A records for domain through the local CoreDNS instance
// (so allow/deny policy applies) and returns the IPv4 answers with TTLs.
func resolve(domain string) []pinEntry {
	cmd := exec.Command("dig", "@"+resolverAddr, "+noall", "+answer", "+time=2", "+tries=1", domain)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var entries []pinEntry
	for _, line := range strings.Split(string(out), "\n") {
		// name TTL IN TYPE RDATA
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[3] != "A" {
			continue
		}
		ip := net.ParseIP(fields[4])
		if ip == nil || ip.To4() == nil {
			continue
		}
		ttl, err := strconv.Atoi(fields[1])
		if err != nil || ttl < 1 {
			ttl = 1
		}
		entries = append(entries, pinEntry{ip: ip.String(), ttl: ttl})
	}
	return entries
}
