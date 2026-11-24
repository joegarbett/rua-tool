// Package scan orchestrates a single-domain scan: read the DMARC record,
// extract the domains its aggregate (rua) and forensic (ruf) reports are sent
// to, and flag any that are unregistered or expiring.
package scan

import (
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/joegarbett/rua-tool/internal/dmarc"
	"github.com/joegarbett/rua-tool/internal/domain"
	"github.com/joegarbett/rua-tool/internal/psl"
)

// Severity levels for a finding.
const (
	SeverityHigh   = "high"   // rua/ruf domain is unregistered
	SeverityMedium = "medium" // rua/ruf domain is expiring soon
)

// Finding is one (scanned domain, vulnerable report-domain) pair worth reporting.
type Finding struct {
	ScannedDomain string        `json:"scannedDomain"` // domain whose DMARC we read
	ReportDomain  string        `json:"reportDomain"`  // registrable domain reports go to
	Addresses     []string      `json:"addresses"`     // the rua/ruf addresses at that domain
	Tag           string        `json:"tag"`           // "rua" | "ruf" | "rua,ruf"
	Status        domain.Status `json:"status"`
	DMARCRaw      string        `json:"dmarcRaw"`
	DiscoveredAt  string        `json:"discoveredAt"`
	Source        string        `json:"source,omitempty"` // e.g. spider seed URL
}

// Severity returns high for unregistered report domains, medium otherwise.
func (f Finding) Severity() string {
	if f.Status.IsVulnerable() {
		return SeverityHigh
	}
	return SeverityMedium
}

// Key is a stable identity so the same issue is not stored twice.
func (f Finding) Key() string { return f.ScannedDomain + "|" + f.ReportDomain }

// CheckedDomain records a report domain that was examined.
type CheckedDomain struct {
	Domain string       `json:"domain"`
	State  domain.State `json:"state"`
}

// Result is the outcome of scanning a single domain.
type Result struct {
	Domain   string          `json:"domain"`
	DMARC    *dmarc.Record   `json:"dmarc"`
	Findings []Finding       `json:"findings"`
	Checked  []CheckedDomain `json:"checked"`
	Note     string          `json:"note,omitempty"`
}

// HasDMARC reports whether a DMARC record was found.
func (r *Result) HasDMARC() bool { return r.DMARC != nil }

// IsVulnerable reports whether any findings were produced.
func (r *Result) IsVulnerable() bool { return len(r.Findings) > 0 }

// Registry resolves a host's registration status. *domain.Checker implements
// it; tests supply fakes.
type Registry interface {
	Check(host string) domain.Status
}

// Scanner ties DMARC lookup and registration checking together.
type Scanner struct {
	DMARC    *dmarc.Lookup
	Registry Registry
}

// NewScanner returns a Scanner with default collaborators.
func NewScanner() *Scanner {
	return &Scanner{DMARC: dmarc.NewLookup(), Registry: domain.NewChecker()}
}

var schemeRe = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.\-]*://`)

// Scan reads the DMARC record for a domain and returns any findings. source is
// optional provenance (e.g. a spider seed URL).
func (s *Scanner) Scan(input, source string) *Result {
	d := normaliseDomain(input)
	record := s.DMARC.Lookup(d)
	if record == nil {
		return &Result{Domain: d, Note: "No DMARC record published."}
	}

	if len(record.ReportAddresses()) == 0 {
		return &Result{Domain: d, DMARC: record, Note: "DMARC record has no rua/ruf reporting addresses."}
	}

	// Group report addresses by the registrable domain that receives them.
	type group struct {
		addresses []string
		tags      map[string]bool
	}
	byDomain := map[string]*group{}
	order := []string{}
	add := func(tag string, addrs []string) {
		for _, addr := range addrs {
			host := addr[strings.IndexByte(addr, '@')+1:]
			rd := psl.RegistrableDomain(host)
			if rd == "" {
				rd = host
			}
			g, ok := byDomain[rd]
			if !ok {
				g = &group{tags: map[string]bool{}}
				byDomain[rd] = g
				order = append(order, rd)
			}
			g.addresses = append(g.addresses, addr)
			g.tags[tag] = true
		}
	}
	add("rua", record.RUA)
	add("ruf", record.RUF)

	self := psl.RegistrableDomain(d)
	now := time.Now().UTC().Format(time.RFC3339)

	res := &Result{Domain: d, DMARC: record}
	for _, rd := range order {
		g := byDomain[rd]
		status := s.Registry.Check(rd)
		res.Checked = append(res.Checked, CheckedDomain{Domain: rd, State: status.State})

		// A domain reporting only to itself cannot be taken over separately.
		if rd == self {
			continue
		}
		if status.IsVulnerable() || status.IsWarning() {
			res.Findings = append(res.Findings, Finding{
				ScannedDomain: d,
				ReportDomain:  rd,
				Addresses:     uniqueStrings(g.addresses),
				Tag:           joinTags(g.tags),
				Status:        status,
				DMARCRaw:      record.Raw,
				DiscoveredAt:  now,
				Source:        source,
			})
		}
	}
	return res
}

func normaliseDomain(input string) string {
	input = strings.TrimSpace(input)
	if i := strings.IndexByte(input, '@'); i >= 0 {
		input = input[i+1:]
	}
	if schemeRe.MatchString(input) {
		if u, err := url.Parse(input); err == nil {
			input = u.Hostname()
		}
	}
	return strings.ToLower(strings.Trim(input, "."))
}

func joinTags(tags map[string]bool) string {
	var parts []string
	for _, t := range []string{"rua", "ruf"} {
		if tags[t] {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, ",")
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
