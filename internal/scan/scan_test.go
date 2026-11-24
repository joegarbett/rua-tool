package scan

import (
	"testing"

	"github.com/joegarbett/rua-tool/internal/dmarc"
	"github.com/joegarbett/rua-tool/internal/domain"
)

// fakeResolver serves canned DMARC TXT records.
type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupTXT(name string) ([]string, error) { return f.txt[name], nil }

// fakeRegistry returns a canned status per registrable domain.
type fakeRegistry struct{ states map[string]domain.State }

func (f fakeRegistry) Check(host string) domain.Status {
	st, ok := f.states[host]
	if !ok {
		st = domain.Registered
	}
	return domain.Status{Domain: host, State: st, Method: "fake", Confidence: "high"}
}

func newScanner(txt map[string][]string, states map[string]domain.State) *Scanner {
	return &Scanner{
		DMARC:    &dmarc.Lookup{Resolver: fakeResolver{txt: txt}},
		Registry: fakeRegistry{states: states},
	}
}

func TestScanUnregisteredReportDomainIsVulnerable(t *testing.T) {
	s := newScanner(
		map[string][]string{"_dmarc.victim.com": {"v=DMARC1; p=reject; rua=mailto:agg@reports.gone.com; ruf=mailto:f@gone.com"}},
		map[string]domain.State{"gone.com": domain.Unregistered},
	)
	res := s.Scan("victim.com", "seed")

	if !res.IsVulnerable() {
		t.Fatalf("expected vulnerable, got findings=%v", res.Findings)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.ReportDomain != "gone.com" {
		t.Errorf("ReportDomain = %q, want gone.com", f.ReportDomain)
	}
	if f.Tag != "rua,ruf" {
		t.Errorf("Tag = %q, want rua,ruf", f.Tag)
	}
	if f.Severity() != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity())
	}
	if len(f.Addresses) != 2 {
		t.Errorf("Addresses = %v, want 2", f.Addresses)
	}
	if f.Source != "seed" {
		t.Errorf("Source = %q, want seed", f.Source)
	}
}

func TestScanSelfHostedReportIsNotFlagged(t *testing.T) {
	// Reports go to the same registrable domain being scanned.
	s := newScanner(
		map[string][]string{"_dmarc.victim.com": {"v=DMARC1; p=reject; rua=mailto:dmarc@victim.com"}},
		map[string]domain.State{"victim.com": domain.Registered},
	)
	res := s.Scan("victim.com", "")
	if res.IsVulnerable() {
		t.Errorf("self-hosted report should not be flagged: %v", res.Findings)
	}
}

func TestScanExpiringSoonIsMediumSeverity(t *testing.T) {
	s := newScanner(
		map[string][]string{"_dmarc.victim.com": {"v=DMARC1; rua=mailto:a@thirdparty.net"}},
		map[string]domain.State{"thirdparty.net": domain.ExpiringSoon},
	)
	res := s.Scan("victim.com", "")
	if len(res.Findings) != 1 || res.Findings[0].Severity() != SeverityMedium {
		t.Fatalf("expected one medium finding, got %+v", res.Findings)
	}
}

func TestScanNoDMARC(t *testing.T) {
	s := newScanner(map[string][]string{}, nil)
	res := s.Scan("victim.com", "")
	if res.HasDMARC() || res.IsVulnerable() {
		t.Errorf("expected no DMARC, got %+v", res)
	}
}

func TestNormaliseDomain(t *testing.T) {
	cases := map[string]string{
		"https://www.Example.com/path": "www.example.com",
		"user@Example.com":             "example.com",
		"Example.com.":                 "example.com",
	}
	for in, want := range cases {
		if got := normaliseDomain(in); got != want {
			t.Errorf("normaliseDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
