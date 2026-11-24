package dmarc

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	raw := "v=DMARC1; p=reject; rua=mailto:agg@x.com,mailto:a2@y.net!10m; ruf=mailto:f@x.com"
	r := Parse("victim.com", raw)

	if r.Policy() != "reject" {
		t.Errorf("Policy = %q, want reject", r.Policy())
	}
	wantRUA := []string{"a2@y.net", "agg@x.com"} // sorted, !10m stripped
	if !reflect.DeepEqual(r.RUA, wantRUA) {
		t.Errorf("RUA = %v, want %v", r.RUA, wantRUA)
	}
	if !reflect.DeepEqual(r.RUF, []string{"f@x.com"}) {
		t.Errorf("RUF = %v, want [f@x.com]", r.RUF)
	}
}

func TestParsePercentEncoded(t *testing.T) {
	// RFC 7489 allows percent-encoding in URIs; a literal comma in a local part
	// would be encoded, but the common case is encoded "!" or spaces.
	r := Parse("victim.com", "v=DMARC1; rua=mailto:re%70orts@x.com")
	if len(r.RUA) != 1 || r.RUA[0] != "reports@x.com" {
		t.Errorf("RUA = %v, want [reports@x.com]", r.RUA)
	}
}

type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupTXT(name string) ([]string, error) { return f.txt[name], nil }

func TestLookupPicksDMARCRecord(t *testing.T) {
	l := &Lookup{Resolver: fakeResolver{txt: map[string][]string{
		"_dmarc.victim.com": {
			"some other txt record",
			"v=DMARC1; p=none; rua=mailto:r@x.com",
		},
	}}}
	r := l.Lookup("victim.com")
	if r == nil {
		t.Fatal("expected a record")
	}
	if r.Policy() != "none" || len(r.RUA) != 1 {
		t.Errorf("unexpected record: %+v", r)
	}
}

func TestLookupNoRecord(t *testing.T) {
	l := &Lookup{Resolver: fakeResolver{txt: map[string][]string{}}}
	if r := l.Lookup("nodmarc.com"); r != nil {
		t.Errorf("expected nil, got %+v", r)
	}
}
