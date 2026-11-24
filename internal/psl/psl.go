// Package psl resolves the registrable domain (eTLD+1) for a host.
//
// This matters a great deal here: a DMARC report address such as
// x@reports.example.co.uk must be reduced to example.co.uk before we ask "is
// this domain registered?". Querying the raw sub-domain against RDAP would
// return 404 (sub-domains are not registrations) and produce a false positive.
//
// It wraps golang.org/x/net/publicsuffix, the canonical Public Suffix List
// implementation, which handles wildcard and exception rules and IDNs. Refresh
// the list with `go get -u golang.org/x/net`.
package psl

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RegistrableDomain returns the eTLD+1 for host, or "" when host has no
// registrable part (it is itself a public suffix, an IP, or has no dot).
func RegistrableDomain(host string) string {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if host == "" || !strings.Contains(host, ".") {
		return ""
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return d
}
