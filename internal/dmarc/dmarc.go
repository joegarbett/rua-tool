// Package dmarc fetches and parses the DMARC record published at
// _dmarc.<domain> (RFC 7489).
package dmarc

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Record is a parsed DMARC record.
type Record struct {
	Domain string            `json:"domain"`
	Raw    string            `json:"raw"`
	Tags   map[string]string `json:"tags"`
	RUA    []string          `json:"rua"` // aggregate report mailto addresses
	RUF    []string          `json:"ruf"` // forensic report mailto addresses
}

// Policy returns the p= tag, defaulting to "none".
func (r *Record) Policy() string {
	if p, ok := r.Tags["p"]; ok {
		return p
	}
	return "none"
}

// ReportAddresses returns the distinct rua and ruf e-mail addresses.
func (r *Record) ReportAddresses() []string {
	return uniqueStrings(append(append([]string{}, r.RUA...), r.RUF...))
}

// Resolver abstracts DNS TXT lookups so they can be mocked in tests.
type Resolver interface {
	LookupTXT(name string) ([]string, error)
}

type netResolver struct{}

func (netResolver) LookupTXT(name string) ([]string, error) { return net.LookupTXT(name) }

// Lookup reads and parses the DMARC record for a domain.
type Lookup struct {
	Resolver Resolver
}

// NewLookup returns a Lookup backed by the system resolver.
func NewLookup() *Lookup { return &Lookup{Resolver: netResolver{}} }

var dmarcVersion = regexp.MustCompile(`(?i)^\s*v\s*=\s*DMARC1\s*;`)

// Lookup returns the DMARC record for domain, or nil when none is published.
func (l *Lookup) Lookup(domain string) *Record {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	txts, err := l.Resolver.LookupTXT("_dmarc." + domain)
	if err != nil {
		return nil
	}
	for _, txt := range txts {
		// A DMARC record must begin with v=DMARC1; other TXT records at the
		// same name are ignored (RFC 7489 §6.6.3).
		if !dmarcVersion.MatchString(txt) {
			continue
		}
		return Parse(domain, txt)
	}
	return nil
}

var sizeLimitSuffix = regexp.MustCompile(`!\S*$`)

// Parse turns a raw DMARC TXT string into a Record.
func Parse(domain, raw string) *Record {
	raw = strings.TrimSpace(raw)
	tags := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}

	return &Record{
		Domain: domain,
		Raw:    raw,
		Tags:   tags,
		RUA:    extractMailtos(tags["rua"]),
		RUF:    extractMailtos(tags["ruf"]),
	}
}

// extractMailtos pulls mailto addresses out of a rua/ruf value, which is a
// comma-separated list of DMARC URIs, dropping the optional "!<size>" limit.
func extractMailtos(value string) []string {
	if value == "" {
		return nil
	}
	var out []string
	for _, uri := range strings.Split(value, ",") {
		uri = strings.TrimSpace(uri)
		if !strings.HasPrefix(strings.ToLower(uri), "mailto:") {
			continue
		}
		addr := strings.TrimSpace(uri[len("mailto:"):])
		addr = strings.TrimSpace(sizeLimitSuffix.ReplaceAllString(addr, ""))
		if dec, err := url.QueryUnescape(addr); err == nil {
			addr = dec
		}
		if strings.Contains(addr, "@") {
			out = append(out, strings.ToLower(addr))
		}
	}
	return uniqueStrings(out)
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
