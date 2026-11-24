package report

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/joegarbett/rua-tool/internal/fetch"
)

// Contact holds discovered disclosure contacts for a domain.
type Contact struct {
	Contacts    []string `json:"contacts"`
	Sources     []string `json:"sources"`
	SecurityTxt string   `json:"securityTxt,omitempty"`
}

// ContactFinder does best-effort discovery of a responsible-disclosure contact,
// preferring (1) /.well-known/security.txt, then (2) RDAP e-mails, then
// (3) conventional role accounts (RFC 2142).
type ContactFinder struct {
	HTTP *fetch.Client
}

// NewContactFinder returns a ContactFinder with a default HTTP client.
func NewContactFinder() *ContactFinder { return &ContactFinder{HTTP: fetch.New()} }

var emailRe = regexp.MustCompile(`(?i)^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Find returns disclosure contacts for domain.
func (cf *ContactFinder) Find(domain string) Contact {
	var contacts, sources []string
	var securityTxt string

	for _, u := range []string{
		"https://" + domain + "/.well-known/security.txt",
		"https://" + domain + "/security.txt",
	} {
		resp := cf.HTTP.Get(u, map[string]string{"Accept": "text/plain"})
		if resp.Err == nil && resp.Status == 200 && strings.Contains(strings.ToLower(resp.ContentType), "text/plain") {
			securityTxt = string(resp.Body)
			for _, c := range parseSecurityTxt(securityTxt) {
				contacts = append(contacts, c)
				sources = append(sources, "security.txt")
			}
			break
		}
	}

	for _, email := range cf.rdapEmails(domain) {
		contacts = append(contacts, email)
		sources = append(sources, "rdap")
	}

	for _, role := range []string{"security", "postmaster", "hostmaster", "abuse", "webmaster"} {
		contacts = append(contacts, role+"@"+domain)
		sources = append(sources, "role-account")
	}

	// De-dupe while keeping discovery order (best sources first).
	seen := map[string]bool{}
	var oc []string
	var os []string
	for i, c := range contacts {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		oc = append(oc, c)
		os = append(os, sources[i])
	}

	return Contact{Contacts: oc, Sources: uniqueStrings(os), SecurityTxt: securityTxt}
}

func parseSecurityTxt(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "contact:") {
			continue
		}
		value := strings.TrimSpace(line[len("contact:"):])
		switch {
		case strings.HasPrefix(strings.ToLower(value), "mailto:"):
			out = append(out, value[len("mailto:"):])
		case emailRe.MatchString(value):
			out = append(out, value)
		case regexp.MustCompile(`(?i)^https?://`).MatchString(value):
			out = append(out, value) // contact URL recorded verbatim
		}
	}
	return out
}

func (cf *ContactFinder) rdapEmails(domain string) []string {
	resp := cf.HTTP.Get("https://rdap.org/domain/"+domain, map[string]string{"Accept": "application/rdap+json"})
	if resp.Err != nil || resp.Status != 200 {
		return nil
	}
	var raw any
	if err := json.Unmarshal(resp.Body, &raw); err != nil {
		return nil
	}
	var emails []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if emailRe.MatchString(t) {
				emails = append(emails, t)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(raw)
	return uniqueStrings(emails)
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
	return out
}
