// Package domain decides whether a domain is registered, available, or about to
// expire.
//
// The primary signal is RDAP (the structured successor to WHOIS) via the
// rdap.org bootstrap router, which redirects to the authoritative registry:
//
//	HTTP 200 -> registered (expiry parsed from the "expiration" event)
//	HTTP 404 -> not registered = available to an attacker = vulnerable
//
// When RDAP is inconclusive (rate limited, a TLD without RDAP) we fall back to a
// lower-confidence DNS check: a registrable domain that resolves to no NS
// records (NXDOMAIN) is very likely unregistered.
package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/joegarbett/rua-tool/internal/fetch"
	"github.com/joegarbett/rua-tool/internal/psl"

	"golang.org/x/net/idna"
)

// State describes a domain's registration posture.
type State string

const (
	Registered   State = "registered"
	Unregistered State = "unregistered"  // available to register — the vulnerable case
	ExpiringSoon State = "expiring_soon" // registered but expiry is imminent
	Unknown      State = "unknown"       // could not determine
)

const defaultExpirySoonDays = 45

// Status is the result of checking one domain.
type Status struct {
	Domain          string `json:"domain"`
	State           State  `json:"state"`
	Method          string `json:"method"` // rdap | dns
	ExpiresAt       string `json:"expiresAt,omitempty"`
	DaysUntilExpiry *int   `json:"daysUntilExpiry,omitempty"`
	Confidence      string `json:"confidence"`
	Detail          string `json:"detail,omitempty"`
}

// IsVulnerable reports whether an attacker could plausibly register this domain
// and receive reports.
func (s Status) IsVulnerable() bool { return s.State == Unregistered }

// IsWarning reports whether the domain is registered but at risk of lapsing.
func (s Status) IsWarning() bool { return s.State == ExpiringSoon }

// NSLookuper abstracts NS lookups so they can be mocked in tests.
type NSLookuper interface {
	LookupNS(name string) ([]*net.NS, error)
}

type netNS struct{}

func (netNS) LookupNS(name string) ([]*net.NS, error) { return net.LookupNS(name) }

// Checker resolves registration status, caching results per registrable domain
// so a spider run does not re-query shared report domains.
type Checker struct {
	HTTP           *fetch.Client
	NS             NSLookuper
	ExpirySoonDays int
	mu             sync.Mutex
	cache          map[string]Status
}

// NewChecker returns a Checker with defaults.
func NewChecker() *Checker {
	return &Checker{
		HTTP:           fetch.New(),
		NS:             netNS{},
		ExpirySoonDays: defaultExpirySoonDays,
		cache:          map[string]Status{},
	}
}

// Check returns the registration status of host, reduced to its registrable
// domain.
func (c *Checker) Check(host string) Status {
	registrable := psl.RegistrableDomain(host)
	if registrable == "" {
		registrable = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	}
	if ascii, err := idna.Lookup.ToASCII(registrable); err == nil && ascii != "" {
		registrable = ascii
	}

	c.mu.Lock()
	if s, ok := c.cache[registrable]; ok {
		c.mu.Unlock()
		return s
	}
	c.mu.Unlock()

	status, ok := c.viaRDAP(registrable)
	if !ok {
		status = c.viaDNS(registrable)
	}

	c.mu.Lock()
	c.cache[registrable] = status
	c.mu.Unlock()
	return status
}

type rdapResponse struct {
	Events []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Status []string `json:"status"`
}

// viaRDAP returns (status, true) when RDAP gives a definitive answer, or
// (_, false) when the caller should fall back to DNS.
func (c *Checker) viaRDAP(domain string) (Status, bool) {
	resp := c.HTTP.Get("https://rdap.org/domain/"+url.PathEscape(domain),
		map[string]string{"Accept": "application/rdap+json"})

	switch {
	case resp.Err != nil:
		return Status{}, false
	case resp.Status == 404:
		return Status{
			Domain:     domain,
			State:      Unregistered,
			Method:     "rdap",
			Confidence: "high",
			Detail:     "RDAP returned 404 (no registration on file).",
		}, true
	case resp.Status == 200:
		return c.parseRDAP(domain, resp.Body), true
	default:
		// 429/403/5xx — inconclusive.
		return Status{}, false
	}
}

func (c *Checker) parseRDAP(domain string, body []byte) Status {
	var data rdapResponse
	_ = json.Unmarshal(body, &data)

	var expiresAt string
	var days *int
	for _, e := range data.Events {
		if strings.EqualFold(e.EventAction, "expiration") && e.EventDate != "" {
			if t, err := time.Parse(time.RFC3339, e.EventDate); err == nil {
				expiresAt = t.UTC().Format(time.RFC3339)
				d := int(time.Until(t).Hours() / 24)
				days = &d
			}
		}
	}

	state := Registered
	detail := "RDAP returned an active registration."

	var releasing []string
	for _, s := range data.Status {
		switch strings.ToLower(s) {
		case "pending delete", "pendingdelete", "redemption period":
			releasing = append(releasing, s)
		}
	}

	switch {
	case len(releasing) > 0:
		state = ExpiringSoon
		detail = "Registry status: " + strings.Join(data.Status, ", ") + " — domain is being released."
	case days != nil && *days <= c.expirySoonDays():
		state = ExpiringSoon
		detail = fmt.Sprintf("Registration expires in %d day(s).", *days)
	}

	return Status{
		Domain:          domain,
		State:           state,
		Method:          "rdap",
		ExpiresAt:       expiresAt,
		DaysUntilExpiry: days,
		Confidence:      "high",
		Detail:          detail,
	}
}

func (c *Checker) viaDNS(domain string) Status {
	ns, err := c.NS.LookupNS(domain)
	notFound := false
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			notFound = dnsErr.IsNotFound
		}
	}

	if len(ns) == 0 && notFound {
		return Status{
			Domain:     domain,
			State:      Unregistered,
			Method:     "dns",
			Confidence: "medium",
			Detail:     "RDAP inconclusive; domain does not resolve (NXDOMAIN) — likely unregistered. Verify by WHOIS before disclosure.",
		}
	}

	return Status{
		Domain:     domain,
		State:      Unknown,
		Method:     "dns",
		Confidence: "low",
		Detail:     "RDAP inconclusive; domain still has DNS delegation, so it appears registered.",
	}
}

func (c *Checker) expirySoonDays() int {
	if c.ExpirySoonDays > 0 {
		return c.ExpirySoonDays
	}
	return defaultExpirySoonDays
}
