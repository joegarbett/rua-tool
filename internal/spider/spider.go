// Package spider is a bounded breadth-first crawler.
//
// It follows links within the seed's own registrable domain (so a crawl stays
// bounded) while harvesting every domain referenced anywhere on the visited
// pages — links, images, scripts, iframes, and e-mail addresses. Those
// harvested domains become the candidate set the scanner checks for expired
// DMARC report addresses.
package spider

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/joegarbett/rua-tool/internal/fetch"
	"github.com/joegarbett/rua-tool/internal/psl"

	"golang.org/x/net/html"
)

// Options configures a crawl. Zero (or negative) MaxPages / MaxDepth mean
// unlimited.
type Options struct {
	MaxPages int
	MaxDepth int
	Delay    time.Duration
	OnPage   func(url string) // optional progress callback
}

// Result summarises a crawl.
type Result struct {
	Domains      []string `json:"domains"`
	PagesCrawled int      `json:"pagesCrawled"`
	SeedDomain   string   `json:"seedDomain"`
}

// Spider performs a crawl.
type Spider struct {
	HTTP *fetch.Client
	Opts Options
}

// New returns a Spider with the given options and a default HTTP client.
func New(opts Options) *Spider {
	if opts.OnPage == nil {
		opts.OnPage = func(string) {}
	}
	return &Spider{HTTP: fetch.New(), Opts: opts}
}

type queued struct {
	url   string
	depth int
}

// Crawl walks from seedURL and returns the harvested registrable domains.
func (s *Spider) Crawl(seedURL string) Result {
	maxPages := s.Opts.MaxPages
	if maxPages <= 0 {
		maxPages = int(^uint(0) >> 1) // max int
	}
	maxDepth := s.Opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = int(^uint(0) >> 1)
	}

	seedURL = normaliseURL(seedURL)
	seedHost := hostOf(seedURL)
	seedDomain := psl.RegistrableDomain(seedHost)

	visited := map[string]bool{}
	domains := map[string]bool{}
	queue := []queued{{url: seedURL, depth: 0}}

	for len(queue) > 0 && len(visited) < maxPages {
		item := queue[0]
		queue = queue[1:]
		if visited[item.url] {
			continue
		}
		visited[item.url] = true
		s.Opts.OnPage(item.url)

		resp := s.HTTP.Get(item.url, map[string]string{"Accept": "text/html,application/xhtml+xml"})
		s.sleep()
		if resp.Err != nil || resp.Status < 200 || resp.Status >= 400 {
			continue
		}
		if !strings.Contains(strings.ToLower(resp.ContentType), "html") {
			continue
		}

		pages, refDomains := extractLinks(string(resp.Body), resp.URL)
		for _, d := range refDomains {
			domains[d] = true
		}

		if item.depth < maxDepth {
			for _, p := range pages {
				if psl.RegistrableDomain(hostOf(p)) == seedDomain && !visited[p] {
					queue = append(queue, queued{url: p, depth: item.depth + 1})
				}
			}
		}
	}

	out := make([]string, 0, len(domains))
	for d := range domains {
		out = append(out, d)
	}
	sort.Strings(out)

	return Result{Domains: out, PagesCrawled: len(visited), SeedDomain: seedDomain}
}

var emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})`)

// extractLinks returns same-document page URLs (http/https anchors) and all
// referenced registrable domains.
func extractLinks(htmlBody, baseURL string) (pages, domains []string) {
	base, err := url.Parse(baseURL)
	if err != nil {
		base = nil
	}

	domainSet := map[string]bool{}
	pageSet := map[string]bool{}
	addDomain := func(host string) {
		host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
		if host == "" {
			return
		}
		if rd := psl.RegistrableDomain(host); rd != "" {
			domainSet[rd] = true
		}
	}

	attrs := map[string]string{"a": "href", "link": "href", "script": "src", "img": "src", "iframe": "src"}

	tok := html.NewTokenizer(strings.NewReader(htmlBody))
	for {
		tt := tok.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		t := tok.Token()
		attr, ok := attrs[t.Data]
		if !ok {
			continue
		}
		var value string
		for _, a := range t.Attr {
			if a.Key == attr {
				value = strings.TrimSpace(a.Val)
				break
			}
		}
		if value == "" {
			continue
		}

		if strings.HasPrefix(strings.ToLower(value), "mailto:") {
			addr := value[len("mailto:"):]
			if i := strings.IndexByte(addr, '@'); i >= 0 {
				addDomain(addr[i+1:])
			}
			continue
		}

		abs := resolveURL(value, base)
		if abs == "" {
			continue
		}
		addDomain(hostOf(abs))
		if t.Data == "a" && strings.HasPrefix(strings.ToLower(abs), "http") {
			pageSet[stripFragment(abs)] = true
		}
	}

	// Harvest bare e-mail addresses in page text.
	for _, m := range emailRe.FindAllStringSubmatch(stripTags(htmlBody), -1) {
		addDomain(m[1])
	}

	for p := range pageSet {
		pages = append(pages, p)
	}
	for d := range domainSet {
		domains = append(domains, d)
	}
	return pages, domains
}

func resolveURL(href string, base *url.URL) string {
	if m := regexp.MustCompile(`(?i)^(javascript|tel|data):`).MatchString(href); m {
		return ""
	}
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	if u.IsAbs() {
		if u.Scheme == "http" || u.Scheme == "https" {
			return u.String()
		}
		return ""
	}
	if base == nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func normaliseURL(u string) string {
	if !regexp.MustCompile(`(?i)^https?://`).MatchString(u) {
		return "https://" + u
	}
	return u
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func stripFragment(u string) string {
	if i := strings.IndexByte(u, '#'); i >= 0 {
		return u[:i]
	}
	return u
}

var tagRe = regexp.MustCompile(`(?s)<[^>]*>`)

func stripTags(s string) string { return tagRe.ReplaceAllString(s, " ") }

func (s *Spider) sleep() {
	if s.Opts.Delay > 0 {
		time.Sleep(s.Opts.Delay)
	}
}
