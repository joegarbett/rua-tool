// Package fetch is a thin HTTP client with sane defaults for polite, bounded
// requests (timeout, descriptive User-Agent, response size cap).
package fetch

import (
	"io"
	"net/http"
	"time"
)

const (
	defaultUserAgent = "rua-tool/1.0 (+https://github.com/garbott/rua-tool; DMARC hygiene research)"
	defaultTimeout   = 15 * time.Second
	defaultMaxBytes  = 2 << 20 // 2 MiB
)

// Response is the outcome of a GET.
type Response struct {
	Status      int
	Body        []byte
	URL         string // final URL after redirects
	ContentType string
	Err         error
}

// Client performs bounded GET requests.
type Client struct {
	hc        *http.Client
	userAgent string
	maxBytes  int64
}

// New returns a Client with default timeout, User-Agent and size cap.
func New() *Client {
	return &Client{
		hc:        &http.Client{Timeout: defaultTimeout},
		userAgent: defaultUserAgent,
		maxBytes:  defaultMaxBytes,
	}
}

// Get fetches url, following redirects, and reads at most maxBytes of the body.
func (c *Client) Get(url string, headers map[string]string) Response {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Response{URL: url, Err: err}
	}
	req.Header.Set("User-Agent", c.userAgent)
	// Do NOT set Accept-Encoding: when it is left unset, net/http transparently
	// requests gzip and decompresses the response. Setting it ourselves would
	// disable that and hand callers compressed bytes.
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return Response{URL: url, Err: err}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes))
	finalURL := url
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	return Response{
		Status:      resp.StatusCode,
		Body:        body,
		URL:         finalURL,
		ContentType: resp.Header.Get("Content-Type"),
	}
}
