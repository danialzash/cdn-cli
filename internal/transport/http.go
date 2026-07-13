package transport

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/vergecloud/cdn-cli/internal/version"
)

const (
	DefaultTimeout = 30 * time.Second
	MaxRetries     = 3
	RetryBackoff   = 500 * time.Millisecond
)

type Options struct {
	Timeout   time.Duration
	UserAgent string
	Verbose   bool
}

func NewHTTPClient(opts Options) *http.Client {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.UserAgent == "" {
		opts.UserAgent = version.UserAgent
	}

	transport := &retryTransport{
		base:      http.DefaultTransport,
		maxRetry:  MaxRetries,
		backoff:   RetryBackoff,
		userAgent: opts.UserAgent,
		verbose:   opts.Verbose,
	}

	return &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
	}
}

type retryTransport struct {
	base      http.RoundTripper
	maxRetry  int
	backoff   time.Duration
	userAgent string
	verbose   bool
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.userAgent)
	}

	var resp *http.Response
	var err error

	for attempt := 0; attempt <= t.maxRetry; attempt++ {
		if t.verbose {
			log.Printf("request: %s %s", req.Method, req.URL)
		}

		resp, err = t.base.RoundTrip(req)
		if err != nil {
			if attempt < t.maxRetry {
				time.Sleep(t.backoff * time.Duration(attempt+1))
				continue
			}
			return nil, fmt.Errorf("request failed: %w", err)
		}

		if resp.StatusCode < 500 || attempt == t.maxRetry {
			return resp, nil
		}

		if t.verbose {
			log.Printf("retrying after status %d (attempt %d/%d)", resp.StatusCode, attempt+1, t.maxRetry)
		}
		drainBody(resp.Body)
		resp.Body.Close()
		time.Sleep(t.backoff * time.Duration(attempt+1))
	}

	return resp, err
}

func drainBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
}
