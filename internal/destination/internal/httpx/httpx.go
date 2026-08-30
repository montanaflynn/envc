// Package httpx is the small HTTP client shared by the API-backed destinations:
// one *http.Client with a timeout, context-aware requests, and a single retry
// that honors Retry-After. 429 is retried for every method; 5xx and network
// errors only for idempotent ones (GET, HEAD, PUT, DELETE), since a POST that
// failed after creating would 409 on the retry and abort a sync midway. It
// never logs anything, so tokens in headers cannot leak through it.
package httpx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Client wraps an *http.Client with retry policy.
type Client struct {
	HTTP *http.Client
	// Backoff is the wait before the retry when the response has no usable
	// Retry-After header.
	Backoff time.Duration
	// MaxRetryAfter caps how long a Retry-After header may make us wait.
	MaxRetryAfter time.Duration
}

// New returns a client with a 30s timeout.
func New() *Client {
	return &Client{
		HTTP:          &http.Client{Timeout: 30 * time.Second},
		Backoff:       time.Second,
		MaxRetryAfter: 60 * time.Second,
	}
}

// Request is one HTTP call. Body may be nil.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// Response is the fully-read result of a Request.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Do performs the request, retrying once on 429 (any method) or on a 5xx /
// network error (idempotent methods only). Non-2xx statuses are not errors;
// callers interpret them.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	var last *Response
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := c.once(ctx, req)
		if err != nil {
			if attempt == 1 || !idempotent(req.Method) || ctx.Err() != nil {
				return nil, err
			}
			if err := sleep(ctx, c.Backoff); err != nil {
				return nil, err
			}
			continue
		}
		last = resp
		if !retryable(req.Method, resp.StatusCode) {
			return resp, nil
		}
		if attempt == 1 {
			break
		}
		wait := retryAfter(resp.Header.Get("Retry-After"), time.Now())
		if wait == 0 {
			wait = c.Backoff
		}
		if c.MaxRetryAfter > 0 && wait > c.MaxRetryAfter {
			wait = c.MaxRetryAfter
		}
		if err := sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
	return last, nil
}

func (c *Client) once(ctx context.Context, req Request) (*Response, error) {
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	hr, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		hr.Header.Set(k, v)
	}
	if req.Body != nil && hr.Header.Get("Content-Type") == "" {
		hr.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("%s %s: reading response: %w", req.Method, req.URL, err)
	}
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: data}, nil
}

// retryable reports whether a response may be retried: rate limits always,
// server errors only when repeating the request cannot double its effect.
func retryable(method string, status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	return status >= 500 && idempotent(method)
}

// idempotent reports whether method is safe to repeat (RFC 9110 §9.2.2).
func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}

// retryAfter parses a Retry-After header (seconds or HTTP-date). Unparseable
// or past values yield 0.
func retryAfter(h string, now time.Time) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		d := t.Sub(now)
		if d < 0 {
			return 0
		}
		return d.Round(time.Second)
	}
	return 0
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
