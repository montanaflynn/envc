package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoRetries(t *testing.T) {
	tests := []struct {
		name       string
		method     string // default POST
		statuses   []int  // status per attempt
		retryAfter string
		wantStatus int
		wantCalls  int32
	}{
		{name: "ok first try", statuses: []int{200}, wantStatus: 200, wantCalls: 1},
		{name: "GET retries once on 500", method: http.MethodGet, statuses: []int{500, 200}, wantStatus: 200, wantCalls: 2},
		{name: "PUT retries once on 502", method: http.MethodPut, statuses: []int{502, 200}, wantStatus: 200, wantCalls: 2},
		{name: "DELETE retries once on 503", method: http.MethodDelete, statuses: []int{503, 200}, wantStatus: 200, wantCalls: 2},
		{name: "HEAD retries once on 500", method: http.MethodHead, statuses: []int{500, 200}, wantStatus: 200, wantCalls: 2},
		{name: "POST is not retried on 500", statuses: []int{500, 200}, wantStatus: 500, wantCalls: 1},
		{name: "PATCH is not retried on 500", method: http.MethodPatch, statuses: []int{500, 200}, wantStatus: 500, wantCalls: 1},
		{name: "POST retries once on 429 with Retry-After", statuses: []int{429, 201}, retryAfter: "0", wantStatus: 201, wantCalls: 2},
		{name: "GET retries once on 429", method: http.MethodGet, statuses: []int{429, 200}, wantStatus: 200, wantCalls: 2},
		{name: "gives up after second failure", method: http.MethodGet, statuses: []int{503, 503, 200}, wantStatus: 503, wantCalls: 2},
		{name: "no retry on 4xx", method: http.MethodGet, statuses: []int{404, 200}, wantStatus: 404, wantCalls: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := atomic.AddInt32(&calls, 1)
				body, _ := readAll(r)
				if string(body) != "payload" {
					t.Errorf("attempt %d body = %q, want payload", n, body)
				}
				if r.Header.Get("X-Test") != "yes" {
					t.Errorf("attempt %d missing header", n)
				}
				st := tc.statuses[n-1]
				if tc.retryAfter != "" && st == 429 {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(st)
				w.Write([]byte("resp"))
			}))
			defer srv.Close()

			method := tc.method
			if method == "" {
				method = http.MethodPost
			}
			c := New()
			c.Backoff = time.Millisecond
			resp, err := c.Do(context.Background(), Request{
				Method:  method,
				URL:     srv.URL + "/x",
				Headers: map[string]string{"X-Test": "yes"},
				Body:    []byte("payload"),
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if method != http.MethodHead && string(resp.Body) != "resp" {
				t.Fatalf("body = %q", resp.Body)
			}
			if calls != tc.wantCalls {
				t.Fatalf("calls = %d, want %d", calls, tc.wantCalls)
			}
		})
	}
}

// A dropped connection is retried for idempotent methods only.
func TestDoRetriesNetworkErrorForIdempotentMethods(t *testing.T) {
	for _, tc := range []struct {
		method    string
		wantErr   bool
		wantCalls int32
	}{
		{http.MethodGet, false, 2},
		{http.MethodPut, false, 2},
		{http.MethodPost, true, 1},
	} {
		t.Run(tc.method, func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if atomic.AddInt32(&calls, 1) == 1 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Fatal(err)
					}
					conn.Close() // client sees EOF, no response
					return
				}
				w.WriteHeader(200)
			}))
			defer srv.Close()
			c := New()
			c.Backoff = time.Millisecond
			resp, err := c.Do(context.Background(), Request{Method: tc.method, URL: srv.URL, Body: []byte("b")})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %d", resp.StatusCode)
				}
			} else if err != nil || resp.StatusCode != 200 {
				t.Fatalf("Do: %v / %v", err, resp)
			}
			if got := atomic.LoadInt32(&calls); got != tc.wantCalls {
				t.Fatalf("calls = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}

func TestDoHonorsContextDuringBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c := New()
	start := time.Now()
	_, err := c.Do(ctx, Request{Method: http.MethodGet, URL: srv.URL})
	if err == nil {
		t.Fatal("expected context error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("did not honor context during Retry-After sleep")
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"5", 5 * time.Second},
		{"garbage", 0},
		{now.Add(7 * time.Second).Format(http.TimeFormat), 7 * time.Second},
		{now.Add(-7 * time.Second).Format(http.TimeFormat), 0},
	}
	for _, tc := range tests {
		if got := retryAfter(tc.in, now); got != tc.want {
			t.Errorf("retryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func readAll(r *http.Request) ([]byte, error) {
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := r.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return []byte(sb.String()), nil
}
