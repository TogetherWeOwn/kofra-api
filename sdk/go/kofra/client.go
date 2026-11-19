// Package kofra is the Go client for the Kofra API.
//
//	c, err := kofra.New() // KOFRA_API_TOKEN, KOFRA_API_URL
//	resp, err := c.Buckets.List(ctx, nil)
//
// Every operation lives on a resource (c.Account, c.Buckets, c.Keys, c.Usage,
// c.Events, c.Objects). The models and the raw client are generated from the
// contract into package api; this file is the hand-written core:
// authentication, base URL, retries, idempotency keys and errors.
package kofra

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TogetherWeOwn/kofra-api/sdk/go/kofra/api"
)

// DefaultBaseURL is used when neither WithBaseURL nor KOFRA_API_URL is set.
const DefaultBaseURL = "https://api.kofra.app"

// Version is sent in the User-Agent header.
const Version = "0.1.0"

// Client is one Kofra API client, safe for concurrent use.
type Client struct {
	services

	raw          *api.ClientWithResponses
	baseURL      string
	token        string
	httpClient   api.HttpRequestDoer
	maxRetries   int
	maxRetryWait time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithToken sets the API token. Without it, KOFRA_API_TOKEN is used.
func WithToken(token string) Option { return func(c *Client) { c.token = token } }

// WithBaseURL sets the API address. Without it, KOFRA_API_URL or DefaultBaseURL is used.
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = u } }

// WithHTTPClient sets the HTTP client (or any doer) that sends the requests.
func WithHTTPClient(doer api.HttpRequestDoer) Option {
	return func(c *Client) { c.httpClient = doer }
}

// WithMaxRetries sets how often an answer of 429 or 503, or a network error,
// is retried. The default is 2; 0 turns retries off.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n >= 0 {
			c.maxRetries = n
		}
	}
}

// WithMaxRetryWait caps the wait between two attempts, including a
// Retry-After the server asks for. The default is 30 seconds.
func WithMaxRetryWait(d time.Duration) Option {
	return func(c *Client) {
		if d >= 0 {
			c.maxRetryWait = d
		}
	}
}

// New builds a client. It fails when no token is given and KOFRA_API_TOKEN is empty.
func New(opts ...Option) (*Client, error) {
	c := &Client{maxRetries: 2, maxRetryWait: 30 * time.Second}
	for _, o := range opts {
		o(c)
	}
	if c.token == "" {
		c.token = os.Getenv("KOFRA_API_TOKEN")
	}
	if c.token == "" {
		return nil, errors.New("kofra: no API token; use WithToken or set KOFRA_API_TOKEN")
	}
	if c.baseURL == "" {
		c.baseURL = os.Getenv("KOFRA_API_URL")
	}
	if c.baseURL == "" {
		c.baseURL = DefaultBaseURL
	}
	c.baseURL = strings.TrimRight(c.baseURL, "/")
	if u, err := url.Parse(c.baseURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("kofra: the base URL %q is not an http(s) URL", c.baseURL)
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	raw, err := api.NewClientWithResponses(c.baseURL,
		api.WithHTTPClient(&retryingDoer{next: c.httpClient, maxRetries: c.maxRetries, maxWait: c.maxRetryWait}),
		api.WithRequestEditorFn(c.editRequest),
	)
	if err != nil {
		return nil, err
	}
	c.raw = raw
	c.initServices()
	return c, nil
}

// BaseURL is the API address this client talks to.
func (c *Client) BaseURL() string { return c.baseURL }

// editRequest adds the token, the User-Agent and, on writes, an
// Idempotency-Key unless the caller set one. It runs once per call, before
// any retry, so every attempt carries the same key.
func (c *Client) editRequest(_ context.Context, req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", "kofra-go/"+Version)
	switch req.Method {
	case http.MethodPost, http.MethodPatch, http.MethodDelete:
		if req.Header.Get("Idempotency-Key") == "" {
			key, err := newUUID()
			if err != nil {
				return err
			}
			req.Header.Set("Idempotency-Key", key)
		}
	}
	return nil
}

// Do sends one request to an API path such as "/v1/buckets" and returns the
// raw JSON answer (nil for 204). body is sent as JSON unless it is nil; a
// json.RawMessage or []byte is sent as is. Any non-2xx answer is an *Error.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body any) ([]byte, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("kofra: path %q must start with /", path)
	}
	target := c.baseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		var data []byte
		switch b := body.(type) {
		case json.RawMessage:
			data = b
		case []byte:
			data = b
		default:
			var err error
			if data, err = json.Marshal(body); err != nil {
				return nil, fmt.Errorf("kofra: encoding the body: %w", err)
			}
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.editRequest(ctx, req); err != nil {
		return nil, err
	}
	doer := &retryingDoer{next: c.httpClient, maxRetries: c.maxRetries, maxWait: c.maxRetryWait}
	resp, err := doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if err := checkResponse(resp, data); err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	return data, nil
}

// Error is any non-2xx answer. Branch on Problem.Code; Problem.Hint says what
// to do next and Problem.RequestId is what support asks for.
type Error struct {
	Status  int
	Problem api.Problem
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("kofra: %s (HTTP %d)", e.Problem.Code, e.Status)
	if e.Problem.Detail != "" {
		msg += ": " + e.Problem.Detail
	}
	return msg
}

// checkResponse turns a non-2xx answer into an *Error carrying the RFC 9457
// problem body, or a stand-in problem when the body is not one.
func checkResponse(resp *http.Response, body []byte) error {
	if resp == nil {
		return errors.New("kofra: no response")
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var p api.Problem
	if err := json.Unmarshal(body, &p); err != nil || p.Code == "" {
		p = api.Problem{
			Type:      "about:blank",
			Title:     "HTTP error",
			Status:    resp.StatusCode,
			Code:      fmt.Sprintf("http_%d", resp.StatusCode),
			Detail:    fmt.Sprintf("The API answered HTTP %d without a problem body.", resp.StatusCode),
			Hint:      "Retry later; if it persists, contact support with the Kofra-Request-Id header.",
			DocsUrl:   "https://kofra.app/docs/errors/index.md",
			RequestId: resp.Header.Get("Kofra-Request-Id"),
			Retryable: resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable,
		}
	}
	return &Error{Status: resp.StatusCode, Problem: p}
}

// retryingDoer retries 429, 503 and network errors with the same request
// (and so the same Idempotency-Key), waiting for Retry-After when the server
// gives one, never longer than maxWait.
type retryingDoer struct {
	next       api.HttpRequestDoer
	maxRetries int
	maxWait    time.Duration
}

func (d *retryingDoer) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	for attempt := 0; ; attempt++ {
		try := req
		if attempt > 0 {
			try = req.Clone(ctx)
			if req.Body != nil && req.Body != http.NoBody {
				if req.GetBody == nil {
					return nil, errors.New("kofra: cannot retry a request whose body cannot be replayed")
				}
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				try.Body = body
			}
		}
		resp, err := d.next.Do(try)
		last := attempt >= d.maxRetries
		if err != nil {
			if last || ctx.Err() != nil {
				return nil, err
			}
			if werr := d.wait(ctx, attempt, ""); werr != nil {
				return nil, err
			}
			continue
		}
		if last || (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable) {
			return resp, nil
		}
		retryAfter := resp.Header.Get("Retry-After")
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if err := d.wait(ctx, attempt, retryAfter); err != nil {
			return nil, err
		}
	}
}

func (d *retryingDoer) wait(ctx context.Context, attempt int, retryAfter string) error {
	delay := time.Duration(500*(1<<min(attempt, 10))) * time.Millisecond
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s >= 0 {
		delay = time.Duration(s) * time.Second
	} else if t, err := http.ParseTime(retryAfter); err == nil {
		delay = time.Until(t)
	}
	delay = max(min(delay, d.maxWait), 0)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// newUUID returns a random (version 4) UUID.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
