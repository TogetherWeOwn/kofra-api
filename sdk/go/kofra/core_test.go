package kofra_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TogetherWeOwn/kofra-api/sdk/go/kofra"
	"github.com/TogetherWeOwn/kofra-api/sdk/go/kofra/api"
)

// answer is one scripted reply: a status with body and headers, or an error.
type answer struct {
	status  int
	body    string
	headers map[string]string
	err     error
}

// script answers requests from a list, without a network.
type script struct {
	mu       sync.Mutex
	answers  []answer
	requests []*http.Request
}

func (s *script) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	if len(s.answers) == 0 {
		return nil, errors.New("no scripted answer left")
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	if a.err != nil {
		return nil, a.err
	}
	h := http.Header{}
	for k, v := range a.headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: a.status, Header: h, Body: io.NopCloser(strings.NewReader(a.body)), Request: req}, nil
}

const bucketJSON = `{"name":"backups","created_at":"2026-11-02T08:00:00Z","stored_bytes":1,"object_count":1}`
const listJSON = `{"data":[],"next_cursor":null}`
const busy409 = `{"type":"about:blank","title":"Same request is still running","status":409,"code":"idempotency_key_in_use","detail":"In progress.","hint":"Wait, then retry with the same key.","docs_url":"https://kofra.app/docs/errors/idempotency_key_in_use.md","request_id":"req_1","retryable":true}`

func scripted(t *testing.T, s *script, opts ...kofra.Option) *kofra.Client {
	t.Helper()
	all := []kofra.Option{
		kofra.WithToken("kofra_tok_test_1"),
		kofra.WithBaseURL("https://api.example.test"),
		kofra.WithHTTPClient(&http.Client{Transport: s}),
		kofra.WithMaxRetryWait(5 * time.Second),
	}
	c, err := kofra.New(append(all, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func json201(body string) answer {
	return answer{status: 201, body: body, headers: map[string]string{"Content-Type": "application/json"}}
}

func TestA409IdempotencyKeyInUseIsRetriedWithTheSameKey(t *testing.T) {
	s := &script{answers: []answer{
		{status: 409, body: busy409, headers: map[string]string{"Content-Type": "application/problem+json", "Retry-After": "0"}},
		json201(bucketJSON),
	}}
	resp, err := scripted(t, s).Buckets.Create(context.Background(), nil, api.BucketCreate{Name: "backups"})
	if err != nil || resp.JSON201 == nil {
		t.Fatalf("err %v", err)
	}
	if len(s.requests) != 2 || s.requests[0].Header.Get("Idempotency-Key") != s.requests[1].Header.Get("Idempotency-Key") {
		t.Fatalf("%d attempts, keys differ or missing", len(s.requests))
	}
}

func TestOther409sAreNotRetried(t *testing.T) {
	s := &script{answers: []answer{{status: 409, body: strings.Replace(busy409, "idempotency_key_in_use", "bucket_already_exists", 1)}}}
	_, err := scripted(t, s).Buckets.Create(context.Background(), nil, api.BucketCreate{Name: "backups"})
	var kerr *kofra.Error
	if !errors.As(err, &kerr) || kerr.Problem.Code != "bucket_already_exists" || len(s.requests) != 1 {
		t.Fatalf("err %v after %d attempts", err, len(s.requests))
	}
}

func TestARetryAfterBeyondTheMaxWaitStopsRetrying(t *testing.T) {
	for _, after := range []string{"120", "Wed, 21 Oct 2099 07:28:00 GMT"} {
		s := &script{answers: []answer{{status: 429, headers: map[string]string{"Retry-After": after}}, {status: 200, body: listJSON}}}
		started := time.Now()
		_, err := scripted(t, s, kofra.WithMaxRetryWait(30*time.Second)).Buckets.List(context.Background(), nil)
		var kerr *kofra.Error
		if !errors.As(err, &kerr) || kerr.Status != 429 || len(s.requests) != 1 {
			t.Fatalf("Retry-After %s: err %v after %d attempts", after, err, len(s.requests))
		}
		if time.Since(started) > 2*time.Second {
			t.Fatalf("Retry-After %s: waited before giving up", after)
		}
	}
}

func TestARetryAfterHTTPDateWithinTheMaxWaitIsHonoured(t *testing.T) {
	when := time.Now().Add(1 * time.Second).UTC().Format(http.TimeFormat)
	s := &script{answers: []answer{{status: 503, headers: map[string]string{"Retry-After": when}}, {status: 200, body: listJSON}}}
	if _, err := scripted(t, s).Buckets.List(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(s.requests) != 2 {
		t.Fatalf("%d attempts", len(s.requests))
	}
}

func TestNetworkErrorsAreRetried(t *testing.T) {
	s := &script{answers: []answer{{err: errors.New("connection refused")}, {status: 200, body: listJSON}}}
	if _, err := scripted(t, s, kofra.WithMaxRetryWait(time.Millisecond)).Buckets.List(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(s.requests) != 2 {
		t.Fatalf("%d attempts", len(s.requests))
	}
	s = &script{answers: []answer{{err: errors.New("connection refused")}, {err: errors.New("connection refused")}}}
	_, err := scripted(t, s, kofra.WithMaxRetries(1), kofra.WithMaxRetryWait(time.Millisecond)).Buckets.List(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "connection refused") || len(s.requests) != 2 {
		t.Fatalf("err %v after %d attempts", err, len(s.requests))
	}
}

func TestEmpty2xxIsSuccess(t *testing.T) {
	s := &script{answers: []answer{{status: 202}}}
	body, err := scripted(t, s).Do(context.Background(), http.MethodPost, "/v1/account/deletion/cancel", nil, nil)
	if err != nil || body != nil {
		t.Fatalf("body %q, err %v", body, err)
	}
}

func TestBaseURLMustBeHTTPSUnlessLoopback(t *testing.T) {
	for _, u := range []string{"http://api.example.test", "http://10.0.0.1:8080", "ftp://x.test", "x.test"} {
		if _, err := kofra.New(kofra.WithToken("t"), kofra.WithBaseURL(u)); err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("%s: err %v", u, err)
		}
	}
	for _, u := range []string{"https://x.test", "http://localhost:4010", "http://127.0.0.2:1", "http://[::1]:4010"} {
		if _, err := kofra.New(kofra.WithToken("t"), kofra.WithBaseURL(u)); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if _, err := kofra.New(kofra.WithToken("t"), kofra.WithBaseURL("http://api.example.test"), kofra.WithInsecureHTTP()); err != nil {
		t.Errorf("opt-in: %v", err)
	}
}

func TestEmptyAndDotPathArgumentsAreRefused(t *testing.T) {
	for _, bad := range []string{"", ".", ".."} {
		s := &script{}
		c := scripted(t, s)
		if _, err := c.Buckets.Get(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "path") {
			t.Errorf("Buckets.Get(%q): err %v", bad, err)
		}
		if _, err := c.Do(context.Background(), http.MethodGet, "/v1/buckets/"+bad, nil, nil); err == nil {
			t.Errorf("Do(/v1/buckets/%s): no error", bad)
		}
		if len(s.requests) != 0 {
			t.Errorf("%q: %d requests sent", bad, len(s.requests))
		}
	}
}
