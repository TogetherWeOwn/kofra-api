package kofra_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TogetherWeOwn/kofra-api/sdk/go/internal/mocktest"
	"github.com/TogetherWeOwn/kofra-api/sdk/go/kofra"
	"github.com/TogetherWeOwn/kofra-api/sdk/go/kofra/api"
)

// recorder sends requests on to the mock, records their headers and, for the
// first `prefer` attempts, asks the mock for a given answer (e.g. code=429).
type recorder struct {
	mu      sync.Mutex
	prefer  []string
	headers []http.Header
	methods []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	if len(r.prefer) > 0 {
		req = req.Clone(req.Context())
		req.Header.Set("Prefer", r.prefer[0])
		r.prefer = r.prefer[1:]
	}
	r.headers = append(r.headers, req.Header.Clone())
	r.methods = append(r.methods, req.Method)
	r.mu.Unlock()
	return http.DefaultTransport.RoundTrip(req)
}

func newClient(t *testing.T, base string, rec *recorder, opts ...kofra.Option) *kofra.Client {
	t.Helper()
	all := []kofra.Option{
		kofra.WithToken("kofra_tok_test_1"),
		kofra.WithBaseURL(base),
		kofra.WithMaxRetryWait(5 * time.Millisecond),
	}
	if rec != nil {
		all = append(all, kofra.WithHTTPClient(&http.Client{Transport: rec}))
	}
	c, err := kofra.New(append(all, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestListCreateGetDelete(t *testing.T) {
	ctx := context.Background()
	c := newClient(t, mocktest.Start(t), nil)

	list, err := c.Buckets.List(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(list.JSON200.Data); got != 2 {
		t.Fatalf("buckets.list: %d buckets, want 2", got)
	}
	created, err := c.Buckets.Create(ctx, nil, api.BucketCreate{Name: "backups"})
	if err != nil {
		t.Fatal(err)
	}
	if created.JSON201.Name != "backups" {
		t.Fatalf("buckets.create: name %q", created.JSON201.Name)
	}
	got, err := c.Buckets.Get(ctx, "backups")
	if err != nil {
		t.Fatal(err)
	}
	if got.JSON200.ObjectCount != 1204 {
		t.Fatalf("buckets.get: object_count %d", got.JSON200.ObjectCount)
	}
	deleted, err := c.Buckets.Delete(ctx, "old-logs", nil)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.StatusCode() != http.StatusNoContent {
		t.Fatalf("buckets.delete: HTTP %d", deleted.StatusCode())
	}
	dry := true
	plan, err := c.Buckets.Delete(ctx, "old-logs", &api.BucketsDeleteParams{DryRun: &dry})
	if err != nil {
		t.Fatal(err)
	}
	if plan.JSON200 == nil || plan.JSON200.Operation != "buckets.delete" {
		t.Fatalf("buckets.delete dry run: %s", plan.Body)
	}
	key, err := c.Keys.Create(ctx, nil, api.AccessKeyCreate{Grants: []api.GrantInput{{Bucket: "backups", Access: api.GrantInputAccessReadWrite}}})
	if err != nil {
		t.Fatal(err)
	}
	if s := key.JSON201.SecretAccessKey; s == nil || *s == "" {
		t.Fatal("keys.create: no secret")
	}
}

func TestErrorCarriesCodeHintAndRequestID(t *testing.T) {
	ctx := context.Background()
	base := mocktest.Start(t)
	_, err := newClient(t, base, nil).Buckets.Get(ctx, "Bad_Name")
	var kerr *kofra.Error
	if !errors.As(err, &kerr) {
		t.Fatalf("want *kofra.Error, got %v", err)
	}
	if kerr.Status != 400 || kerr.Problem.Code != "validation_failed" {
		t.Fatalf("got %d %s", kerr.Status, kerr.Problem.Code)
	}
	if kerr.Problem.Hint == "" || !strings.HasPrefix(kerr.Problem.RequestId, "req_") {
		t.Fatalf("hint %q, request_id %q", kerr.Problem.Hint, kerr.Problem.RequestId)
	}
	if !strings.Contains(kerr.Error(), "validation_failed") {
		t.Fatalf("message %q", kerr.Error())
	}

	readonly, err := kofra.New(kofra.WithToken("kofra_tok_ci_readonly"), kofra.WithBaseURL(base))
	if err != nil {
		t.Fatal(err)
	}
	_, err = readonly.Buckets.Create(ctx, nil, api.BucketCreate{Name: "backups"})
	if !errors.As(err, &kerr) || kerr.Problem.Code != "insufficient_scope" {
		t.Fatalf("want insufficient_scope, got %v", err)
	}
}

func TestRetriesOn429And503WithTheSameIdempotencyKey(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{prefer: []string{"code=429", "code=503"}}
	c := newClient(t, mocktest.Start(t), rec)
	created, err := c.Buckets.Create(ctx, nil, api.BucketCreate{Name: "backups"})
	if err != nil {
		t.Fatal(err)
	}
	if created.JSON201 == nil || created.JSON201.Name != "backups" {
		t.Fatalf("after retries: HTTP %d %s", created.StatusCode(), created.Body)
	}
	if len(rec.headers) != 3 {
		t.Fatalf("%d attempts, want 3", len(rec.headers))
	}
	key := rec.headers[0].Get("Idempotency-Key")
	for i, h := range rec.headers {
		if h.Get("Idempotency-Key") != key {
			t.Fatalf("attempt %d changed the Idempotency-Key", i)
		}
	}
}

func TestRetriesAreBounded(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{prefer: []string{"code=429", "code=429", "code=429", "code=429"}}
	c := newClient(t, mocktest.Start(t), rec, kofra.WithMaxRetries(1))
	_, err := c.Buckets.List(ctx, nil)
	var kerr *kofra.Error
	if !errors.As(err, &kerr) || kerr.Status != 429 || !kerr.Problem.Retryable {
		t.Fatalf("want a retryable 429, got %v", err)
	}
	if len(rec.headers) != 2 {
		t.Fatalf("%d attempts, want 2", len(rec.headers))
	}
}

func TestIdempotencyKeyOnWritesOnly(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{}
	c := newClient(t, mocktest.Start(t), rec)
	own := "my-key-1"
	if _, err := c.Buckets.List(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Buckets.Create(ctx, nil, api.BucketCreate{Name: "backups"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Keys.Update(ctx, "KF7Q2M8X4T7R5N0B", nil, api.AccessKeyUpdate{Name: &own}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Buckets.Delete(ctx, "old-logs", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Buckets.Create(ctx, &api.BucketsCreateParams{IdempotencyKey: &own}, api.BucketCreate{Name: "backups"}); err != nil {
		t.Fatal(err)
	}
	for i, h := range rec.headers {
		key := h.Get("Idempotency-Key")
		if rec.methods[i] == http.MethodGet && key != "" {
			t.Fatalf("GET carried an Idempotency-Key")
		}
		if rec.methods[i] != http.MethodGet && key == "" {
			t.Fatalf("%s carried no Idempotency-Key", rec.methods[i])
		}
		if got := h.Get("Authorization"); got != "Bearer kofra_tok_test_1" {
			t.Fatalf("Authorization header not set")
		}
	}
	if got := rec.headers[4].Get("Idempotency-Key"); got != own {
		t.Fatalf("the caller's Idempotency-Key was replaced with %q", got)
	}
}

func TestDo(t *testing.T) {
	ctx := context.Background()
	c := newClient(t, mocktest.Start(t), nil)
	body, err := c.Do(ctx, http.MethodPost, "/v1/buckets", nil, map[string]string{"name": "backups"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"backups"`) {
		t.Fatalf("body %s", body)
	}
	body, err = c.Do(ctx, http.MethodDelete, "/v1/buckets/old-logs", nil, nil)
	if err != nil || body != nil {
		t.Fatalf("delete: %s, %v", body, err)
	}
	_, err = c.Do(ctx, http.MethodPost, "/v1/buckets", nil, map[string]string{"nmae": "backups"})
	var kerr *kofra.Error
	if !errors.As(err, &kerr) || kerr.Problem.Code != "unknown_field" {
		t.Fatalf("want unknown_field, got %v", err)
	}
}

func TestEnvironmentAndMissingToken(t *testing.T) {
	t.Setenv("KOFRA_API_TOKEN", "")
	t.Setenv("KOFRA_API_URL", "")
	if _, err := kofra.New(); err == nil || !strings.Contains(err.Error(), "KOFRA_API_TOKEN") {
		t.Fatalf("want a missing-token error, got %v", err)
	}
	t.Setenv("KOFRA_API_TOKEN", "kofra_tok_env")
	t.Setenv("KOFRA_API_URL", "http://127.0.0.1:9/")
	c, err := kofra.New()
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != "http://127.0.0.1:9" {
		t.Fatalf("base URL %q", c.BaseURL())
	}
	if _, err := kofra.New(kofra.WithBaseURL("ftp://x")); err == nil {
		t.Fatal("a non-http base URL was accepted")
	}
}
