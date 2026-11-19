package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TogetherWeOwn/kofra-api/sdk/go/internal/mocktest"
)

type result struct {
	code           int
	stdout, stderr string
}

func cli(t *testing.T, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &errOut, func(k string) string { return env[k] })
	return result{code, out.String(), errOut.String()}
}

func mockEnv(t *testing.T) map[string]string {
	return map[string]string{"KOFRA_API_TOKEN": "kofra_tok_test_1", "KOFRA_API_URL": mocktest.Start(t)}
}

func TestUsageErrorsExit2(t *testing.T) {
	env := map[string]string{"KOFRA_API_TOKEN": "kofra_tok_test_1", "KOFRA_API_URL": "http://127.0.0.1:9"}
	cases := [][]string{
		{},
		{"nope"},
		{"buckets"},
		{"buckets", "nope"},
		{"buckets", "get"},
		{"buckets", "get", "a", "b"},
		{"buckets", "list", "--nope", "1"},
		{"buckets", "list", "--dry-run"},
		{"buckets", "create"},
		{"buckets", "create", "--body", "[1]"},
		{"buckets", "get", "backups", "--body", "{}"},
		{"buckets", "list", "--limit"},
	}
	for _, args := range cases {
		r := cli(t, env, "", args...)
		if r.code != exitUsage || r.stderr == "" {
			t.Errorf("kofra %s: exit %d, stderr %q; want exit 2 with a message", strings.Join(args, " "), r.code, r.stderr)
		}
	}
}

func TestHelpGoesToStdout(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"--help"}, {"buckets", "--help"}, {"buckets", "delete", "--help"}} {
		r := cli(t, nil, "", args...)
		if r.code != exitOK || !strings.Contains(r.stdout, "delete") {
			t.Errorf("kofra %s: exit %d, stdout %q", strings.Join(args, " "), r.code, r.stdout)
		}
	}
	r := cli(t, nil, "", "help")
	for _, c := range commands {
		if !strings.Contains(r.stdout, "kofra "+c.resource+" "+c.name) {
			t.Errorf("help does not list kofra %s %s", c.resource, c.name)
		}
	}
}

func TestDestructiveNeedsYes(t *testing.T) {
	env := mockEnv(t)
	for _, c := range commands {
		if !c.destructive {
			continue
		}
		args := []string{c.resource, c.name}
		for range c.args {
			args = append(args, "x")
		}
		r := cli(t, env, "", args...)
		if r.code != exitUsage || !strings.Contains(r.stderr, "--yes") {
			t.Errorf("%s without --yes: exit %d, stderr %q", cliName(&c), r.code, r.stderr)
		}
	}
	r := cli(t, env, "", "buckets", "delete", "old-logs", "--yes")
	if r.code != exitOK || !strings.Contains(r.stdout, "Done") {
		t.Fatalf("with --yes: exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
}

func TestDryRunNeedsNoYes(t *testing.T) {
	r := cli(t, mockEnv(t), "", "buckets", "delete", "old-logs", "--dry-run", "--json")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var plan struct {
		DryRun    bool   `json:"dry_run"`
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &plan); err != nil || !plan.DryRun || plan.Operation != "buckets.delete" {
		t.Fatalf("plan %q (%v)", r.stdout, err)
	}
}

func TestJSONOutput(t *testing.T) {
	env := mockEnv(t)
	r := cli(t, env, "", "buckets", "list", "--json", "--limit", "10")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var list struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &list); err != nil || len(list.Data) != 2 {
		t.Fatalf("stdout %q (%v)", r.stdout, err)
	}
	r = cli(t, env, `{"name":"backups"}`, "buckets", "create", "--body", "-", "--json")
	if r.code != exitOK || !strings.Contains(r.stdout, `"name": "backups"`) {
		t.Fatalf("create: exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
}

func TestTextOutput(t *testing.T) {
	env := mockEnv(t)
	r := cli(t, env, "", "buckets", "list")
	if r.code != exitOK || !strings.Contains(r.stdout, "NAME") || !strings.Contains(r.stdout, "photos") {
		t.Fatalf("list: exit %d, stdout %q", r.code, r.stdout)
	}
	r = cli(t, env, "", "buckets", "get", "backups")
	if r.code != exitOK || !strings.Contains(r.stdout, "object_count:") {
		t.Fatalf("get: exit %d, stdout %q", r.code, r.stdout)
	}
}

func TestAPIErrorExit1(t *testing.T) {
	env := mockEnv(t)
	r := cli(t, env, "", "buckets", "get", "Bad_Name")
	if r.code != exitAPI {
		t.Fatalf("exit %d, want 1", r.code)
	}
	for _, want := range []string{"validation_failed", "hint: ", "request_id: req_"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q: %s", want, r.stderr)
		}
	}
	r = cli(t, env, "", "buckets", "create", "--body", `{"nmae":"x"}`)
	if r.code != exitAPI || !strings.Contains(r.stderr, "unknown_field") {
		t.Fatalf("unknown field: exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestTokenIsNeverPrinted(t *testing.T) {
	env := mockEnv(t)
	env["KOFRA_API_TOKEN"] = "kofra_tok_expired"
	r := cli(t, env, "", "buckets", "list")
	if r.code != exitAPI || !strings.Contains(r.stderr, "token_expired") {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	if strings.Contains(r.stdout+r.stderr, "kofra_tok_expired") {
		t.Fatal("the token was printed")
	}
	r = cli(t, map[string]string{}, "", "buckets", "list")
	if r.code != exitUsage || !strings.Contains(r.stderr, "KOFRA_API_TOKEN") {
		t.Fatalf("no token: exit %d, stderr %q", r.code, r.stderr)
	}

	const secret = "kofra_tok_never_printed_1"
	// A network error: nothing listens on the port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + l.Addr().String()
	_ = l.Close()
	r = cli(t, map[string]string{"KOFRA_API_TOKEN": secret, "KOFRA_API_URL": closed}, "", "buckets", "list")
	if r.code != exitAPI || r.stderr == "" {
		t.Fatalf("network error: exit %d, stderr %q", r.code, r.stderr)
	}
	if strings.Contains(r.stdout+r.stderr, secret) {
		t.Fatal("the token was printed on a network error")
	}
	// A base URL that is refused before any request.
	r = cli(t, map[string]string{"KOFRA_API_TOKEN": secret, "KOFRA_API_URL": "http://api.example.test"}, "", "buckets", "list")
	if r.code != exitUsage || !strings.Contains(r.stderr, "https") {
		t.Fatalf("bad base URL: exit %d, stderr %q", r.code, r.stderr)
	}
	if strings.Contains(r.stdout+r.stderr, secret) {
		t.Fatal("the token was printed on a bad base URL")
	}
}

func TestEmpty2xxIsDone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	env := map[string]string{"KOFRA_API_TOKEN": "kofra_tok_test_1", "KOFRA_API_URL": srv.URL}
	for _, args := range [][]string{{"account", "cancel-deletion"}, {"account", "cancel-deletion", "--json"}} {
		r := cli(t, env, "", args...)
		if r.code != exitOK {
			t.Fatalf("%v: exit %d, stderr %q", args, r.code, r.stderr)
		}
	}
	r := cli(t, env, "", "account", "cancel-deletion")
	if !strings.Contains(r.stdout, "Done") {
		t.Fatalf("stdout %q", r.stdout)
	}
}

func TestEmptyAndDotPathArgumentsExit2(t *testing.T) {
	env := map[string]string{"KOFRA_API_TOKEN": "kofra_tok_test_1", "KOFRA_API_URL": "http://127.0.0.1:9"}
	for _, bad := range []string{"", ".", ".."} {
		r := cli(t, env, "", "buckets", "get", bad)
		if r.code != exitUsage || !strings.Contains(r.stderr, "path argument") {
			t.Errorf("buckets get %q: exit %d, stderr %q", bad, r.code, r.stderr)
		}
	}
}

func TestFlagValues(t *testing.T) {
	env := map[string]string{"KOFRA_API_TOKEN": "kofra_tok_test_1", "KOFRA_API_URL": "http://127.0.0.1:9"}
	for _, args := range [][]string{
		{"buckets", "list", "--limit", "--json"},
		{"buckets", "list", "--cursor", "--"},
		{"buckets", "create", "--body", "--yes"},
	} {
		r := cli(t, env, "", args...)
		if r.code != exitUsage || !strings.Contains(r.stderr, "needs a value") {
			t.Errorf("kofra %s: exit %d, stderr %q", strings.Join(args, " "), r.code, r.stderr)
		}
	}
	r := cli(t, mockEnv(t), "", "buckets", "list", "--limit=1", "--json")
	if r.code != exitOK || !strings.Contains(r.stdout, `"data"`) {
		t.Fatalf("--limit=1: exit %d, stderr %q", r.code, r.stderr)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestOutputWriteErrorsExit1(t *testing.T) {
	env := mockEnv(t)
	for _, args := range [][]string{{"buckets", "list"}, {"buckets", "get", "backups"}, {"buckets", "list", "--json"}} {
		var errOut bytes.Buffer
		code := run(context.Background(), args, strings.NewReader(""), failingWriter{}, &errOut, func(k string) string { return env[k] })
		if code != exitAPI || !strings.Contains(errOut.String(), "disk full") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut.String())
		}
	}
}

func TestInterruptStopsABodyRead(t *testing.T) {
	env := map[string]string{"KOFRA_API_TOKEN": "kofra_tok_test_1", "KOFRA_API_URL": "http://127.0.0.1:9"}
	stdin, w := io.Pipe() // nothing is ever written
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		var out, errOut bytes.Buffer
		done <- run(ctx, []string{"buckets", "create", "--body", "-"}, stdin, &out, &errOut, func(k string) string { return env[k] })
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case code := <-done:
		if code == exitOK {
			t.Fatal("an interrupted body read exited 0")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the body read ignored the interrupt")
	}
}
