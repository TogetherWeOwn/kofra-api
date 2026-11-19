package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

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
}
