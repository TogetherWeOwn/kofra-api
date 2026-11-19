// Package mocktest starts the contract's mock server (tools/mock/server.mjs,
// run with Node) for the Go tests.
package mocktest

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

var listening = regexp.MustCompile(`http://[0-9.]+:\d+`)

// Start runs the mock on a free port and returns its base URL. The mock is
// stopped when the test ends.
func Start(t testing.TB) string {
	t.Helper()
	server := findServer(t)
	cmd := exec.Command("node", server, "--port", "0")
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the mock with node: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	found := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			if u := listening.FindString(scanner.Text()); u != "" {
				found <- u
				break
			}
		}
		for scanner.Scan() {
		}
	}()
	select {
	case u := <-found:
		return u
	case <-time.After(20 * time.Second):
		t.Fatal("the mock did not print its URL within 20s")
		return ""
	}
}

func findServer(t testing.TB) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		p := filepath.Join(dir, "tools", "mock", "server.mjs")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("tools/mock/server.mjs not found above the test directory")
		}
		dir = parent
	}
}
