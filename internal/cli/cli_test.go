package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unixapple/utlsproxy/internal/config"
)

func TestCLIHelpAndErrors(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"serve", "--help"}, {"test", "--help"}, {"ca", "--help"}, {"ca", "trust", "--help"}, {"ca", "untrust", "--help"}, {"ca", "trust-status", "--help"}} {
		var out, stderr bytes.Buffer
		if code := Execute(args, &out, &stderr, "test"); code != 0 || out.Len()+stderr.Len() == 0 {
			t.Fatalf("help %v: %d %s", args, code, &stderr)
		}
	}
	for _, args := range [][]string{{"unknown"}, {"serve", "--nonsense"}, {"profiles", "show", "unknown"}, {"profiles", "show"}, {"version", "extra"}} {
		var out, stderr bytes.Buffer
		if code := Execute(args, &out, &stderr, "test"); code != 2 {
			t.Fatalf("invalid command %v: %d %s", args, code, &stderr)
		}
	}
	var out, stderr bytes.Buffer
	if code := Execute([]string{"status", "--socket", "/tmp/utlsproxy-nonexistent-cli-test.sock"}, &out, &stderr, "test"); code != 3 {
		t.Fatalf("missing daemon: %d %s", code, &stderr)
	}
}

func TestLocalSetup(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "utlsproxy-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "config.json")
	run := func(args ...string) string {
		t.Helper()
		var out, stderr bytes.Buffer
		if code := Execute(args, &out, &stderr, "test"); code != 0 {
			t.Fatalf("%v failed (%d): %s", args, code, &stderr)
		}
		return out.String()
	}
	run("config", "init", "--local", "--output", path)
	var effective config.Config
	if err := json.Unmarshal([]byte(run("config", "show", "--config", path)), &effective); err != nil {
		t.Fatal(err)
	}
	if effective.Listen[0] != "127.0.0.1:8443" || !strings.HasPrefix(effective.CA.Cert, dir) {
		t.Fatalf("non-local setup: %+v", effective)
	}
	run("ca", "init", "--config", path)
	run("config", "validate", "--config", path)
	var info map[string]any
	if err := json.Unmarshal([]byte(run("ca", "inspect", "--config", path, "--json")), &info); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := Execute([]string{"config", "init", "--local", "--output", path}, &out, &stderr, "test"); code == 0 {
		t.Fatal("config overwritten")
	}
}
