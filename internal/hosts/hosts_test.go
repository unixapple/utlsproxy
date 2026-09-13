package hosts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hosts")
	if e := os.WriteFile(path, []byte(text), 0644); e != nil {
		t.Fatal(e)
	}
	return path
}
func TestManagedRoundTrip(t *testing.T) {
	original := "127.0.0.1 localhost\n# personal comment\n192.0.2.1 untouched.example alias.example\n"
	path := fixture(t, original)
	p, e := Prepare(path, []string{"tls.peet.ws"}, "127.0.0.1", false)
	if e != nil {
		t.Fatal(e)
	}
	if !p.Changed {
		t.Fatal("missing change")
	}
	backup, e := Apply(p, filepath.Join(t.TempDir(), "state"))
	if e != nil {
		t.Fatal(e)
	}
	if backup == "" {
		t.Fatal("missing backup")
	}
	p, e = Prepare(path, []string{"tls.peet.ws"}, "127.0.0.1", false)
	if e != nil || p.Changed {
		t.Fatalf("not idempotent: %v", e)
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString("192.0.2.2 later.example\n")
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	p, e = Prepare(path, nil, "", true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Apply(p, filepath.Join(t.TempDir(), "state")); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if string(b) != original+"192.0.2.2 later.example\n" {
		t.Fatalf("lost unrelated edits: %s", b)
	}
	i, _ := os.Stat(path)
	if i.Mode().Perm() != 0644 {
		t.Fatal("lost permissions")
	}
}
func TestConflictsAndConcurrentEdits(t *testing.T) {
	path := fixture(t, "192.0.2.1 tls.peet.ws\n")
	if _, e := Prepare(path, []string{"tls.peet.ws"}, "127.0.0.1", false); e == nil {
		t.Fatal("accepted unmanaged conflict")
	}
	path = fixture(t, "# original\n")
	p, e := Prepare(path, []string{"tls.peet.ws"}, "127.0.0.1", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte("# concurrent\n"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = Apply(p, filepath.Join(t.TempDir(), "state")); e == nil {
		t.Fatal("overwrote concurrent edit")
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "concurrent") {
		t.Fatal("lost concurrent edit")
	}
	path = fixture(t, Begin+"\n"+Begin+"\n"+End+"\n")
	if _, e = Prepare(path, nil, "", true); e == nil {
		t.Fatal("accepted duplicate markers")
	}
}
