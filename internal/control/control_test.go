package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSocketOwnership(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "c.sock")
	l, cleanup, e := Listen(path)
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	defer l.Close()
	if _, _, e = Listen(path); e == nil {
		t.Fatal("second listener replaced live socket")
	}
	i, _ := os.Stat(path)
	if i.Mode().Perm() != 0600 {
		t.Fatal("socket is not private")
	}
	other := filepath.Join(dir, "ordinary")
	if e = os.WriteFile(other, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = Listen(other); e == nil {
		t.Fatal("replaced ordinary file")
	}
	b, _ := os.ReadFile(other)
	if string(b) != "preserve" {
		t.Fatal("lost ordinary file")
	}
}
