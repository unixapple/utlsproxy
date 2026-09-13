package logging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotationIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.limit = 8
	for i := 0; i < 10; i++ {
		if _, err = r.Write([]byte("12345678")); err != nil {
			t.Fatal(err)
		}
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", ".1", ".2", ".3"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != 8 || info.Mode().Perm() != 0600 {
			t.Fatalf("log not bounded/private: %s %v", suffix, info)
		}
	}
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Fatal("too many log backups")
	}
	link := filepath.Join(t.TempDir(), "symlink.log")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("log symlink accepted")
	}
}
