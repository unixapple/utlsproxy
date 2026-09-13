package trust

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/unixapple/utlsproxy/internal/fsutil"
)

func TestMacCommandsAndExactFingerprint(t *testing.T) {
	_, _, path := fixture(t)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	m := &macBackend{keychain: "/Library/Keychains/System.keychain", run: func(_ context.Context, input []byte, tool string, args ...string) ([]byte, error) {
		if tool != "/usr/bin/security" {
			t.Fatalf("non-system command: %s", tool)
		}
		calls = append(calls, append([]string{}, args...))
		switch args[0] {
		case "find-certificate":
			return c.PEM, nil
		case "verify-cert":
			if !bytes.Equal(input, c.PEM) {
				t.Fatal("verification used wrong certificate")
			}
			for _, a := range args {
				if a == "-r" {
					t.Fatal("verification implicitly trusted the supplied root")
				}
			}
		}
		return nil, nil
	}}
	s, err := m.Inspect(context.Background(), c)
	if err != nil || !s.Installed || !s.Trusted {
		t.Fatalf("inspection: %+v %v", s, err)
	}
	if err = m.Add(context.Background(), c, "/private/snapshot.crt"); err != nil {
		t.Fatal(err)
	}
	want := []string{"add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl", "-k", m.keychain, "/private/snapshot.crt"}
	if !reflect.DeepEqual(calls[len(calls)-1], want) {
		t.Fatalf("not SSL-scoped admin trust: %v", calls)
	}
	if err = m.Remove(context.Background(), c, "/private/snapshot.crt"); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete-certificate", "-Z", c.SHA256, m.keychain}
	if !reflect.DeepEqual(calls[len(calls)-1], want) {
		t.Fatal("removal did not use exact fingerprint")
	}
	negative := exec.Command("false").Run()
	m.run = func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		if args[0] == "verify-cert" {
			return []byte("not trusted"), negative
		}
		return c.PEM, nil
	}
	s, err = m.Inspect(context.Background(), c)
	if err != nil || s.Trusted {
		t.Fatalf("untrusted CA reported trusted: %+v %v", s, err)
	}
	m.run = func(context.Context, []byte, string, ...string) ([]byte, error) { return nil, os.ErrPermission }
	if _, err = m.Inspect(context.Background(), c); !errors.Is(err, os.ErrPermission) {
		t.Fatal("native inspection failure hidden")
	}
}

func TestLinuxDistributionDetection(t *testing.T) {
	for _, tc := range []struct{ release, kind, tool string }{
		{"ID=ubuntu\nID_LIKE=debian", "debian-ca-certificates", "/usr/sbin/update-ca-certificates"},
		{"ID=debian", "debian-ca-certificates", "/usr/sbin/update-ca-certificates"},
		{"ID=rocky\nID_LIKE=\"rhel centos fedora\"", "fedora-ca-trust", "/usr/bin/update-ca-trust"},
		{"ID=custom\nID_LIKE=\"fedora\"", "fedora-ca-trust", "/usr/bin/update-ca-trust"},
	} {
		b, err := linuxStore(tc.release, nil)
		if err != nil || b.kind != tc.kind || b.tool != tc.tool {
			t.Fatalf("%s: %+v %v", tc.release, b, err)
		}
	}
	if _, err := linuxStore("ID=unknown", nil); err == nil {
		t.Fatal("guessed unsupported trust store")
	}
}

func TestLinuxTrustLifecycleAndConflict(t *testing.T) {
	for _, release := range []string{"ID=debian", "ID=fedora"} {
		t.Run(release, func(t *testing.T) {
			m, _, path := fixture(t)
			c, _ := Load(path)
			b, err := linuxStore(release, nil)
			if err != nil {
				t.Fatal(err)
			}
			base := t.TempDir()
			b.dir, b.bundle = filepath.Join(base, "anchors"), filepath.Join(base, "bundle.pem")
			b.protect = func(path string) error { return os.MkdirAll(path, 0755) }
			b.checkTool = func(string) error { return nil }
			var refreshes int
			b.run = func(_ context.Context, _ []byte, tool string, args ...string) ([]byte, error) {
				if tool != b.tool || !reflect.DeepEqual(args, b.args) {
					t.Fatal("wrong distribution update command")
				}
				refreshes++
				contents, err := os.ReadFile(b.Store(c).Target)
				if err != nil && !os.IsNotExist(err) {
					return nil, err
				}
				return nil, os.WriteFile(b.bundle, contents, 0644)
			}
			m.backend = b
			r, err := m.Execute(context.Background(), "trust", path, false)
			if err != nil || !r.Trusted || !r.Installed {
				t.Fatalf("trust: %+v %v", r, err)
			}
			if !strings.Contains(r.Store.Scope, "not restricted to SSL") {
				t.Fatal("Linux scope limitation not disclosed")
			}
			info, err := os.Stat(b.Store(c).Target)
			if err != nil || info.Mode().Perm() != 0644 {
				t.Fatal("CA not publicly readable")
			}
			if _, err = m.Execute(context.Background(), "trust", path, false); err != nil || refreshes != 1 {
				t.Fatal("repeat rebuilt system trust")
			}
			_, _, otherPath := fixture(t)
			other, _ := os.ReadFile(otherPath)
			if err := os.WriteFile(b.Store(c).Target, other, 0644); err != nil {
				t.Fatal(err)
			}
			if _, err = m.Execute(context.Background(), "untrust", path, false); err == nil {
				t.Fatal("removed a replacement certificate")
			}
			if err = os.WriteFile(b.Store(c).Target, c.PEM, 0644); err != nil {
				t.Fatal(err)
			}
			r, err = m.Execute(context.Background(), "untrust", path, false)
			if err != nil || r.Trusted || refreshes != 2 {
				t.Fatalf("untrust: %+v %v", r, err)
			}
			if _, err = m.Execute(context.Background(), "untrust", path, false); err != nil || refreshes != 2 {
				t.Fatal("repeat removal was not harmless")
			}
			if err = os.Symlink(otherPath, b.Store(c).Target); err != nil {
				t.Fatal(err)
			}
			if _, err = b.Inspect(context.Background(), c); err == nil {
				t.Fatal("accepted symlink anchor")
			}
		})
	}
}

func TestLinuxUpdateFailureKeepsRecovery(t *testing.T) {
	m, _, path := fixture(t)
	b, _ := linuxStore("ID=ubuntu", func(context.Context, []byte, string, ...string) ([]byte, error) {
		return nil, errors.New("update failed")
	})
	b.dir, b.bundle = filepath.Join(t.TempDir(), "anchors"), filepath.Join(t.TempDir(), "bundle")
	b.protect = func(path string) error { return os.MkdirAll(path, 0755) }
	b.checkTool = func(string) error { return nil }
	m.backend = b
	r, err := m.Execute(context.Background(), "trust", path, false)
	if err == nil {
		t.Fatal("update failure hidden")
	}
	if err = fsutil.Regular(r.Receipt); err != nil {
		t.Fatal("receipt lost after failed rollback")
	}
}
