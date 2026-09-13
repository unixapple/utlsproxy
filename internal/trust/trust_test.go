package trust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unixapple/utlsproxy/internal/ca"
	"github.com/unixapple/utlsproxy/internal/fsutil"
)

type fakeBackend struct {
	state               State
	adds, removes       int
	failAdd, failRemove bool
}

func (f *fakeBackend) Store(Certificate) Store {
	return Store{"fixture", "fixture-system-store", "SSL"}
}
func (f *fakeBackend) Inspect(context.Context, Certificate) (State, error) { return f.state, nil }
func (f *fakeBackend) Add(_ context.Context, c Certificate, path string) error {
	f.adds++
	snapshot, err := Load(path)
	if err != nil || snapshot.SHA256 != c.SHA256 {
		return errors.New("incorrect install snapshot")
	}
	f.state = State{true, true}
	if f.failAdd {
		return errors.New("partial native install failure")
	}
	return nil
}
func (f *fakeBackend) Remove(context.Context, Certificate, string) error {
	f.removes++
	if f.failRemove {
		return errors.New("native removal failed")
	}
	f.state = State{}
	return nil
}
func fixture(t *testing.T) (*Manager, *fakeBackend, string) {
	t.Helper()
	dir := t.TempDir()
	if _, err := ca.Init(filepath.Join(dir, "ca"), "same display name", 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	f := &fakeBackend{}
	m := &Manager{backend: f, dir: filepath.Join(dir, "receipts"), euid: func() int { return 0 }, protect: fsutil.PrivateDir}
	return m, f, filepath.Join(dir, "ca", "ca.crt")
}
func TestTrustLifecycleAndPrivateKeyIndependence(t *testing.T) {
	m, f, path := fixture(t)
	// A client machine needs only ca.crt; the private key is not available.
	key := filepath.Join(filepath.Dir(path), "ca.key")
	if err := os.Rename(key, key+".kept-private"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dry, err := m.Execute(ctx, "trust", path, true)
	if err != nil || dry.Changed || f.adds != 0 {
		t.Fatalf("dry run: %+v %v", dry, err)
	}
	if _, err = os.Stat(m.dir); !os.IsNotExist(err) {
		t.Fatal("dry run wrote state")
	}
	r, err := m.Execute(ctx, "trust", path, false)
	if err != nil || !r.Changed || !r.Trusted || !r.Managed || f.adds != 1 {
		t.Fatalf("install: %+v %v", r, err)
	}
	info, _ := os.Stat(r.Receipt)
	if info.Mode().Perm() != 0600 {
		t.Fatal("receipt is not private")
	}
	repeat, err := m.Execute(ctx, "trust", path, false)
	if err != nil || repeat.Changed || f.adds != 1 {
		t.Fatal("repeat install mutated trust")
	}
	if _, err = m.Execute(ctx, "trust-status", path, false); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Execute(ctx, "untrust", path, true); err != nil || f.removes != 0 {
		t.Fatal("dry removal mutated trust")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	r, err = m.Execute(ctx, "untrust", r.RecoveryCertificate, false)
	if err != nil || !r.Changed || r.Trusted || r.Managed || f.removes != 1 {
		t.Fatalf("remove: %+v %v", r, err)
	}
	if _, err = os.Stat(key + ".kept-private"); err != nil {
		t.Fatal("private key was touched")
	}
	if _, err = os.Stat(r.Receipt); !os.IsNotExist(err) {
		t.Fatal("receipt not removed")
	}
}
func TestUnmanagedAndPermissionSafety(t *testing.T) {
	m, f, path := fixture(t)
	f.state = State{true, true}
	r, err := m.Execute(context.Background(), "trust", path, false)
	if err != nil || r.Managed || f.adds != 0 {
		t.Fatal("adopted pre-existing trust")
	}
	if _, err = m.Execute(context.Background(), "untrust", path, false); err == nil || f.removes != 0 {
		t.Fatal("removed unmanaged trust")
	}
	f.state.Trusted = false
	if _, err = m.Execute(context.Background(), "trust", path, false); err == nil || f.adds != 0 {
		t.Fatal("modified unmanaged certificate")
	}
	m.euid = func() int { return 501 }
	if _, err = m.Execute(context.Background(), "trust", path, false); !errors.Is(err, os.ErrPermission) {
		t.Fatal("did not require root")
	}
}
func TestRollbackAndRetry(t *testing.T) {
	m, f, path := fixture(t)
	f.failAdd = true
	r, err := m.Execute(context.Background(), "trust", path, false)
	if err == nil || f.state.Installed || f.removes != 1 {
		t.Fatalf("failed install rollback: %+v %v", r, err)
	}
	if _, e := os.Stat(r.Receipt); !os.IsNotExist(e) {
		t.Fatal("successful rollback left ownership")
	}
	f.failRemove = true
	r, err = m.Execute(context.Background(), "trust", path, false)
	if err == nil {
		t.Fatal("failed rollback hidden")
	}
	if _, e := os.Stat(r.Receipt); e != nil {
		t.Fatal("lost recovery receipt")
	}
	f.failRemove = false
	if _, err = m.Execute(context.Background(), "untrust", path, false); err != nil {
		t.Fatal(err)
	}
}
func TestReceiptFingerprintAndExpiredRemoval(t *testing.T) {
	m, f, path := fixture(t)
	r, err := m.Execute(context.Background(), "trust", path, false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(r.Receipt)
	var saved receipt
	json.Unmarshal(b, &saved)
	saved.SHA256 = strings.Repeat("0", 64)
	b, _ = json.Marshal(saved)
	if err = os.WriteFile(r.Receipt, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Execute(context.Background(), "untrust", path, false); err == nil {
		t.Fatal("accepted tampered receipt")
	}
	expired := filepath.Join(t.TempDir(), "expired")
	if _, err = ca.Init(expired, "expired", time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Execute(context.Background(), "trust", filepath.Join(expired, "ca.crt"), false); err == nil {
		t.Fatal("trusted an expired CA")
	}
	f.state = State{}
	if _, err = m.Execute(context.Background(), "untrust", filepath.Join(expired, "ca.crt"), false); err != nil {
		t.Fatalf("expired certificate blocked removal: %v", err)
	}
}
func TestPublicCertificateValidation(t *testing.T) {
	_, _, path := fixture(t)
	b, _ := os.ReadFile(path)
	key, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "ca.key"))
	for _, invalid := range [][]byte{key, append(append([]byte{}, b...), key...), bytes.Repeat(b, 2), []byte("junk")} {
		if _, err := Parse(invalid); err == nil {
			t.Fatal("accepted non-single-public-CA input")
		}
	}
}
