package ca

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerationTrustAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	info, e := Init(dir, "Test CA", 365*24*time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if info.SHA256 == "" {
		t.Fatal("missing fingerprint")
	}
	key := filepath.Join(dir, "ca.key")
	original, e := os.ReadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Init(dir, "replacement", time.Hour); e == nil {
		t.Fatal("overwrote CA")
	}
	after, _ := os.ReadFile(key)
	if !bytes.Equal(original, after) {
		t.Fatal("key changed")
	}
	stat, _ := os.Stat(key)
	if stat.Mode().Perm() != 0600 {
		t.Fatal("insecure key mode")
	}
	a, e := Load(filepath.Join(dir, "ca.crt"), key)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := a.Certificate("example.com")
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	if _, e = leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "example.com"}); e != nil {
		t.Fatal(e)
	}
	if _, e = leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "other.example"}); e == nil {
		t.Fatal("certificate valid for unconfigured name")
	}
	second, e := a.Certificate("example.com")
	if e != nil || second != leaf {
		t.Fatal("leaf cache missed")
	}
	if e = os.Chmod(key, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(filepath.Join(dir, "ca.crt"), key); e == nil {
		t.Fatal("insecure key accepted")
	}
}
func TestPartialCAIsPreserved(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "ca.crt")
	if e := os.WriteFile(path, []byte("existing"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := Init(dir, "test", time.Hour); e == nil {
		t.Fatal("accepted partial CA")
	}
	if _, e := os.Stat(filepath.Join(dir, "ca.key")); !os.IsNotExist(e) {
		t.Fatal("created key beside partial CA")
	}
}
