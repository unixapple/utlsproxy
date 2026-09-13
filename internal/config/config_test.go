package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStrictConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"defaults", `{"version":1}`, true},
		{"unknown", `{"bogus":true}`, false},
		{"case", `{"Version":1}`, false},
		{"duplicate", `{"version":1,"version":1}`, false},
		{"nested_duplicate", `{"dns":{"mode":"auto","mode":"manual"}}`, false},
		{"null", `{"ca":null}`, false},
		{"trailing", `{} {}`, false},
		{"ipv6", `{"listen":["[::1]:443"]}`, false},
		{"empty_domains", `{"domains":[]}`, false},
		{"duplicate_domains", `{"domains":["EXAMPLE.com","example.com."]}`, false},
		{"wildcard", `{"domains":["*.example.com"]}`, false},
		{"zero_timeout", `{"dns":{"timeout":"0s"}}`, false},
		{"manual_no_server", `{"dns":{"mode":"manual"}}`, false},
		{"auto_server", `{"dns":{"servers":["1.1.1.1:53"]}}`, false},
		{"profile", `{"upstream":{"profile":"made-up"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.json")
			if e := os.WriteFile(p, []byte(tc.body), 0600); e != nil {
				t.Fatal(e)
			}
			_, e := Load(p)
			if (e == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, e)
			}
		})
	}
}
func TestPathsAndDomainNormalization(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	e := os.WriteFile(p, []byte(`{"domains":["BÜCHER.example."],"ca":{"cert":"ca/cert.pem","key":"ca/key.pem"}}`), 0600)
	if e != nil {
		t.Fatal(e)
	}
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if c.Domains[0] != "xn--bcher-kva.example" || c.CA.Cert != filepath.Join(dir, "ca", "cert.pem") {
		t.Fatalf("wrong normalized config: %+v", c)
	}
}
func TestReloadBoundary(t *testing.T) {
	a := Defaults()
	b := Defaults()
	b.Upstream.Profile = "firefox-120"
	if RestartRequired(a, b) {
		t.Fatal("profile should reload")
	}
	b.Runtime.ControlSocket = "/another/socket"
	if !RestartRequired(a, b) {
		t.Fatal("socket change must require restart")
	}
}
