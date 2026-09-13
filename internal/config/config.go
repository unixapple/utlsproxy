// Package config defines the on-disk configuration and its validated defaults.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/unixapple/utlsproxy/internal/profiles"
	"golang.org/x/net/idna"
)

type Duration time.Duration

func (d Duration) Value() time.Duration         { return time.Duration(d) }
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

type DNS struct {
	Mode            string   `json:"mode"`
	Servers         []string `json:"servers"`
	RefreshInterval Duration `json:"refresh_interval"`
	Timeout         Duration `json:"timeout"`
	CacheSize       int      `json:"cache_size"`
}
type Config struct {
	Version  int      `json:"version"`
	Listen   []string `json:"listen"`
	Domains  []string `json:"domains"`
	Upstream struct {
		Port     int    `json:"port"`
		Profile  string `json:"profile"`
		ALPNMode string `json:"alpn_mode"`
	} `json:"upstream"`
	DNS DNS `json:"dns"`
	CA  struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"ca"`
	Hosts struct {
		Address string `json:"address"`
	} `json:"hosts"`
	Access struct {
		ClientCIDRs []string `json:"client_cidrs"`
	} `json:"access"`
	Runtime struct {
		StateDir         string   `json:"state_dir"`
		ControlSocket    string   `json:"control_socket"`
		MaxConnections   int      `json:"max_connections"`
		HandshakeTimeout Duration `json:"handshake_timeout"`
		IdleTimeout      Duration `json:"idle_timeout"`
		ShutdownTimeout  Duration `json:"shutdown_timeout"`
	} `json:"runtime"`
	Log struct {
		Level  string `json:"level"`
		Format string `json:"format"`
	} `json:"log"`
}

type Paths struct{ Config, State, CA, Socket, Executable, Service, Log string }

func PlatformPaths() Paths {
	p := Paths{Config: "/etc/utlsproxy/config.json", State: "/var/lib/utlsproxy", CA: "/var/lib/utlsproxy/ca", Socket: "/var/run/utlsproxy/control.sock", Executable: "/usr/local/bin/utlsproxy", Service: "/etc/systemd/system/utlsproxy.service"}
	if runtime.GOOS == "darwin" {
		base := "/Library/Application Support/utlsproxy"
		p.Config, p.State, p.CA = base+"/config.json", base+"/state", base+"/ca"
		p.Service, p.Log = "/Library/LaunchDaemons/local.utlsproxy.plist", "/var/log/utlsproxy/utlsproxy.log"
	}
	return p
}
func Defaults() Config {
	p := PlatformPaths()
	c := Config{Version: 1, Listen: []string{"127.0.0.1:443"}, Domains: []string{"tls.peet.ws"}}
	c.Upstream.Port, c.Upstream.Profile, c.Upstream.ALPNMode = 443, "chrome-133", "compatible"
	c.DNS = DNS{Mode: "auto", Servers: []string{}, RefreshInterval: Duration(30 * time.Second), Timeout: Duration(3 * time.Second), CacheSize: 1024}
	c.CA.Cert, c.CA.Key = filepath.Join(p.CA, "ca.crt"), filepath.Join(p.CA, "ca.key")
	c.Hosts.Address = "127.0.0.1"
	c.Access.ClientCIDRs = []string{"127.0.0.0/8"}
	c.Runtime.StateDir, c.Runtime.ControlSocket = p.State, p.Socket
	c.Runtime.MaxConnections = 1024
	c.Runtime.HandshakeTimeout, c.Runtime.IdleTimeout, c.Runtime.ShutdownTimeout = Duration(15*time.Second), Duration(5*time.Minute), Duration(10*time.Second)
	c.Log.Level, c.Log.Format = "info", "json"
	return c
}

// Load rejects duplicate keys and nulls before decoding into defaults.
func Load(path string) (Config, error) {
	c := Defaults()
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return c, err
	}
	if len(b) > 1024*1024 {
		return c, errors.New("configuration exceeds 1 MiB")
	}
	if err := CheckJSON(b); err != nil {
		return c, err
	}
	if err := exactFields(b, reflect.TypeOf(c)); err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return c, err
	}
	for _, p := range []*string{&c.CA.Cert, &c.CA.Key, &c.Runtime.StateDir, &c.Runtime.ControlSocket} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	return c, c.Validate()
}
func exactFields(b []byte, t reflect.Type) error {
	if t.Kind() != reflect.Struct {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	known := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		known[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
	}
	for name, value := range fields {
		field, ok := known[name]
		if !ok {
			return fmt.Errorf("unknown configuration field %q", name)
		}
		if err := exactFields(value, field); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}
func CheckJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if t == nil {
			return errors.New("null configuration values are not allowed")
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					s, ok := k.(string)
					if !ok {
						return errors.New("invalid object key")
					}
					if seen[s] {
						return fmt.Errorf("duplicate JSON key %q", s)
					}
					seen[s] = true
					if err := walk(); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(); err != nil {
						return err
					}
				}
			default:
				return errors.New("unexpected JSON delimiter")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("configuration must contain one JSON value")
	}
	return nil
}
func Domain(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	a, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", err
	}
	if len(a) == 0 || len(a) > 253 {
		return "", errors.New("invalid domain length")
	}
	if _, err := netip.ParseAddr(a); err == nil {
		return "", errors.New("domain must not be an IP literal")
	}
	for _, label := range strings.Split(a, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", s)
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", fmt.Errorf("invalid domain %q", s)
			}
		}
	}
	return a, nil
}
func Endpoint(s string, listener bool) error {
	a, err := netip.ParseAddrPort(s)
	if err != nil || !a.Addr().Is4() || a.Port() == 0 {
		return fmt.Errorf("expected IPv4:port, got %q", s)
	}
	if a.Addr().IsMulticast() || a.Addr() == netip.MustParseAddr("255.255.255.255") || (!listener && a.Addr().IsUnspecified()) {
		return fmt.Errorf("invalid endpoint %q", s)
	}
	return nil
}
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported configuration version %d", c.Version)
	}
	if len(c.Listen) == 0 || len(c.Listen) > 16 {
		return errors.New("listen requires 1..16 IPv4 endpoints")
	}
	seen := map[string]bool{}
	for _, s := range c.Listen {
		if err := Endpoint(s, true); err != nil {
			return err
		}
		if seen[s] {
			return fmt.Errorf("duplicate listener %s", s)
		}
		seen[s] = true
	}
	if len(c.Domains) == 0 || len(c.Domains) > 4096 {
		return errors.New("domains requires 1..4096 exact names")
	}
	seen = map[string]bool{}
	for i, s := range c.Domains {
		d, err := Domain(s)
		if err != nil {
			return err
		}
		if seen[d] {
			return fmt.Errorf("duplicate domain %s", d)
		}
		seen[d] = true
		c.Domains[i] = d
	}
	if _, err := profiles.Get(c.Upstream.Profile); err != nil {
		return err
	}
	if c.Upstream.Port < 1 || c.Upstream.Port > 65535 {
		return errors.New("upstream.port must be 1..65535")
	}
	if c.Upstream.ALPNMode != "strict" && c.Upstream.ALPNMode != "compatible" {
		return errors.New("alpn_mode must be strict or compatible")
	}
	if c.DNS.Mode != "auto" && c.DNS.Mode != "manual" {
		return errors.New("dns.mode must be auto or manual")
	}
	if (c.DNS.Mode == "auto" && len(c.DNS.Servers) != 0) || (c.DNS.Mode == "manual" && len(c.DNS.Servers) == 0) {
		return errors.New("DNS auto requires no servers; manual requires servers")
	}
	if len(c.DNS.Servers) > 16 {
		return errors.New("at most 16 DNS servers allowed")
	}
	for _, s := range c.DNS.Servers {
		if err := Endpoint(s, false); err != nil {
			return err
		}
	}
	if c.DNS.CacheSize < 0 || c.DNS.CacheSize > 65536 {
		return errors.New("DNS cache_size must be 0..65536")
	}
	if len(c.Access.ClientCIDRs) == 0 {
		return errors.New("client_cidrs must not be empty")
	}
	for _, s := range c.Access.ClientCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("invalid IPv4 client CIDR %q", s)
		}
	}
	a, err := netip.ParseAddr(c.Hosts.Address)
	if err != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a == netip.MustParseAddr("255.255.255.255") {
		return errors.New("hosts.address must be a unicast IPv4 address")
	}
	for _, p := range []string{c.CA.Cert, c.CA.Key, c.Runtime.StateDir, c.Runtime.ControlSocket} {
		if p == "" {
			return errors.New("CA and runtime paths must not be empty")
		}
	}
	if len(c.Runtime.ControlSocket) > 100 {
		return errors.New("control socket path exceeds portable 100-byte limit")
	}
	if c.Runtime.MaxConnections < 1 || c.Runtime.MaxConnections > 65536 {
		return errors.New("max_connections must be 1..65536")
	}
	for _, d := range []Duration{c.DNS.Timeout, c.DNS.RefreshInterval, c.Runtime.HandshakeTimeout, c.Runtime.IdleTimeout, c.Runtime.ShutdownTimeout} {
		if d.Value() <= 0 || d.Value() > 24*time.Hour {
			return errors.New("timeouts and refresh interval must be positive and at most 24h")
		}
	}
	if c.DNS.RefreshInterval.Value() < time.Second {
		return errors.New("DNS refresh interval must be at least 1s")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("log.level must be debug, info, warn or error")
	}
	if c.Log.Format != "json" && c.Log.Format != "text" {
		return errors.New("log.format must be json or text")
	}
	return nil
}
func (c Config) AllowsDomain(s string) bool {
	for _, d := range c.Domains {
		if d == s {
			return true
		}
	}
	return false
}
func (c Config) AllowsClient(a netip.Addr) bool {
	for _, s := range c.Access.ClientCIDRs {
		p, _ := netip.ParsePrefix(s)
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}
func RestartRequired(a, b Config) bool {
	return !reflect.DeepEqual(a.Listen, b.Listen) || a.Upstream.Port != b.Upstream.Port || a.CA != b.CA || a.Runtime.StateDir != b.Runtime.StateDir || a.Runtime.ControlSocket != b.Runtime.ControlSocket || a.Log.Format != b.Log.Format
}
