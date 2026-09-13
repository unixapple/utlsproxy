// Package profiles is the versioned registry of supported upstream ClientHellos.
package profiles

import (
	"crypto/x509"
	"fmt"
	"net"
	"slices"

	utls "github.com/refraction-networking/utls"
)

type Profile struct {
	Name  string   `json:"name"`
	ID    string   `json:"utls_id"`
	ALPN  []string `json:"alpn"`
	Notes string   `json:"notes"`
}

func List() []Profile {
	return []Profile{
		{Name: "chrome-133", ID: "HelloChrome_133", ALPN: []string{"h2", "http/1.1"}, Notes: "TLS 1.3, ML-KEM, shuffled extensions and GREASE; nonempty upstream ALPS settings are rejected (use firefox-120); HTTP behavior remains the original client's"},
		{Name: "firefox-120", ID: "HelloFirefox_120", ALPN: []string{"h2", "http/1.1"}, Notes: "Versioned Firefox ClientHello; HTTP behavior remains the original client's"},
	}
}
func Get(name string) (Profile, error) {
	for _, p := range List() {
		if p.Name == name {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("unsupported profile %q (see profiles list)", name)
}
func New(raw net.Conn, name, host, mode string, offered []string, roots *x509.CertPool) (*utls.UConn, []string, error) {
	if _, err := Get(name); err != nil {
		return nil, nil, err
	}
	id := utls.HelloChrome_133
	if name == "firefox-120" {
		id = utls.HelloFirefox_120
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, nil, err
	}
	var modifications []string
	if mode == "compatible" {
		var allowed []string
		for _, e := range spec.Extensions {
			if a, ok := e.(*utls.ALPNExtension); ok {
				for _, p := range a.AlpnProtocols {
					if slices.Contains(offered, p) {
						allowed = append(allowed, p)
					}
				}
				if !slices.Equal(allowed, a.AlpnProtocols) {
					modifications = append(modifications, "ALPN restricted to client protocols")
				}
				a.AlpnProtocols = allowed
			}
		}
		if len(offered) > 0 && len(allowed) == 0 {
			return nil, nil, fmt.Errorf("no common application protocol")
		}
		filtered := spec.Extensions[:0]
		for _, e := range spec.Extensions {
			switch a := e.(type) {
			case *utls.ALPNExtension:
				if len(allowed) == 0 {
					continue
				}
			case *utls.ApplicationSettingsExtension:
				a.SupportedProtocols = intersection(a.SupportedProtocols, allowed)
				if len(a.SupportedProtocols) == 0 {
					modifications = append(modifications, "ALPS removed with unsupported protocol")
					continue
				}
			case *utls.ApplicationSettingsExtensionNew:
				a.SupportedProtocols = intersection(a.SupportedProtocols, allowed)
				if len(a.SupportedProtocols) == 0 {
					modifications = append(modifications, "ALPS removed with unsupported protocol")
					continue
				}
			}
			filtered = append(filtered, e)
		}
		spec.Extensions = filtered
	}
	u := utls.UClient(raw, &utls.Config{ServerName: host, MinVersion: utls.VersionTLS12, RootCAs: roots}, utls.HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		return nil, nil, err
	}
	return u, modifications, nil
}
func intersection(a, b []string) []string {
	var out []string
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}
func Compatible(negotiated string, offered []string) bool {
	if negotiated == "" {
		return len(offered) == 0 || slices.Contains(offered, "http/1.1")
	}
	return slices.Contains(offered, negotiated) && (negotiated == "h2" || negotiated == "http/1.1")
}
