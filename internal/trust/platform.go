package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/unixapple/utlsproxy/internal/config"
	"github.com/unixapple/utlsproxy/internal/fsutil"
)

type runner func(context.Context, []byte, string, ...string) ([]byte, error)

func command(ctx context.Context, input []byte, path string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, path, args...)
	c.Stdin = bytes.NewReader(input)
	b, err := c.CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("%s %v: %w: %s", path, args, err, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func New() (*Manager, error) {
	var b backend
	switch runtime.GOOS {
	case "darwin":
		b = &macBackend{run: command, keychain: "/Library/Keychains/System.keychain"}
	case "linux":
		release, err := os.ReadFile("/etc/os-release")
		if err != nil {
			return nil, err
		}
		b, err = linuxStore(string(release), command)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("CA trust unsupported on %s; import the public CA manually", runtime.GOOS)
	}
	return &Manager{backend: b, dir: filepath.Join(filepath.Dir(config.PlatformPaths().Config), "trust"), euid: os.Geteuid, protect: func(path string) error {
		if err := fsutil.PrivateDir(path); err != nil {
			return err
		}
		return fsutil.RootOwned(path)
	}}, nil
}

func containsCertificate(b []byte, fingerprint string) bool {
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			return false
		}
		b = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) == fingerprint {
			return true
		}
	}
}

type macBackend struct {
	run      runner
	keychain string
}

func (m *macBackend) Store(Certificate) Store {
	return Store{"macos-keychain", m.keychain, "SSL only; admin trust domain"}
}
func missingItem(b []byte) bool {
	s := strings.ToLower(string(b))
	return strings.Contains(s, "the specified item could not be found") || strings.Contains(s, "no trust settings were found")
}
func (m *macBackend) Inspect(ctx context.Context, c Certificate) (State, error) {
	b, err := m.run(ctx, nil, "/usr/bin/security", "find-certificate", "-a", "-p", m.keychain)
	if err != nil && !missingItem(b) {
		return State{}, err
	}
	s := State{Installed: containsCertificate(b, c.SHA256)}
	// A supplied root (-r) would incorrectly make this an implicit trust test.
	// -l allows checking a CA, -L prohibits fetching from the network, and the
	// input is the exact parsed certificate snapshot, never its private key.
	_, err = m.run(ctx, c.PEM, "/usr/bin/security", "verify-cert", "-c", "/dev/stdin", "-p", "ssl", "-l", "-L", "-k", m.keychain, "-q")
	if err != nil {
		if ctx.Err() != nil {
			return s, ctx.Err()
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return s, err
		}
	}
	s.Trusted = err == nil
	return s, nil
}
func (m *macBackend) Add(ctx context.Context, c Certificate, snapshot string) error {
	_, err := m.run(ctx, nil, "/usr/bin/security", "add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl", "-k", m.keychain, snapshot)
	return err
}
func (m *macBackend) Remove(ctx context.Context, c Certificate, snapshot string) error {
	b, err := m.run(ctx, nil, "/usr/bin/security", "remove-trusted-cert", "-d", snapshot)
	if err != nil && !missingItem(b) {
		return err
	}
	b, err = m.run(ctx, nil, "/usr/bin/security", "delete-certificate", "-Z", c.SHA256, m.keychain)
	if err != nil && !missingItem(b) {
		return err
	}
	return nil
}

type linuxBackend struct {
	kind, dir, bundle, tool string
	args                    []string
	run                     runner
	protect                 func(string) error
	checkTool               func(string) error
}

func linuxStore(release string, run runner) (*linuxBackend, error) {
	ids := ""
	for _, line := range strings.Split(release, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && (k == "ID" || k == "ID_LIKE") {
			ids += " " + strings.Trim(strings.TrimSpace(v), "\"'")
		}
	}
	for _, id := range strings.Fields(ids) {
		var b *linuxBackend
		switch id {
		case "debian", "ubuntu":
			b = &linuxBackend{kind: "debian-ca-certificates", dir: "/usr/local/share/ca-certificates", bundle: "/etc/ssl/certs/ca-certificates.crt", tool: "/usr/sbin/update-ca-certificates"}
		case "fedora", "rhel", "centos", "rocky", "almalinux":
			b = &linuxBackend{kind: "fedora-ca-trust", dir: "/etc/pki/ca-trust/source/anchors", bundle: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", tool: "/usr/bin/update-ca-trust", args: []string{"extract"}}
		case "arch":
			b = &linuxBackend{kind: "arch-ca-trust", dir: "/etc/ca-certificates/trust-source/anchors", bundle: "/etc/ca-certificates/extracted/tls-ca-bundle.pem", tool: "/usr/bin/update-ca-trust", args: []string{"extract"}}
		}
		if b != nil {
			b.run = run
			b.checkTool = fsutil.RootOwned
			b.protect = func(path string) error {
				if err := os.MkdirAll(path, 0755); err != nil {
					return err
				}
				return fsutil.RootOwned(path)
			}
			return b, nil
		}
	}
	return nil, errors.New("unsupported Linux trust store; supported: Debian/Ubuntu, Fedora/RHEL and Arch Linux families; install ca.crt manually")
}
func (l *linuxBackend) Store(c Certificate) Store {
	return Store{l.kind, filepath.Join(l.dir, "utlsproxy-"+c.SHA256+".crt"), "system CA trust (not restricted to SSL)"}
}
func (l *linuxBackend) anchor(c Certificate) (bool, error) {
	path := l.Store(c).Target
	if err := fsutil.Regular(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	stored, err := Load(path)
	if err != nil {
		return false, err
	}
	if stored.SHA256 != c.SHA256 {
		return false, errors.New("trust anchor path contains a different certificate; refusing replacement/removal")
	}
	return true, nil
}
func (l *linuxBackend) Inspect(ctx context.Context, c Certificate) (State, error) {
	present, err := l.anchor(c)
	if err != nil {
		return State{}, err
	}
	b, err := os.ReadFile(l.bundle)
	if err != nil && !os.IsNotExist(err) {
		return State{}, err
	}
	return State{present, c.validNow() && containsCertificate(b, c.SHA256)}, nil
}
func (l *linuxBackend) refresh(ctx context.Context) error {
	if err := l.checkTool(l.tool); err != nil {
		return fmt.Errorf("install the distribution ca-certificates package: %w", err)
	}
	_, err := l.run(ctx, nil, l.tool, l.args...)
	return err
}
func (l *linuxBackend) Add(ctx context.Context, c Certificate, snapshot string) error {
	if err := l.checkTool(l.tool); err != nil {
		return fmt.Errorf("install the distribution ca-certificates package: %w", err)
	}
	if err := l.protect(l.dir); err != nil {
		return err
	}
	present, err := l.anchor(c)
	if err != nil {
		return err
	}
	if !present {
		if err = fsutil.Exclusive(l.Store(c).Target, c.PEM, 0644); err != nil {
			return err
		}
	}
	return l.refresh(ctx)
}
func (l *linuxBackend) Remove(ctx context.Context, c Certificate, snapshot string) error {
	if err := l.protect(l.dir); err != nil {
		return err
	}
	present, err := l.anchor(c)
	if err != nil {
		return err
	}
	if present {
		if err = os.Remove(l.Store(c).Target); err != nil {
			return err
		}
	}
	// Refresh even after a previous interrupted removal deleted the source file.
	return l.refresh(ctx)
}
