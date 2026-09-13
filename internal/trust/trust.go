// Package trust manages explicitly requested system CA trust. It never reads a
// private key and never takes ownership of a previously installed certificate.
package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/unixapple/utlsproxy/internal/fsutil"
)

var ErrNotTrusted = errors.New("CA is not trusted for TLS in the checked system store")

type Certificate struct {
	X509   *x509.Certificate
	PEM    []byte
	SHA256 string
}

func (c Certificate) validNow() bool {
	return !time.Now().Before(c.X509.NotBefore) && time.Now().Before(c.X509.NotAfter)
}

func Parse(b []byte) (Certificate, error) {
	b = bytes.TrimSpace(b)
	if !bytes.HasPrefix(b, []byte("-----BEGIN CERTIFICATE-----")) {
		return Certificate{}, errors.New("expected one public PEM CA certificate, not a private key or bundle")
	}
	p, rest := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return Certificate{}, errors.New("expected exactly one PEM certificate")
	}
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return Certificate{}, err
	}
	if !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 || c.CheckSignatureFrom(c) != nil {
		return Certificate{}, errors.New("trust operations require a self-signed signing CA")
	}
	sum := sha256.Sum256(c.Raw)
	return Certificate{c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), hex.EncodeToString(sum[:])}, nil
}

func Load(path string) (Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return Certificate{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return Certificate{}, err
	}
	if len(b) > 1024*1024 {
		return Certificate{}, errors.New("CA certificate exceeds 1 MiB")
	}
	return Parse(b)
}

type State struct {
	Installed bool `json:"installed"`
	Trusted   bool `json:"trusted"`
}
type Store struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Scope  string `json:"scope"`
}
type backend interface {
	Store(Certificate) Store
	Inspect(context.Context, Certificate) (State, error)
	Add(context.Context, Certificate, string) error
	Remove(context.Context, Certificate, string) error
}
type receipt struct {
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
	Store   Store  `json:"store"`
	Phase   string `json:"phase"`
}
type Report struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	Certificate   string `json:"certificate"`
	Subject       string `json:"subject"`
	SHA256        string `json:"sha256"`
	Store         Store  `json:"store"`
	State
	Managed             bool   `json:"managed"`
	OwnershipKnown      bool   `json:"ownership_known"`
	Receipt             string `json:"receipt"`
	RecoveryCertificate string `json:"recovery_certificate"`
	DryRun              bool   `json:"dry_run"`
	Changed             bool   `json:"changed"`
	Message             string `json:"message"`
}
type Manager struct {
	backend backend
	dir     string
	euid    func() int
	protect func(string) error
}

func (m *Manager) readReceipt(path string, c Certificate) (*receipt, error) {
	if err := fsutil.Regular(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r receipt
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Version != 1 || r.SHA256 != c.SHA256 || r.Store != m.backend.Store(c) || (r.Phase != "pending" && r.Phase != "installed") {
		return nil, errors.New("invalid or mismatched trust receipt; refusing to change trust")
	}
	return &r, nil
}

func (m *Manager) Execute(ctx context.Context, action, path string, dry bool) (Report, error) {
	r := Report{SchemaVersion: 1, Action: action, DryRun: dry, OwnershipKnown: true}
	if action != "trust" && action != "untrust" && action != "trust-status" {
		return r, errors.New("unknown trust action")
	}
	c, err := Load(path)
	if err != nil {
		return r, err
	}
	r.Certificate, err = filepath.Abs(path)
	if err != nil {
		return r, err
	}
	r.Subject, r.SHA256, r.Store = c.X509.Subject.String(), c.SHA256, m.backend.Store(c)
	r.Receipt = filepath.Join(m.dir, c.SHA256+".json")
	r.RecoveryCertificate = filepath.Join(m.dir, c.SHA256+".crt")
	if action == "trust" && !c.validNow() {
		return r, errors.New("cannot trust a CA that is not currently valid")
	}
	if action != "trust-status" && !dry {
		if m.euid() != 0 {
			return r, os.ErrPermission
		}
		if err = m.protect(m.dir); err != nil {
			return r, err
		}
		unlock, e := fsutil.Lock(filepath.Join(m.dir, "trust.lock"))
		if e != nil {
			return r, e
		}
		defer unlock()
	}
	owned, err := m.readReceipt(r.Receipt, c)
	if err != nil {
		if action == "trust-status" && errors.Is(err, os.ErrPermission) {
			r.OwnershipKnown = false
		} else {
			return r, err
		}
	}
	r.Managed = owned != nil
	if owned != nil {
		stored, e := Load(r.RecoveryCertificate)
		if e != nil {
			return r, fmt.Errorf("trust recovery certificate: %w", e)
		}
		if stored.SHA256 != c.SHA256 {
			return r, errors.New("trust recovery certificate was modified")
		}
	}
	r.State, err = m.backend.Inspect(ctx, c)
	if err != nil {
		return r, err
	}
	if action == "trust-status" {
		r.Message = "Checks the system store/native TLS policy, not every browser or application trust store."
		if !r.Trusted {
			return r, ErrNotTrusted
		}
		return r, nil
	}
	if action == "trust" {
		if r.Trusted {
			r.Message = "Already trusted; no trust settings changed."
			if !r.Managed {
				r.Message += " Pre-existing trust remains unmanaged and will not be removed by ca untrust."
			}
			return r, nil
		}
		if r.Installed && owned == nil {
			return r, errors.New("this exact CA already exists but is not trusted; configure its trust manually (utlsproxy will not take over an unmanaged certificate)")
		}
		if dry {
			r.Message = "Would install this exact public CA and update system trust; no changes made."
			return r, nil
		}
		if owned == nil {
			if err = fsutil.Exclusive(r.RecoveryCertificate, c.PEM, 0644); err != nil {
				return r, fmt.Errorf("trust recovery snapshot: %w", err)
			}
			owned = &receipt{1, c.SHA256, r.Store, "pending"}
			b, _ := json.MarshalIndent(owned, "", "  ")
			if err = fsutil.Exclusive(r.Receipt, b, 0600); err != nil {
				_ = os.Remove(r.RecoveryCertificate)
				return r, err
			}
		}
		r.Managed = true
		err = m.backend.Add(ctx, c, r.RecoveryCertificate)
		if err == nil {
			r.State, err = m.backend.Inspect(ctx, c)
			if err == nil && !r.Trusted {
				err = ErrNotTrusted
			}
		}
		if err != nil {
			// The pending receipt survives failed rollback, allowing exact-CA
			// recovery even if the original configuration or certificate is lost.
			recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			rollback := m.backend.Remove(recovery, c, r.RecoveryCertificate)
			if rollback == nil {
				rollback = m.removeReceipt(r)
				if rollback == nil {
					r.Managed = false
				}
			}
			if state, probeErr := m.backend.Inspect(recovery, c); probeErr == nil {
				r.State = state
			} else {
				rollback = errors.Join(rollback, probeErr)
			}
			r.Message = "Trust installation failed; rollback attempted. If recovery files remain, retry ca untrust --cert with the recovery certificate."
			return r, errors.Join(err, rollback)
		}
		owned.Phase = "installed"
		b, _ := json.MarshalIndent(owned, "", "  ")
		if err = fsutil.Atomic(r.Receipt, b, 0600); err != nil {
			return r, fmt.Errorf("CA trusted; pending receipt retained: %w", err)
		}
		r.Changed, r.Message = true, "Public CA installed and trusted. Restart affected clients; private keys were not accessed."
		return r, nil
	}
	if owned == nil {
		if r.Installed || r.Trusted {
			return r, errors.New("CA was not installed by utlsproxy; refusing to remove unmanaged trust (use the original installation method)")
		}
		r.Message = "No managed installation or trusted CA found; nothing to remove."
		return r, nil
	}
	if dry {
		r.Message = "Would remove only this receipt-owned certificate and update system trust; no changes made."
		return r, nil
	}
	if err = m.backend.Remove(ctx, c, r.RecoveryCertificate); err != nil {
		return r, fmt.Errorf("removal failed; receipt retained for retry: %w", err)
	}
	r.State, err = m.backend.Inspect(ctx, c)
	if err != nil {
		return r, fmt.Errorf("removal verification failed; receipt retained: %w", err)
	}
	if r.Installed {
		return r, errors.New("owned certificate remains installed after removal; receipt retained for retry")
	}
	if err = m.removeReceipt(r); err != nil {
		return r, err
	}
	r.Managed, r.Changed, r.Message = false, true, "Removed the managed trust installation; original CA files and private key are unchanged."
	if r.Trusted {
		r.Message += " The CA is still trusted through another installation; that trust was preserved."
	}
	return r, nil
}

func (m *Manager) removeReceipt(r Report) error {
	// Delete only the two exact files owned by this fingerprint's receipt.
	if err := os.Remove(r.Receipt); err != nil {
		return err
	}
	return os.Remove(r.RecoveryCertificate)
}
