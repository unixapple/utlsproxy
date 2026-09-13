package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/unixapple/utlsproxy/internal/fsutil"
)

type Info struct {
	SchemaVersion int       `json:"schema_version"`
	Subject       string    `json:"subject"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	SHA256        string    `json:"sha256"`
	Certificate   string    `json:"certificate"`
}

func Inspect(path string) (Info, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Info{}, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return Info{}, errors.New("invalid PEM certificate")
	}
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return Info{}, err
	}
	sum := sha256.Sum256(c.Raw)
	return Info{1, c.Subject.String(), c.NotBefore, c.NotAfter, hex.EncodeToString(sum[:]), path}, nil
}
func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func Init(dir, name string, validity time.Duration) (Info, error) {
	if validity <= 0 || validity > 20*365*24*time.Hour {
		return Info{}, errors.New("CA validity must be positive and at most 20 years")
	}
	if name == "" {
		return Info{}, errors.New("CA name must not be empty")
	}
	if err := fsutil.PrivateDir(dir); err != nil {
		return Info{}, err
	}
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	for _, p := range []string{certPath, keyPath} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return Info{}, fmt.Errorf("refusing to overwrite existing CA output %s", p)
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Info{}, err
	}
	s, err := serial()
	if err != nil {
		return Info{}, err
	}
	now := time.Now()
	t := &x509.Certificate{SerialNumber: s, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(validity), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if err != nil {
		return Info{}, err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return Info{}, err
	}
	if err = fsutil.Exclusive(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600); err != nil {
		return Info{}, err
	}
	if err = fsutil.Exclusive(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		_ = os.Remove(keyPath)
		return Info{}, err
	}
	return Inspect(certPath)
}

type Authority struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	cache map[string]*tls.Certificate
	max   int
}

func Load(certPath, keyPath string) (*Authority, error) {
	if err := fsutil.Regular(keyPath); err != nil {
		return nil, err
	}
	i, err := os.Stat(keyPath)
	if err != nil {
		return nil, err
	}
	if i.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("CA key must have mode 600: %s", keyPath)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("certificate is not a signing CA")
	}
	if now := time.Now(); now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
		return nil, errors.New("CA is not currently valid")
	}
	k, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("expected ECDSA CA key")
	}
	return &Authority{cert: c, key: k, cache: map[string]*tls.Certificate{}, max: 4096}, nil
}
func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if now.Before(a.cert.NotBefore) || !now.Before(a.cert.NotAfter) {
		return nil, errors.New("CA is not currently valid")
	}
	if c := a.cache[host]; c != nil && c.Leaf.NotAfter.After(now.Add(24*time.Hour)) {
		return c, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s, err := serial()
	if err != nil {
		return nil, err
	}
	end := now.Add(30 * 24 * time.Hour)
	if end.After(a.cert.NotAfter) {
		end = a.cert.NotAfter
	}
	start := now.Add(-5 * time.Minute)
	if start.Before(a.cert.NotBefore) {
		start = a.cert.NotBefore
	}
	t := &x509.Certificate{SerialNumber: s, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: start, NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, t, a.cert, &k.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}
	if len(a.cache) >= a.max {
		for key := range a.cache {
			delete(a.cache, key)
			break
		}
	}
	a.cache[host] = c
	return c, nil
}
