package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/unixapple/utlsproxy/internal/ca"
	"github.com/unixapple/utlsproxy/internal/config"
	"github.com/unixapple/utlsproxy/internal/control"
	"github.com/unixapple/utlsproxy/internal/dns"
	"github.com/unixapple/utlsproxy/internal/fsutil"
	"github.com/unixapple/utlsproxy/internal/proxy"
)

const fingerprintURL = "https://tls.peet.ws/api/all"

type fingerprint struct {
	HTTP string `json:"http_version"`
	TLS  struct {
		JA3 string `json:"ja3_hash"`
		JA4 string `json:"ja4"`
	} `json:"tls"`
	HTTP2 struct {
		Hash string `json:"akamai_fingerprint_hash"`
	} `json:"http2"`
}

func fetchFingerprint(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) (fingerprint, error) {
	transport := &http.Transport{Proxy: nil, DialContext: dial, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("unexpected fingerprint endpoint redirect")
	}}
	req, e := http.NewRequestWithContext(ctx, "GET", fingerprintURL, nil)
	if e != nil {
		return fingerprint{}, e
	}
	req.Header.Set("User-Agent", "utlsproxy-fingerprint-test/1")
	r, e := client.Do(req)
	if e != nil {
		return fingerprint{}, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fingerprint{}, fmt.Errorf("fingerprint endpoint returned %s", r.Status)
	}
	var result fingerprint
	if e = json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&result); e != nil {
		return result, e
	}
	if result.TLS.JA3 == "" || result.TLS.JA4 == "" {
		return result, errors.New("fingerprint response missing JA3/JA4")
	}
	return result, nil
}
func temporaryTest(out, errOut io.Writer, version, profile, dnsOption string, asJSON bool) (retErr error) {
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, deadlineCancel := context.WithTimeout(signalCtx, 90*time.Second)
	defer deadlineCancel()
	// This directory is created by this command; its contents are never reused.
	dir, e := os.MkdirTemp("/tmp", "utlsproxy-test-")
	if e != nil {
		return e
	}
	defer func() { retErr = errors.Join(retErr, os.RemoveAll(dir)) }()
	c := config.Defaults()
	c.Domains = []string{"tls.peet.ws"}
	c.Upstream.Profile = profile
	c.Runtime.StateDir = filepath.Join(dir, "state")
	c.Runtime.ControlSocket = filepath.Join(dir, "state", "control.sock")
	c.Runtime.ShutdownTimeout = config.Duration(200 * time.Millisecond)
	c.CA.Cert, c.CA.Key = filepath.Join(dir, "ca", "ca.crt"), filepath.Join(dir, "ca", "ca.key")
	if dnsOption != "auto" {
		c.DNS.Mode, c.DNS.Servers = "manual", strings.Split(dnsOption, ",")
	}
	reservation, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return e
	}
	address := reservation.Addr().String()
	reservation.Close()
	c.Listen = []string{address}
	if e = c.Validate(); e != nil {
		return invalid(e)
	}
	if _, e = ca.Init(filepath.Dir(c.CA.Cert), "utlsproxy temporary test CA", 24*time.Hour); e != nil {
		return e
	}
	configPath := filepath.Join(dir, "config.json")
	b, _ := json.Marshal(c)
	if e = fsutil.Exclusive(configPath, b, 0600); e != nil {
		return e
	}
	logger := slog.New(slog.NewTextHandler(errOut, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s, e := proxy.New(ctx, c, configPath, version, func() (config.Config, error) { return c, nil }, logger, nil)
	if e != nil {
		return e
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			retErr = errors.Join(retErr, err)
		case <-time.After(5 * time.Second):
			retErr = errors.Join(retErr, errors.New("temporary daemon did not stop promptly"))
		}
	}()
	for {
		select {
		case err := <-done:
			done <- nil
			return fmt.Errorf("temporary daemon startup: %w", err)
		default:
		}
		var status proxy.Status
		probe, cancelProbe := context.WithTimeout(ctx, 200*time.Millisecond)
		e = control.Request(probe, c.Runtime.ControlSocket, "GET", "/v1/status", &status)
		cancelProbe()
		if e == nil {
			if status.Health != "ready" {
				return fmt.Errorf("automatic DNS unavailable: %v", status.Reasons)
			}
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	resolver := dns.New(ctx, c.DNS)
	ips, e := resolver.Lookup(ctx, "tls.peet.ws")
	if e != nil {
		return e
	}
	baselineDial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var last error
		for _, ip := range ips {
			if e := proxy.CheckDestination(ip, c.Hosts.Address); e != nil {
				last = e
				continue
			}
			conn, e := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), "443"))
			if e == nil {
				return conn, nil
			}
			last = e
		}
		return nil, last
	}
	if !asJSON {
		fmt.Fprintf(out, "Testing %s with profile %s on %s\n", fingerprintURL, profile, address)
	}
	direct, e := fetchFingerprint(ctx, baselineDial, nil)
	if e != nil {
		return fmt.Errorf("direct request: %w", e)
	}
	certBytes, e := os.ReadFile(c.CA.Cert)
	if e != nil {
		return e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certBytes) {
		return errors.New("invalid temporary CA")
	}
	proxied, e := fetchFingerprint(ctx, func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	}, roots)
	if e != nil {
		return fmt.Errorf("proxied request: %w", e)
	}
	changed := direct.TLS.JA4 != proxied.TLS.JA4
	preserved := direct.HTTP2.Hash != "" && direct.HTTP2.Hash == proxied.HTTP2.Hash
	report := map[string]any{"schema_version": 1, "target": fingerprintURL, "profile": profile, "direct": direct, "proxied": proxied, "tls_fingerprint_changed": changed, "http2_fingerprint_preserved": preserved, "system_changes": false, "temporary_files_removed_on_exit": true}
	if asJSON {
		_ = emit(out, report)
	} else {
		fmt.Fprintf(out, "Direct JA4:  %s\nProxied JA4: %s\nTLS fingerprint changed: %t\nHTTP/2 fingerprint preserved: %t\nTemporary proxy and CA are cleaned up on exit; hosts, trust and services were not changed.\n", direct.TLS.JA4, proxied.TLS.JA4, changed, preserved)
	}
	if !changed || !preserved {
		return errors.New("fingerprint comparison did not meet expected TLS-change / HTTP2-preservation checks")
	}
	return nil
}
