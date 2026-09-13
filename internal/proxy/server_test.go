package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/unixapple/utlsproxy/internal/ca"
	"github.com/unixapple/utlsproxy/internal/config"
	"github.com/unixapple/utlsproxy/internal/dns"
)

func shortTemp(t *testing.T) string {
	t.Helper()
	d, e := os.MkdirTemp("/tmp", "utlsproxy-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
func trust(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		t.Fatal("bad CA")
	}
	return p
}
func freeAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}
func TestHTTPSRelayAndReload(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			root := shortTemp(t)
			upCA := filepath.Join(root, "up-ca")
			if _, e := ca.Init(upCA, "upstream", 24*time.Hour); e != nil {
				t.Fatal(e)
			}
			authority, e := ca.Load(filepath.Join(upCA, "ca.crt"), filepath.Join(upCA, "ca.key"))
			if e != nil {
				t.Fatal(e)
			}
			certificate, e := authority.Certificate("origin.example")
			if e != nil {
				t.Fatal(e)
			}
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = http.NewResponseController(w).EnableFullDuplex()
				w.Header().Set("X-Origin-Proto", r.Proto)
				_, _ = io.Copy(w, r.Body)
			}))
			origin.EnableHTTP2 = proto == "h2"
			origin.TLS = &tls.Config{Certificates: []tls.Certificate{*certificate}}
			origin.StartTLS()
			defer origin.Close()
			c := config.Defaults()
			c.Domains = []string{"origin.example"}
			c.Listen = []string{freeAddress(t)}
			c.CA.Cert, c.CA.Key = filepath.Join(root, "ca", "ca.crt"), filepath.Join(root, "ca", "ca.key")
			c.Runtime.StateDir = filepath.Join(root, "state")
			c.Runtime.ControlSocket = filepath.Join(root, "state", "control.sock")
			c.Runtime.ShutdownTimeout = config.Duration(100 * time.Millisecond)
			c.Upstream.ALPNMode = "compatible"
			c.DNS.Mode = "manual"
			c.DNS.Servers = []string{"192.0.2.1:53"}
			if _, e = ca.Init(filepath.Join(root, "ca"), "proxy", 24*time.Hour); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(root, "config.json")
			save := func(c config.Config) {
				b, _ := json.Marshal(c)
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			save(c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, e := New(ctx, c, path, "test", func() (config.Config, error) { return config.Load(path) }, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
			if e != nil {
				t.Fatal(e)
			}
			roots := trust(t, filepath.Join(upCA, "ca.crt"))
			s.dial = func(ctx context.Context, c config.Config, _ *dns.Resolver, host string, offered []string) (*utls.UConn, []string, string, error) {
				raw, e := (&net.Dialer{}).DialContext(ctx, "tcp4", origin.Listener.Addr().String())
				if e != nil {
					return nil, nil, "", e
				}
				u, mods, e := handshakeUpstream(ctx, raw, c, host, offered, roots)
				if e != nil {
					raw.Close()
				}
				return u, mods, origin.Listener.Addr().String(), e
			}
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				select {
				case e := <-done:
					if e != nil {
						t.Error(e)
					}
				case <-time.After(3 * time.Second):
					t.Error("daemon failed to stop")
				}
			})
			deadline := time.Now().Add(3 * time.Second)
			for {
				if _, e := os.Stat(c.Runtime.ControlSocket); e == nil {
					conn, e := net.DialTimeout("tcp4", c.Listen[0], 100*time.Millisecond)
					if e == nil {
						conn.Close()
						break
					}
				}
				if time.Now().After(deadline) {
					t.Fatal("daemon did not listen")
				}
				time.Sleep(5 * time.Millisecond)
			}
			transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: proto == "h2", TLSClientConfig: &tls.Config{RootCAs: trust(t, c.CA.Cert)}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp4", c.Listen[0])
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			payload := bytes.Repeat([]byte("streamed-data"), 16000)
			resp, e := client.Post("https://origin.example/echo", "application/octet-stream", bytes.NewReader(payload))
			if e != nil {
				t.Fatal(e)
			}
			body, e := io.ReadAll(resp.Body)
			resp.Body.Close()
			if e != nil || !bytes.Equal(payload, body) {
				t.Fatalf("stream corrupted: bytes=%d error=%v", len(body), e)
			}
			want := "HTTP/1.1"
			if proto == "h2" {
				want = "HTTP/2.0"
			}
			if resp.Proto != want || resp.Header.Get("X-Origin-Proto") != want {
				t.Fatalf("protocol mismatch %s/%s", resp.Proto, resp.Header.Get("X-Origin-Proto"))
			}
			generation := s.Status().Generation
			c.Listen = []string{"127.0.0.1:1"}
			save(c)
			if e = s.Reload(context.Background()); e == nil {
				t.Fatal("live listener change accepted")
			}
			if s.Status().Generation != generation {
				t.Fatal("bad reload mutated config")
			}
			c = s.Status().Config
			c.Upstream.Profile = "firefox-120"
			save(c)
			if e = s.Reload(context.Background()); e != nil {
				t.Fatal(e)
			}
			if s.Status().Generation != generation+1 {
				t.Fatal("reload generation not advanced")
			}
			transport.CloseIdleConnections()
			resp, e = client.Post("https://origin.example/echo", "application/octet-stream", strings.NewReader("after reload"))
			if e != nil {
				t.Fatal(e)
			}
			body, e = io.ReadAll(resp.Body)
			resp.Body.Close()
			if e != nil || string(body) != "after reload" {
				t.Fatal("relay failed after reload")
			}
			// Separate transports force simultaneous independent TLS tunnels, not
			// merely streams multiplexed over one HTTP/2 connection.
			results := make(chan error, 24)
			for i := 0; i < cap(results); i++ {
				tr := transport.Clone()
				go func() {
					defer tr.CloseIdleConnections()
					cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
					r, err := cl.Post("https://origin.example/concurrent", "application/octet-stream", bytes.NewReader(payload))
					if err == nil {
						var b []byte
						b, err = io.ReadAll(r.Body)
						r.Body.Close()
						if err == nil && (!bytes.Equal(b, payload) || r.Proto != want) {
							err = fmt.Errorf("concurrent stream corrupted or wrong protocol")
						}
					}
					results <- err
				}()
			}
			for i := 0; i < cap(results); i++ {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
			bad := &tls.Config{RootCAs: trust(t, c.CA.Cert), ServerName: "denied.example"}
			conn, e := tls.Dial("tcp4", c.Listen[0], bad)
			if e == nil {
				conn.Close()
				t.Fatal("unconfigured SNI accepted")
			}
		})
	}
}
func TestUpstreamCertificateRejection(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("application bytes reached untrusted upstream") }))
	defer origin.Close()
	raw, e := net.Dial("tcp4", origin.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, e = handshakeUpstream(ctx, raw, config.Defaults(), "example.com", []string{"h2", "http/1.1"}, x509.NewCertPool()); e == nil {
		t.Fatal("accepted untrusted upstream certificate")
	}
}
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	left, e := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	right, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { left.Close(); right.Close() })
	return left, right
}
func TestRelayHalfClose(t *testing.T) {
	client, pclient := tcpPair(t)
	pupstream, origin := tcpPair(t)
	deadline := time.Now().Add(2 * time.Second)
	client.SetDeadline(deadline)
	origin.SetDeadline(deadline)
	var sent, received atomic.Int64
	done := make(chan error, 1)
	go func() { done <- relay(pclient, pupstream, time.Second, &sent, &received) }()
	client.Write([]byte("request"))
	client.CloseWrite()
	request, e := io.ReadAll(origin)
	if e != nil || string(request) != "request" {
		t.Fatal("request did not drain")
	}
	origin.Write([]byte("response after EOF"))
	origin.CloseWrite()
	response, e := io.ReadAll(client)
	if e != nil || string(response) != "response after EOF" {
		t.Fatalf("reverse stream truncated: %q %v", response, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if sent.Load() != 7 || received.Load() != 18 {
		t.Fatalf("wrong counters %d/%d", sent.Load(), received.Load())
	}
}
func TestLoopPrevention(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.10"} {
		if e := CheckDestination(netip.MustParseAddr(ip), "192.0.2.10"); e == nil {
			t.Errorf("accepted %s", ip)
		}
	}
}

func TestHandshakeLimitAndTimeoutCleanup(t *testing.T) {
	c := config.Defaults()
	c.Runtime.MaxConnections = 2
	c.Runtime.HandshakeTimeout = config.Duration(100 * time.Millisecond)
	s := &Server{connections: map[uint64]*active{}, failures: map[string]uint64{}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.current.Store(&snapshot{config: c})
	for i := 0; i < 3; i++ {
		_, raw := tcpPair(t)
		s.accept(raw)
	}
	s.mu.Lock()
	active, rejected := len(s.connections), s.failures["connection_limit"]
	s.mu.Unlock()
	if active != 2 || rejected != 1 {
		t.Fatalf("limit not enforced: active=%d rejected=%d", active, rejected)
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake resources not released")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.connections) != 0 || s.failures["timeout"] != 2 {
		t.Fatalf("timeout cleanup failed: %+v", s.failures)
	}
}
