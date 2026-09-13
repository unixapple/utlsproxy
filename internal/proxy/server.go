package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/unixapple/utlsproxy/internal/ca"
	"github.com/unixapple/utlsproxy/internal/config"
	"github.com/unixapple/utlsproxy/internal/control"
	"github.com/unixapple/utlsproxy/internal/dns"
	"github.com/unixapple/utlsproxy/internal/fsutil"
)

type snapshot struct {
	config     config.Config
	authority  *ca.Authority
	generation uint64
}
type Connection struct {
	ID            uint64    `json:"id"`
	Started       time.Time `json:"started"`
	Client        string    `json:"client"`
	SNI           string    `json:"sni,omitempty"`
	Upstream      string    `json:"upstream,omitempty"`
	Profile       string    `json:"profile"`
	Modifications []string  `json:"modifications,omitempty"`
	ClientTLS     uint16    `json:"client_tls,omitempty"`
	UpstreamTLS   uint16    `json:"upstream_tls,omitempty"`
	ClientALPN    string    `json:"client_alpn"`
	UpstreamALPN  string    `json:"upstream_alpn"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
	State         string    `json:"state"`
}
type active struct {
	record         Connection
	raw            net.Conn
	cancel         context.CancelFunc
	sent, received atomic.Int64
}
type Status struct {
	SchemaVersion int               `json:"schema_version"`
	PID           int               `json:"pid"`
	Version       string            `json:"version"`
	Started       time.Time         `json:"started"`
	Uptime        string            `json:"uptime"`
	Health        string            `json:"health"`
	Reasons       []string          `json:"reasons,omitempty"`
	ConfigPath    string            `json:"config_path"`
	Config        config.Config     `json:"config"`
	Generation    uint64            `json:"configuration_generation"`
	Active        int               `json:"active_connections"`
	Total         uint64            `json:"total_connections"`
	BytesSent     int64             `json:"bytes_sent"`
	BytesReceived int64             `json:"bytes_received"`
	Failures      map[string]uint64 `json:"failures"`
	DNS           dns.State         `json:"dns"`
}
type Server struct {
	current        atomic.Pointer[snapshot]
	resolver       *dns.Resolver
	log            *slog.Logger
	level          *slog.LevelVar
	version, path  string
	load           func() (config.Config, error)
	reloadMu       sync.Mutex
	mu             sync.Mutex
	connections    map[uint64]*active
	failures       map[string]uint64
	started        time.Time
	total, next    uint64
	sent, received int64
	listeners      []net.Listener
	stopping       bool
	wg             sync.WaitGroup
	dial           func(context.Context, config.Config, *dns.Resolver, string, []string) (*utls.UConn, []string, string, error)
}

func New(ctx context.Context, c config.Config, path, version string, load func() (config.Config, error), logger *slog.Logger, level *slog.LevelVar) (*Server, error) {
	a, err := ca.Load(c.CA.Cert, c.CA.Key)
	if err != nil {
		return nil, err
	}
	s := &Server{resolver: dns.New(ctx, c.DNS), log: logger, level: level, path: path, version: version, load: load, connections: map[uint64]*active{}, failures: map[string]uint64{}, started: time.Now(), dial: DialUpstream}
	s.current.Store(&snapshot{c, a, 1})
	return s, nil
}
func (s *Server) Status() Status {
	snap := s.current.Load()
	d := s.resolver.Status()
	s.mu.Lock()
	defer s.mu.Unlock()
	health := "ready"
	var reasons []string
	if s.stopping {
		health = "stopping"
		reasons = append(reasons, "daemon is shutting down")
	}
	if d.LastError != "" {
		health = "degraded"
		reasons = append(reasons, d.LastError)
	}
	failures := map[string]uint64{}
	for k, v := range s.failures {
		failures[k] = v
	}
	sent, received := s.sent, s.received
	for _, c := range s.connections {
		sent += c.sent.Load()
		received += c.received.Load()
	}
	return Status{SchemaVersion: 1, PID: os.Getpid(), Version: s.version, Started: s.started, Uptime: time.Since(s.started).Round(time.Second).String(), Health: health, Reasons: reasons, ConfigPath: s.path, Config: snap.config, Generation: snap.generation, Active: len(s.connections), Total: s.total, BytesSent: sent, BytesReceived: received, Failures: failures, DNS: d}
}
func (s *Server) Connections() []Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Connection, 0, len(s.connections))
	for _, c := range s.connections {
		r := c.record
		r.BytesSent, r.BytesReceived = c.sent.Load(), c.received.Load()
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (s *Server) Reload(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	c, err := s.load()
	if err != nil {
		return err
	}
	old := s.current.Load()
	if config.RestartRequired(old.config, c) {
		return errors.New("restart_required: listener, upstream port, CA/runtime paths or log format changed")
	}
	a, err := ca.Load(c.CA.Cert, c.CA.Key)
	if err != nil {
		return err
	}
	s.current.Store(&snapshot{c, a, old.generation + 1})
	s.resolver.Configure(ctx, c.DNS)
	if s.level != nil {
		var l slog.Level
		_ = l.UnmarshalText([]byte(c.Log.Level))
		s.level.Set(l)
	}
	s.log.Info("configuration reloaded", "generation", old.generation+1)
	return nil
}
func (s *Server) Run(ctx context.Context) error {
	c := s.current.Load().config
	if err := fsutil.PrivateDir(c.Runtime.StateDir); err != nil {
		return err
	}
	unlock, err := fsutil.Lock(filepath.Join(c.Runtime.StateDir, "daemon.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	cl, cleanup, err := control.Listen(c.Runtime.ControlSocket)
	if err != nil {
		return err
	}
	defer cleanup()
	for _, addr := range c.Listen {
		l, e := net.Listen("tcp4", addr)
		if e != nil {
			for _, old := range s.listeners {
				old.Close()
			}
			return e
		}
		s.listeners = append(s.listeners, l)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { control.JSON(w, 200, s.Status()) })
	mux.HandleFunc("GET /v1/connections", func(w http.ResponseWriter, r *http.Request) {
		control.JSON(w, 200, map[string]any{"schema_version": 1, "connections": s.Connections()})
	})
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Reload(r.Context()); err != nil {
			control.JSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		control.JSON(w, 200, map[string]any{"schema_version": 1, "reloaded": true})
	})
	httpServer := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	background, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.resolver.Run(background)
	errCh := make(chan error, len(s.listeners)+1)
	go func() {
		if e := httpServer.Serve(cl); e != nil && !errors.Is(e, http.ErrServerClosed) {
			errCh <- e
		}
	}()
	for _, l := range s.listeners {
		go func(l net.Listener) {
			for {
				raw, e := l.Accept()
				if e != nil {
					errCh <- e
					return
				}
				s.accept(raw)
			}
		}(l)
	}
	s.log.Info("daemon listening", "listen", c.Listen, "control_socket", c.Runtime.ControlSocket, "dns", s.resolver.Status())
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	for _, l := range s.listeners {
		l.Close()
	}
	cancel()
	finished := make(chan struct{})
	go func() { s.wg.Wait(); close(finished) }()
	timer := time.NewTimer(s.current.Load().config.Runtime.ShutdownTimeout.Value())
	defer timer.Stop()
	select {
	case <-finished:
	case <-timer.C:
		s.mu.Lock()
		for _, c := range s.connections {
			if c.cancel != nil {
				c.cancel()
			}
			c.raw.Close()
		}
		s.mu.Unlock()
		<-finished
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	_ = httpServer.Shutdown(stopCtx)
	s.log.Info("daemon stopped")
	return runErr
}
func (s *Server) accept(raw net.Conn) {
	snap := s.current.Load()
	addr, err := netip.ParseAddrPort(raw.RemoteAddr().String())
	if err != nil || !snap.config.AllowsClient(addr.Addr()) {
		s.failure("client_denied")
		raw.Close()
		return
	}
	s.mu.Lock()
	if s.stopping || len(s.connections) >= snap.config.Runtime.MaxConnections {
		s.failures["connection_limit"]++
		s.mu.Unlock()
		raw.Close()
		return
	}
	s.next++
	s.total++
	a := &active{record: Connection{ID: s.next, Started: time.Now(), Client: raw.RemoteAddr().String(), Profile: snap.config.Upstream.Profile, State: "handshake"}, raw: raw}
	s.connections[a.record.ID] = a
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer raw.Close()
		err := s.handle(a, snap)
		s.mu.Lock()
		s.sent += a.sent.Load()
		s.received += a.received.Load()
		delete(s.connections, a.record.ID)
		record := a.record
		stopping := s.stopping
		s.mu.Unlock()
		if stopping && (errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)) {
			s.log.Debug("connection closed during shutdown", "id", record.ID)
			return
		}
		if err != nil {
			s.failure(category(err))
			s.log.Warn("connection failed", "id", record.ID, "sni", record.SNI, "error", err)
		} else {
			s.log.Info("connection closed", "id", record.ID, "sni", record.SNI, "upstream", record.Upstream, "profile", record.Profile, "alpn", record.UpstreamALPN, "bytes_sent", a.sent.Load(), "bytes_received", a.received.Load())
		}
	}()
}
func category(err error) string {
	v := err.Error()
	for _, c := range []string{"sni_missing", "domain_denied", "upstream_loop", "alpn_mismatch", "unsupported_alps", "dns_", "upstream_connect", "upstream_tls"} {
		if strings.Contains(v, c) {
			return strings.TrimSuffix(c, "_")
		}
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	return "connection"
}
func (s *Server) failure(kind string) { s.mu.Lock(); s.failures[kind]++; s.mu.Unlock() }
func (s *Server) handle(a *active, snap *snapshot) error {
	c := snap.config
	deadline := a.record.Started.Add(c.Runtime.HandshakeTimeout.Value())
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	s.mu.Lock()
	a.cancel = cancel
	s.mu.Unlock()
	_ = a.raw.SetDeadline(deadline)
	var upstream *utls.UConn
	defer func() {
		if upstream != nil {
			upstream.Close()
		}
	}()
	client := tls.Server(a.raw, &tls.Config{MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if upstream != nil {
			return nil, errors.New("repeated ClientHello callback")
		}
		if hello.ServerName == "" {
			return nil, errors.New("sni_missing")
		}
		host, err := config.Domain(hello.ServerName)
		if err != nil {
			return nil, err
		}
		if !c.AllowsDomain(host) {
			return nil, fmt.Errorf("domain_denied: %s", host)
		}
		s.mu.Lock()
		a.record.SNI = host
		s.mu.Unlock()
		cert, err := snap.authority.Certificate(host)
		if err != nil {
			return nil, err
		}
		u, mods, ip, err := s.dial(ctx, c, s.resolver, host, hello.SupportedProtos)
		if err != nil {
			return nil, err
		}
		upstream = u
		state := u.ConnectionState()
		s.mu.Lock()
		a.record.Upstream, a.record.Modifications, a.record.UpstreamTLS, a.record.UpstreamALPN = ip, mods, state.Version, state.NegotiatedProtocol
		s.mu.Unlock()
		var protocols []string
		if state.NegotiatedProtocol != "" {
			protocols = []string{state.NegotiatedProtocol}
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}, NextProtos: protocols, SessionTicketsDisabled: true}, nil
	}})
	if err := client.HandshakeContext(ctx); err != nil {
		return err
	}
	if upstream == nil {
		return errors.New("upstream handshake missing")
	}
	state := client.ConnectionState()
	if state.NegotiatedProtocol != upstream.ConnectionState().NegotiatedProtocol {
		return errors.New("alpn_mismatch after client handshake")
	}
	s.mu.Lock()
	a.record.ClientTLS, a.record.ClientALPN, a.record.State = state.Version, state.NegotiatedProtocol, "relaying"
	s.mu.Unlock()
	_ = a.raw.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	return relay(client, upstream, c.Runtime.IdleTimeout.Value(), &a.sent, &a.received)
}

type halfConn interface {
	net.Conn
	CloseWrite() error
}

// Each copy closes only its write half on EOF. The reverse direction keeps draining.
func relay(client, upstream halfConn, idle time.Duration, sent, received *atomic.Int64) error {
	last := atomic.Int64{}
	last.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)
	go func() {
		interval := min(idle/2, time.Second)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, last.Load())) >= idle {
					_ = client.SetDeadline(time.Now())
					_ = upstream.SetDeadline(time.Now())
					return
				}
			}
		}
	}()
	errs := make(chan error, 2)
	copyStream := func(dst, src halfConn, count *atomic.Int64) {
		buf := make([]byte, 32*1024)
		_, err := io.CopyBuffer(&progressWriter{Writer: dst, count: count, last: &last}, src, buf)
		if err == nil {
			_ = dst.SetWriteDeadline(time.Now().Add(time.Second))
			err = dst.CloseWrite()
			_ = dst.SetWriteDeadline(time.Time{})
		}
		errs <- err
	}
	go copyStream(upstream, client, sent)
	go copyStream(client, upstream, received)
	first := <-errs
	if first != nil {
		client.Close()
		upstream.Close()
	}
	second := <-errs
	if first != nil {
		return first
	}
	return second
}

type progressWriter struct {
	io.Writer
	count *atomic.Int64
	last  *atomic.Int64
}

func (w *progressWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	if n > 0 {
		w.count.Add(int64(n))
		w.last.Store(time.Now().UnixNano())
	}
	return n, err
}
