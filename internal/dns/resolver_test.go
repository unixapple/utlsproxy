package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/unixapple/utlsproxy/internal/config"
)

func testDNS(t *testing.T, handler mdns.HandlerFunc) string {
	t.Helper()
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	tcp, e := net.Listen("tcp4", udp.LocalAddr().String())
	if e != nil {
		udp.Close()
		t.Fatal(e)
	}
	u, s := &mdns.Server{PacketConn: udp, Handler: handler}, &mdns.Server{Listener: tcp, Handler: handler}
	go u.ActivateAndServe()
	go s.ActivateAndServe()
	t.Cleanup(func() { u.Shutdown(); s.Shutdown() })
	return udp.LocalAddr().String()
}
func answer(q *mdns.Msg, ip string, ttl uint32) *mdns.Msg {
	r := new(mdns.Msg)
	r.SetReply(q)
	r.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: ttl}, A: net.ParseIP(ip).To4()}}
	return r
}
func resolverFor(server string) *Resolver {
	c := config.Defaults().DNS
	c.Mode = "manual"
	c.Servers = []string{server}
	c.Timeout = config.Duration(300 * time.Millisecond)
	return New(context.Background(), c)
}
func TestDirectQueryBypassesHostsAndCaches(t *testing.T) {
	var count atomic.Int32
	server := testDNS(t, func(w mdns.ResponseWriter, q *mdns.Msg) { count.Add(1); _ = w.WriteMsg(answer(q, "203.0.113.9", 60)) })
	r := resolverFor(server)
	for range 2 {
		ips, e := r.Lookup(context.Background(), "localhost")
		if e != nil {
			t.Fatal(e)
		}
		if len(ips) != 1 || ips[0] != netip.MustParseAddr("203.0.113.9") {
			t.Fatalf("consulted local hosts or wrong reply: %v", ips)
		}
	}
	if count.Load() != 1 {
		t.Fatalf("expected one network lookup, got %d", count.Load())
	}
}
func TestZeroTTLAndTCPFallback(t *testing.T) {
	var udp, tcp atomic.Int32
	server := testDNS(t, func(w mdns.ResponseWriter, q *mdns.Msg) {
		r := answer(q, "203.0.113.10", 0)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			udp.Add(1)
			r.Truncated = true
			r.Answer = nil
		} else {
			tcp.Add(1)
		}
		_ = w.WriteMsg(r)
	})
	r := resolverFor(server)
	for range 2 {
		if _, e := r.Lookup(context.Background(), "test.example"); e != nil {
			t.Fatal(e)
		}
	}
	if udp.Load() != 2 || tcp.Load() != 2 {
		t.Fatalf("UDP=%d TCP=%d", udp.Load(), tcp.Load())
	}
}
func TestCNAMEAndUnrelatedAnswers(t *testing.T) {
	server := testDNS(t, func(w mdns.ResponseWriter, q *mdns.Msg) {
		r := answer(q, "203.0.113.20", 60)
		r.Answer[0].Header().Name = "unrelated.example."
		r.Answer = append(r.Answer, &mdns.CNAME{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 0}, Target: "target.example."}, &mdns.A{Hdr: mdns.RR_Header{Name: "target.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.21").To4()})
		_ = w.WriteMsg(r)
	})
	r := resolverFor(server)
	ips, e := r.Lookup(context.Background(), "test.example")
	if e != nil {
		t.Fatal(e)
	}
	if len(ips) != 1 || ips[0].String() != "203.0.113.21" {
		t.Fatalf("accepted unrelated address: %v", ips)
	}
	if r.Status().CacheEntries != 0 {
		t.Fatal("extended alias zero TTL")
	}
}
func TestNXDOMAINDoesNotTryFallback(t *testing.T) {
	server := testDNS(t, func(w mdns.ResponseWriter, q *mdns.Msg) {
		r := new(mdns.Msg)
		r.SetRcode(q, mdns.RcodeNameError)
		_ = w.WriteMsg(r)
	})
	var count atomic.Int32
	fallback := testDNS(t, func(w mdns.ResponseWriter, q *mdns.Msg) { count.Add(1); _ = w.WriteMsg(answer(q, "203.0.113.1", 60)) })
	c := config.Defaults().DNS
	c.Mode = "manual"
	c.Servers = []string{server, fallback}
	r := New(context.Background(), c)
	_, e := r.Lookup(context.Background(), "private.example")
	var permanent *nameError
	if !errors.As(e, &permanent) {
		t.Fatalf("expected NXDOMAIN: %v", e)
	}
	if count.Load() != 0 {
		t.Fatal("NXDOMAIN leaked to fallback")
	}
}
func TestCoalescedQueries(t *testing.T) {
	var count atomic.Int32
	server := testDNS(t, func(w mdns.ResponseWriter, q *mdns.Msg) {
		count.Add(1)
		time.Sleep(30 * time.Millisecond)
		_ = w.WriteMsg(answer(q, "203.0.113.4", 60))
	})
	r := resolverFor(server)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, e := r.Lookup(context.Background(), "same.example"); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("queries were not coalesced: %d", count.Load())
	}
}
func TestConfigurationRefreshDuringDiscovery(t *testing.T) {
	c := config.Defaults().DNS
	entered, release := make(chan struct{}), make(chan struct{})
	r := &Resolver{cfg: c, cache: map[string]cached{}, discover: func(context.Context) (Discovery, error) {
		close(entered)
		<-release
		return Discovery{Source: "old", Groups: []Group{{Default: true, Servers: []string{"192.0.2.1:53"}}}}, nil
	}}
	done := make(chan struct{})
	go func() { _ = r.Refresh(context.Background()); close(done) }()
	<-entered
	manual := c
	manual.Mode = "manual"
	manual.Servers = []string{"192.0.2.2:53"}
	configured := make(chan struct{})
	go func() { r.Configure(context.Background(), manual); close(configured) }()
	// Ensure Configure has published its desired config before releasing discovery.
	deadline := time.Now().Add(time.Second)
	for {
		r.mu.Lock()
		ready := r.cfg.Mode == "manual"
		r.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("configuration not published")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	<-done
	<-configured
	s := r.Status()
	if s.Mode != "manual" || s.Groups[0].Servers[0] != "192.0.2.2:53" {
		t.Fatalf("stale discovery won: %+v", s)
	}
}
func TestResolverSelection(t *testing.T) {
	groups := []Group{{Default: true, Servers: []string{"default"}}, {Domains: []string{"corp.example"}, Servers: []string{"private"}}, {Domains: []string{"deep.corp.example"}, Servers: []string{}}}
	for _, tc := range []struct {
		name string
		want string
	}{{"public.example", "default"}, {"api.corp.example", "private"}, {"notcorp.example", "default"}} {
		g := Select(groups, tc.name)
		if len(g) != 1 || g[0].Servers[0] != tc.want {
			t.Fatalf("%s: %+v", tc.name, g)
		}
	}
	g := Select(groups, "a.deep.corp.example")
	if len(g) != 1 || len(g[0].Servers) != 0 {
		t.Fatal("unavailable private resolver escaped to default")
	}
}
func TestScutilParser(t *testing.T) {
	d, e := ParseScutil("DNS configuration\nresolver #1\n nameserver[0] : 192.0.2.1\n if_index : 7 (en0)\nresolver #2\n domain : corp.example\n nameserver[0] : 192.0.2.2\n order : 100\nresolver #3\n domain : local\n options : mdns\nDNS configuration (for scoped queries)\nresolver #1\n nameserver[0] : 192.0.2.3\n")
	if e != nil {
		t.Fatal(e)
	}
	if len(d.Groups) != 2 || d.Groups[0].Interface != 7 || d.Groups[1].Domains[0] != "corp.example" {
		t.Fatalf("wrong parse: %+v", d)
	}
	if _, e = ParseScutil("resolver #1\n if_index :\n"); e == nil {
		t.Fatal("accepted malformed interface")
	}
}
