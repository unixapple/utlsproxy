package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/unixapple/utlsproxy/internal/config"
	"golang.org/x/sync/singleflight"
)

type State struct {
	Mode string `json:"mode"`
	Discovery
	Generation   uint64    `json:"generation"`
	LastRefresh  time.Time `json:"last_refresh"`
	LastError    string    `json:"last_error,omitempty"`
	CacheEntries int       `json:"cache_entries"`
}
type cached struct {
	ips     []netip.Addr
	expires time.Time
}
type Resolver struct {
	mu        sync.Mutex
	cfg       config.DNS
	applied   config.DNS
	state     State
	cache     map[string]cached
	flights   singleflight.Group
	refreshMu sync.Mutex
	discover  func(context.Context) (Discovery, error)
}

func New(ctx context.Context, c config.DNS) *Resolver {
	r := &Resolver{cfg: c, cache: map[string]cached{}, discover: Discover}
	_ = r.Refresh(ctx)
	return r
}
func (r *Resolver) Status() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.state
	s.CacheEntries = len(r.cache)
	return s
}
func (r *Resolver) Configure(ctx context.Context, c config.DNS) {
	r.mu.Lock()
	r.cfg = c
	r.cache = map[string]cached{}
	r.mu.Unlock()
	_ = r.Refresh(ctx)
}
func (r *Resolver) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.mu.Lock()
			due := time.Since(r.state.LastRefresh) >= r.cfg.RefreshInterval.Value()
			r.mu.Unlock()
			if due {
				_ = r.Refresh(ctx)
			}
		}
	}
}
func (r *Resolver) Refresh(ctx context.Context) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	r.mu.Lock()
	c := r.cfg
	if reflect.DeepEqual(c, r.applied) && time.Since(r.state.LastRefresh) < 100*time.Millisecond {
		last := r.state.LastError
		r.mu.Unlock()
		if last != "" {
			return errors.New(last)
		}
		return nil
	}
	r.mu.Unlock()
	var d Discovery
	var e error
	if c.Mode == "manual" {
		d = Discovery{Source: "configuration", Routing: "manual", Groups: []Group{{Servers: append([]string{}, c.Servers...), Default: true}}}
	} else {
		timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		d, e = r.discover(timeout)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !reflect.DeepEqual(c, r.cfg) {
		return nil
	}
	errorText := ""
	if e != nil {
		errorText = e.Error()
		d.Groups = nil
	}
	if !reflect.DeepEqual(c, r.applied) || !reflect.DeepEqual(d, r.state.Discovery) || errorText != r.state.LastError || c.Mode != r.state.Mode {
		r.state.Generation++
		r.cache = map[string]cached{}
	}
	r.applied = c
	r.state.Mode, r.state.Discovery, r.state.LastError, r.state.LastRefresh = c.Mode, d, errorText, time.Now()
	return e
}
func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := r.lookup(ctx, host)
	if err != nil && !errors.Is(err, context.Canceled) {
		r.mu.Lock()
		refresh := r.cfg.Mode == "auto" && time.Since(r.state.LastRefresh) > time.Second
		gen := r.state.Generation
		r.mu.Unlock()
		if refresh {
			_ = r.Refresh(ctx)
			if r.Status().Generation != gen {
				return r.lookup(ctx, host)
			}
		}
	}
	return ips, err
}
func (r *Resolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.ToLower(mdns.Fqdn(host))
	r.mu.Lock()
	s, c := r.state, r.cfg
	key := fmt.Sprintf("%d:%s", s.Generation, host)
	if s.LastError != "" {
		r.mu.Unlock()
		return nil, fmt.Errorf("dns_unavailable: %s", s.LastError)
	}
	if entry, ok := r.cache[key]; ok {
		if time.Now().Before(entry.expires) {
			r.mu.Unlock()
			return append([]netip.Addr{}, entry.ips...), nil
		}
		delete(r.cache, key)
	}
	r.mu.Unlock()
	groups := Select(s.Groups, host)
	if len(groups) == 0 {
		return nil, errors.New("dns_unavailable: no eligible resolver group")
	}
	result := r.flights.DoChan(key, func() (any, error) {
		work, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var ips []netip.Addr
		var ttl uint32
		var last error
		var queryStarted time.Time
		for _, g := range groups {
			for _, server := range g.Servers {
				queryStarted = time.Now()
				ips, ttl, last = resolve(work, server, g.Interface, host, c.Timeout.Value())
				if last == nil {
					break
				}
				var permanent *nameError
				if errors.As(last, &permanent) {
					return nil, last
				}
			}
			if last == nil && len(ips) > 0 {
				break
			}
		}
		if len(ips) == 0 {
			if last == nil {
				last = errors.New("no usable IPv4 DNS server in matched group")
			}
			return nil, last
		}
		r.mu.Lock()
		// Count the whole successful resolution against the minimum chain TTL.
		// This is conservative and cannot extend an alias TTL while following it.
		expires := queryStarted.Add(time.Duration(ttl) * time.Second)
		if r.state.Generation == s.Generation && ttl > 0 && time.Now().Before(expires) && c.CacheSize > 0 {
			if len(r.cache) >= c.CacheSize {
				for k := range r.cache {
					delete(r.cache, k)
					break
				}
			}
			r.cache[key] = cached{ips: ips, expires: expires}
		}
		r.mu.Unlock()
		return ips, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-result:
		if res.Err != nil {
			return nil, res.Err
		}
		return append([]netip.Addr{}, res.Val.([]netip.Addr)...), nil
	}
}

type nameError struct{ message string }

func (e *nameError) Error() string { return e.message }
func resolve(ctx context.Context, server string, index int, name string, timeout time.Duration) ([]netip.Addr, uint32, error) {
	ttl := ^uint32(0)
	seen := map[string]bool{}
	for hop := 0; hop <= 8; hop++ {
		if seen[name] {
			return nil, 0, errors.New("dns_cname_cycle")
		}
		seen[name] = true
		q := new(mdns.Msg)
		q.SetQuestion(name, mdns.TypeA)
		q.RecursionDesired = true
		client := &mdns.Client{Net: "udp4", Timeout: timeout, Dialer: &net.Dialer{Timeout: timeout, Control: bindInterface(index)}}
		response, _, err := client.ExchangeContext(ctx, q, server)
		if err != nil {
			return nil, 0, fmt.Errorf("dns_query %s: %w", server, err)
		}
		if response.Truncated {
			client.Net = "tcp4"
			response, _, err = client.ExchangeContext(ctx, q, server)
			if err != nil {
				return nil, 0, err
			}
		}
		if !response.Response || response.Truncated || response.Opcode != mdns.OpcodeQuery || response.Id != q.Id || len(response.Question) != 1 || !strings.EqualFold(response.Question[0].Name, name) || response.Question[0].Qtype != mdns.TypeA || response.Question[0].Qclass != mdns.ClassINET {
			return nil, 0, errors.New("dns_malformed_response")
		}
		if response.Rcode == mdns.RcodeNameError {
			return nil, 0, &nameError{"dns_nxdomain: " + name}
		}
		if response.Rcode != mdns.RcodeSuccess {
			return nil, 0, fmt.Errorf("dns_server_error: %s", mdns.RcodeToString[response.Rcode])
		}
		// Follow only the queried owner's chain; never accept unrelated answer A records.
		owner := name
		for {
			var ips []netip.Addr
			next := ""
			for _, rr := range response.Answer {
				if rr.Header().Class != mdns.ClassINET || !strings.EqualFold(rr.Header().Name, owner) {
					continue
				}
				switch v := rr.(type) {
				case *mdns.A:
					ip, ok := netip.AddrFromSlice(v.A)
					if ok {
						ips = append(ips, ip.Unmap())
						ttl = min(ttl, v.Hdr.Ttl)
					}
				case *mdns.CNAME:
					target := strings.ToLower(v.Target)
					if next != "" && next != target {
						return nil, 0, errors.New("dns_conflicting_cname")
					}
					next = target
					ttl = min(ttl, v.Hdr.Ttl)
				}
			}
			if len(ips) > 0 {
				if next != "" {
					return nil, 0, errors.New("dns_conflicting_address_and_cname")
				}
				return ips, ttl, nil
			}
			if next == "" {
				if owner != name {
					name = owner
					break
				}
				return nil, 0, &nameError{"dns_no_ipv4_address: " + name}
			}
			if seen[next] || len(seen) > 8 {
				return nil, 0, errors.New("dns_cname_cycle_or_limit")
			}
			// Continue through aliases already supplied in the same answer.
			hasOwner := false
			for _, rr := range response.Answer {
				if strings.EqualFold(rr.Header().Name, next) {
					hasOwner = true
					break
				}
			}
			if !hasOwner {
				name = next
				break
			}
			seen[next] = true
			owner = next
		}
	}
	return nil, 0, errors.New("dns_cname_limit")
}
