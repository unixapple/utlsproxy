package proxy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	utls "github.com/refraction-networking/utls"
	"github.com/unixapple/utlsproxy/internal/config"
	"github.com/unixapple/utlsproxy/internal/dns"
	"github.com/unixapple/utlsproxy/internal/profiles"
)

func CheckDestination(ip netip.Addr, redirect string) error {
	local, err := dns.LocalAddresses()
	if err != nil {
		return err
	}
	if !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip == netip.MustParseAddr("255.255.255.255") || local[ip] || ip.String() == redirect {
		return fmt.Errorf("upstream_loop_or_invalid_address: %s", ip)
	}
	return nil
}
func DialUpstream(ctx context.Context, c config.Config, r *dns.Resolver, host string, offered []string) (*utls.UConn, []string, string, error) {
	ips, err := r.Lookup(ctx, host)
	if err != nil {
		return nil, nil, "", err
	}
	var last error
	for _, ip := range ips {
		if err := CheckDestination(ip, c.Hosts.Address); err != nil {
			last = err
			continue
		}
		address := net.JoinHostPort(ip.String(), strconv.Itoa(c.Upstream.Port))
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		if err != nil {
			last = fmt.Errorf("upstream_connect: %w", err)
			continue
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = raw.SetDeadline(deadline)
		}
		u, mods, err := handshakeUpstream(ctx, raw, c, host, offered, nil)
		if err != nil {
			raw.Close()
			last = err
			continue
		}
		return u, mods, address, nil
	}
	if last == nil {
		last = errors.New("dns_no_ipv4_address")
	}
	return nil, nil, "", last
}

// roots is nil in production (system trust); local integration fixtures supply
// their own trust anchor while exercising the same verification and ALPN path.
func handshakeUpstream(ctx context.Context, raw net.Conn, c config.Config, host string, offered []string, roots *x509.CertPool) (*utls.UConn, []string, error) {
	u, mods, err := profiles.New(raw, c.Upstream.Profile, host, c.Upstream.ALPNMode, offered, roots)
	if err != nil {
		return nil, nil, err
	}
	if err = u.HandshakeContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("upstream_tls: %w", err)
	}
	state := u.ConnectionState()
	if !profiles.Compatible(state.NegotiatedProtocol, offered) {
		return nil, nil, fmt.Errorf("alpn_mismatch: upstream selected %q, client offered %v (use compatible mode if needed)", state.NegotiatedProtocol, offered)
	}
	if len(state.PeerApplicationSettings) > 0 {
		return nil, nil, errors.New("unsupported_alps: upstream sent application settings that cannot be forwarded through the downstream TLS stack; select firefox-120")
	}
	return u, mods, nil
}
