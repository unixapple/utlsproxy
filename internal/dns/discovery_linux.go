package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/godbus/dbus/v5"
	mdns "github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

func Discover(ctx context.Context) (Discovery, error) {
	path, _ := filepath.EvalSymlinks("/etc/resolv.conf")
	known := strings.Contains(path, "/systemd/resolve/")
	if _, e := os.Stat("/run/systemd/resolve/stub-resolv.conf"); e == nil {
		known = true
	}
	conn, err := dbus.ConnectSystemBus()
	if err == nil {
		defer conn.Close()
		var owner bool
		err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, "org.freedesktop.resolve1").Store(&owner)
		if err == nil && owner {
			d, e := resolved(ctx, conn)
			if e != nil {
				return d, e
			}
			return usable(d)
		}
	}
	if known {
		return Discovery{}, errors.New("systemd-resolved routing configuration unavailable; refusing flat/stub fallback; configure manual DNS")
	}
	c, e := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if e != nil {
		return Discovery{}, e
	}
	g := Group{Default: true}
	for _, s := range c.Servers {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			g.Servers = append(g.Servers, net.JoinHostPort(s, c.Port))
		}
	}
	return usable(Discovery{Source: "/etc/resolv.conf", Routing: "default-only", Groups: []Group{g}})
}
func properties(ctx context.Context, obj dbus.BusObject, iface string) (map[string]dbus.Variant, error) {
	var props map[string]dbus.Variant
	err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, iface).Store(&props)
	return props, err
}

type resolvedDNS struct {
	Family  int32
	Address []byte
}
type resolvedDNSEx struct {
	Family     int32
	Address    []byte
	Port       uint16
	ServerName string
}
type resolvedDomain struct {
	Name      string
	RouteOnly bool
}

func linkGroup(props map[string]dbus.Variant, index int) (Group, error) {
	g := Group{Interface: index}
	if v, ok := props["DNSOverTLS"]; ok && v.Value() == "yes" {
		return g, errors.New("mandatory DNS-over-TLS is unsupported; provide a suitable manual DNS server")
	}
	if v, ok := props["DefaultRoute"]; ok {
		g.Default, _ = v.Value().(bool)
	}
	if v, ok := props["DNSEx"]; ok {
		var servers []resolvedDNSEx
		if err := dbus.Store([]any{v.Value()}, &servers); err != nil {
			return g, err
		}
		for _, s := range servers {
			if s.Family == unix.AF_INET && len(s.Address) == 4 {
				port := s.Port
				if port == 0 {
					port = 53
				}
				g.Servers = append(g.Servers, net.JoinHostPort(net.IP(s.Address).String(), strconv.Itoa(int(port))))
			}
		}
	} else if v, ok := props["DNS"]; ok {
		var servers []resolvedDNS
		if err := dbus.Store([]any{v.Value()}, &servers); err != nil {
			return g, err
		}
		for _, s := range servers {
			if s.Family == unix.AF_INET && len(s.Address) == 4 {
				g.Servers = append(g.Servers, net.JoinHostPort(net.IP(s.Address).String(), "53"))
			}
		}
	}
	if v, ok := props["Domains"]; ok {
		var ds []resolvedDomain
		if err := dbus.Store([]any{v.Value()}, &ds); err != nil {
			return g, err
		}
		for _, d := range ds {
			g.Domains = append(g.Domains, d.Name)
		}
	}
	return g, nil
}
func resolved(ctx context.Context, c *dbus.Conn) (Discovery, error) {
	return resolvedDiscovery(ctx, func(path dbus.ObjectPath) dbus.BusObject {
		return c.Object("org.freedesktop.resolve1", path)
	}, net.Interfaces)
}

func resolvedDiscovery(ctx context.Context, object func(dbus.ObjectPath) dbus.BusObject, interfaces func() ([]net.Interface, error)) (Discovery, error) {
	d := Discovery{Source: "org.freedesktop.resolve1", Routing: "domain-aware"}
	o := object("/org/freedesktop/resolve1")
	p, err := properties(ctx, o, "org.freedesktop.resolve1.Manager")
	if err != nil {
		return d, err
	}
	if v, ok := p["DNSOverTLS"]; ok && v.Value() == "yes" {
		return d, errors.New("mandatory DNS-over-TLS is unsupported")
	}
	g, err := managerGroup(p)
	if err != nil {
		return d, err
	}
	if len(g.Servers) > 0 || len(g.Domains) > 0 {
		d.Groups = append(d.Groups, g)
	}
	// resolve1 has GetLink, but no ListLinks (that belongs to network1).
	// Enumerate kernel interfaces so links with routing domains but no DNS
	// servers are retained, too.
	links, err := interfaces()
	if err != nil {
		return d, fmt.Errorf("enumerate DNS interfaces: %w", err)
	}
	for _, l := range links {
		var path dbus.ObjectPath
		e := o.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.GetLink", 0, int32(l.Index)).Store(&path)
		if e != nil {
			var busErr dbus.Error
			if errors.As(e, &busErr) && busErr.Name == "org.freedesktop.resolve1.NoSuchLink" {
				// The interface may have disappeared or may not be tracked by resolved.
				continue
			}
			return d, fmt.Errorf("get DNS link %s: %w", l.Name, e)
		}
		p, e := properties(ctx, object(path), "org.freedesktop.resolve1.Link")
		if e != nil {
			return d, fmt.Errorf("read DNS link %s: %w", l.Name, e)
		}
		g, e := linkGroup(p, int(l.Index))
		if e != nil {
			return d, fmt.Errorf("link %s: %w", l.Name, e)
		}
		if len(g.Servers) > 0 || len(g.Domains) > 0 {
			d.Groups = append(d.Groups, g)
		}
	}
	return d, nil
}
func bindInterface(index int) func(string, string, syscall.RawConn) error {
	if index == 0 {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		iface, e := net.InterfaceByIndex(index)
		if e != nil {
			return e
		}
		var err error
		e = c.Control(func(fd uintptr) {
			err = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name)
		})
		if e != nil {
			return e
		}
		return err
	}
}
