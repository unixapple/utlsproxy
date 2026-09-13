package dns

import (
	"net"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

// Manager properties contain all links. Only index zero belongs to the global
// group; per-link entries must retain the routing policy read from Link objects.
// See systemd's org.freedesktop.resolve1 Manager DNSEx and Domains signatures.
func managerGroup(props map[string]dbus.Variant) (Group, error) {
	g := Group{Default: true}
	if v, ok := props["DNSEx"]; ok {
		var servers []struct {
			Index      int32
			Family     int32
			Address    []byte
			Port       uint16
			ServerName string
		}
		if err := dbus.Store([]any{v.Value()}, &servers); err != nil {
			return g, err
		}
		for _, s := range servers {
			if s.Index == 0 && s.Family == 2 && len(s.Address) == 4 {
				port := s.Port
				if port == 0 {
					port = 53
				}
				g.Servers = append(g.Servers, net.JoinHostPort(net.IP(s.Address).String(), strconv.Itoa(int(port))))
			}
		}
	} else if v, ok := props["DNS"]; ok {
		var servers []struct {
			Index   int32
			Family  int32
			Address []byte
		}
		if err := dbus.Store([]any{v.Value()}, &servers); err != nil {
			return g, err
		}
		for _, s := range servers {
			if s.Index == 0 && s.Family == 2 && len(s.Address) == 4 {
				g.Servers = append(g.Servers, net.JoinHostPort(net.IP(s.Address).String(), "53"))
			}
		}
	}
	if v, ok := props["Domains"]; ok {
		var domains []struct {
			Index     int32
			Name      string
			RouteOnly bool
		}
		if err := dbus.Store([]any{v.Value()}, &domains); err != nil {
			return g, err
		}
		for _, d := range domains {
			if d.Index == 0 {
				g.Domains = append(g.Domains, strings.ToLower(d.Name))
			}
		}
	}
	return g, nil
}
