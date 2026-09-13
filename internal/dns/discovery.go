package dns

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Group struct {
	Servers   []string `json:"servers"`
	Domains   []string `json:"domains,omitempty"`
	Interface int      `json:"interface_index,omitempty"`
	Priority  int      `json:"priority,omitempty"`
	Default   bool     `json:"default"`
}
type Discovery struct {
	Source  string  `json:"source"`
	Routing string  `json:"routing"`
	Groups  []Group `json:"groups"`
}

func LocalAddresses() (map[netip.Addr]bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := map[netip.Addr]bool{}
	for _, a := range addrs {
		p, e := netip.ParsePrefix(a.String())
		if e == nil && p.Addr().Is4() {
			out[p.Addr()] = true
		}
	}
	return out, nil
}
func usable(d Discovery) (Discovery, error) {
	local, err := LocalAddresses()
	if err != nil {
		return d, err
	}
	count := 0
	for i, g := range d.Groups {
		servers := []string{}
		for _, s := range g.Servers {
			a, e := netip.ParseAddrPort(s)
			if e == nil && a.Addr().Is4() && !a.Addr().IsLoopback() && !a.Addr().IsUnspecified() && !a.Addr().IsMulticast() && !local[a.Addr()] {
				servers = append(servers, s)
				count++
			}
		}
		d.Groups[i].Servers = servers
	}
	if count == 0 {
		return d, errors.New("auto DNS found no usable IPv4 upstream; configure --dns IPv4:port for an opaque local DNS stub")
	}
	return d, nil
}

// ParseScutil keeps unscoped default/supplemental groups. The subsequent
// scoped-query list describes interface-specific caller requests, not extra defaults.
func ParseScutil(text string) (Discovery, error) {
	d := Discovery{Source: "scutil --dns", Routing: "domain-aware"}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var g *Group
	mdns := false
	port := 53
	seenHeader := false
	flush := func() {
		if g != nil && !mdns {
			for i, s := range g.Servers {
				g.Servers[i] = net.JoinHostPort(s, strconv.Itoa(port))
			}
			g.Default = len(g.Domains) == 0
			d.Groups = append(d.Groups, *g)
		}
		g = nil
		mdns = false
		port = 53
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "DNS configuration (for scoped queries)") {
			break
		}
		if strings.HasPrefix(line, "resolver #") {
			flush()
			g = &Group{}
			seenHeader = true
			continue
		}
		if g == nil {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case strings.HasPrefix(key, "nameserver["):
			a, e := netip.ParseAddr(value)
			if e == nil && a.Is4() {
				g.Servers = append(g.Servers, a.String())
			}
		case key == "domain":
			g.Domains = append(g.Domains, strings.TrimSuffix(strings.ToLower(value), "."))
		case key == "if_index":
			parts := strings.Fields(value)
			if len(parts) == 0 {
				return d, errors.New("empty scutil interface")
			}
			n, e := strconv.Atoi(parts[0])
			if e != nil {
				return d, fmt.Errorf("invalid scutil interface: %w", e)
			}
			g.Interface = n
		case key == "port":
			n, e := strconv.Atoi(value)
			if e != nil || n < 1 || n > 65535 {
				return d, errors.New("invalid scutil DNS port")
			}
			port = n
		case key == "order":
			n, e := strconv.Atoi(value)
			if e != nil {
				return d, e
			}
			g.Priority = n
		case key == "options" && strings.Contains(value, "mdns"):
			mdns = true
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return d, err
	}
	if !seenHeader || len(d.Groups) == 0 {
		return d, errors.New("unrecognized or empty macOS DNS configuration")
	}
	return d, nil
}

func Select(groups []Group, name string) []Group {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	best := -1
	priority := int(^uint(0) >> 1)
	var matched []Group
	for _, g := range groups {
		score := -1
		for _, domain := range g.Domains {
			domain = strings.ToLower(domain)
			domain = strings.TrimPrefix(domain, "~")
			domain = strings.TrimSuffix(domain, ".")
			if domain == "" {
				score = max(score, 0)
			} else if name == domain || strings.HasSuffix(name, "."+domain) {
				score = max(score, len(strings.Split(domain, ".")))
			}
		}
		if score < 0 {
			continue
		}
		if score > best || (score == best && g.Priority < priority) {
			best, priority = score, g.Priority
			matched = nil
		}
		if score == best && g.Priority == priority {
			matched = append(matched, g)
		}
	}
	if best >= 0 {
		return matched
	}
	for _, g := range groups {
		if g.Default {
			if g.Priority < priority {
				priority = g.Priority
				matched = nil
			}
			if g.Priority == priority {
				matched = append(matched, g)
			}
		}
	}
	return matched
}
