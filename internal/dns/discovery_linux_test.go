package dns

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"
)

type discoveryObject struct {
	dbus.BusObject
	call func(string, ...any) *dbus.Call
}

func (o discoveryObject) CallWithContext(_ context.Context, method string, _ dbus.Flags, args ...any) *dbus.Call {
	return o.call(method, args...)
}

func TestResolvedDiscoveryGetLink(t *testing.T) {
	for _, failure := range []string{"", "missing", "denied", "properties", "interfaces", "dot"} {
		t.Run(failure, func(t *testing.T) {
			var queried []int32
			object := func(path dbus.ObjectPath) dbus.BusObject {
				return discoveryObject{call: func(method string, args ...any) *dbus.Call {
					if path == "/org/freedesktop/resolve1" {
						switch method {
						case "org.freedesktop.DBus.Properties.GetAll":
							return &dbus.Call{Body: []any{map[string]dbus.Variant{}}}
						case "org.freedesktop.resolve1.Manager.GetLink":
							index := args[0].(int32)
							queried = append(queried, index)
							if index == 9 {
								if failure == "missing" {
									return &dbus.Call{Err: dbus.Error{Name: "org.freedesktop.resolve1.NoSuchLink"}}
								}
								if failure == "denied" {
									return &dbus.Call{Err: dbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied"}}
								}
								return &dbus.Call{Body: []any{dbus.ObjectPath("/org/freedesktop/resolve1/link/_9")}}
							}
							return &dbus.Call{Body: []any{dbus.ObjectPath("/org/freedesktop/resolve1/link/_2")}}
						}
						t.Fatalf("unexpected manager call: %s", method)
					}
					if method != "org.freedesktop.DBus.Properties.GetAll" || args[0] != "org.freedesktop.resolve1.Link" {
						t.Fatalf("unexpected link call: %s %v", method, args)
					}
					p := map[string]dbus.Variant{}
					if path == "/org/freedesktop/resolve1/link/_2" {
						p["DNS"] = dbus.MakeVariant([]resolvedDNS{{Family: 2, Address: []byte{192, 0, 2, 53}}})
						p["DefaultRoute"] = dbus.MakeVariant(true)
					} else {
						if failure == "properties" {
							return &dbus.Call{Err: errors.New("link properties unavailable")}
						}
						// A domain-only link must not be lost, or its queries could
						// escape to the default interface's DNS server.
						p["Domains"] = dbus.MakeVariant([]resolvedDomain{{Name: "corp.example", RouteOnly: true}})
						if failure == "dot" {
							p["DNSOverTLS"] = dbus.MakeVariant("yes")
						}
					}
					return &dbus.Call{Body: []any{p}}
				}}
			}
			d, err := resolvedDiscovery(context.Background(), object, func() ([]net.Interface, error) {
				if failure == "interfaces" {
					return nil, errors.New("interface enumeration failed")
				}
				return []net.Interface{{Index: 2, Name: "eth0"}, {Index: 9, Name: "vpn0"}}, nil
			})
			if failure == "denied" || failure == "properties" || failure == "interfaces" || failure == "dot" {
				if err == nil {
					t.Fatal("discovery failure hidden")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(queried, []int32{2, 9}) {
				t.Fatalf("interfaces not queried: %v", queried)
			}
			want := []Group{{Interface: 2, Servers: []string{"192.0.2.53:53"}, Default: true}}
			if failure != "missing" {
				want = append(want, Group{Interface: 9, Domains: []string{"corp.example"}})
			}
			if !reflect.DeepEqual(d.Groups, want) {
				t.Fatalf("DNS routing changed: %+v", d.Groups)
			}
			if failure == "" {
				selected := Select(d.Groups, "secret.corp.example")
				if len(selected) != 1 || selected[0].Interface != 9 || len(selected[0].Servers) != 0 {
					t.Fatalf("domain-only route escaped to default DNS: %+v", selected)
				}
			}
		})
	}
}
