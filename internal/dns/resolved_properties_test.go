package dns

import (
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestManagerRoutingProperties(t *testing.T) {
	// DBus wire-shaped values: (interface, family, address, port, TLS name).
	p := map[string]dbus.Variant{
		"DNSEx": dbus.MakeVariant([][]any{
			{int32(0), int32(2), []byte{192, 0, 2, 53}, uint16(5353), ""},
			{int32(7), int32(2), []byte{10, 0, 0, 53}, uint16(53), ""},
			{int32(0), int32(10), make([]byte, 16), uint16(53), ""},
		}),
		"Domains": dbus.MakeVariant([][]any{
			{int32(0), "CORP.EXAMPLE", true}, {int32(7), "vpn.example", true},
		}),
	}
	g, err := managerGroup(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.Servers, []string{"192.0.2.53:5353"}) || !reflect.DeepEqual(g.Domains, []string{"corp.example"}) || !g.Default {
		t.Fatalf("routing or nonstandard port lost: %+v", g)
	}
	if got := Select([]Group{g, {Servers: []string{"192.0.2.2:53"}, Default: true}}, "secret.corp.example"); len(got) != 1 || got[0].Servers[0] != g.Servers[0] {
		t.Fatalf("global routing domain escaped to default: %+v", got)
	}
	delete(p, "DNSEx")
	p["DNS"] = dbus.MakeVariant([][]any{{int32(0), int32(2), []byte{192, 0, 2, 53}}})
	g, err = managerGroup(p)
	if err != nil || !reflect.DeepEqual(g.Servers, []string{"192.0.2.53:53"}) {
		t.Fatalf("legacy property: %+v %v", g, err)
	}
	p["DNS"] = dbus.MakeVariant("malformed")
	if _, err = managerGroup(p); err == nil {
		t.Fatal("malformed DBus property accepted")
	}
}
