package service

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/unixapple/utlsproxy/internal/config"
)

func TestNativeDefinitions(t *testing.T) {
	c := config.Defaults()
	p := config.Paths{Executable: "/usr/local/bin/utlsproxy", Service: "/tmp/service", Log: "/var/log/utlsproxy.log"}
	mac, e := Generate("darwin", p, c, "/Library/Application Support/A&B/config.json")
	if e != nil {
		t.Fatal(e)
	}
	d := xml.NewDecoder(strings.NewReader(mac.Definition))
	for {
		_, e := d.Token()
		if e != nil {
			if e.Error() != "EOF" {
				t.Fatal(e)
			}
			break
		}
	}
	if !strings.Contains(mac.Definition, "A&amp;B") || !strings.Contains(mac.Definition, "KeepAlive") {
		t.Fatal("invalid launchd definition")
	}
	linux, e := Generate("linux", p, c, "/etc/space $user %n/config.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"Restart=always", "WantedBy=multi-user.target", "$$user %%n", "Type=simple"} {
		if !strings.Contains(linux.Definition, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if _, e = Generate("linux", p, c, "/etc/config\nInjected=yes"); e == nil {
		t.Fatal("allowed service directive injection")
	}
}
