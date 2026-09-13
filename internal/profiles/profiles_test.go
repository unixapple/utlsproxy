package profiles

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"testing"
	"time"
)

func capture(t *testing.T, profile, mode string, offered []string) (map[uint16][]byte, []string) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	u, mods, e := New(client, profile, "example.com", mode, offered, nil)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = u.HandshakeContext(ctx); close(done) }()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	header := make([]byte, 5)
	if _, e = io.ReadFull(server, header); e != nil {
		t.Fatal(e)
	}
	record := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, e = io.ReadFull(server, record); e != nil {
		t.Fatal(e)
	}
	server.Close()
	<-done
	r := bytes.NewReader(record)
	skip := func(n int) {
		if n > r.Len() {
			t.Fatal("truncated ClientHello")
		}
		r.Seek(int64(n), io.SeekCurrent)
	}
	u8 := func() int {
		b, e := r.ReadByte()
		if e != nil {
			t.Fatal(e)
		}
		return int(b)
	}
	u16 := func() int {
		var n uint16
		if e := binary.Read(r, binary.BigEndian, &n); e != nil {
			t.Fatal(e)
		}
		return int(n)
	}
	skip(4 + 2 + 32)
	skip(u8())
	skip(u16())
	skip(u8())
	length := u16()
	if length != r.Len() {
		t.Fatalf("extension length %d != %d", length, r.Len())
	}
	ext := map[uint16][]byte{}
	for r.Len() > 0 {
		id := u16()
		n := u16()
		b := make([]byte, n)
		if _, e = io.ReadFull(r, b); e != nil {
			t.Fatal(e)
		}
		ext[uint16(id)] = b
	}
	return ext, mods
}
func protocols(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	b = b[2:]
	var out []string
	for len(b) > 0 {
		n := int(b[0])
		if len(b) < n+1 {
			return nil
		}
		out = append(out, string(b[1:n+1]))
		b = b[n+1:]
	}
	return out
}
func TestActualClientHelloALPN(t *testing.T) {
	for _, p := range List() {
		t.Run(p.Name, func(t *testing.T) {
			ext, mods := capture(t, p.Name, "strict", []string{"http/1.1"})
			if !slices.Equal(protocols(ext[16]), []string{"h2", "http/1.1"}) || len(mods) != 0 {
				t.Fatal("strict profile changed wire ALPN")
			}
			if p.Name == "chrome-133" {
				if _, ok := ext[17613]; !ok {
					t.Fatal("missing Chrome ALPS extension")
				}
			}
			ext, mods = capture(t, p.Name, "compatible", []string{"http/1.1"})
			if !slices.Equal(protocols(ext[16]), []string{"http/1.1"}) || len(mods) == 0 {
				t.Fatal("compatible wire ALPN was not restricted")
			}
			if _, ok := ext[17613]; ok {
				t.Fatal("left h2 ALPS in HTTP/1.1 profile")
			}
			ext, _ = capture(t, p.Name, "compatible", nil)
			if _, ok := ext[16]; ok {
				t.Fatal("no-ALPN client still advertises ALPN")
			}
		})
	}
}
