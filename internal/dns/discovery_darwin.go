package dns

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func Discover(ctx context.Context) (Discovery, error) {
	b, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return Discovery{}, fmt.Errorf("scutil DNS discovery: %w", err)
	}
	d, err := ParseScutil(string(b))
	if err != nil {
		return d, err
	}
	return usable(d)
}
func bindInterface(index int) func(string, string, syscall.RawConn) error {
	if index == 0 {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		e := c.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index) })
		if e != nil {
			return e
		}
		return err
	}
}
