package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/unixapple/utlsproxy/internal/fsutil"
)

func Listen(path string) (net.Listener, func(), error) {
	if err := fsutil.PrivateDir(filepath.Dir(path)); err != nil {
		return nil, nil, err
	}
	unlock, err := fsutil.Lock(path + ".lock")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { unlock() }
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			cleanup()
			return nil, nil, fmt.Errorf("refusing to remove non-socket path %s", path)
		}
		c, e := net.DialTimeout("unix", path, 250*time.Millisecond)
		if e == nil {
			c.Close()
			cleanup()
			return nil, nil, errors.New("control socket already in use")
		}
		if !errors.Is(e, os.ErrNotExist) && !errors.Is(e, syscall.ECONNREFUSED) {
			cleanup()
			return nil, nil, fmt.Errorf("cannot prove existing socket is stale: %w", e)
		}
		if err = os.Remove(path); err != nil {
			cleanup()
			return nil, nil, err
		}
	} else if !os.IsNotExist(err) {
		cleanup()
		return nil, nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		l.Close()
		cleanup()
		return nil, nil, err
	}
	return l, func() { l.Close(); unlock() }, nil
}
func Request(ctx context.Context, socket, method, path string, out any) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("daemon unavailable at %s: %w", socket, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned %s: %s", resp.Status, string(b))
	}
	return json.Unmarshal(b, out)
}
func JSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
