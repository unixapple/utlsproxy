// Package hosts edits only an explicitly marked block and preserves other bytes.
package hosts

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/unixapple/utlsproxy/internal/fsutil"
	"golang.org/x/sys/unix"
)

const Begin = "# BEGIN utlsproxy managed hosts v1"
const End = "# END utlsproxy managed hosts v1"

type Plan struct {
	Path      string   `json:"path"`
	Changed   bool     `json:"changed"`
	Managed   []string `json:"managed"`
	Conflicts []string `json:"conflicts,omitempty"`
	Diff      string   `json:"diff"`
	Before    []byte   `json:"-"`
	After     []byte   `json:"-"`
}

func block(b []byte) (start, end int, err error) {
	start, end = -1, -1
	offset := 0
	for _, line := range bytes.SplitAfter(b, []byte("\n")) {
		t := strings.TrimSpace(string(line))
		if strings.HasPrefix(t, "# BEGIN utlsproxy") || strings.HasPrefix(t, "# END utlsproxy") {
			if t == Begin && start < 0 && end < 0 {
				start = offset
			} else if t == End && start >= 0 && end < 0 {
				end = offset + len(line)
			} else {
				return 0, 0, errors.New("malformed, duplicate or unknown-version utlsproxy hosts block")
			}
		}
		offset += len(line)
	}
	if (start < 0) != (end < 0) {
		return 0, 0, errors.New("incomplete utlsproxy hosts block")
	}
	return start, end, nil
}
func Prepare(path string, domains []string, address string, remove bool) (Plan, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Plan{}, err
	}
	if err = fsutil.Regular(resolved); err != nil {
		return Plan{}, err
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return Plan{}, err
	}
	if len(b) > 4*1024*1024 {
		return Plan{}, errors.New("hosts file exceeds 4 MiB")
	}
	start, end, err := block(b)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Path: resolved, Before: b, Managed: []string{}}
	out := append([]byte{}, b...)
	if start >= 0 {
		for _, line := range strings.Split(string(b[start:end]), "\n") {
			if !strings.HasPrefix(line, "#") && strings.TrimSpace(line) != "" {
				p.Managed = append(p.Managed, line)
			}
		}
		out = append(append([]byte{}, b[:start]...), b[end:]...)
	}
	wanted := map[string]bool{}
	for _, d := range domains {
		wanted[d] = true
	}
	for _, line := range strings.Split(string(out), "\n") {
		text, _, _ := strings.Cut(line, "#")
		parts := strings.Fields(text)
		if len(parts) < 2 {
			continue
		}
		for _, name := range parts[1:] {
			if wanted[strings.TrimSuffix(strings.ToLower(name), ".")] {
				p.Conflicts = append(p.Conflicts, line)
			}
		}
	}
	if !remove && len(p.Conflicts) > 0 {
		return p, fmt.Errorf("unmanaged hosts entries conflict with configured domains: %v", p.Conflicts)
	}
	if !remove {
		var generated strings.Builder
		generated.WriteString(Begin + "\n")
		for _, d := range domains {
			fmt.Fprintf(&generated, "%s %s\n", address, d)
		}
		generated.WriteString(End + "\n")
		if start >= 0 {
			out = append(append(append([]byte{}, b[:start]...), []byte(generated.String())...), b[end:]...)
		} else {
			if len(out) > 0 && out[len(out)-1] != '\n' {
				out = append(out, '\n')
			}
			out = append(out, generated.String()...)
		}
	}
	p.After = out
	p.Changed = !bytes.Equal(b, out)
	if p.Changed {
		p.Diff = fmt.Sprintf("--- %s (current)\n+++ %s (proposed)\n%s", p.Path, p.Path, lineDiff(b, out))
	} else {
		p.Diff = "No hosts changes needed.\n"
	}
	return p, nil
}
func lineDiff(before, after []byte) string {
	a, b := strings.SplitAfter(string(before), "\n"), strings.SplitAfter(string(after), "\n")
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	j, k := len(a), len(b)
	for j > i && k > i && a[j-1] == b[k-1] {
		j--
		k--
	}
	var out strings.Builder
	fmt.Fprintf(&out, "@@ lines %d..%d -> %d..%d @@\n", i+1, j, i+1, k)
	for _, line := range a[i:j] {
		out.WriteString("-" + line)
	}
	for _, line := range b[i:k] {
		out.WriteString("+" + line)
	}
	return out.String()
}
func Apply(p Plan, stateDir string) (string, error) {
	if !p.Changed {
		return "", nil
	}
	if err := fsutil.PrivateDir(stateDir); err != nil {
		return "", err
	}
	unlock, err := fsutil.Lock(filepath.Join(stateDir, "hosts.lock"))
	if err != nil {
		return "", err
	}
	defer unlock()
	current, err := os.ReadFile(p.Path)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(current, p.Before) {
		return "", errors.New("hosts changed concurrently; review and retry")
	}
	backup := filepath.Join(stateDir, "hosts-backup-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err = fsutil.Exclusive(backup, p.Before, 0600); err != nil {
		return "", err
	}
	var st unix.Stat_t
	if err = unix.Stat(p.Path, &st); err != nil {
		return backup, err
	}
	f, err := os.CreateTemp(filepath.Dir(p.Path), ".utlsproxy-hosts-*")
	if err != nil {
		return backup, err
	}
	defer f.Close()
	defer os.Remove(f.Name())
	if _, err = f.Write(p.After); err != nil {
		return backup, err
	}
	if err = f.Chown(int(st.Uid), int(st.Gid)); err != nil {
		return backup, err
	}
	if err = f.Chmod(os.FileMode(st.Mode) & 0777); err != nil {
		return backup, err
	}
	if err = copyXattrs(p.Path, f.Name()); err != nil {
		return backup, err
	}
	if err = f.Sync(); err != nil {
		return backup, err
	}
	if err = f.Close(); err != nil {
		return backup, err
	}
	current, err = os.ReadFile(p.Path)
	if err != nil {
		return backup, err
	}
	if sha256.Sum256(current) != sha256.Sum256(p.Before) {
		return backup, errors.New("hosts changed concurrently before replacement; no changes applied")
	}
	var latest unix.Stat_t
	if err = unix.Stat(p.Path, &latest); err != nil {
		return backup, err
	}
	if st.Ino != latest.Ino || st.Mode != latest.Mode || st.Uid != latest.Uid || st.Gid != latest.Gid {
		return backup, errors.New("hosts identity or metadata changed concurrently")
	}
	if err = os.Rename(f.Name(), p.Path); err != nil {
		return backup, fmt.Errorf("atomic hosts replacement unsupported or failed: %w", err)
	}
	d, e := os.Open(filepath.Dir(p.Path))
	if e == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return backup, nil
}
func copyXattrs(src, dst string) error {
	n, err := unix.Listxattr(src, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if n > 1024*1024 {
		return errors.New("hosts metadata too large")
	}
	buf := make([]byte, n)
	n, err = unix.Listxattr(src, buf)
	if err != nil {
		return err
	}
	for _, key := range strings.Split(string(buf[:n]), "\x00") {
		if key == "" {
			continue
		}
		size, e := unix.Getxattr(src, key, nil)
		if e != nil {
			return e
		}
		if size > 1024*1024 {
			return errors.New("hosts attribute too large")
		}
		data := make([]byte, size)
		size, e = unix.Getxattr(src, key, data)
		if e != nil {
			return e
		}
		if e = unix.Setxattr(dst, key, data[:size], 0); e != nil {
			return fmt.Errorf("preserving hosts metadata %s: %w", key, e)
		}
	}
	return nil
}
