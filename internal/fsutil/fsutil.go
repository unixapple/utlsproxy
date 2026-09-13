package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func PrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("not a real directory: %s", path)
	}
	if i.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("directory %s must be private (chmod 700)", path)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return err
	}
	if st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private directory belongs to another user: %s", path)
	}
	return nil
}
func Exclusive(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// Atomic replaces only the explicitly supplied target. Callers own conflict checks.
func Atomic(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".utlsproxy-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err == nil {
		defer d.Close()
		_ = d.Sync()
	}
	return nil
}
func Lock(path string) (func(), error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("already locked %s: %w", path, err)
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }, nil
}
func Regular(path string) error {
	i, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", path)
	}
	return nil
}
func RootOwned(path string) error {
	lexical, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for p := lexical; ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if err = unix.Lstat(p, &st); err != nil {
			return err
		}
		if st.Uid != 0 || (st.Mode&unix.S_IFMT != unix.S_IFLNK && st.Mode&0022 != 0) {
			return fmt.Errorf("root service requires a protected path: %s", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	p, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for {
		i, err := os.Stat(p)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err = unix.Stat(p, &st); err != nil {
			return err
		}
		if st.Uid != 0 || i.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("root service requires root-owned, non-writable path: %s", p)
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	return nil
}
func IsMissing(err error) bool { return errors.Is(err, os.ErrNotExist) }
