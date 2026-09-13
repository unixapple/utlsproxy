package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Rotator struct {
	mu    sync.Mutex
	path  string
	file  *os.File
	size  int64
	limit int64
}

func Open(path string) (*Rotator, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if i, e := os.Lstat(path); e == nil && !i.Mode().IsRegular() {
		return nil, fmt.Errorf("log is not a regular file: %s", path)
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	i, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	return &Rotator{path: path, file: f, size: i.Size(), limit: 10 * 1024 * 1024}, nil
}
func (r *Rotator) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(b)) > r.limit {
		if err := r.file.Close(); err != nil {
			return 0, err
		}
		for i := 3; i >= 1; i-- {
			src := r.path
			if i > 1 {
				src = fmt.Sprintf("%s.%d", r.path, i-1)
			}
			dst := fmt.Sprintf("%s.%d", r.path, i)
			if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
				return 0, err
			}
		}
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return 0, err
		}
		r.file = f
		r.size = 0
	}
	n, e := r.file.Write(b)
	r.size += int64(n)
	return n, e
}
func (r *Rotator) Close() error { r.mu.Lock(); defer r.mu.Unlock(); return r.file.Close() }
