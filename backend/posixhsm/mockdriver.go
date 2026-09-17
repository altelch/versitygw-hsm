// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package posixhsm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// MockDriver is an HsmDriver backed by local files. It appends the
// archived bytes of each object to a shared data file under
// <dir>/mock/data and returns one locator per file of the form
// "mock:<abspath>:<offset>:<length>". It is intended for unit tests and
// local development where no real tape subsystem is available.
//
// The single shared data file avoids one file per object. Offsets are
// assigned atomically, so restarts do not corrupt previously appended
// data. Purge is a no-op (the mock cannot reclaim a range without a
// rewrite), satisfying the idempotent contract.
type MockDriver struct {
	dataPath string
	dir      string

	mu   sync.Mutex
	next atomic.Uint64
}

var _ HsmDriver = (*MockDriver)(nil)

// NewMockDriver creates a mock driver rooted at dir, creating the mock
// data directory and data file if needed.
func NewMockDriver(dir string) (*MockDriver, error) {
	if dir == "" {
		return nil, errors.New("mock driver: empty dir")
	}
	mockDir := filepath.Join(dir, "mock")
	if err := os.MkdirAll(mockDir, 0o755); err != nil {
		return nil, fmt.Errorf("mock driver: mkdir: %w", err)
	}
	dataPath := filepath.Join(mockDir, "data")
	d := &MockDriver{dataPath: dataPath, dir: dir}
	if fi, err := os.Stat(dataPath); err == nil {
		d.next.Store(uint64(fi.Size()))
	} else {
		if err := os.WriteFile(dataPath, nil, 0o644); err != nil {
			return nil, fmt.Errorf("mock driver: create data: %w", err)
		}
	}
	return d, nil
}

func (m *MockDriver) Name() string { return "mock" }

func (m *MockDriver) makeLocator(off, length int64) string {
	return "mock:" + m.dataPath + ":" + strconv.FormatInt(off, 10) + ":" + strconv.FormatInt(length, 10)
}

// parseLocator splits "mock:<path>:<off>:<len>" into its components using
// the last two colons (the path may legitimately contain other characters).
func parseLocator(loc string) (path string, offset, length int64, err error) {
	if !strings.HasPrefix(loc, "mock:") {
		return "", 0, 0, fmt.Errorf("mock driver: locator %q is not a mock locator", loc)
	}
	rest := loc[len("mock:"):]
	j := strings.LastIndex(rest, ":")
	if j < 0 {
		return "", 0, 0, fmt.Errorf("mock driver: malformed locator: %q", loc)
	}
	lengthStr := rest[j+1:]
	rest = rest[:j]
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return "", 0, 0, fmt.Errorf("mock driver: malformed locator: %q", loc)
	}
	offsetStr := rest[i+1:]
	path = rest[:i]
	if path == "" {
		return "", 0, 0, fmt.Errorf("mock driver: empty path in locator: %q", loc)
	}
	if offset, err = strconv.ParseInt(offsetStr, 10, 64); err != nil {
		return "", 0, 0, fmt.Errorf("mock driver: bad offset %q: %w", offsetStr, err)
	}
	if length, err = strconv.ParseInt(lengthStr, 10, 64); err != nil {
		return "", 0, 0, fmt.Errorf("mock driver: bad length %q: %w", lengthStr, err)
	}
	return path, offset, length, nil
}

func (m *MockDriver) ArchiveWave(ctx context.Context, files []WaveFile) ([]string, error) {
	locs := make([]string, len(files))
	// Phase 1: allocate contiguous offsets for every file. If any file is
	// unreadable at archive time the whole wave fails (files unmodified).
	offsets := make([]int64, len(files))
	m.mu.Lock()
	var base int64 = int64(m.next.Load())
	for i, f := range files {
		if f.Size < 0 {
			m.mu.Unlock()
			return nil, fmt.Errorf("mock driver: negative size for %s", f.Path)
		}
		offsets[i] = base
		base += f.Size
	}
	m.next.Store(uint64(base))
	m.mu.Unlock()

	// Phase 2: read each file and append at its reserved offset.
	f, err := os.OpenFile(m.dataPath, os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("mock driver: open: %w", err)
	}
	defer f.Close()
	for i, wf := range files {
		if wf.Size == 0 {
			locs[i] = m.makeLocator(offsets[i], 0)
			continue
		}
		src, err := os.Open(wf.Path)
		if err != nil {
			return nil, fmt.Errorf("mock driver: open %s: %w", wf.Path, err)
		}
		nw, cerr := io.CopyN(f, src, wf.Size)
		src.Close()
		if cerr != nil && !errors.Is(cerr, io.EOF) {
			return nil, fmt.Errorf("mock driver: append %s: %w", wf.Path, cerr)
		}
		if nw != wf.Size {
			return nil, fmt.Errorf("mock driver: short write for %s: wrote %d, want %d", wf.Path, nw, wf.Size)
		}
		locs[i] = m.makeLocator(offsets[i], wf.Size)
	}
	return locs, nil
}

func (m *MockDriver) Restore(ctx context.Context, locator string, wr io.Writer, size int64) error {
	path, offset, length, err := parseLocator(locator)
	if err != nil {
		return err
	}
	if path != m.dataPath {
		return fmt.Errorf("mock driver: locator points to %q, expected %q", path, m.dataPath)
	}
	if size > 0 && length != size {
		return fmt.Errorf("mock driver: size mismatch: locator has %d, want %d", length, size)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("mock driver: open: %w", err)
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("mock driver: seek: %w", err)
	}
	n, err := io.CopyN(wr, f, length)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("mock driver: read %d bytes: %w", length, err)
	}
	if n != length {
		return fmt.Errorf("mock driver: short read: got %d, want %d", n, length)
	}
	return nil
}

func (m *MockDriver) Purge(_ context.Context, _ string) error {
	// The mock stores ranges inside a shared file and cannot reclaim space
	// without a rewrite; Purge is a no-op satisfying the idempotent
	// contract.
	return nil
}

func (m *MockDriver) Close() error { return nil }
