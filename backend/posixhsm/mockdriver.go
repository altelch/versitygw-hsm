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
	"crypto/sha256"
	"encoding/hex"
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
var _ MetaPayload = (*MockDriver)(nil)

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

func (m *MockDriver) metaDir() string { return filepath.Join(m.dir, "mock", "meta") }

func (m *MockDriver) makeLocator(off, length int64, metaName string) string {
	b := "mock:" + m.dataPath + ":" + strconv.FormatInt(off, 10) + ":" + strconv.FormatInt(length, 10)
	if metaName != "" {
		b += ":m=" + metaName
	}
	return b
}

// metaNameOf extracts the ":m=<name>" companion encoding from a mock
// locator, returning "" when the locator carries no companion.
func metaNameOf(loc string) string {
	const mark = ":m="
	i := strings.LastIndex(loc, mark)
	if i < 0 {
		return ""
	}
	return loc[i+len(mark):]
}

// stripMeta removes the ":m=<name>" suffix (if any) from a mock locator,
// leaving the plain "mock:<path>:<off>:<len>" form for parseLocator.
func stripMeta(loc string) string {
	const mark = ":m="
	if i := strings.LastIndex(loc, mark); i >= 0 {
		return loc[:i]
	}
	return loc
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
	// Data objects go into the shared data file (append, atomic offsets).
	// Metadata companions — when present — are written as one self-contained
	// file each under <dir>/mock/meta/, so they are independently
	// addressable (FetchMeta) and purgeable without rewriting the data
	// file. The companion file name is a stable hash of the object's live
	// path, and it is also encoded into the locator (":m=<name>") so that
	// FetchMeta/Purge — which only see the locator — can find it.
	metaDir := filepath.Join(m.dir, "mock", "meta")

	// Reserve contiguous offsets for the data objects.
	offsets := make([]int64, len(files))
	for _, f := range files {
		if f.Size < 0 {
			return nil, fmt.Errorf("mock driver: negative size for %s", f.Path)
		}
	}
	m.mu.Lock()
	base := int64(m.next.Load())
	for i, f := range files {
		offsets[i] = base
		base += f.Size
	}
	m.next.Store(uint64(base))
	m.mu.Unlock()

	// Write data objects.
	fh, err := os.OpenFile(m.dataPath, os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("mock driver: open: %w", err)
	}
	for i, wf := range files {
		if wf.Size > 0 {
			src, err := os.Open(wf.Path)
			if err != nil {
				fh.Close()
				return nil, fmt.Errorf("mock driver: open %s: %w", wf.Path, err)
			}
			if _, s_err := fh.Seek(offsets[i], io.SeekStart); s_err != nil {
				src.Close()
				fh.Close()
				return nil, fmt.Errorf("mock driver: seek to %d: %w", offsets[i], s_err)
			}
			nw, cerr := io.CopyN(fh, src, wf.Size)
			src.Close()
			if cerr != nil && !errors.Is(cerr, io.EOF) {
				fh.Close()
				return nil, fmt.Errorf("mock driver: append %s: %w", wf.Path, cerr)
			}
			if nw != wf.Size {
				fh.Close()
				return nil, fmt.Errorf("mock driver: short write for %s: %d != %d", wf.Path, nw, wf.Size)
			}
		}
		locs[i] = m.makeLocator(offsets[i], wf.Size, "") // meta name set below if present
	}
	fh.Close()

	// Write metadata companions and record their name in the locator.
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		return nil, fmt.Errorf("mock driver: mkdir meta: %w", err)
	}
	for i, wf := range files {
		if len(wf.Meta) == 0 {
			continue
		}
		metaName := metaCompanionName(wf.Path)
		metaPath := filepath.Join(metaDir, metaName)
		if err := os.WriteFile(metaPath, wf.Meta, 0o644); err != nil {
			return nil, fmt.Errorf("mock driver: write meta %s: %w", metaPath, err)
		}
		locs[i] = m.makeLocator(offsets[i], wf.Size, metaName)
	}
	return locs, nil
}

// metaCompanionName derives a stable, filesystem-safe companion file name
// from an object's live path (sha256, hex-encoded).
func metaCompanionName(livePath string) string {
	sum := sha256.Sum256([]byte(livePath))
	return hex.EncodeToString(sum[:16]) + MetaSuffix
}

func (m *MockDriver) Restore(ctx context.Context, locator string, wr io.Writer, size int64) error {
	path, offset, length, err := parseLocator(stripMeta(locator))
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

func (m *MockDriver) Purge(_ context.Context, locator string) error {
	// The mock stores data ranges inside a shared file and cannot reclaim
	// that space without a rewrite, but the metadata companion is a real
	// file and IS removed to honour the idempotent contract (and to avoid
	// leaking the payload).
	if name := metaNameOf(locator); name != "" {
		_ = os.Remove(filepath.Join(m.metaDir(), name))
	}
	return nil
}

// FetchMeta implements MetaPayload: it returns the archived metadata
// companion for the object described by locator. A locator without a
// companion (":m=" absent) yields an empty payload, not an error.
func (m *MockDriver) FetchMeta(ctx context.Context, locator string) ([]byte, error) {
	name := metaNameOf(locator)
	if name == "" {
		return nil, nil // no companion was archived
	}
	b, err := os.ReadFile(filepath.Join(m.metaDir(), name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("mock driver: read meta %q: %w", name, err)
	}
	return b, nil
}

func (m *MockDriver) Close() error { return nil }
