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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tsmRun is injectable on the TsmHsmDriver. fakeTsmRun records the
// request line of every batch and returns the configured response for the
// last (operation-of-interest) line, mirroring the helper's protocol.
type fakeTsmRun struct {
	gotBatch  [][]string
	archiveOK *tsmBatch
	restoreOK *tsmBatch
	purgeOK   *tsmBatch
	defBatch  *tsmBatch
	// onBatch, when set, is called with the recorded commands so tests
	// can inspect driver state at the moment a helper would run.
	onBatch func(lines []string)
	// restoreTmpPath lets a test plant a .tsmpartial next to a live path
	// before Restore is invoked.
	restoreTmpDir string
}

func (f *fakeTsmRun) run(ctx context.Context, path string, lines []string) ([]byte, error) {
	captured := append([]string{}, lines...)
	f.gotBatch = append(f.gotBatch, captured)
	// Find the last non-signon, non-quit line (the op of interest).
	var opLine string
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == `{"op":"quit"}` || strings.Contains(l, `"op":"signon"`) || l == `{"op":"ping"}` {
			continue
		}
		opLine = l
		break
	}
	// Route to the right batch based on the op.
	var b *tsmBatch
	switch {
	case strings.Contains(opLine, `"op":"send"`):
		b = f.archiveOK
	case strings.Contains(opLine, `"op":"get"`):
		b = f.restoreOK
	case strings.Contains(opLine, `"op":"delete"`):
		b = f.purgeOK
	default:
		b = f.defBatch
	}
	if b == nil {
		b = f.defBatch
	}
	if b == nil {
		return []byte(`{"ok":false,"op":"fake-missing","rc":-1,"msg":"fake: no batch configured"}` + "\n"), nil
	}
	return b.result, b.err
}

type tsmBatch struct {
	result []byte
	err    error
}

func okResp(op string) []byte {
	if op == "signon" {
		return []byte(`{"ok":true,"op":"signon","server":"storage1","sv":"8.1.27.1"}` + "\n")
	}
	return []byte(fmt.Sprintf(`{"ok":true,"op":%q}`, op) + "\n")
}

func errResp(op string, rc int, msg string) []byte {
	return []byte(fmt.Sprintf(`{"ok":false,"op":%q,"rc":%d,"msg":%q}`, op, rc, msg) + "\n")
}

func newTsmFakeDriver(t *testing.T, archiveOK, restoreOK, purgeOK *tsmBatch) (*TsmHsmDriver, *fakeTsmRun) {
	t.Helper()
	rootdir := t.TempDir()
	return newTsmFakeDriverInRoot(t, rootdir, archiveOK, restoreOK, purgeOK)
}

func newTsmFakeDriverInRoot(t *testing.T, rootdir string, archiveOK, restoreOK, purgeOK *tsmBatch) (*TsmHsmDriver, *fakeTsmRun) {
	t.Helper()
	f := &fakeTsmRun{
		archiveOK: archiveOK,
		restoreOK: restoreOK,
		purgeOK:   purgeOK,
	}
	d, err := NewTsmDriver(TsmOpts{
		Node:      "node1",
		Timeout:   5 * time.Second,
		Filespace: rootdir,
	}, rootdir)
	if err != nil {
		t.Fatalf("NewTsmDriver: %v", err)
	}
	d.run = f.run
	return d, f
}

// tsmSeedFile creates a regular file at path with n bytes and returns its path.
func tsmSeedFile(t *testing.T, path string, n int) string {
	t.Helper()
	data := make([]byte, n)
	for i := range data {
		data[i] = byte('a' + i%26)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("tsmSeedFile: %v", err)
	}
	return path
}

func TestParseTsmLocator_RoundTrip(t *testing.T) {
	cases := []struct {
		fs, hl, ll string
	}{
		{"/data", "a/b", "c.dat"},
		{"/data", "", "top.dat"},
		{"/data/sub/root", "dir with space/inner", "name with space.txt"},
		{"/data", "a:b", "c:d"},
		{"/data", "p%q", "r%q"},
	}
	for _, c := range cases {
		loc := tsmLocator(c.fs, c.hl, c.ll)
		fs, hl, ll, ok := parseTsmLocator(loc)
		if !ok {
			t.Fatalf("parseTsmLocator(%q) = ok false", loc)
		}
		if fs != c.fs || hl != c.hl || ll != c.ll {
			t.Errorf("round-trip mismatch: want (%q,%q,%q), got (%q,%q,%q)", c.fs, c.hl, c.ll, fs, hl, ll)
		}
	}
}

func TestParseTsmLocator_Malformed(t *testing.T) {
	cases := []string{
		"",
		"bareos:100:/path",
		"tsm:",
		"tsm:one",
		"tsm:one:two",
		"tsm:/bad",
		"tsm:/root:",    // empty ll
		"tsm:/root:%zz", // bad escape
	}
	for _, loc := range cases {
		if _, _, _, ok := parseTsmLocator(loc); ok {
			t.Errorf("parseTsmLocator(%q) = ok true; want false", loc)
		}
	}
}

func TestDecomposePath(t *testing.T) {
	fs := "/root/data"
	cases := []struct {
		path   string
		hl     string
		ll     string
		wantOK bool
	}{
		{filepath.Join(fs, "a", "b", "c.dat"), "a/b", "c.dat", true},
		{filepath.Join(fs, "top.dat"), "", "top.dat", true},
		{"/other", "", "", false},              // wrong fs
		{fs, "", "", false},                    // fs itself
		{filepath.Join(fs, ""), "", "", false}, // trailing slash = empty
	}
	for _, tc := range cases {
		hl, ll, err := decomposePath(fs, tc.path)
		ok := err == nil
		if ok != tc.wantOK {
			t.Errorf("decomposePath(%q) ok=%v; want ok=%v (err=%v)", tc.path, ok, tc.wantOK, err)
			continue
		}
		if tc.wantOK && (hl != tc.hl || ll != tc.ll) {
			t.Errorf("decomposePath(%q) = (%q,%q); want (%q,%q)", tc.path, hl, ll, tc.hl, tc.ll)
		}
	}
}

func TestDecomposePath_SizeLimits(t *testing.T) {
	fs := "/root"
	longLL := strings.Repeat("x", tsmMaxLLBytes+1)
	longHL := strings.Repeat("x", tsmMaxHLBytes+1)
	if _, _, err := decomposePath(fs, filepath.Join(fs, longLL)); err == nil {
		t.Errorf("decomposePath: expected error for ll > %d bytes", tsmMaxLLBytes)
	}
	if _, _, err := decomposePath(fs, filepath.Join(fs, longHL, "x.dat")); err == nil {
		t.Errorf("decomposePath: expected error for hl > %d bytes", tsmMaxHLBytes)
	}
}

func TestTsmDriver_ArchiveWave_OK(t *testing.T) {
	rootdir := t.TempDir()
	f := filepath.Join(rootdir, "bucket", "key1")
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	tsmSeedFile(t, f, 1024)
	d, fake := newTsmFakeDriverInRoot(t, rootdir, &tsmBatch{result: okResp("send")}, nil, nil)

	files := []WaveFile{{Path: f, Size: 1024}}
	locs, err := d.ArchiveWave(context.Background(), files)
	if err != nil {
		t.Fatalf("ArchiveWave: %v", err)
	}
	if len(locs) != 1 {
		t.Fatalf("ArchiveWave: got %d locators, want 1", len(locs))
	}
	// Locator should be well-formed and round-trip.
	_, hl, ll, ok := parseTsmLocator(locs[0])
	if !ok {
		t.Fatalf("locator %q does not parse", locs[0])
	}
	if hl != "bucket" || ll != "key1" {
		t.Fatalf("locator (%q,%q); want (bucket,key1)", hl, ll)
	}
	// The batch should contain signon first, the send, and quit last.
	if len(fake.gotBatch) != 1 {
		t.Fatalf("fake run: %d batches, want 1", len(fake.gotBatch))
	}
	lines := fake.gotBatch[0]
	if !strings.Contains(lines[0], `"op":"signon"`) {
		t.Errorf("batch[0] should be signon, got %s", lines[0])
	}
	if !strings.Contains(lines[1], `"op":"send"`) {
		t.Errorf("batch[1] should be send, got %s", lines[1])
	}
	if len(lines) >= 3 && !strings.Contains(lines[len(lines)-1], `"op":"quit"`) {
		t.Errorf("last batch line should be quit, got %s", lines[len(lines)-1])
	}
}

func TestTsmDriver_ArchiveWave_SendFail(t *testing.T) {
	rootdir := t.TempDir()
	f := filepath.Join(rootdir, "a.dat")
	tsmSeedFile(t, f, 64)
	d, _ := newTsmFakeDriverInRoot(t, rootdir,
		&tsmBatch{result: errResp("send", 100, "no space on server")}, nil, nil)

	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: f, Size: 64}}); err == nil {
		t.Fatalf("ArchiveWave should fail when send fails")
	}
}

func TestTsmDriver_ArchiveWave_VanishedFile(t *testing.T) {
	rootdir := t.TempDir()
	d, _ := newTsmFakeDriverInRoot(t, rootdir, &tsmBatch{result: okResp("send")}, nil, nil)
	vanished := filepath.Join(rootdir, "gone.dat")
	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: vanished, Size: 0}}); err == nil {
		t.Fatalf("ArchiveWave: expected error for vanished file")
	}
}

func TestTsmDriver_ArchiveWave_WrongFilespace(t *testing.T) {
	rootdir := t.TempDir()
	d, _ := newTsmFakeDriverInRoot(t, rootdir, &tsmBatch{result: okResp("send")}, nil, nil)
	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: "/etc/hostname", Size: 0}}); err == nil {
		t.Fatalf("ArchiveWave: expected error for path outside filespace")
	}
}

func TestTsmDriver_ArchiveWave_MultiWave(t *testing.T) {
	rootdir := t.TempDir()
	d, _ := newTsmFakeDriverInRoot(t, rootdir, &tsmBatch{result: okResp("send")}, nil, nil)

	if !d.SingleWave() {
		// TSM is transactional per file -> waves are allowed to be split.
	} else {
		t.Fatalf("TSM driver reports SingleWave=true; this driver is per-file")
	}

	files := make([]WaveFile, 5)
	for i := range files {
		p := filepath.Join(rootdir, fmt.Sprintf("w%d.dat", i))
		tsmSeedFile(t, p, 16+i)
		files[i] = WaveFile{Path: p, Size: 16 + int64(i)}
	}
	// The daemon splits into waves of <= 256; this driver accepts any size.
	locs, err := d.ArchiveWave(context.Background(), files)
	if err != nil {
		t.Fatalf("ArchiveWave: %v", err)
	}
	if len(locs) != len(files) {
		t.Fatalf("ArchiveWave: %d locators, want %d", len(locs), len(files))
	}
}

func TestTsmDriver_ArchiveWave_EmptyIsNoop(t *testing.T) {
	rootdir := t.TempDir()
	d, fake := newTsmFakeDriverInRoot(t, rootdir, &tsmBatch{result: okResp("send")}, nil, nil)
	locs, err := d.ArchiveWave(context.Background(), nil)
	if err != nil || len(locs) != 0 {
		t.Fatalf("ArchiveWave(empty) = (%v,%v); want (nil,nil)", locs, err)
	}
	if len(fake.gotBatch) != 0 {
		t.Fatalf("ArchiveWave(empty) should not invoke helper, got %d batches", len(fake.gotBatch))
	}
}

func TestTsmDriver_Restore_OK(t *testing.T) {
	rootdir := t.TempDir()
	livePath := filepath.Join(rootdir, "bkt", "obj1")
	if err := os.MkdirAll(filepath.Dir(livePath), 0o755); err != nil {
		t.Fatal(err)
	}
	// The live file must exist (the daemon creates it before Restore). It is
	// expected to be 0 bytes after truncation (or contain the data we'll
	// restore over).
	if err := os.WriteFile(livePath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	// Plant a .tsmpartial as if the helper had just restored it.
	partial := livePath + ".tsmpartial"
	payload := []byte("hello-restore")
	if err := os.WriteFile(partial, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	d, _ := newTsmFakeDriverInRoot(t, rootdir, nil,
		&tsmBatch{result: []byte(`{"ok":true,"op":"get","found":true,"bytes":13,"tmp":"` + partial + `"}` + "\n")}, nil)

	loc := tsmLocator(rootdir, "bkt", "obj1")
	var buf bytes.Buffer
	if err := d.Restore(context.Background(), loc, &buf, int64(len(payload))); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatalf("ReadFile(livePath): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("live file after restore: %q; want %q", got, payload)
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Errorf("partial file should be gone after rename")
	}
}

func TestTsmDriver_Restore_NotFound(t *testing.T) {
	rootdir := t.TempDir()
	live := filepath.Join(rootdir, "n.dat")
	_ = os.WriteFile(live, []byte{}, 0o644)
	notFound := []byte(`{"ok":true,"op":"get","found":false}` + "\n")
	d, _ := newTsmFakeDriverInRoot(t, rootdir, nil, &tsmBatch{result: notFound}, nil)
	loc := tsmLocator(rootdir, "", "n.dat")
	if err := d.Restore(context.Background(), loc, io.Discard, 0); err == nil {
		t.Fatalf("Restore: expected error when helper reports found=false")
	}
}

func TestTsmDriver_Restore_MalformedLocator(t *testing.T) {
	rootdir := t.TempDir()
	d, _ := newTsmFakeDriverInRoot(t, rootdir, nil, &tsmBatch{result: okResp("get")}, nil)
	if err := d.Restore(context.Background(), "bareos:123:/x", io.Discard, 1); err == nil {
		t.Fatalf("Restore: expected error on malformed locator")
	}
}

func TestTsmDriver_Restore_CrossFilespace(t *testing.T) {
	rootdir := t.TempDir()
	d, _ := newTsmFakeDriverInRoot(t, rootdir, nil, &tsmBatch{result: okResp("get")}, nil)
	other := tsmLocator("/other-fs", "b", "obj")
	if err := d.Restore(context.Background(), other, io.Discard, 1); err == nil {
		t.Fatalf("Restore: expected error for cross-driver (filespace) locator")
	}
}

func TestTsmDriver_Purge_OK(t *testing.T) {
	rootdir := t.TempDir()
	d, _ := newTsmFakeDriverInRoot(t, rootdir, nil, nil, &tsmBatch{result: []byte(`{"ok":true,"op":"delete","deleted":1}` + "\n")})
	loc := tsmLocator(rootdir, "a", "b.c")
	if err := d.Purge(context.Background(), loc); err != nil {
		t.Fatalf("Purge: %v", err)
	}
}

func TestTsmDriver_Purge_NotFoundIsNoop(t *testing.T) {
	rootdir := t.TempDir()
	d, _ := newTsmFakeDriverInRoot(t, rootdir, nil, nil, &tsmBatch{result: []byte(`{"ok":true,"op":"delete","deleted":0}` + "\n")})
	loc := tsmLocator(rootdir, "a", "b.c")
	if err := d.Purge(context.Background(), loc); err != nil {
		t.Fatalf("Purge (idempotent no-op): %v", err)
	}
}

func TestTsmDriver_Purge_Malformed(t *testing.T) {
	rootdir := t.TempDir()
	d, _ := newTsmFakeDriverInRoot(t, rootdir, nil, nil, nil)
	if err := d.Purge(context.Background(), "not-a-locator"); err == nil {
		t.Fatalf("Purge: expected error on malformed locator")
	}
}

func TestTsmDriver_BatchIncludesSignonAndQuit(t *testing.T) {
	rootdir := t.TempDir()
	f := filepath.Join(rootdir, "x.dat")
	tsmSeedFile(t, f, 8)
	fake := &fakeTsmRun{
		defBatch: &tsmBatch{result: []byte(`{"ok":true,"op":"send"}` + "\n")},
	}
	d, _ := newTsmFakeDriverInRoot(t, rootdir, nil, nil, nil)
	d.run = fake.run

	// Run a single-archive wave to inspect the exact batch.
	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: f, Size: 8}}); err != nil {
		t.Fatalf("ArchiveWave: %v", err)
	}
	if len(fake.gotBatch) != 1 {
		t.Fatalf("fake: %d batches, want 1", len(fake.gotBatch))
	}
	batch := fake.gotBatch[0]
	if len(batch) < 3 {
		t.Fatalf("batch too small: %v", batch)
	}
	// First line should be a valid signon JSON.
	var first struct {
		Op   string `json:"op"`
		Node string `json:"node"`
	}
	if err := json.Unmarshal([]byte(batch[0]), &first); err != nil {
		t.Fatalf("batch[0] not valid JSON: %v (%q)", err, batch[0])
	}
	if first.Op != "signon" {
		t.Errorf("batch[0].op = %q; want signon", first.Op)
	}
	if first.Node != "node1" {
		t.Errorf("batch[0].node = %q; want node1", first.Node)
	}
	// Last line should be quit.
	var last struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal([]byte(batch[len(batch)-1]), &last); err != nil {
		t.Fatalf("last batch line not valid JSON: %v (%q)", err, batch[len(batch)-1])
	}
	if last.Op != "quit" {
		t.Errorf("last batch op = %q; want quit", last.Op)
	}
}

func TestTsmDriver_OptDefaults(t *testing.T) {
	o := TsmOpts{}
	o.withDefaults()
	if o.ClientDir != "/opt/tivoli/tsm/client/api/bin64" {
		t.Errorf("ClientDir default = %q", o.ClientDir)
	}
	if o.Timeout != 30*time.Minute {
		t.Errorf("Timeout default = %v; want 30m", o.Timeout)
	}
}

func TestTsmDriver_New_RequiresNode(t *testing.T) {
	if _, err := NewTsmDriver(TsmOpts{Timeout: time.Second}, "/tmp/ro"); err == nil {
		t.Errorf("NewTsmDriver: expected error when Node is missing")
	}
}

func TestTsmDriver_New_RequiresRoot(t *testing.T) {
	if _, err := NewTsmDriver(TsmOpts{Node: "n", Timeout: time.Second}, ""); err == nil {
		t.Errorf("NewTsmDriver: expected error when rootdir is missing")
	}
}

func TestTsmDriver_New_RelativeFilespaceReject(t *testing.T) {
	if _, err := NewTsmDriver(TsmOpts{Node: "n", Filespace: "relative/path", Timeout: time.Second}, "/tmp"); err == nil {
		t.Errorf("NewTsmDriver: expected error for relative Filespace")
	}
}

func TestTsmDriver_TsmBatch_Malformed(t *testing.T) {
	d, _ := newTsmFakeDriverInRoot(t, t.TempDir(), nil, nil, nil)
	d.run = func(ctx context.Context, path string, lines []string) ([]byte, error) {
		return []byte("this is not json\n"), nil
	}
	if _, err := d.tsmBatch(context.Background(), []string{`{"op":"ping"}`}); err == nil {
		t.Errorf("tsmBatch: expected error on malformed response")
	}
}

func TestTsmDriver_TsmBatch_HelperError(t *testing.T) {
	d, _ := newTsmFakeDriverInRoot(t, t.TempDir(), nil, nil, nil)
	d.run = func(ctx context.Context, path string, lines []string) ([]byte, error) {
		return nil, fmt.Errorf("helper exploded")
	}
	if _, err := d.tsmBatch(context.Background(), []string{`{"op":"ping"}`}); err == nil {
		t.Errorf("tsmBatch: expected error when helper process fails")
	}
}
