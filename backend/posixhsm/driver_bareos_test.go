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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bareosBatch is the recorded console-command list of one bconsole invocation,
// keyed by the kind of batch (chosen by its first command).
type bareosBatch struct {
	cmds   []string
	result []byte
	err    error
}

// fakeExec is a consoleExec that records every batch and returns the
// configured result for the batch type. It is the seam that lets us test the
// driver against documented-shaped Bareos output without a live instance.
type fakeExec struct {
	got     [][]string
	archive *bareosBatch
	restore *bareosBatch
}

func (f *fakeExec) run(ctx context.Context, path, config, director string, cmds []string) ([]byte, error) {
	f.got = append(f.got, append([]string{}, cmds...))
	if len(cmds) == 0 {
		return nil, nil
	}
	for _, c := range cmds {
		switch {
		case strings.HasPrefix(c, "run job="):
			b := f.archive
			if b == nil {
				return nil, fmt.Errorf("fake: no archive batch configured")
			}
			return b.result, b.err
		case strings.HasPrefix(c, "restore client="):
			b := f.restore
			if b == nil {
				return nil, fmt.Errorf("fake: no restore batch configured")
			}
			return b.result, b.err
		}
	}
	return []byte(""), nil
}

func newFakeDriver(archive, restore *bareosBatch) (*BareosHsmDriver, *fakeExec) {
	f := &fakeExec{archive: archive, restore: restore}
	d := newBareosDriverWithExec(BareosOpts{
		Client:     "client1",
		BackupJob:  "BackupTest",
		RestoreJob: "RestoreTest",
		Timeout:    5 * time.Second,
	}, f.run)
	return d, f
}

// archiveOK mirrors a documented successful backup job run (jobid 101) plus the
// `list jobs` JSON-RPC 2.0 response for job name "BackupTest".
func archiveOK(jobname string, jobid int) *bareosBatch {
	return &bareosBatch{result: []byte(fmt.Sprintf(
		"Start Backup Job: %s\n"+
			"Termination:          * Backup completed without errors.\n"+
			`{"jsonrpc":"2.0","id":null,"result":{"jobs":[{"jobid":"%d","name":"%s","type":"B","level":"F","jobstatus":"T"}]}}
`, jobname, jobid, jobname))}
}

// restoreOK mirrors a documented successful restore job run.
func restoreOK() *bareosBatch {
	return &bareosBatch{result: []byte(
		"Start Restore Job: RestoreTest\n" +
			"Termination:          * Restore completed without errors.\n" +
			`{"jsonrpc":"2.0","id":null,"result":{}}
`)}
}

func TestBareosDriver_ArchiveWave(t *testing.T) {
	d, _ := newFakeDriver(archiveOK("BackupTest", 101), restoreOK())

	dir := t.TempDir()
	obj := filepath.Join(dir, "bucket", "key.bin")
	if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	locs, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: obj, Size: 7}})
	if err != nil {
		t.Fatalf("ArchiveWave: %v", err)
	}
	if len(locs) != 1 {
		t.Fatalf("expected 1 locator, got %d", len(locs))
	}
	jobid, path, ok := parseBareosLocator(locs[0])
	if !ok {
		t.Fatalf("malformed locator %q", locs[0])
	}
	if jobid != 101 {
		t.Errorf("locator jobid = %d, want 101", jobid)
	}
	if path != obj {
		t.Errorf("locator path = %q, want %q", path, obj)
	}
}

func TestBareosDriver_ArchiveWaveFailure(t *testing.T) {
	failure := &bareosBatch{result: []byte(
		"Start Backup Job: BackupTest\n" +
			"Termination:          * Fatal error: Volume out of space.\n" +
			`{"jsonrpc":"2.0","id":null,"result":{"jobs":[{"jobid":"101","name":"BackupTest","jobstatus":"F"}]}}
`)}
	d, _ := newFakeDriver(failure, restoreOK())

	dir := t.TempDir()
	obj := filepath.Join(dir, "bucket", "key.bin")
	_ = os.MkdirAll(filepath.Dir(obj), 0o755)
	_ = os.WriteFile(obj, []byte("payload"), 0o644)

	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: obj, Size: 7}}); err == nil {
		t.Error("expected error when job report indicates failure")
	}
	if d != nil {
		d.Close()
	}
}

func TestBareosDriver_ArchiveWaveTransportError(t *testing.T) {
	d, _ := newFakeDriver(&bareosBatch{err: fmt.Errorf("director unreachable")}, restoreOK())

	dir := t.TempDir()
	obj := filepath.Join(dir, "bucket", "key.bin")
	_ = os.MkdirAll(filepath.Dir(obj), 0o755)
	_ = os.WriteFile(obj, []byte("payload"), 0o644)

	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: obj, Size: 7}}); err == nil {
		t.Error("expected error when bconsole transport fails")
	}
}

func TestBareosDriver_Restore(t *testing.T) {
	d, f := newFakeDriver(archiveOK("BackupTest", 101), restoreOK())

	dir := t.TempDir()
	obj := filepath.Join(dir, "bucket", "key.bin")
	// the daemon re-creates the live file before restoring.
	if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	loc := bareosLocator(101, obj)

	var buf bytes.Buffer
	if err := d.Restore(context.Background(), loc, &buf, 7); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// The driver must have issued a restore batch with the right jobid and file.
	var sawRestore bool
	for _, cmds := range f.got {
		joined := strings.Join(cmds, " ")
		if joined == "" {
			continue
		}
		if strings.Contains(joined, "jobid=101") && strings.Contains(joined, "file="+obj) {
			sawRestore = true
		}
	}
	if !sawRestore {
		t.Errorf("restore batch did not include jobid=101 and file=%s. batches: %q", obj, f.got)
	}
}

func TestBareosDriver_RestoreRestoreJobFailure(t *testing.T) {
	badRestore := &bareosBatch{result: []byte(
		"Termination:          * Fatal error: No such file.\n" +
			`{"jsonrpc":"2.0","id":null,"result":{}}
`)}
	d, _ := newFakeDriver(archiveOK("BackupTest", 101), badRestore)

	loc := bareosLocator(101, "/some/object.bin")
	var buf bytes.Buffer
	if err := d.Restore(context.Background(), loc, &buf, 7); err == nil {
		t.Error("expected error when restore job fails")
	}
}

func TestBareosDriver_RestoreBadLocator(t *testing.T) {
	d, _ := newFakeDriver(archiveOK("BackupTest", 101), restoreOK())
	var buf bytes.Buffer
	if err := d.Restore(context.Background(), "not-a-bareos-locator", &buf, 1); err == nil {
		t.Error("expected error for non-bareos locator")
	}
	if err := d.Restore(context.Background(), "bareos:", &buf, 1); err == nil {
		t.Error("expected error for empty locator")
	}
}

func TestBareosDriver_PurgeUnknownIsNoop(t *testing.T) {
	d, _ := newFakeDriver(archiveOK("BackupTest", 101), restoreOK())
	if err := d.Purge(context.Background(), "not-a-bareos-locator"); err != nil {
		t.Errorf("expected idempotent no-op for unknown locator, got %v", err)
	}
}

func TestBareosLocatorRoundTrip(t *testing.T) {
	cases := []string{
		"/data/bkt/key.bin",
		"/data/bkt/with space.bin",
		"/data/bkt/a:b.bin",
	}
	for _, p := range cases {
		loc := bareosLocator(7, p)
		jobid, got, ok := parseBareosLocator(loc)
		if !ok || jobid != 7 || got != p {
			t.Errorf("round-trip failed for %q: loc=%q jobid=%d got=%q", p, loc, jobid, got)
		}
	}
}

func TestConsoleQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/data/bucket/key", "/data/bucket/key"},
		{"/data/bucket/with space", `"/data/bucket/with space"`},
		{"/data/bucket/with\"quote", `"/data/bucket/with""quote"`},
		{"", `""`},
	}
	for _, c := range cases {
		if got := consoleQuote(c.in); got != c.want {
			t.Errorf("consoleQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNewBareosDriverRequiresNames(t *testing.T) {
	if _, err := NewBareosDriver(BareosOpts{}); err == nil {
		t.Error("expected error when client/job names are missing")
	}
	if _, err := NewBareosDriver(BareosOpts{Client: "c", BackupJob: "b"}); err == nil {
		t.Error("expected error when restore job is missing")
	}
	if _, err := NewBareosDriver(BareosOpts{Client: "c", BackupJob: "b", RestoreJob: "r"}); err != nil {
		t.Errorf("expected valid driver, got err %v", err)
	}
}
