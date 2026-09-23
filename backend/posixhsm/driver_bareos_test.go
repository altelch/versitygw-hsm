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
	// onRunJob, when set, is called with the recorded commands at the
	// moment a run-job batch is observed — lets tests inspect driver state
	// (e.g. the due-file list) at exactly the point bconsole would run.
	onRunJob func(cmds []string)
}

func (f *fakeExec) run(ctx context.Context, path, config, director string, cmds []string) ([]byte, error) {
	f.got = append(f.got, append([]string{}, cmds...))
	if len(cmds) == 0 {
		return nil, nil
	}
	for _, c := range cmds {
		switch {
		case strings.HasPrefix(c, "run job="):
			if f.onRunJob != nil {
				f.onRunJob(cmds)
			}
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

// newFakeDriver builds a driver over the fake exec. An empty filelist
// defaults to a path inside the test's temp dir; ArchiveWave requires a
// configured FileListPath.
func newFakeDriver(t *testing.T, filelist string, archive, restore *bareosBatch) (*BareosHsmDriver, *fakeExec) {
	t.Helper()
	if filelist == "" {
		filelist = filepath.Join(t.TempDir(), "hsm-bareos-filelist.txt")
	}
	f := &fakeExec{archive: archive, restore: restore}
	d := newBareosDriverWithExec(BareosOpts{
		Client:       "client1",
		BackupJob:    "BackupTest",
		RestoreJob:   "RestoreTest",
		FileListPath: filelist,
		Timeout:      5 * time.Second,
	}, f.run)
	return d, f
}

// archiveOK mirrors a documented successful backup job run (jobid 101) plus the
// `list jobs` JSON-RPC 2.0 response for job name "BackupTest". The buffer is
// shaped like real bconsole output under `.api 2`: the job report text plus a
// JSON object from the `run` command (jobid at result.jobid), one from
// `wait`, and finally the `list jobs` object (jobid at result.jobs[].jobid),
// interleaved with plain text. This is the exact buffer the old
// json.Unmarshal(first{...}) path mangled past the first object.
func archiveOK(jobname string, jobid int) *bareosBatch {
	run := fmt.Sprintf(`{"jsonrpc":"2.0","id":null,"result":{
"jobid": "%d", "name": "%s"}}
`, jobid, jobname)
	wait := `{"jsonrpc":"2.0","id":null,"result":{
"jobstatus": "T"}}
`
	listjobs := fmt.Sprintf(`{"jsonrpc":"2.0","id":null,"result":{
"jobs": [{"jobid": "1", "name": "OtherJob", "jobstatus": "T"},
{"jobid": "%d", "name": "%s", "type": "B", "level": "F", "jobstatus": "T"}]}}
`, jobid, jobname)
	return &bareosBatch{result: []byte(
		"Start Backup Job: " + jobname + "\n" +
			run +
			"Job is running\n" +
			wait +
			"Termination:          * Backup completed without errors.\n" +
			listjobs)}
}

// restoreOK mirrors a documented successful restore job run.
func restoreOK() *bareosBatch {
	return &bareosBatch{result: []byte(
		"Start Restore Job: RestoreTest\n" +
			"Termination:          * Restore completed without errors.\n" +
			`{"jsonrpc":"2.0","id":null,"result":{
"jobid": "999", "jobstatus": "T"}}
`)}
}

// TestLookupJobID covers the documented response shapes. The key regression:
// under `.api 2` the bconsole buffer holds SEVERAL JSON objects interleaved
// with plain text (one per command: run, wait, list jobs). The old code ran
// json.Unmarshal from the first '{' to the end, which chokes on the trailing
// objects/text, and fell through to a text scan that finds no JobId -> 0.
func TestLookupJobID(t *testing.T) {
	jsonList := `{"jsonrpc":"2.0","id":null,"result":{
"jobs": [
  {"jobid":"7","name":"Other","jobstatus":"T"},
  {"jobid":"142","name":"HsmTierBackup","type":"B","level":"F","jobstatus":"T"}
]}}
`
	jsonOnlyOther := `{"jsonrpc":"2.0","id":null,"result":{
"jobs": [{"jobid":"200","name":"Other","jobstatus":"T"}]}}
`
	jsonRun := `{"jsonrpc":"2.0","id":null,"result":{
"jobid":"142","name":"HsmTierBackup"}}
`
	waitObj := `{"jsonrpc":"2.0","id":null,"result":{
"jobstatus":"T"}}
`
	report := "Start Backup Job: HsmTierBackup\nRunning job: HsmTierBackup.2026-09-23_15.18.01_00 (JobId=142)\nTermination:          * Backup completed without errors.\n"

	cases := map[string]struct {
		buf  string
		want int
	}{
		"single list jobs json object": {buf: report + jsonList + "\n", want: 142},
		"multiple interleaved objects": {buf: report + jsonRun + waitObj + jsonList, want: 142},
		"json embedded in text noise":  {buf: "Connecting to Director x\n" + jsonRun + "\ngarbage\n" + jsonList, want: 142},
		"no jobs for other name":       {buf: jsonOnlyOther, want: 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := lookupJobID([]byte(c.buf), "HsmTierBackup"); got != c.want {
				t.Fatalf("lookupJobID = %d, want %d", got, c.want)
			}
		})
	}

	// Text-only fallback (`.api 0/1`): the `run` report's (JobId=N) line and
	// the `list jobs` table row.
	t.Run("text jobid paren", func(t *testing.T) {
		buf := "Running job: HsmTierBackup.2026-09-23_15.18.01_00 (JobId=142)\n" +
			"Termination:          * Backup completed without errors.\n"
		if got := lookupJobID([]byte(buf), "HsmTierBackup"); got != 142 {
			t.Fatalf("lookupJobID = %d, want 142", got)
		}
	})
	t.Run("text list jobs table", func(t *testing.T) {
		buf := "+------+------------+-------+\n| JobId | Name         | Type  |\n+------+------------+-------+\n" +
			"|    7 | Other      | B     |\n" +
			"|  142 | HsmTierBackup | B     |\n+------+------------+-------+\n"
		if got := lookupJobID([]byte(buf), "HsmTierBackup"); got != 142 {
			t.Fatalf("lookupJobID = %d, want 142", got)
		}
	})
}

func TestBareosDriver_ArchiveWave(t *testing.T) {
	d, _ := newFakeDriver(t, "", archiveOK("BackupTest", 101), restoreOK())

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
	d, _ := newFakeDriver(t, "", failure, restoreOK())

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
	d, _ := newFakeDriver(t, "", &bareosBatch{err: fmt.Errorf("director unreachable")}, restoreOK())

	dir := t.TempDir()
	obj := filepath.Join(dir, "bucket", "key.bin")
	_ = os.MkdirAll(filepath.Dir(obj), 0o755)
	_ = os.WriteFile(obj, []byte("payload"), 0o644)

	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: obj, Size: 7}}); err == nil {
		t.Error("expected error when bconsole transport fails")
	}
}

func TestBareosDriver_Restore(t *testing.T) {
	d, f := newFakeDriver(t, "", archiveOK("BackupTest", 101), restoreOK())

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
	d, _ := newFakeDriver(t, "", archiveOK("BackupTest", 101), badRestore)

	loc := bareosLocator(101, "/some/object.bin")
	var buf bytes.Buffer
	if err := d.Restore(context.Background(), loc, &buf, 7); err == nil {
		t.Error("expected error when restore job fails")
	}
}

func TestBareosDriver_RestoreBadLocator(t *testing.T) {
	d, _ := newFakeDriver(t, "", archiveOK("BackupTest", 101), restoreOK())
	var buf bytes.Buffer
	if err := d.Restore(context.Background(), "not-a-bareos-locator", &buf, 1); err == nil {
		t.Error("expected error for non-bareos locator")
	}
	if err := d.Restore(context.Background(), "bareos:", &buf, 1); err == nil {
		t.Error("expected error for empty locator")
	}
}

func TestBareosDriver_PurgeUnknownIsNoop(t *testing.T) {
	d, _ := newFakeDriver(t, "", archiveOK("BackupTest", 101), restoreOK())
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
	if _, err := NewBareosDriver(BareosOpts{Client: "c", BackupJob: "b", RestoreJob: "r"}); err == nil {
		t.Error("expected error when file list path is missing")
	}
	if _, err := NewBareosDriver(BareosOpts{
		Client: "c", BackupJob: "b", RestoreJob: "r", FileListPath: "/tmp/list.txt",
	}); err != nil {
		t.Errorf("expected valid driver, got err %v", err)
	}
}

// The job's FileSet reads the list the driver wrote; if the file did not
// contain exactly the due set (or did not exist by the time `run job=` is
// issued), the archive would be wrong. Assert the file state AT the run
// command, and that each wave/pass fully replaces the previous list.
func TestBareosDriver_ArchiveWaveWritesFileList(t *testing.T) {
	listPath := filepath.Join(t.TempDir(), "hsm-bareos-filelist.txt")
	d, f := newFakeDriver(t, listPath, archiveOK("BackupTest", 101), restoreOK())

	dir := t.TempDir()
	obj1 := filepath.Join(dir, "bkt", "a.bin")
	obj2 := filepath.Join(dir, "bkt", "with space.bin")
	for _, o := range []string{obj1, obj2} {
		if err := os.MkdirAll(filepath.Dir(o), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(o, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var seen string
	f.onRunJob = func(_ []string) {
		got, err := os.ReadFile(listPath)
		if err != nil {
			seen = "MISSING: " + err.Error()
			return
		}
		seen = string(got)
	}

	if _, err := d.ArchiveWave(context.Background(), []WaveFile{
		{Path: obj1, Size: 4}, {Path: obj2, Size: 4},
	}); err != nil {
		t.Fatalf("ArchiveWave: %v", err)
	}
	if want := obj1 + "\n" + obj2 + "\n"; seen != want {
		t.Fatalf("file list at run time = %q, want %q", seen, want)
	}

	// A later pass must fully replace the list (no stale entries).
	obj3 := filepath.Join(dir, "bkt", "c.bin")
	if err := os.WriteFile(obj3, []byte("d"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: obj3, Size: 1}}); err != nil {
		t.Fatalf("ArchiveWave pass 2: %v", err)
	}
	if want := obj3 + "\n"; seen != want {
		t.Fatalf("file list after second pass = %q, want %q", seen, want)
	}

	// Only one temp file may linger, no matter how many passes ran.
	ents, err := os.ReadDir(filepath.Dir(listPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != filepath.Base(listPath) {
		names := []string{}
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("temp file left in list dir: %v", names)
	}
}

// A missing file in the due set must fail the wave before the job runs (and
// before any list rewrite), so a vanished object is never archived as a
// stale path entry.
func TestBareosDriver_ArchiveWaveMissingFileFailsBeforeRun(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "list.txt")
	d, f := newFakeDriver(t, listPath, archiveOK("BackupTest", 101), restoreOK())

	gone := filepath.Join(dir, "bkt", "gone.bin")
	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: gone, Size: 9}}); err == nil {
		t.Fatal("expected error for missing file")
	}
	if len(f.got) != 0 {
		t.Fatalf("no bconsole batch may run when a due file is missing, got %q", f.got)
	}
	if _, err := os.Stat(listPath); !os.IsNotExist(err) {
		t.Fatal("list file must not be written when validation fails")
	}
}

// Without a FileListPath the driver must refuse to run (the internal seam
// could otherwise trigger a job fed by whatever the FileSet points at).
func TestBareosDriver_ArchiveWaveRefusesWithoutFileList(t *testing.T) {
	f := &fakeExec{archive: archiveOK("BackupTest", 101)}
	d := newBareosDriverWithExec(BareosOpts{
		Client: "c", BackupJob: "BackupTest", RestoreJob: "r",
	}, f.run)

	dir := t.TempDir()
	obj := filepath.Join(dir, "bkt", "k.bin")
	if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: obj, Size: 1}}); err == nil {
		t.Fatal("expected refusal when FileListPath is empty")
	}
	if len(f.got) != 0 {
		t.Fatalf("no job may run without a file list path, got %q", f.got)
	}
}
