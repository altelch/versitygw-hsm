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

	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posixhsm/state"
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
	// onRestore, when set, is called with the restore command (the single
	// "restore client=..." line) at the moment a restore batch is observed
	// — lets tests emulate the fd writing the restored file in place.
	onRestore func(restoreCmd string)
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
			if f.onRestore != nil {
				f.onRestore(c)
			}
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

// --- sidecar metadata companion (CompanionMeta) ----------------------------

func newCompanionDriver(t *testing.T, filelist, metaDir string, archive, restore *bareosBatch) (*BareosHsmDriver, *fakeExec) {
	t.Helper()
	if filelist == "" {
		filelist = filepath.Join(t.TempDir(), "hsm-bareos-filelist.txt")
	}
	f := &fakeExec{archive: archive, restore: restore}
	d := newBareosDriverWithExec(BareosOpts{
		Client:        "client1",
		BackupJob:     "BackupTest",
		RestoreJob:    "RestoreTest",
		FileListPath:  filelist,
		Timeout:       5 * time.Second,
		CompanionMeta: true,
		MetaStageDir:  metaDir,
	}, f.run)
	return d, f
}

func TestCompanionNameForDeterministic(t *testing.T) {
	a := companionNameFor("/data/bkt/key.bin")
	b := companionNameFor("/data/bkt/key.bin")
	c := companionNameFor("/data/bkt2/key.bin")
	if a != b {
		t.Fatalf("same path must yield the same companion name: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("different dirs with same leaf must NOT collide: %q", a)
	}
	if !strings.HasSuffix(a, MetaSuffix) {
		t.Fatalf("companion name %q must end with %s", a, MetaSuffix)
	}
}

// A file with a Meta snapshot, when CompanionMeta is on, must be staged to
// a companion file OUTSIDE the rootdir AND appended to the due-list, so the
// same backup job archives it.
func TestBareosDriver_ArchiveWaveCompanionStaging(t *testing.T) {
	root := t.TempDir()
	metaDir := t.TempDir()
	listPath := filepath.Join(metaDir, "hsm-bareos-filelist.txt")

	d, f := newCompanionDriver(t, listPath, metaDir, archiveOK("BackupTest", 101), restoreOK())

	obj := filepath.Join(root, "bkt", "key.bin")
	if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"src":"` + obj + `","attrs":{"tag":"aGk="}}`)

	// The companion mirrors the object's directory under the staging dir
	// (<MetaStageDir>/<dir-of-object>/<leaf>-<hash16>.hsm-meta). Use the
	// driver's own helper so the test can't drift from the implementation.
	wantCompanion := d.companionPathOf(obj)

	// Observe staging state at the moment the job runs (the driver cleans
	// up the staging copy right after a successful backup, so the
	// assertions must be taken inside the hook).
	var seenList, seenCompanion string
	gotCompanion := false
	f.onRunJob = func(_ []string) {
		if b, err := os.ReadFile(listPath); err == nil {
			seenList = string(b)
		}
		if b, err := os.ReadFile(wantCompanion); err == nil {
			seenCompanion = string(b)
			gotCompanion = true
		}
	}

	_, err := d.ArchiveWave(context.Background(), []WaveFile{{Bucket: "bkt", Key: "key.bin", Path: obj, Size: 7, Meta: payload}})
	if err != nil {
		t.Fatalf("ArchiveWave: %v", err)
	}

	if !gotCompanion {
		t.Fatalf("companion was never staged at %s", wantCompanion)
	}
	if seenCompanion != string(payload) {
		t.Fatalf("companion content at run time = %q, want %q", seenCompanion, payload)
	}
	wantList := obj + "\n" + wantCompanion + "\n"
	if seenList != wantList {
		t.Fatalf("due-list at run time = %q, want %q", seenList, wantList)
	}

	// Staging copies are transient job sources: they must be removed on
	// success, not left to pollute the scratch dir.
	if _, err := os.Stat(wantCompanion); !os.IsNotExist(err) {
		t.Fatalf("companion staging copy must be removed after a successful backup, but %s still exists", wantCompanion)
	}
}

// FetchMeta must re-derive the companion from the data locator, restore it,
// and hand back the exact payload that was staged at archive time. Since
// the restore job uses Where = /, the driver must issue a restore for the
// companion path (NOT the data path).
func TestBareosDriver_FetchMetaRoundTrip(t *testing.T) {
	metaDir := t.TempDir()
	d, f := newCompanionDriver(t, "", metaDir, archiveOK("BackupTest", 101), restoreOK())

	obj := "/data/bkt/key.bin"
	loc := bareosLocator(101, obj)
	payload := []byte(`{"src":"` + obj + `","attrs":{"tag":"aGk="}}`)

	// The fake does not run bareos-fd, so emulate the documented
	// Where = / behaviour: when the driver issues a restore for the
	// companion, write the restored bytes to that exact path (in place).
	f.onRestore = func(restoreCmd string) {
		if idx := strings.Index(restoreCmd, "file="); idx >= 0 {
			target := restoreCmd[idx+len("file="):]
			os.MkdirAll(filepath.Dir(target), 0o700)
			os.WriteFile(target, payload, 0o644)
		}
	}

	b, err := d.FetchMeta(context.Background(), loc)
	if err != nil {
		t.Fatalf("FetchMeta: %v", err)
	}
	if string(b) != string(payload) {
		t.Fatalf("FetchMeta = %q, want %q", b, payload)
	}

	// The restore must have targeted the COMPANION (not the data path).
	wantCompanion := companionNameFor(obj)
	issued := false
	for _, cmds := range f.got {
		for _, c := range cmds {
			if strings.HasPrefix(c, "restore client=") && strings.Contains(c, wantCompanion) {
				issued = true
			}
		}
	}
	if !issued {
		t.Errorf("FetchMeta did not issue a restore for the companion %s; batches: %q", wantCompanion, f.got)
	}
}

// A locator for an object archived without a companion (file absent after a
// clean restore report) must yield an EMPTY payload, not an error: the
// daemon then skips the replay.
func TestBareosDriver_FetchMetaNoCompanion(t *testing.T) {
	metaDir := t.TempDir()
	d, _ := newCompanionDriver(t, "", metaDir, archiveOK("BackupTest", 101), restoreOK())

	obj := "/data/bkt/key.bin"
	loc := bareosLocator(101, obj)
	// The fake restore reports success but writes nothing (no companion was
	// ever archived). FetchMeta must return empty, without error.
	b, err := d.FetchMeta(context.Background(), loc)
	if err != nil {
		t.Fatalf("FetchMeta(no companion) must not error, got %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("FetchMeta(no companion) = %q, want empty", b)
	}
}

// The payload returned by FetchMeta must be one that state.RestoreMeta can
// actually replay onto an object (the daemon's exact sequence in
// RestoreJobs), so a sidecar-mode metadata round trip is complete: capture
// -> archive companion -> fetch -> replay.
func TestBareosDriver_CompanionReplayRoundTrip(t *testing.T) {
	metaDir := t.TempDir()
	d, f := newCompanionDriver(t, "", metaDir, archiveOK("BackupTest", 101), restoreOK())

	payload := []byte(`{"src":"/data/bkt/key.bin","attrs":{"tag":"aGk="}}`)
	obj := "/data/bkt/key.bin"
	loc := bareosLocator(101, obj)
	f.onRestore = func(restoreCmd string) {
		if idx := strings.Index(restoreCmd, "file="); idx >= 0 {
			target := restoreCmd[idx+len("file="):]
			os.MkdirAll(filepath.Dir(target), 0o700)
			os.WriteFile(target, payload, 0o644)
		}
	}
	b, err := d.FetchMeta(context.Background(), loc)
	if err != nil {
		t.Fatalf("FetchMeta: %v", err)
	}

	// A capturing storer proving the payload replays exactly one attribute
	// (the HSM state keys are excluded by capture, and "tag" is not one).
	type recorded struct{ addr, obj, attr string; val []byte }
	storer := &bareosReplayStorer{}
	if err := state.RestoreMeta(storer, obj, "", b); err != nil {
		t.Fatalf("RestoreMeta should accept a payload produced by the driver, got %v", err)
	}
	if len(storer.stored) != 1 {
		t.Fatalf("RestoreMeta replayed %d attributes, want 1: %+v", len(storer.stored), storer.stored)
	}
	if got := storer.stored[0]; got.attr != "tag" || string(got.val) != "hi" {
		t.Fatalf("replayed wrong attribute: %+v", got)
	}
}

type bareosReplayStorer struct {
	stored []struct {
		addr, obj, attr string
		val             []byte
	}
}

func (s *bareosReplayStorer) RetrieveAttribute(_ *os.File, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *bareosReplayStorer) StoreAttribute(_ *os.File, addr, obj, attr string, val []byte) error {
	s.stored = append(s.stored, struct {
		addr, obj, attr string
		val             []byte
	}{addr, obj, attr, val})
	return nil
}
func (s *bareosReplayStorer) DeleteAttribute(_, _ string, _ string) error { return nil }
func (s *bareosReplayStorer) DeleteAttributes(_, _ string) error        { return nil }
func (s *bareosReplayStorer) ListAttributes(addr, object string) ([]string, error) {
	return nil, nil
}
func (s *bareosReplayStorer) RenameObject(_ string, _, _ string) error { return nil }

var _ meta.MetadataStorer = (*bareosReplayStorer)(nil)

// CompanionMeta OFF (xattr mode) must be a hard no-op on both sides: no
// companions are staged into the due-list, and FetchMeta returns empty
// without ever talking to bconsole.
func TestBareosDriver_CompanionMetaOffIsNoop(t *testing.T) {
	listPath := filepath.Join(t.TempDir(), "list.txt")
	f := &fakeExec{archive: archiveOK("BackupTest", 101), restore: restoreOK()}
	d := newBareosDriverWithExec(BareosOpts{
		Client: "client1", BackupJob: "BackupTest", RestoreJob: "RestoreTest",
		FileListPath: listPath, Timeout: 5 * time.Second,
		// CompanionMeta left false (default) -- xattr relies on native transport.
	}, f.run)

	root := t.TempDir()
	obj := filepath.Join(root, "bkt", "key.bin")
	if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"src":"` + obj + `","attrs":{"tag":"aGk="}}`)

	var seenList string
	f.onRunJob = func(_ []string) {
		if b, err := os.ReadFile(listPath); err == nil {
			seenList = string(b)
		}
	}
	if _, err := d.ArchiveWave(context.Background(), []WaveFile{{Path: obj, Size: 7, Meta: payload}}); err != nil {
		t.Fatalf("ArchiveWave: %v", err)
	}
	if strings.Contains(seenList, MetaSuffix) {
		t.Fatalf("companion must NOT enter the due-list when CompanionMeta is off; list=%q", seenList)
	}

	loc := bareosLocator(101, obj)
	nBefore := len(f.got)
	b, err := d.FetchMeta(context.Background(), loc)
	if err != nil {
		t.Fatalf("FetchMeta: %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("FetchMeta(off) = %q, want empty", b)
	}
	if len(f.got) != nBefore {
		t.Fatalf("FetchMeta(off) must not issue any bconsole batch; batches=%q", f.got)
	}
}
