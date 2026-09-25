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

package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posixhsm"
	"github.com/versity/versitygw/backend/posixhsm/policy"
	"github.com/versity/versitygw/backend/posixhsm/queue"
	"github.com/versity/versitygw/backend/posixhsm/state"
)

// setup builds a tempdir with a bucket + object and wires up a Daemon over
// the mock driver against that tree.
func setup(t *testing.T, now time.Time) (*Daemon, string, string) {
	t.Helper()
	base := t.TempDir()
	return setupWithStore(t, now, base, nil)
}

// setupSidecar wires the same tree and daemon, but HSM state lives in
// sidecar metadata files (the split representation). The storer is built
// exactly like cmd/vgwtaped does it: meta.NewSideCar wrapped in
// PathRelStorer, because the daemon addresses state by absolute path while
// the gateway (and SideCar itself) use root-relative names. Returns the
// sidecar dir alongside the daemon.
func setupSidecar(t *testing.T, now time.Time) (*Daemon, string, string, string) {
	t.Helper()
	base := t.TempDir()
	sidecar := filepath.Join(base, "sidecar")
	if err := os.MkdirAll(sidecar, 0o755); err != nil {
		t.Fatal(err)
	}
	inner, err := meta.NewSideCar(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	ms := state.NewPathRelStorer(inner, filepath.Join(base, "root"))
	d, rootdir, obj := setupWithStore(t, now, base, ms)
	return d, rootdir, obj, sidecar
}

// setupWithStore builds the tree under base; a nil storer means xattrs on
// the object files (the default posix representation).
func setupWithStore(t *testing.T, now time.Time, base string, ms meta.MetadataStorer) (*Daemon, string, string) {
	t.Helper()
	rootdir := filepath.Join(base, "root")
	statedir := filepath.Join(base, "state")
	const bucket = "bkt"
	key := "object.bin"
	obj := filepath.Join(rootdir, bucket, key)
	if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("daemon-e2e-body")
	if err := os.WriteFile(obj, body, 0o644); err != nil {
		t.Fatal(err)
	}
	// set an old mtime so the policy's min-age is satisfied
	old := now.Add(-2 * time.Hour)
	_ = os.Chtimes(obj, old, old)

	if ms == nil {
		ms = meta.XattrMeta{}
	}
	q, err := queue.New(statedir)
	if err != nil {
		t.Fatal(err)
	}
	drv, err := posixhsm.NewMockDriver(statedir)
	if err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{
		Default: policy.Rule{MinAge: 1 * time.Hour},
	}
	list := newFsLister(rootdir)
	d := New(Config{
		Driver:   drv,
		Queue:    q,
		Meta:     ms,
		Policy:   pol,
		Lister:   list,
		WaveSize: 10,
	})
	d.now = func() time.Time { return now }
	return d, rootdir, obj
}

func TestDaemonGlacierWorkflow(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	d, rootdir, obj := setup(t, now)
	runGlacierWorkflow(t, d, now, obj)
	_ = rootdir // rootdir kept for potential future assertions
}

// TestDaemonGlacierWorkflowSidecar runs the identical workflow with the
// split-file (sidecar) metadata representation; on top of the flow checks
// it asserts where the metadata actually lands on disk.
func TestDaemonGlacierWorkflowSidecar(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	d, rootdir, obj, sidecar := setupSidecar(t, now)
	runGlacierWorkflow(t, d, now, obj)

	// metadata lives under the sidecar dir, never as an xattr or as a
	// doubled-up absolute path on the object file.
	marker := filepath.Join(sidecar, "bkt", "object.bin", "meta", "hsm-loc")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected sidecar locator at %s: %v", marker, err)
	}
	if got := filepath.Base(filepath.Dir(filepath.Dir(marker))); got != "object.bin" {
		t.Fatalf("unexpected sidecar layout: %s", marker)
	}
	if doubled := filepath.Join(sidecar, rootdir, "bkt"); dirExists(doubled) {
		t.Fatalf("sidecar path doubled rootdir: %s exists", doubled)
	}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// runGlacierWorkflow drives Tier → RestoreJobs → Sweep over one eligible
// object, independent of the metadata representation.
func runGlacierWorkflow(t *testing.T, d *Daemon, now time.Time, obj string) {
	t.Helper()
	ctx := context.Background()

	// ---- 1) tier the object ----
	tiered, err := d.Tier(ctx)
	if err != nil {
		t.Fatalf("tier: %v", err)
	}
	if tiered != 1 {
		t.Fatalf("expected 1 tiered, got %d", tiered)
	}
	fi, err := os.Stat(obj)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Fatalf("expected truncated object, size=%d", fi.Size())
	}
	st := state.Store(d.meta, obj)
	if !st.Offline {
		t.Fatal("expected offline=true after tier")
	}
	if st.Locator == "" {
		t.Fatal("expected a locator after tier")
	}
	if st.Size != 15 {
		t.Fatalf("expected recorded size 15, got %d", st.Size)
	}

	// ---- 2) enqueuing a duplicate tier does NOT double-tier ----
	if tiered2, _ := d.Tier(ctx); tiered2 != 0 {
		t.Fatalf("expected 0 second-pass tiering, got %d", tiered2)
	}

	// ---- 3) restore the object (simulate a gateway restore request) ----
	_, _ = d.q.Enqueue(queue.Job{Op: queue.JobOpRestore, Bucket: "bkt", Key: "object.bin", Days: 3})
	restoreCount, err := d.RestoreJobs(ctx, 10)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restoreCount != 1 {
		t.Fatalf("expected 1 restored, got %d", restoreCount)
	}
	fi, _ = os.Stat(obj)
	if fi.Size() != 15 {
		t.Fatalf("expected restored size 15, got %d", fi.Size())
	}
	st = state.Store(d.meta, obj)
	if st.Offline {
		t.Fatal("expected offline cleared after restore")
	}
	if st.Expiry == "" {
		t.Fatal("expected expiry set after restore")
	}
	// verify the data survived the round trip
	body, err := os.ReadFile(obj)
	if err != nil || string(body) != "daemon-e2e-body" {
		t.Fatalf("round-trip body mismatch: %q err=%v", body, err)
	}

	// ---- 4) expiry not yet reached: Sweep should not re-tier ----
	reTiered, _ := d.Sweep(ctx)
	if reTiered != 0 {
		t.Fatalf("expected 0 re-tier (expiry not yet reached), got %d", reTiered)
	}

	// ---- 5) expire it and Sweep (sweep physically re-tiers on expiry) ----
	_ = state.Set(d.meta, obj, state.Expiry, now.Add(-1*time.Minute).UTC().Format(time.RFC3339))
	reTiered, err = d.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if reTiered != 1 {
		t.Fatalf("expected 1 re-tiered via sweep, got %d", reTiered)
	}
	st = state.Store(d.meta, obj)
	if !st.Offline {
		t.Fatal("expected offline again after re-tier")
	}
	if fi, _ := os.Stat(obj); fi.Size() != 0 {
		t.Fatalf("expected truncated again after re-tier, size=%d", fi.Size())
	}
}

func TestDaemonPolicyRespectsMinAge(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	d, _, obj := setup(t, now)

	// freshen the mtime — should no longer be tier-eligible
	_ = os.Chtimes(obj, now.Add(-30*time.Minute), now.Add(-30*time.Minute))
	tiered, _ := d.Tier(context.Background())
	if tiered != 0 {
		t.Fatalf("expected 0 (mtime < min-age), got %d", tiered)
	}
}

// countDriver records how many ArchiveWave calls arrive and how many files
// each carried. singleWaveDriver adds the SingleWave marker, as the Bareos
// driver does: the daemon must then deliver the whole due set in ONE call.
type countDriver struct {
	calls [][]posixhsm.WaveFile
}

func (c *countDriver) Name() string { return "counting" }

func (c *countDriver) ArchiveWave(_ context.Context, files []posixhsm.WaveFile) ([]string, error) {
	c.calls = append(c.calls, files)
	locs := make([]string, len(files))
	for i, f := range files {
		locs[i] = fmt.Sprintf("count:%d:%s", i, f.Path)
	}
	return locs, nil
}

func (c *countDriver) Restore(_ context.Context, _ string, _ io.Writer, _ int64) error {
	return nil
}
func (c *countDriver) Purge(_ context.Context, _ string) error { return nil }
func (c *countDriver) Close() error                            { return nil }

type singleWaveDriver struct{ countDriver }

func (*singleWaveDriver) SingleWave() bool { return true }

// countSetup wires a Daemon over a tree with `n` old, tier-eligible objects.
func countSetup(t *testing.T, now time.Time, drv posixhsm.HsmDriver, waveSize, n int) *Daemon {
	t.Helper()
	base := t.TempDir()
	rootdir := filepath.Join(base, "root")
	statedir := filepath.Join(base, "state")
	const bucket = "bkt"
	for i := 0; i < n; i++ {
		obj := filepath.Join(rootdir, bucket, fmt.Sprintf("obj-%02d", i))
		if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(obj, []byte("body"), 0o644); err != nil {
			t.Fatal(err)
		}
		old := now.Add(-2 * time.Hour)
		_ = os.Chtimes(obj, old, old)
	}
	q, err := queue.New(statedir)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{
		Driver:   drv,
		Queue:    q,
		Meta:     meta.XattrMeta{},
		Policy:   &policy.Policy{Default: policy.Rule{MinAge: 1 * time.Hour}},
		Lister:   newFsLister(rootdir),
		WaveSize: waveSize,
	})
	d.now = func() time.Time { return now }
	return d
}

func TestDaemonSingleWaveDriver(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	// Without the marker: 9 due files, wave size 4 -> waves of 4+4+1.
	var plain countDriver
	d := countSetup(t, now, &plain, 4, 9)
	if tiered, err := d.Tier(ctx); err != nil || tiered != 9 {
		t.Fatalf("plain tier: tiered=%d err=%v", tiered, err)
	}
	if len(plain.calls) != 3 {
		t.Fatalf("expected 3 waves for a wave-immune driver, got %d", len(plain.calls))
	}

	// With the marker: WaveSize 4 must be ignored -> exactly one call.
	var sw singleWaveDriver
	d2 := countSetup(t, now, &sw, 4, 9)
	if tiered, err := d2.Tier(ctx); err != nil || tiered != 9 {
		t.Fatalf("single-wave tier: tiered=%d err=%v", tiered, err)
	}
	if len(sw.calls) != 1 {
		t.Fatalf("expected 1 ArchiveWave call for a single-wave driver, got %d", len(sw.calls))
	}
	if len(sw.calls[0]) != 9 {
		t.Fatalf("expected the whole due set in one wave, got %d files", len(sw.calls[0]))
	}
	// and every object really went offline
	for i := 0; i < 9; i++ {
		p := filepath.Join(d2.lister.(*fsLister).rootdir, "bkt", fmt.Sprintf("obj-%02d", i))
		if fi, err := os.Stat(p); err != nil || fi.Size() != 0 {
			t.Fatalf("obj-%02d not truncated: %v", i, err)
		}
		if !state.Store(d2.meta, p).Offline {
			t.Fatalf("obj-%02d not offline", i)
		}
	}
}

func TestDaemonSingleWaveSweep(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	var sw singleWaveDriver
	d := countSetup(t, now, &sw, 4, 9)
	// tier once (call 1), then mark everything expired and sweep.
	if _, err := d.Tier(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		p := filepath.Join(d.lister.(*fsLister).rootdir, "bkt", fmt.Sprintf("obj-%02d", i))
		st := state.Store(d.meta, p)
		if !st.Offline {
			t.Fatalf("obj-%02d should be offline pre-sweep", i)
		}
		if err := state.Set(d.meta, p, state.Offline, ""); err != nil {
			t.Fatal(err)
		}
		if err := state.Set(d.meta, p, state.Expiry, now.Add(-time.Minute).UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	// sweep must re-tier all 9 expired objects in one call.
	reTiered, err := d.Sweep(ctx)
	if err != nil || reTiered != 9 {
		t.Fatalf("sweep: reTiered=%d err=%v", reTiered, err)
	}
	calls := sw.calls
	if len(calls) != 2 || len(calls[1]) != 9 {
		t.Fatalf("expected a single 9-file sweep wave, got calls=%v", waveCount(calls))
	}
}

func waveCount(calls [][]posixhsm.WaveFile) []int {
	out := make([]int, len(calls))
	for i, c := range calls {
		out[i] = len(c)
	}
	return out
}

// TestDaemonGlacierWorkflowMetaCompanion proves the metadata-survival
// property over the whole tier → loss-on-source → restore cycle: the
// object's S3 metadata is captured into a companion by the (mock) driver,
// the source xattrs are then LOST (e.g. by a sidecar volume loss or by a
// tier pass on a different host), and the restore must replay the
// metadata from the archived companion.
func TestDaemonGlacierWorkflowMetaCompanion(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	d, _, obj := setup(t, now)
	ctx := context.Background()
	ms := meta.XattrMeta{}

	// S3-visible metadata on the live object (plus the daemon's own HSM
	// state keys, which must NOT be captured).
	if err := ms.StoreAttribute(nil, obj, "", "x-user-critical", []byte("keep-me")); err != nil {
		t.Fatal(err)
	}
	if err := ms.StoreAttribute(nil, obj, "", "x-user-two", []byte("two")); err != nil {
		t.Fatal(err)
	}

	// ---- tier: the daemon must snapshot the metadata into a companion ----
	if tiered, err := d.Tier(ctx); err != nil || tiered != 1 {
		t.Fatalf("tier: tiered=%d err=%v", tiered, err)
	}
	st := state.Store(d.meta, obj)
	if !st.Offline || st.Locator == "" {
		t.Fatalf("expected offline state after tier, got %+v", st)
	}

	// ---- simulate metadata loss on the source (the whole point) ----
	for _, a := range []string{"x-user-critical", "x-user-two"} {
		if err := ms.DeleteAttribute(obj, "", a); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := ms.RetrieveAttribute(nil, obj, "", "x-user-critical"); err == nil {
		t.Fatalf("xattr should be gone, got %q", v)
	}

	// ---- restore ----
	_, _ = d.q.Enqueue(queue.Job{Op: queue.JobOpRestore, Bucket: "bkt", Key: "object.bin", Days: 3})
	if n, err := d.RestoreJobs(ctx, 10); err != nil || n != 1 {
		t.Fatalf("restore: n=%d err=%v", n, err)
	}
	// data must be back
	if b, err := os.ReadFile(obj); err != nil || string(b) != "daemon-e2e-body" {
		t.Fatalf("data round-trip: %q err=%v", b, err)
	}
	// AND the captured S3 metadata must have been replayed from the
	// companion, even though the source copy is gone.
	v, err := ms.RetrieveAttribute(nil, obj, "", "x-user-critical")
	if err != nil || string(v) != "keep-me" {
		t.Fatalf("x-user-critical = %q (%v), want keep-me (replayed from companion)", v, err)
	}
	v, err = ms.RetrieveAttribute(nil, obj, "", "x-user-two")
	if err != nil || string(v) != "two" {
		t.Fatalf("x-user-two = %q (%v), want two", v, err)
	}
	// HSM state must be offline-cleared, not replayed.
	if s := state.Store(d.meta, obj); s.Offline {
		t.Fatal("HSM offline state must not be replayed by the companion")
	}
}
