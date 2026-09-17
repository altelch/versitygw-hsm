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

	meta := meta.XattrMeta{}
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
		Meta:     meta,
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

	_ = rootdir // rootdir kept for potential future assertions
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
