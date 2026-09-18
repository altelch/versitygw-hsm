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
	"sort"
	"testing"
	"time"
)

// fakeZfs is a scriptable ZfsRunner for tests.
type fakeZfs struct {
	// diffBy[prev] -> []string (paths to return when DiffBetween(...prev...)).
	diffBy map[string][]string
	// diffErrBy[prev] sets an error for DiffBetween(prev, ...).
	diffErrBy map[string]error
	// created / destroyed record calls to inspect assertions.
	created   []string
	destroyed []string
	nextError error // if set, CreateSnapshot returns this error (reset after use)
}

func (f *fakeZfs) CreateSnapshot(ctx context.Context, dataset, snap string) error {
	if f.nextError != nil {
		err := f.nextError
		f.nextError = nil
		return err
	}
	f.created = append(f.created, dataset+"@"+snap)
	return nil
}

func (f *fakeZfs) DestroySnapshot(ctx context.Context, dataset, snap string) error {
	f.destroyed = append(f.destroyed, dataset+"@"+snap)
	return nil
}

func (f *fakeZfs) DiffBetween(ctx context.Context, dataset, prev, cur string) ([]string, error) {
	if err, ok := f.diffErrBy[prev]; ok {
		return nil, err
	}
	return f.diffBy[prev], nil
}

// helpers

func seedObject(t *testing.T, root, bucket, key string, payload string) string {
	t.Helper()
	p := filepath.Join(root, bucket, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func listPaths(cands []Candidate) []string {
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.Key)
	}
	sort.Strings(out)
	return out
}

func TestZfsLister_DisabledWhenNoDataset(t *testing.T) {
	root := t.TempDir()
	seedObject(t, root, "b", "a.txt", "hello")
	l := NewZfsLister(root, "", t.TempDir(), nil)
	if err := l.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	cands, err := l.ListCandidates(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got := listPaths(cands); len(got) != 1 || got[0] != "a.txt" {
		t.Fatalf("want full-walk result, got %v", got)
	}
}

func TestZfsLister_FirstPassBaselineFullWalk(t *testing.T) {
	root := t.TempDir()
	seedObject(t, root, "b", "a.txt", "hello")
	seedObject(t, root, "b", "sub/dir/c.txt", "hello2")
	stateDir := t.TempDir()
	r := &fakeZfs{}
	l := NewZfsLister(root, "tank/data", stateDir, r)
	if err := l.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	// both snapshots created, in order.
	if len(r.created) != 2 || r.created[0] != "tank/data@vgwtape-a" || r.created[1] != "tank/data@vgwtape-b" {
		t.Fatalf("baseline created = %v", r.created)
	}
	// slot file should be 'a' (last = a after rebaseline).
	data, err := os.ReadFile(filepath.Join(stateDir, "zfs-snap-slot"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "vgwtape-a\n" {
		t.Fatalf("slot=%q", string(data))
	}
	// first-pass should be a full walk regardless of the fake diff.
	cands, err := l.ListCandidates(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got := listPaths(cands); len(got) != 2 {
		t.Fatalf("want 2 objects, got %v", got)
	}
}

func TestZfsLister_SecondPassUsesDiff(t *testing.T) {
	root := t.TempDir()
	stateDir := t.TempDir()

	// simulate first pass having established a baseline with two objects
	seedObject(t, root, "b", "old.txt", "data")
	seedObject(t, root, "b", "changed.txt", "data")
	seedObject(t, root, "other", "keep.txt", "data")

	r := &fakeZfs{
		diffBy: map[string][]string{
			// previous slot was 'a' after rebaseline; next slot is 'b'.
			"vgwtape-a": {"b/changed.txt", "b/new.txt", "other/discard.txt"},
		},
	}
	l := NewZfsLister(root, "tank/data", stateDir, r)
	// write the slot file as if pass 1 ended with slot 'a'
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "zfs-snap-slot"), []byte("vgwtape-a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	// b/new.txt does not exist on disk -> mapChangedPath drops it.
	cands, err := l.ListCandidates(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got := listPaths(cands); len(got) != 1 || got[0] != "changed.txt" {
		t.Fatalf("want [changed.txt], got %v", got)
	}
	// ping-pong advanced: destroy 'a', slot file now 'b'
	lastDestroyed := r.destroyed[len(r.destroyed)-1]
	if lastDestroyed != "tank/data@vgwtape-a" {
		t.Fatalf("last destroy = %q, want tank/data@vgwtape-a", lastDestroyed)
	}
	data, _ := os.ReadFile(filepath.Join(stateDir, "zfs-snap-slot"))
	if string(data) != "vgwtape-b\n" {
		t.Fatalf("slot = %q, want vgwtape-b\n", string(data))
	}
}

func TestZfsLister_DiffErrorsFallBackToFullWalk(t *testing.T) {
	root := t.TempDir()
	stateDir := t.TempDir()
	seedObject(t, root, "b", "a.txt", "x")
	seedObject(t, root, "b", "b.txt", "y")

	r := &fakeZfs{
		diffErrBy: map[string]error{"vgwtape-b": os.ErrNotExist},
	}
	l := NewZfsLister(root, "tank/data", stateDir, r)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// seed slot to say last = b (cur will be a)
	if err := os.WriteFile(filepath.Join(stateDir, "zfs-snap-slot"), []byte("vgwtape-b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	cands, err := l.ListCandidates(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got := listPaths(cands); len(got) != 2 {
		t.Fatalf("want full walk [a.txt b.txt], got %v", got)
	}
}

func TestZfsLister_AgingIndexRemembered(t *testing.T) {
	root := t.TempDir()
	stateDir := t.TempDir()
	// no diff changes; only an aging-index record.
	r := &fakeZfs{
		diffBy: map[string][]string{"vgwtape-b": {}},
	}
	l := NewZfsLister(root, "tank/data", stateDir, r)
	if err := os.WriteFile(filepath.Join(stateDir, "zfs-snap-slot"), []byte("vgwtape-b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	age := time.Now().Add(-48 * time.Hour)
	l.RememberConsidered("b", filepath.Join(root, "b", "aged.txt"), age, 100)

	// now create the object on disk so that stat succeeds
	if err := os.MkdirAll(filepath.Join(root, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b", "aged.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(filepath.Join(root, "b", "aged.txt"), age, age)

	// Begin: fake diff returns 0 changed paths.  Aging index should produce
	// the one remembered path.
	if err := l.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	cands, err := l.ListCandidates(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got := listPaths(cands); len(got) != 1 || got[0] != "aged.txt" {
		t.Fatalf("want [aged.txt], got %v", got)
	}

	// forget removes it from the index
	l.Forget("b", filepath.Join(root, "b", "aged.txt"))

	// new Begin -> diff empty; aging index should be empty too.
	r2 := &fakeZfs{diffBy: map[string][]string{"vgwtape-a": {}}}
	l2 := NewZfsLister(root, "tank/data", stateDir, r2)
	if err := l2.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	cands2, err := l2.ListCandidates(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got := listPaths(cands2); len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}

func TestZfsLister_MissingAgingEntryDropped(t *testing.T) {
	root := t.TempDir()
	stateDir := t.TempDir()
	r := &fakeZfs{diffBy: map[string][]string{"vgwtape-b": {}}}
	l := NewZfsLister(root, "tank/data", stateDir, r)

	// record a candidate for a path that does NOT exist on disk; load should
	// drop it.
	gonePath := filepath.Join(root, "b", "gone.txt")
	l.RememberConsidered("b", gonePath, time.Now(), 1)

	if err := l.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	cands, err := l.ListCandidates(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got := listPaths(cands); len(got) != 0 {
		t.Fatalf("want 0, got %v", got)
	}
}

func TestZfsLister_SkipsNonBucketsAndDirs(t *testing.T) {
	root := t.TempDir()
	seedObject(t, root, "b", "ok.txt", "x")
	seedObject(t, root, "c", "other.txt", "y")
	// a bucket-less file at the root (should be ignored)
	if err := os.WriteFile(filepath.Join(root, "orphan.txt"), []byte("z"), 0o644); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	r := &fakeZfs{diffBy: map[string][]string{"vgwtape-b": {"b/ok.txt", "c/other.txt", "orphan.txt"}}}
	l := NewZfsLister(root, "tank/data", stateDir, r)
	if err := os.WriteFile(filepath.Join(stateDir, "zfs-snap-slot"), []byte("vgwtape-b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	// bucket 'b' should return only its own paths
	cb, err := l.ListCandidates(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got := listPaths(cb); len(got) != 1 || got[0] != "ok.txt" {
		t.Fatalf("want [ok.txt], got %v", got)
	}
	cc, err := l.ListCandidates(context.Background(), "c")
	if err != nil {
		t.Fatal(err)
	}
	if got := listPaths(cc); len(got) != 1 || got[0] != "other.txt" {
		t.Fatalf("want [other.txt], got %v", got)
	}
}

func TestAgingIndex_Persistence(t *testing.T) {
	dir := t.TempDir()
	objDir := filepath.Join(t.TempDir(), "b")
	if err := os.MkdirAll(objDir, 0o755); err != nil {
		t.Fatal(err)
	}
	objPath := filepath.Join(objDir, "a.txt")
	if err := os.WriteFile(objPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	ai := newAgingIndex(dir)
	ai.record("b", objPath, time.Now(), 5)

	// fresh index on the same dir should reload the recorded entry (paths
	// are validated via os.Stat; objPath exists)
	if got := newAgingIndex(dir).pathsFor("b"); len(got) != 1 || got[0] != objPath {
		t.Fatalf("after record, want [%q], got %v", objPath, got)
	}
	ai.remove("b", objPath)
	if got := newAgingIndex(dir).pathsFor("b"); len(got) != 0 {
		t.Fatalf("after remove, want empty, got %v", got)
	}
}
