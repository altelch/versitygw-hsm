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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// zfsLister is a Lister that, when backed by a ZFS dataset, enumerates
// changed objects per pass via `zfs diff` between two ping-pong
// snapshots, with a full-walk fallback.  It also maintains an
// "aging-index" of objects that were evaluated but not-tiered on the
// prior pass, so objects that cross min-age policy purely by aging
// (mtime is unchanged) are still presented to the policy evaluator.
//
// The ping-pong
//
// We maintain two snapshots of the dataset, `@vgwtape-a` and
// `@vgwtape-b`, alternating every pass.  A small file in the state
// dir (`<state-dir>/zfs-snap-slot`) records which slot is the "last"
// (we diff from it); the other is "cur" (we create this pass, then
// advance).  First pass: create both, full-walk (baseline, and seed
// the aging index); each subsequent pass: `zfs diff last→cur` gives
// the added + modified paths in the interval.
//
// Fallbacks (no correctness loss; just more I/O)
//
//   - `runner == nil` or `dataset == "":` behaves exactly like the
//     plain fsLister (zfsEnabled=false).
//   - Begin fails: zfsEnabled remains (or becomes) false for the
//     current pass; ListCandidates falls back to a full walk.
//   - `last` snapshot missing on Begin (crash / manual destroy):
//     re-baseline (best effort), full-walk this pass.
//
// Aging-index
//
// Per-bucket on-disk set of "evaluated but still online" candidate
// paths.  Closed gap: objects that cross min-age without changing
// content are NOT in a zfs-diff, so without this index we would stop
// re-evaluating them.  When the daemon skips a candidate (offline,
// restoring-in-flight, or not-yet-eligible) it calls
// RememberConsidered so the object stays in the index for the next
// pass.  When the daemon tiers it or it disappears, Forget drops it.
//
// Layout
//
// <state-dir>/zfs-aging/<bucket>.json
// { "<absolute path>": { "mtime": "<RFC3339>", "size": N }, ... }

type zfsLister struct {
	rootdir  string
	dataset  string    // full ZFS dataset name
	runner   ZfsRunner // nil disables zfs diff
	stateDir string
	base     *fsLister
	aging    *agingIndex

	mu         sync.Mutex
	zfsEnabled bool     // set by Begin when the diff succeeded for this pass
	changed    []string // last Begin's added+modified paths (mount-root-relative)
}

// NewZfsLister creates a zfsLister.  dataset or runner may be empty/nil
// to disable ZFS diff (behaves like the base fsLister).
func NewZfsLister(rootdir, dataset, stateDir string, runner ZfsRunner) *zfsLister {
	l := &zfsLister{
		rootdir:  rootdir,
		dataset:  dataset,
		runner:   runner,
		stateDir: stateDir,
		base:     &fsLister{rootdir: rootdir},
	}
	if stateDir != "" {
		l.aging = newAgingIndex(filepath.Join(stateDir, "zfs-aging"))
	}
	return l
}

// Begin runs the snapshot ping-pong once and caches the diff for the
// current pass.  Each call yields a fresh diff: ZFS snapshots are cheap
// (metadata-only), so we prefer a fresh one over a cached one since the
// daemon's Tier modifies xattrs between Begin and Sweep's Begin, and the
// newer diff naturally reflects the tree's current state.
func (l *zfsLister) Begin(ctx context.Context) error {
	if !l.zfsAvailable() {
		l.setZfsEnabled(false)
		return nil
	}
	changed, fullWalk, err := l.snapshotCycle(ctx)
	l.mu.Lock()
	l.changed = changed
	l.zfsEnabled = !fullWalk && err == nil
	l.mu.Unlock()
	return err
}

// ListCandidates implements Lister.
func (l *zfsLister) ListCandidates(ctx context.Context, bucket string) ([]Candidate, error) {
	l.mu.Lock()
	enabled := l.zfsEnabled
	ch := l.changed
	l.mu.Unlock()

	if !enabled {
		// fallback: full walk (also the path taken on the first pass
		// and on any error) and record the candidates we just saw
		// into the aging index for future passes.
		cands, werr := l.base.ListCandidates(ctx, bucket)
		if werr != nil {
			return nil, werr
		}
		for _, c := range cands {
			l.recordAging(bucket, c)
		}
		return cands, nil
	}

	var out []Candidate
	seen := map[string]bool{}
	for _, p := range ch {
		c, ok := l.mapChangedPath(p, bucket)
		if !ok {
			continue
		}
		out = append(out, c)
		seen[c.Path] = true
	}
	// union with the aging index (objects that aged past min-age
	// since the last pass without a content change).  Dedup against the
	// changed-set; and only add to the aging index after we've walked it
	// to avoid same-pass contamination.
	if l.aging != nil {
		for _, ap := range l.aging.pathsFor(bucket) {
			if seen[ap] {
				continue
			}
			if c, ok := l.mapAgingPath(ap, bucket); ok {
				out = append(out, c)
				seen[ap] = true
			}
		}
	}
	if len(out) > 0 {
		for _, c := range out {
			l.recordAging(bucket, c)
		}
	}
	return out, nil
}

// RememberConsidered is called by the daemon for a candidate that was
// evaluated and skipped (offline / restoring / not-yet-eligible) so the
// object stays in the aging index for the next pass.
func (l *zfsLister) RememberConsidered(bucket, path string, mtime time.Time, size int64) {
	l.recordAgingByKey(bucket, path, mtime, size)
}

// Forget drops an object from the aging index (called by the daemon
// once an object is tiered, or if it disappears).
func (l *zfsLister) Forget(bucket, path string) {
	if l.aging != nil {
		l.aging.remove(bucket, path)
	}
}

// ResolvePath and Buckets delegate to the base lister.
func (l *zfsLister) ResolvePath(bucket, key, versionId string) string {
	return l.base.ResolvePath(bucket, key, versionId)
}

func (l *zfsLister) Buckets(ctx context.Context) ([]string, error) {
	return l.base.Buckets(ctx)
}

// --- helpers ----------------------------------------------------------

func (l *zfsLister) zfsAvailable() bool {
	return l.dataset != "" && l.runner != nil
}

func (l *zfsLister) setZfsEnabled(v bool) {
	l.mu.Lock()
	l.zfsEnabled = v
	l.mu.Unlock()
}

const (
	zfsSlotA = "vgwtape-a"
	zfsSlotB = "vgwtape-b"
)

func otherSlot(s string) string {
	if s == zfsSlotA {
		return zfsSlotB
	}
	return zfsSlotA
}

// snapshotCycle runs one ping-pong iteration and returns:
//
//	changed  - added/modified paths (mount-root-relative)
//	fullWalk - true if the caller should full-walk (first pass or
//	           re-baseline)
//	err      - a ZFS failure (caller should fall back to a walk)
//
// On success the ping-pong is advanced.  On any failure the ping-pong
// is in a consistent baseline state (both slots exist, slot file is
// set) for the next pass.
func (l *zfsLister) snapshotCycle(ctx context.Context) (changed []string, fullWalk bool, err error) {
	last := l.readSlot()
	if last != zfsSlotA && last != zfsSlotB {
		// No slot file yet (first pass) or corrupt.  Re-baseline and
		// full-walk this pass to seed the aging index.
		if berr := l.rebaseline(ctx); berr != nil {
			return nil, true, berr
		}
		return nil, true, nil
	}

	cur := otherSlot(last)
	// Ensure `cur` is a fresh snapshot of the tree's current state.
	_ = l.runner.DestroySnapshot(ctx, l.dataset, cur) // idempotent; may fail if no perms
	if serr := l.runner.CreateSnapshot(ctx, l.dataset, cur); serr != nil {
		return nil, false, fmt.Errorf("zfs create snapshot %s: %w", cur, serr)
	}
	paths, derr := l.runner.DiffBetween(ctx, l.dataset, last, cur)
	if derr != nil {
		// `last` may be gone: re-baseline, walk this pass.
		if berr := l.rebaseline(ctx); berr != nil {
			return nil, true, derr
		}
		return nil, true, nil
	}
	// Advance the ping-pong.
	_ = l.runner.DestroySnapshot(ctx, l.dataset, last)
	if werr := l.writeSlot(cur); werr != nil {
		// non-fatal: worst case the next pass re-baselines.
	}
	return paths, false, nil
}

// rebaseline re-creates both snapshots at the tree's current state and
// resets the slot file.  Used on first-pass and crash recovery.  After a
// successful rebaseline the lister is in `full-walk` mode for the
// current pass so the aging index is seeded.
func (l *zfsLister) rebaseline(ctx context.Context) error {
	_ = l.runner.DestroySnapshot(ctx, l.dataset, zfsSlotA)
	_ = l.runner.DestroySnapshot(ctx, l.dataset, zfsSlotB)
	if err := l.runner.CreateSnapshot(ctx, l.dataset, zfsSlotA); err != nil {
		return fmt.Errorf("zfs baseline %s: %w", zfsSlotA, err)
	}
	if err := l.runner.CreateSnapshot(ctx, l.dataset, zfsSlotB); err != nil {
		return fmt.Errorf("zfs baseline %s: %w", zfsSlotB, err)
	}
	_ = l.writeSlot(zfsSlotA)
	l.mu.Lock()
	l.zfsEnabled = false // next ListCandidates does a full walk
	l.changed = nil
	l.mu.Unlock()
	return nil
}

func (l *zfsLister) slotFile() string {
	if l.stateDir == "" {
		return ""
	}
	return filepath.Join(l.stateDir, "zfs-snap-slot")
}

func (l *zfsLister) readSlot() string {
	f := l.slotFile()
	if f == "" {
		return ""
	}
	data, err := os.ReadFile(f)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if s != zfsSlotA && s != zfsSlotB {
		return ""
	}
	return s
}

func (l *zfsLister) writeSlot(v string) error {
	f := l.slotFile()
	if f == "" {
		return nil
	}
	if dir := filepath.Dir(f); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	return os.WriteFile(f, []byte(v+"\n"), 0o644)
}

// mapChangedPath maps a `zfs diff` path (relative to the dataset's
// mountpoint root) to a Candidate, if it lives under the given bucket.
// The daemon's contract is that the ZFS dataset's mount root ==
// the posix-hsm rootdir; otherwise operators must use a dataset
// that is mounted exactly at the posix-hsm root.
func (l *zfsLister) mapChangedPath(p, bucket string) (Candidate, bool) {
	parts := strings.SplitN(p, "/", 2)
	if len(parts) != 2 || parts[0] != bucket {
		return Candidate{}, false
	}
	abs := filepath.Join(l.rootdir, bucket, filepath.FromSlash(parts[1]))
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() || !fi.Mode().IsRegular() {
		return Candidate{}, false
	}
	return Candidate{Bucket: bucket, Key: parts[1], Path: abs,
		Size: fi.Size(), Mtime: fi.ModTime()}, true
}

func (l *zfsLister) mapAgingPath(abs, bucket string) (Candidate, bool) {
	rel, err := filepath.Rel(l.rootdir, abs)
	if err != nil {
		l.Forget(bucket, abs)
		return Candidate{}, false
	}
	rel = filepath.ToSlash(rel)
	parts := strings.SplitN(rel, "/", 2)
	if len(parts) != 2 || parts[0] != bucket {
		l.Forget(bucket, abs)
		return Candidate{}, false
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() || !fi.Mode().IsRegular() {
		l.Forget(bucket, abs)
		return Candidate{}, false
	}
	return Candidate{Bucket: bucket, Key: parts[1], Path: abs,
		Size: fi.Size(), Mtime: fi.ModTime()}, true
}

func (l *zfsLister) recordAging(bucket string, c Candidate) {
	l.recordAgingByKey(bucket, c.Path, c.Mtime, c.Size)
}

func (l *zfsLister) recordAgingByKey(bucket, path string, mtime time.Time, size int64) {
	if l.aging == nil {
		return
	}
	l.aging.record(bucket, path, mtime, size)
}

// --- aging index --------------------------------------------------------

type agingEntry struct {
	Mtime string `json:"mtime"`
	Size  int64  `json:"size"`
}

type agingIndex struct {
	dir   string
	mu    sync.Mutex
	cache map[string]map[string]*agingEntry
}

func newAgingIndex(dir string) *agingIndex {
	_ = os.MkdirAll(dir, 0o755)
	return &agingIndex{dir: dir, cache: map[string]map[string]*agingEntry{}}
}

func (ai *agingIndex) file(bucket string) string {
	return filepath.Join(ai.dir, sanitizeBucketName(bucket)+".json")
}

func sanitizeBucketName(name string) string {
	var out strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			out.WriteRune(r)
		default:
			out.WriteRune('_')
		}
	}
	if out.Len() == 0 {
		return "default"
	}
	return out.String()
}

func (ai *agingIndex) load(bucket string) map[string]*agingEntry {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	if m, ok := ai.cache[bucket]; ok {
		return m
	}
	data, err := os.ReadFile(ai.file(bucket))
	m := make(map[string]*agingEntry, 1024)
	if err == nil {
		_ = json.Unmarshal(data, &m)
	}
	for p := range m {
		if _, serr := os.Stat(p); serr != nil {
			delete(m, p)
		}
	}
	ai.cache[bucket] = m
	return m
}

func (ai *agingIndex) save(bucket string) {
	ai.mu.Lock()
	m, ok := ai.cache[bucket]
	if ok {
		data, err := json.Marshal(m)
		ai.mu.Unlock()
		if err == nil {
			_ = os.MkdirAll(ai.dir, 0o755)
			_ = os.WriteFile(ai.file(bucket), data, 0o644)
		}
		return
	}
	ai.mu.Unlock()
}

func (ai *agingIndex) record(bucket, path string, mtime time.Time, size int64) {
	ai.mu.Lock()
	m, ok := ai.cache[bucket]
	if !ok {
		m = make(map[string]*agingEntry, 1024)
		ai.cache[bucket] = m
	}
	m[path] = &agingEntry{Mtime: mtime.UTC().Format(time.RFC3339), Size: size}
	ai.mu.Unlock()
	ai.save(bucket)
}

func (ai *agingIndex) remove(bucket, path string) {
	ai.mu.Lock()
	if m, ok := ai.cache[bucket]; ok {
		delete(m, path)
	}
	ai.mu.Unlock()
	ai.save(bucket)
}

func (ai *agingIndex) pathsFor(bucket string) []string {
	m := ai.load(bucket)
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	return out
}
