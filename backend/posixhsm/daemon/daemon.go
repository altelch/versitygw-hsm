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

// Package vgwtape implements the HSM tiering daemon (vgwtaped). It owns all
// physical data movement for the posix-hsm backend:
//
//   - Tier (archive): collects all objects due for tiering, batches them
//     into waves, hands each wave to the HsmDriver (e.g. Bareos), and once
//     the archive succeeds records size+locator and truncates each object
//     to zero bytes. Drivers reporting SingleWave() (see SingleWaveArchiver)
//     receive the whole due set in one call per pass.
//   - Restore: claims restore jobs, materializes the data back over the
//     truncated object (preserving inode + xattrs), and records expiry.
//   - Sweep: re-tiers objects whose restored copy is past its expiry window.
//   - GC: purges secondary-store copies whose objects were deleted.
//
// The daemon communicates with the gateway only through the shared state
// directory (xattr flags on the objects plus the job queue). It reads the
// posix tree directly for candidate discovery and path resolution.
package daemon

import (
	"context"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posixhsm"
	"github.com/versity/versitygw/backend/posixhsm/policy"
	"github.com/versity/versitygw/backend/posixhsm/queue"
	"github.com/versity/versitygw/backend/posixhsm/state"
)

// Candidate is an object discovered by the lister that the policy may tier.
type Candidate struct {
	Bucket string
	Key    string
	Path   string // absolute path to the live object
	Size   int64
	Mtime  time.Time
}

// Lister enumerates candidate objects for tiering. The daemon filters these
// against policy (age/size/tags) and against the HSM state (skip offline).
type Lister interface {
	Buckets(ctx context.Context) ([]string, error)
	ListCandidates(ctx context.Context, bucket string) ([]Candidate, error)
	// ResolvePath maps (bucket,key,versionId) to an absolute object path.
	ResolvePath(bucket, key, versionId string) string
}

// PassBeginner is an optional Lister extension for listers that have a
// per-pass setup step (e.g. a ZFS snapshot diff).  The daemon calls it once
// before iterating buckets in a Tier or Sweep pass.
type PassBeginner interface {
	Begin(ctx context.Context) error
}

// ConsiderNoter is an optional Lister extension.  The daemon calls it for a
// candidate it chose NOT to tier (offline, restoring, or not-yet-eligible);
// the lister can keep the object in an internal "aging" index so it is
// reconsidered on the next pass.
type ConsiderNoter interface {
	RememberConsidered(bucket, path string, mtime time.Time, size int64)
}

// Forgetter is an optional Lister extension.  The daemon calls it for a
// candidate that was successfully tiered this pass, so the lister can drop
// it from any internal index.
type Forgetter interface {
	Forget(bucket, path string)
}

// SingleWaveArchiver is an optional HsmDriver extension.  A driver that
// reports true wants the entire due set passed in a single ArchiveWave call
// per Tier/Sweep pass.  This is for drivers whose ArchiveWave triggers a
// fixed-content job (e.g. Bareos: the job archives whatever its FileSet
// covers; the file list is advisory): splitting the due set into waves
// would just run the same job repeatedly per pass.
type SingleWaveArchiver interface {
	SingleWave() bool
}

func (d *Daemon) beginPass(ctx context.Context) {
	if b, ok := d.lister.(PassBeginner); ok {
		_ = b.Begin(ctx) // graceful degradation on error
	}
}

func (d *Daemon) rememberConsidered(bucket, path string, mtime time.Time, size int64) {
	if n, ok := d.lister.(ConsiderNoter); ok {
		n.RememberConsidered(bucket, path, mtime, size)
	}
}

func (d *Daemon) forget(bucket, path string) {
	if f, ok := d.lister.(Forgetter); ok {
		f.Forget(bucket, path)
	}
}

// fsLister walks a real posix tree rooted at rootdir.
type fsLister struct {
	rootdir string
}

func newFsLister(rootdir string) *fsLister { return &fsLister{rootdir: rootdir} }

// NewFSLister returns a Lister that walks a real posix tree rooted at rootdir.
func NewFSLister(rootdir string) Lister { return &fsLister{rootdir: rootdir} }

func (l *fsLister) ResolvePath(bucket, key, versionId string) string {
	if versionId != "" {
		return "" // versioned restores handled via the recorded path (daemon v1: current only)
	}
	return filepath.Join(l.rootdir, bucket, key)
}

func (l *fsLister) Buckets(_ context.Context) ([]string, error) {
	entries, err := os.ReadDir(l.rootdir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func (l *fsLister) ListCandidates(_ context.Context, bucket string) ([]Candidate, error) {
	bucketRoot := filepath.Join(l.rootdir, bucket)
	var out []Candidate
	err := filepath.Walk(bucketRoot, func(path string, d fs.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d == nil || d.IsDir() {
			return nil
		}
		key, _ := filepath.Rel(bucketRoot, path)
		key = filepath.ToSlash(key)
		out = append(out, Candidate{
			Bucket: bucket,
			Key:    key,
			Path:   path,
			Size:   d.Size(),
			Mtime:  d.ModTime(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Daemon performs HSM tiering.
type Daemon struct {
	drv      posixhsm.HsmDriver
	q        *queue.Queue
	meta     meta.MetadataStorer
	pol      *policy.Policy
	lister   Lister
	waveSize int
	now      func() time.Time
}

// Config constructs a Daemon.
type Config struct {
	Driver posixhsm.HsmDriver
	Queue  *queue.Queue
	Meta   meta.MetadataStorer
	Policy *policy.Policy
	Lister Lister
	// WaveSize is the max files per ArchiveWave call. Ignored (forced to
	// one wave per pass) when the driver implements SingleWaveArchiver and
	// reports SingleWave() == true.
	WaveSize int
}

func New(cfg Config) *Daemon {
	wave := cfg.WaveSize
	if wave <= 0 {
		wave = 256
	}
	if s, ok := cfg.Driver.(SingleWaveArchiver); ok && s.SingleWave() {
		wave = math.MaxInt
	}
	return &Daemon{
		drv:      cfg.Driver,
		q:        cfg.Queue,
		meta:     cfg.Meta,
		pol:      cfg.Policy,
		lister:   cfg.Lister,
		waveSize: wave,
		now:      time.Now,
	}
}

// Tier scans all buckets, finds objects due for tiering per policy, batches
// them into waves, and runs each wave through the driver. On success it
// truncates + marks offline. Returns the number of objects tiered.
func (d *Daemon) Tier(ctx context.Context) (int, error) {
	if d.pol == nil {
		return 0, errors.New("vgwtape: no policy configured")
	}
	d.beginPass(ctx)
	buckets, err := d.lister.Buckets(ctx)
	if err != nil {
		return 0, err
	}

	var due []posixhsm.WaveFile
	type keyedFile struct {
		wf     posixhsm.WaveFile
		bucket string
	}
	var dueKeyed []keyedFile
	for _, bucket := range buckets {
		rule := d.pol.RuleFor(bucket)
		cands, err := d.lister.ListCandidates(ctx, bucket)
		if err != nil {
			continue
		}
		for _, c := range cands {
			st := state.Store(d.meta, c.Path)
			if st.Offline || st.Restoring {
				d.rememberConsidered(bucket, c.Path, c.Mtime, c.Size)
				continue
			}
			obj := policy.ObjInfo{
				Bucket:       bucket,
				Key:          c.Key,
				LastModified: c.Mtime,
				Size:         c.Size,
			}
			if !rule.ShouldTier(obj, d.now()) {
				d.rememberConsidered(bucket, c.Path, c.Mtime, c.Size)
				continue
			}
			// enqueue a tier job for bookkeeping/dedup
			_, _ = d.q.Enqueue(queue.Job{Op: queue.JobOpTier, Bucket: bucket, Key: c.Key})
			due = append(due, posixhsm.WaveFile{Path: c.Path, Size: c.Size})
			dueKeyed = append(dueKeyed, keyedFile{wf: posixhsm.WaveFile{Path: c.Path, Size: c.Size}, bucket: bucket})
		}
	}
	if len(due) == 0 {
		return 0, nil
	}

	// batch into waves and archive
	n, err := d.archiveWaves(ctx, due)
	if err == nil {
		// objects successfully tiered: drop them from the lister's aging
		// index (they are now offline; they return to candidacy after a
		// restore, at which point they are re-remembered on a later pass).
		for _, kf := range dueKeyed {
			d.forget(kf.bucket, kf.wf.Path)
		}
	}
	return n, err
}

// archiveWaves splits due files into waves and runs each through the driver.
func (d *Daemon) archiveWaves(ctx context.Context, due []posixhsm.WaveFile) (int, error) {
	var tiered int
	for i := 0; i < len(due); i += d.waveSize {
		end := i + d.waveSize
		if end > len(due) {
			end = len(due)
		}
		wave := due[i:end]
		locs, err := d.drv.ArchiveWave(ctx, wave)
		if err != nil {
			// A failed wave leaves all files intact on disk.
			return tiered, err
		}
		if len(locs) != len(wave) {
			return tiered, errors.New("vgwtape: locator count mismatch")
		}
		for j, m := range wave {
			if m.Size > 0 {
				if err := os.Truncate(m.Path, 0); err != nil {
					return tiered, err
				}
			}
			if err := state.SetOffline(d.meta, m.Path, locs[j], m.Size); err != nil {
				return tiered, err
			}
			tiered++
		}
	}
	return tiered, nil
}

// RestoreJobs processes all pending restore jobs (single objects).
func (d *Daemon) RestoreJobs(ctx context.Context, max int) (int, error) {
	if max <= 0 {
		max = 1024
	}
	done := 0
	for i := 0; i < max; i++ {
		job, err := d.q.Claim(ctx)
		if errors.Is(err, queue.ErrEmpty) {
			return done, nil
		}
		if err != nil {
			return done, err
		}
		if job.Op != queue.JobOpRestore {
			// not a restore; put it back for the tier path to handle
			_ = d.q.Fail(job, "not a restore job")
			continue
		}
		path := d.lister.ResolvePath(job.Bucket, job.Key, job.VersionID)
		if path == "" {
			_ = d.q.Fail(job, "unresolvable object path")
			continue
		}
		st := state.Store(d.meta, path)
		if !st.Offline {
			_ = d.q.Complete(job)
			continue
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			_ = d.q.Fail(job, err.Error())
			continue
		}
		rerr := d.drv.Restore(ctx, st.Locator, f, st.Size)
		f.Close()
		if rerr != nil {
			_ = d.q.Fail(job, rerr.Error())
			continue
		}
		if cerr := state.ClearOffline(d.meta, path); cerr != nil {
			_ = d.q.Fail(job, cerr.Error())
			continue
		}
		if job.Days > 0 {
			_ = state.SetExpiry(d.meta, path, d.now().Add(time.Duration(job.Days)*24*time.Hour))
		}
		_ = d.q.Complete(job)
		done++
	}
	return done, nil
}

// Sweep re-tiers objects whose restored copy is past its expiry window.
// Re-tiering on expiry is unconditional (matching Glacier, where a restored
// copy always returns to the archive when the window ends) — it does not
// re-check the age/size/tag policy, which only governs initial tiering.
// Expired objects are batched and archived the same way as a fresh tier.
func (d *Daemon) Sweep(ctx context.Context) (int, error) {
	d.beginPass(ctx)
	buckets, err := d.lister.Buckets(ctx)
	if err != nil {
		return 0, err
	}
	var expired []posixhsm.WaveFile
	for _, bucket := range buckets {
		cands, err := d.lister.ListCandidates(ctx, bucket)
		if err != nil {
			continue
		}
		for _, c := range cands {
			st := state.Store(d.meta, c.Path)
			// An online object with a past expiry is due for re-tiering.
			if st.Offline || st.Expiry == "" {
				continue
			}
			exp, perr := time.Parse(time.RFC3339, st.Expiry)
			if perr != nil {
				continue
			}
			if d.now().After(exp) {
				_ = state.Set(d.meta, c.Path, state.Expiry, "")
				_, _ = d.q.Enqueue(queue.Job{Op: queue.JobOpTier, Bucket: bucket, Key: c.Key})
				expired = append(expired, posixhsm.WaveFile{Path: c.Path, Size: c.Size})
			}
		}
	}
	if len(expired) == 0 {
		return 0, nil
	}
	return d.archiveWaves(ctx, expired)
}

// GC reads the GC file (one locator per line) and purges each entry, then
// removes the file. Returns the number of locators purged.
func (d *Daemon) GC(ctx context.Context, gcFile string) (int, error) {
	data, err := os.ReadFile(gcFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	purged := 0
	for _, line := range splitLines(data) {
		if line == "" {
			continue
		}
		if perr := d.drv.Purge(ctx, line); perr != nil {
			continue
		}
		purged++
	}
	_ = os.Remove(gcFile)
	return purged, nil
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}
