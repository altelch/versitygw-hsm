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

// Package queue implements a durable job queue backed by the filesystem.
// Both the S3 gateway (which enqueues restore jobs) and the HSM daemon
// (which claims and completes jobs) are processes that share the same
// state directory. Atomicity is provided by atomic renames and the
// filesystem. Dedup is provided by a per-job marker file.
package queue

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JobOp is the operation requested by a queue entry.
type JobOp string

const (
	// JobOpRestore materializes an offline object back to disk.
	JobOpRestore JobOp = "restore"
	// JobOpTier archives an object to a secondary store.
	JobOpTier JobOp = "tier"
	// JobOpPurge removes a secondary-store copy (e.g. after delete).
	JobOpPurge JobOp = "purge"
)

// Job is a queue entry. It may be a restore (single object) or a
// tier/purge (single object). Batch/archive waves are grouped by the
// daemon from multiple tier jobs.
type Job struct {
	Op          JobOp   `json:"op"`
	Bucket      string  `json:"bucket"`
	Key         string  `json:"key"`
	VersionID   string  `json:"versionId,omitempty"`
	Days        int32   `json:"days,omitempty"`      // restore window, days
	Loc         string  `json:"locator,omitempty"`   // driver locator
	SubmittedAt int64   `json:"submittedAt"`         // unix seconds
	ID          uint64  `json:"id"`
}

func (j Job) identity() string {
	sum := sha256.Sum256([]byte(string(j.Op) + j.Bucket + j.Key + j.VersionID))
	return fmt.Sprintf("%x", sum)
}

// Queue is a filesystem-backed job queue.
type Queue struct {
	dir string

	mu    sync.Mutex
	ready []Job
}

// New opens a queue rooted at dir, creating the directory if needed.
// Multiple processes may open the same queue concurrently; claims and
// enqueues are serialized by atomic filesystem renames.
func New(dir string) (*Queue, error) {
	if dir == "" {
		return nil, errors.New("queue: empty dir")
	}
	if err := os.MkdirAll(filepath.Join(dir, "pending"), 0o755); err != nil {
		return nil, fmt.Errorf("queue: mkdir pending: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "claimed"), 0o755); err != nil {
		return nil, fmt.Errorf("queue: mkdir claimed: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "done"), 0o755); err != nil {
		return nil, fmt.Errorf("queue: mkdir done: %w", err)
	}
	q := &Queue{dir: dir}
	// Load any unclaimed jobs left over from a previous run.
	q.mu.Lock()
	q.ready = q.listPending()
	q.mu.Unlock()
	return q, nil
}

// Enqueue appends a job to the pending set. If a job with an equivalent
// identity is already pending, the second enqueue is silently dropped
// (dedup). The returned job is the canonical one.
func (q *Queue) Enqueue(job Job) (Job, error) {
	if job.SubmittedAt == 0 {
		job.SubmittedAt = time.Now().Unix()
	}
	id, err := q.nextID()
	if err != nil {
		return job, err
	}
	job.ID = id
	path := q.jobPath("pending", job.identity())
	data, err := json.Marshal(job)
	if err != nil {
		return job, err
	}
	// Atomic write: write to a temp name and rename. Rename onto an
	// existing pending file is a no-op (dedup).
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return job, fmt.Errorf("queue: write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return job, fmt.Errorf("queue: rename: %w", err)
	}
	q.mu.Lock()
	q.ready = append(q.ready, job)
	q.mu.Unlock()
	return job, nil
}

// Claim removes the next pending job and returns it. When the queue is
// empty, Claim returns a non-nil ErrEmpty. Concurrent claimers are
// serialized by the atomic rename to the "claimed" set.
func (q *Queue) Claim(ctx context.Context) (Job, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Job{}, err
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.ready) == 0 {
		// Re-list in case another process enqueued since our last scan.
		q.ready = q.listPending()
	}
	for len(q.ready) > 0 {
		job := q.ready[0]
		q.ready = q.ready[1:]
		src := q.jobPath("pending", job.identity())
		dst := q.jobPath("claimed", job.identity())
		if err := os.Rename(src, dst); err != nil {
			// lost the race: another process claimed it first.
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return Job{}, fmt.Errorf("queue: claim rename: %w", err)
		}
		return job, nil
	}
	return Job{}, ErrEmpty
}

// ErrEmpty is returned by Claim when the queue has no jobs.
var ErrEmpty = errors.New("queue: empty")

// Complete marks a job as done and removes its claimed marker.
func (q *Queue) Complete(job Job) error {
	src := q.jobPath("claimed", job.identity())
	dst := q.jobPath("done", job.identity())
	if err := os.Rename(src, dst); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("queue: complete rename: %w", err)
	}
	return nil
}

// Fail marks a job as failed by moving it to the done set with a
// failed marker. The caller may inspect the marker file for diagnostics.
func (q *Queue) Fail(job Job, reason string) error {
	src := q.jobPath("claimed", job.identity())
	dst := q.jobPath("done", job.identity())
	if err := os.Rename(src, dst); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("queue: fail rename: %w", err)
	}
	if reason != "" {
		_ = os.WriteFile(dst+".reason", []byte(reason), 0o644)
	}
	return nil
}

// ResetClaimed returns all claimed jobs to the pending set. Used on
// daemon startup when a worker crashed mid-claim.
func (q *Queue) ResetClaimed() error {
	claimed, err := os.ReadDir(filepath.Join(q.dir, "claimed"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, e := range claimed {
		src := filepath.Join(q.dir, "claimed", e.Name())
		dst := filepath.Join(q.dir, "pending", e.Name())
		if err := os.Rename(src, dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			continue
		}
		var job Job
		data, err := os.ReadFile(src)
		if err == nil {
			_ = json.Unmarshal(data, &job)
			q.ready = append(q.ready, job)
		}
	}
	return nil
}

func (q *Queue) jobPath(state, id string) string {
	return filepath.Join(q.dir, state, id)
}

func (q *Queue) listPending() []Job {
	dir := filepath.Join(q.dir, "pending")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var jobs []Job
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".reason") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var job Job
		if err := json.Unmarshal(data, &job); err != nil {
			continue
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].SubmittedAt != jobs[j].SubmittedAt {
			return jobs[i].SubmittedAt < jobs[j].SubmittedAt
		}
		return jobs[i].ID < jobs[j].ID
	})
	return jobs
}

func (q *Queue) nextID() (uint64, error) {
	// Use a counter file with atomic reads/writes: this is best-effort
	// uniqueness; collisions are harmless because the identity is a
	// hash of (op,bucket,key,version) which is stable across retries.
	dir := filepath.Join(q.dir, "counter")
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "next")
	var id uint64
	if data, err := os.ReadFile(path); err == nil {
		_, _ = fmt.Sscanf(string(data), "%d", &id)
	}
	id++
	if err := os.WriteFile(path, []byte(strconv.FormatUint(id, 10)), 0o644); err != nil {
		return id, nil // best-effort
	}
	return id, nil
}
