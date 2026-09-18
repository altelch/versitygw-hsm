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

package queue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestEnqueueDedup(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := q.Enqueue(Job{Op: JobOpRestore, Bucket: "b", Key: "k", Days: 3}); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	// only 1 pending entry after 5 enqueues of the same identity
	pending := filepath.Join(dir, "pending")
	entries, err := os.ReadDir(pending)
	if err != nil {
		t.Fatalf("readdir pending: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 pending entry after dedup, got %d", len(entries))
	}
}

func TestClaimCompleteFail(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	j1, err := q.Enqueue(Job{Op: JobOpTier, Bucket: "b1", Key: "k1"})
	if err != nil {
		t.Fatalf("Enqueue j1: %v", err)
	}
	if _, err := q.Enqueue(Job{Op: JobOpTier, Bucket: "b2", Key: "k2"}); err != nil {
		t.Fatalf("Enqueue j2: %v", err)
	}

	got, err := q.Claim(context.Background())
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if got.Bucket != j1.Bucket && got.Bucket != "b2" {
		t.Fatalf("unexpected bucket %q", got.Bucket)
	}
	if err := q.Complete(got); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	got2, err := q.Claim(context.Background())
	if err != nil {
		t.Fatalf("Claim 2: %v", err)
	}
	if err := q.Fail(got2, "test reason"); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	if _, err := q.Claim(context.Background()); !errors.Is(err, ErrEmpty) {
		t.Fatalf("expected ErrEmpty, got %v", err)
	}
}

func TestResetClaimed(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	j, _ := q.Enqueue(Job{Op: JobOpRestore, Bucket: "b", Key: "k", Days: 7})
	if _, err := q.Claim(context.Background()); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := q.ResetClaimed(); err != nil {
		t.Fatalf("ResetClaimed: %v", err)
	}
	got, err := q.Claim(context.Background())
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if got.Identity() != j.Identity() {
		t.Fatalf("expected same identity, got %q vs %q", got.Identity(), j.Identity())
	}
}

func TestConcurrentClaimNoDup(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const n = 50
	for i := 0; i < n; i++ {
		if _, err := q.Enqueue(Job{Op: JobOpTier, Bucket: "b", Key: fmt.Sprintf("k%d", i)}); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		seen   = map[uint64]bool{}
		claims int
	)
	const workers = 8
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j, err := q.Claim(context.Background())
				if errors.Is(err, ErrEmpty) {
					return
				}
				if err != nil {
					t.Errorf("claim: %v", err)
					return
				}
				mu.Lock()
				if seen[j.ID] {
					t.Errorf("duplicate claim for id %d", j.ID)
				}
				seen[j.ID] = true
				claims++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if claims != n {
		t.Fatalf("expected %d claims, got %d", n, claims)
	}
}

// Identity is exposed for tests to compare claims by job identity.
func (j Job) Identity() string { return j.identity() }
