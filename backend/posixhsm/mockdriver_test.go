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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedFile writes a file with the given payload.
func seedFile(t *testing.T, dir, name, payload string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestMockDriver_MultiWaveOffsetRestores is a regression test for the
// "mock driver: short read: got N, want M" failure that happened when
// ArchiveWave allocated a non-zero offset via m.next but wrote to file
// position 0 anyway. Two successive archive calls followed by restore
// of each must round-trip.
func TestMockDriver_MultiWaveOffsetRestores(t *testing.T) {
	dir := t.TempDir()
	d, err := NewMockDriver(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	ctx := context.Background()
	aDir, bDir := t.TempDir(), t.TempDir()
	// Different payloads, similar sizes to keep the offsets close.
	seedFile(t, aDir, "a", "object-alpha")
	seedFile(t, bDir, "b", "object-beta")
	p1 := filepath.Join(aDir, "a")
	p2 := filepath.Join(bDir, "b")

	// Two separate waves (simulates two scan passes within one daemon
	// process -- the original failure mode).
	locs1, err := d.ArchiveWave(ctx, []WaveFile{{Path: p1, Size: 12}})
	if err != nil {
		t.Fatal(err)
	}
	locs2, err := d.ArchiveWave(ctx, []WaveFile{{Path: p2, Size: 11}})
	if err != nil {
		t.Fatal(err)
	}
	if len(locs1) != 1 || len(locs2) != 1 {
		t.Fatalf("want 1 locator each, got %v / %v", locs1, locs2)
	}
	// The two locators must reference different offsets in the archive.
	if locs1[0] == locs2[0] {
		t.Fatalf("offsets collide: both %q", locs1[0])
	}
	if !strings.HasPrefix(locs2[0], "mock:") || !strings.HasPrefix(locs1[0], "mock:") {
		t.Fatalf("unexpected locator formats: %q / %q", locs1[0], locs2[0])
	}

	// Restore both and compare byte-for-byte.
	restore := func(loc string, size int64) []byte {
		t.Helper()
		var buf bytes.Buffer
		if rerr := d.Restore(ctx, loc, &buf, size); rerr != nil {
			t.Fatalf("restore %q: %v", loc, rerr)
		}
		return buf.Bytes()
	}
	gotA := restore(locs1[0], 12)
	if !bytes.Equal(gotA, []byte("object-alpha")) {
		t.Fatalf("object A mismatch: %q", gotA)
	}
	gotB := restore(locs2[0], 11)
	if !bytes.Equal(gotB, []byte("object-beta")) {
		t.Fatalf("object B mismatch: %q", gotB)
	}

	// Sanity: the shared data file must be at least the sum of the two
	// object sizes (they were appended, not overwritten on top of each
	// other).
	fi, err := os.Stat(filepath.Join(dir, "mock", "data"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() < 23 {
		t.Fatalf("archive size = %d, want >= 23", fi.Size())
	}
}

// TestMockDriver_RestoreRejectsLengthMismatch guards the "size mismatch"
// path: restoring a locator to a different expected length must fail, not
// silently truncate or over-read.
func TestMockDriver_RestoreRejectsLengthMismatch(t *testing.T) {
	dir := t.TempDir()
	d, err := NewMockDriver(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	src := seedFile(t, t.TempDir(), "o", "payload") // 7 bytes
	locs, err := d.ArchiveWave(ctx, []WaveFile{{Path: src, Size: 7}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := d.Restore(ctx, locs[0], &buf, 5); err == nil {
		t.Fatalf("expected length-mismatch error, got %d bytes", buf.Len())
	}
}
