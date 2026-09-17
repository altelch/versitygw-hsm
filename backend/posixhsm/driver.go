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
	"context"
	"io"
)

// WaveFile is one object within an archive wave.
// Path is the absolute path to the live object file; Size is its byte
// count. Drivers use these to read the data.
type WaveFile struct {
	Path string
	Size int64
}

// HsmDriver abstracts the secondary store a daemon uses to bulk-move
// object data between the local filesystem and a remote/tape store.
//
// The interface is wave-aware because that matches the natural unit of
// work for the primary target (Bareos: one `define job` = one batch of
// files). Drivers return one locator per file, in the same order as the
// input slice. A driver may fail per-file or fail the whole wave; the
// daemon treats a failed wave as "nothing was archived" and retries.
//
// The posixhsm backend wrapper does not talk to the driver directly —
// the daemon streams the live file (or a hard-linked staging copy, per
// the driver's preference) through ArchiveWave and then marks the
// object offline in the shared xattr state.
type HsmDriver interface {
	// Name returns a short driver identifier, e.g. "mock" or "bareos".
	Name() string

	// ArchiveWave reads each WaveFile.Path and stores its data on the
	// secondary store. On success it returns one locator per file
	// (same order as input) usable with Restore and Purge. On any
	// failure, all files in the wave are left unmodified on disk and
	// the error is returned.
	ArchiveWave(ctx context.Context, files []WaveFile) ([]string, error)

	// Restore materializes one object: it reads the data identified by
	// locator and writes it (size bytes) to wr. The daemon provides a
	// writer to the live object file path so the inode, ACL, and xattrs
	// are preserved.
	Restore(ctx context.Context, locator string, wr io.Writer, size int64) error

	// Purge removes the secondary-store copy identified by locator.
	// Idempotent: purging an unknown locator is not an error.
	Purge(ctx context.Context, locator string) error

	// Close releases resources held by the driver.
	Close() error
}
