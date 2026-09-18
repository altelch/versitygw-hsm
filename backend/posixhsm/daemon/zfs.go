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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ZfsRunner abstracts the `zfs` CLI commands the daemon uses to enumerate
// the set of objects that changed between two consecutive snapshots.
//
// Why: a naive tier pass walks the entire posix tree and reads xattrs for
// every object (O(n) readdir + O(n) getxattr regardless of whether anything
// changed). ZFS `diff` between two snapshots yields exactly the added and
// modified paths in the interval, so the daemon only stats + reads xattrs
// for the small changed set -- and, critically, does not readdir the whole
// tree on every pass.
//
// The production implementation shells out to the `zfs` binary; tests
// inject a fake to replay documented `zfs diff` output without a live pool.
type ZfsRunner interface {
	// CreateSnapshot creates dataset@snap. Idempotent.
	CreateSnapshot(ctx context.Context, dataset, snap string) error
	// DestroySnapshot deletes dataset@snap. Idempotent (no error if
	// already gone).
	DestroySnapshot(ctx context.Context, dataset, snap string) error
	// DiffBetween returns the absolute paths that were added (+) or
	// modified (~) in the dataset between the two named snapshots.
	// Removed paths (-) are excluded: they no longer exist and cannot
	// be tiered. Paths are relative to the ZFS mountpoint root.
	DiffBetween(ctx context.Context, dataset, prev, cur string) ([]string, error)
}

// execZfsRunner runs real `zfs` commands.
type execZfsRunner struct {
	path string // "" => resolve via VGWTAPED_ZFS then $PATH
}

// NewExecZfsRunner returns a ZfsRunner that executes `zfs`. path may be
// empty; the runner then honours $VGWTAPED_ZFS and finally $PATH.
func NewExecZfsRunner(path string) ZfsRunner {
	if path == "" {
		path = os.Getenv("VGWTAPED_ZFS")
	}
	return &execZfsRunner{path: path}
}

func (r *execZfsRunner) binary() (string, error) {
	if r.path != "" {
		if _, err := os.Stat(r.path); err != nil {
			return "", fmt.Errorf("zfs runner: binary %q: %w", r.path, err)
		}
		return r.path, nil
	}
	for _, cand := range []string{os.Getenv("VGWTAPED_ZFS"), "zfs"} {
		if cand == "" {
			continue
		}
		if p, err := exec.LookPath(cand); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("zfs runner: `zfs` not found (install zfsutils or set VGWTAPED_ZFS)")
}

func (r *execZfsRunner) run(ctx context.Context, args ...string) ([]byte, error) {
	bin, err := r.binary()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()
	out := buf.Bytes()
	if runErr == nil {
		return out, nil
	}
	return out, fmt.Errorf("zfs %s: %v (output: %s)", strings.Join(args, " "), runErr, truncatedBytes(out, 400))
}

func (r *execZfsRunner) CreateSnapshot(ctx context.Context, dataset, snap string) error {
	out, err := r.run(ctx, "snapshot", dataset+"@"+snap)
	if err == nil {
		return nil
	}
	if strings.Contains(string(out), "already exists") {
		return nil
	}
	return err
}

func (r *execZfsRunner) DestroySnapshot(ctx context.Context, dataset, snap string) error {
	out, err := r.run(ctx, "destroy", dataset+"@"+snap)
	if err == nil {
		return nil
	}
	if strings.Contains(string(out), "does not exist") || strings.Contains(string(out), "cannot destroy") {
		return nil
	}
	return err
}

func (r *execZfsRunner) DiffBetween(ctx context.Context, dataset, prev, cur string) ([]string, error) {
	out, err := r.run(ctx, "diff", dataset+"@"+prev, dataset+"@"+cur)
	if err != nil {
		return nil, err
	}
	return parseZfsDiff(out), nil
}

// parseZfsDiff parses `zfs diff` output. Each line begins with an action
// byte then whitespace then a mountpoint-relative path:
//
//   - <path>  added
//   - <path>  removed   (excluded)
//     ~ <path>  modified
//
// Returns the added and modified paths.
func parseZfsDiff(out []byte) []string {
	var res []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] != '+' && line[0] != '~' {
			continue // drop removed (-) and any non-diff noise
		}
		rest := line[1:]
		i := 0
		for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
			i++
		}
		if i < len(rest) {
			res = append(res, string(rest[i:]))
		}
	}
	return res
}

func truncatedBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + " …"
}
