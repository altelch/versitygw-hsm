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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Bareos integration, grounded in the official docs
// (https://docs.bareos.org -- "Bareos Console" / "The Restore Command" /
// "API" chapters).
//
// bconsole is a console client that reads a list of console commands from
// stdin (see the "Running the Console from a Shell Script" section):
//
//	bconsole -c bconsole.conf <<END
//	  run job=BackupJob
//	  wait
//	  messages
//	  quit
//	END
//
// success is signalled by the job-report line
//
//	Termination:          * Backup completed without errors.
//
// The documented single-file (by filename) restore flow is:
//
//	restore client=<client> jobid=<jobid> file=<absolute path> yes
//
// followed by `wait` and `messages`, with success on the same
// Termination line (suffix `Restore OK` / `completed without errors`).
//
// JSON output for `list jobs` is enabled by the documented `.api 2` command
// (see "API mode 2 (json)").
//
// Operator pre-configuration (bareos-dir.conf + bareos-fd.conf), required
// by the driver but NOT created by it (safety):
//
//   - A Client resource (Bareos File Daemon) named opts.Client that
//     corresponds to the host running the posix-hsm gateway.
//   - A FileSet resource named opts.Fileset that includes the posix-hsm
//     tree to be backed up.
//   - A Backup Job (e.g. "HsmBackup") using the above, with the intended
//     Storage/Pool.  This is what ArchiveWave runs.
//   - A Restore Job (e.g. "HsmRestore") of Type = Restore whose Where
//     equals the posix rootdir (default for `where` in the restore
//     command) -- the bareos-fd must restore the file back to its
//     original location so the live inode + xattrs are preserved.
//
// Bareos has no per-file delete from a written volume; Purge below is
// therefore best-effort on the catalog (prune files jobid=...), plus a
// hard no-op for the physical tape contents (operators manage volume
// recycle independently of the daemon).

// BareosOpts is the configuration surface for a Bareos-backed HsmDriver.
// All fields are optional when using the driver in a test-harness
// environment (see the injectable console-executor hook on the driver).
type BareosOpts struct {
	// BConsolePath is the absolute path to the `bconsole` binary. When
	// empty the driver resolves "bconsole" from $PATH (and honours the
	// BAREOS_BCONSOLE environment variable as an override).
	BConsolePath string

	// BConsoleConfig is the value passed to -c (a config directory or
	// file defining the Director to talk to). Defaults to the standard
	// bconsole.conf.
	BConsoleConfig string

	// Director is an optional named-console to select with -D.
	Director string

	// Client is the name of the Bareos Client (File Daemon) resource
	// matching the gateway host. Required.
	Client string

	// BackupJob is the name of a Type=Backup Job that will archive the
	// tiered objects (its FileSet resource must include the posix-hsm
	// tree). Required.
	BackupJob string

	// RestoreJob is the name of a Type=Restore Job used to restore a
	// single file at its original location. Required.
	RestoreJob string

	// Timeout bounds a single bconsole batch (which may internally block
	// on `wait` for the job to complete). Default: 10m.
	Timeout time.Duration
}

func (o *BareosOpts) withDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Minute
	}
}

// BareosHsmDriver satisfies HsmDriver by driving the `bconsole` batch
// protocol with the documented backup / restore commands.
//
// The driver is injectable: `exec` is the process-boundary, and tests can
// replace it with a fake that replays the documented output for the
// commands they observe.
type BareosHsmDriver struct {
	opts    BareosOpts
	execcmd consoleExec
}

var _ HsmDriver = (*BareosHsmDriver)(nil)

// consoleExec executes a bconsole batch. The command list (without `quit`,
// which is appended by the default implementation) is sent on standard
// input, and the combined stdout+stderr is returned. A non-nil returned
// error indicates the bconsole process itself failed (bad config, timeout,
// connection, etc.) -- not a job failure, which must be detected from
// the job-report text.
type consoleExec func(ctx context.Context, path, config, director string, cmds []string) ([]byte, error)

func defaultConsoleExec(ctx context.Context, bconsolePath, config, director string, cmds []string) ([]byte, error) {
	if bconsolePath == "" {
		bconsolePath = "bconsole"
		if env := os.Getenv("BAREOS_BCONSOLE"); env != "" {
			bconsolePath = env
		}
	}
	args := []string{}
	if config != "" {
		args = append(args, "-c", config)
	}
	if director != "" {
		args = append(args, "-D", director)
	}
	stdin := strings.Join(append(cmds, "quit"), "\n") + "\n"

	cmd := exec.CommandContext(ctx, bconsolePath, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

// NewBareosDriver validates opts and returns a BareosHsmDriver.
func NewBareosDriver(o BareosOpts) (*BareosHsmDriver, error) {
	o.withDefaults()
	if o.Client == "" {
		return nil, errors.New("bareos driver: opts.Client is required (name of the Bareos File Daemon resource for this gateway)")
	}
	if o.BackupJob == "" {
		return nil, errors.New("bareos driver: opts.BackupJob is required (a Type=Backup Job to archive the tiered objects)")
	}
	if o.RestoreJob == "" {
		return nil, errors.New("bareos driver: opts.RestoreJob is required (a Type=Restore Job to restore a single file in place)")
	}
	return newBareosDriverWithExec(o, defaultConsoleExec), nil
}

// newBareosDriverWithExec constructs a driver with an injectable executor
// so the driver logic can be tested without a live Bareos.
func newBareosDriverWithExec(o BareosOpts, ex consoleExec) *BareosHsmDriver {
	o.withDefaults()
	return &BareosHsmDriver{opts: o, execcmd: ex}
}

func (d *BareosHsmDriver) Name() string { return "bareos" }

// bareosSend runs one bconsole batch on the standard input of bconsole.
func (d *BareosHsmDriver) bareosSend(ctx context.Context, cmds ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, d.opts.Timeout)
	defer cancel()
	return d.execcmd(ctx, d.opts.BConsolePath, d.opts.BConsoleConfig, d.opts.Director, cmds)
}

// --- locator encoding ----------------------------------------------------------

// The locator must let us round-trip "given a WaveFile in ArchiveWave, find
// its JobId after the backup completes and later restore that exact file by
// name on that JobId." We encode jobid and absolute path:
//
//	"bareos:<jobid>:<url-encoded abs path>"
//
// (JobId is a unique numeric identifier for the job run; the path is what
// we'll pass to `restore ... file=<path>`.)

func bareosLocator(jobid int, path string) string {
	return "bareos:" + strconv.Itoa(jobid) + ":" + url.PathEscape(path)
}

func parseBareosLocator(loc string) (jobid int, path string, ok bool) {
	if !strings.HasPrefix(loc, "bareos:") {
		return 0, "", false
	}
	rest := loc[len("bareos:"):]
	sep := strings.IndexByte(rest, ':')
	if sep <= 0 {
		return 0, "", false
	}
	j, err := strconv.Atoi(rest[:sep])
	if err != nil {
		return 0, "", false
	}
	p, uerr := url.PathUnescape(rest[sep+1:])
	if uerr != nil {
		return 0, "", false
	}
	return j, p, true
}

// --- job report parsing --------------------------------------------------------

// terminationRe matches the job-report line
//
//	Termination:           *Backup completed without errors.
//
// and captures the human-readable tail. The exact wording of the tail varies
// between Bareos versions and job types (Backup vs Restore); we treat any
// tail containing the documented success phrases as OK.
var terminationRe = regexp.MustCompile(`(?im)^\s*Termination:\s+(\S.*)$`)

func extractTermination(out []byte) string {
	m := terminationRe.FindSubmatch(out)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

func isOKTermination(tail string) bool {
	l := strings.ToLower(tail)
	return strings.Contains(l, "backup ok") ||
		strings.Contains(l, "restore ok") ||
		strings.Contains(l, "completed without errors")
}

// lookupJobID scans the `list jobs` portion of the output for an entry whose
// name matches jobname, and returns the largest numeric JobId (the most
// recent run). It accepts both the documented JSON-RPC 2.0 envelope (from
// `.api 2`) and a legacy text/table form as a best-effort fallback. Because
// the JSON path is documented, we prefer it; the text fallback relies on
// the row having the jobid as its first whitespace-separated token and the
// job name appearing on the same line -- the documented `list jobs` table
// format uses a fixed column order that places them near the start.
func lookupJobID(out []byte, jobname string) int {
	// Try the JSON-RPC form first:
	//   {"jsonrpc":"2.0","id":null,"result":{"jobs":[{"jobid":"N","name":"X",...}]}}
	// The response may be preceded by job-report text, so locate the first
	// '{' and unmarshal from there.
	if start := bytes.IndexByte(out, '{'); start >= 0 {
		type resp struct {
			Result *struct {
				Jobs []struct {
					Jobid string `json:"jobid"`
					Name  string `json:"name"`
				} `json:"jobs"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		var r resp
		if err := json.Unmarshal(out[start:], &r); err == nil && r.Result != nil && r.Result.Jobs != nil {
			best := 0
			for _, j := range r.Result.Jobs {
				if j.Name != jobname {
					continue
				}
				if n, err := strconv.Atoi(j.Jobid); err == nil && n > best {
					best = n
				}
			}
			if best > 0 {
				return best
			}
		}
	}
	// Text fallback: the `list jobs` table starts with "| JobId | ..." rows;
	// the job NAME is the "Name" column. Best-effort: any line containing
	// both the name and a plausible leading integer.
	rows := strings.Split(string(out), "\n")
	best := 0
	for _, raw := range rows {
		line := strings.TrimSpace(raw)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		j, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		for _, f := range fields[1:] {
			if f == jobname && j > best {
				best = j
			}
		}
	}
	return best
}

func truncated(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + " …"
}

// --- HsmDriver -----------------------------------------------------------------

func (d *BareosHsmDriver) ArchiveWave(ctx context.Context, files []WaveFile) ([]string, error) {
	if len(files) == 0 {
		return nil, nil
	}
	// Bareos archives whatever its Fileset covers. The daemon passes the
	// tiered objects; we stat them for a sanity check (also surfaces
	// typos in the fileset config as an early error).
	for _, f := range files {
		fi, err := os.Stat(f.Path)
		if err != nil {
			return nil, fmt.Errorf("bareos driver: cannot stat %s: %w", f.Path, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("bareos driver: %s is not a regular file", f.Path)
		}
	}

	// Batch: enable JSON api, run the backup job, wait, drain messages,
	// then query the catalog for the most recent JobId for the job name.
	out, err := d.bareosSend(ctx,
		".api 2",
		"run job="+d.opts.BackupJob,
		"wait",
		"messages",
		"list jobs",
	)
	if err != nil {
		return nil, fmt.Errorf("bareos driver: bconsole run %q: %w (output: %s)", d.opts.BackupJob, err, truncated(out, 400))
	}
	tail := extractTermination(out)
	if tail == "" {
		return nil, fmt.Errorf("bareos driver: no Termination: line in job report: %s", truncated(out, 400))
	}
	if !isOKTermination(tail) {
		return nil, fmt.Errorf("bareos driver: job %q reported: %q (output: %s)", d.opts.BackupJob, tail, truncated(out, 400))
	}
	jobid := lookupJobID(out, d.opts.BackupJob)
	if jobid <= 0 {
		return nil, fmt.Errorf("bareos driver: unable to determine JobId for job %q from list-jobs output: %s",
			d.opts.BackupJob, truncated(out, 400))
	}
	locs := make([]string, len(files))
	for i, f := range files {
		locs[i] = bareosLocator(jobid, f.Path)
	}
	return locs, nil
}

func (d *BareosHsmDriver) Restore(ctx context.Context, locator string, wr io.Writer, size int64) error {
	jobid, path, ok := parseBareosLocator(locator)
	if !ok {
		return fmt.Errorf("bareos driver: malformed locator %q", locator)
	}
	// The daemon hands us `wr` (a writer on the live object path in append
	// mode).  Bareos restores via its file daemon, writing to the original
	// on-disk location (where=<poshsm rootdir>) -- i.e. it will write to
	// the same `path` we already have open.  Since we only need to ensure the
	// job succeeds, we can ignore `wr` after bconsole completes, and close
	// it in the daemon.
	out, err := d.bareosSend(ctx,
		".api 2",
		fmt.Sprintf("restore client=%s jobid=%d file=%s", d.opts.Client, jobid, consoleQuote(path)),
		fmt.Sprintf("restorejob=%s", d.opts.RestoreJob),
		"yes",
		"wait",
		"messages",
	)
	if err != nil {
		return fmt.Errorf("bareos driver: restore jobid=%d of %s: %w (output: %s)", jobid, path, err, truncated(out, 400))
	}
	tail := extractTermination(out)
	if tail == "" || !isOKTermination(tail) {
		return fmt.Errorf("bareos driver: restore did not complete successfully: %q (output: %s)", tail, truncated(out, 400))
	}
	return nil
}

func (d *BareosHsmDriver) Purge(ctx context.Context, locator string) error {
	// Bareos has no per-file delete from a written volume, and issuing a
	// catalog-level `prune` here would be too aggressive (it would remove File
	// records for jobs whose retention has not elapsed) and would not free the
	// physical tape data. Volume recycling is managed by operators (pool
	// recycling / pruning settings, see the "Volume Management" docs)
	// independent of this daemon. Per the HsmDriver contract, purging an
	// unknown locator is not an error, so we satisfy it as a documented no-op.
	_ = locator
	return nil
}

func (d *BareosHsmDriver) Close() error { return nil }

// consoleQuote safely quotes a bconsole argument (see the `configure add`
// docs for values containing spaces/quotes).  We emit values verbatim when
// they are safe; otherwise we double-quote and double any inner quotes.
func consoleQuote(v string) string {
	if v == "" {
		return `""`
	}
	if !strings.ContainsAny(v, " \t\"'`") && !strings.HasPrefix(v, "-") {
		return v
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '"':
			b.WriteString(`""`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
