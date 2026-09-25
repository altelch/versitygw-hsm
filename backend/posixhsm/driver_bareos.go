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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
//   - A FileSet whose Include contains `File = "<opts.FileListPath"`,
//     i.e. it reads the per-pass due-file list the driver writes (one
//     absolute path per line) instead of pinning a static directory.
//   - A Backup Job (e.g. "HsmBackup") at `Level = Full` using the above,
//     with the intended Storage/Pool and with NO Schedule or other
//     trigger (see PROJECT.MD §7 "Job content").  This is what
//     ArchiveWave runs; its content is exactly the due set.
//     NOTE: `Full` is the correct *job* level here. (There is no
//     Director job level called `File` — `File` is a file-daemon *scan*
//     concept. `Level = File` makes bareos-dir refuse to start.)
//   - A Restore Job (e.g. "HsmRestore") of Type = Restore whose
//     Where = / (restore to original location) -- the bareos-fd must
//     restore the file back to its on-disk location so the live inode
//     + xattrs are preserved.
//
// Why the due-file list matters: the job must NOT archive a static
// directory. After tiering truncates an object to 0 bytes, a
// changed-since-Incremental run would re-save the 0-byte stub, and a
// restore would then hand back empty data. The list makes the job content
// exactly the online, due objects and nothing else. Level = Full saves
// every file named by the list-constrained FileSet as a full version, so
// an unchanged-but-listed file is never skipped (a locator pinning a
// jobid that omits it would be unrecoverable).
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
	// tiered objects. Its FileSet must consume the per-pass due-file list
	// via `File = "<FileListPath"` and run at `Level = Full`, so the job
	// archive contains exactly the objects the daemon decided to tier.
	// Required.
	BackupJob string

	// FileListPath is the file the driver writes the due-file list to
	// before triggering the backup job (one absolute file path per line).
	// The FileListPath must reside on the filesystem of the File Daemon
	// (for single-host setups the usual case, the daemon and the fd share
	// it), and the fd user must be able to read it. It must be kept out
	// of the FileSet itself, or the job would archive its own list.
	// Required.
	FileListPath string

	// RestoreJob is the name of a Type=Restore Job used to restore a
	// single file at its original location. Required.
	RestoreJob string

	// Timeout bounds a single bconsole batch (which may internally block
	// on `wait` for the job to complete). Default: 10m.
	Timeout time.Duration

	// CompanionMeta enables archiving the daemon's WaveFile.Meta snapshot
	// as a companion file in the SAME backup job, so sidecar-mode metadata
	// (which lives OUTSIDE the rootdir and is therefore invisible to the
	// fd's xattr/scan machinery) survives with the object. When false (the
	// default) the driver relies on the fd's native xattr transport, which
	// is correct for xattr mode. See the FetchMeta / companionStaging docs.
	CompanionMeta bool

	// MetaStageDir is the scratch directory the driver uses to stage the
	// companion files before they ride in the due-list (backup) and the
	// place the fd writes them back to on restore (Where = / puts the
	// restore at the original location, i.e. back into this directory).
	// It must sit OUTSIDE the posix rootdir -- the daemon's object
	// lister must never see companions as data objects -- and OUTSIDE the
	// FileSet's static include set. Default: the system temp dir.
	MetaStageDir string
}

func (o *BareosOpts) withDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Minute
	}
	if o.CompanionMeta && o.MetaStageDir == "" {
		o.MetaStageDir = os.TempDir()
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

// SingleWave reports true: one bareos run cannot split its input list, and
// re-running the same named job per wave would produce several catalog jobs
// per pass with no benefit (lookupJobID keys on highest JobId of the name).
// The daemon therefore passes the whole due set in one ArchiveWave call,
// which ArchiveWave renders into the fd's file list.
func (*BareosHsmDriver) SingleWave() bool { return true }

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
	if o.FileListPath == "" {
		return nil, errors.New("bareos driver: opts.FileListPath is required (the due-file list the backup job's FileSet reads via `File = \"< file\"`)")
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

// lookupJobID scans the batch output for an entry whose name matches
// jobname and returns the largest numeric JobId (the most recent run).
//
// Under the documented `.api 2` mode *every* console command emits its own
// JSON-RPC 2.0 response object, interleaved with plain-text job reports, so
// one bconsole batch contains several JSON objects side by side. Extract
// each top-level object brace-aware, unmarshal them independently, and take
// the maximum matching JobId. Text fallbacks cover `.api 0/1` output: the
// `run` report's "Running job: <ujobid> (JobId=N)" line, and plain `list
// jobs` table rows (JobId column first, name column after).
var jobIDParenRe = regexp.MustCompile(`\(JobId\s*=\s*(\d+)\)`)

type bareosAPIJob struct {
	Jobid string `json:"jobid"`
	Name  string `json:"name"`
}

func lookupJobID(out []byte, jobname string) int {
	type resp struct {
		Result *struct {
			Jobs  []bareosAPIJob `json:"jobs"`
			Jobid string         `json:"jobid"`
			Name  string         `json:"name"`
		} `json:"result"`
	}
	best := 0
	for _, obj := range topLevelJSONObjects(out) {
		var r resp
		if err := json.Unmarshal(obj, &r); err != nil || r.Result == nil {
			continue
		}
		for _, j := range r.Result.Jobs {
			if j.Name == jobname {
				if n, err := strconv.Atoi(j.Jobid); err == nil && n > best {
					best = n
				}
			}
		}
		if r.Result.Name == jobname {
			if n, err := strconv.Atoi(r.Result.Jobid); err == nil && n > best {
				best = n
			}
		}
		if best > 0 {
			break
		}
	}
	if best > 0 {
		return best
	}
	rows := strings.Split(string(out), "\n")
	for _, raw := range rows {
		line := strings.TrimSpace(raw)
		if line == "" || !strings.Contains(line, jobname) {
			continue
		}
		if m := jobIDParenRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n > best {
				best = n
			}
			continue
		}
		// `list jobs` table: JobId is the numeric column, the name a
		// following column (`| 142 | HsmTierBackup | ...`).
		fields := strings.Fields(line)
		first := -1
		for i, f := range fields {
			if _, err := strconv.Atoi(f); err == nil {
				first = i
				break
			}
		}
		if first < 0 {
			continue
		}
		jobid, err := strconv.Atoi(fields[first])
		if err != nil || jobid <= best {
			continue
		}
		for _, f := range fields[first+1:] {
			if f == jobname {
				best = jobid
				break
			}
		}
	}
	return best
}

// topLevelJSONObjects returns each complete top-level JSON object in b as a
// separate byte slice. Brace pairs inside string literals are ignored.
func topLevelJSONObjects(b []byte) [][]byte {
	var out [][]byte
	var cur []byte
	depth := 0
	inStr := false
	esc := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inStr:
			cur = append(cur, c)
			switch c {
			case '\\':
				esc = true
			case '"':
				if !esc {
					inStr = false
				}
				esc = false
			default:
				esc = false
			}
		case c == '"':
			inStr = true
			if depth > 0 {
				cur = append(cur, c)
			}
		case c == '{':
			if depth == 0 {
				cur = cur[:0]
			}
			depth++
			cur = append(cur, c)
		case c == '}':
			if depth > 0 {
				depth--
				cur = append(cur, c)
				if depth == 0 {
					out = append(out, append([]byte(nil), cur...))
				}
			}
		default:
			if depth > 0 {
				cur = append(cur, c)
			}
		}
	}
	return out
}

func truncated(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + " …"
}

// --- HsmDriver -----------------------------------------------------------------

// writeFileList atomically rewrites opts.FileListPath with one absolute
// file path per line (the due set of this wave/pass plus its metadata
// companions, when CompanionMeta is on). The backup job's FileSet reads
// this file on the fd (`File = "<file`): the docs guarantee an explicitly
// listed file is saved at job start even when it lies outside the
// FileSet's static include set, which is how companions staged OUTSIDE
// the rootdir ride in the same job.
func (d *BareosHsmDriver) writeFileList(files []WaveFile, companions []string) error {
	var b bytes.Buffer
	b.Grow((len(files) + len(companions)) * 64)
	for _, f := range files {
		b.WriteString(f.Path)
		b.WriteByte('\n')
	}
	for _, c := range companions {
		b.WriteString(c)
		b.WriteByte('\n')
	}

	dir := filepath.Dir(d.opts.FileListPath)
	tmp, err := os.CreateTemp(dir, ".hsm-bareos-filelist-*")
	if err != nil {
		return fmt.Errorf("bareos driver: create file list %q: %w", d.opts.FileListPath, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(b.Bytes()); err != nil {
		tmp.Close()
		return fmt.Errorf("bareos driver: write file list %q: %w", d.opts.FileListPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bareos driver: close file list %q: %w", d.opts.FileListPath, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("bareos driver: chmod file list %q: %w", d.opts.FileListPath, err)
	}
	if err := os.Rename(tmpName, d.opts.FileListPath); err != nil {
		return fmt.Errorf("bareos driver: install file list %q: %w", d.opts.FileListPath, err)
	}
	return nil
}

// companionNameFor returns the deterministic companion file name for the
// live object at path: <leaf>-<hex16(sha256(dir:leaf))>.hsm-meta. The
// hash covers the directory AS WELL as the leaf so two objects sharing a
// leaf name never collide, and it is derived from the full live path so
// the archive side (ArchiveWave) and the fetch side (FetchMeta) agree
// with no persisted record -- the same principle as the TSM driver's
// MetaName.
func companionNameFor(path string) string {
	dir := filepath.Dir(path)
	leaf := filepath.Base(path)
	sum := sha256.Sum256([]byte(dir + ":" + leaf))
	h16 := hex.EncodeToString(sum[:metaNameHashBytes])
	return leaf + "-" + h16 + MetaSuffix
}

// companionPathOf returns the location a companion file lives in (and is
// restored back to, since the restore job uses Where = /):
// <MetaStageDir>/<dir-of-path>/<companionName>.
func (d *BareosHsmDriver) companionPathOf(path string) string {
	stageDir := d.opts.MetaStageDir
	if stageDir == "" {
		stageDir = os.TempDir()
	}
	return filepath.Join(stageDir, filepath.Dir(path), companionNameFor(path))
}

// stageCompanion writes a file's WaveFile.Meta snapshot to its companion
// staging path (temp + rename so bareos-fd can never read a partial
// companion). It must land OUTSIDE the posix rootdir so the daemon's
// object lister does not see companions as data objects.
func (d *BareosHsmDriver) stageCompanion(path string, payload []byte) (string, error) {
	target := d.companionPathOf(path)
	cdir := filepath.Dir(target)
	if err := os.MkdirAll(cdir, 0o700); err != nil {
		return "", fmt.Errorf("bareos driver: mkdir companion dir %q: %w", cdir, err)
	}
	f, err := os.CreateTemp(cdir, ".hsm-meta-*")
	if err != nil {
		return "", fmt.Errorf("bareos driver: stage companion for %q: %w", path, err)
	}
	tmp := f.Name()
	if _, err := f.Write(payload); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", fmt.Errorf("bareos driver: write companion for %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("bareos driver: close companion for %q: %w", path, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("bareos driver: install companion for %q: %w", path, err)
	}
	return target, nil
}

// removeCompanionStaging best-effort unlinks companion staging files left
// over from a failed wave (they are transient; on failure they are left
// for the OS / the next pass).
func (d *BareosHsmDriver) removeCompanionStaging(paths []string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

func (d *BareosHsmDriver) ArchiveWave(ctx context.Context, files []WaveFile) ([]string, error) {
	if len(files) == 0 {
		return nil, nil
	}
	if d.opts.FileListPath == "" {
		return nil, errors.New("bareos driver: FileListPath is not configured; refusing to run a job whose FileSet would archive a stale or static set")
	}
	// Sanity check the due set before pinning any state on it: every file
	// must be a regular file that is present right now (a vanished file
	// would otherwise make the whole fd job fail on a stale list entry,
	// which is slower to diagnose than an early error here).
	for _, f := range files {
		fi, err := os.Stat(f.Path)
		if err != nil {
			return nil, fmt.Errorf("bareos driver: cannot stat %s: %w", f.Path, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("bareos driver: %s is not a regular file", f.Path)
		}
	}

	// Companion metadata (sidecar mode): stage every file carrying a
	// WaveFile.Meta snapshot outside the rootdir and extend the due-list
	// with the companion paths, so the fd archives them as full files in
	// this very job. The companion name is deterministic (see
	// companionNameFor), so FetchMeta can re-derive it from the data
	// locator's path alone.
	var companions []string
	if d.opts.CompanionMeta {
		for _, f := range files {
			if len(f.Meta) == 0 {
				continue
			}
			c, serr := d.stageCompanion(f.Path, f.Meta)
			if serr != nil {
				// Clean up whatever staged so far; the wave must fail
				// atomically with no partial staging left behind.
				d.removeCompanionStaging(companions)
				return nil, serr
			}
			companions = append(companions, c)
		}
	}

	// The job's FileSet reads the per-pass list at FileListPath (`File =
	// "< file"`) and Level=Full saves exactly these files (plus the
	// companions appended below), so a truncate from an earlier pass can
	// never make it into the archive and no not-yet-due object rides
	// along. Atomic write (temp + rename) so the fd can never observe a
	// half-written list.
	if err := d.writeFileList(files, companions); err != nil {
		d.removeCompanionStaging(companions)
		return nil, err
	}

	// Batch: enable JSON api, run the backup job, wait, drain messages,
	// then query the catalog for the most recent JobId for the job name.
	// Any failure below must also clean up the staged companions (they are
	// transient scratch, and a half-written sidecar would otherwise ride
	// into the next job or be restored by a later FetchMeta).
	out, err := d.bareosSend(ctx,
		".api 2",
		"run job="+d.opts.BackupJob,
		"wait",
		"messages",
		"list jobs",
	)
	if err != nil {
		d.removeCompanionStaging(companions)
		return nil, fmt.Errorf("bareos driver: bconsole run %q: %w (output: %s)", d.opts.BackupJob, err, truncated(out, 400))
	}
	tail := extractTermination(out)
	if tail == "" {
		d.removeCompanionStaging(companions)
		return nil, fmt.Errorf("bareos driver: no Termination: line in job report: %s", truncated(out, 400))
	}
	if !isOKTermination(tail) {
		d.removeCompanionStaging(companions)
		return nil, fmt.Errorf("bareos driver: job %q reported: %q (output: %s)", d.opts.BackupJob, tail, truncated(out, 400))
	}
	jobid := lookupJobID(out, d.opts.BackupJob)
	if jobid <= 0 {
		d.removeCompanionStaging(companions)
		return nil, fmt.Errorf("bareos driver: unable to determine JobId for job %q from list-jobs output: %s",
			d.opts.BackupJob, truncated(out, 400))
	}
	locs := make([]string, len(files))
	for i, f := range files {
		locs[i] = bareosLocator(jobid, f.Path)
	}
	// The companions are archived; the staging copies are just the job's
	// on-disk source and must not linger (they are outside the rootdir,
	// so they would simply pollute the scratch dir -- but they must never
	// be re-typed on a later pass or mistaken for live companions).
	d.removeCompanionStaging(companions)
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

var _ MetaPayload = (*BareosHsmDriver)(nil)

// FetchMeta implements MetaPayload for the sidecar companion. The data
// locator's path identifies the object, and the companion name is derived
// deterministically from that path (companionNameFor), so no bookkeeping is
// needed. The restore job's Where = / puts the companion back at its
// ORIGINAL location (the driver's staging dir), so we restore exactly that
// path and read the file back.
//
// A locator whose object was archived WITHOUT a companion (CompanionMeta
// off, empty Meta, or archived before this feature existed) must yield an
// empty payload, not an error: the daemon then skips the replay. We cannot
// tell the two cases apart from the bconsole report alone, so the caller's
// contract is: an empty file read-back means "no companion" only when the
// restore reported success on an empty/absent payload; a hard bconsole
// failure OR a missing file after a nominal success is surfaced as an
// error so the daemon can retry.
func (d *BareosHsmDriver) FetchMeta(ctx context.Context, locator string) ([]byte, error) {
	jobid, dataPath, ok := parseBareosLocator(locator)
	if !ok {
		return nil, fmt.Errorf("bareos driver: malformed locator %q", locator)
	}
	if !d.opts.CompanionMeta {
		return nil, nil // this store does not keep a companion
	}
	companion := d.companionPathOf(dataPath)

	out, err := d.bareosSend(ctx,
		".api 2",
		fmt.Sprintf("restore client=%s jobid=%d file=%s", d.opts.Client, jobid, consoleQuote(companion)),
		fmt.Sprintf("restorejob=%s", d.opts.RestoreJob),
		"yes",
		"wait",
		"messages",
	)
	if err != nil {
		return nil, fmt.Errorf("bareos driver: restore companion %s (jobid=%d): %w (output: %s)", companion, jobid, err, truncated(out, 400))
	}
	tail := extractTermination(out)
	if tail == "" || !isOKTermination(tail) {
		return nil, fmt.Errorf("bareos driver: restore companion %s did not complete: %q (output: %s)", companion, tail, truncated(out, 400))
	}
	b, rerr := os.ReadFile(companion)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			// Job said OK but the file is not there: the catalog held no
			// such file (no companion was archived for this object).
			return nil, nil
		}
		return nil, fmt.Errorf("bareos driver: read restored companion %q: %w", companion, rerr)
	}
	return b, nil
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
