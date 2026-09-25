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
	"path/filepath"
	"strings"
	"time"
)

// IBM Storage Protect (TSM) 8.1+ integration, grounded in the DAPI (Data
// Application Programming Interface) supplied by the 8.1.27.1 client
// installed under /opt/tivoli/tsm/client/api (headers under
// .../bin64/sample, library libApiTSM64.so). The daemon's pure-Go build
// cannot link the DAPI, so the C helper `tsmapi` (hsmtools/tsmapi) is the
// process boundary: it runs the DAPI flow (signon -> send/get/delete/query)
// and speaks NDJSON over stdio, one response line per request.
//
// Protocol (request -> response, exactly one line each, \n framed):
//
//	{"op":"signon","node":"N","owner":"O","clientdir":"/cd","dsmopt":"...","options":"...","fs":"/root"}
//	    -> {"ok":true,"op":"signon","server":"..." ,"sv":"8.1.27.1"}
//	    -> {"ok":false,"op":"signon","rc":N,"msg":"..."}
//
//	{"op":"send","fs":"/root","hl":"a/b","ll":"c.dat","path":"/abs/live"}
//	    -> {"ok":true,"op":"send"}                     // file sent + committed
//	    -> {"ok":false,"op":"send","rc":N,"msg":"..."} // txn aborted
//
//	{"op":"get","fs":"/root","hl":"a/b","ll":"c.dat","path":"/abs/live"}
//	    -> {"ok":true,"op":"get","found":false}        // no matching active object
//	    -> {"ok":true,"op":"get","found":true,"bytes":N,"tmp":"/abs/live.tsmpartial"}
//	    -> {"ok":false,"op":"get","rc":N,"msg":"..."}
//
//	{"op":"delete","fs":"/root","hl":"a/b","ll":"c.dat"}
//	    -> {"ok":true,"op":"delete","deleted":0}       // idempotent: not found
//	    -> {"ok":true,"op":"delete","deleted":N}
//	    -> {"ok":false,"op":"delete","rc":N,"msg":"..."}
//
//	{"op":"query","fs":"/root","hl":"a/b","ll":"c.dat"}
//	    -> {"ok":true,"op":"query","objs":[{"hi":H,"lo":L,"size":S,"active":1}...]}
//
//	{"op":"ping"}   -> {"ok":true,"op":"ping"}
//	{"op":"quit"}   -> {"ok":true,"op":"quit"}  (helper exits)
//
// The helper's DAPI session (dsmSetUp/dsmInitEx) is per-process: a batch
// that performs sends must start with a `signon` line, and the same
// constraint applies to `get`/`delete`/`query`. The driver therefore
// always runs each HsmDriver operation as a single helper batch:
// [signon, op, quit]. This keeps the helper stateless between daemon calls
// (no long-lived process to leak when a daemon restarts mid-pass) at the
// cost of one dsmInitEx per HsmDriver call, which is acceptable for
// tape-class transfer rates.
//
// DAPI object coordinates follow dsmObjName: fs (filespace; the daemon's
// absolute posix rootdir so the hl/ll decomposition is stable), hl
// (high-level: the parent directory chain under the filespace), ll
// (low-level: the leaf name), objType=DSM_OBJ_FILE. Name limits enforced
// before the network call: ll <= 255 bytes, hl <= 1023 bytes
// (DSM_MAX_LL_LENGTH / DSM_MAX_HL_LENGTH are 256 / 1024 including NUL).
//
// Operator pre-configuration (DSAPI 8.1+ "Application" registration),
// required by the helper but NOT created by the driver (safety), in
// <clientdir>:
//
//   - dsm.sys with a CommServer matching the Storage Protect server for
//     this node.
//   - dsm.opt with the client options (directory, management policies,
//     etc.). v1 deliberately does NOT override the mgmt class per file.
//   - dsmkey (or an equivalent keyring) holding the node password, so the
//     driver can sign on with a NULL password (keyring lookup).
//   - The filespace registered on the server and authorized by the
//     management class in use.
//
// Why a C helper instead of shelling to dsmc: the DAPI 8.1 SDK installed
// here ships only the C API and samples (no dsmc CLI), and the DAPI's
// per-file transaction model (dsmBeginTxn / dsmSendObj / dsmSendData /
// dsmEndSendObjEx / dsmEndTxn) is the documented way to batch one file
// atomically. The helper is small, stateless across HsmDriver calls, and
// speaks the same NDJSON dialect the driver's fake-runner tests replay.

// TsmOpts is the configuration surface for a TSM-backed HsmDriver.
type TsmOpts struct {
	// HelperPath is the absolute path (or PATH-resolved name) of the
	// `tsmapi` C helper. Defaults to "tsmapi" on $PATH (honours TSM_HELPER
	// as an override).
	HelperPath string

	// Node is the TSM client node name to sign on as. Required.
	Node string

	// Owner is the owner name for dsmInitEx; defaults to Node.
	Owner string

	// Filespace is the TSM filespace under which hl/ll are scoped. This is
	// the posix rootdir (absolute) so the hl/ll decomposition has a stable
	// anchor. If empty, NewTsmDriver uses rootdir.
	Filespace string

	// ClientDir is the TSM client configuration directory holding dsm.sys,
	// dsm.opt and (optionally) dsmkey / NLS catalogs. The helper opens this
	// directory as `dsmiDir` and `dsmiLog`, so the daemon user must own
	// write permission here. Defaults to /opt/tivoli/tsm/client/ba/bin (the
	// standard dsmc client dir, NOT the DAPI-SDK lib dir under client/api/,
	// which never holds dsm.sys/dsm.opt).
	ClientDir string

	// DsmOpt is the options file to pass to dsmSetUp (as dsmiConfig). The
	// dsmSetUp(3) call does NOT auto-discover dsm.opt from dsmiDir; without
	// this (or an explicit --tsm-options), signon fails with
	// DSM_RC_NO_OPT_FILE (406). Auto-derived to <ClientDir>/dsm.opt when
	// empty.
	DsmOpt string

	// Options is the inline option string to pass to dsmInitEx. Optional.
	Options string

	// TmpDir is where the driver stages metadata companion payloads
	// before sending them (the helper's `send` reads a real file).
	// Defaults to os.TempDir(). Created on demand; the driver removes
	// the staging file after each successful wave.
	TmpDir string

	// Timeout bounds one helper batch (signon + op + quit). The daemon's
	// overall pass timeout is what actually bounds a long restore.
	// Default: 30m.
	Timeout time.Duration
}

const (
	tsmMaxLLBytes = 255
	tsmMaxHLBytes = 1023
)

func (o *TsmOpts) withDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Minute
	}
	if o.ClientDir == "" {
		o.ClientDir = "/opt/tivoli/tsm/client/ba/bin"
	}
	if o.Owner == "" {
		o.Owner = o.Node
	}
	if o.DsmOpt == "" {
		o.DsmOpt = filepath.Join(o.ClientDir, "dsm.opt")
	}
}

// TsmHsmDriver satisfies HsmDriver by driving the `tsmapi` NDJSON protocol.
// The driver is injectable: `run` is the process-boundary, and tests can
// replace it with a fake that replays responses for the command batches it
// observes.
type TsmHsmDriver struct {
	opts TsmOpts
	run  tsmRun
	// metaStaging holds the on-disk paths of metadata companion payloads
	// staged for the in-flight ArchiveWave. It is cleared after the wave
	// completes (success or failure). The driver is used by a single
	// daemon at a time, so no locking is required.
	metaStaging []string
}

var _ HsmDriver = (*TsmHsmDriver)(nil)

// SingleWave reports false: the TSM helper is transactional per file, so
// many 256-file waves run identically (each file gets its own DAPI txn);
// lumping the whole due set into one helper batch yields no benefit.
func (*TsmHsmDriver) SingleWave() bool { return false }

// tsmRun executes one helper process: writes the request batch (one NDJSON
// line each) to stdin, reads the combined stdout+stderr until EOF, and
// returns the raw output plus the process error (if any).
type tsmRun func(ctx context.Context, helperPath string, lines []string) ([]byte, error)

func defaultTsmRun(ctx context.Context, helperPath string, lines []string) ([]byte, error) {
	if helperPath == "" {
		helperPath = "tsmapi"
		if env := os.Getenv("TSM_HELPER"); env != "" {
			helperPath = env
		}
	}
	var req bytes.Buffer
	for i, l := range lines {
		if i > 0 {
			req.WriteByte('\n')
		}
		req.WriteString(l)
	}
	req.WriteByte('\n')
	cmd := exec.CommandContext(ctx, helperPath)
	cmd.Stdin = &req
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

// NewTsmDriver validates opts and returns a TsmHsmDriver. rootdir is the
// daemon's object root (absolute) and is used as the TSM filespace when
// o.Filespace is not set. It must not be empty so the hl/ll decomposition
// is stable across passes.
func NewTsmDriver(o TsmOpts, rootdir string) (*TsmHsmDriver, error) {
	o.withDefaults()
	if o.Node == "" {
		return nil, errors.New("tsm driver: opts.Node is required (the TSM client node name)")
	}
	if rootdir == "" {
		return nil, errors.New("tsm driver: rootdir is required (absolute posix object root; used as the TSM filespace)")
	}
	fs := o.Filespace
	if fs == "" {
		fs = rootdir
	}
	if !strings.HasPrefix(fs, "/") {
		return nil, fmt.Errorf("tsm driver: filespace %q must be an absolute path (DSAPI fs is the posix rootdir)", fs)
	}
	o.Filespace = fs
	return newTsmDriverWithRun(o, defaultTsmRun), nil
}

// newTsmDriverWithRun constructs a driver with an injectable runner so the
// driver logic can be tested without a live TSM server.
func newTsmDriverWithRun(o TsmOpts, r tsmRun) *TsmHsmDriver {
	o.withDefaults()
	return &TsmHsmDriver{opts: o, run: r}
}

// --- NDJSON client ------------------------------------------------------------

// tsmResp is one helper response line. Only the fields relevant to the
// specific op are populated; the rest are zero.
type tsmResp struct {
	OK      bool   `json:"ok"`
	Op      string `json:"op"`
	RC      int    `json:"rc"`
	Msg     string `json:"msg"`
	Found   *bool  `json:"found"`   // get: false means no active object
	Deleted *int   `json:"deleted"` // delete: how many objects removed
	Server  string `json:"server"`
	Sv      string `json:"sv"`
	Bytes   int64  `json:"bytes"` // get: bytes restored (informational)
	Tmp     string `json:"tmp"`   // get: restored-to path (informational)
	Objs    []tsmQ `json:"objs"`  // query: object listing
}

type tsmQ struct {
	Hi     uint32 `json:"hi"`
	Lo     uint32 `json:"lo"`
	Size   int64  `json:"size"`
	Active int    `json:"active"`
}

// tsmBatch runs one helper process with the given request lines and returns
// the last response line (the response to the operation of interest). The
// helper is synchronous and replies line-for-line in order, so the final
// JSON line in the stdout buffer is the last operation result. Callers
// whose batch contains MULTIPLE operations (e.g. ArchiveWave with metadata
// companions) must additionally run checkAllOK on the raw output, because
// a mid-batch failure would be masked by a successful final line.
func (d *TsmHsmDriver) tsmBatch(ctx context.Context, lines []string) (*tsmResp, []byte, error) {
	out, err := d.run(ctx, d.opts.HelperPath, lines)
	if err != nil {
		return nil, out, fmt.Errorf("tsm driver: helper %s: %w (output: %s)", d.opts.HelperPath, err, truncated(out, 400))
	}
	line := lastJSONLine(out)
	var r tsmResp
	if e := json.Unmarshal(line, &r); e != nil {
		return nil, out, fmt.Errorf("tsm driver: malformed helper response %q: %w", truncate(string(line), 200), e)
	}
	return &r, out, nil
}

// anyLineFailed reports whether any JSON response line in out carries
// "ok":false. Lines that are not JSON (DAPI diagnostics) are ignored.
func anyLineFailed(out []byte) bool {
	for _, l := range lastJSONLines(out, 0) {
		var r tsmResp
		if json.Unmarshal(l, &r) == nil && !r.OK {
			return true
		}
	}
	return false
}

// firstFailedReason returns the first "msg" (or "op") found on a failing
// response line, for a concise error message.
func firstFailedReason(out []byte) string {
	for _, l := range lastJSONLines(out, 0) {
		var r tsmResp
		if json.Unmarshal(l, &r) == nil && !r.OK {
			if r.Msg != "" {
				return r.Msg
			}
			return "op=" + r.Op
		}
	}
	return "unknown helper failure"
}

// lastJSONLines returns every line in out that parses as a JSON object.
// n=0 means all.
func lastJSONLines(out []byte, n int) [][]byte {
	lines := bytes.Split(out, []byte("\n"))
	var res [][]byte
	for i := len(lines) - 1; i >= 0 && (n == 0 || len(res) < n); i-- {
		ln := bytes.TrimSpace(lines[i])
		if len(ln) >= 2 && ln[0] == '{' && ln[len(ln)-1] == '}' {
			res = append(res, ln)
		}
	}
	// reverse so the result reads in the original order
	for i, j := 0, len(res)-1; i < j; i, j = i+1, j-1 {
		res[i], res[j] = res[j], res[i]
	}
	return res
}

// tsmSignon builds the signon request line for a batch.
func (d *TsmHsmDriver) tsmSignon() string {
	b, _ := json.Marshal(map[string]string{
		"op":        "signon",
		"node":      d.opts.Node,
		"owner":     d.opts.Owner,
		"clientdir": d.opts.ClientDir,
		"dsmopt":    d.opts.DsmOpt,
		"options":   d.opts.Options,
		"fs":        d.opts.Filespace,
	})
	return string(b)
}

// lastJSONLine returns the last line of out that parses as a complete JSON
// object (leading/trailing whitespace tolerated). DAPI diagnostics go to
// the helper's stderr (which is captured alongside stdout by the runner),
// so the operation response is always the final line.
func lastJSONLine(out []byte) []byte {
	lines := bytes.Split(out, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		ln := bytes.TrimSpace(lines[i])
		if len(ln) >= 2 && ln[0] == '{' && ln[len(ln)-1] == '}' {
			return ln
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + " …"
}

// --- locator encoding ----------------------------------------------------------

// The locator must survive a round-trip: given a WaveFile.Path under the
// filespace, we encode (fs, hl, ll) as percent-escaped colon-separated
// fields, so every pathologically-named object round-trips. url.PathEscape
// is unsuitable because it does NOT escape ':' (a field separator), so we
// roll our own minimal percent-encoding that also escapes ':' and keeps
// the encoding reversible via url.PathUnescape (which correctly decodes
// %3A back to ':'):
//
//	"tsm:<fs>:<hl>:<ll>"
const tsmLocatorPrefix = "tsm:"

// tsmFieldEscape percent-encodes a locator field, escaping every byte that
// is not an unreserved character (RFC 3986) plus '/', so field boundaries
// (':') cannot be confused with path separators inside a field.
func tsmFieldEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || c == '/':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func tsmLocator(fs, hl, ll string) string {
	return tsmLocatorPrefix + tsmFieldEscape(fs) + ":" + tsmFieldEscape(hl) + ":" + tsmFieldEscape(ll)
}

func parseTsmLocator(loc string) (fs, hl, ll string, ok bool) {
	if !strings.HasPrefix(loc, tsmLocatorPrefix) {
		return "", "", "", false
	}
	rest := loc[len(tsmLocatorPrefix):]
	raw, ok := splitEscapedColon(rest, 2)
	if !ok || len(raw) != 3 {
		return "", "", "", false
	}
	f, e1 := url.PathUnescape(raw[0])
	h, e2 := url.PathUnescape(raw[1])
	l, e3 := url.PathUnescape(raw[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return "", "", "", false
	}
	if l == "" || !strings.HasPrefix(f, "/") {
		return "", "", "", false
	}
	return f, h, l, true
}

// splitEscapedColon splits s on the first n colon characters that are not
// part of a %XX escape, returning the n+1 un-escaped pieces (escapes
// intact for the caller to PathUnescape).
func splitEscapedColon(s string, n int) ([]string, bool) {
	pieces := make([]string, 0, n+1)
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) && isHex(s[i+1:i+3]) {
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			cur.WriteByte(s[i+2])
			i += 2
			continue
		}
		if c == ':' && len(pieces) < n {
			pieces = append(pieces, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if len(pieces) != n {
		return nil, false
	}
	pieces = append(pieces, cur.String())
	return pieces, true
}

func isHex(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// decomposePath maps an absolute path under the filespace to (hl, ll).
// A live object lives at <fs>/<hl>/<ll>; with hl == "" the object sits at
// the top of the filespace and only ll is meaningful.
func decomposePath(fs, abs string) (hl, ll string, err error) {
	if !strings.HasPrefix(abs, fs+"/") {
		return "", "", fmt.Errorf("tsm driver: path %q is not under filespace %q (the daemon must pass paths rooted at the filespace)", abs, fs)
	}
	rel := strings.TrimPrefix(abs, fs+"/")
	if rel == "" {
		return "", "", fmt.Errorf("tsm driver: path %q is the filespace itself; a filespace is a directory, not an object", abs)
	}
	idx := strings.LastIndexByte(rel, '/')
	if idx < 0 {
		hl, ll = "", rel
	} else {
		hl, ll = rel[:idx], rel[idx+1:]
		if ll == "" {
			return "", "", fmt.Errorf("tsm driver: path %q has an empty low-level name", abs)
		}
	}
	if len(ll) > tsmMaxLLBytes {
		return "", "", fmt.Errorf("tsm driver: ll %q is %d bytes, exceeds TSM limit of %d", ll, len(ll), tsmMaxLLBytes)
	}
	if hl != "" && len(hl) > tsmMaxHLBytes {
		return "", "", fmt.Errorf("tsm driver: hl %q is %d bytes, exceeds TSM limit of %d", hl, len(hl), tsmMaxHLBytes)
	}
	return hl, ll, nil
}

// --- HsmDriver -----------------------------------------------------------------

func (d *TsmHsmDriver) Name() string { return "tsm" }

func (d *TsmHsmDriver) ArchiveWave(ctx context.Context, files []WaveFile) ([]string, error) {
	if len(files) == 0 {
		return nil, nil
	}
	// Pre-flight: every file present and regular. A vanished file would
	// otherwise make the helper's per-file txn fail late (after N-1
	// successful sends), which is more expensive to diagnose than the
	// immediate error we surface here.
	for _, f := range files {
		fi, err := os.Stat(f.Path)
		if err != nil {
			return nil, fmt.Errorf("tsm driver: cannot stat %s: %w", f.Path, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("tsm driver: %s is not a regular file", f.Path)
		}
	}

	locs := make([]string, len(files))
	lines := []string{d.tsmSignon()}
	for i, f := range files {
		hl, ll, err := decomposePath(d.opts.Filespace, f.Path)
		if err != nil {
			return nil, err
		}
		req, _ := json.Marshal(map[string]string{
			"op":   "send",
			"fs":   d.opts.Filespace,
			"hl":   hl,
			"ll":   ll,
			"path": f.Path,
		})
		lines = append(lines, string(req))
		locs[i] = tsmLocator(d.opts.Filespace, hl, ll)
	}
	// Metadata companions ride in the SAME batch (see header doc): one
	// extra `send` per file with a WaveFile.Meta snapshot.
	if err := d.archiveMetaCompanions(files, &lines); err != nil {
		d.removeMetaStaging()
		return nil, err
	}
	lines = append(lines, `{"op":"quit"}`)

	resp, out, err := d.tsmBatch(ctx, lines)
	if err != nil {
		d.removeMetaStaging()
		return nil, err
	}
	if !resp.OK || anyLineFailed(out) {
		d.removeMetaStaging()
		return nil, fmt.Errorf("tsm driver: helper batch failed: %s (output: %s)", firstFailedReason(out), truncated(out, 400))
	}
	d.removeMetaStaging()
	return locs, nil
}

// archiveMetaCompanions appends a `send` request line for every file that
// carries a WaveFile.Meta snapshot, staging the payload to a real file the
// helper's `send` can read (the helper reads `path`, it cannot take an
// inline byte string). The companion is a normal TSM object: it shares the
// data object's high-level name (hl) and gets the deterministic low-level
// name from MetaName(hl, ll), so archive / fetch / purge all derive it
// from the same (hl, ll) without any persisted mapping.
func (d *TsmHsmDriver) archiveMetaCompanions(files []WaveFile, lines *[]string) error {
	for _, f := range files {
		if len(f.Meta) == 0 {
			continue
		}
		hl, ll, err := decomposePath(d.opts.Filespace, f.Path)
		if err != nil {
			return err
		}
		metaLL := MetaName(hl, ll)
		staged, err := d.stageMetaPayload(metaLL, f.Meta)
		if err != nil {
			return err
		}
		d.metaStaging = append(d.metaStaging, staged)
		req, _ := json.Marshal(map[string]string{
			"op":   "send",
			"fs":   d.opts.Filespace,
			"hl":   hl,
			"ll":   metaLL,
			"path": staged,
		})
		*lines = append(*lines, string(req))
	}
	return nil
}

// stageMetaPayload writes the metadata bytes to a uniquely-named file in
// the driver TmpDir and returns its path.
func (d *TsmHsmDriver) stageMetaPayload(name string, payload []byte) (string, error) {
	dir := d.opts.TmpDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("tsm driver: mkdir %q: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, "hsm-meta-*.json")
	if err != nil {
		return "", fmt.Errorf("tsm driver: create temp %q: %w", dir, err)
	}
	path := f.Name()
	if _, err := f.Write(payload); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("tsm driver: write %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("tsm driver: close %q: %w", path, err)
	}
	return path, nil
}

// removeMetaStaging best-effort unlinks the companion staging files for a
// wave (they are transient; on failure they are left for the OS).
func (d *TsmHsmDriver) removeMetaStaging() {
	for _, p := range d.metaStaging {
		_ = os.Remove(p)
	}
	d.metaStaging = nil
}

func (d *TsmHsmDriver) Restore(ctx context.Context, locator string, wr io.Writer, size int64) error {
	fs, hl, ll, ok := parseTsmLocator(locator)
	if !ok {
		return fmt.Errorf("tsm driver: malformed locator %q", locator)
	}
	if fs != d.opts.Filespace {
		return fmt.Errorf("tsm driver: locator filespace %q != driver filespace %q (cross-driver restore is not supported)", fs, d.opts.Filespace)
	}
	livePath := filepath.Join(fs, hl, ll)

	req, _ := json.Marshal(map[string]string{
		"op":   "get",
		"fs":   fs,
		"hl":   hl,
		"ll":   ll,
		"path": livePath,
	})
	lines := []string{d.tsmSignon(), string(req), `{"op":"quit"}`}
	resp, _, err := d.tsmBatch(ctx, lines)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("tsm driver: get %s/%s: %s (rc=%d)", hl, ll, resp.Msg, resp.RC)
	}
	if resp.Found != nil && !*resp.Found {
		return fmt.Errorf("tsm driver: no active TSM object for %s/%s (locator %q)", hl, ll, locator)
	}
	// The helper has already written the restored bytes to <livePath>.tsmpartial;
	// atomically rename onto the live path so concurrent opens resolve to the
	// final contents. (This mirrors how bareos does it: the HSM daemon writes
	// into the original location via its own fd, while we — running the helper
	// as a subprocess — write via the .tsmpartial intermediate. A reader that
	// opened the live path before this rename will be left reading the old
	// inode (which has been unlinked); a reader that opens after will see the
	// restored data. That's the same edge case bareos has on its own fd.)
	partial := livePath + ".tsmpartial"
	if err := os.Rename(partial, livePath); err != nil {
		return fmt.Errorf("tsm driver: rename restore %s -> %s: %w", partial, livePath, err)
	}
	// The daemon still holds `wr` open on the live path. It is responsible
	// for closing it; we must NOT close it here (the descriptor belongs to
	// the daemon, and closing it would break a daemon that expects its own
	// close to be the only one). See RestoreJobs in daemon.go.
	_ = wr
	return nil
}

func (d *TsmHsmDriver) Purge(ctx context.Context, locator string) error {
	fs, hl, ll, ok := parseTsmLocator(locator)
	if !ok {
		return fmt.Errorf("tsm driver: malformed locator %q", locator)
	}
	if fs != d.opts.Filespace {
		return nil // Not this driver's store; idempotent no-op per contract.
	}
	// Remove the data object AND its metadata companion (deleting both
	// in one sign-on/quit batch; the helper treats a missing companion
	// as deleted:0, so this is idempotent even for objects archived
	// before the companion feature existed).
	reqData, _ := json.Marshal(map[string]string{"op": "delete", "fs": fs, "hl": hl, "ll": ll})
	reqMeta, _ := json.Marshal(map[string]string{"op": "delete", "fs": fs, "hl": hl, "ll": MetaName(hl, ll)})
	lines := []string{d.tsmSignon(), string(reqData), string(reqMeta), `{"op":"quit"}`}
	resp, out, err := d.tsmBatch(ctx, lines)
	if err != nil {
		return err
	}
	if !resp.OK || anyLineFailed(out) {
		return fmt.Errorf("tsm driver: delete %s/%s: %s (rc=%d)", hl, ll, firstFailedReason(out), -1)
	}
	return nil
}

// FetchMeta retrieves the metadata companion of the object identified by
// locator, returning its JSON payload. A locator whose object was archived
// without a companion yields an empty payload (not an error): the daemon
// then simply skips the replay. This implements the optional MetaPayload
// interface so the daemon can drive it polymorphically.
func (d *TsmHsmDriver) FetchMeta(ctx context.Context, locator string) ([]byte, error) {
	fs, hl, ll, ok := parseTsmLocator(locator)
	if !ok {
		return nil, fmt.Errorf("tsm driver: malformed locator %q", locator)
	}
	if fs != d.opts.Filespace {
		return nil, nil // not this driver's store
	}
	metaLL := MetaName(hl, ll)
	dir := d.opts.TmpDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tsm driver: mkdir %q: %w", dir, err)
	}
	staged, err := os.CreateTemp(dir, "hsm-meta-rx-*.json")
	if err != nil {
		return nil, fmt.Errorf("tsm driver: create temp: %w", err)
	}
	target := staged.Name()
	staged.Close()
	defer os.Remove(target + ".tsmpartial")

	req, _ := json.Marshal(map[string]string{"op": "get", "fs": fs, "hl": hl, "ll": metaLL, "path": target})
	lines := []string{d.tsmSignon(), string(req), `{"op":"quit"}`}
	resp, _, err := d.tsmBatch(ctx, lines)
	if err != nil {
		return nil, err
	}
	if resp.Found != nil && !*resp.Found {
		return nil, nil // no companion was archived
	}
	if resp.Found == nil && !resp.OK {
		return nil, fmt.Errorf("tsm driver: get metadata companion: %s (rc=%d)", resp.Msg, resp.RC)
	}
	b, err := os.ReadFile(target + ".tsmpartial")
	if err != nil {
		return nil, fmt.Errorf("tsm driver: read restored metadata %q: %w", target, err)
	}
	return b, nil
}

func (d *TsmHsmDriver) Close() error { return nil }
