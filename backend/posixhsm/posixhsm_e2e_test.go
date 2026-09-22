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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/backend/posixhsm/queue"
	"github.com/versity/versitygw/backend/posixhsm/state"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// setupBackend builds a real *posix.Posix backed by xattrs on a tempdir and
// wraps it with PosixHsm so the tests exercise the actual posix code paths
// (put/get/list/head/copy) alongside the HSM overrides.
func setupBackend(t *testing.T) (*PosixHsm, string, func()) {
	t.Helper()
	h, rootdir, _, cleanup := setupBackendStore(t, false)
	return h, rootdir, cleanup
}

// setupBackendStore builds the same stack; with sidecar=true the
// representation is the split-file one (metadata in <sidecar>/<bucket>/<key>/
// meta/ files, nothing on the object inode). The second return value of the
// daemonStorer — when sidecar — is a storer addressing the SAME sidecar dir
// the way vgwtaped does (absolute object paths via PathRelStorer), so tests
// can simulate daemon-side state writes with the real cross-process
// addressing.
func setupBackendStore(t *testing.T, sidecar bool) (*PosixHsm, string, meta.MetadataStorer, func()) {
	t.Helper()
	base := t.TempDir()
	rootdir := filepath.Join(base, "root")
	state_dir := filepath.Join(base, "state")

	if err := os.MkdirAll(rootdir, 0o755); err != nil {
		t.Fatalf("mkdir rootdir: %v", err)
	}
	// Note: posix.New chdirs into rootdir by default; that's the state in
	// which the gateway runs too.

	var ms meta.MetadataStorer = meta.XattrMeta{}
	opts := posix.PosixOpts{
		NewDirPerm:  0o755,
		NewFilePerm: 0o644,
		Concurrency: 50,
	}
	var daemonStorer meta.MetadataStorer
	if sidecar {
		sd := filepath.Join(base, "sidecar")
		if err := os.MkdirAll(sd, 0o755); err != nil {
			t.Fatalf("mkdir sidecar: %v", err)
		}
		sc, err := meta.NewSideCar(sd)
		if err != nil {
			t.Fatalf("new sidecar: %v", err)
		}
		ms = sc
		opts.SideCarDir = sd
		daemonStorer = state.NewPathRelStorer(sc, rootdir)
	}
	p, err := posix.New(rootdir, ms, opts)
	if err != nil {
		// posix.New fails when the FS does not support xattr. On CI
		// (macOS APFS, tmpfs, some btrfs configs) this can happen; the
		// HSM tests are posix-only and are expected to run on Linux
		// where xattrs are standard.
		t.Skipf("posix.New requires xattr support: %v", err)
	}
	q, err := queue.New(state_dir)
	if err != nil {
		t.Fatalf("queue.New: %v", err)
	}
	h, err := New(p, ms, q, PosixHsmOpts{StateDir: state_dir, Glacier: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(base)
	}
	return h, rootdir, daemonStorer, cleanup
}

// putObject creates bucket + object on the wrapped backend, mirroring the
// real S3 flow but skipping HTTP/auth. For the posix backend a directory at
// the root is a bucket, so we create it directly.
func putObject(t *testing.T, h *PosixHsm, rootdir, bucket, key string, body []byte) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(rootdir, bucket), 0o755); err != nil {
		t.Fatalf("mkdir bucket: %v", err)
	}
	reader := bytes.NewReader(body)
	_, err := h.PutObject(ctxT(), s3response.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          reader,
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String("application/octet-stream"),
	})
	if err != nil {
		t.Fatalf("put object: %v", err)
	}
}

func ctxT() context.Context { return context.Background() }

func TestGlacierOfflineSemantics(t *testing.T) {
	h, rootdir, cleanup := setupBackend(t)
	defer cleanup()

	const (
		bucket = "glacier-bucket"
		key    = "object.bin"
	)
	body := []byte("glacier-test-payload")
	putObject(t, h, rootdir, bucket, key, body)

	// --- pre-tier: STANDARD, normal get ---
	hh, err := h.HeadObject(ctxT(), &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("head pre-tier: %v", err)
	}
	if hh.StorageClass != types.StorageClassStandard {
		t.Fatalf("expected STANDARD before tier, got %q", hh.StorageClass)
	}

	got, err := h.GetObject(ctxT(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("get pre-tier: %v", err)
	}
	gotBody := collect(t, got.Body)
	if string(gotBody) != string(body) {
		t.Fatalf("body mismatch before tier: got %q", gotBody)
	}

	// --- simulate tier (same calls the daemon makes) ---
	obj := filepath.Join(rootdir, bucket, key)
	loc := "mock:" + obj + ":0:1"
	_ = h.meta.StoreAttribute(nil, obj, "", attrSize, []byte(fmt.Sprint(len(body))))
	_ = h.meta.StoreAttribute(nil, obj, "", attrLoc, []byte(loc))
	if err := os.Truncate(obj, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	_ = h.meta.StoreAttribute(nil, obj, "", attrOffline, []byte("1"))

	// --- post-tier: HEAD ---
	hh, err = h.HeadObject(ctxT(), &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("head post-tier: %v", err)
	}
	if hh.StorageClass != types.StorageClassGlacier {
		t.Fatalf("expected GLACIER after tier, got %q", hh.StorageClass)
	}
	if hh.ContentLength == nil || *hh.ContentLength != int64(len(body)) {
		t.Fatalf("expected reported size %d, got %v", len(body), hh.ContentLength)
	}
	if hh.Restore == nil {
		t.Fatalf("expected x-amz-restore header after tier; got nil")
	}
	if !strings.Contains(*hh.Restore, `ongoing-request="false"`) {
		t.Fatalf("expected ongoing-request=false, got %q", *hh.Restore)
	}

	// --- post-tier: GET should return InvalidObjectState ---
	_, err = h.GetObject(ctxT(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	var apiErr s3err.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "InvalidObjectState" {
		t.Fatalf("expected InvalidObjectState, got %v", err)
	}

	// --- post-tier: COPY should return InvalidObjectState ---
	_, err = h.CopyObject(ctxT(), s3response.CopyObjectInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String("copy.bin"),
		CopySource: aws.String("/" + bucket + "/" + key),
	})
	if !errors.As(err, &apiErr) || apiErr.Code != "InvalidObjectState" {
		t.Fatalf("expected InvalidObjectState on copy, got %v", err)
	}

	// --- post-tier: LIST should show GLACIER + size ---
	lr, err := h.ListObjectsV2(ctxT(), &s3.ListObjectsV2Input{Bucket: aws.String(bucket), StartAfter: aws.String(""), MaxKeys: aws.Int32(1000)})
	if err != nil {
		t.Fatalf("list post-tier: %v", err)
	}
	if len(lr.Contents) != 1 {
		t.Fatalf("expected exactly 1 object in list, got %d", len(lr.Contents))
	}
	obj0 := lr.Contents[0]
	if obj0.StorageClass != types.ObjectStorageClassGlacier {
		t.Fatalf("expected GLACIER in list, got %q", obj0.StorageClass)
	}
	if obj0.Size == nil || *obj0.Size != int64(len(body)) {
		t.Fatalf("expected listed size %d, got %v", len(body), obj0.Size)
	}
	if obj0.RestoreStatus == nil {
		t.Fatalf("expected RestoreStatus in list entry")
	}
	if obj0.RestoreStatus.IsRestoreInProgress == nil || *obj0.RestoreStatus.IsRestoreInProgress {
		t.Fatalf("expected IsRestoreInProgress=false in list entry, got %v", obj0.RestoreStatus.IsRestoreInProgress)
	}

	// --- RestoreObject should enqueue a restore (queue non-empty afterwards) and
	// --- mark the object restoring (x-amz-restore ongoing-request="true"). ---
	err = h.RestoreObject(ctxT(), &s3.RestoreObjectInput{
		Bucket:         aws.String(bucket),
		Key:            aws.String(key),
		RestoreRequest: &types.RestoreRequest{Days: aws.Int32(3)},
	})
	if err != nil {
		t.Fatalf("restore object: %v", err)
	}
	hh, err = h.HeadObject(ctxT(), &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("head post-restore-request: %v", err)
	}
	if hh.Restore == nil || !strings.Contains(*hh.Restore, `ongoing-request="true"`) {
		t.Fatalf("expected ongoing-request=true after restore request, got %v", hh.Restore)
	}

	// --- simulate the daemon completing the restore (materialize bytes, clear flags) ---
	if err := os.WriteFile(obj, body, 0o644); err != nil {
		t.Fatalf("restore materialize: %v", err)
	}
	_ = h.meta.StoreAttribute(nil, obj, "", attrRestoring, []byte(""))
	_ = h.meta.StoreAttribute(nil, obj, "", attrOffline, []byte(""))

	// --- GET should work and return the original body ---
	got, err = h.GetObject(ctxT(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("get post-restore: %v", err)
	}
	all := collect(t, got.Body)
	if string(all) != string(body) {
		t.Fatalf("body mismatch after restore: got %q", all)
	}
}

// TestGlacierExpiryReTier is a minimal sanity for the expiry path: objects
// restored with a Days window should still be reported with the expiry
// xattr present (the daemon's sweeper will use it). This test only checks
// the state is visible; it does not advance a real clock.
func TestGlacierExpiryStateVisible(t *testing.T) {
	h, rootdir, cleanup := setupBackend(t)
	defer cleanup()
	const bucket, key = "expiry-bucket", "obj.bin"
	body := []byte("expiry-test")
	putObject(t, h, rootdir, bucket, key, body)

	obj := filepath.Join(rootdir, bucket, key)
	// set tier flags the way the daemon would after re-tiering
	_ = h.meta.StoreAttribute(nil, obj, "", attrOffline, []byte("1"))
	_ = h.meta.StoreAttribute(nil, obj, "", attrSize, []byte("5"))
	_ = h.meta.StoreAttribute(nil, obj, "", attrLoc, []byte("mock:"+obj+":0:1"))
	// set expiry in the future
	expiry := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	_ = h.meta.StoreAttribute(nil, obj, "", attrExpiry, []byte(expiry))

	// HEAD after tier+expiry: should still be GLACIER, ongoing-request=false
	hh, err := h.HeadObject(ctxT(), &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if hh.StorageClass != types.StorageClassGlacier {
		t.Fatalf("expected GLACIER, got %q", hh.StorageClass)
	}
}

func collect(t *testing.T, r interface{ Read([]byte) (int, error) }) []byte {
	t.Helper()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return buf.Bytes()
}

// TestGlacierOfflineSemanticsSidecar runs the offline/restore semantics with
// the split-file (sidecar) metadata representation. The simulated daemon
// writes state the way vgwtaped does — absolute object paths through
// PathRelStorer — while the gateway reads/writes its own state through the
// raw storer with root-relative names. The test asserts both address the
// same sidecar files: that bridge is what makes the two processes agree.
func TestGlacierOfflineSemanticsSidecar(t *testing.T) {
	h, rootdir, daemonStorer, cleanup := setupBackendStore(t, true)
	defer cleanup()
	if daemonStorer == nil {
		t.Fatal("expected daemon storer for sidecar setup")
	}

	const (
		bucket = "sc-bucket"
		key    = "object.bin"
	)
	body := []byte("sidecar-glacier-payload")
	putObject(t, h, rootdir, bucket, key, body)

	// --- daemon tiers the object (absolute-path addressing) ---
	obj := filepath.Join(rootdir, bucket, key)
	if err := state.SetOffline(daemonStorer, obj, "mock:"+obj+":0:"+fmt.Sprint(len(body)), int64(len(body))); err != nil {
		t.Fatalf("daemon set-offline: %v", err)
	}
	if err := os.Truncate(obj, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// --- gateway (root-relative addressing) sees GLACIER ---
	hh, err := h.HeadObject(ctxT(), &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("head post-tier: %v", err)
	}
	if hh.StorageClass != types.StorageClassGlacier {
		t.Fatalf("expected GLACIER, got %q", hh.StorageClass)
	}
	if hh.ContentLength == nil || *hh.ContentLength != int64(len(body)) {
		t.Fatalf("expected reported size %d, got %v", len(body), hh.ContentLength)
	}

	_, err = h.GetObject(ctxT(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	var apiErr s3err.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "InvalidObjectState" {
		t.Fatalf("expected InvalidObjectState, got %v", err)
	}

	// --- gateway enqueues + marks restoring; daemon-side reader sees it ---
	if err := h.RestoreObject(ctxT(), &s3.RestoreObjectInput{
		Bucket:         aws.String(bucket),
		Key:            aws.String(key),
		RestoreRequest: &types.RestoreRequest{Days: aws.Int32(1)},
	}); err != nil {
		t.Fatalf("restore object: %v", err)
	}
	if st := state.Store(daemonStorer, obj); !st.Offline || !st.Restoring {
		t.Fatalf("daemon-side state after gateway restore request: %+v", st)
	}

	// --- daemon completes the restore (absolute path again) ---
	if err := os.WriteFile(obj, body, 0o644); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if err := state.ClearOffline(daemonStorer, obj); err != nil {
		t.Fatalf("daemon clear-offline: %v", err)
	}

	// --- gateway serves the original bytes again ---
	got, err := h.GetObject(ctxT(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("get post-restore: %v", err)
	}
	if all := collect(t, got.Body); string(all) != string(body) {
		t.Fatalf("body mismatch after restore: got %q", all)
	}

	// --- on-disk layout: state under <sidecar>/<bucket>/<key>/meta/, never
	// a doubled-up absolute path, and nothing as xattr on the object.
	base := filepath.Dir(rootdir)
	metaDir := filepath.Join(base, "sidecar", bucket, key, "meta")
	if _, err := os.Stat(filepath.Join(metaDir, "hsm-loc")); err != nil {
		t.Fatalf("expected %s/hsm-loc: %v", metaDir, err)
	}
	if doubled := filepath.Join(base, "sidecar", rootdir); dirExists(doubled) {
		t.Fatalf("sidecar doubled the absolute root: %s", doubled)
	}
	if attrs, err := (&meta.XattrMeta{}).ListAttributes(obj, ""); err == nil {
		for _, a := range attrs {
			if strings.HasPrefix(a, "hsm-") {
				t.Fatalf("hsm state leaked to xattr on %s: %v", obj, attrs)
			}
		}
	}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
