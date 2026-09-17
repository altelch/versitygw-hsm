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

// Package posixhsm wraps the posix backend with a glacier-style
// hierarchical-storage-management workflow. Object data is tiered to a
// secondary store (e.g. tape managed by bareos) by an external daemon
// (vgwtaped), which truncates the on-disk object to zero bytes while the
// object's metadata — including user metadata xattrs — remains on the
// filesystem. Objects whose data is offline are reported with the GLACIER
// storage class, cannot be read or copied, and are restorable by enqueuing
// a restore job that the daemon materializes back to disk.
//
// The wrapper is read-only with respect to HSM state on the data path:
// it reports offline state and enqueues restore jobs. All physical
// movement (archive, restore, purge) is performed by the daemon.
package posixhsm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/backend/posixhsm/queue"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// HSM state xattr keys, stored on the object file via the backend's
// MetadataStorer. Kept short to fit within xattr value limits across
// filesystems.
const (
	attrOffline   = "hsm-offline"
	attrSize      = "hsm-size"
	attrLoc       = "hsm-loc"
	attrRestoring = "hsm-restoring"
	attrExpiry    = "hsm-expiry"
)

// version-id attr key, kept consistent with the posix backend.
const versionIdAttr = "version-id"

// x-amz-restore header values, kept in line with the S3 API and with the
// scoutfs glacier-mode constants.
const (
	stageComplete   = `ongoing-request="false", expiry-date="Fri, 2 Dec 2050 00:00:00 GMT"`
	stageInProgress = `ongoing-request="true"`
)

// PosixHsmOpts configure the posixhsm backend wrapper.
type PosixHsmOpts struct {
	// StateDir is the shared HSM state directory. Required for
	// RestoreObject (job queue). May be empty otherwise.
	StateDir string
	// Glacier is the glacier emulation mode. The posixhsm backend is
	// intended to always be run with glacier enabled, but the knob is
	// kept for flexibility.
	Glacier bool
}

type PosixHsm struct {
	*posix.Posix
	meta    meta.MetadataStorer
	queue   *queue.Queue
	glacier bool
}

var _ backend.Backend = (*PosixHsm)(nil)

// New wraps an existing posix backend with HSM semantics.
func New(p *posix.Posix, ms meta.MetadataStorer, q *queue.Queue, o PosixHsmOpts) (*PosixHsm, error) {
	if p == nil {
		return nil, errors.New("posixhsm: nil posix backend")
	}
	if o.StateDir != "" && q == nil {
		return nil, errors.New("posixhsm: state dir set but nil queue")
	}
	return &PosixHsm{
		Posix:   p,
		meta:    ms,
		queue:   q,
		glacier: o.Glacier || true,
	}, nil
}

func (h *PosixHsm) String() string { return "PosixHsm Gateway" }

// versionedPath reproduces the posix versioning directory layout:
// <versioningDir>/<bucket>/<aa>/<bb>/<cc>/<fullsha256>/<versionId>.
func versionedPath(versioningDir, bucket, key, versionId string) (string, error) {
	if versioningDir == "" || bucket == "" || key == "" {
		return "", errors.New("posixhsm: versioned path requires non-empty paths")
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	return filepath.Join(versioningDir, bucket, sum[:2], sum[2:4], sum[4:6], sum, versionId), nil
}

// isNoAttrErr reports whether err indicates an absent attribute.
func isNoAttrErr(err error) bool {
	return errors.Is(err, meta.ErrNoSuchKey) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist)
}

// hsmState is the per-object HSM state, read from xattrs.
type hsmState struct {
	Offline   bool
	Restoring bool
	Size      int64
	HasSize   bool
	Loc       string
	Expiry    string
}

// readState reads the HSM state xattrs from a file path. An empty file
// path yields a zero state.
func (h *PosixHsm) readState(filePath string) hsmState {
	var st hsmState
	if filePath == "" {
		return st
	}
	readStr := func(key string) string {
		v, err := h.meta.RetrieveAttribute(nil, filePath, "", key)
		if err != nil {
			return ""
		}
		return string(v)
	}
	st.Offline = readStr(attrOffline) == "1"
	st.Restoring = readStr(attrRestoring) == "1"
	if v := readStr(attrSize); v != "" {
		var n int64
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			st.Size = n
			st.HasSize = true
		}
	}
	st.Loc = readStr(attrLoc)
	st.Expiry = readStr(attrExpiry)
	return st
}

// hsmFilePath resolves which file carries the HSM state for (bucket, key,
// versionId). For versionId=="" the current object is addressed. When
// versionId is set and the current object is a newer version, the path
// falls back to the versioning directory layout.
func (h *PosixHsm) hsmFilePath(bucket, key, versionId string) string {
	if versionId == "" {
		return h.ObjectPath(bucket, key)
	}
	// The posix backend keeps the current object at
	// <bucket>/<key> with a "version-id" xattr. If the current
	// version does not match the requested one, the version lives in
	// the versioning directory.
	current := h.ObjectPath(bucket, key)
	if fi, err := os.Stat(current); err == nil && !fi.IsDir() {
		if vId, err := h.meta.RetrieveAttribute(nil, bucket, key, versionIdAttr); err == nil && string(vId) == versionId {
			return current
		}
	}
	p, err := versionedPath(h.Posix.VersioningDir(), bucket, key, versionId)
	if err != nil {
		return ""
	}
	return p
}

// sizeFor returns the reported size for an object: the stored original
// size when offline, otherwise the on-disk size.
func (h *PosixHsm) sizeFor(bucket, key, versionId string) (int64, bool) {
	st := h.readState(h.hsmFilePath(bucket, key, versionId))
	if st.Offline && st.HasSize {
		return st.Size, true
	}
	fi, err := os.Stat(h.hsmFilePath(bucket, key, versionId))
	if err != nil {
		return 0, false
	}
	return fi.Size(), true
}

// isOffline reports whether the object is currently offline (data on tape).
func (h *PosixHsm) isOffline(bucket, key, versionId string) bool {
	filePath := h.hsmFilePath(bucket, key, versionId)
	if filePath == "" {
		return false
	}
	fi, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		return false
	}
	return h.readState(filePath).Offline
}

// restoreHeaderValue returns the x-amz-restore value for an offline object.
func (h *PosixHsm) restoreHeaderValue(bucket, key, versionId string) string {
	st := h.readState(h.hsmFilePath(bucket, key, versionId))
	if !st.Offline {
		return ""
	}
	if st.Restoring {
		return stageInProgress
	}
	return stageComplete
}

func (h *PosixHsm) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	res, err := h.Posix.HeadObject(ctx, input)
	if err != nil {
		return nil, err
	}
	if input.Bucket == nil || input.Key == nil {
		return res, nil
	}
	bucket, key := *input.Bucket, *input.Key
	versionId := ""
	if input.VersionId != nil {
		versionId = *input.VersionId
	}
	if !h.isOffline(bucket, key, versionId) {
		return res, nil
	}
	res.StorageClass = types.StorageClassGlacier
	hsm := h.restoreHeaderValue(bucket, key, versionId)
	res.Restore = &hsm
	if size, ok := h.sizeFor(bucket, key, versionId); ok {
		res.ContentLength = &size
	}
	return res, nil
}

func (h *PosixHsm) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	if input.Bucket != nil && input.Key != nil {
		bucket, key := *input.Bucket, *input.Key
		versionId := ""
		if input.VersionId != nil {
			versionId = *input.VersionId
		}
		if h.isOffline(bucket, key, versionId) {
			return nil, s3err.GetAPIError(s3err.ErrInvalidObjectState)
		}
	}
	res, err := h.Posix.GetObject(ctx, input)
	if err != nil {
		return nil, err
	}
	if res == nil || input.Bucket == nil || input.Key == nil {
		return res, nil
	}
	bucket, key := *input.Bucket, *input.Key
	versionId := ""
	if input.VersionId != nil {
		versionId = *input.VersionId
	}
	hsm := h.restoreHeaderValue(bucket, key, versionId)
	if hsm != "" {
		res.Restore = &hsm
		if res.StorageClass == "" {
			res.StorageClass = types.StorageClassGlacier
		}
	}
	return res, nil
}

// hsmFileToObj decorates the posix FileToObj with glacier semantics
// for offline objects.
func (h *PosixHsm) hsmFileToObj(bucket string, fetchOwner bool) backend.GetObjFunc {
	base := h.Posix.FileToObj(bucket, fetchOwner)
	return func(path string, d fs.DirEntry) (s3response.Object, error) {
		obj, err := base(path, d)
		if err != nil || d.IsDir() {
			return obj, err
		}
		if !h.isOffline(bucket, path, "") {
			return obj, nil
		}
		obj.StorageClass = types.ObjectStorageClassGlacier
		restoring := h.restoreHeaderValue(bucket, path, "") == stageInProgress
		obj.RestoreStatus = &types.RestoreStatus{IsRestoreInProgress: &restoring}
		if size, ok := h.sizeFor(bucket, path, ""); ok && size > 0 {
			obj.Size = &size
		}
		return obj, nil
	}
}

func (h *PosixHsm) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
	return h.Posix.ListObjectsParametrized(ctx, input, h.customFileToObj)
}

func (h *PosixHsm) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	return h.Posix.ListObjectsV2Parametrized(ctx, input, h.customFileToObj)
}

// customFileToObj matches the func(string, bool) backend.GetObjFunc
// signature expected by the parametrized list operations.
func (h *PosixHsm) customFileToObj(bucket string, fetchOwner bool) backend.GetObjFunc {
	return h.hsmFileToObj(bucket, fetchOwner)
}

func (h *PosixHsm) ListObjectVersions(ctx context.Context, input *s3.ListObjectVersionsInput) (s3response.ListVersionsResult, error) {
	bucket := ""
	if input.Bucket != nil {
		bucket = *input.Bucket
	}
	res, err := h.Posix.ListObjectVersions(ctx, input)
	if err != nil {
		return res, err
	}
	for i := range res.Versions {
		v := &res.Versions[i]
		key := ""
		if v.Key != nil {
			key = *v.Key
		}
		versionId := ""
		if v.VersionId != nil {
			versionId = *v.VersionId
		}
		if v.Key == nil || key == "" {
			continue
		}
		if !h.isOffline(bucket, key, versionId) {
			continue
		}
		res.Versions[i].StorageClass = types.ObjectVersionStorageClass("GLACIER")
		restoring := h.restoreHeaderValue(bucket, key, versionId) == stageInProgress
		res.Versions[i].RestoreStatus = &types.RestoreStatus{IsRestoreInProgress: &restoring}
		if size, ok := h.sizeFor(bucket, key, versionId); ok && size > 0 {
			res.Versions[i].Size = &size
		}
	}
	return res, nil
}

// copySourceParse splits an S3 x-amz-copy-source value of the form
// "/bucket/key?versionId=..." into bucket, key, versionId.
func copySourceParse(copySource string) (bucket, key, versionId string, err error) {
	if copySource == "" {
		return "", "", "", errors.New("posixhsm: empty copy source")
	}
	rest := strings.TrimPrefix(copySource, "/")
	i := strings.Index(rest, "/")
	if i <= 0 {
		return "", "", "", errors.New("posixhsm: copy source missing bucket/key separator")
	}
	bucket, rest = rest[:i], rest[i+1:]
	if rest == "" {
		return "", "", "", errors.New("posixhsm: copy source missing key")
	}
	if idx := strings.Index(rest, "?"); idx >= 0 {
		q := rest[idx+1:]
		rest = rest[:idx]
		parsed, perr := url.ParseQuery(q)
		if perr == nil {
			if v := parsed.Get("versionId"); v != "" {
				versionId = v
			}
		}
	}
	key = rest
	return bucket, key, versionId, nil
}

func (h *PosixHsm) CopyObject(ctx context.Context, input s3response.CopyObjectInput) (s3response.CopyObjectOutput, error) {
	if input.CopySource != nil && *input.CopySource != "" {
		bucket, key, versionId, err := copySourceParse(*input.CopySource)
		if err == nil && h.isOffline(bucket, key, versionId) {
			return s3response.CopyObjectOutput{}, s3err.GetAPIError(s3err.ErrInvalidObjectState)
		}
	}
	return h.Posix.CopyObject(ctx, input)
}

func (h *PosixHsm) UploadPartCopy(ctx context.Context, upi *s3.UploadPartCopyInput) (s3response.CopyPartResult, error) {
	if upi.CopySource != nil && *upi.CopySource != "" {
		bucket, key, versionId, err := copySourceParse(*upi.CopySource)
		if err == nil && h.isOffline(bucket, key, versionId) {
			return s3response.CopyPartResult{}, s3err.GetAPIError(s3err.ErrInvalidObjectState)
		}
	}
	return h.Posix.UploadPartCopy(ctx, upi)
}

// RestoreObject enqueues a restore job for the daemon to materialize the
// object back to disk and marks the object as restoring. If the object is
// not offline the call is a no-op (matches S3 semantics where a restore of
// a non-archived object succeeds silently).
func (h *PosixHsm) RestoreObject(ctx context.Context, input *s3.RestoreObjectInput) error {
	if input.Bucket == nil || input.Key == nil {
		return s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	if h.queue == nil {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	bucket, key := *input.Bucket, *input.Key
	versionId := ""
	if input.VersionId != nil {
		versionId = *input.VersionId
	}
	if !h.isOffline(bucket, key, versionId) {
		return nil
	}
	days := int32(1)
	if input.RestoreRequest != nil && input.RestoreRequest.Days != nil && *input.RestoreRequest.Days > 0 {
		days = *input.RestoreRequest.Days
	}
	job := queue.Job{
		Op:        queue.JobOpRestore,
		Bucket:    bucket,
		Key:       key,
		VersionID: versionId,
		Days:      days,
	}
	if _, err := h.queue.Enqueue(job); err != nil {
		return fmt.Errorf("posixhsm: enqueue restore: %w", err)
	}
	// Best-effort: mark the object as restoring so subsequent
	// Head/Get/List calls report ongoing-request="true". The daemon
	// clears this upon completion.
	filePath := h.hsmFilePath(bucket, key, versionId)
	if filePath != "" {
		_ = h.meta.StoreAttribute(nil, filePath, "", attrRestoring, []byte("1"))
	}
	return nil
}
