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

package state

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/versity/versitygw/backend/meta"
)

// PathRelStorer adapts a path-relative metadata storer (SideCar) for callers
// that address objects by their absolute filesystem path.
//
// The gateway addresses HSM state with the root-relative object path as the
// bucket argument (posix runs with rootdir as the working directory, and
// SideCar resolves the bucket under its metadata directory), while the daemon
// addresses state by absolute path: state.Store/Set pass the absolute object
// path as the bucket with an empty object. XattrMeta tolerates both because
// it passes an absolute bucket through verbatim; SideCar would join the
// absolute path under its metadata dir and double up rootdir. This wrapper
// rewrites absolute paths under root to root-relative before delegating.
// Absolute paths outside root (e.g. versioning-directory objects) and plain
// bucket names pass through unchanged.
type PathRelStorer struct {
	inner  meta.MetadataStorer
	prefix string
}

var _ meta.MetadataStorer = PathRelStorer{}

// NewPathRelStorer returns a storer that maps absolute paths under rootdir to
// their root-relative names before delegating to inner. rootdir must be
// absolute; inner must not be nil.
func NewPathRelStorer(inner meta.MetadataStorer, rootdir string) PathRelStorer {
	prefix := rootdir
	if prefix != "" && !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return PathRelStorer{inner: inner, prefix: prefix}
}

// rel maps an absolute path under root to its root-relative form; any other
// value is returned unchanged.
func (s PathRelStorer) rel(bucket string) string {
	if s.prefix != "" && filepath.IsAbs(bucket) && strings.HasPrefix(bucket, s.prefix) {
		return bucket[len(s.prefix):]
	}
	return bucket
}

// RetrieveAttribute retrieves the value of a specific attribute for an object
// or a bucket.
func (s PathRelStorer) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	return s.inner.RetrieveAttribute(f, s.rel(bucket), object, attribute)
}

// StoreAttribute stores the value of a specific attribute for an object or a
// bucket.
func (s PathRelStorer) StoreAttribute(f *os.File, bucket, object, attribute string, value []byte) error {
	return s.inner.StoreAttribute(f, s.rel(bucket), object, attribute, value)
}

// DeleteAttribute removes the value of a specific attribute for an object or
// a bucket.
func (s PathRelStorer) DeleteAttribute(bucket, object, attribute string) error {
	return s.inner.DeleteAttribute(s.rel(bucket), object, attribute)
}

// ListAttributes lists all attributes for an object or a bucket.
func (s PathRelStorer) ListAttributes(bucket, object string) ([]string, error) {
	return s.inner.ListAttributes(s.rel(bucket), object)
}

// DeleteAttributes removes all attributes for an object or a bucket.
func (s PathRelStorer) DeleteAttributes(bucket, object string) error {
	return s.inner.DeleteAttributes(s.rel(bucket), object)
}

// RenameObject renames all stored metadata from oldObject to newObject. The
// bucket argument passes through the same root-relative mapping; a plain
// bucket name is passed through unchanged.
func (s PathRelStorer) RenameObject(bucket, oldObject, newObject string) error {
	return s.inner.RenameObject(s.rel(bucket), oldObject, newObject)
}
