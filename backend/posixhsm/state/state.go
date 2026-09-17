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

// Package state holds the on-disk HSM (hierarchical storage management)
// state shared by the posixhsm backend wrapper and the vgwtaped daemon.
// Keeping the definitions in one place guarantees the gateway and daemon
// interpret the same xattrs and the same object paths.
package state

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/versity/versitygw/backend/meta"
)

// Xattr keys for per-object HSM state, stored via meta.MetadataStorer.
// Kept short to fit within xattr value limits across filesystems.
const (
	Offline   = "hsm-offline"   // "1" when data is on the secondary store
	Size      = "hsm-size"      // original byte count (file is 0 bytes while offline)
	Locator   = "hsm-loc"       // driver locator for the offline data
	Restoring = "hsm-restoring" // "1" while a restore is in flight
	Expiry    = "hsm-expiry"    // RFC3339 restored-copy expiry (set by daemon)
)

// State is the per-object HSM state.
type State struct {
	Offline   bool
	Restoring bool
	Size      int64
	HasSize   bool
	Locator   string
	Expiry    string
}

// Store reads HSM state from an object file path. An empty path yields a
// zero State.
func Store(r meta.MetadataStorer, path string) State {
	var st State
	if path == "" || r == nil {
		return st
	}
	get := func(key string) string {
		v, err := r.RetrieveAttribute(nil, path, "", key)
		if err != nil {
			return ""
		}
		return string(v)
	}
	st.Offline = get(Offline) == "1"
	st.Restoring = get(Restoring) == "1"
	if v := get(Size); v != "" {
		var n int64
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			st.Size = n
			st.HasSize = true
		}
	}
	st.Locator = get(Locator)
	st.Expiry = get(Expiry)
	return st
}

// Set writes a single HSM key to the object file path.
func Set(w meta.MetadataStorer, path, key, value string) error {
	return w.StoreAttribute(nil, path, "", key, []byte(value))
}

// SetOffline atomically-flavours the three keys needed to mark an object
// offline: locator, size, then offline flag (offline last so readers only
// ever see offline once a locator + size exist — no crash window loses data).
func SetOffline(w meta.MetadataStorer, path string, locator string, size int64) error {
	if err := Set(w, path, Locator, locator); err != nil {
		return err
	}
	if err := Set(w, path, Size, fmt.Sprint(size)); err != nil {
		return err
	}
	return Set(w, path, Offline, "1")
}

// ClearOffline removes the offline/restoring markers after a restore.
func ClearOffline(w meta.MetadataStorer, path string) error {
	_ = Set(w, path, Restoring, "")
	return Set(w, path, Offline, "")
}

// SetRestoring marks an object as in the restore queue.
func SetRestoring(w meta.MetadataStorer, path string, on bool) error {
	if on {
		return Set(w, path, Restoring, "1")
	}
	return Set(w, path, Restoring, "")
}

// SetExpiry records when a restored copy may be re-tiered.
func SetExpiry(w meta.MetadataStorer, path string, expiry time.Time) error {
	return Set(w, path, Expiry, expiry.UTC().Format(time.RFC3339))
}

// ResolveObjectPath returns the filesystem path of object (bucket, key,
// versionId) under the given posix root. For versionId=="" it is
// <root>/<bucket>/<key>. For a versioned object it follows the posix
// versioning layout.
func ResolveObjectPath(rootdir, versioningDir, bucket, key, versionId string) string {
	if versionId == "" {
		return filepath.Join(rootdir, bucket, key)
	}
	if versioningDir == "" {
		return ""
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	return filepath.Join(versioningDir, bucket, sum[:2], sum[2:4], sum[4:6], sum, versionId)
}

// Exists reports whether path is an existing regular file.
func Exists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
