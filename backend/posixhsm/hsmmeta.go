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
// KIND, either express or implied.  See the license for the
// specific language governing permissions and limitations
// under the License.

package posixhsm

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	// MetaSuffix is the fixed part of a metadata companion object name.
	MetaSuffix = ".hsm-meta"

	// metaNameHashBytes is the number of hex characters of the object
	// identity hash embedded in the companion name.
	metaNameHashBytes = 8 // 16 hex chars
)

// MetaName derives the deterministic companion-object name for the data
// object identified by (hl, ll). The name is stable across drivers and
// passes so that the archive side (ArchiveWave) and the fetch/purge side
// (FetchMeta / Purge) always agree without any persisted bookkeeping:
//
//	<ll>-<hash16>.hsm-meta     (when that fits a TSM low-level name: <= 255B)
//	<hex(sha256(hl+":"+ll))>.hsm-meta   (fallback for long leaf names)
//
// The hash covers hl AND ll so two objects with the same leaf name in
// different directories never collide. The hash is derived from the full
// identity (not just ll) so the companion is unique per object.
func MetaName(hl, ll string) string {
	sum := sha256.Sum256([]byte(hl + ":" + ll))
	h16 := hex.EncodeToString(sum[:metaNameHashBytes])
	named := ll + "-" + h16 + MetaSuffix
	if len(named) <= 255 {
		return named
	}
	return h16 + MetaSuffix
}

// IsMetaName reports whether name looks like a metadata companion object
// (i.e. ends with the .hsm-meta suffix). Drivers use this to keep their
// list/query paths from treating companions as data objects.
func IsMetaName(name string) bool {
	return strings.HasSuffix(name, MetaSuffix)
}
