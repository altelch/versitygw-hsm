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

// Metadata capture and replay for the HSM tiering backend. S3 metadata
// (etag, content-type, user tags, …) lives in two places that the tiering
// flow treats differently:
//
//   - xattrs on the live POSIX file — these are NOT archived by TSM (the
//     DAPI sends data only) and, in sidecar mode, they DO not exist in the
//     first place;
//   - sidecar metadata files — these live OUTSIDE --rootdir by design, so
//     they are outside the TSM filespace and outside the Bareos due-file
//     list, i.e. they are never archived at all.
//
// The result: a tiered object's S3 metadata can be lost in TSM and in
// sidecar layouts. Capture snapshots the object's S3-visible attributes
// (via the shared MetadataStorer, so both xattr and sidecar work) into a
// single JSON payload that each driver archives as a companion object
// alongside the data. Replay (RestoreMeta) writes the payload's attributes
// back through the same storer — which makes restore work regardless of
// whether the gateway runs in xattr or sidecar mode.
//
// The daemon's internal HSM state keys (Offline, Size, Locator, Restoring,
// Expiry) are excluded: replaying them onto a just-recovered object would
// re-mark it offline with a stale locator.
package state

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/versity/versitygw/backend/meta"
)

// capturedMeta is the serialised form of an object's S3 metadata. It
// travels as one JSON value inside a secondary-store object (or file, for
// bareos), so the daemon's FetchMeta and the tsmapi CLI can share the
// shape. Attribute names are storer-level names (without the platform
// "user." prefix that xattr storers re-attach at the filesystem level),
// which is the only form that round-trips identically through xattr and
// sidecar.
type capturedMeta struct {
	// Source records the storer address the metadata was captured FROM
	// (informational: debug/replay diagnostics). Empty for payloads made
	// before this field existed.
	Source string `json:"src,omitempty"`
	// Attrs maps attribute name to its base64-encoded value.
	Attrs map[string]string `json:"attrs"`
}

// CaptureMeta snapshots the S3-visible attributes of the object addressed
// as (addr, object) into a canonical JSON payload ("canonical": the same
// attributes always produce the same bytes, because map keys are sorted
// during marshal).
//
// Naming follows the shared state package convention: the daemon addresses
// objects with the absolute file path as addr and object == ""; the
// gateway's path form (bucket, key) is accepted as well because both
// storers take (bucket, object) verbatim.
//
// A nil storer yields an empty payload; an attribute that is listed but
// cannot be read is skipped rather than failing the whole capture (the
// object's data is still worth archiving even if one metadata row is
// lost).
func CaptureMeta(r meta.MetadataStorer, addr, object string) ([]byte, error) {
	attrs := map[string]string{}
	if r != nil {
		names, err := r.ListAttributes(addr, object)
		if err != nil {
			return nil, fmt.Errorf("list attributes %s/%s: %w", addr, object, err)
		}
		for _, name := range names {
			if isHSMStateKey(name) {
				continue
			}
			v, err := r.RetrieveAttribute(nil, addr, object, name)
			if err != nil {
				continue
			}
			attrs[name] = base64.StdEncoding.EncodeToString(v)
		}
	}
	cm := capturedMeta{Source: addr, Attrs: attrs}
	return json.Marshal(cm)
}

// RestoreMeta replays a payload produced by CaptureMeta: each attribute is
// stored via the same (addr, object) the caller used. An empty payload or
// nil storer is a no-op. This keeps the daemon's restore path forgiving of
// a companion object that was never written: the data restore succeeds,
// the object's (pre-existing) metadata stays as-is.
func RestoreMeta(w meta.MetadataStorer, addr, object string, payload []byte) error {
	if w == nil || len(payload) == 0 {
		return nil
	}
	var cm capturedMeta
	if err := json.Unmarshal(payload, &cm); err != nil {
		return fmt.Errorf("metadata payload malformed: %w", err)
	}
	for name, b64 := range cm.Attrs {
		v, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("metadata payload attribute %q: %w", name, err)
		}
		if err := w.StoreAttribute(nil, addr, object, name, v); err != nil {
			return fmt.Errorf("store attribute %q: %w", name, err)
		}
	}
	return nil
}

// isHSMStateKey reports whether name is one of the daemon's own HSM state
// keys. These are excluded from capture/replay.
func isHSMStateKey(name string) bool {
	switch name {
	case Offline, Size, Locator, Restoring, Expiry:
		return true
	}
	return false
}
