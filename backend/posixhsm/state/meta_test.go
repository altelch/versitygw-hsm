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

package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/versity/versitygw/backend/meta"
)

func TestCaptureMetaXattrRoundTrip(t *testing.T) {
	dir := t.TempDir()
	obj := filepath.Join(dir, "bkt", "key")
	if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	ms := meta.XattrMeta{}
	if err := ms.StoreAttribute(nil, obj, "", "x-content-type", []byte("text/plain")); err != nil {
		t.Fatal(err)
	}
	if err := ms.StoreAttribute(nil, obj, "", "x-etag", []byte("1234")); err != nil {
		t.Fatal(err)
	}
	// A daemon HSM state key must NOT be captured (replaying it would
	// re-mark the object offline).
	if err := ms.StoreAttribute(nil, obj, "", Offline, []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := ms.StoreAttribute(nil, obj, "", Locator, []byte("tsm:/x/y")); err != nil {
		t.Fatal(err)
	}

	payload, err := CaptureMeta(ms, obj, "")
	if err != nil {
		t.Fatalf("CaptureMeta: %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("CaptureMeta: empty payload")
	}

	// Replay onto a DIFFERENT file must restore exactly the two S3 attrs.
	obj2 := filepath.Join(dir, "bkt2", "key2")
	if err := os.MkdirAll(filepath.Dir(obj2), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj2, []byte("restored"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RestoreMeta(ms, obj2, "", payload); err != nil {
		t.Fatalf("RestoreMeta: %v", err)
	}
	v, err := ms.RetrieveAttribute(nil, obj2, "", "x-content-type")
	if err != nil || string(v) != "text/plain" {
		t.Fatalf("x-content-type = %q (%v), want text/plain", v, err)
	}
	v, err = ms.RetrieveAttribute(nil, obj2, "", "x-etag")
	if err != nil || string(v) != "1234" {
		t.Fatalf("x-etag = %q (%v), want 1234", v, err)
	}
	if st := Store(ms, obj2); st.Offline {
		t.Fatal("HSM state must not be replayed by RestoreMeta")
	}
}

func TestCaptureMetaNilStorer(t *testing.T) {
	p, err := CaptureMeta(nil, "/any/path", "")
	if err != nil {
		t.Fatalf("CaptureMeta(nil): %v", err)
	}
	// An empty object map is still valid JSON.
	if string(p) != `{"src":"/any/path","attrs":{}}` {
		t.Fatalf("unexpected empty capture: %s", p)
	}
}

func TestRestoreMetaEmptyPayload(t *testing.T) {
	if err := RestoreMeta(meta.XattrMeta{}, "/some/obj", "", nil); err != nil {
		t.Fatalf("RestoreMeta(empty) should be a no-op, got %v", err)
	}
}

func TestRestoreMetaMalformedPayload(t *testing.T) {
	if err := RestoreMeta(meta.XattrMeta{}, "/some/obj", "", []byte("not json")); err == nil {
		t.Fatal("RestoreMeta should reject malformed payloads")
	}
}

func TestCaptureMetaSidecarRoundTrip(t *testing.T) {
	base := t.TempDir()
	sidebar := filepath.Join(base, "sidecar")
	if err := os.MkdirAll(sidebar, 0o755); err != nil {
		t.Fatal(err)
	}
	sc, err := meta.NewSideCar(sidebar)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.StoreAttribute(nil, "bkt", "key", "x-user-tag", []byte("v=1")); err != nil {
		t.Fatal(err)
	}
	payload, err := CaptureMeta(sc, "bkt", "key")
	if err != nil {
		t.Fatalf("CaptureMeta: %v", err)
	}
	// Replay sidecar-into-sidecar for another object.
	if err := RestoreMeta(sc, "bkt", "key2", payload); err != nil {
		t.Fatalf("RestoreMeta: %v", err)
	}
	v, err := sc.RetrieveAttribute(nil, "bkt", "key2", "x-user-tag")
	if err != nil || string(v) != "v=1" {
		t.Fatalf("x-user-tag = %q (%v), want v=1", v, err)
	}
}
