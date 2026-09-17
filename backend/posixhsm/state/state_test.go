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
	"testing"
	"time"

	"github.com/versity/versitygw/backend/meta"
)

func newMeta(t *testing.T) (meta.MetadataStorer, string) {
	t.Helper()
	root := t.TempDir()
	objectPath := root + "/bkt/object.bin"
	if err := os.MkdirAll(root+"/bkt", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return meta.XattrMeta{}.WithRootDir(root), objectPath
}

func TestStoreZeroState(t *testing.T) {
	m, path := newMeta(t)
	st := Store(m, path)
	if st != (State{}) {
		t.Fatalf("expected zero state, got %+v", st)
	}
	if st := Store(m, ""); st != (State{}) {
		t.Fatalf("expected zero state for empty path, got %+v", st)
	}
	if st := Store(nil, path); st != (State{}) {
		t.Fatalf("expected zero state for nil storer, got %+v", st)
	}
}

func TestSetOfflineRoundTrip(t *testing.T) {
	m, path := newMeta(t)
	if err := SetOffline(m, path, "mock:/data:0:10", 1234); err != nil {
		t.Fatal(err)
	}
	st := Store(m, path)
	if !st.Offline {
		t.Error("expected offline=true")
	}
	if !st.HasSize || st.Size != 1234 {
		t.Errorf("expected size 1234, got %d (has=%v)", st.Size, st.HasSize)
	}
	if st.Locator != "mock:/data:0:10" {
		t.Errorf("expected locator round-trip, got %q", st.Locator)
	}
	if st.Restoring {
		t.Error("expected restoring=false on a fresh offline state")
	}
}

func TestClearOfflineAndSetRestoring(t *testing.T) {
	m, path := newMeta(t)
	if err := SetOffline(m, path, "loc", 1); err != nil {
		t.Fatal(err)
	}
	if err := SetRestoring(m, path, true); err != nil {
		t.Fatal(err)
	}
	st := Store(m, path)
	if !st.Restoring {
		t.Error("expected restoring=true")
	}
	if err := ClearOffline(m, path); err != nil {
		t.Fatal(err)
	}
	st = Store(m, path)
	if st.Offline {
		t.Error("expected offline=false after clear")
	}
	if st.Restoring {
		t.Error("expected restoring=false after clear")
	}
}

func TestSetExpiry(t *testing.T) {
	m, path := newMeta(t)
	exp := time.Date(2026, 6, 1, 12, 30, 0, 0, time.UTC)
	if err := SetExpiry(m, path, exp); err != nil {
		t.Fatal(err)
	}
	st := Store(m, path)
	if st.Expiry != exp.Format(time.RFC3339) {
		t.Errorf("expected expiry %q, got %q", exp.Format(time.RFC3339), st.Expiry)
	}
	got, err := time.Parse(time.RFC3339, st.Expiry)
	if err != nil {
		t.Fatalf("parsing expiry: %v", err)
	}
	if !got.Equal(exp) {
		t.Errorf("expected %v, got %v", exp, got)
	}
}

func TestExists(t *testing.T) {
	root := t.TempDir()
	if Exists(root + "/missing") {
		t.Error("expected false for missing path")
	}
	if Exists("") {
		t.Error("expected false for empty path")
	}
	if Exists(root) {
		t.Error("expected false for a directory")
	}
	p := root + "/file"
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Exists(p) {
		t.Error("expected true for existing regular file")
	}
}
