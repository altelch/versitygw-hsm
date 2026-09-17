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

package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAndRuleFor(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pol.yaml")
	body := `
default:
  min-age: 1h
  min-size: 100
buckets:
  cold:
    min-age: 24h
    min-size: 10
    tags:
      hsm: "eligible"
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	def := pol.RuleFor("bkt")
	if def.MinAge != time.Hour {
		t.Errorf("default min-age = %v, want 1h", def.MinAge)
	}
	if def.MinSize != 100 {
		t.Errorf("default min-size = %d, want 100", def.MinSize)
	}

	cold := pol.RuleFor("cold")
	if cold.MinAge != 24*time.Hour {
		t.Errorf("cold min-age = %v, want 24h", cold.MinAge)
	}
	if cold.Tags["hsm"] != "eligible" {
		t.Errorf("cold tag = %v, want eligible", cold.Tags["hsm"])
	}
}

func TestLoadMissingAndMalformed(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing policy")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "pol.yaml")
	if err := os.WriteFile(p, []byte("default: 123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for type-mismatched policy")
	}
}

func TestValidateNegative(t *testing.T) {
	pol := &Policy{Default: Rule{MinAge: -time.Hour}}
	if err := pol.Validate(); err == nil {
		t.Fatal("expected error for negative min-age")
	}
	pol2 := &Policy{Buckets: map[string]Rule{"b": {MinSize: -1}}}
	if err := pol2.Validate(); err == nil {
		t.Fatal("expected error for negative min-size")
	}
}

func TestShouldTier(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// age
	rule := Rule{MinAge: 1 * time.Hour}
	if !rule.ShouldTier(ObjInfo{LastModified: now.Add(-2 * time.Hour)}, now) {
		t.Error("expected old object to be tiered")
	}
	if rule.ShouldTier(ObjInfo{LastModified: now.Add(-30 * time.Minute)}, now) {
		t.Error("expected young object to be skipped")
	}
	// zero age tiers any
	zero := Rule{MinAge: 0}
	if !zero.ShouldTier(ObjInfo{LastModified: now}, now) {
		t.Error("expected zero-age rule to tier any object")
	}

	// size
	sz := Rule{MinSize: 1000}
	if !sz.ShouldTier(ObjInfo{Size: 2000}, now) {
		t.Error("expected object >= min-size to be tiered")
	}
	if sz.ShouldTier(ObjInfo{Size: 500}, now) {
		t.Error("expected small object to be skipped")
	}

	// tags: all must match
	tags := Rule{Tags: map[string]string{"a": "1", "b": "2"}}
	if !tags.ShouldTier(ObjInfo{Tags: map[string]string{"a": "1", "b": "2"}}, now) {
		t.Error("expected matching tags to be tiered")
	}
	if tags.ShouldTier(ObjInfo{Tags: map[string]string{"a": "1"}}, now) {
		t.Error("expected missing tag to be skipped")
	}
	if tags.ShouldTier(ObjInfo{Tags: map[string]string{"a": "1", "b": "3"}}, now) {
		t.Error("expected mismatched tag value to be skipped")
	}

	// combined
	combo := Rule{MinAge: 1 * time.Hour, MinSize: 10, Tags: map[string]string{"hsm": "eligible"}}
	obj := ObjInfo{LastModified: now.Add(-2 * time.Hour), Size: 100, Tags: map[string]string{"hsm": "eligible"}}
	if !combo.ShouldTier(obj, now) {
		t.Error("expected combined-eligible object to be tiered")
	}
	if combo.ShouldTier(ObjInfo{LastModified: now, Size: 100, Tags: obj.Tags}, now) {
		t.Error("expected too-young object to be skipped despite tags")
	}
}
