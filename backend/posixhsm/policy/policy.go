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

// Package policy defines the tiering rules that vgwtaped applies when
// deciding which objects to archive and when.
package policy

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy is the top-level tiering policy consumed by vgwtaped.
type Policy struct {
	// Default applies to every bucket.
	Default Rule `yaml:"default"`
	// Buckets overrides Default for named buckets (exact name match).
	Buckets map[string]Rule `yaml:"buckets"`
}

// Rule is a tiering rule. Empty / zero fields are treated as "no limit" —
// a zero MinAge tiers any object regardless of age; a zero MinSize tiers
// any size; an empty Tags map requires no tag constraint.
type Rule struct {
	// MinAge: only tier objects whose LastModified is at least this old.
	// Zero means no minimum age.
	MinAge time.Duration `yaml:"min-age"`
	// MinSize: skip objects smaller than this in bytes. Zero means no minimum.
	MinSize int64 `yaml:"min-size"`
	// Tags: every key/value pair must be present on the object for it to
	// be tiered. Empty map means no tag requirement.
	Tags map[string]string `yaml:"tags"`
}

// ObjInfo is the minimum object information needed to evaluate a rule.
type ObjInfo struct {
	Bucket       string
	Key          string
	LastModified time.Time
	Size         int64
	Tags         map[string]string
}

// Load reads, decodes, and validates a YAML policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %q: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy: parse %q: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("policy: validate: %w", err)
	}
	return &p, nil
}

// Validate rejects negative thresholds.
func (p *Policy) Validate() error {
	if p.Default.MinAge < 0 {
		return errors.New("default: min-age must be >= 0")
	}
	if p.Default.MinSize < 0 {
		return errors.New("default: min-size must be >= 0")
	}
	for name, r := range p.Buckets {
		if r.MinAge < 0 {
			return fmt.Errorf("bucket %q: min-age must be >= 0", name)
		}
		if r.MinSize < 0 {
			return fmt.Errorf("bucket %q: min-size must be >= 0", name)
		}
	}
	return nil
}

// RuleFor returns the effective rule for a bucket.
func (p *Policy) RuleFor(bucket string) Rule {
	if r, ok := p.Buckets[bucket]; ok {
		return r
	}
	return p.Default
}

// ShouldTier reports whether the object satisfies the rule at the given
// reference time.
func (r Rule) ShouldTier(obj ObjInfo, now time.Time) bool {
	if r.MinAge > 0 && !obj.LastModified.IsZero() {
		if now.Sub(obj.LastModified) < r.MinAge {
			return false
		}
	}
	if r.MinSize > 0 && obj.Size < r.MinSize {
		return false
	}
	for k, want := range r.Tags {
		if got, ok := obj.Tags[k]; !ok || got != want {
			return false
		}
	}
	return true
}
