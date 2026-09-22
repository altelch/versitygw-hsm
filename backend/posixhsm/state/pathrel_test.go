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
	"errors"
	"os"
	"testing"

	"github.com/versity/versitygw/backend/meta"
)

// captureMeta records the arguments of every MetadataStorer call so the
// tests can assert exactly what the delegate received.
type captureMeta struct {
	lastMethod string
	lastBucket string
	lastObject string
	lastAttr   string
	lastValue  []byte
	lastFile   *os.File
	err        error
}

func (c *captureMeta) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	c.lastMethod, c.lastBucket, c.lastObject, c.lastAttr, c.lastFile = "RetrieveAttribute", bucket, object, attribute, f
	if c.err != nil {
		return nil, c.err
	}
	return []byte("v"), nil
}

func (c *captureMeta) StoreAttribute(f *os.File, bucket, object, attribute string, value []byte) error {
	c.lastMethod, c.lastBucket, c.lastObject, c.lastAttr, c.lastValue, c.lastFile = "StoreAttribute", bucket, object, attribute, value, f
	return c.err
}

func (c *captureMeta) DeleteAttribute(bucket, object, attribute string) error {
	c.lastMethod, c.lastBucket, c.lastObject, c.lastAttr = "DeleteAttribute", bucket, object, attribute
	return c.err
}

func (c *captureMeta) ListAttributes(bucket, object string) ([]string, error) {
	c.lastMethod, c.lastBucket, c.lastObject = "ListAttributes", bucket, object
	if c.err != nil {
		return nil, c.err
	}
	return []string{"a"}, nil
}

func (c *captureMeta) DeleteAttributes(bucket, object string) error {
	c.lastMethod, c.lastBucket, c.lastObject = "DeleteAttributes", bucket, object
	return c.err
}

func (c *captureMeta) RenameObject(bucket, oldObject, newObject string) error {
	c.lastMethod, c.lastBucket, c.lastObject = "RenameObject", bucket, oldObject+"->"+newObject
	return c.err
}

var _ meta.MetadataStorer = (*captureMeta)(nil)

func TestPathRelStorerRewritesAbsUnderRoot(t *testing.T) {
	inner := &captureMeta{}
	s := NewPathRelStorer(inner, "/srv/data")

	const in = "/srv/data/bkt/dir/obj.bin"
	const want = "bkt/dir/obj.bin"

	if _, err := s.RetrieveAttribute(nil, in, "", "hsm-offline"); err != nil {
		t.Fatal(err)
	}
	if inner.lastBucket != want {
		t.Fatalf("RetrieveAttribute bucket = %q, want %q", inner.lastBucket, want)
	}
	if err := s.StoreAttribute(nil, in, "", "hsm-loc", []byte("l")); err != nil {
		t.Fatal(err)
	}
	if inner.lastBucket != want {
		t.Fatalf("StoreAttribute bucket = %q, want %q", inner.lastBucket, want)
	}
	if err := s.DeleteAttribute(in, "", "hsm-loc"); err != nil {
		t.Fatal(err)
	}
	if inner.lastBucket != want {
		t.Fatalf("DeleteAttribute bucket = %q, want %q", inner.lastBucket, want)
	}
	if _, err := s.ListAttributes(in, ""); err != nil {
		t.Fatal(err)
	}
	if inner.lastBucket != want {
		t.Fatalf("ListAttributes bucket = %q, want %q", inner.lastBucket, want)
	}
	if err := s.DeleteAttributes(in, ""); err != nil {
		t.Fatal(err)
	}
	if inner.lastBucket != want {
		t.Fatalf("DeleteAttributes bucket = %q, want %q", inner.lastBucket, want)
	}
	if err := s.RenameObject(in, "a", "b"); err != nil {
		t.Fatal(err)
	}
	if inner.lastBucket != want {
		t.Fatalf("RenameObject bucket = %q, want %q", inner.lastBucket, want)
	}
}

func TestPathRelStorerPassThrough(t *testing.T) {
	inner := &captureMeta{}
	s := NewPathRelStorer(inner, "/srv/data")

	passThrough := []string{
		"bkt",               // plain bucket name (gateway-style)
		"/other/dir/obj",    // absolute but outside root (versioning dir)
		"/srv/data-other/x", // prefix match without separator must NOT trigger
		"",
	}
	for _, in := range passThrough {
		if err := s.StoreAttribute(nil, in, "", "k", []byte("v")); err != nil {
			t.Fatal(err)
		}
		if inner.lastBucket != in {
			t.Fatalf("StoreAttribute(%q): delegate bucket = %q, want unchanged", in, inner.lastBucket)
		}
	}
}

func TestPathRelStorerPreservesOtherArgs(t *testing.T) {
	inner := &captureMeta{}
	s := NewPathRelStorer(inner, "/srv/data")

	f := &os.File{} // identity check only; never read
	if err := s.StoreAttribute(f, "/srv/data/bkt/o", "sub", "attr", []byte("val")); err != nil {
		t.Fatal(err)
	}
	if inner.lastFile != f {
		t.Fatal("file handle not passed through")
	}
	if inner.lastObject != "sub" {
		t.Fatalf("object = %q, want %q", inner.lastObject, "sub")
	}
	if inner.lastAttr != "attr" || string(inner.lastValue) != "val" {
		t.Fatalf("attr/value mangled: %q %q", inner.lastAttr, inner.lastValue)
	}
}

func TestPathRelStorerDelegatesErrors(t *testing.T) {
	want := errors.New("boom")
	inner := &captureMeta{err: want}
	s := NewPathRelStorer(inner, "/srv/data")
	if _, err := s.RetrieveAttribute(nil, "/srv/data/b/o", "", "k"); !errors.Is(err, want) {
		t.Fatalf("RetrieveAttribute err = %v, want %v", err, want)
	}
	if err := s.StoreAttribute(nil, "/srv/data/b/o", "", "k", nil); !errors.Is(err, want) {
		t.Fatalf("StoreAttribute err = %v, want %v", err, want)
	}
}
