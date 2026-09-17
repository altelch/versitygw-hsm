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

package posixhsm

import (
	"context"
	"fmt"
	"io"
)

// BareosOpts is the configuration surface for a Bareos-backed HsmDriver.
// See the driver implementation notes for which fields gate the physical
// operations (a full Bareos round-trip requires a live Bareos instance + the
// bareos-client `bconsole`/`bareos-restore` tools and must be verified
// against the exact target Bareos version before production use).
type BareosOpts struct {
	// Console is the bconsole endpoint host:port, e.g. "127.0.0.1:913".
	Console string
	// Pool is the Bareos pool used by archive jobs.
	Pool string
	// Drive is the Bareos drive label assigned to jobs.
	Drive string
}

// BareosHsmDriver is a placeholder HsmDriver for the Bareos target. It
// satisfies the HsmDriver contract and reports its identity, but the data
// operations return a descriptive error until a bareos-client-based
// implementation (bconsole batch archive + bareos-restore) has been written
// and verified against a live Bareos instance.
//
// This keeps the posix-hsm pipeline (state, queue, daemon, mock driver) fully
// functional and testable today; production deployments select the bareos
// driver and receive a clear, actionable failure rather than a silent
// no-op.
type BareosHsmDriver struct {
	opts BareosOpts
}

var _ HsmDriver = (*BareosHsmDriver)(nil)

// NewBareosDriver validates opts and returns a BareosHsmDriver.
func NewBareosDriver(o BareosOpts) (*BareosHsmDriver, error) {
	if o.Console == "" {
		return nil, fmt.Errorf("bareos driver: --bareos-console host:port is required")
	}
	return &BareosHsmDriver{opts: o}, nil
}

func (d *BareosHsmDriver) Name() string { return "bareos" }

func (d *BareosHsmDriver) notYet() error {
	return fmt.Errorf("bareos driver: data operations are not yet implemented against the live Bareos instance %q (verified-bareos round-trip pending)", d.opts.Console)
}

func (d *BareosHsmDriver) ArchiveWave(_ context.Context, _ []WaveFile) ([]string, error) {
	return nil, d.notYet()
}

func (d *BareosHsmDriver) Restore(_ context.Context, _ string, _ io.Writer, _ int64) error {
	return d.notYet()
}

func (d *BareosHsmDriver) Purge(_ context.Context, _ string) error {
	return d.notYet()
}

func (d *BareosHsmDriver) Close() error { return nil }
