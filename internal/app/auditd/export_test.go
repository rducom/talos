// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package auditd

import (
	"context"
	"time"

	"github.com/cosi-project/runtime/pkg/state"
)

// AVC exposes avc for tests.
type AVC = avc

// ParseAVC exposes parseAVC for tests.
var ParseAVC = parseAVC

// AccessLogger exposes accessLogger for tests.
type AccessLogger = accessLogger

// NewAccessLogger exposes newAccessLogger for tests.
func NewAccessLogger(st state.State) *AccessLogger {
	return newAccessLogger(st)
}

// Record exposes record for tests.
func (l *AccessLogger) Record(record AVC, now time.Time) {
	l.record(record, now)
}

// SetLost exposes setLost for tests.
func (l *AccessLogger) SetLost(lost uint64) {
	l.setLost(lost)
}

// Flush exposes flush for tests.
func (l *AccessLogger) Flush(ctx context.Context) error {
	return l.flush(ctx)
}
