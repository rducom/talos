// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package auditd

import (
	"cmp"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/cosi-project/runtime/pkg/state"

	"github.com/siderolabs/talos/internal/pkg/selinux/fcontext"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// avc is one AVC record of the kernel.
type avc struct {
	granted    bool
	perms      []string
	source     string
	target     string
	class      string
	permissive bool
	comm       string
	path       string
}

var avcRe = regexp.MustCompile(`(?:^|\s)avc:\s+(denied|granted)\s+\{ ([^}]*) \} for\s+(.*)$`)

// parseAVC parses an AVC record, such as:
//
//	audit(1788848806.164:7): avc:  denied  { execute } for  pid=1 comm="runc:[2:INIT]" path="/hello-world" dev="overlay" ino=6
//	scontext=system_u:system_r:sys_containerd_t:s0 tcontext=system_u:object_r:unlabeled_t:s0 tclass=file permissive=0
func parseAVC(msg string) (avc, bool) {
	match := avcRe.FindStringSubmatch(msg)
	if match == nil {
		return avc{}, false
	}

	fields := map[string]string{}

	for field := range strings.FieldsSeq(match[3]) {
		if key, value, ok := strings.Cut(field, "="); ok {
			fields[key] = strings.Trim(value, `"`)
		}
	}

	record := avc{
		granted:    match[1] == "granted",
		perms:      strings.Fields(match[2]),
		source:     fcontext.TypeOf(fields["scontext"]),
		target:     fcontext.TypeOf(fields["tcontext"]),
		class:      fields["tclass"],
		permissive: fields["permissive"] == "1",
		comm:       fields["comm"],
		path:       cmp.Or(fields["path"], fields["name"]),
	}

	return record, record.source != "" && record.target != "" && record.class != "" && len(record.perms) > 0
}

// String renders the record for the logs and the tests.
func (record avc) String() string {
	decision := "denied"
	if record.granted {
		decision = "granted"
	}

	return fmt.Sprintf("%s %s %s %s %s permissive=%t comm=%s path=%s", decision, strings.Join(record.perms, " "),
		record.source, record.target, record.class, record.permissive, record.comm, record.path)
}

// accessLogLimit is the number of distinct accesses a log keeps per list.
const accessLogLimit = 2048

// accessLogger aggregates the AVC records by source domain and publishes them as SELinuxAccessLog resources.
type accessLogger struct {
	mu sync.Mutex

	st    state.State
	logs  map[string]*accessLog
	dirty map[string]struct{}
	lost  uint64
}

type accessLog struct {
	denied    map[string]*runtime.SELinuxAccess
	granted   map[string]*runtime.SELinuxAccess
	truncated bool
}

func newAccessLogger(st state.State) *accessLogger {
	return &accessLogger{st: st, logs: map[string]*accessLog{}, dirty: map[string]struct{}{}}
}

func (l *accessLogger) record(rec avc, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	log, ok := l.logs[rec.source]
	if !ok {
		log = &accessLog{denied: map[string]*runtime.SELinuxAccess{}, granted: map[string]*runtime.SELinuxAccess{}}
		l.logs[rec.source] = log
	}

	set := log.denied
	if rec.granted {
		set = log.granted
	}

	for _, perm := range rec.perms {
		key := rec.target + "|" + rec.class + "|" + perm

		access, ok := set[key]
		if !ok {
			if len(set) >= accessLogLimit {
				log.truncated = true

				continue
			}

			access = &runtime.SELinuxAccess{Target: rec.target, Class: rec.class, Permission: perm, First: now}
			set[key] = access
		}

		access.Count++
		access.Last = now
		access.Permissive = rec.permissive
		access.Comm = rec.comm
		access.Path = rec.path
	}

	l.dirty[rec.source] = struct{}{}
}

func (l *accessLogger) setLost(lost uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if lost != l.lost {
		l.lost = lost

		for id := range l.logs {
			l.dirty[id] = struct{}{}
		}
	}
}

// flush publishes the logs which changed since the last flush.
func (l *accessLogger) flush(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	for id := range l.dirty {
		log := l.logs[id]
		spec := runtime.SELinuxAccessLogSpec{Denied: sortedAccesses(log.denied), Granted: sortedAccesses(log.granted), Lost: l.lost, Truncated: log.truncated}

		if err := safe.StateModify(ctx, l.st, runtime.NewSELinuxAccessLog(id), func(res *runtime.SELinuxAccessLog) error {
			*res.TypedSpec() = spec

			return nil
		}); err != nil {
			return err
		}

		delete(l.dirty, id)
	}

	return nil
}

func sortedAccesses(set map[string]*runtime.SELinuxAccess) []runtime.SELinuxAccess {
	if len(set) == 0 {
		return nil
	}

	accesses := make([]runtime.SELinuxAccess, 0, len(set))

	for _, access := range set {
		accesses = append(accesses, *access)
	}

	slices.SortFunc(accesses, runtime.CompareSELinuxAccess)

	return accesses
}
