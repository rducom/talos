// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package auditd_test

import (
	"testing"
	"time"

	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/cosi-project/runtime/pkg/state/impl/inmem"
	"github.com/cosi-project/runtime/pkg/state/impl/namespaced"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/app/auditd"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// records observed on a node, as auditd receives them: denials in enforcing and permissive mode, then a record of an
// auditallow rule and a denial in the same domain.
const (
	deniedExecute = `audit(1788848806.164:7): avc:  denied  { execute } for  pid=2140 comm="runc:[2:INIT]" path="/hello-world" dev="overlay" ino=6 ` +
		`scontext=system_u:system_r:sys_containerd_t:s0 tcontext=system_u:object_r:unlabeled_t:s0 tclass=file permissive=0`
	deniedReadOpen = `audit(1788848811.203:23): avc:  denied  { read open } for  pid=187 comm="hello-world" name="hello-world" dev="overlay" ino=6 ` +
		`scontext=system_u:system_r:unconfined_container_t:s0 tcontext=system_u:object_r:unlabeled_t:s0 tclass=file permissive=1`
	grantedSearch = `audit(1788849744.539:3311): avc:  granted  { search } for  pid=3212 comm="cat" name="kubernetes" dev="tmpfs" ino=2 ` +
		`scontext=system_u:system_r:pod_t:s0:c233,c506 tcontext=system_u:object_r:k8s_conf_t:s0 tclass=dir`
	deniedWrite = `audit(1788849745.102:3312): avc:  denied  { write } for  pid=3212 comm="cat" name="kubernetes" dev="tmpfs" ino=2 ` +
		`scontext=system_u:system_r:pod_t:s0:c233,c506 tcontext=system_u:object_r:k8s_conf_t:s0 tclass=dir permissive=0`
)

func TestParseAVC(t *testing.T) {
	record, ok := auditd.ParseAVC(deniedReadOpen)
	require.True(t, ok)
	assert.Equal(t, "denied read open unconfined_container_t unlabeled_t file comm=hello-world path=hello-world", record.String())

	record, ok = auditd.ParseAVC(grantedSearch)
	require.True(t, ok)
	assert.Equal(t, "granted search pod_t k8s_conf_t dir comm=cat path=kubernetes", record.String())

	_, ok = auditd.ParseAVC(`audit(1757300000.000:12): op=load_policy lsm=selinux seqno=3 res=1`)
	assert.False(t, ok)
}

func TestAccessLogger(t *testing.T) {
	st := state.WrapCore(namespaced.NewState(inmem.Build))
	logger := auditd.NewAccessLogger(st)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	for i, msg := range []string{deniedExecute, deniedReadOpen, deniedReadOpen, grantedSearch, deniedWrite} {
		record, ok := auditd.ParseAVC(msg)
		require.True(t, ok)

		logger.Record(record, now.Add(time.Duration(i)*time.Second))
	}

	logger.SetLost(7)

	require.NoError(t, logger.Flush(t.Context()))

	// a domain no audit module observes has no granted record: its denials stay in the audit log
	for _, id := range []string{"sys_containerd_t", "unconfined_container_t"} {
		_, err := safe.StateGetByID[*runtime.SELinuxAccessLog](t.Context(), st, id)
		assert.True(t, state.IsNotFoundError(err), id)
	}

	log, err := safe.StateGetByID[*runtime.SELinuxAccessLog](t.Context(), st, "pod_t")
	require.NoError(t, err)
	assert.Equal(t, runtime.SELinuxAccessLogSpec{
		Denied:  []runtime.SELinuxAccess{{Target: "k8s_conf_t", Class: "dir", Permission: "write", Last: now.Add(4 * time.Second), Comm: "cat", Path: "kubernetes"}},
		Granted: []runtime.SELinuxAccess{{Target: "k8s_conf_t", Class: "dir", Permission: "search", Last: now.Add(3 * time.Second), Comm: "cat", Path: "kubernetes"}},
		Lost:    7,
	}, *log.TypedSpec())
}
