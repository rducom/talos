// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extgen_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
)

// TestStateKind: a state directory is never a mount point of the host nor a directory Talos labels itself.
func TestStateKind(t *testing.T) {
	t.Parallel()

	for source, want := range map[string]extgen.Kind{
		"/var/lib/tailscale":              extgen.KindState,
		"/var/log/netbird":                extgen.KindState,
		"/var/cache/nvidia-fabricmanager": extgen.KindState,
		"/var/run/tailscale":              extgen.KindRun,
		"/run/hyperv-kvp":                 extgen.KindRun,
		"/run/rpcbind/":                   extgen.KindRun,
		"/var":                            extgen.KindOther,
		"/var/lib":                        extgen.KindOther,
		"/run":                            extgen.KindOther,
		"/var/mnt/fscache":                extgen.KindOther,
		"/var/lib/kubelet":                extgen.KindOther,
		"/var/lib/kubelet/plugins":        extgen.KindOther,
		"/var/lib/containerd/io.containerd.snapshotter.v1.soci": extgen.KindOther,
		"/var/log/containers":               extgen.KindOther,
		"/var/log/audit/kube":               extgen.KindOther,
		"/run/lock/iscsi":                   extgen.KindOther,
		"/run/udev":                         extgen.KindOther,
		"/dev/net/tun":                      extgen.KindOther,
		"/system/run/machined/machine.sock": extgen.KindOther,
	} {
		assert.Equal(t, want, extgen.StateKind(source), source)
	}
}
