// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package fcontext_test

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/internal/pkg/selinux/fcontext"
)

func TestLookup(t *testing.T) {
	rules, err := selinux.FileContextRules()
	require.NoError(t, err)

	for path, want := range map[string]string{
		// exact entries
		"/usr/bin/init": "init_exec_t",
		"/usr/bin/runc": "containerd_exec_t",
		// the last matching entry wins
		"/usr/bin/foo":                                      "bin_exec_t",
		"/usr/lib/modules/somemod.ko":                       "module_t",
		"/usr/lib/udev/ata_id":                              "udev_exec_t",
		"/usr/lib/udev/hwdb.bin":                            "udev_hwdb_t",
		"/usr/lib/udev/hwdb.d/20-OUI.hwdb":                  "lib_t",
		"/usr/lib/udev/rules.d/99-talos.rules":              "udev_rules_t",
		"/usr/local/lib/kubelet/credentialproviders/ecr":    "k8s_credentialproviders_t",
		"/usr/local/lib/containers/hello-world/hello-world": "usr_t",
		"/etc/cri/conf.d/00-foo.part":                       "etc_t",
		"/etc/cni/00-foo.conf":                              "cni_conf_t",
	} {
		assert.Equal(t, "system_u:object_r:"+want+":s0", fcontext.Lookup(rules, path, fcontext.TypeReg), path)
	}

	// a type spec restricts the entry to its file type: the directory keeps the generic label
	assert.Equal(t, "system_u:object_r:lib_t:s0", fcontext.Lookup(rules, "/usr/lib/udev/foo", fcontext.TypeDir))
	assert.Equal(t, "system_u:object_r:rootfs_t:s0", fcontext.Lookup(rules, "/", fcontext.FileTypeOf(fs.ModeDir)))
	assert.Empty(t, fcontext.Lookup(rules, "/var/lib/foo", fcontext.TypeDir))
}
