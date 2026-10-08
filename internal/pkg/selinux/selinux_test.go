// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package selinux_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/pkg/selinux"
)

// TestCompile compiles the policy sources shipped in the rootfs with modules, the way machined does for SELinuxPolicyConfig.
//
// A neverallow on a rule of the base policy fails to compile, which proves the rule exists without a policy query tool.
func TestCompile(t *testing.T) {
	if _, err := os.Stat("/usr/bin/secilc"); err != nil {
		t.Skip("secilc and the policy sources are only available in the Talos rootfs")
	}

	for _, test := range []struct {
		name, module, wantErr string
	}{
		{
			"modules built on the macros",
			"(type pod_hostmon_t)\n(call pod_hostmon_domain (pod_hostmon_t))\n(type pod_cni_t)\n(call pod_privileged_domain (pod_cni_t))\n",
			"",
		},
		{
			"STATE stays out of reach of every pod domain",
			"(type pod_evil_t)\n(call pod_domain (pod_evil_t))\n(allow pod_evil_t system_state_t (fs_classes (ro)))\n",
			"neverallow check failed",
		},
		{
			"the kubelet relabels its plugin directories from pod_file_t at every start",
			"(neverallow kubelet_t pod_file_t (dir (relabelfrom relabelto)))\n",
			"neverallow check failed",
		},
		{
			"a domain the CRI starts outside the macros is a workload all the same",
			"(type x_t)\n(call pod_p (x_t))\n",
			"neverallow check failed",
		},
		{
			"a pod domain has the rights of pod_t, NFS volumes included",
			"(type pod_nfs_t)\n(call pod_domain (pod_nfs_t))\n(neverallow pod_nfs_t network_fs_t (file (write)))\n",
			"neverallow check failed",
		},
		{
			"extension domains built on the macros",
			"(type ext_custom_t)\n(call ext_domain (ext_custom_t))\n(type ext_wide_t)\n(call ext_privileged_domain (ext_wide_t))\n" +
				"(type ext_custom_state_t)\n(call ext_state_f (ext_custom_state_t))\n(allow ext_custom_t ext_custom_state_t (fs_classes (rw)))\n",
			"",
		},
		{
			"STATE stays out of reach of every extension domain",
			"(type ext_evil_t)\n(call ext_domain (ext_evil_t))\n(allow ext_evil_t system_state_t (fs_classes (ro)))\n",
			"neverallow check failed",
		},
		{
			"no pod reads the state of an extension, privileged or not",
			"(neverallow pod_p ext_state_t (file (read)))\n(neverallow pod_p ext_run_t (file (read)))\n",
			"",
		},
		{
			"the system containerd prepares the rootfs of a service, the service executes from it and does not write it",
			"(neverallow ext_t ext_rootfs_t (file (write)))\n(neverallow pod_p ext_rootfs_t (file (read)))\n" +
				"(neverallow sys_containerd_t ext_rootfs_t (dir (write)))\n",
			"neverallow check failed",
		},
		{
			"machined mounts the rootfs: a service uses the files overlayfs opens with the credentials of machined",
			"(neverallow ext_t init_t (fd (use)))\n",
			"neverallow check failed",
		},
		{
			"the entrypoint of a service may be a binary of the host its spec mounts",
			"(neverallow ext_t usr_t (file (entrypoint)))\n",
			"neverallow check failed",
		},
		{
			"the default extension profile reaches its state but not the host state",
			"(neverallow ext_t ext_state_t (file (write)))\n",
			"neverallow check failed",
		},
		{
			"the base profiles reach the state of every service through the attribute, a derived type its own only",
			"(type ext_x_state_t)\n(call ext_state_f (ext_x_state_t))\n(type ext_y_t)\n(call ext_domain (ext_y_t))\n" +
				"(neverallow ext_y_t ext_x_state_t (file (read)))\n(neverallow ext_privileged_t ext_x_state_t (file (read)))\n",
			"neverallow check failed",
		},
		{
			"an unknown type is reported with the module and the line",
			"(allow pod_t nonexistent_t (file (read)))\n",
			"module.cil:1",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := selinux.Compile(t.Context(), map[string]string{"module": test.module})

			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}
		})
	}
}

// TestSetLabelRecursive labels the directory last: its label tells the whole tree carries it.
func TestSetLabelRecursive(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a", "b", "c"), nil, 0o644))

	var labeled []string

	selinux.IsEnabled = func() bool { return true }

	selinux.SetLabelFunc(func(path, label string, _ ...string) error {
		labeled = append(labeled, path)

		return nil
	})

	require.NoError(t, selinux.SetLabelRecursive(root, "system_u:object_r:ext_x_state_t:s0"))
	assert.Equal(t, []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b"), filepath.Join(root, "a", "b", "c"), root}, labeled)
}
