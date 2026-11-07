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

// TestBootPolicy: init loads the policy the imager compiled with the extension services, or the base policy without one.
func TestBootPolicy(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "policy.33")

	base, err := selinux.BootPolicy(path)
	require.NoError(t, err)
	assert.NotEmpty(t, base)

	require.NoError(t, os.WriteFile(path, []byte("image policy"), 0o644))

	image, err := selinux.BootPolicy(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("image policy"), image)
}
