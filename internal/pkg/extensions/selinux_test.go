// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extensions_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/pkg/extensions"
	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
)

// TestCompileSELinuxPolicy checks that the modules of the extension services compile with the policy sources, and that
// machined reads back what the imager wrote.
func TestCompileSELinuxPolicy(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("secilc"); err != nil {
		t.Skip("secilc is missing")
	}

	modules := []extgen.Module{
		{
			Name:     "agent",
			Type:     "ext_agent_t",
			Content:  "(type ext_agent_t)\n(call ext_domain (ext_agent_t))\n",
			Labels:   map[string]string{"/var/lib/agent": "ext_agent_state_t"},
			Warnings: []string{"no rule derived for the mount source /mnt/data"},
		},
	}

	policyDir := t.TempDir()

	require.NoError(t, extensions.CompileSELinuxPolicy(t.Context(), modules, "../selinux/policy/selinux", policyDir))

	policy, err := os.ReadFile(filepath.Join(policyDir, filepath.Base(selinux.ImagePolicy)))
	require.NoError(t, err)
	assert.NotEmpty(t, policy)

	read, err := extgen.ReadModules(filepath.Join(policyDir, filepath.Base(selinux.ExtensionModulesDir)))
	require.NoError(t, err)
	assert.Equal(t, modules, read)

	// a module the policy refuses fails the build
	modules[0].Content = "(allow ext_agent_t nonexistent_t (file (read)))\n"

	assert.Error(t, extensions.CompileSELinuxPolicy(t.Context(), modules, "../selinux/policy/selinux", t.TempDir()))
}
