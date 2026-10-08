// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package selinux_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/pkg/selinux"
)

// TestParseAccessVector parses an answer observed on a node: auditallow getattr, open and read on a file.
func TestParseAccessVector(t *testing.T) {
	av, err := selinux.ParseAccessVector("8f82b38 ffffffff 2820 ffffffff 2 0")
	require.NoError(t, err)
	assert.Equal(t, selinux.AccessVector{Allowed: 0x8f82b38, Seqno: 2}, av)
}

func TestTypes(t *testing.T) {
	assert.Equal(t, []string{"ext_t", "pod_t"}, selinux.Types("(type pod_t)\n  (typealias spc_t)\n(typealiasactual spc_t pod_t)\n", "(type ext_t)\n(typeattribute any_p)\n(type pod_t)\n"))
}
