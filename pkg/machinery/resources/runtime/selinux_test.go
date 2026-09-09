// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime_test

import (
	"context"
	"testing"
	"time"

	"github.com/cosi-project/runtime/pkg/state"
	"github.com/cosi-project/runtime/pkg/state/impl/inmem"
	"github.com/cosi-project/runtime/pkg/state/impl/namespaced"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// TestSELinuxPolicyCondition: the condition holds once the status lists every requested module, loaded or rejected.
func TestSELinuxPolicyCondition(t *testing.T) {
	t.Parallel()

	st := state.WrapCore(namespaced.NewState(inmem.Build))

	status := runtime.NewSELinuxPolicyStatus()
	status.TypedSpec().Modules = []string{"config-hostmon", "ext-hello-world"}
	status.TypedSpec().Error = "rejected"
	require.NoError(t, st.Create(t.Context(), status))

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	assert.NoError(t, runtime.NewSELinuxPolicyCondition(st, []string{"ext-hello-world"}).Wait(ctx))
	assert.NoError(t, runtime.NewSELinuxPolicyCondition(st, nil).Wait(ctx))
	assert.ErrorIs(t, runtime.NewSELinuxPolicyCondition(st, []string{"ext-hello-world", "ext-tailscale"}).Wait(ctx), context.DeadlineExceeded)

	// a type is checked at every change of the status, until the policy defines it
	defined := func(typ string) bool { return typ == "ext_custom_t" }

	ctx, cancel = context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	assert.NoError(t, runtime.NewSELinuxPolicyCondition(st, []string{"ext-hello-world"}).WithType("ext_custom_t", defined).Wait(ctx))
	assert.Equal(t, "selinux policy modules ext-hello-world, selinux type ext_custom_t", runtime.NewSELinuxPolicyCondition(st, []string{"ext-hello-world"}).WithType("ext_custom_t", defined).String())
	assert.ErrorIs(t, runtime.NewSELinuxPolicyCondition(st, []string{"ext-hello-world"}).WithType("ext_unknown_t", defined).Wait(ctx), context.DeadlineExceeded)
}
