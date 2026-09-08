// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/siderolabs/talos/internal/app/machined/pkg/controllers/ctest"
	runtimecontrollers "github.com/siderolabs/talos/internal/app/machined/pkg/controllers/runtime"
	runtimeres "github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

type SELinuxPolicySuite struct {
	ctest.DefaultSuite
}

func TestSELinuxPolicySuite(t *testing.T) {
	suite.Run(t, &SELinuxPolicySuite{
		DefaultSuite: ctest.DefaultSuite{
			AfterSetup: func(suite *ctest.DefaultSuite) {
				suite.Require().NoError(suite.Runtime().RegisterController(&runtimecontrollers.SELinuxPolicyController{
					// a module saying so is rejected, and so is a module needing another one absent from the set
					Compile: func(_ context.Context, modules map[string]string) ([]byte, error) {
						for id, content := range modules {
							if strings.Contains(content, "bad") {
								return nil, errors.New("secilc: " + id + " rejected")
							}

							if _, needs, ok := strings.Cut(content, "needs "); ok {
								if _, present := modules[strings.TrimSpace(needs)]; !present {
									return nil, errors.New("secilc: " + id + " needs " + needs)
								}
							}
						}

						return []byte("policy"), nil
					},
					Load: func([]byte) error { return nil },
				}))
			},
		},
	})
}

func (suite *SELinuxPolicySuite) module(id, content string) *runtimeres.SELinuxModule {
	module := runtimeres.NewSELinuxModule(id)
	module.TypedSpec().Content = content
	suite.Create(module)

	return module
}

// TestRejectedModules: a module the compile rejects is left out and the others load, whatever the order the compile
// needs them in; the status lists the modules present, the ones loaded, and the rejected ones with their errors, until
// they change.
func (suite *SELinuxPolicySuite) TestRejectedModules() {
	suite.module("config-good", "(type pod_good_t)\n")

	ctest.AssertResource(suite, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Equal([]string{"config-good"}, status.TypedSpec().Modules)
		asrt.Equal([]string{"config-good"}, status.TypedSpec().Loaded)
		asrt.Empty(status.TypedSpec().Error)
	})

	bad := suite.module("config-bad", "(type bad_t)\n")

	// config-a-extra needs config-z-base, which the name order compiles after it
	suite.module("config-a-extra", "needs config-z-base\n")
	suite.module("config-z-base", "(type pod_z_t)\n")

	ctest.AssertResource(suite, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Equal([]string{"config-a-extra", "config-bad", "config-good", "config-z-base"}, status.TypedSpec().Modules)
		asrt.Equal([]string{"config-a-extra", "config-good", "config-z-base"}, status.TypedSpec().Loaded)
		asrt.Equal("module config-bad rejected: secilc: config-bad rejected", status.TypedSpec().Error)
	})

	suite.Destroy(bad)

	ctest.AssertResource(suite, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Equal([]string{"config-a-extra", "config-good", "config-z-base"}, status.TypedSpec().Modules)
		asrt.Equal(status.TypedSpec().Modules, status.TypedSpec().Loaded)
		asrt.Empty(status.TypedSpec().Error)
	})
}
