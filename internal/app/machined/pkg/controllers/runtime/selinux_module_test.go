// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/siderolabs/talos/internal/app/machined/pkg/controllers/ctest"
	runtimecontrollers "github.com/siderolabs/talos/internal/app/machined/pkg/controllers/runtime"
	"github.com/siderolabs/talos/pkg/machinery/config/container"
	runtimeconfig "github.com/siderolabs/talos/pkg/machinery/config/types/runtime"
	"github.com/siderolabs/talos/pkg/machinery/resources/config"
	runtimeres "github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

type SELinuxModuleSuite struct {
	ctest.DefaultSuite
}

func TestSELinuxModuleSuite(t *testing.T) {
	suite.Run(t, &SELinuxModuleSuite{
		DefaultSuite: ctest.DefaultSuite{
			AfterSetup: func(suite *ctest.DefaultSuite) {
				suite.Require().NoError(suite.Runtime().RegisterController(&runtimecontrollers.SELinuxModuleConfigController{}))
				suite.Require().NoError(suite.Runtime().RegisterController(&runtimecontrollers.ExtensionSELinuxModuleController{ConfigPath: "testdata/extservices/"}))
			},
		},
	})
}

// TestModules checks the modules of the machine config and of the extension services.
func (suite *SELinuxModuleSuite) TestModules() {
	policy := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("hostmon")
	policy.PolicyContent = "(type pod_hostmon_t)\n"

	cfg, err := container.New(policy)
	suite.Require().NoError(err)

	suite.Create(config.NewMachineConfig(cfg))

	ctest.AssertResource(suite, "config-hostmon", func(module *runtimeres.SELinuxModule, asrt *assert.Assertions) {
		asrt.Equal("(type pod_hostmon_t)\n", module.TypedSpec().Content)
	})

	// the host service gets no module, the container service gets its derived one
	ctest.AssertResource(suite, "ext-hello-world", func(module *runtimeres.SELinuxModule, asrt *assert.Assertions) {
		asrt.Equal("(type ext_hello_world_t)\n(call ext_domain (ext_hello_world_t))\n", module.TypedSpec().Content)
		asrt.Equal("ext_hello_world_t", module.TypedSpec().Type)
	})
	ctest.AssertNoResource[*runtimeres.SELinuxModule](suite, "ext-frr")

	machineConfig := config.NewMachineConfig(cfg)
	suite.Destroy(machineConfig)

	ctest.AssertNoResource[*runtimeres.SELinuxModule](suite, "config-hostmon")
}
