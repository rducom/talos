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
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
	runtimeres "github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

type SELinuxModuleSuite struct {
	ctest.DefaultSuite
}

func TestSELinuxModuleSuite(t *testing.T) {
	suite.Run(t, &SELinuxModuleSuite{
		AfterSetup: func(suite *ctest.DefaultSuite) {
			// the modules the imager derived and wrote to the image
			modulesPath := suite.T().TempDir()
			suite.Require().NoError(extgen.WriteModules(modulesPath, []extgen.Module{
				{
					Name: "hello-world", Type: "ext_hello_world_t", Content: "(type ext_hello_world_t)\n(call ext_domain (ext_hello_world_t))\n",
					Labels: map[string]string{"/var/lib/hello": "ext_hello_world_state_t"},
				},
			}))

			suite.Require().NoError(suite.Runtime().RegisterController(&runtimecontrollers.ExtensionSELinuxModuleController{ModulesPath: modulesPath}))
		},
	})
}

// TestModules checks the modules the imager derived for the extension services.
func (suite *SELinuxModuleSuite) TestModules() {
	ctest.AssertResource(suite, "ext-hello-world", func(module *runtimeres.SELinuxModule, asrt *assert.Assertions) {
		asrt.Equal("(type ext_hello_world_t)\n(call ext_domain (ext_hello_world_t))\n", module.TypedSpec().Content)
		asrt.Equal("ext_hello_world_t", module.TypedSpec().Type)
		asrt.Equal(map[string]string{"/var/lib/hello": "ext_hello_world_state_t"}, module.TypedSpec().Labels)
	})
}
