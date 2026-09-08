// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime_test

import (
	"errors"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/siderolabs/talos/internal/app/machined/pkg/controllers/ctest"
	runtimecontrollers "github.com/siderolabs/talos/internal/app/machined/pkg/controllers/runtime"
	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/pkg/machinery/config/container"
	runtimeconfig "github.com/siderolabs/talos/pkg/machinery/config/types/runtime"
	"github.com/siderolabs/talos/pkg/machinery/resources/config"
	runtimeres "github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

type SELinuxAuditSuite struct {
	ctest.DefaultSuite

	now      atomic.Int64
	seqno    atomic.Uint32
	computed atomic.Int64
}

func TestSELinuxAuditSuite(t *testing.T) {
	s := &SELinuxAuditSuite{}
	s.now.Store(time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC).Unix())
	s.seqno.Store(1)

	// a policy of two file types and three domains: ext_hello_world_t reads and opens a_t files and searches b_t directories,
	// pod_x_t searches b_t directories and the directories of pod_y_t, a domain of a module
	classes := map[string]selinux.Class{
		"file": {Index: 6, Perms: map[string]uint32{"read": 1, "write": 2, "open": 4}},
		"dir":  {Index: 7, Perms: map[string]uint32{"search": 1, "write": 2}},
	}

	allowed := map[string]uint32{
		"ext_hello_world_t a_t 6": 5,
		"ext_hello_world_t b_t 7": 1,
		"pod_x_t b_t 7":           1,
		"pod_x_t pod_y_t 7":       1,
	}

	domains := []string{"ext_hello_world_t", "pod_x_t", "pod_y_t", "ext_t", "init_t"}

	s.DefaultSuite = ctest.DefaultSuite{
		AfterSetup: func(suite *ctest.DefaultSuite) {
			suite.Require().NoError(suite.Runtime().RegisterController(&runtimecontrollers.SELinuxAuditController{
				Classes: func() (map[string]selinux.Class, error) { return classes, nil },
				PolicySources: func() (string, error) {
					return "(type a_t)\n(type b_t)\n(type ext_hello_world_t)\n(type pod_x_t)\n", nil
				},
				Now: func() time.Time { return time.Unix(s.now.Load(), 0).UTC() },
				CheckContext: func(label string) error {
					if slices.Contains(domains, strings.Split(label, ":")[2]) {
						return nil
					}

					return errors.New("invalid context")
				},
				ComputeAV: func(scon, tcon string, class uint16) (selinux.AccessVector, error) {
					source, target := strings.Split(scon, ":")[2], strings.Split(tcon, ":")[2]

					if source != "init_t" {
						s.computed.Add(1)
					}

					return selinux.AccessVector{Allowed: allowed[source+" "+target+" "+string(rune('0'+class))], Seqno: s.seqno.Load()}, nil
				},
			}))
		},
	}

	suite.Run(t, s)
}

// TestAudit follows the audit of an extension domain: the module of the first round audits every granted access, the
// observed accesses leave the module at the next round and enter the narrowed module, denials are suggested as rules, and
// stopping the audit removes the module and the status.
func (suite *SELinuxAuditSuite) TestAudit() {
	cfg := runtimeres.NewExtensionServiceConfigSpec(runtimeres.NamespaceName, "hello-world")
	cfg.TypedSpec().SELinuxAudit = true
	suite.Create(cfg)

	module := runtimeres.NewSELinuxModule("ext-hello-world")
	module.TypedSpec().Type = "ext_hello_world_t"
	suite.Create(module)

	status := runtimeres.NewSELinuxPolicyStatus()
	status.TypedSpec().Modules = []string{"ext-hello-world"}
	status.TypedSpec().Loaded = []string{"ext-hello-world"}
	suite.Create(status)

	ctest.AssertResource(suite, "audit-ext_hello_world_t", func(res *runtimeres.SELinuxModule, asrt *assert.Assertions) {
		asrt.Equal("(auditallow ext_hello_world_t a_t (file (open read)))\n(auditallow ext_hello_world_t b_t (dir (search)))\n", strings.SplitN(res.TypedSpec().Content, "\n", 2)[1])
	})

	ctest.AssertResource(suite, "ext_hello_world_t", func(res *runtimeres.SELinuxDomainStatus, asrt *assert.Assertions) {
		asrt.Equal(uint32(1), res.TypedSpec().Rounds)
		asrt.Len(res.TypedSpec().Unexercised, 3)
		asrt.Empty(res.TypedSpec().Exercised)
		asrt.Equal(time.Unix(suite.now.Load(), 0).UTC(), res.TypedSpec().ObservedSince)
	})

	// a set rejected for another module leaves the service in its domain: the observation goes on
	status.TypedSpec().Modules = []string{"config-bad", "ext-hello-world"}
	status.TypedSpec().Error = "secilc: config-bad rejected"
	suite.Update(status)

	ctest.AssertResource(suite, "ext_hello_world_t", func(res *runtimeres.SELinuxDomainStatus, asrt *assert.Assertions) {
		asrt.Equal(uint32(1), res.TypedSpec().Rounds)
		asrt.Equal(time.Unix(suite.now.Load(), 0).UTC(), res.TypedSpec().ObservedSince)
	})
	ctest.AssertNoResource[*runtimeres.SELinuxDomainStatus](suite, "ext_t")

	status.TypedSpec().Modules = []string{"ext-hello-world"}
	status.TypedSpec().Error = ""
	suite.Update(status)

	// the domain reads a file and gets denied a write; a search and a denial observed before the audit began do not count
	now := time.Unix(suite.now.Load(), 0).UTC()

	log := runtimeres.NewSELinuxAccessLog("ext_hello_world_t")
	log.TypedSpec().Granted = []runtimeres.SELinuxAccess{
		{Target: "a_t", Class: "file", Permission: "read", Count: 4, Last: now, Comm: "hello-world", Path: "/a"},
		{Target: "b_t", Class: "dir", Permission: "search", Count: 1, Last: now.Add(-time.Hour)},
	}
	log.TypedSpec().Denied = []runtimeres.SELinuxAccess{
		{Target: "c_t", Class: "file", Permission: "write", Count: 1, Last: now, Permissive: true, Comm: "hello-world", Path: "/c"},
		{Target: "d_t", Class: "file", Permission: "write", Count: 1, Last: now.Add(-time.Hour)},
	}
	log.TypedSpec().Lost = 3
	log.TypedSpec().Truncated = true
	suite.Create(log)

	ctest.AssertResource(suite, "ext_hello_world_t", func(res *runtimeres.SELinuxDomainStatus, asrt *assert.Assertions) {
		asrt.Len(res.TypedSpec().Exercised, 1)
		asrt.Len(res.TypedSpec().Unexercised, 2)
		asrt.Equal(`(allow ext_hello_world_t c_t (file (write))) ; comm="hello-world" path="/c"`+"\n", res.TypedSpec().SuggestedAllows)
		asrt.Equal(uint64(3), res.TypedSpec().LostRecords)
		// the log dropped accesses: the audit may never converge
		asrt.True(res.TypedSpec().Truncated)
		// less than a minute after the first round: the module waits
		asrt.Equal(uint32(1), res.TypedSpec().Rounds)
	})

	suite.now.Add(61)

	log.TypedSpec().Granted[0].Count++
	suite.Update(log)

	ctest.AssertResource(suite, "audit-ext_hello_world_t", func(res *runtimeres.SELinuxModule, asrt *assert.Assertions) {
		asrt.Equal("(auditallow ext_hello_world_t a_t (file (open)))\n(auditallow ext_hello_world_t b_t (dir (search)))\n", strings.SplitN(res.TypedSpec().Content, "\n", 2)[1])
	})

	ctest.AssertResource(suite, "ext_hello_world_t", func(res *runtimeres.SELinuxDomainStatus, asrt *assert.Assertions) {
		asrt.Equal(uint32(2), res.TypedSpec().Rounds)
		asrt.Equal("(type ext_hello_world_t)\n(call ext_plumbing (ext_hello_world_t))\n(allow ext_hello_world_t a_t (file (read)))\n", res.TypedSpec().NarrowedModule)
	})

	cfg.TypedSpec().SELinuxAudit = false
	suite.Update(cfg)

	ctest.AssertNoResource[*runtimeres.SELinuxModule](suite, "audit-ext_hello_world_t")
	ctest.AssertNoResource[*runtimeres.SELinuxDomainStatus](suite, "ext_hello_world_t")

	// the domains of an audited config module are observed too, without the extension plumbing; its file types are not
	policy := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("x")
	policy.PolicyContent = "(type pod_x_t)\n(call pod_domain (pod_x_t))\n(type x_file_t)\n"
	policy.PolicyAudit = true

	cntr, err := container.New(policy)
	suite.Require().NoError(err)

	suite.Create(config.NewMachineConfig(cntr))

	ctest.AssertResource(suite, "pod_x_t", func(res *runtimeres.SELinuxDomainStatus, asrt *assert.Assertions) {
		asrt.Equal(uint32(1), res.TypedSpec().Rounds)
		asrt.Len(res.TypedSpec().Unexercised, 1)
		asrt.True(strings.HasPrefix(res.TypedSpec().NarrowedModule, "(type pod_x_t)\n; add the plumbing of the domain"))
	})
	ctest.AssertNoResource[*runtimeres.SELinuxDomainStatus](suite, "x_file_t")
	ctest.AssertNoResource[*runtimeres.SELinuxModule](suite, "audit-x_file_t")
}

// TestPolicyChanges: the audit module names the types of the modules present, so a module removed leaves it whatever the
// policy status says, and a policy the kernel reloaded is enumerated again without a round when nothing changed.
func (suite *SELinuxAuditSuite) TestPolicyChanges() {
	y := runtimeres.NewSELinuxModule("config-y")
	y.TypedSpec().Content = "(type pod_y_t)\n(call pod_domain (pod_y_t))\n"
	suite.Create(y)

	status := runtimeres.NewSELinuxPolicyStatus()
	status.TypedSpec().Modules = []string{"config-x", "config-y"}
	status.TypedSpec().Loaded = []string{"config-x", "config-y"}
	suite.Create(status)

	policy := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("x")
	policy.PolicyContent = "(type pod_x_t)\n(call pod_domain (pod_x_t))\n"
	policy.PolicyAudit = true

	cntr, err := container.New(policy)
	suite.Require().NoError(err)

	suite.Create(config.NewMachineConfig(cntr))

	ctest.AssertResource(suite, "audit-pod_x_t", func(res *runtimeres.SELinuxModule, asrt *assert.Assertions) {
		asrt.Equal("(auditallow pod_x_t b_t (dir (search)))\n(auditallow pod_x_t pod_y_t (dir (search)))\n", strings.SplitN(res.TypedSpec().Content, "\n", 2)[1])
	})

	// the document y is removed and the policy controller rejects the set, the audit module still naming pod_y_t
	suite.Destroy(y)

	status.TypedSpec().Modules = []string{"audit-pod_x_t", "config-x"}
	status.TypedSpec().Error = "secilc: Failed to resolve pod_y_t"
	suite.Update(status)

	ctest.AssertResource(suite, "audit-pod_x_t", func(res *runtimeres.SELinuxModule, asrt *assert.Assertions) {
		asrt.Equal("(auditallow pod_x_t b_t (dir (search)))\n", strings.SplitN(res.TypedSpec().Content, "\n", 2)[1])
	})

	ctest.AssertResource(suite, "pod_x_t", func(res *runtimeres.SELinuxDomainStatus, asrt *assert.Assertions) {
		asrt.Equal(uint32(2), res.TypedSpec().Rounds)
	})

	// the kernel loads a policy: the grants are enumerated again, without a round when nothing changed
	computed := suite.computed.Load()
	suite.seqno.Add(1)

	status.TypedSpec().Error = ""
	suite.Update(status)

	suite.Require().Eventually(func() bool { return suite.computed.Load() > computed }, 5*time.Second, 10*time.Millisecond)

	ctest.AssertResource(suite, "pod_x_t", func(res *runtimeres.SELinuxDomainStatus, asrt *assert.Assertions) {
		asrt.Equal(uint32(2), res.TypedSpec().Rounds)
	})
}

// TestNarrowedModuleCompiles: the rules the audit renders are a module the base policy compiles, on the extension plumbing.
func TestNarrowedModuleCompiles(t *testing.T) {
	if _, err := os.Stat("/usr/bin/secilc"); err != nil {
		t.Skip("secilc and the policy sources are only available in the Talos rootfs")
	}

	module := "(type ext_narrowed_t)\n(call ext_plumbing (ext_narrowed_t))\n" + runtimecontrollers.RenderRules("allow", "ext_narrowed_t", []runtimeres.SELinuxAccess{
		{Target: "usr_t", Class: "file", Permission: "read"},
		{Target: "usr_t", Class: "file", Permission: "entrypoint"},
		{Target: "ext_narrowed_t", Class: "process", Permission: "fork"},
		{Target: "ext_state_t", Class: "dir", Permission: "write"},
		{Target: "device_t", Class: "chr_file", Permission: "ioctl"},
	}, false)

	_, err := selinux.Compile(t.Context(), map[string]string{"config-narrowed": module})
	require.NoError(t, err)
}
