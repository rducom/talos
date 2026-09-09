// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extgen_test

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	extservices "github.com/siderolabs/talos/pkg/machinery/extensions/services"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

var update = flag.Bool("update", false, "update the golden file")

// modules derives the module of every container-mode spec of testdata/specs, one per behavior of the generator, keyed by service name.
func modules(t *testing.T) (map[string]extgen.Module, string) {
	t.Helper()

	rules, err := selinux.FileContextRules()
	require.NoError(t, err)

	paths, err := filepath.Glob("testdata/specs/*.yaml")
	require.NoError(t, err)

	specs := make([]extservices.Spec, 0, len(paths))

	for _, path := range paths {
		data, err := os.ReadFile(path)
		require.NoError(t, err)

		var spec extservices.Spec

		require.NoError(t, yaml.Unmarshal(data, &spec))
		require.NoError(t, spec.Validate(), path)

		specs = append(specs, spec)
	}

	var (
		out    strings.Builder
		byName = map[string]extgen.Module{}
	)

	for _, module := range extgen.Generate(specs, rules) {
		require.Empty(t, module.Error, module.Name)

		byName[module.Name] = module

		fmt.Fprintf(&out, ";; %s\n%s", module.Name, module.Content)

		for _, source := range slices.Sorted(maps.Keys(module.Labels)) {
			fmt.Fprintf(&out, ";; label %s %s\n", source, module.Labels[source])
		}

		if len(module.Warnings) > 0 {
			fmt.Fprintf(&out, ";; warnings: %s\n", strings.Join(module.Warnings, " "))
		}

		out.WriteString("\n")
	}

	return byName, out.String()
}

func TestGenerate(t *testing.T) {
	_, got := modules(t)

	if *update {
		require.NoError(t, os.WriteFile("testdata/modules.cil", []byte(got), 0o644))
	}

	golden, err := os.ReadFile("testdata/modules.cil")
	require.NoError(t, err)

	assert.Equal(t, string(golden), got)
}

func TestGenerateRefusals(t *testing.T) {
	rules, err := selinux.FileContextRules()
	require.NoError(t, err)

	spec := func(name string, sources ...string) extservices.Spec {
		s := extservices.Spec{Name: name}

		for _, source := range sources {
			s.Container.Mounts = append(s.Container.Mounts, specs.Mount{Source: source, Destination: source})
		}

		return s
	}

	modules := extgen.Generate([]extservices.Spec{spec("agent", constants.StateMountPoint+"/config")}, rules)
	assert.Equal(t, `service "agent": mount source /system/state/config is on the STATE partition (system_state_t), which no extension may access`, modules[0].Error)

	modules = extgen.Generate([]extservices.Spec{spec("privileged")}, rules)
	assert.Equal(t, `service "privileged": type ext_privileged_t belongs to the base policy`, modules[0].Error)

	modules = extgen.Generate([]extservices.Spec{spec("agent", "/mnt/data", "/etc/ssl/certs", "/dev/net/tun", "/dev/tpmrm0", "/dev/pts", "/system/run/machined")}, rules)
	assert.Empty(t, modules[0].Error)
	assert.Equal(t, []string{"no rule derived for the mount source /mnt/data"}, modules[0].Warnings)
	assert.Contains(t, modules[0].Content, "; no rule derived for the mount source /mnt/data\n")
	assert.Contains(t, modules[0].Content, "(allow ext_agent_t etc_t (fs_classes (rw))) ; /etc/ssl/certs\n")
	assert.Contains(t, modules[0].Content, "(allow ext_agent_t device_t (fs_classes (rw))) ; /dev/net/tun\n")
	assert.Contains(t, modules[0].Content, "(allow ext_agent_t tpm_device_t (fs_classes (rw))) ; /dev/tpmrm0\n")
	assert.Contains(t, modules[0].Content, "(allow ext_agent_t devpts_t (fs_classes (rw))) ; /dev/pts\n")
	assert.Contains(t, modules[0].Content, "(allow ext_agent_t init_t (unix_stream_socket (connectto)))\n")

	// a source above directories Talos labels gets the type of the source only, and says so
	modules = extgen.Generate([]extservices.Spec{spec("wide", "/var/log")}, rules)
	assert.Equal(t, []string{
		"/var/log covers /var/log/audit (audit_log_t), /var/log/audit/kube (kube_log_t), /var/log/containers (containers_log_t), /var/log/pods (pods_log_t): not granted",
	}, modules[0].Warnings)
	assert.Contains(t, modules[0].Content, "(allow ext_wide_t var_log_t (fs_classes (rw))) ; /var/log\n")
	assert.NotContains(t, modules[0].Content, "audit_log_t (")

	// a mount of another kind carries the type of its filesystem
	tmpfs := spec("tmp")
	tmpfs.Container.Mounts = []specs.Mount{{Source: "tmpfs", Destination: "/tmp", Type: "tmpfs"}}
	assert.Empty(t, extgen.Generate([]extservices.Spec{tmpfs}, rules)[0].Warnings)

	// nested state directories keep the shared type; /var/run and /run are one directory
	modules = extgen.Generate([]extservices.Spec{spec("outer", "/var/lib/foo"), spec("inner", "/var/lib/foo/bar"), spec("a", "/var/run/x"), spec("b", "/run/x/")}, rules)
	assert.Equal(t, map[string]string{"/var/lib/foo": constants.SELinuxTypeExtensionState}, modules[0].Labels)
	assert.Contains(t, modules[1].Content, "(allow ext_inner_t ext_state_t (fs_classes (rw))) ; /var/lib/foo/bar (shared with outer)\n")
	assert.Equal(t, map[string]string{"/run/x": constants.SELinuxTypeExtensionRun}, modules[2].Labels)
	assert.Contains(t, modules[3].Content, "(allow ext_b_t ext_run_t (fs_classes (rw))) ; /run/x (shared with a)\n")

	// the names of the services are not the names of the types
	modules = extgen.Generate([]extservices.Spec{spec("a-b"), spec("a_b"), spec("foo"), spec("foo-state")}, rules)
	assert.Equal(t, `service "a_b": type ext_a_b_t is already declared by service "a-b"`, modules[1].Error)
	assert.Equal(t, `service "foo-state": type ext_foo_state_t is already declared by service "foo"`, modules[3].Error)
	assert.Empty(t, modules[0].Error+modules[2].Error)
}

func TestResolvedType(t *testing.T) {
	t.Parallel()

	module := &runtime.SELinuxModuleSpec{Type: "ext_hello_t", Labels: map[string]string{"/var/lib/hello": "ext_hello_state_t"}}

	for _, test := range []struct {
		configured  string
		module      *runtime.SELinuxModuleSpec
		loaded      bool
		typ, reason string
	}{
		{"ext_privileged_t", module, true, "ext_privileged_t", ""},
		{"", nil, true, "ext_t", ""},
		{"", &runtime.SELinuxModuleSpec{Error: "not derived"}, true, "ext_t", "not derived"},
		{"", module, false, "ext_t", "policy module of the service is not loaded"},
		{"", module, true, "ext_hello_t", ""},
	} {
		typ, labels, reason := extgen.ResolvedType(test.configured, test.module, test.loaded)
		assert.Equal(t, []any{test.typ, test.reason}, []any{typ, reason})
		assert.Equal(t, typ == "ext_hello_t", labels != nil)
	}
}

// TestGenerateCompiles compiles the derived modules with the base policy: every type they use exists, and no two services
// collide.
func TestGenerateCompiles(t *testing.T) {
	if _, err := os.Stat("/usr/bin/secilc"); err != nil {
		t.Skip("secilc and the policy sources are only available in the Talos rootfs")
	}

	byName, _ := modules(t)

	contents := map[string]string{}

	for name, module := range byName {
		contents["ext-"+name] = module.Content
	}

	_, err := selinux.Compile(t.Context(), contents)
	require.NoError(t, err)

	// the derived types are extension domains: the floor of the base policy applies to them, and no pod reads their state
	contents["ceiling"] = "(neverallow extension_p system_state_t (file (read)))\n(neverallow pod_p ext_agent_state_t (file (read)))\n"

	_, err = selinux.Compile(t.Context(), contents)
	require.NoError(t, err)

	contents["extra"] = "(allow ext_agent_t system_state_t (fs_classes (ro)))\n"

	_, err = selinux.Compile(t.Context(), contents)
	require.ErrorContains(t, err, "neverallow check failed")
}
