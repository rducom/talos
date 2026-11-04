// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extgen_test

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
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

	module := &extgen.Module{Type: "ext_hello_t", Labels: map[string]string{"/var/lib/hello": "ext_hello_state_t"}}

	// the state directories keep the types of the module whatever the type
	for _, test := range []struct {
		configured string
		module     *extgen.Module
		typ        string
		labels     bool
	}{
		{"ext_privileged_t", module, "ext_privileged_t", true},
		{"ext_privileged_t", nil, "ext_privileged_t", false},
		{"", nil, "ext_t", false},
		{"", &extgen.Module{}, "ext_t", false},
		{"", module, "ext_hello_t", true},
	} {
		typ, labels := extgen.ResolvedType(test.configured, test.module)
		assert.Equal(t, []any{test.typ, test.labels}, []any{typ, labels != nil})
	}
}

// TestGenerateCompiles compiles the derived modules with the base policy: every type they use exists, and no two services
// collide.
func TestGenerateCompiles(t *testing.T) {
	secilc, err := exec.LookPath("secilc")
	if err != nil {
		t.Skip("secilc is not available")
	}

	byName, _ := modules(t)

	contents := map[string]string{}

	for name, module := range byName {
		contents["ext-"+name] = module.Content
	}

	require.NoError(t, compile(t, secilc, contents))

	// the derived types are extension domains: the floor of the base policy applies to them, and no regular pod reads
	// their state
	contents["ceiling"] = "(neverallow extension_p system_state_t (file (read)))\n(neverallow pod_t ext_agent_state_t (file (read)))\n"

	require.NoError(t, compile(t, secilc, contents))

	// the clients boolean of the service grants its state to the CSI node plugin domain
	contents["clients"] = "(neverallow pod_csi_t ext_agent_state_t (file (read)))\n"

	require.ErrorContains(t, compile(t, secilc, contents), "neverallow check failed")

	delete(contents, "clients")

	contents["extra"] = "(allow ext_agent_t system_state_t (fs_classes (ro)))\n"

	require.ErrorContains(t, compile(t, secilc, contents), "neverallow check failed")
}

func TestClientsBooleanName(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "ext_iscsi_tools_clients", extgen.ClientsBooleanName("iscsi-tools"))
}

// compile compiles the policy sources of the tree with the modules, by name, as the imager does.
func compile(t *testing.T, secilc string, modules map[string]string) error {
	t.Helper()

	files, err := filepath.Glob("../policy/selinux/*/*.cil")
	require.NoError(t, err)

	dir := t.TempDir()

	for name, content := range modules {
		file := filepath.Join(dir, name+".cil")
		require.NoError(t, os.WriteFile(file, []byte(content), 0o644))

		files = append(files, file)
	}

	output, err := exec.CommandContext(t.Context(), secilc, append([]string{
		"-c", "33", "-O", "-o", filepath.Join(dir, "policy.33"),
		"-f", filepath.Join(dir, "file_contexts"),
	}, files...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, output)
	}

	return nil
}
