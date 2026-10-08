// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extensions_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/pkg/extensions"
	"github.com/siderolabs/talos/internal/pkg/selinux"
	imagerextensions "github.com/siderolabs/talos/pkg/imager/extensions"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	machineryextensions "github.com/siderolabs/talos/pkg/machinery/extensions"
)

func TestDeriveSELinux(t *testing.T) {
	t.Parallel()

	extension := func(name, body string) *extensions.Extension {
		spec := "name: " + name + "\ncontainer:\n  entrypoint: ./" + name + "\n" + body + "restart: always\n"

		rootfs := filepath.Join(t.TempDir(), "rootfs")
		require.NoError(t, os.MkdirAll(filepath.Join(rootfs, constants.ExtensionServiceConfigPath), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(rootfs, constants.ExtensionServiceConfigPath, name+".yaml"), []byte(spec), 0o644))

		return &extensions.Extension{Extension: machineryextensions.New(rootfs, name, machineryextensions.Manifest{Metadata: machineryextensions.Metadata{Name: name}})}
	}

	var log strings.Builder

	builder := imagerextensions.Builder{Printf: func(format string, v ...any) { fmt.Fprintf(&log, format+"\n", v...) }}

	mount := func(source string) string {
		return "  mounts:\n    - source: " + source + "\n      destination: /data\n      type: bind\n"
	}

	agent := extension("agent", mount("/mnt/data"))

	modules, err := builder.DeriveSELinux([]*extensions.Extension{agent})
	require.NoError(t, err)
	assert.Equal(t, "ext_agent_t", modules[0].Type)
	assert.Contains(t, log.String(), `SELinux policy of extension "agent", service "agent": no rule derived for the mount source /mnt/data`)

	_, err = builder.DeriveSELinux([]*extensions.Extension{extension("wide", mount("/var"))})
	require.NoError(t, err)
	assert.Contains(t, log.String(), `SELinux policy of extension "wide", service "wide": /var covers /var/lib/cni (cni_state_t), `)

	// the names of the services are not the names of the types
	_, err = builder.DeriveSELinux([]*extensions.Extension{extension("a-gent", ""), extension("a_gent", "")})
	assert.EqualError(t, err, `SELinux policy of extension "a_gent": service "a_gent": type ext_a_gent_t is already declared by service "a-gent"`)

	_, err = builder.DeriveSELinux([]*extensions.Extension{agent, extension("thief", mount("/system/state"))})
	assert.EqualError(t, err, `SELinux policy of extension "thief": service "thief": mount source /system/state is on the STATE partition (system_state_t), `+
		`which no extension may access`)

	// an image whose services all run in host mode has no module
	modules, err = builder.DeriveSELinux([]*extensions.Extension{extension("virtqemud", "runnerMode: host\n")})
	require.NoError(t, err)
	assert.Empty(t, modules)

	// the policy of the image is the imager's
	forger := extension("forger", "")
	require.NoError(t, os.MkdirAll(filepath.Join(forger.RootfsPath(), selinux.PolicyDir), 0o755))

	_, err = builder.DeriveSELinux([]*extensions.Extension{forger})
	assert.EqualError(t, err, `extension "forger" ships files in /usr/share/selinux/talos`)
}
