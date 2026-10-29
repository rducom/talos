// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extensions_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/pkg/extensions"
)

func TestCopyFilesTruncatesExistingDestination(t *testing.T) {
	t.Parallel()

	sourcePath := filepath.Join(t.TempDir(), "modules.softdep")
	destinationPath := filepath.Join(t.TempDir(), "modules.softdep")

	require.NoError(t, os.WriteFile(sourcePath, []byte("short\n"), 0o644))
	require.NoError(t, os.WriteFile(destinationPath, []byte("long destination content\n"), 0o644))
	require.NoError(t, extensions.CopyFiles(sourcePath, destinationPath))

	contents, err := os.ReadFile(destinationPath)
	require.NoError(t, err)
	require.Equal(t, "short\n", string(contents))
}

// TestWritePseudo: extension files get the labels of the Talos rootfs, unless the extension carries its own.
func TestWritePseudo(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()

	for _, dir := range []string{"usr/local/bin", "usr/lib/modules/6.18", "etc/cri/conf.d", `usr/local/share/a b`} {
		require.NoError(t, os.MkdirAll(filepath.Join(rootfs, dir), 0o755))
	}

	for _, file := range []string{"usr/local/bin/tool", "usr/lib/modules/6.18/x.ko", "etc/cri/conf.d/x.part", `usr/local/share/a b/c"d\e`, "usr/local/share/trailing."} {
		require.NoError(t, os.WriteFile(filepath.Join(rootfs, file), nil, 0o644))
	}

	require.NoError(t, os.Symlink("/usr/local/bin/tool", filepath.Join(rootfs, "usr/local/bin/link")))

	var pseudo strings.Builder

	require.NoError(t, extensions.NewForTest(rootfs).WritePseudo(&pseudo, map[string]string{filepath.Join(rootfs, "usr/lib/modules/6.18/x.ko"): "system_u:object_r:usr_t:s0"}))

	label := func(typ string) string {
		return "0s" + base64.StdEncoding.EncodeToString([]byte("system_u:object_r:"+typ+":s0\x00"))
	}

	// the paths are quoted: a space, a quote or a backslash in a name does not end nor escape the definition
	assert.Equal(t, []string{
		`"/" x security.selinux=` + label("rootfs_t"),
		`"/etc" x security.selinux=` + label("etc_t"),
		`"/etc/cri" x security.selinux=` + label("etc_t"),
		`"/etc/cri/conf.d" x security.selinux=` + label("etc_t"),
		`"/etc/cri/conf.d/x.part" x security.selinux=` + label("etc_t"),
		`"/usr" x security.selinux=` + label("usr_t"),
		`"/usr/lib" x security.selinux=` + label("lib_t"),
		`"/usr/lib/modules" x security.selinux=` + label("module_t"),
		`"/usr/lib/modules/6.18" x security.selinux=` + label("module_t"),
		`"/usr/lib/modules/6.18/x.ko" x security.selinux=` + label("usr_t"), // shipped by the extension, wins
		`"/usr/local" x security.selinux=` + label("usr_t"),
		`"/usr/local/bin" x security.selinux=` + label("usr_t"),
		`"/usr/local/bin/link" x security.selinux=` + label("usr_t"),
		`"/usr/local/bin/tool" x security.selinux=` + label("usr_t"),
		`"/usr/local/share" x security.selinux=` + label("usr_t"),
		`"/usr/local/share/a b" x security.selinux=` + label("usr_t"),
		`"/usr/local/share/a b/c\"d\\e" x security.selinux=` + label("usr_t"),
		`"/usr/local/share/trailing." x security.selinux=` + label("usr_t"),
		"",
	}, strings.Split(pseudo.String(), "\n"))
}
