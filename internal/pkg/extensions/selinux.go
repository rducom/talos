// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extensions

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/extensions"
)

// GenerateSELinuxPolicyExtension builds the extension which carries the SELinux policy modules derived from the extension
// services, and the policy the imager compiles them into with the policy sources of the rootfs, which init loads at boot.
func GenerateSELinuxPolicyExtension(
	ctx context.Context,
	modules []extgen.Module,
	initramfsPath, scratchPath string,
	printFunc func(format string, v ...any),
) (*Extension, error) {
	printFunc("compiling the SELinux policy of the extension services")

	tempDir, err := os.MkdirTemp("", "ext-selinux")
	if err != nil {
		return nil, err
	}

	defer logErr("removing temporary directory", func() error {
		return os.RemoveAll(tempDir)
	})

	initramfsxz, err := os.Open(initramfsPath)
	if err != nil {
		return nil, err
	}

	defer logErr("closing initramfs", func() error {
		return initramfsxz.Close()
	})

	r, err := autoDecompress(initramfsxz)
	if err != nil {
		return nil, err
	}

	tempRootfsFile := filepath.Join(tempDir, constants.RootfsAsset)

	if err = extractRootfsFromInitramfs(r, tempRootfsFile); err != nil {
		return nil, err
	}

	sources := filepath.Join(tempDir, "sources")

	if err = unsquash(ctx, tempRootfsFile, sources, selinux.PolicyDir); err != nil {
		return nil, err
	}

	// we want the extension to survive this function, so not storing in a temporary directory
	stagingDir := filepath.Join(scratchPath, "selinux-policy")

	if err = CompileSELinuxPolicy(ctx, modules, filepath.Join(sources, selinux.PolicyDir), filepath.Join(stagingDir, selinux.PolicyDir)); err != nil {
		return nil, err
	}

	return &Extension{extensions.New(
		stagingDir, "selinux-policy",
		extensions.Manifest{
			Version: "v1alpha1",
			Metadata: extensions.Metadata{
				Name:        "selinux-policy",
				Version:     "v1alpha1",
				Author:      "Talos Machinery",
				Description: "SELinux policy of the extension services",
			},
		},
	)}, nil
}

// CompileSELinuxPolicy writes the modules to the extensions directory of policyDir, and compiles them with the policy sources
// of sourcesDir into the policy of policyDir.
func CompileSELinuxPolicy(ctx context.Context, modules []extgen.Module, sourcesDir, policyDir string) error {
	// secilc runs in a directory of its own
	sourcesDir, err := filepath.Abs(sourcesDir)
	if err != nil {
		return err
	}

	modulesDir, err := filepath.Abs(filepath.Join(policyDir, filepath.Base(selinux.ExtensionModulesDir)))
	if err != nil {
		return err
	}

	if err = extgen.WriteModules(modulesDir, modules); err != nil {
		return err
	}

	sourceFiles, err := filepath.Glob(filepath.Join(sourcesDir, "*", "*.cil"))
	if err != nil {
		return err
	}

	moduleFiles, err := filepath.Glob(filepath.Join(modulesDir, "*.cil"))
	if err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "selinux-")
	if err != nil {
		return err
	}

	defer os.RemoveAll(dir) //nolint:errcheck

	cmd := exec.CommandContext(ctx, "secilc", append([]string{"-c", "33", "-O", "-o", "policy.33", "-f", "file_contexts"}, append(sourceFiles, moduleFiles...)...)...)
	cmd.Dir = dir

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("secilc: %w: %s", err, bytes.TrimSpace(output))
	}

	policy, err := os.ReadFile(filepath.Join(dir, "policy.33"))
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(policyDir, filepath.Base(selinux.ImagePolicy)), policy, 0o644)
}
