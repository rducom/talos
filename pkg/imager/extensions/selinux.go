// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extensions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v4"

	"github.com/siderolabs/talos/internal/pkg/extensions"
	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	extservices "github.com/siderolabs/talos/pkg/machinery/extensions/services"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// checkSELinux derives the policy module of every extension service the way machined will, so that an image whose
// module machined would refuse fails to build with the reason, and compiles the modules with the Talos policy when
// the imager has secilc, so that the compile error of the node shows up here first.
//
//nolint:gocyclo
func (builder *Builder) checkSELinux(ctx context.Context, extensionsList []*extensions.Extension) error {
	var (
		specs     []extservices.Spec
		extension = map[string]string{}
	)

	for _, ext := range extensionsList {
		paths, err := filepath.Glob(filepath.Join(ext.RootfsPath(), constants.ExtensionServiceConfigPath, "*.yaml"))
		if err != nil {
			return err
		}

		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			var spec extservices.Spec

			if err = yaml.Unmarshal(data, &spec); err != nil {
				return fmt.Errorf("error parsing service spec %s of extension %q: %w", filepath.Base(path), ext.Manifest.Metadata.Name, err)
			}

			// machined skips these with a log
			if _, duplicate := extension[spec.Name]; duplicate || spec.Validate() != nil {
				continue
			}

			extension[spec.Name] = ext.Manifest.Metadata.Name

			specs = append(specs, spec)
		}
	}

	rules, err := selinux.FileContextRules()
	if err != nil {
		return err
	}

	modules := map[string]string{}

	for _, module := range extgen.Generate(specs, rules) {
		if module.Error != "" {
			return fmt.Errorf("SELinux policy of extension %q: %s", extension[module.Name], module.Error)
		}

		for _, warning := range module.Warnings {
			builder.Printf("SELinux policy of extension %q, service %q: %s", extension[module.Name], module.Name, warning)
		}

		modules[runtime.SELinuxModuleExtensionPrefix+module.Name] = module.Content
	}

	// services in host mode have no module: nothing to compile
	if len(modules) == 0 {
		return nil
	}

	if _, statErr := os.Stat("/usr/bin/secilc"); statErr != nil {
		builder.Printf("SELinux policy modules of %d extension services derived, not compiled (no secilc)", len(modules))

		return nil //nolint:nilerr
	}

	if _, err = selinux.Compile(ctx, modules); err != nil {
		return fmt.Errorf("error compiling the SELinux policy with the modules of the extension services: %w", err)
	}

	builder.Printf("SELinux policy compiled with the modules of %d extension services", len(modules))

	return nil
}
