// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extensions

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v4"

	"github.com/siderolabs/talos/internal/pkg/extensions"
	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	extservices "github.com/siderolabs/talos/pkg/machinery/extensions/services"
)

// deriveSELinux derives the policy module of every extension service in container mode, which the image carries compiled
// into its policy, and fails the build with the reason when a module cannot be derived.
//
//nolint:gocyclo
func (builder *Builder) deriveSELinux(extensionsList []*extensions.Extension) ([]extgen.Module, error) {
	var (
		specs     []extservices.Spec
		extension = map[string]string{}
	)

	for _, ext := range extensionsList {
		// the policy of the image is the imager's: no extension ships policy files of its own
		if _, err := os.Stat(filepath.Join(ext.RootfsPath(), selinux.PolicyDir)); err == nil {
			return nil, fmt.Errorf("extension %q ships files in %s", ext.Manifest.Metadata.Name, selinux.PolicyDir)
		}

		paths, err := filepath.Glob(filepath.Join(ext.RootfsPath(), constants.ExtensionServiceConfigPath, "*.yaml"))
		if err != nil {
			return nil, err
		}

		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}

			var spec extservices.Spec

			if err = yaml.Unmarshal(data, &spec); err != nil {
				return nil, fmt.Errorf("error parsing service spec %s of extension %q: %w", filepath.Base(path), ext.Manifest.Metadata.Name, err)
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
		return nil, err
	}

	modules := extgen.Generate(specs, rules)

	for _, module := range modules {
		if module.Error != "" {
			return nil, fmt.Errorf("SELinux policy of extension %q: %s", extension[module.Name], module.Error)
		}

		builder.Printf("SELinux policy of extension %q, service %q: derived %s", extension[module.Name], module.Name, module.Type)

		for _, warning := range module.Warnings {
			builder.Printf("SELinux policy of extension %q, service %q: %s", extension[module.Name], module.Name, warning)
		}
	}

	return modules, nil
}
