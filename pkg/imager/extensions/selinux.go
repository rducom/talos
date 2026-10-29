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

// checkSELinux derives the policy module of every extension service the way machined will, so that an image whose
// module machined would refuse fails to build with the reason.
//
//nolint:gocyclo
func (builder *Builder) checkSELinux(extensionsList []*extensions.Extension) error {
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

	for _, module := range extgen.Generate(specs, rules) {
		if module.Error != "" {
			return fmt.Errorf("SELinux policy of extension %q: %s", extension[module.Name], module.Error)
		}

		builder.Printf("SELinux policy of extension %q, service %q: derived %s", extension[module.Name], module.Name, module.Type)

		for _, warning := range module.Warnings {
			builder.Printf("SELinux policy of extension %q, service %q: %s", extension[module.Name], module.Name, warning)
		}
	}

	return nil
}
