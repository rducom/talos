// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extgen

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v4"
)

// moduleFile is what machined needs of a module besides its CIL.
type moduleFile struct {
	Type     string            `yaml:"type"`
	Labels   map[string]string `yaml:"labels,omitempty"`
	Warnings []string          `yaml:"warnings,omitempty"`
}

// WriteModules writes the modules to dir: the CIL of each one to <name>.cil, which the policy sources include, and its type,
// labels and warnings to <name>.yaml.
func WriteModules(dir string, modules []Module) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	for _, module := range modules {
		data, err := yaml.Marshal(moduleFile{Type: module.Type, Labels: module.Labels, Warnings: module.Warnings})
		if err != nil {
			return err
		}

		if err = os.WriteFile(filepath.Join(dir, module.Name+".yaml"), data, 0o644); err != nil {
			return err
		}

		if err = os.WriteFile(filepath.Join(dir, module.Name+".cil"), []byte(module.Content), 0o644); err != nil {
			return err
		}
	}

	return nil
}

// ReadModules reads back the modules WriteModules wrote to dir.
func ReadModules(dir string) ([]Module, error) {
	// an image without extension services has no such directory
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}

	modules := make([]Module, 0, len(paths))

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		var file moduleFile

		if err = yaml.Unmarshal(data, &file); err != nil {
			return nil, err
		}

		name := strings.TrimSuffix(filepath.Base(path), ".yaml")

		content, err := os.ReadFile(filepath.Join(dir, name+".cil"))
		if err != nil {
			return nil, err
		}

		modules = append(modules, Module{Name: name, Type: file.Type, Content: string(content), Labels: file.Labels, Warnings: file.Warnings})
	}

	return modules, nil
}

// ReadModule reads back the module of the service from dir, nil when the image derived none for it.
func ReadModule(dir, name string) (*Module, error) {
	data, err := os.ReadFile(filepath.Join(dir, name+".yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil //nolint:nilnil
	}

	if err != nil {
		return nil, err
	}

	var file moduleFile

	if err = yaml.Unmarshal(data, &file); err != nil {
		return nil, err
	}

	return &Module{Name: name, Type: file.Type, Labels: file.Labels, Warnings: file.Warnings}, nil
}
