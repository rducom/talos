// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package config

// ExtensionServiceConfig is a config for extension services.
type ExtensionServiceConfig interface {
	Name() string
	ConfigFiles() []ExtensionServiceConfigFile
	Environment() []string
	// SELinuxType is the type the service runs as, empty to let Talos choose it.
	SELinuxType() string
}

// ExtensionServiceConfigFile is a config file for extension services.
type ExtensionServiceConfigFile interface {
	Content() string
	MountPath() string
}
