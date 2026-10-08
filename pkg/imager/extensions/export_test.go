// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extensions

import (
	"github.com/siderolabs/talos/internal/pkg/extensions"
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
)

// DeriveSELinux exposes deriveSELinux for tests.
func (builder *Builder) DeriveSELinux(extensionsList []*extensions.Extension) ([]extgen.Module, error) {
	return builder.deriveSELinux(extensionsList)
}
