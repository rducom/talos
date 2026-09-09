// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extensions

import (
	"context"

	"github.com/siderolabs/talos/internal/pkg/extensions"
)

// CheckSELinux exposes checkSELinux for tests.
func (builder *Builder) CheckSELinux(ctx context.Context, extensionsList []*extensions.Extension) error {
	return builder.checkSELinux(ctx, extensionsList)
}
