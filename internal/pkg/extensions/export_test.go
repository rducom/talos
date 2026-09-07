// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extensions

import (
	"io"

	"github.com/siderolabs/talos/pkg/machinery/extensions"
)

// NewForTest builds an extension around a rootfs directory.
func NewForTest(rootfsPath string) *Extension {
	return &Extension{extensions.New(rootfsPath, "", extensions.Manifest{})}
}

// CopyFiles is a test export of the copyFiles function to allow testing of the function in isolation.
func CopyFiles(srcPath, dstPath string) error {
	return copyFiles(srcPath, dstPath)
}

// WritePseudo is a test export of the writePseudo method.
func (ext *Extension) WritePseudo(w io.Writer, xattrsMap map[string]string) error {
	return ext.writePseudo(w, xattrsMap)
}
