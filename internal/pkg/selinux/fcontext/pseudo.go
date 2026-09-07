// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package fcontext

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
)

// WritePseudo writes the mksquashfs pseudo-file definitions carrying the SELinux label of every entry of a source tree:
// the label shipped for the entry, by path of the source tree, else the one the rules give the same path in the image.
//
// The value is written as libselinux writes it, with a trailing NUL byte, base64-encoded: the 0x parser of the
// squashfs-tools of the build environment segfaults. The path is quoted, so that a space, a quote or a backslash
// in a name does not end or escape the definition.
func WritePseudo(w io.Writer, rootDir string, rules []Rule, shipped map[string]string) error {
	bw := bufio.NewWriter(w)

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}

		imgPath := "/"
		if rel != "." {
			imgPath += rel
		}

		context, ok := shipped[path]
		if !ok {
			info, err := d.Info()
			if err != nil {
				return err
			}

			if context = Lookup(rules, imgPath, FileTypeOf(info.Mode())); context == "" {
				return nil
			}
		}

		_, err = fmt.Fprintf(bw, "%s x security.selinux=0s%s\n", quote(imgPath), base64.StdEncoding.EncodeToString([]byte(strings.TrimSuffix(context, "\x00")+"\x00")))

		return err
	})
	if err != nil {
		return err
	}

	return bw.Flush()
}

// quote writes a path as a quoted name of a pseudo-file definition.
func quote(path string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(path) + `"`
}
