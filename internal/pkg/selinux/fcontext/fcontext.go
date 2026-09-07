// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package fcontext resolves paths against a SELinux file_contexts specification.
package fcontext

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"slices"
	"strings"
)

// FileType restricts a rule to one kind of inode, as the optional second column of file_contexts does.
type FileType int

// File types, in the order of the file_contexts type specifications.
const (
	TypeAny FileType = iota
	TypeReg
	TypeDir
	TypeLnk
	TypeChr
	TypeBlk
	TypeFifo
	TypeSock
)

var typeSpecs = map[string]FileType{"--": TypeReg, "-d": TypeDir, "-l": TypeLnk, "-c": TypeChr, "-b": TypeBlk, "-p": TypeFifo, "-s": TypeSock}

// Rule is one entry of file_contexts.
type Rule struct {
	re      *regexp.Regexp
	ftype   FileType
	context string
}

// Parse reads a file_contexts specification.
func Parse(r io.Reader) ([]Rule, error) {
	var rules []Rule

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)

		rule := Rule{ftype: TypeAny}

		switch len(fields) {
		case 2:
			rule.context = fields[1]
		case 3:
			var ok bool

			if rule.ftype, ok = typeSpecs[fields[1]]; !ok {
				return nil, fmt.Errorf("unknown file_contexts type spec %q", fields[1])
			}

			rule.context = fields[2]
		default:
			return nil, fmt.Errorf("malformed file_contexts line: %q", line)
		}

		// file_contexts patterns are anchored against the full path.
		re, err := regexp.Compile("^" + fields[0] + "$")
		if err != nil {
			return nil, fmt.Errorf("compiling pattern %q: %w", fields[0], err)
		}

		rule.re = re

		rules = append(rules, rule)
	}

	return rules, scanner.Err()
}

// FileTypeOf maps a file mode to its file_contexts type.
func FileTypeOf(m fs.FileMode) FileType {
	switch {
	case m&fs.ModeSymlink != 0:
		return TypeLnk
	case m.IsDir():
		return TypeDir
	case m&fs.ModeCharDevice != 0:
		return TypeChr
	case m&fs.ModeDevice != 0:
		return TypeBlk
	case m&fs.ModeNamedPipe != 0:
		return TypeFifo
	case m&fs.ModeSocket != 0:
		return TypeSock
	default:
		return TypeReg
	}
}

// Lookup returns the context of path for the given file type, or an empty string when no rule matches.
//
// As libselinux's selabel_lookup does, the last matching entry wins, and an entry whose type spec does not
// match the file type is skipped.
func Lookup(rules []Rule, path string, ft FileType) string {
	for _, r := range slices.Backward(rules) {
		if (r.ftype == TypeAny || r.ftype == ft) && r.re.MatchString(path) {
			return r.context
		}
	}

	return ""
}
