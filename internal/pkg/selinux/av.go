// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package selinux

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const selinuxFS = "/sys/fs/selinux"

// Class is an object class of the loaded policy, with the bit of each of its permissions in an access vector.
type Class struct {
	Index uint16
	Perms map[string]uint32
}

// Classes reads the object classes of the loaded policy from selinuxfs.
func Classes() (map[string]Class, error) {
	entries, err := os.ReadDir(filepath.Join(selinuxFS, "class"))
	if err != nil {
		return nil, err
	}

	classes := map[string]Class{}

	for _, entry := range entries {
		index, err := readUint(filepath.Join(selinuxFS, "class", entry.Name(), "index"))
		if err != nil {
			return nil, err
		}

		class := Class{Index: uint16(index), Perms: map[string]uint32{}}

		perms, err := os.ReadDir(filepath.Join(selinuxFS, "class", entry.Name(), "perms"))
		if err != nil {
			return nil, err
		}

		for _, perm := range perms {
			bit, err := readUint(filepath.Join(selinuxFS, "class", entry.Name(), "perms", perm.Name()))
			if err != nil {
				return nil, err
			}

			class.Perms[perm.Name()] = 1 << (bit - 1)
		}

		classes[entry.Name()] = class
	}

	return classes, nil
}

func readUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
}

// AccessVector is the decision of the kernel for a source, a target and a class.
type AccessVector struct {
	// Allowed permissions, as bits of the class.
	Allowed uint32
	// Seqno of the loaded policy.
	Seqno uint32
}

// ComputeAV asks the security server of the kernel the permissions the source context is allowed on the target
// context for the class: the decision it would take, macros, attributes, aliases and modules included.
func ComputeAV(scon, tcon string, class uint16) (AccessVector, error) {
	f, err := os.OpenFile(filepath.Join(selinuxFS, "access"), os.O_RDWR, 0)
	if err != nil {
		return AccessVector{}, err
	}

	defer f.Close() //nolint:errcheck

	if _, err = fmt.Fprintf(f, "%s %s %d", scon, tcon, class); err != nil {
		return AccessVector{}, err
	}

	buf := make([]byte, 128)

	n, err := f.Read(buf)
	if err != nil {
		return AccessVector{}, err
	}

	return parseAccessVector(string(buf[:n]))
}

// parseAccessVector parses the answer of selinuxfs: allowed, decided, auditallow, auditdeny, seqno, flags.
func parseAccessVector(s string) (AccessVector, error) {
	var (
		av                             AccessVector
		decided, auditallow, auditdeny uint32
		flags                          uint32
	)

	if _, err := fmt.Sscanf(s, "%x %x %x %x %d %x", &av.Allowed, &decided, &auditallow, &auditdeny, &av.Seqno, &flags); err != nil {
		return av, fmt.Errorf("error parsing the access vector %q: %w", s, err)
	}

	return av, nil
}

var typeRe = regexp.MustCompile(`(?m)^\s*\(type ([a-z0-9_]+)\)`)

// Types returns the types the CIL sources declare, sorted; the aliases are left out, the kernel names the type.
func Types(sources ...string) []string {
	var types []string

	for _, source := range sources {
		for _, match := range typeRe.FindAllStringSubmatch(source, -1) {
			types = append(types, match[1])
		}
	}

	slices.Sort(types)

	return slices.Compact(types)
}

// PolicySources returns the CIL sources of the policy shipped in the rootfs.
func PolicySources() (string, error) {
	files, err := filepath.Glob(filepath.Join(policyDir, "*", "*.cil"))
	if err != nil {
		return "", err
	}

	var sources strings.Builder

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}

		sources.Write(data)
		sources.WriteByte('\n')
	}

	return sources.String(), nil
}
