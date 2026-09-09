// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package extgen

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/siderolabs/talos/internal/pkg/selinux/fcontext"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	extservices "github.com/siderolabs/talos/pkg/machinery/extensions/services"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// Module is the policy module derived from the spec of an extension service.
type Module struct {
	// Name of the service.
	Name string
	// Type is the domain of the service.
	Type string
	// Content is the module in CIL.
	Content string
	// Labels are the types machined gives the state directories the service mounts, by mount source, once the
	// module is loaded.
	Labels map[string]string
	// Warnings lists the mount sources no rule could be derived for.
	Warnings []string
	// Error tells why no module could be derived: a mount source no extension may access, a name colliding with the
	// base policy.
	Error string
}

// TypeName returns the domain of an extension service.
func TypeName(name string) string {
	return "ext_" + strings.ReplaceAll(name, "-", "_") + "_t"
}

var (
	stateSuffix     = map[Kind]string{KindState: "_state_t", KindRun: "_run_t"}
	stateMacro      = map[Kind]string{KindState: "ext_state_f", KindRun: "ext_run_f"}
	sharedStateType = map[Kind]string{KindState: constants.SELinuxTypeExtensionState, KindRun: constants.SELinuxTypeExtensionRun}
	reservedTypes   = []string{constants.SELinuxTypeExtension, constants.SELinuxTypeExtensionPrivileged, constants.SELinuxTypeExtensionState, constants.SELinuxTypeExtensionRun}
)

// StateTypeName returns the type of the state directories of an extension service, on EPHEMERAL (state) or on
// a tmpfs (run).
func StateTypeName(name string, kind Kind) string {
	return strings.TrimSuffix(TypeName(name), "_t") + stateSuffix[kind]
}

// ResolvedType returns the type a service runs as: the type of the machine config, else the type its module
// derives from the spec when the module is loaded, else the default profile with the reason; with the labels
// of the state directories of the service.
func ResolvedType(configured string, module *runtime.SELinuxModuleSpec, loaded bool) (typ string, labels map[string]string, reason string) {
	switch {
	case configured != "":
		return configured, nil, ""
	case module == nil:
		return constants.SELinuxTypeExtension, nil, ""
	case module.Type == "":
		return constants.SELinuxTypeExtension, nil, module.Error
	case !loaded:
		return constants.SELinuxTypeExtension, nil, "policy module of the service is not loaded"
	default:
		return module.Type, module.Labels, ""
	}
}

// Generate derives the module of every service in container mode among the specs: a domain built on ext_domain, a type
// for its state directories, and for every bind mount source the permissions its options ask on the type of the source:
// the state type of the service (shared ext_state_t or ext_run_t when several services mount it), the type of a mount
// point Talos labels, or the file_contexts label of the image. An unresolved source is a warning, so is a source above
// directories Talos labels with types of their own, which the service does not get; a source on STATE is an error, and
// so is a type another service declares already.
func Generate(specs []extservices.Spec, rules []fcontext.Rule) []Module {
	sources := map[string][]string{}
	owners := map[string]string{}

	for _, spec := range specs {
		for _, mount := range spec.Container.Mounts {
			source := Normalize(mount.Source)
			sources[source] = append(sources[source], spec.Name)
		}
	}

	var modules []Module

	for _, spec := range specs {
		if spec.RunnerMode == extservices.RunnerModeHost {
			continue
		}

		module, err := generate(spec, rules, func(source string) []string { return sharers(sources, source) }, owners)
		if err != nil {
			module = Module{Name: spec.Name, Error: err.Error()}
		}

		modules = append(modules, module)
	}

	return modules
}

// sharers lists the services mounting a state directory, or a state directory above or below it: nested state
// directories keep the shared type, so that no service relabels the state of another.
func sharers(sources map[string][]string, source string) []string {
	var names []string

	for other, shared := range sources {
		if other == source || (StateKind(other) != KindOther && (strings.HasPrefix(other, source+"/") || strings.HasPrefix(source, other+"/"))) {
			names = append(names, shared...)
		}
	}

	slices.Sort(names)

	return slices.Compact(names)
}

//nolint:gocyclo,cyclop
func generate(spec extservices.Spec, rules []fcontext.Rule, sharers func(string) []string, owners map[string]string) (Module, error) {
	module := Module{Name: spec.Name, Type: TypeName(spec.Name), Labels: map[string]string{}}

	if slices.Contains(reservedTypes, module.Type) {
		return module, fmt.Errorf("service %q: type %s belongs to the base policy", spec.Name, module.Type)
	}

	// the names of the services are not the names of the types: a-b and a_b, foo and foo-state collide
	for _, typ := range []string{module.Type, StateTypeName(spec.Name, KindState), StateTypeName(spec.Name, KindRun)} {
		if owner, ok := owners[typ]; ok && owner != spec.Name {
			return module, fmt.Errorf("service %q: type %s is already declared by service %q", spec.Name, typ, owner)
		}

		owners[typ] = spec.Name
	}

	var (
		content = fmt.Sprintf("(type %s)\n(call ext_domain (%s))\n", module.Type, module.Type)
		grants  = grants{}
		states  = map[Kind]bool{}
	)

	for _, mount := range spec.Container.Mounts {
		// a mount of another kind carries the type of its filesystem
		if mount.Type != "" && mount.Type != "bind" {
			continue
		}

		source := Normalize(mount.Source)

		fs := "rw"
		if slices.Contains(mount.Options, "ro") {
			fs = "ro"
		}

		var typ string

		switch kind := StateKind(source); {
		case kind != KindOther:
			typ = StateTypeName(spec.Name, kind)

			if shared := sharers(source); len(shared) > 1 {
				// several services mount the directory: it keeps the type they all share
				typ = sharedStateType[kind]
				source += " (shared with " + strings.Join(slices.DeleteFunc(shared, func(name string) bool { return name == spec.Name }), " ") + ")"
			} else {
				states[kind] = true
			}

			module.Labels[Normalize(mount.Source)] = typ
		case source == constants.MachineSocketPath || source == filepath.Dir(constants.MachineSocketPath):
			// connecting needs write on the socket file and connectto on machined, whatever the mount options
			grants.add("machine_socket_t", source, "", "(sock_file (write))")
			grants.add("system_run_t", "", "ro")
			grants.add("init_t", "", "", "(unix_stream_socket (connectto))")

			continue
		case strings.HasPrefix(source, "/dev/"):
			if _, typ = mountType(source); typ == "" || typ == "device_t" {
				typ = deviceType(source)
			}
		default:
			var prefix string

			if prefix, typ = mountType(source); typ == "" {
				typ = fileContextType(rules, source)
			} else if subs := covered(source); len(subs) > 0 {
				module.Warnings = append(module.Warnings, source+" covers "+strings.Join(subs, ", ")+": not granted")
			} else if prefix != source && stateRoot(source) != "" {
				// a directory of the service under one Talos labels keeps the type of its parent, which the service shares
				module.Warnings = append(module.Warnings, fmt.Sprintf("%s is under %s (%s): the service shares that type, it is not a state directory of its own", source, prefix, typ))
			}
		}

		switch {
		case typ == "":
			module.Warnings = append(module.Warnings, "no rule derived for the mount source "+source)

			continue
		case typ == "system_state_t":
			return module, fmt.Errorf("service %q: mount source %s is on the STATE partition (%s), which no extension may access", spec.Name, source, typ)
		case strings.HasSuffix(typ, "_exec_t") && typ != "bin_exec_t":
			// a binary of the host executed without a transition, such as /sbin/init to reach machined
			grants.add(typ, source, fs, "(file (execute execute_no_trans))")
		default:
			grants.add(typ, source, fs)
		}
	}

	for _, kind := range []Kind{KindState, KindRun} {
		if states[kind] {
			content += fmt.Sprintf("(type %s)\n(call %s (%s))\n", StateTypeName(spec.Name, kind), stateMacro[kind], StateTypeName(spec.Name, kind))
		}
	}

	security := spec.Container.Security

	if security.WriteableSysfs {
		grants.add("sysfs_t", "container.security.writeableSysfs", "rw")
	}

	if security.WriteableRootfs {
		grants.add(constants.SELinuxTypeExtensionRootfs, "container.security.writeableRootfs", "rw")
	}

	if security.RootfsPropagation == "shared" {
		// mount and unmount on every filesystem, STATE included: what the snapshotters need; selinux.audit narrows it
		grants.add("filesystem_f", "container.security.rootfsPropagation", "", "(filesystem (mount remount unmount getattr))")
		grants.add("any_f", "container.security.rootfsPropagation", "", "(fs_classes (mounton))")
	}

	module.Content = content + grants.render(module.Type)

	for _, warning := range module.Warnings {
		module.Content += "; " + warning + "\n"
	}

	// a pod reaching the service through its state, the way a CSI driver talks to a storage daemon, needs the state
	// types and the socket of the service, which pod_domain does not grant
	for _, kind := range []Kind{KindState, KindRun} {
		if states[kind] {
			module.Content += fmt.Sprintf("; a pod domain reaching the service: (allow <pod_type> %s (fs_classes (rw))) (allow <pod_type> %s (unix_stream_socket (connectto)))\n",
				StateTypeName(spec.Name, kind), module.Type)
		}
	}

	return module, nil
}

// grant is what a domain gets on a type: the fs_classes set of its mounts, ro or rw, and other permission sets,
// commented with the mount sources or the security options asking for them.
type grant struct {
	fs      string
	sets    []string
	sources []string
}

type grants map[string]*grant

func (g grants) add(typ, source, fs string, sets ...string) {
	gr := g[typ]
	if gr == nil {
		gr = &grant{}
		g[typ] = gr
	}

	if fs == "rw" || gr.fs == "" {
		gr.fs = fs
	}

	if source != "" && !slices.Contains(gr.sources, source) {
		gr.sources = append(gr.sources, source)
	}

	for _, set := range sets {
		if !slices.Contains(gr.sets, set) {
			gr.sets = append(gr.sets, set)
		}
	}
}

// render writes one allow rule per type and permission set, sorted by type.
func (g grants) render(domain string) string {
	var out strings.Builder

	for _, typ := range slices.Sorted(maps.Keys(g)) {
		gr, comment := g[typ], ""

		if len(gr.sources) > 0 {
			comment = " ; " + strings.Join(gr.sources, " ")
		}

		sets := gr.sets
		if gr.fs != "" {
			sets = append([]string{"(fs_classes (" + gr.fs + "))"}, sets...)
		}

		for _, set := range sets {
			fmt.Fprintf(&out, "(allow %s %s %s)%s\n", domain, typ, set, comment)
		}
	}

	return out.String()
}

// fileContextType resolves a path of the image against file_contexts, through the symlinks of the FHS layout.
func fileContextType(rules []fcontext.Rule, source string) string {
	for from, to := range map[string]string{"/sbin/": "/usr/bin/", "/bin/": "/usr/bin/", "/lib/": "/usr/lib/", "/lib64/": "/usr/lib/"} {
		if rest, ok := strings.CutPrefix(source, from); ok {
			source = to + rest
		}
	}

	return fcontext.TypeOf(fcontext.Lookup(rules, source, fcontext.TypeReg))
}
