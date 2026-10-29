// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package extgen derives the SELinux policy of extension services from what their specs declare.
package extgen

import (
	"path/filepath"
	"strings"

	"github.com/siderolabs/talos/internal/pkg/selinux/fcontext"
	"github.com/siderolabs/talos/pkg/machinery/constants"
)

// Kind tells whether a mount source is a state directory of the service, which machined labels with a type of
// the service before it starts.
type Kind int

// Kinds of mount sources.
const (
	KindOther Kind = iota
	KindState      // a directory of the EPHEMERAL partition, under /var/{lib,log,cache,local}
	KindRun        // a directory of a tmpfs, under /var/run or /run
)

var stateRoots = map[string]Kind{
	"/var/lib":        KindState,
	"/var/log":        KindState,
	"/var/cache":      KindState,
	"/var/local":      KindState,
	"/var/run":        KindRun,
	constants.RunPath: KindRun,
}

// mountTypes are the types of the mount points of Talos and of the directories it labels with a type of its own.
//
// A mount source not declared as state resolves to the type of its longest prefix here; a source under one of
// these directories is never a state directory of a service.
var mountTypes = map[string]string{
	constants.EphemeralMountPoint:   fcontext.TypeOf(constants.EphemeralSelinuxLabel),
	constants.KubeletDataPath:       fcontext.TypeOf(constants.KubeletDataSELinuxLabel),
	constants.EtcdDataPath:          fcontext.TypeOf(constants.EtcdDataSELinuxLabel),
	constants.CRIContainerdDataPath: fcontext.TypeOf(constants.CRIContainerdDataSELinuxLabel),
	"/var/log":                      fcontext.TypeOf(constants.LogSELinuxLabel),
	"/var/run":                      fcontext.TypeOf(constants.RunSelinuxLabel),
	constants.RunPath:               fcontext.TypeOf(constants.RunSelinuxLabel),
	constants.SystemPath:            fcontext.TypeOf(constants.SystemSelinuxLabel),
	constants.SystemVarPath:         fcontext.TypeOf(constants.SystemVarSelinuxLabel),
	constants.SystemEtcPath:         fcontext.TypeOf(constants.EtcSelinuxLabel),
	constants.StateMountPoint:       fcontext.TypeOf(constants.StateSelinuxLabel),
	constants.MachineSocketPath:     fcontext.TypeOf(constants.MachineSocketLabel),
	// labeled by the policy or by a mount option, without a constant for the label
	constants.SeccompProfilesDirectory: "seccomp_profile_t",
	constants.KubernetesAuditLogDir:    "kube_log_t",
	constants.SystemRunPath:            "system_run_t",
	"/var/lib/cni":                     "cni_state_t",
	"/var/log/audit":                   "audit_log_t",
	"/var/log/containers":              "containers_log_t",
	"/var/log/pods":                    "pods_log_t",
	"/var/run/lock":                    "var_lock_t",
	"/run/lock":                        "var_lock_t",
	"/run/udev":                        "udev_run_t",
	"/run/containerd":                  "pod_containerd_run_t",
	"/dev":                             "device_t",
	"/sys":                             "sysfs_t",
	"/sys/fs/cgroup":                   "cgroup_t",
	"/sys/module":                      "sys_module_t",
	"/proc":                            "procfs_t",
}

// mountType returns the type of the longest prefix of the source in mountTypes.
func mountType(source string) (prefix, typ string) {
	for candidate, t := range mountTypes {
		if (source == candidate || strings.HasPrefix(source, candidate+"/")) && len(candidate) > len(prefix) {
			prefix, typ = candidate, t
		}
	}

	return prefix, typ
}

// StateKind classifies a mount source: a path strictly under one of the state roots is a state directory of the
// service, unless Talos labels it or one of its parents with a type of its own.
func StateKind(source string) Kind {
	source = filepath.Clean(source)

	for root, kind := range stateRoots {
		if strings.HasPrefix(source, root+"/") {
			if prefix, _ := mountType(source); len(prefix) > len(root) {
				return KindOther
			}

			return kind
		}
	}

	return KindOther
}
