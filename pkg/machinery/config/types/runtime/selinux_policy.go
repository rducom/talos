// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

//docgen:jsonschema

import (
	"errors"
	"fmt"

	"github.com/siderolabs/talos/pkg/machinery/config/config"
	"github.com/siderolabs/talos/pkg/machinery/config/internal/registry"
	"github.com/siderolabs/talos/pkg/machinery/config/types/meta"
	"github.com/siderolabs/talos/pkg/machinery/config/validation"
	"github.com/siderolabs/talos/pkg/machinery/labels"
)

// SELinuxPolicyConfigKind is a config document kind.
const SELinuxPolicyConfigKind = "SELinuxPolicyConfig"

func init() {
	registry.Register(SELinuxPolicyConfigKind, func(version string) config.Document {
		switch version {
		case "v1alpha1": //nolint:goconst
			return &SELinuxPolicyConfigV1Alpha1{}
		default:
			return nil
		}
	})
}

// Check interfaces.
var (
	_ config.SELinuxPolicyConfig = &SELinuxPolicyConfigV1Alpha1{}
	_ config.NamedDocument       = &SELinuxPolicyConfigV1Alpha1{}
	_ config.Validator           = &SELinuxPolicyConfigV1Alpha1{}
)

// SELinuxPolicyConfigV1Alpha1 is a SELinux policy module document.
//
//	examples:
//	  - value: exampleSELinuxPolicyConfigV1Alpha1()
//	alias: SELinuxPolicyConfig
//	schemaRoot: true
//	schemaMeta: v1alpha1/SELinuxPolicyConfig
type SELinuxPolicyConfigV1Alpha1 struct {
	meta.Meta `yaml:",inline"`
	//   description: |
	//     Name of the policy module.
	//   schemaRequired: true
	MetaName string `yaml:"name"`
	//   description: |
	//     Policy module in CIL, compiled with the Talos policy and loaded without a reboot.
	//     A module declares a type and calls one of the macros of the base policy:
	//     `pod_domain` gives the rights of a regular pod, `pod_privileged_domain` those of `pod_privileged_t`
	//     and `pod_hostmon_domain` those of a process monitor, which reads `/proc` and the files of every pod
	//     across MCS categories but never writes them.
	//     The attributes `any_p` (every process type), `any_f` (every file type),
	//     `privileged_readable_f` (files a privileged pod may read), `mcs_exempt_p` and `mcs_read_exempt_p`
	//     (domains ignoring MCS categories, in both directions or for reading only) are available to extra rules.
	//     Whatever a module grants, a workload domain never reads the STATE partition, connects to machined
	//     or ptraces a host service: `secilc` rejects such a module and the running policy is unchanged.
	//     Anything else is open to a module, which is as trusted as the machine config carrying it.
	//     A workload selects the type with `securityContext.seLinuxOptions.type` in its pod spec.
	//     Load the module before rolling the workload out, a type unknown to the policy fails the container at runc;
	//     delete the workload before removing its module, a type removed from the policy leaves its running
	//     containers without any access.
	//     Privileged containers cannot select a type: containerd clears their label and they land in `pod_privileged_t`.
	//     `spc_t` is already an alias of `pod_privileged_t`, any other type must be declared by a module.
	//   schemaRequired: true
	PolicyContent string `yaml:"content"`
}

// NewSELinuxPolicyConfigV1Alpha1 creates a new SELinuxPolicyConfig document.
func NewSELinuxPolicyConfigV1Alpha1(name string) *SELinuxPolicyConfigV1Alpha1 {
	return &SELinuxPolicyConfigV1Alpha1{
		Meta: meta.Meta{
			MetaKind:       SELinuxPolicyConfigKind,
			MetaAPIVersion: "v1alpha1",
		},
		MetaName: name,
	}
}

func exampleSELinuxPolicyConfigV1Alpha1() *SELinuxPolicyConfigV1Alpha1 {
	cfg := NewSELinuxPolicyConfigV1Alpha1("hostmon")
	cfg.PolicyContent = "(type pod_hostmon_t)\n(call pod_hostmon_domain (pod_hostmon_t))\n"

	return cfg
}

// Clone implements config.Document interface.
func (s *SELinuxPolicyConfigV1Alpha1) Clone() config.Document {
	return s.DeepCopy()
}

// Name implements config.NamedDocument interface.
func (s *SELinuxPolicyConfigV1Alpha1) Name() string {
	return s.MetaName
}

// Content implements config.SELinuxPolicyConfig interface.
func (s *SELinuxPolicyConfigV1Alpha1) Content() string {
	return s.PolicyContent
}

// SELinuxPolicyConfigSignal implements config.SELinuxPolicyConfig interface.
func (s *SELinuxPolicyConfigV1Alpha1) SELinuxPolicyConfigSignal() {}

// Validate implements config.Validator interface.
func (s *SELinuxPolicyConfigV1Alpha1) Validate(validation.RuntimeMode, ...validation.Option) ([]string, error) {
	var validationErrors error

	if err := labels.ValidateDNS1123Subdomain(s.MetaName); err != nil {
		validationErrors = errors.Join(validationErrors, fmt.Errorf("invalid name: %w", err))
	}

	if s.PolicyContent == "" {
		validationErrors = errors.Join(validationErrors, errors.New("content is required"))
	}

	return nil, validationErrors
}
