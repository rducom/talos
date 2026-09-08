// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

import (
	"time"

	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/resource/meta"
	"github.com/cosi-project/runtime/pkg/resource/protobuf"
	"github.com/cosi-project/runtime/pkg/resource/typed"

	"github.com/siderolabs/talos/pkg/machinery/proto"
)

// SELinuxDomainStatusType is type of SELinuxDomainStatus resource.
const SELinuxDomainStatusType = resource.Type("SELinuxDomainStatuses.talos.dev")

// SELinuxDomainStatus reports what a domain, its ID, exercised of the permissions the loaded policy grants it and
// what it did not, while the machine config audits it.
type SELinuxDomainStatus = typed.Resource[SELinuxDomainStatusSpec, SELinuxDomainStatusExtension]

// SELinuxDomainStatusSpec describes the SELinuxDomainStatus resource.
//
//gotagsrewrite:gen
type SELinuxDomainStatusSpec struct {
	// Exercised are the granted accesses observed since ObservedSince.
	Exercised []SELinuxAccess `yaml:"exercised,omitempty" protobuf:"1"`
	// Unexercised are the granted accesses not observed since ObservedSince.
	Unexercised []SELinuxAccess `yaml:"unexercised,omitempty" protobuf:"2"`
	// ObservedSince is the start of the audit.
	ObservedSince time.Time `yaml:"observedSince" protobuf:"3"`
	// Rounds counts the reloads of the audit module since ObservedSince.
	Rounds uint32 `yaml:"rounds" protobuf:"4"`
	// LostRecords counts the audit records the kernel dropped since ObservedSince: an exercised access may have been missed.
	LostRecords uint64 `yaml:"lostRecords,omitempty" protobuf:"5"`
	// Truncated reports that a list reached its size.
	Truncated bool `yaml:"truncated,omitempty" protobuf:"6"`
	// NarrowedModule is a policy module granting the domain the exercised accesses only; it names the types of the loaded
	// policy, modules included, and compiles as long as they do. The module derived for an extension service declares its
	// type already: rename the type before loading the module, and select it with selinux.type.
	NarrowedModule string `yaml:"narrowedModule,omitempty" protobuf:"7"`
	// SuggestedAllows are the accesses the domain was denied since ObservedSince, as allow rules to sort out.
	SuggestedAllows string `yaml:"suggestedAllows,omitempty" protobuf:"8"`
}

// NewSELinuxDomainStatus initializes a SELinuxDomainStatus resource.
func NewSELinuxDomainStatus(id resource.ID) *SELinuxDomainStatus {
	return typed.NewResource[SELinuxDomainStatusSpec, SELinuxDomainStatusExtension](
		resource.NewMetadata(NamespaceName, SELinuxDomainStatusType, id, resource.VersionUndefined),
		SELinuxDomainStatusSpec{},
	)
}

// SELinuxDomainStatusExtension provides auxiliary methods for SELinuxDomainStatus.
type SELinuxDomainStatusExtension struct{}

// ResourceDefinition implements [typed.Extension] interface.
func (SELinuxDomainStatusExtension) ResourceDefinition() meta.ResourceDefinitionSpec {
	return meta.ResourceDefinitionSpec{
		Type:             SELinuxDomainStatusType,
		Aliases:          []resource.Type{},
		DefaultNamespace: NamespaceName,
		PrintColumns: []meta.PrintColumn{
			{Name: "Observed Since", JSONPath: `{.observedSince}`},
			{Name: "Rounds", JSONPath: `{.rounds}`},
			{Name: "Lost Records", JSONPath: `{.lostRecords}`},
			{Name: "Truncated", JSONPath: `{.truncated}`},
		},
	}
}

func init() {
	proto.RegisterDefaultTypes()

	err := protobuf.RegisterDynamic[SELinuxDomainStatusSpec](SELinuxDomainStatusType, &SELinuxDomainStatus{})
	if err != nil {
		panic(err)
	}
}
