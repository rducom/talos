// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

import (
	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/resource/meta"
	"github.com/cosi-project/runtime/pkg/resource/protobuf"
	"github.com/cosi-project/runtime/pkg/resource/typed"

	"github.com/siderolabs/talos/pkg/machinery/proto"
)

// SELinuxModuleType is type of SELinuxModule resource.
const SELinuxModuleType = resource.Type("SELinuxModules.talos.dev")

// SELinuxModuleExtensionPrefix is followed by the name of the extension service the module is derived for, which makes the
// ID of the module the ID of the service.
const SELinuxModuleExtensionPrefix = "ext-"

// SELinuxModule is a policy module the imager derived from the spec of an extension service and compiled into the policy
// of the image.
type SELinuxModule = typed.Resource[SELinuxModuleSpec, SELinuxModuleExtension]

// SELinuxModuleSpec describes the SELinuxModule resource.
//
//gotagsrewrite:gen
type SELinuxModuleSpec struct {
	// Content is the module in CIL.
	Content string `yaml:"content,omitempty" protobuf:"1"`
	// Labels are the types machined gives the state directories of the service, by mount source.
	Labels map[string]string `yaml:"labels,omitempty" protobuf:"2"`
	// Warnings lists what could not be derived from the service spec.
	Warnings []string `yaml:"warnings,omitempty" protobuf:"3"`
	// Type is the domain the module declares for the service.
	Type string `yaml:"type,omitempty" protobuf:"4"`
}

// NewSELinuxModule initializes a SELinuxModule resource.
func NewSELinuxModule(id resource.ID) *SELinuxModule {
	return typed.NewResource[SELinuxModuleSpec, SELinuxModuleExtension](
		resource.NewMetadata(NamespaceName, SELinuxModuleType, id, resource.VersionUndefined),
		SELinuxModuleSpec{},
	)
}

// SELinuxModuleExtension provides auxiliary methods for SELinuxModule.
type SELinuxModuleExtension struct{}

// ResourceDefinition implements [typed.Extension] interface.
func (SELinuxModuleExtension) ResourceDefinition() meta.ResourceDefinitionSpec {
	return meta.ResourceDefinitionSpec{
		Type:             SELinuxModuleType,
		Aliases:          []resource.Type{},
		DefaultNamespace: NamespaceName,
		PrintColumns: []meta.PrintColumn{
			{Name: "Type", JSONPath: `{.type}`},
			{Name: "Warnings", JSONPath: `{.warnings}`},
		},
	}
}

func init() {
	proto.RegisterDefaultTypes()

	err := protobuf.RegisterDynamic[SELinuxModuleSpec](SELinuxModuleType, &SELinuxModule{})
	if err != nil {
		panic(err)
	}
}
