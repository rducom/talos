// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

import (
	"cmp"
	"time"

	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/resource/meta"
	"github.com/cosi-project/runtime/pkg/resource/protobuf"
	"github.com/cosi-project/runtime/pkg/resource/typed"

	"github.com/siderolabs/talos/pkg/machinery/proto"
)

// SELinuxAccessLogType is type of SELinuxAccessLog resource.
const SELinuxAccessLogType = resource.Type("SELinuxAccessLogs.talos.dev")

// SELinuxAccessLog is the AVC records auditd received for a source domain an audit module observes, its ID, aggregated
// by target type, class and permission.
type SELinuxAccessLog = typed.Resource[SELinuxAccessLogSpec, SELinuxAccessLogExtension]

// SELinuxAccessLogSpec describes the SELinuxAccessLog resource.
//
//gotagsrewrite:gen
type SELinuxAccessLogSpec struct {
	// Denied are the accesses the kernel refused, or would have refused in permissive mode.
	Denied []SELinuxAccess `yaml:"denied,omitempty" protobuf:"1"`
	// Granted are the accesses auditallow rules recorded.
	Granted []SELinuxAccess `yaml:"granted,omitempty" protobuf:"2"`
	// Lost is the count of records the kernel dropped since boot, whatever their domain, at the last update.
	Lost uint64 `yaml:"lost,omitempty" protobuf:"3"`
	// Truncated reports that the log reached its size and dropped new accesses.
	Truncated bool `yaml:"truncated,omitempty" protobuf:"4"`
}

// SELinuxAccess is a permission on a class of objects of a type, with the observations of its use.
//
//gotagsrewrite:gen
type SELinuxAccess struct {
	Target     string `yaml:"target" protobuf:"1"`
	Class      string `yaml:"class" protobuf:"2"`
	Permission string `yaml:"permission" protobuf:"3"`
	// Last, Comm and Path of the last record.
	Last time.Time `yaml:"last,omitempty" protobuf:"6"`
	Comm string    `yaml:"comm,omitempty" protobuf:"8"`
	Path string    `yaml:"path,omitempty" protobuf:"9"`
}

// CompareSELinuxAccess orders accesses by target, class and permission.
func CompareSELinuxAccess(a, b SELinuxAccess) int {
	return cmp.Or(cmp.Compare(a.Target, b.Target), cmp.Compare(a.Class, b.Class), cmp.Compare(a.Permission, b.Permission))
}

// NewSELinuxAccessLog initializes a SELinuxAccessLog resource.
func NewSELinuxAccessLog(id resource.ID) *SELinuxAccessLog {
	return typed.NewResource[SELinuxAccessLogSpec, SELinuxAccessLogExtension](
		resource.NewMetadata(NamespaceName, SELinuxAccessLogType, id, resource.VersionUndefined),
		SELinuxAccessLogSpec{},
	)
}

// SELinuxAccessLogExtension provides auxiliary methods for SELinuxAccessLog.
type SELinuxAccessLogExtension struct{}

// ResourceDefinition implements [typed.Extension] interface.
func (SELinuxAccessLogExtension) ResourceDefinition() meta.ResourceDefinitionSpec {
	return meta.ResourceDefinitionSpec{
		Type:             SELinuxAccessLogType,
		Aliases:          []resource.Type{},
		DefaultNamespace: NamespaceName,
		PrintColumns:     []meta.PrintColumn{},
	}
}

func init() {
	proto.RegisterDefaultTypes()

	err := protobuf.RegisterDynamic[SELinuxAccessLogSpec](SELinuxAccessLogType, &SELinuxAccessLog{})
	if err != nil {
		panic(err)
	}
}
