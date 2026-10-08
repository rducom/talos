// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

import (
	"context"
	"errors"
	"io/fs"

	"github.com/cosi-project/runtime/pkg/controller"
	"github.com/cosi-project/runtime/pkg/safe"
	"go.uber.org/zap"

	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// ExtensionSELinuxModuleController derives a SELinuxModule from the spec of every extension service in container mode.
//
// The module stays whatever type the machine config selects for the service: a type removed from the policy while a
// process still carries it leaves it unlabeled.
type ExtensionSELinuxModuleController struct {
	ConfigPath string
}

// Name implements controller.Controller interface.
func (ctrl *ExtensionSELinuxModuleController) Name() string {
	return "runtime.ExtensionSELinuxModuleController"
}

// Inputs implements controller.Controller interface.
func (ctrl *ExtensionSELinuxModuleController) Inputs() []controller.Input {
	return nil
}

// Outputs implements controller.Controller interface.
func (ctrl *ExtensionSELinuxModuleController) Outputs() []controller.Output {
	return []controller.Output{
		{
			Type: runtime.SELinuxModuleType,
			Kind: controller.OutputShared,
		},
	}
}

// Run implements controller.Controller interface.
func (ctrl *ExtensionSELinuxModuleController) Run(ctx context.Context, r controller.Runtime, logger *zap.Logger) error {
	// the specs are static: the modules are derived once
	select {
	case <-ctx.Done():
		return nil
	case <-r.EventCh():
	}

	rules, err := selinux.FileContextRules()
	if err != nil {
		return err
	}

	specs, err := loadExtensionServiceSpecs(ctrl.ConfigPath, logger)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}

		return err
	}

	for _, module := range extgen.Generate(specs, rules) {
		if module.Error != "" {
			logger.Error("SELinux policy of the extension service is not derived", zap.String("service", module.Name), zap.String("error", module.Error))
		}

		if err = safe.WriterModify(ctx, r, runtime.NewSELinuxModule(runtime.SELinuxModuleExtensionPrefix+module.Name), func(res *runtime.SELinuxModule) error {
			*res.TypedSpec() = runtime.SELinuxModuleSpec{Content: module.Content, Type: module.Type, Labels: module.Labels, Warnings: module.Warnings, Error: module.Error}

			return nil
		}); err != nil {
			return err
		}
	}

	return nil
}
