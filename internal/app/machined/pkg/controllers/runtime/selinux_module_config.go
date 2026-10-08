// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

import (
	"context"
	"fmt"

	"github.com/cosi-project/runtime/pkg/controller"
	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/siderolabs/gen/optional"
	"go.uber.org/zap"

	"github.com/siderolabs/talos/pkg/machinery/resources/config"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// SELinuxModuleConfigController publishes the SELinuxPolicyConfig documents of the machine config as SELinuxModule resources.
type SELinuxModuleConfigController struct{}

// Name implements controller.Controller interface.
func (ctrl *SELinuxModuleConfigController) Name() string {
	return "runtime.SELinuxModuleConfigController"
}

// Inputs implements controller.Controller interface.
func (ctrl *SELinuxModuleConfigController) Inputs() []controller.Input {
	return []controller.Input{
		{
			Namespace: config.NamespaceName,
			Type:      config.MachineConfigType,
			ID:        optional.Some(config.ActiveID),
			Kind:      controller.InputWeak,
		},
	}
}

// Outputs implements controller.Controller interface.
func (ctrl *SELinuxModuleConfigController) Outputs() []controller.Output {
	return []controller.Output{
		{
			Type: runtime.SELinuxModuleType,
			Kind: controller.OutputShared,
		},
	}
}

// Run implements controller.Controller interface.
func (ctrl *SELinuxModuleConfigController) Run(ctx context.Context, r controller.Runtime, _ *zap.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.EventCh():
		}

		cfg, err := safe.ReaderGetByID[*config.MachineConfig](ctx, r, config.ActiveID)
		if err != nil && !state.IsNotFoundError(err) {
			return fmt.Errorf("error getting machine config: %w", err)
		}

		r.StartTrackingOutputs()

		if cfg != nil {
			for _, module := range cfg.Config().SELinuxPolicyConfigs() {
				if err = safe.WriterModify(ctx, r, runtime.NewSELinuxModule(runtime.SELinuxModuleConfigPrefix+module.Name()), func(res *runtime.SELinuxModule) error {
					res.TypedSpec().Content = module.Content()

					return nil
				}); err != nil {
					return err
				}
			}
		}

		if err = safe.CleanupOutputs[*runtime.SELinuxModule](ctx, r); err != nil {
			return err
		}
	}
}
