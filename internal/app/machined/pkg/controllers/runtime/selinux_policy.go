// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/cosi-project/runtime/pkg/controller"
	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/siderolabs/gen/optional"
	"go.uber.org/zap"

	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/pkg/machinery/resources/config"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// SELinuxPolicyController compiles the SELinux policy with the SELinuxPolicyConfig modules and loads it.
type SELinuxPolicyController struct {
	modules map[string]string // modules compiled into the loaded policy, nil until the first reconcile
}

// Name implements controller.Controller interface.
func (ctrl *SELinuxPolicyController) Name() string {
	return "runtime.SELinuxPolicyController"
}

// Inputs implements controller.Controller interface.
func (ctrl *SELinuxPolicyController) Inputs() []controller.Input {
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
func (ctrl *SELinuxPolicyController) Outputs() []controller.Output {
	return []controller.Output{
		{
			Type: runtime.SELinuxPolicyStatusType,
			Kind: controller.OutputExclusive,
		},
	}
}

// Run implements controller.Controller interface.
//
//nolint:gocyclo
func (ctrl *SELinuxPolicyController) Run(ctx context.Context, r controller.Runtime, logger *zap.Logger) error {
	if !selinux.IsEnabled() {
		return nil
	}

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

		modules := map[string]string{}

		if cfg != nil {
			for _, module := range cfg.Config().SELinuxPolicyConfigs() {
				modules[module.Name()] = module.Content()
			}
		}

		if ctrl.modules != nil && maps.Equal(modules, ctrl.modules) {
			continue
		}

		names := slices.Sorted(maps.Keys(modules))

		var loadErr error

		// init has loaded the base policy already, only the modules need a compile and a load
		if ctrl.modules != nil || len(modules) > 0 {
			if loadErr = ctrl.load(ctx, modules); loadErr == nil {
				logger.Info("SELinux policy loaded", zap.Strings("modules", names))
			}
		}

		if loadErr == nil {
			ctrl.modules = modules
		}

		if err = safe.WriterModify(ctx, r, runtime.NewSELinuxPolicyStatus(), func(status *runtime.SELinuxPolicyStatus) error {
			status.TypedSpec().Modules = names
			status.TypedSpec().Error = ""

			if loadErr != nil {
				status.TypedSpec().Error = loadErr.Error()
			}

			return nil
		}); err != nil {
			return fmt.Errorf("error updating SELinux policy status: %w", err)
		}

		if loadErr != nil {
			return loadErr
		}
	}
}

func (ctrl *SELinuxPolicyController) load(ctx context.Context, modules map[string]string) error {
	policy, err := selinux.Compile(ctx, modules)
	if err != nil {
		return fmt.Errorf("error compiling SELinux policy: %w", err)
	}

	if err = selinux.LoadPolicy(policy); err != nil {
		return fmt.Errorf("error loading SELinux policy: %w", err)
	}

	return nil
}
