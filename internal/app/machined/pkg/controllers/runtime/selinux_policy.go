// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/cosi-project/runtime/pkg/controller"
	"github.com/cosi-project/runtime/pkg/safe"
	"go.uber.org/zap"

	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// SELinuxPolicyController compiles the SELinux policy with the SELinuxModule resources and loads it.
//
// The modules of the extension services are part of the policy sources of the image, which the imager compiled into the
// policy init loaded: only the other modules need a compile and a load.
type SELinuxPolicyController struct {
	// The compiler and the loader, replaced in tests.
	Compile func(ctx context.Context, modules map[string]string) ([]byte, error)
	Load    func(policy []byte) error

	requested  map[string]string // modules to compile present at the last reconcile, nil until the first one
	extensions []string          // modules of the extension services present at the last reconcile
	loaded     map[string]string
	rejected   map[string]error
}

// Name implements controller.Controller interface.
func (ctrl *SELinuxPolicyController) Name() string {
	return "runtime.SELinuxPolicyController"
}

// Inputs implements controller.Controller interface.
func (ctrl *SELinuxPolicyController) Inputs() []controller.Input {
	return []controller.Input{
		{
			Namespace: runtime.NamespaceName,
			Type:      runtime.SELinuxModuleType,
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
	if ctrl.Compile == nil {
		if !selinux.IsEnabled() {
			return nil
		}

		ctrl.Compile, ctrl.Load = selinux.Compile, selinux.LoadPolicy
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.EventCh():
		}

		list, err := safe.ReaderListAll[*runtime.SELinuxModule](ctx, r)
		if err != nil {
			return fmt.Errorf("error listing SELinux modules: %w", err)
		}

		var (
			modules    = map[string]string{}
			extensions []string
		)

		for module := range list.All() {
			if id := module.Metadata().ID(); strings.HasPrefix(id, runtime.SELinuxModuleExtensionPrefix) {
				extensions = append(extensions, id)
			} else {
				modules[id] = module.TypedSpec().Content
			}
		}

		if ctrl.requested != nil && maps.Equal(modules, ctrl.requested) && slices.Equal(extensions, ctrl.extensions) {
			continue
		}

		// init has loaded the policy of the image already, only a change of the other modules needs a compile and a load
		if !maps.Equal(modules, ctrl.requested) {
			start := time.Now()

			if ctrl.loaded, ctrl.rejected, err = ctrl.load(ctx, modules); err != nil {
				return err
			}

			logger.Info("SELinux policy loaded", zap.Strings("modules", slices.Sorted(maps.Keys(ctrl.loaded))), zap.Duration("duration", time.Since(start)))

			for _, name := range slices.Sorted(maps.Keys(ctrl.rejected)) {
				logger.Error("SELinux policy module rejected", zap.String("module", name), zap.Error(ctrl.rejected[name]))
			}
		}

		ctrl.requested, ctrl.extensions = modules, extensions

		if err = safe.WriterModify(ctx, r, runtime.NewSELinuxPolicyStatus(), func(status *runtime.SELinuxPolicyStatus) error {
			status.TypedSpec().Modules = slices.Sorted(slices.Values(append(slices.Collect(maps.Keys(modules)), extensions...)))
			status.TypedSpec().Loaded = slices.Sorted(slices.Values(append(slices.Collect(maps.Keys(ctrl.loaded)), extensions...)))
			status.TypedSpec().Error = rejectedError(ctrl.rejected)

			return nil
		}); err != nil {
			return fmt.Errorf("error updating SELinux policy status: %w", err)
		}
	}
}

// load compiles and loads the policy with the modules, leaving out the ones the compile rejects: the modules are added one
// at a time, in name order, and a module rejected for a type a later one declares gets another pass, so that a bad module
// never takes the others down.
func (ctrl *SELinuxPolicyController) load(ctx context.Context, modules map[string]string) (map[string]string, map[string]error, error) {
	loaded, rejected := modules, map[string]error{}

	policy, err := ctrl.Compile(ctx, modules)
	if err != nil {
		loaded = map[string]string{}

		for added := true; added; {
			added = false

			for _, name := range slices.Sorted(maps.Keys(modules)) {
				if _, ok := loaded[name]; ok {
					continue
				}

				trial := maps.Clone(loaded)
				trial[name] = modules[name]

				if _, err = ctrl.Compile(ctx, trial); err == nil {
					loaded, added = trial, true

					delete(rejected, name)
				} else {
					rejected[name] = err
				}
			}
		}

		if policy, err = ctrl.Compile(ctx, loaded); err != nil {
			return nil, nil, fmt.Errorf("error compiling SELinux policy: %w", err)
		}
	}

	if err = ctrl.Load(policy); err != nil {
		return nil, nil, fmt.Errorf("error loading SELinux policy: %w", err)
	}

	return loaded, rejected, nil
}

// rejectedError renders the rejected modules and their errors for the status.
func rejectedError(rejected map[string]error) string {
	lines := make([]string, 0, len(rejected))

	for _, name := range slices.Sorted(maps.Keys(rejected)) {
		lines = append(lines, fmt.Sprintf("module %s rejected: %v", name, rejected[name]))
	}

	return strings.Join(lines, "\n")
}
