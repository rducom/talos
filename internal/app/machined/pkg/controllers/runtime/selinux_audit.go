// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/cosi-project/runtime/pkg/controller"
	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/siderolabs/gen/optional"
	"go.uber.org/zap"

	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
	"github.com/siderolabs/talos/pkg/machinery/resources/config"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// SELinuxAuditController observes the domains the machine config asks to audit.
//
// For each of them it asks the kernel every permission the loaded policy grants the domain, keeps an auditallow
// module on the ones not observed yet, reloaded at most once a minute, and publishes a SELinuxDomainStatus with
// what the domain exercised, what it did not, and a module narrowed to what it exercised.
type SELinuxAuditController struct {
	// The kernel interfaces, replaced in tests.
	ComputeAV     func(scon, tcon string, class uint16) (selinux.AccessVector, error)
	Classes       func() (map[string]selinux.Class, error)
	CheckContext  func(label string) error
	PolicySources func() (string, error)
	Now           func() time.Time

	observations map[string]*observation
	base         string // the CIL sources of the base policy, read once
	policyKey    string // the modules present, audit modules excluded
	seqno        uint32 // the policy the kernel runs
}

// observation is the audit of one domain.
type observation struct {
	since     time.Time
	rounds    uint32
	lostBase  uint64
	lastLost  uint64
	lastRound time.Time
	policyKey string
	seqno     uint32
	module    string
	plumbing  string // the plumbing of the domain, from the domain the system transitions to it from, and its MCS exemption
	granted   map[string]runtime.SELinuxAccess
	exercised map[string]runtime.SELinuxAccess
}

// auditRoundInterval separates two reloads of the audit module of a domain.
const auditRoundInterval = time.Minute

// auditListLimit is the number of accesses a status lists at most.
const auditListLimit = 512

// Name implements controller.Controller interface.
func (ctrl *SELinuxAuditController) Name() string {
	return "runtime.SELinuxAuditController"
}

// Inputs implements controller.Controller interface.
func (ctrl *SELinuxAuditController) Inputs() []controller.Input {
	return []controller.Input{
		{
			Namespace: config.NamespaceName,
			Type:      config.MachineConfigType,
			ID:        optional.Some(config.ActiveID),
			Kind:      controller.InputWeak,
		},
		{
			Namespace: runtime.NamespaceName,
			Type:      runtime.ExtensionServiceConfigType,
			Kind:      controller.InputWeak,
		},
		{
			Namespace: runtime.NamespaceName,
			Type:      runtime.SELinuxModuleType,
			Kind:      controller.InputWeak,
		},
		{
			Namespace: runtime.NamespaceName,
			Type:      runtime.SELinuxPolicyStatusType,
			ID:        optional.Some(runtime.SELinuxPolicyStatusID),
			Kind:      controller.InputWeak,
		},
		{
			Namespace: runtime.NamespaceName,
			Type:      runtime.SELinuxAccessLogType,
			Kind:      controller.InputWeak,
		},
	}
}

// Outputs implements controller.Controller interface.
func (ctrl *SELinuxAuditController) Outputs() []controller.Output {
	return []controller.Output{
		{
			Type: runtime.SELinuxModuleType,
			Kind: controller.OutputShared,
		},
		{
			Type: runtime.SELinuxDomainStatusType,
			Kind: controller.OutputExclusive,
		},
	}
}

// Run implements controller.Controller interface.
//
//nolint:gocyclo,cyclop
func (ctrl *SELinuxAuditController) Run(ctx context.Context, r controller.Runtime, logger *zap.Logger) error {
	if ctrl.ComputeAV == nil {
		if !selinux.IsEnabled() {
			return nil
		}

		ctrl.ComputeAV, ctrl.Classes, ctrl.CheckContext, ctrl.PolicySources, ctrl.Now = selinux.ComputeAV, selinux.Classes, selinux.CheckContext, selinux.PolicySources, time.Now
	}

	ctrl.observations = map[string]*observation{}

	// a round deferred by the interval wakes the controller up once
	var wake <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.EventCh():
		case <-wake:
			wake = nil
		}

		audited, sources, reconciled, err := ctrl.audited(ctx, r)
		if err != nil {
			return err
		}

		var classes map[string]selinux.Class

		if len(audited) > 0 && reconciled {
			if classes, err = ctrl.Classes(); err != nil {
				return fmt.Errorf("error reading the object classes: %w", err)
			}

			// the seqno of the policy the kernel runs: it changes at every load
			if av, err := ctrl.ComputeAV(selinux.Label("init_t"), selinux.Label("init_t"), classes["process"].Index); err == nil {
				ctrl.seqno = av.Seqno
			}
		}

		accessLogs, err := safe.ReaderListAll[*runtime.SELinuxAccessLog](ctx, r)
		if err != nil {
			return fmt.Errorf("error listing the access logs: %w", err)
		}

		logs := map[string]*runtime.SELinuxAccessLogSpec{}

		var lost uint64

		for log := range accessLogs.All() {
			logs[log.Metadata().ID()] = log.TypedSpec()
			lost = max(lost, log.TypedSpec().Lost)
		}

		for typ, obs := range ctrl.observations {
			if _, ok := audited[typ]; !ok {
				delete(ctrl.observations, typ)

				logger.Info("SELinux audit of the domain stopped", zap.String("type", typ), zap.Uint32("rounds", obs.rounds))
			}
		}

		r.StartTrackingOutputs()

		for _, typ := range slices.Sorted(maps.Keys(audited)) {
			// the policy controller has not reconciled yet
			if !reconciled {
				break
			}

			obs, ok := ctrl.observations[typ]
			if !ok {
				obs = &observation{since: ctrl.Now(), lostBase: lost, lastLost: lost, exercised: map[string]runtime.SELinuxAccess{}}
				ctrl.observations[typ] = obs
			}

			spec, deferred, err := ctrl.round(ctx, r, logger, typ, obs, logs[typ], sources, classes, lost)
			if err != nil {
				return err
			}

			if deferred && wake == nil {
				wake = time.After(auditRoundInterval)
			}

			spec.LostRecords = max(lost, obs.lostBase) - obs.lostBase

			if err = safe.WriterModify(ctx, r, runtime.NewSELinuxDomainStatus(typ), func(res *runtime.SELinuxDomainStatus) error {
				*res.TypedSpec() = spec

				return nil
			}); err != nil {
				return err
			}
		}

		// one call: the first ends the tracking
		if err = r.CleanupOutputs(ctx,
			resource.NewMetadata(runtime.NamespaceName, runtime.SELinuxModuleType, "", resource.VersionUndefined),
			resource.NewMetadata(runtime.NamespaceName, runtime.SELinuxDomainStatusType, "", resource.VersionUndefined),
		); err != nil {
			return err
		}
	}
}

// audited returns the domains to audit, the CIL sources of the base policy and of the modules present, and whether the
// policy controller has reconciled; it keys the policy by the modules present, audit modules excluded, so that a module
// removed leaves the audit modules whatever the status says.
//
//nolint:gocyclo,cyclop
func (ctrl *SELinuxAuditController) audited(ctx context.Context, r controller.Reader) (map[string]struct{}, []string, bool, error) {
	moduleList, err := safe.ReaderListAll[*runtime.SELinuxModule](ctx, r)
	if err != nil {
		return nil, nil, false, fmt.Errorf("error listing the SELinux modules: %w", err)
	}

	modules := map[string]*runtime.SELinuxModuleSpec{}
	key := sha256.New()

	for module := range moduleList.All() {
		modules[module.Metadata().ID()] = module.TypedSpec()
	}

	for _, id := range slices.Sorted(maps.Keys(modules)) {
		if !strings.HasPrefix(id, "audit-") {
			fmt.Fprintf(key, "%s\n%s\n", id, modules[id].Content)
		}
	}

	ctrl.policyKey = hex.EncodeToString(key.Sum(nil))

	status, err := safe.ReaderGetByID[*runtime.SELinuxPolicyStatus](ctx, r, runtime.SELinuxPolicyStatusID)
	if err != nil && !state.IsNotFoundError(err) {
		return nil, nil, false, fmt.Errorf("error getting the SELinux policy status: %w", err)
	}

	var loaded []string

	if err == nil {
		loaded = status.TypedSpec().Loaded
	}

	audited := map[string]struct{}{}

	serviceConfigs, err := safe.ReaderListAll[*runtime.ExtensionServiceConfig](ctx, r)
	if err != nil {
		return nil, nil, false, fmt.Errorf("error listing the extension service configs: %w", err)
	}

	for cfg := range serviceConfigs.All() {
		id := runtime.SELinuxModuleExtensionPrefix + cfg.Metadata().ID()

		// a service in host mode has no module; the type is the one the service resolves
		if module, ok := modules[id]; ok && cfg.TypedSpec().SELinuxAudit {
			typ, _, _ := extgen.ResolvedType(cfg.TypedSpec().SELinuxType, module, slices.Contains(loaded, id))
			audited[typ] = struct{}{}
		}
	}

	cfg, err := safe.ReaderGetByID[*config.MachineConfig](ctx, r, config.ActiveID)
	if err != nil && !state.IsNotFoundError(err) {
		return nil, nil, false, fmt.Errorf("error getting machine config: %w", err)
	}

	if cfg != nil {
		for _, module := range cfg.Config().SELinuxPolicyConfigs() {
			if module.Audit() {
				for _, typ := range selinux.Types(module.Content()) {
					// a module declares file types too: only a domain is observed
					if ctrl.CheckContext(selinux.Label(typ)) == nil {
						audited[typ] = struct{}{}
					}
				}
			}
		}
	}

	if ctrl.base == "" {
		if ctrl.base, err = ctrl.PolicySources(); err != nil {
			return nil, nil, false, fmt.Errorf("error reading the policy sources: %w", err)
		}
	}

	sources := []string{ctrl.base}

	for _, module := range modules {
		sources = append(sources, module.Content)
	}

	return audited, sources, status != nil, nil
}

// round merges the new observations of a domain, reloads its audit module unless the last reload is less than the
// interval away, and returns its status.
//
//nolint:gocyclo
func (ctrl *SELinuxAuditController) round(
	ctx context.Context, r controller.ReaderWriter, logger *zap.Logger,
	typ string, obs *observation, log *runtime.SELinuxAccessLogSpec, sources []string, classes map[string]selinux.Class, lost uint64,
) (runtime.SELinuxDomainStatusSpec, bool, error) {
	var spec runtime.SELinuxDomainStatusSpec

	// the modules present changed, or the kernel loaded a policy: the grants are enumerated again, and the module
	// follows without waiting, so that it never names a type of a module removed
	enumerated := obs.policyKey != ctrl.policyKey || obs.seqno != ctrl.seqno

	if enumerated {
		obs.granted, obs.policyKey, obs.seqno = ctrl.enumerate(typ, sources, classes), ctrl.policyKey, ctrl.seqno
		obs.plumbing = ctrl.plumbing(typ, obs.granted, classes)
	}

	if log != nil {
		for _, access := range log.Granted {
			key := accessKey(access)

			// the log runs since boot: only what was observed since the audit began counts
			if _, ok := obs.granted[key]; ok && !access.Last.Before(obs.since) {
				obs.exercised[key] = access
			}
		}

		denied := slices.DeleteFunc(slices.Clone(log.Denied), func(access runtime.SELinuxAccess) bool { return access.Last.Before(obs.since) })
		spec.SuggestedAllows = renderRules("allow", typ, denied, true)
	}

	var unexercised []runtime.SELinuxAccess

	for key, access := range obs.granted {
		if _, ok := obs.exercised[key]; !ok {
			unexercised = append(unexercised, access)
		}
	}

	now := ctrl.Now()
	module := renderRules("auditallow", typ, unexercised, false)
	reload := obs.rounds == 0 || module != obs.module
	deferred := reload && obs.rounds > 0 && !enumerated && now.Sub(obs.lastRound) < auditRoundInterval

	if reload && !deferred {
		obs.module, obs.lastRound = module, now
		obs.rounds++

		// the records the kernel dropped since the last round, whatever their domain
		logger.Info("SELinux audit module reloaded", zap.String("type", typ), zap.Uint32("round", obs.rounds), zap.Int("unexercised", len(unexercised)),
			zap.Uint64("lost", max(lost, obs.lastLost)-obs.lastLost))

		obs.lastLost = max(lost, obs.lastLost)
	}

	if err := safe.WriterModify(ctx, r, runtime.NewSELinuxModule("audit-"+typ), func(res *runtime.SELinuxModule) error {
		res.TypedSpec().Content = fmt.Sprintf("; audit of %s, round %d, since %s\n%s", typ, obs.rounds, obs.since.Format(time.RFC3339), obs.module)

		return nil
	}); err != nil {
		return spec, false, err
	}

	exercised := slices.Collect(maps.Values(obs.exercised))

	var truncated bool

	spec.Exercised, spec.Truncated = capList(exercised)
	spec.Unexercised, truncated = capList(unexercised)
	spec.Truncated = spec.Truncated || truncated || (log != nil && log.Truncated)
	spec.ObservedSince = obs.since
	spec.Rounds = obs.rounds

	spec.NarrowedModule = narrowedModule(typ, obs, exercised, log != nil && log.Truncated)

	return spec, deferred, nil
}

// narrowedModule renders the module narrowed to the exercised accesses, on the plumbing of the domain; it opens with a
// warning when the observation cannot be complete: the domain has not started since the audit began, or the audit log
// dropped accesses of the domain.
func narrowedModule(typ string, obs *observation, exercised []runtime.SELinuxAccess, truncated bool) string {
	var header string

	if !slices.ContainsFunc(exercised, func(access runtime.SELinuxAccess) bool { return access.Permission == "entrypoint" }) {
		header += "; not started since " + obs.since.Format(time.RFC3339) + ": restart the workload, the accesses of its start are missing\n"
	}

	if truncated {
		header += "; the audit log dropped accesses of the domain: exercised accesses may be missing\n"
	}

	return header + "(type " + typ + ")\n" + obs.plumbing + renderRules("allow", typ, exercised, false)
}

// plumbing returns the rules a narrowed module needs beside the exercised accesses: the plumbing macro of the domain the
// system transitions to it from (pod_containerd_t for a pod, sys_containerd_t for an extension service), and its MCS
// exemption, which the kernel tells by allowing a file access on a target carrying a category the domain does not hold.
func (ctrl *SELinuxAuditController) plumbing(typ string, granted map[string]runtime.SELinuxAccess, classes map[string]selinux.Class) string {
	var out string

	for macro, from := range map[string]string{"pod_plumbing": "pod_containerd_t", "ext_plumbing": "sys_containerd_t"} {
		if av, err := ctrl.ComputeAV(selinux.Label(from), selinux.Label(typ), classes["process"].Index); err == nil && av.Allowed&classes["process"].Perms["transition"] != 0 {
			out = "(call " + macro + " (" + typ + "))\n"
		}
	}

	if out == "" {
		out = "; add the plumbing of the domain, such as (call pod_plumbing (" + typ + "))\n"
	}

	switch {
	case ctrl.mcsExempt(typ, granted, classes["file"], "write"):
		out += "(typeattributeset mcs_exempt_p " + typ + ")\n"
	case ctrl.mcsExempt(typ, granted, classes["file"], "read"):
		out += "(typeattributeset mcs_read_exempt_p " + typ + ")\n"
	}

	return out
}

// mcsExempt reports whether the domain keeps a granted file permission on a target carrying a category it does not hold.
func (ctrl *SELinuxAuditController) mcsExempt(typ string, granted map[string]runtime.SELinuxAccess, file selinux.Class, perm string) bool {
	for _, access := range granted {
		if access.Class != "file" || access.Permission != perm {
			continue
		}

		av, err := ctrl.ComputeAV(selinux.Label(typ), "system_u:object_r:"+access.Target+":s0:c1023", file.Index)

		return err == nil && av.Allowed&file.Perms[perm] != 0
	}

	return false
}

// enumerate asks the kernel every permission the domain holds on every type of the policy, in every class.
func (ctrl *SELinuxAuditController) enumerate(typ string, sources []string, classes map[string]selinux.Class) map[string]runtime.SELinuxAccess {
	granted := map[string]runtime.SELinuxAccess{}
	scon := selinux.Label(typ)

	for _, target := range selinux.Types(sources...) {
		// object_r is valid with every type, and type enforcement ignores the role
		tcon := "system_u:object_r:" + target + ":s0"

		for name, class := range classes {
			av, err := ctrl.ComputeAV(scon, tcon, class.Index)
			if err != nil {
				// a type of a module the policy did not load
				break
			}

			for perm, bit := range class.Perms {
				if av.Allowed&bit != 0 {
					access := runtime.SELinuxAccess{Target: target, Class: name, Permission: perm}
					granted[accessKey(access)] = access
				}
			}
		}
	}

	return granted
}

func accessKey(access runtime.SELinuxAccess) string {
	return access.Target + "|" + access.Class + "|" + access.Permission
}

// capList sorts the accesses and cuts the list at the limit.
func capList(accesses []runtime.SELinuxAccess) ([]runtime.SELinuxAccess, bool) {
	accesses = slices.Clone(accesses)
	slices.SortFunc(accesses, runtime.CompareSELinuxAccess)

	if len(accesses) > auditListLimit {
		return accesses[:auditListLimit], true
	}

	return accesses, false
}

// renderRules renders the accesses as rules of the kind for the type, one per target and class, sorted; with comments,
// each rule names the command and the path last observed.
func renderRules(kind, typ string, accesses []runtime.SELinuxAccess, comments bool) string {
	accesses = slices.Clone(accesses)
	slices.SortFunc(accesses, runtime.CompareSELinuxAccess)

	var out strings.Builder

	for i := 0; i < len(accesses); {
		j := i

		var perms []string

		for j < len(accesses) && accesses[j].Target == accesses[i].Target && accesses[j].Class == accesses[i].Class {
			perms = append(perms, accesses[j].Permission)
			j++
		}

		fmt.Fprintf(&out, "(%s %s %s (%s (%s)))", kind, typ, accesses[i].Target, accesses[i].Class, strings.Join(perms, " "))

		if last := accesses[j-1]; comments && (last.Comm != "" || last.Path != "") {
			fmt.Fprintf(&out, " ; comm=%q path=%q", last.Comm, last.Path)
		}

		out.WriteByte('\n')

		i = j
	}

	return out.String()
}
