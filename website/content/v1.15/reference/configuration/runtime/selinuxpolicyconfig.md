---
description: SELinuxPolicyConfig is a SELinux policy module document.
title: SELinuxPolicyConfig
---

<!-- markdownlint-disable -->









{{< highlight yaml >}}
apiVersion: v1alpha1
kind: SELinuxPolicyConfig
name: hostmon # Name of the policy module.
content: | # Policy module in CIL, compiled with the Talos policy and loaded without a reboot.
    (type pod_hostmon_t)
    (call pod_hostmon_domain (pod_hostmon_t))
{{< /highlight >}}


| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`name` |string |Name of the policy module.  | |
|`content` |string |Policy module in CIL, compiled with the Talos policy and loaded without a reboot.<br>A module declares a type and calls one of the macros of the base policy:<br>`pod_domain` gives the rights of a regular pod, `pod_privileged_domain` those of `pod_privileged_t`<br>and `pod_hostmon_domain` those of a process monitor, which reads `/proc` and the files of every pod<br>across MCS categories but never writes them.<br>The attributes `any_p` (every process type), `any_f` (every file type),<br>`privileged_readable_f` (files a privileged pod may read), `mcs_exempt_p` and `mcs_read_exempt_p`<br>(domains ignoring MCS categories, in both directions or for reading only) are available to extra rules.<br>Whatever a module grants, a workload domain never reads the STATE partition, connects to machined<br>or ptraces a host service: `secilc` rejects such a module. A rejected module is left out and the other<br>modules are loaded; `talosctl get selinuxpolicystatus` names it with the error of the compiler.<br>Anything else is open to a module, which is as trusted as the machine config carrying it.<br>A workload selects the type with `securityContext.seLinuxOptions.type` in its pod spec.<br>Load the module before rolling the workload out, a type unknown to the policy fails the container at runc;<br>delete the workload before removing its module, a type removed from the policy leaves its running<br>containers without any access.<br>Privileged containers cannot select a type: containerd clears their label and they land in `pod_privileged_t`.<br>`spc_t` is already an alias of `pod_privileged_t`, any other type must be declared by a module.<br>A type named `ext_<x>_t` collides with the module Talos derives for an extension service `x`.  | |
|`audit` |bool |Observe the permissions the types of the module exercise: the SELinuxDomainStatus of each type lists the<br>accesses the policy grants it, exercised or not since the audit began, and a policy module narrowed to the<br>exercised ones. Restart the workload once the flag is set: the accesses of its start are observed only then,<br>and the narrowed module says so while they are missing.  | |






