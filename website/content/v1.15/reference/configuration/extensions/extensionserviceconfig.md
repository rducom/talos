---
description: ExtensionServiceConfig is a extensionserviceconfig document.
title: ExtensionServiceConfig
---

<!-- markdownlint-disable -->









{{< highlight yaml >}}
apiVersion: v1alpha1
kind: ExtensionServiceConfig
name: nut-client # Name of the extension service.
# The config files for the extension service.
configFiles:
    - content: MONITOR ${upsmonHost} 1 remote username password # The content of the extension service config file.
      mountPath: /usr/local/etc/nut/upsmon.conf # The mount path of the extension service config file.
# The environment for the extension service.
environment:
    - NUT_UPS=upsname
{{< /highlight >}}


| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`name` |string |Name of the extension service.  | |
|`configFiles` |<a href="#ExtensionServiceConfig.configFiles.">[]ConfigFile</a> |The config files for the extension service.  | |
|`environment` |[]string |The environment for the extension service.  | |
|`selinux` |<a href="#ExtensionServiceConfig.selinux">ServiceSELinux</a> |SELinux settings of the extension service, ignored for a service in host runner mode.<br>A change of the settings restarts the service.  | |




## configFiles[] {#ExtensionServiceConfig.configFiles.}

ConfigFile is a config file for extension services.




| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`content` |string |The content of the extension service config file.  | |
|`mountPath` |string |The mount path of the extension service config file.  | |






## selinux {#ExtensionServiceConfig.selinux}

ServiceSELinux is the SELinux settings of an extension service.




| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`type` |string |SELinux type the service runs as, in place of the type Talos derives from the service spec.<br>The type must exist in the loaded policy: `ext_t` and `ext_privileged_t` come with the base policy,<br>any other is declared by a SELinuxPolicyConfig document, with the `ext_domain` or `ext_privileged_domain` macro.<br>A service which failed on a type absent from the policy restarts with the next version of this document. <details><summary>Show example(s)</summary>{{< highlight yaml >}}
type: ext_privileged_t
{{< /highlight >}}</details> | |








