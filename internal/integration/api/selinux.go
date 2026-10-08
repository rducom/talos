// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build integration_api

package api

import (
	"bytes"
	"context"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cosi-project/runtime/pkg/resource/rtestutils"
	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/siderolabs/go-pointer"
	"github.com/siderolabs/go-procfs/procfs"
	"github.com/siderolabs/go-retry/retry"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/siderolabs/talos/cmd/talosctl/pkg/talos/helpers"
	"github.com/siderolabs/talos/internal/integration/base"
	"github.com/siderolabs/talos/internal/pkg/selinux/extgen"
	"github.com/siderolabs/talos/pkg/machinery/api/common"
	machineapi "github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/config/machine"
	runtimeconfig "github.com/siderolabs/talos/pkg/machinery/config/types/runtime"
	"github.com/siderolabs/talos/pkg/machinery/config/types/runtime/extensions"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/resources/block"
	"github.com/siderolabs/talos/pkg/machinery/resources/k8s"
	runtimeres "github.com/siderolabs/talos/pkg/machinery/resources/runtime"
	"github.com/siderolabs/talos/pkg/machinery/resources/v1alpha1"
)

// SELinuxSuite ...
type SELinuxSuite struct {
	base.K8sSuite

	ctx       context.Context //nolint:containedctx
	ctxCancel context.CancelFunc
}

// SuiteName ...
func (suite *SELinuxSuite) SuiteName() string {
	return "api.SELinuxSuite"
}

// SetupTest ...
func (suite *SELinuxSuite) SetupTest() {
	suite.ctx, suite.ctxCancel = context.WithTimeout(context.Background(), 10*time.Minute)

	if suite.Cluster == nil || suite.Cluster.Provisioner() != base.ProvisionerQEMU {
		suite.T().Skip("skipping SELinux test since provisioner is not qemu")
	}
}

// TearDownTest ...
func (suite *SELinuxSuite) TearDownTest() {
	if suite.ctxCancel != nil {
		suite.ctxCancel()
	}
}

func (suite *SELinuxSuite) getLabel(nodeCtx context.Context, pid int32) string {
	r, err := suite.Client.Read(nodeCtx, filepath.Join("/proc", strconv.Itoa(int(pid)), "attr/current"))
	suite.Require().NoError(err)

	value, err := io.ReadAll(r)
	suite.Require().NoError(err)

	suite.Require().NoError(r.Close())

	return string(bytes.Trim(value, " \n\x00"))
}

// TestFileMountLabels reads labels of runtime-created files and mounts from xattrs
// to ensure SELinux labels for files are set when they are created and FS's are mounted with correct labels.
// FIXME: cancel the test in case system was upgraded.
func (suite *SELinuxSuite) TestFileMountLabels() {
	workers := suite.DiscoverNodeInternalIPsByType(suite.ctx, machine.TypeWorker)
	controlplanes := suite.DiscoverNodeInternalIPsByType(suite.ctx, machine.TypeControlPlane)

	expectedLabelsWorker := map[string]string{
		// Mounts
		constants.SystemPath:          constants.SystemSelinuxLabel,
		constants.EphemeralMountPoint: constants.EphemeralSelinuxLabel,
		constants.StateMountPoint:     constants.SystemSelinuxLabel,
		constants.SystemVarPath:       constants.SystemVarSelinuxLabel,
		constants.RunPath:             constants.RunSelinuxLabel,
		"/run/containerd":             "system_u:object_r:pod_containerd_run_t:s0",
		"/run/lock":                   "system_u:object_r:var_lock_t:s0",
		"/run/lock/lvm":               "system_u:object_r:var_lock_t:s0",
		constants.SystemRunPath:       "system_u:object_r:system_run_t:s0",
		"/var/run":                    constants.RunSelinuxLabel,
		// Runtime files
		constants.APIRuntimeSocketPath:  constants.APIRuntimeSocketLabel,
		constants.DBusClientSocketPath:  constants.DBusClientSocketLabel,
		constants.UdevRulesPath:         constants.UdevRulesLabel,
		constants.DBusServiceSocketPath: constants.DBusServiceSocketLabel,
		constants.MachineSocketPath:     constants.MachineSocketLabel,
		// Overlays
		"/etc/cni":                        constants.CNISELinuxLabel,
		constants.KubernetesConfigBaseDir: constants.KubernetesConfigSELinuxLabel,
		"/opt":                            constants.OptSELinuxLabel,
		"/opt/cni":                        "system_u:object_r:cni_plugin_t:s0",
		"/opt/containerd":                 "system_u:object_r:containerd_plugin_t:s0",
		// Directories
		"/var/lib/containerd":           "system_u:object_r:containerd_state_t:s0",
		"/var/lib/cni":                  "system_u:object_r:cni_state_t:s0",
		"/var/lib/kubelet":              "system_u:object_r:kubelet_state_t:s0",
		"/var/lib/kubelet/seccomp":      "system_u:object_r:seccomp_profile_t:s0",
		constants.LogMountPoint:         "system_u:object_r:var_log_t:s0",
		"/var/log/audit":                "system_u:object_r:audit_log_t:s0",
		constants.KubernetesAuditLogDir: "system_u:object_r:kube_log_t:s0",
		"/var/log/containers":           "system_u:object_r:containers_log_t:s0",
		"/var/log/pods":                 "system_u:object_r:pods_log_t:s0",
		// Mounts and runtime-generated files
		"/etc":                  constants.EtcSelinuxLabel,
		constants.SystemEtcPath: constants.EtcSelinuxLabel,
		// Build-time files
		"/usr/share/containers/selinux/contexts": "system_u:object_r:usr_t:s0",
	}

	if suite.extensionsInstalled(client.WithNode(suite.ctx, suite.RandomDiscoveredNodeInternalIP())) {
		// the imager labels the extension layers with the file_contexts of the rootfs; the service rootfs directories
		// under /usr/local/lib/containers carry the label of the overlay machined mounts on them instead
		expectedLabelsWorker[constants.ExtensionServiceConfigPath] = "system_u:object_r:usr_t:s0"
	}

	// Only running on controlplane
	expectedLabelsControlPlane := map[string]string{
		constants.EtcdPKIPath:                           constants.EtcdPKISELinuxLabel,
		constants.EtcdDataPath:                          constants.EtcdDataSELinuxLabel,
		constants.KubernetesAPIServerConfigDir:          constants.KubernetesAPIServerConfigDirSELinuxLabel,
		constants.KubernetesAPIServerSecretsDir:         constants.KubernetesAPIServerSecretsDirSELinuxLabel,
		constants.KubernetesControllerManagerSecretsDir: constants.KubernetesControllerManagerSecretsDirSELinuxLabel,
		constants.KubernetesSchedulerConfigDir:          constants.KubernetesSchedulerConfigDirSELinuxLabel,
		constants.KubernetesSchedulerSecretsDir:         constants.KubernetesSchedulerSecretsDirSELinuxLabel,
		constants.TrustdRuntimeSocketPath:               constants.TrustdRuntimeSocketLabel,
	}

	for _, node := range append(slices.Clone(workers), controlplanes...) {
		nodeCtx := client.WithNode(suite.ctx, node)

		if !suite.criLabelsContainers(nodeCtx) {
			continue
		}

		for _, dir := range kubeletPluginDirs {
			expectedLabelsWorker[dir] = "system_u:object_r:pod_file_t:s0"
		}

		// the audit log of the kube-apiserver carries the fixed level of the pod, the same at every boot
		expectedLabelsControlPlane[filepath.Join(constants.KubernetesAuditLogDir, "kube-apiserver.log")] = "system_u:object_r:kube_log_t:" + constants.KubernetesAPIServerSELinuxLevel

		// the kubelet relabels its directories at every start, from pod_file_t itself once they carry it
		_, err := suite.Client.ServiceRestart(nodeCtx, "kubelet")
		suite.Require().NoError(err)

		rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, "kubelet", func(svc *v1alpha1.Service, asrt *assert.Assertions) {
			asrt.True(svc.TypedSpec().Healthy && svc.TypedSpec().Running)
		})
	}

	maps.Copy(expectedLabelsControlPlane, expectedLabelsWorker)

	// Devices labeled by subsystems, labeled by udev
	expectedLabelsDevices := map[string]string{
		"/dev/rtc0":      "system_u:object_r:rtc_device_t:s0",
		"/dev/tpm0":      "system_u:object_r:tpm_device_t:s0",
		"/dev/tpmrm0":    "system_u:object_r:tpm_device_t:s0",
		"/dev/watchdog":  "system_u:object_r:wdt_device_t:s0",
		"/dev/watchdog0": "system_u:object_r:wdt_device_t:s0",
		"/dev/null":      "system_u:object_r:null_device_t:s0",
		"/dev/zero":      "system_u:object_r:null_device_t:s0",
	}

	suite.checkFileLabels(workers, expectedLabelsWorker, false)
	suite.checkFileLabels(controlplanes, expectedLabelsControlPlane, false)
	suite.checkFileLabels(workers, expectedLabelsDevices, true)
	suite.checkFileLabels(controlplanes, expectedLabelsDevices, true)
}

//nolint:gocyclo
func (suite *SELinuxSuite) checkFileLabels(nodes []string, expectedLabels map[string]string, allowMissing bool) {
	paths := make([]string, 0, len(expectedLabels))
	for k := range expectedLabels {
		paths = append(paths, k)
	}

	for _, node := range nodes {
		nodeCtx := client.WithNode(suite.ctx, node)
		cmdline := suite.ReadCmdline(nodeCtx)

		seLinuxEnabled := pointer.SafeDeref(procfs.NewCmdline(cmdline).Get(constants.KernelParamSELinux).First()) != ""
		if !seLinuxEnabled {
			suite.T().Skip("skipping SELinux test since SELinux is disabled")
		}

		for path, label := range expectedLabels {
			req := &machineapi.ListRequest{
				Root:         path,
				ReportXattrs: true,
			}

			stream, err := suite.Client.LS(nodeCtx, req)

			suite.Require().NoError(err)

			err = helpers.ReadGRPCStream(stream, func(info *machineapi.FileInfo, node string, multipleNodes bool) error {
				// E.g. /var/lib should inherit /var label, while /var/run is a new mountpoint
				if slices.Contains(paths, info.Name) && info.Name != path {
					return nil
				}

				if slices.Contains(
					append([]string{
						constants.RunPath,
						constants.SystemRunPath,
						"/run/containerd",
						"/var/run",
						"/var/log/containers",
					}, kubeletPluginDirs...),
					path,
				) && info.Name != path {
					return nil
				}

				suite.Require().NotNil(info.Xattrs, "expected %s to have xattrs (checking %s)", info.Name, path)

				found := false

				for _, l := range info.Xattrs {
					if l.Name == "security.selinux" {
						got := string(bytes.Trim(l.Data, "\x00\n"))
						suite.Require().Contains(got, label, "expected %s to have label %s, got %s (checking %s)", info.Name, label, got, path)

						found = true

						break
					}
				}

				suite.Require().True(found, "expected to find security.selinux xattr for %s (checking %s)", info.Name, path)

				return nil
			})

			if allowMissing {
				if err != nil {
					suite.Require().Contains(err.Error(), "lstat")
					suite.Require().Contains(err.Error(), "no such file or directory")
				}
			} else {
				suite.Require().NoError(err)
			}
		}
	}
}

func (suite *SELinuxSuite) extensionsInstalled(nodeCtx context.Context) bool {
	extensions, err := safe.StateListAll[*runtimeres.ExtensionStatus](nodeCtx, suite.Client.COSI)
	suite.Require().NoError(err)

	return extensions.Len() > 0
}

// TestProcessLabels reads labels of system processes from procfs
// to ensure SELinux labels for processes are correctly set
//
//nolint:gocyclo
func (suite *SELinuxSuite) TestProcessLabels() {
	nodes := suite.DiscoverNodeInternalIPs(suite.ctx)

	for _, node := range nodes {
		nodeCtx := client.WithNode(suite.ctx, node)
		cmdline := suite.ReadCmdline(nodeCtx)

		seLinuxEnabled := pointer.SafeDeref(procfs.NewCmdline(cmdline).Get(constants.KernelParamSELinux).First()) != ""
		if !seLinuxEnabled {
			suite.T().Skip("skipping SELinux test since SELinux is disabled")
		}

		r, err := suite.Client.Processes(nodeCtx)
		suite.Require().NoError(err)

		for _, msg := range r.Messages {
			procs := msg.Processes

			for _, p := range procs {
				switch p.Command {
				case "systemd-udevd":
					suite.Require().Contains(
						suite.getLabel(nodeCtx, p.Pid),
						constants.SelinuxLabelUdevd,
					)
				case "dashboard":
					suite.Require().Contains(
						suite.getLabel(nodeCtx, p.Pid),
						constants.SelinuxLabelDashboard,
					)
				case "containerd":
					if strings.Contains(p.Args, "/system/run/containerd") {
						suite.Require().Contains(
							suite.getLabel(nodeCtx, p.Pid),
							constants.SelinuxLabelSystemRuntime,
						)
					} else {
						suite.Require().Contains(
							suite.getLabel(nodeCtx, p.Pid),
							constants.SelinuxLabelPodRuntime,
						)
					}
				case "init":
					suite.Require().Contains(
						suite.getLabel(nodeCtx, p.Pid),
						constants.SelinuxLabelMachined,
					)
				case "kubelet":
					suite.Require().Contains(
						suite.getLabel(nodeCtx, p.Pid),
						constants.SelinuxLabelKubelet,
					)
				case "apid":
					suite.Require().Contains(
						suite.getLabel(nodeCtx, p.Pid),
						constants.SelinuxLabelApid,
					)
				case "trustd":
					suite.Require().Contains(
						suite.getLabel(nodeCtx, p.Pid),
						constants.SelinuxLabelTrustd,
					)
				}
			}
		}
	}
}

// TestSecurityState validates SecurityState in accordance to -talos.enforcing.
func (suite *SELinuxSuite) TestSecurityState() {
	for _, node := range suite.DiscoverNodeInternalIPs(suite.ctx) {
		nodeCtx := client.WithNode(suite.ctx, node)
		cmdline := suite.ReadCmdline(nodeCtx)

		seLinuxEnabled := pointer.SafeDeref(procfs.NewCmdline(cmdline).Get(constants.KernelParamSELinux).First()) != ""
		if !seLinuxEnabled {
			continue
		}

		rtestutils.AssertResource(
			nodeCtx,
			suite.T(),
			suite.Client.COSI,
			runtimeres.SecurityStateID,
			func(state *runtimeres.SecurityState, asrt *assert.Assertions) {
				if suite.SelinuxEnforcing {
					asrt.Equal(runtimeres.SELinuxStateEnforcing, state.TypedSpec().SELinuxState)
				} else {
					asrt.Equal(runtimeres.SELinuxStatePermissive, state.TypedSpec().SELinuxState)
				}
			},
		)
	}
}

type podRunner interface {
	Name() string
	Create(ctx context.Context, waitTimeout time.Duration) error
	Delete(ctx context.Context) error
	Exec(ctx context.Context, command string) (string, string, error)
}

func (suite *SELinuxSuite) readStream(stream client.MachineStream) string {
	reader, err := client.ReadStream(stream)
	suite.Require().NoError(err)

	body, err := io.ReadAll(reader)
	suite.Require().NoError(err)
	suite.Require().NoError(reader.Close())

	return string(body)
}

func (suite *SELinuxSuite) denials(node, subject string) int {
	stream, err := suite.Client.Logs(client.WithNode(suite.ctx, node), constants.SystemContainerdNamespace, common.ContainerDriver_CONTAINERD, "auditd", false, -1)
	suite.Require().NoError(err)

	return strings.Count(suite.readStream(stream), " scontext=system_u:system_r:"+subject+":")
}

var kubeletPluginDirs = []string{"/var/lib/kubelet/plugins", "/var/lib/kubelet/plugins_registry", "/var/lib/kubelet/device-plugins"}

// podDomains are the workload domains of the base policy and of the modules in hack/test/patches/selinux-workloads.yaml.
var podDomains = []string{"pod_t", "pod_privileged_t", "pod_hostmon_t", "pod_cni_t"}

// criLabelsContainers reports whether the node's CRI labels containers, which the kubelet mounts reflect.
func (suite *SELinuxSuite) criLabelsContainers(nodeCtx context.Context) bool {
	spec, err := safe.StateGetByID[*k8s.KubeletSpec](nodeCtx, suite.Client.COSI, k8s.KubeletID)
	suite.Require().NoError(err)

	return slices.ContainsFunc(spec.TypedSpec().ExtraMounts, func(mount specs.Mount) bool { return mount.Destination == "/sys/fs/selinux" })
}

// labelingNode returns the address and the name of a node whose CRI labels containers, and skips the test without one,
// or in permissive mode when the test checks the denials.
func (suite *SELinuxSuite) labelingNode(enforcing bool) (string, string) {
	if enforcing && !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	ip := suite.RandomDiscoveredNodeInternalIP()

	if !suite.criLabelsContainers(client.WithNode(suite.ctx, ip)) {
		suite.T().Skip("skipping SELinux pod domain tests since the CRI does not label containers")
	}

	node, err := suite.GetK8sNodeByInternalIP(suite.ctx, ip)
	suite.Require().NoError(err)

	return ip, node.Name
}

func (suite *SELinuxSuite) kubeletMetric(nodeName, metric string) float64 {
	body, err := suite.Clientset.CoreV1().RESTClient().Get().Resource("nodes").Name(nodeName).SubResource("proxy").Suffix("metrics").DoRaw(suite.ctx)
	suite.Require().NoError(err)

	for line := range strings.SplitSeq(string(body), "\n") {
		if value, ok := strings.CutPrefix(line, metric+" "); ok {
			parsed, err := strconv.ParseFloat(value, 64)
			suite.Require().NoError(err)

			return parsed
		}
	}

	return 0
}

// exec creates the pod, runs the command in it and deletes it.
func (suite *SELinuxSuite) exec(pod podRunner, command string) (string, string, error) {
	suite.Require().NoError(pod.Create(suite.ctx, 5*time.Minute))

	defer pod.Delete(suite.ctx) //nolint:errcheck

	return pod.Exec(suite.ctx, command)
}

// TestPodDomains verifies the domains pods land in when the CRI labels containers, and that a type the policy does not
// let pods enter fails the container.
func (suite *SELinuxSuite) TestPodDomains() {
	_, node := suite.labelingNode(false)

	for _, test := range []struct {
		name       string
		privileged bool
		options    *corev1.SELinuxOptions
		label      string // empty when the container must fail
		enforcing  bool   // a refusal permissive mode does not enforce
	}{
		{name: "selinux-pod", label: `^system_u:system_r:pod_t:s0:c\d+,c\d+$`},
		{name: "selinux-privileged", privileged: true, label: `^system_u:system_r:pod_privileged_t:s0$`},
		{name: "selinux-hostmon", options: &corev1.SELinuxOptions{Type: "pod_hostmon_t"}, label: `^system_u:system_r:pod_hostmon_t:s0:c\d+,c\d+$`},
		{name: "selinux-spc", options: &corev1.SELinuxOptions{Type: "spc_t", Level: "s0"}, label: `^system_u:system_r:pod_privileged_t:s0$`},
		{name: "selinux-unknown", options: &corev1.SELinuxOptions{Type: "unknown_t"}},
		{name: "selinux-kubelet", options: &corev1.SELinuxOptions{Type: "kubelet_t"}, enforcing: true},
	} {
		if test.enforcing && !suite.SelinuxEnforcing {
			continue
		}

		newPod := suite.NewPod
		if test.privileged {
			newPod = suite.NewPrivilegedPod
		}

		podDef, err := newPod(test.name)
		suite.Require().NoError(err)

		pod := podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node).WithSELinuxOptions(test.options)

		if test.label == "" {
			suite.Assert().Error(pod.Create(suite.ctx, 20*time.Second), test.name)
			suite.Require().NoError(pod.Delete(suite.ctx))

			continue
		}

		stdout, stderr, err := suite.exec(pod, "cat /proc/self/attr/current")
		suite.Require().NoError(err, test.name)
		suite.Assert().Empty(stderr, test.name)
		suite.Assert().Regexp(test.label, strings.TrimRight(stdout, "\n\x00"), test.name)
	}
}

// TestPodMCSIsolation checks the MCS categories on a hostPath: a pod reads the files of another pod only at the same
// fixed level, which outlives the pods, and a process monitor reads them all without writing any.
func (suite *SELinuxSuite) TestPodMCSIsolation() {
	_, node := suite.labelingNode(true)

	file := "/data/mcs-" + strconv.FormatInt(time.Now().UnixNano(), 36)

	// one pod after the other: the files outlive the pod that wrote them
	for _, step := range []struct {
		name    string
		options *corev1.SELinuxOptions
		command string
		want    string // the output, or a permission denied when empty
	}{
		{"selinux-mcs-writer", nil, "echo secret > " + file + " && echo written", "written\n"},
		{"selinux-mcs-reader", nil, "cat " + file, ""},
		{"selinux-mcs-hostmon", &corev1.SELinuxOptions{Type: "pod_hostmon_t"}, "cat " + file, "secret\n"},
		{"selinux-mcs-tamper", &corev1.SELinuxOptions{Type: "pod_hostmon_t"}, "echo tampered >> " + file, ""},
		{"selinux-level-first", &corev1.SELinuxOptions{Level: "s0:c600,c601"}, "echo secret > " + file + "-fixed && echo written", "written\n"},
		{"selinux-level-second", &corev1.SELinuxOptions{Level: "s0:c600,c601"}, "cat " + file + "-fixed", "secret\n"},
		{"selinux-level-other", &corev1.SELinuxOptions{Level: "s0:c602,c603"}, "cat " + file + "-fixed", ""},
	} {
		podDef, err := suite.NewPod(step.name)
		suite.Require().NoError(err)

		pod := podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node).WithHostVolumeMount("/var/selinux-test", "/data").
			WithSELinuxOptions(step.options)

		stdout, stderr, err := suite.exec(pod, step.command)

		if step.want == "" {
			suite.Assert().Error(err, step.name)
			suite.Assert().Contains(stderr, "Permission denied", step.name)
		} else {
			suite.Assert().NoError(err, step.name)
			suite.Assert().Equal(step.want, stdout, step.name)
		}
	}
}

// TestPrivilegedHostAccess runs a host binary from a privileged pod the way TopoLVM does and serves a socket to a sidecar, without denials.
func (suite *SELinuxSuite) TestPrivilegedHostAccess() {
	ip, node := suite.labelingNode(true)

	before := suite.denials(ip, "pod_privileged_t")

	podDef, err := suite.NewPrivilegedPod("selinux-nsenter")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNodeName(node).WithHostPID()

	suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	stdout, stderr, err := podDef.Exec(suite.ctx, "nsenter -t 1 -m -- /usr/bin/lvm version")
	suite.Require().NoError(err)
	suite.Assert().Empty(stderr, "stderr: %s", stderr)
	suite.Assert().Contains(stdout, "LVM version")

	_, _, err = podDef.Exec(suite.ctx, "apk add --update socat && (socat UNIX-LISTEN:/host/var/selinux-test/"+podDef.Name()+",fork EXEC:cat >/dev/null 2>&1 &) && sleep 1")
	suite.Require().NoError(err)

	sidecar, err := suite.NewPod("selinux-socket-client")
	suite.Require().NoError(err)

	sidecar = sidecar.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node).WithHostVolumeMount("/var/selinux-test", "/data")

	stdout, _, err = suite.exec(sidecar, "apk add --update socat >/dev/null && echo hello | socat - UNIX-CONNECT:/data/"+podDef.Name())
	suite.Require().NoError(err)
	suite.Assert().Equal("hello\n", stdout)
	suite.Assert().Equal(before, suite.denials(ip, "pod_privileged_t"))
}

// TestPodProcAccess reads the /proc of every host process from a pod sharing the host PID namespace: pod_t is denied and
// the denial audited, a process monitor and a module domain built on pod_privileged_domain are not.
func (suite *SELinuxSuite) TestPodProcAccess() {
	ip, node := suite.labelingNode(true)

	for _, test := range []struct {
		domain       string
		capabilities []corev1.Capability
		command      string
		want         string // a regexp the output matches, empty when the command must be denied and audited
	}{
		// the shell glob drops the entries it cannot search, hence the explicit loop
		{domain: "pod_t", command: "rc=0; for p in $(ls /proc | grep -E '^[0-9]+$'); do cat /proc/$p/comm >/dev/null || rc=1; done; exit $rc"},
		// readlink of /proc/1/exe needs CAP_SYS_PTRACE on a non-dumpable process, a DAC check with no AVC record
		{domain: "pod_hostmon_t", command: "for p in /proc/[0-9]*; do cat $p/stat $p/comm; ls $p/task; readlink $p/exe; done >/dev/null 2>&1; cat /proc/1/comm", want: `\S`},
		// lvm also probes /dev/mapper/control, which the device cgroup of a non-privileged container refuses
		{
			domain: "pod_cni_t", capabilities: []corev1.Capability{"SYS_ADMIN", "SYS_PTRACE", "SYS_CHROOT"},
			command: "cat /proc/self/attr/current; nsenter -t 1 -m -- /usr/bin/lvm version", want: `(?s)^system_u:system_r:pod_cni_t:s0:c\d+,c\d+.*LVM version`,
		},
	} {
		podDef, err := suite.NewPod("selinux-proc-" + strings.ReplaceAll(test.domain, "_", "-"))
		suite.Require().NoError(err)

		pod := podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node).WithHostPID().WithCapabilities(test.capabilities...).
			WithSELinuxOptions(&corev1.SELinuxOptions{Type: test.domain})

		before := suite.denials(ip, test.domain)
		stdout, stderr, err := suite.exec(pod, test.command)
		denied := suite.denials(ip, test.domain) - before

		if test.want == "" {
			suite.Assert().Error(err, test.domain)
			suite.Assert().Contains(stderr, "Permission denied", test.domain)
			suite.Assert().Positive(denied, test.domain)
		} else {
			suite.Assert().NoError(err, test.domain)
			suite.Assert().Regexp(test.want, stdout, test.domain)
			suite.Assert().Zero(denied, test.domain)
		}
	}
}

// TestKubeletVolumeLabels checks the kubelet sees SELinux when the CRI labels containers and computes the mount label of a ReadWriteOncePod volume.
func (suite *SELinuxSuite) TestKubeletVolumeLabels() {
	_, nodeName := suite.labelingNode(false)

	name := "selinux-test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	driver := name + ".csi.talos.dev"
	metric := `volume_manager_selinux_volumes_admitted_total{access_mode="RWOP",volume_plugin="kubernetes.io/csi/` + driver + `"}`

	_, err := suite.Clientset.StorageV1().CSIDrivers().Create(suite.ctx, &storagev1.CSIDriver{
		Name: driver,
		Spec: storagev1.CSIDriverSpec{AttachRequired: new(false), SELinuxMount: new(true)},
	}, metav1.CreateOptions{})
	suite.Require().NoError(err)

	defer suite.Clientset.StorageV1().CSIDrivers().Delete(suite.ctx, driver, metav1.DeleteOptions{}) //nolint:errcheck

	_, err = suite.Clientset.CoreV1().PersistentVolumes().Create(suite.ctx, &corev1.PersistentVolume{
		Name: name,
		Spec: corev1.PersistentVolumeSpec{
			Capacity:               corev1.ResourceList{corev1.ResourceStorage: apiresource.MustParse("1Mi")},
			AccessModes:            []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod},
			StorageClassName:       name,
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: driver, VolumeHandle: name}},
		},
	}, metav1.CreateOptions{})
	suite.Require().NoError(err)

	defer suite.Clientset.CoreV1().PersistentVolumes().Delete(suite.ctx, name, metav1.DeleteOptions{}) //nolint:errcheck

	_, err = suite.Clientset.CoreV1().PersistentVolumeClaims("kube-system").Create(suite.ctx, &corev1.PersistentVolumeClaim{
		Name: name,
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod},
			StorageClassName: new(name),
			VolumeName:       name,
			Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: apiresource.MustParse("1Mi")}},
		},
	}, metav1.CreateOptions{})
	suite.Require().NoError(err)

	defer suite.Clientset.CoreV1().PersistentVolumeClaims("kube-system").Delete(suite.ctx, name, metav1.DeleteOptions{}) //nolint:errcheck

	before := suite.kubeletMetric(nodeName, metric)

	podDef, err := suite.NewPod("selinux-pvc")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(nodeName).
		WithSELinuxOptions(&corev1.SELinuxOptions{Level: "s0:c600,c601"}).WithPersistentVolumeClaim(name, "/data")

	// no driver serves the volume, the pod never runs
	suite.Assert().Error(podDef.Create(suite.ctx, 20*time.Second))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	suite.Require().NoError(retry.Constant(time.Minute, retry.WithUnits(time.Second)).Retry(func() error {
		if suite.kubeletMetric(nodeName, metric) <= before {
			return retry.ExpectedErrorf("the kubelet did not admit the volume with a SELinux label")
		}

		return nil
	}))
}

// TestNoHostDenials checks that the policy defines every kernel permission and that AVC denials only ever hit pods, never the host domains.
func (suite *SELinuxSuite) TestNoHostDenials() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	for _, node := range suite.DiscoverNodeInternalIPs(suite.ctx) {
		nodeCtx := client.WithNode(suite.ctx, node)

		dmesg, err := suite.Client.Dmesg(nodeCtx, false, false)
		suite.Require().NoError(err)

		audit, err := suite.Client.Logs(nodeCtx, constants.SystemContainerdNamespace, common.ContainerDriver_CONTAINERD, "auditd", false, -1)
		suite.Require().NoError(err)

		for _, stream := range []client.MachineStream{dmesg, audit} {
			for line := range strings.SplitSeq(suite.readStream(stream), "\n") {
				suite.Assert().NotContains(line, "not defined in policy")

				if !strings.Contains(line, "avc:  denied") {
					continue
				}

				_, scontext, _ := strings.Cut(line, " scontext=")
				scontext, _, _ = strings.Cut(scontext, " ")

				fields := strings.SplitN(scontext, ":", 4)
				suite.Require().Len(fields, 4, "unexpected AVC record: %s", line)
				suite.Assert().True(slices.Contains(podDomains, fields[2]) || strings.Contains(fields[3], ":c"), "host domain denied: %s", line)
			}
		}
	}
}

// extensionServicePID returns the PID of a running extension service, once it differs from the previous one.
func (suite *SELinuxSuite) extensionServicePID(nodeCtx context.Context, id string, previous int32) int32 {
	var pid int32

	suite.Require().NoError(retry.Constant(2*time.Minute, retry.WithUnits(time.Second)).Retry(func() error {
		res, err := safe.StateGetByID[*runtimeres.ServicePID](nodeCtx, suite.Client.COSI, id)
		if err != nil {
			return retry.ExpectedError(err)
		}

		if pid = res.TypedSpec().PID; pid == previous {
			return retry.ExpectedErrorf("%s: not restarted yet", id)
		}

		return nil
	}))

	return pid
}

// waitForExtensionServiceEvent waits for the last event of an extension service to carry the message.
func (suite *SELinuxSuite) waitForExtensionServiceEvent(nodeCtx context.Context, id, message string) {
	suite.Require().NoError(retry.Constant(2*time.Minute, retry.WithUnits(time.Second)).Retry(func() error {
		info, err := suite.Client.ServiceInfo(nodeCtx, id)
		if err != nil {
			return retry.ExpectedError(err)
		}

		events := info[0].Service.Events.Events
		if len(events) == 0 || !strings.Contains(events[len(events)-1].Msg, message) {
			return retry.ExpectedErrorf("%s: last event is not %q", id, message)
		}

		return nil
	}))
}

// fileLabel returns the SELinux label of a path on the node.
func (suite *SELinuxSuite) fileLabel(nodeCtx context.Context, path string) string {
	stream, err := suite.Client.LS(nodeCtx, &machineapi.ListRequest{Root: path, ReportXattrs: true})
	suite.Require().NoError(err)

	var label string

	suite.Require().NoError(helpers.ReadGRPCStream(stream, func(info *machineapi.FileInfo, _ string, _ bool) error {
		if info.Name != path {
			return nil
		}

		for _, xattr := range info.Xattrs {
			if xattr.Name == "security.selinux" {
				label = string(bytes.Trim(xattr.Data, "\x00\n"))
			}
		}

		return nil
	}))

	return label
}

// containerExtensionService returns the name and the PID of a running extension service in container mode, and skips the
// test without one.
func (suite *SELinuxSuite) containerExtensionService(nodeCtx context.Context) (string, int32) {
	if pointer.SafeDeref(procfs.NewCmdline(suite.ReadCmdline(nodeCtx)).Get(constants.KernelParamSELinux).First()) == "" {
		suite.T().Skip("skipping SELinux test since SELinux is disabled")
	}

	if !suite.extensionsInstalled(nodeCtx) {
		suite.T().Skip("skipping SELinux test since no extension is installed")
	}

	var (
		name string
		pid  int32
	)

	// a previous test may have left the services restarting
	err := retry.Constant(2*time.Minute, retry.WithUnits(2*time.Second)).Retry(func() error {
		services, err := safe.StateListAll[*v1alpha1.Service](nodeCtx, suite.Client.COSI)
		if err != nil {
			return retry.ExpectedError(err)
		}

		for svc := range services.All() {
			if !strings.HasPrefix(svc.Metadata().ID(), "ext-") || !svc.TypedSpec().Running {
				continue
			}

			res, err := safe.StateGetByID[*runtimeres.ServicePID](nodeCtx, suite.Client.COSI, svc.Metadata().ID())
			if err != nil {
				continue
			}

			// services in host mode keep their domain
			if pid = res.TypedSpec().PID; suite.getLabel(nodeCtx, pid) != constants.SelinuxLabelUnconfinedService {
				name = strings.TrimPrefix(svc.Metadata().ID(), "ext-")

				return nil
			}
		}

		return retry.ExpectedErrorf("no extension service running in container mode")
	})
	if err != nil {
		suite.T().Skip("skipping SELinux test since no extension service runs in container mode")
	}

	return name, pid
}

// TestExtensionServiceDomains checks the domain of the extension services in container mode: the type their module derives
// from the spec, with their state directories labeled for them, unless the machine config selects another type; an unknown
// type fails the service with a readable error; a module contradicting a neverallow of the config is rejected without
// touching the loaded policy.
//
//nolint:gocyclo
func (suite *SELinuxSuite) TestExtensionServiceDomains() {
	node := suite.RandomDiscoveredNodeInternalIP()
	nodeCtx := client.WithNode(suite.ctx, node)

	name, pid := suite.containerExtensionService(nodeCtx)
	id, typ := "ext-"+name, extgen.TypeName(name)

	suite.Assert().Equal(selinuxLabel(typ), suite.getLabel(nodeCtx, pid))

	// the rootfs the service runs from is one type, the files of the image and the mount points runc creates alike
	rootfs := filepath.Join(constants.ExtensionServiceRootfsPath, name)

	for _, path := range []string{rootfs, filepath.Join(rootfs, "etc", "hosts")} {
		suite.Assert().Equal("system_u:object_r:"+constants.SELinuxTypeExtensionRootfs+":s0", suite.fileLabel(nodeCtx, path), path)
	}

	module, err := safe.StateGetByID[*runtimeres.SELinuxModule](nodeCtx, suite.Client.COSI, id)
	suite.Require().NoError(err)

	for source, stateType := range module.TypedSpec().Labels {
		suite.Assert().Equal("system_u:object_r:"+stateType+":s0", suite.fileLabel(nodeCtx, source), source)
	}

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Contains(status.TypedSpec().Modules, id)
		asrt.Empty(status.TypedSpec().Error)
	})

	cfg := extensions.NewServicesConfigV1Alpha1()
	cfg.ServiceName = name
	cfg.ServiceSELinux = &extensions.ServiceSELinux{SELinuxType: "ext_privileged_t"}

	suite.PatchMachineConfig(nodeCtx, cfg)

	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, name)

	pid = suite.extensionServicePID(nodeCtx, id, pid)
	suite.Assert().Equal(selinuxLabel("ext_privileged_t"), suite.getLabel(nodeCtx, pid))

	// a type no module declares yet: the service waits for it, and starts by itself once a module declares it
	cfg.ServiceSELinux.SELinuxType = "ext_declared_later_t"

	suite.PatchMachineConfig(nodeCtx, cfg)
	suite.waitForExtensionServiceEvent(nodeCtx, id, "selinux type ext_declared_later_t")

	declared := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("declared-later")
	declared.PolicyContent = "(type ext_declared_later_t)\n(call ext_privileged_domain (ext_declared_later_t))\n"

	suite.PatchMachineConfig(nodeCtx, declared)

	pid = suite.extensionServicePID(nodeCtx, id, pid)
	suite.Assert().Equal(selinuxLabel("ext_declared_later_t"), suite.getLabel(nodeCtx, pid))

	// the service leaves the type before its module goes
	suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, name)

	pid = suite.extensionServicePID(nodeCtx, id, pid)
	suite.Assert().Equal(selinuxLabel(typ), suite.getLabel(nodeCtx, pid))

	suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "declared-later")

	// a ceiling every extension domain contradicts: the compile fails, the service keeps running with the loaded policy
	ceiling := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("ceiling")
	ceiling.PolicyContent = "(neverallow extension_p usr_t (file (execute)))\n"

	suite.PatchMachineConfig(nodeCtx, ceiling)

	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "ceiling")

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Contains(status.TypedSpec().Modules, "config-ceiling")
		asrt.NotContains(status.TypedSpec().Loaded, "config-ceiling")
		asrt.Contains(status.TypedSpec().Loaded, id)
		asrt.Contains(status.TypedSpec().Error, "module config-ceiling rejected")
		asrt.Contains(status.TypedSpec().Error, "neverallow check failed")
	})

	suite.Assert().Equal(selinuxLabel(typ), suite.getLabel(nodeCtx, pid))

	// the rejected document takes nothing else down: a module declared beside it is loaded, the service selects its type
	beside := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("beside-ceiling")
	beside.PolicyContent = "(type ext_beside_t)\n(call ext_privileged_domain (ext_beside_t))\n"

	suite.PatchMachineConfig(nodeCtx, beside)

	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "beside-ceiling")

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Contains(status.TypedSpec().Loaded, "config-beside-ceiling")
		asrt.NotContains(status.TypedSpec().Loaded, "config-ceiling")
	})

	cfg.ServiceSELinux.SELinuxType = "ext_beside_t"

	suite.PatchMachineConfig(nodeCtx, cfg)

	pid = suite.extensionServicePID(nodeCtx, id, pid)
	suite.Assert().Equal(selinuxLabel("ext_beside_t"), suite.getLabel(nodeCtx, pid))

	suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, name)

	pid = suite.extensionServicePID(nodeCtx, id, pid)
	suite.Assert().Equal(selinuxLabel(typ), suite.getLabel(nodeCtx, pid))

	suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "ceiling")

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.NotContains(status.TypedSpec().Modules, "config-ceiling")
		asrt.Empty(status.TypedSpec().Error)
	})
}

// TestExtensionServiceAudit audits an extension service in container mode until its usual accesses are seen, then runs it
// in the module narrowed to the exercised permissions, without a denial.
//
//nolint:gocyclo
func (suite *SELinuxSuite) TestExtensionServiceAudit() {
	node := suite.RandomDiscoveredNodeInternalIP()
	nodeCtx := client.WithNode(suite.ctx, node)

	name, pid := suite.containerExtensionService(nodeCtx)
	id, typ := "ext-"+name, extgen.TypeName(name)

	cfg := extensions.NewServicesConfigV1Alpha1()
	cfg.ServiceName = name
	cfg.ServiceSELinux = &extensions.ServiceSELinux{SELinuxAudit: true}

	suite.PatchMachineConfig(nodeCtx, cfg)

	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, name)

	// the first round audits every access the policy grants
	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, typ, func(status *runtimeres.SELinuxDomainStatus, asrt *assert.Assertions) {
		asrt.False(status.TypedSpec().ObservedSince.IsZero())
		asrt.GreaterOrEqual(status.TypedSpec().Rounds, uint32(1))
		asrt.NotEmpty(status.TypedSpec().Unexercised)
	})

	// the service restarts with the audit module loaded, so that its startup path is observed
	pid = suite.extensionServicePID(nodeCtx, id, pid)

	_, err := suite.Client.ServiceRestart(nodeCtx, id)
	suite.Require().NoError(err)

	suite.extensionServicePID(nodeCtx, id, pid)

	// the exercised accesses settle once the usual ones are seen
	var exercised, stable int

	suite.Require().NoError(retry.Constant(5*time.Minute, retry.WithUnits(10*time.Second)).Retry(func() error {
		status, err := safe.StateGetByID[*runtimeres.SELinuxDomainStatus](nodeCtx, suite.Client.COSI, typ)
		if err != nil {
			return retry.ExpectedError(err)
		}

		if len(status.TypedSpec().Exercised) != exercised {
			exercised, stable = len(status.TypedSpec().Exercised), 0
		} else {
			stable++
		}

		if exercised == 0 || stable < 3 {
			return retry.ExpectedErrorf("%d accesses exercised, stable %d times", exercised, stable)
		}

		return nil
	}))

	// the observed accesses leave the audit module at the next round, a minute after the first one at least
	var status *runtimeres.SELinuxDomainStatus

	suite.Require().NoError(retry.Constant(3*time.Minute, retry.WithUnits(5*time.Second)).Retry(func() error {
		status, err = safe.StateGetByID[*runtimeres.SELinuxDomainStatus](nodeCtx, suite.Client.COSI, typ)
		if err != nil {
			return retry.ExpectedError(err)
		}

		if status.TypedSpec().Rounds < 2 {
			return retry.ExpectedErrorf("round %d", status.TypedSpec().Rounds)
		}

		return nil
	}))

	suite.Assert().NotEmpty(status.TypedSpec().Exercised)
	suite.Assert().Contains(status.TypedSpec().NarrowedModule, "(call ext_plumbing ("+typ+"))")
	// the service restarted during the audit: its start was observed
	suite.Assert().NotContains(status.TypedSpec().NarrowedModule, "; not started since")

	// the narrowed module, under a name of its own, runs the service without a denial
	narrowed := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("narrowed")
	narrowed.PolicyContent = strings.ReplaceAll(status.TypedSpec().NarrowedModule, typ, "ext_narrowed_t")

	suite.PatchMachineConfig(nodeCtx, narrowed)

	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "narrowed")

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Contains(status.TypedSpec().Modules, "config-narrowed")
		asrt.Empty(status.TypedSpec().Error)
	})

	before := suite.denials(node, "ext_narrowed_t")

	// the document is replaced, a patch could not clear the audit flag
	suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, name)

	pid = suite.extensionServicePID(nodeCtx, id, pid)

	cfg.ServiceSELinux = &extensions.ServiceSELinux{SELinuxType: "ext_narrowed_t"}

	suite.PatchMachineConfig(nodeCtx, cfg)

	pid = suite.extensionServicePID(nodeCtx, id, pid)
	suite.Assert().Equal(selinuxLabel("ext_narrowed_t"), suite.getLabel(nodeCtx, pid))

	// the audit stops with the flag
	rtestutils.AssertNoResource[*runtimeres.SELinuxDomainStatus](nodeCtx, suite.T(), suite.Client.COSI, typ)

	time.Sleep(30 * time.Second)

	suite.Assert().Equal(before, suite.denials(node, "ext_narrowed_t"))

	// the service leaves the type before its module goes: a type removed while in use leaves the kernel objects unlabeled
	suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, name)
	suite.extensionServicePID(nodeCtx, id, pid)
}

// TestPodDomainAudit audits a pod domain of a module until a process monitor pod has exercised its accesses, then runs
// the same pod in the module narrowed to them, on the pod plumbing, without a denial on either side.
//
//nolint:gocyclo
func (suite *SELinuxSuite) TestPodDomainAudit() {
	ip, nodeName := suite.labelingNode(true)
	nodeCtx := client.WithNode(suite.ctx, ip)

	audited := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("audited")
	audited.PolicyContent = "(type pod_audited_t)\n(call pod_hostmon_domain (pod_audited_t))\n"
	audited.PolicyAudit = true

	suite.PatchMachineConfig(nodeCtx, audited)

	// the pods leave the types before their modules go
	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "audited")

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, "pod_audited_t", func(status *runtimeres.SELinuxDomainStatus, asrt *assert.Assertions) {
		asrt.GreaterOrEqual(status.TypedSpec().Rounds, uint32(1))
		// nothing ran in the domain yet
		asrt.Contains(status.TypedSpec().NarrowedModule, "; not started since")
	})

	const exercise = "for p in /proc/[0-9]*; do cat $p/stat $p/comm; ls $p/task; readlink $p/exe; done >/dev/null 2>&1; cat /proc/1/comm"

	monitor := func(name, typ string) podRunner {
		podDef, err := suite.NewPod(name)
		suite.Require().NoError(err)

		podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(nodeName).WithHostPID().WithSELinuxOptions(&corev1.SELinuxOptions{Type: typ})

		suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

		_, _, err = podDef.Exec(suite.ctx, exercise)
		suite.Require().NoError(err)

		return podDef
	}

	podDef := monitor("selinux-audited", "pod_audited_t")
	defer suite.deletePod(podDef)

	// the pod exercises its accesses again after every reload of the audit module and every record the audit log drops,
	// which a busy node does by the hundred thousand: the narrowed module has settled once neither happened for a minute
	// after an exercise, the interval between two rounds
	var (
		module string
		round  uint32
		lost   uint64
		quiet  int
	)

	suite.Require().NoError(retry.Constant(6*time.Minute, retry.WithUnits(10*time.Second)).Retry(func() error {
		status, err := safe.StateGetByID[*runtimeres.SELinuxDomainStatus](nodeCtx, suite.Client.COSI, "pod_audited_t")
		if err != nil {
			return retry.ExpectedError(err)
		}

		if spec := status.TypedSpec(); spec.Rounds != round || spec.LostRecords != lost {
			if _, _, err = podDef.Exec(suite.ctx, exercise); err != nil {
				return retry.ExpectedError(err)
			}

			round, lost, quiet = spec.Rounds, spec.LostRecords, 0

			return retry.ExpectedErrorf("exercised again at round %d, %d records dropped", round, lost)
		}

		module = status.TypedSpec().NarrowedModule

		if quiet++; quiet < 7 {
			return retry.ExpectedErrorf("quiet for %d looks", quiet)
		}

		return nil
	}))

	suite.Assert().Contains(module, "(call pod_plumbing (pod_audited_t))")
	suite.Assert().Contains(module, "(typeattributeset mcs_read_exempt_p pod_audited_t)")
	suite.Assert().NotContains(module, "; not started since")

	suite.deletePod(podDef)

	// the narrowed module, under a name of its own, runs the same pod without a denial, as a subject or as a target
	narrowed := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("pod-narrowed")
	narrowed.PolicyContent = strings.ReplaceAll(module, "pod_audited_t", "pod_narrowed_t")

	suite.PatchMachineConfig(nodeCtx, narrowed)

	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "pod-narrowed")

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Contains(status.TypedSpec().Loaded, "config-pod-narrowed")
	})

	before, beforeTarget := suite.denials(ip, "pod_narrowed_t"), suite.targetDenials(ip, "pod_narrowed_t")

	narrowedPod := monitor("selinux-narrowed", "pod_narrowed_t")
	suite.deletePod(narrowedPod)

	suite.Assert().Equal(before, suite.denials(ip, "pod_narrowed_t"))
	suite.Assert().Equal(beforeTarget, suite.targetDenials(ip, "pod_narrowed_t"))
}

// targetDenials counts the denials of the audit log on a domain as the target, the accesses of the kubelet and of other
// pods to its /proc entries for instance.
func (suite *SELinuxSuite) targetDenials(node, target string) int {
	stream, err := suite.Client.Logs(client.WithNode(suite.ctx, node), constants.SystemContainerdNamespace, common.ContainerDriver_CONTAINERD, "auditd", false, -1)
	suite.Require().NoError(err)

	return strings.Count(suite.readStream(stream), " tcontext=system_u:system_r:"+target+":")
}

// deletePod deletes a pod gracefully and waits for it to be gone, which the kubelet completes once the containers have
// stopped: a module can go then without leaving a process in a type the policy no longer has, which nothing may signal.
func (suite *SELinuxSuite) deletePod(pod podRunner) {
	pods := corev1.SchemeGroupVersion.WithResource("pods")

	suite.Require().NoError(suite.DeleteResource(suite.ctx, pods, "kube-system", pod.Name()))
	suite.Require().NoError(suite.EnsureResourceIsDeleted(suite.ctx, time.Minute, pods, "kube-system", pod.Name()))
}

func selinuxLabel(typ string) string {
	return "system_u:system_r:" + typ + ":s0"
}

// TestNoPtrace confirms ptracing system processes is prohibited in enforcing mode.
func (suite *SELinuxSuite) TestNoPtrace() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	podDef, err := suite.NewPrivilegedPod("pid1-ptrace-test")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true)

	suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	_, stderr, err := podDef.Exec(
		suite.ctx,
		"apk add --update strace",
	)

	suite.Assert().NoError(err)
	suite.Assert().Empty(stderr, "stderr: %s", stderr)

	// if attached, timeout
	ctx, cancel := context.WithTimeout(suite.ctx, time.Second*5)
	defer cancel()

	_, stderr, err = podDef.Exec(
		ctx,
		"strace -p 1",
	)

	// in case of successful attach it will be context.DeadlineExceeded
	suite.Require().Error(err)
	suite.Assert().ErrorContains(err, "command terminated with exit code 1")
	// strace first tests ptrace against itself, which we also deny currently
	suite.Assert().Contains(stderr, "strace: do_test_ptrace_get_syscall_info: PTRACE_TRACEME: Permission denied")
	suite.Assert().Contains(stderr, "strace: attach: ptrace(PTRACE_SEIZE, 1): Permission denied")
	suite.Assert().NotContains(stderr, "attached")
}

// TestNoMachineSocketAccess confirms pods cannot reach machined socket (not apid, but unsecured one).
func (suite *SELinuxSuite) TestNoMachineSocketAccess() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	podDef, err := suite.NewPrivilegedPod("pid1-socket-test")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true)

	suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	_, stderr, err := podDef.Exec(
		suite.ctx,
		"apk add --update socat",
	)

	suite.Assert().NoError(err)
	suite.Assert().Empty(stderr, "stderr: %s", stderr)

	// if attached, timeout
	ctx, cancel := context.WithTimeout(suite.ctx, time.Second*5)
	defer cancel()

	_, stderr, err = podDef.Exec(
		ctx,
		"socat - UNIX-CONNECT:/host/system/run/machined/machine.sock",
	)

	// in case of successful attach it will be context.DeadlineExceeded
	suite.Require().Error(err)
	suite.Assert().ErrorContains(err, "command terminated with exit code 1")
	suite.Assert().Contains(stderr, "Permission denied")
}

// TestNoStateAccess verifies mounting STATE does not allow /system/state/config.yaml access.
//
// STATE carries no xattr labels and machined only mounts it transiently with context=system_state_t, so a
// mount of the device from a pod shows its files as unlabeled_t, which no pod domain may read. The
// system_state_t type itself is a neverallow for every pod domain, checked by secilc at compile time.
func (suite *SELinuxSuite) TestNoStateAccess() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	node := suite.RandomDiscoveredNodeInternalIP()
	nodeCtx := client.WithNode(suite.ctx, node)

	state, err := safe.StateGetByID[*block.VolumeStatus](nodeCtx, suite.Client.COSI, "STATE")
	suite.Assert().NoError(err)

	podDef, err := suite.NewPrivilegedPod("system-state-test")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true)

	suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	_, stderr, err := podDef.Exec(
		suite.ctx,
		"mount "+state.TypedSpec().MountLocation+" /mnt",
	)

	suite.Assert().NoError(err)
	suite.Assert().Empty(stderr, "stderr: %s", stderr)

	_, stderr, err = podDef.Exec(
		suite.ctx,
		"cat /mnt/config.yaml",
	)

	suite.Require().Error(err)
	suite.Assert().ErrorContains(err, "command terminated with exit code 1")
	suite.Assert().Contains(stderr, "cat: can't open '/mnt/config.yaml': Permission denied")
}

func init() {
	allSuites = append(allSuites, new(SELinuxSuite))
}
