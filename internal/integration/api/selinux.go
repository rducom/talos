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

	return string(bytes.TrimSpace(value))
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

						// the state directories of extension services carry the types of their modules
						if !strings.Contains(got, ":ext_") {
							suite.Require().Contains(got, label, "expected %s to have label %s, got %s (checking %s)", info.Name, label, got, path)
						}

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

func (suite *SELinuxSuite) extensionsInstalled(nodeCtx context.Context) bool {
	extensions, err := safe.StateListAll[*runtimeres.ExtensionStatus](nodeCtx, suite.Client.COSI)
	suite.Require().NoError(err)

	return extensions.Len() > 0
}

func (suite *SELinuxSuite) skipUnlessCRILabels(node string) {
	if !suite.criLabelsContainers(client.WithNode(suite.ctx, node)) {
		suite.T().Skip("skipping SELinux pod domain tests since the CRI does not label containers")
	}
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

func (suite *SELinuxSuite) podLabel(podDef podRunner) string {
	suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	stdout, stderr, err := podDef.Exec(suite.ctx, "cat /proc/self/attr/current")
	suite.Require().NoError(err)
	suite.Assert().Empty(stderr, "stderr: %s", stderr)

	return strings.TrimRight(stdout, "\n\x00")
}

// TestPodDomains verifies the domains pods land in when the CRI labels containers.
func (suite *SELinuxSuite) TestPodDomains() {
	suite.skipUnlessCRILabels(suite.RandomDiscoveredNodeInternalIP())

	podDef, err := suite.NewPod("selinux-pod")
	suite.Require().NoError(err)

	suite.Assert().Regexp(`^system_u:system_r:pod_t:s0:c\d+,c\d+$`, suite.podLabel(podDef.WithQuiet(true)))

	podDef, err = suite.NewPrivilegedPod("selinux-privileged")
	suite.Require().NoError(err)

	suite.Assert().Equal("system_u:system_r:pod_privileged_t:s0", suite.podLabel(podDef.WithQuiet(true)))

	podDef, err = suite.NewPod("selinux-hostmon")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithSELinuxOptions(&corev1.SELinuxOptions{Type: "pod_hostmon_t"})

	suite.Assert().Regexp(`^system_u:system_r:pod_hostmon_t:s0:c\d+,c\d+$`, suite.podLabel(podDef))

	podDef, err = suite.NewPod("selinux-spc")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithSELinuxOptions(&corev1.SELinuxOptions{Type: "spc_t", Level: "s0"})

	suite.Assert().Equal("system_u:system_r:pod_privileged_t:s0", suite.podLabel(podDef))

	podDef, err = suite.NewPod("selinux-unknown")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithSELinuxOptions(&corev1.SELinuxOptions{Type: "unknown_t"})

	suite.Assert().Error(podDef.Create(suite.ctx, 20*time.Second))
	suite.Require().NoError(podDef.Delete(suite.ctx))

	if !suite.SelinuxEnforcing {
		return
	}

	podDef, err = suite.NewPod("selinux-kubelet")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithSELinuxOptions(&corev1.SELinuxOptions{Type: "kubelet_t"})

	suite.Assert().Error(podDef.Create(suite.ctx, 20*time.Second))
	suite.Require().NoError(podDef.Delete(suite.ctx))
}

// TestPodMCSIsolation confirms pods with distinct categories cannot read each other's files, and that a process monitor reads them without writing.
func (suite *SELinuxSuite) TestPodMCSIsolation() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	ip := suite.RandomDiscoveredNodeInternalIP()
	suite.skipUnlessCRILabels(ip)

	node, err := suite.GetK8sNodeByInternalIP(suite.ctx, ip)
	suite.Require().NoError(err)

	newPod := func(name string) podRunner {
		podDef, err := suite.NewPod(name)
		suite.Require().NoError(err)

		podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node.Name).WithHostVolumeMount("/var/selinux-test", "/data")

		if name == "selinux-mcs-hostmon" {
			podDef = podDef.WithSELinuxOptions(&corev1.SELinuxOptions{Type: "pod_hostmon_t"})
		}

		suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

		return podDef
	}

	writer := newPod("selinux-mcs-writer")
	defer writer.Delete(suite.ctx) //nolint:errcheck

	reader := newPod("selinux-mcs-reader")
	defer reader.Delete(suite.ctx) //nolint:errcheck

	hostmon := newPod("selinux-mcs-hostmon")
	defer hostmon.Delete(suite.ctx) //nolint:errcheck

	file := "/data/" + writer.Name()

	_, stderr, err := writer.Exec(suite.ctx, "echo secret > "+file)
	suite.Require().NoError(err)
	suite.Assert().Empty(stderr, "stderr: %s", stderr)

	_, stderr, err = reader.Exec(suite.ctx, "cat "+file)
	suite.Require().Error(err)
	suite.Assert().Contains(stderr, "Permission denied")

	stdout, _, err := hostmon.Exec(suite.ctx, "cat "+file)
	suite.Require().NoError(err)
	suite.Assert().Equal("secret\n", stdout)

	_, stderr, err = hostmon.Exec(suite.ctx, "echo tampered >> "+file)
	suite.Require().Error(err)
	suite.Assert().Contains(stderr, "Permission denied")
}

// TestPrivilegedHostAccess runs a host binary from a privileged pod the way TopoLVM does and serves a socket to a sidecar, without denials.
func (suite *SELinuxSuite) TestPrivilegedHostAccess() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	ip := suite.RandomDiscoveredNodeInternalIP()
	suite.skipUnlessCRILabels(ip)

	node, err := suite.GetK8sNodeByInternalIP(suite.ctx, ip)
	suite.Require().NoError(err)

	before := suite.denials(ip, "pod_privileged_t")

	podDef, err := suite.NewPrivilegedPod("selinux-nsenter")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNodeName(node.Name).WithHostPID()

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

	sidecar = sidecar.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node.Name).WithHostVolumeMount("/var/selinux-test", "/data")

	suite.Require().NoError(sidecar.Create(suite.ctx, 5*time.Minute))

	defer sidecar.Delete(suite.ctx) //nolint:errcheck

	stdout, _, err = sidecar.Exec(suite.ctx, "apk add --update socat >/dev/null && echo hello | socat - UNIX-CONNECT:/data/"+podDef.Name())
	suite.Require().NoError(err)
	suite.Assert().Equal("hello\n", stdout)
	suite.Assert().Equal(before, suite.denials(ip, "pod_privileged_t"))
}

// TestHostmonProcAccess reads every host process through /proc from a pod_hostmon_t pod, without denials.
func (suite *SELinuxSuite) TestHostmonProcAccess() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	ip := suite.RandomDiscoveredNodeInternalIP()
	suite.skipUnlessCRILabels(ip)

	node, err := suite.GetK8sNodeByInternalIP(suite.ctx, ip)
	suite.Require().NoError(err)

	before := suite.denials(ip, "pod_hostmon_t")

	podDef, err := suite.NewPod("selinux-hostmon-proc")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node.Name).WithHostPID().WithSELinuxOptions(&corev1.SELinuxOptions{Type: "pod_hostmon_t"})

	suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	// readlink of /proc/1/exe needs CAP_SYS_PTRACE on a non-dumpable process, a DAC check with no AVC record
	stdout, _, err := podDef.Exec(suite.ctx, "for p in /proc/[0-9]*; do cat $p/stat $p/comm; ls $p/task; readlink $p/exe; done >/dev/null 2>&1; cat /proc/1/comm")
	suite.Require().NoError(err)
	suite.Assert().NotEmpty(strings.TrimSpace(stdout))
	suite.Assert().Equal(before, suite.denials(ip, "pod_hostmon_t"))
}

// TestKubeletVolumeLabels checks the kubelet sees SELinux when the CRI labels containers and computes the mount label of a ReadWriteOncePod volume.
func (suite *SELinuxSuite) TestKubeletVolumeLabels() {
	ip := suite.RandomDiscoveredNodeInternalIP()
	suite.skipUnlessCRILabels(ip)

	node, err := suite.GetK8sNodeByInternalIP(suite.ctx, ip)
	suite.Require().NoError(err)

	name := "selinux-test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	driver := name + ".csi.talos.dev"
	metric := `volume_manager_selinux_volumes_admitted_total{access_mode="RWOP",volume_plugin="kubernetes.io/csi/` + driver + `"}`

	_, err = suite.Clientset.StorageV1().CSIDrivers().Create(suite.ctx, &storagev1.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{Name: driver},
		Spec:       storagev1.CSIDriverSpec{AttachRequired: new(false), SELinuxMount: new(true)},
	}, metav1.CreateOptions{})
	suite.Require().NoError(err)

	defer suite.Clientset.StorageV1().CSIDrivers().Delete(suite.ctx, driver, metav1.DeleteOptions{}) //nolint:errcheck

	_, err = suite.Clientset.CoreV1().PersistentVolumes().Create(suite.ctx, &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
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
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod},
			StorageClassName: new(name),
			VolumeName:       name,
			Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: apiresource.MustParse("1Mi")}},
		},
	}, metav1.CreateOptions{})
	suite.Require().NoError(err)

	defer suite.Clientset.CoreV1().PersistentVolumeClaims("kube-system").Delete(suite.ctx, name, metav1.DeleteOptions{}) //nolint:errcheck

	before := suite.kubeletMetric(node.Name, metric)

	podDef, err := suite.NewPod("selinux-pvc")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node.Name).
		WithSELinuxOptions(&corev1.SELinuxOptions{Level: "s0:c600,c601"}).WithPersistentVolumeClaim(name, "/data")

	// no driver serves the volume, the pod never runs
	suite.Assert().Error(podDef.Create(suite.ctx, 20*time.Second))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	suite.Require().NoError(retry.Constant(time.Minute, retry.WithUnits(time.Second)).Retry(func() error {
		if suite.kubeletMetric(node.Name, metric) <= before {
			return retry.ExpectedErrorf("the kubelet did not admit the volume with a SELinux label")
		}

		return nil
	}))
}

// TestPrivilegedDomainModule runs a host binary from a non-privileged pod with capabilities in a module domain built on pod_privileged_domain, without denials.
func (suite *SELinuxSuite) TestPrivilegedDomainModule() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	ip := suite.RandomDiscoveredNodeInternalIP()
	suite.skipUnlessCRILabels(ip)

	node, err := suite.GetK8sNodeByInternalIP(suite.ctx, ip)
	suite.Require().NoError(err)

	before := suite.denials(ip, "pod_cni_t")

	podDef, err := suite.NewPod("selinux-cni")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node.Name).WithHostPID().
		WithCapabilities("SYS_ADMIN", "SYS_PTRACE", "SYS_CHROOT").WithSELinuxOptions(&corev1.SELinuxOptions{Type: "pod_cni_t"})

	suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	// lvm also probes /dev/mapper/control, which the device cgroup of a non-privileged container refuses
	stdout, _, err := podDef.Exec(suite.ctx, "cat /proc/self/attr/current; nsenter -t 1 -m -- /usr/bin/lvm version")
	suite.Require().NoError(err)
	suite.Assert().Regexp(`^system_u:system_r:pod_cni_t:s0:c\d+,c\d+`, stdout)
	suite.Assert().Contains(stdout, "LVM version")
	suite.Assert().Equal(before, suite.denials(ip, "pod_cni_t"))
}

// TestHostPathFixedLevel shares a hostPath between successive pods carrying the same level and keeps it from pods with other categories.
func (suite *SELinuxSuite) TestHostPathFixedLevel() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	ip := suite.RandomDiscoveredNodeInternalIP()
	suite.skipUnlessCRILabels(ip)

	node, err := suite.GetK8sNodeByInternalIP(suite.ctx, ip)
	suite.Require().NoError(err)

	newPod := func(name, level string) podRunner {
		podDef, err := suite.NewPod(name)
		suite.Require().NoError(err)

		return podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node.Name).WithHostVolumeMount("/var/selinux-test", "/data").
			WithSELinuxOptions(&corev1.SELinuxOptions{Level: level})
	}

	first := newPod("selinux-level-first", "s0:c600,c601")
	suite.Require().NoError(first.Create(suite.ctx, 5*time.Minute))

	file := "/data/fixed-" + strconv.FormatInt(time.Now().UnixNano(), 36)

	stdout, stderr, err := first.Exec(suite.ctx, "cat /proc/self/attr/current; echo secret > "+file)
	suite.Require().NoError(err)
	suite.Assert().Empty(stderr, "stderr: %s", stderr)
	suite.Assert().Equal("system_u:system_r:pod_t:s0:c600,c601", strings.TrimRight(stdout, "\n\x00"))
	suite.Require().NoError(first.Delete(suite.ctx))

	second := newPod("selinux-level-second", "s0:c600,c601")
	suite.Require().NoError(second.Create(suite.ctx, 5*time.Minute))

	defer second.Delete(suite.ctx) //nolint:errcheck

	stdout, _, err = second.Exec(suite.ctx, "cat "+file)
	suite.Require().NoError(err)
	suite.Assert().Equal("secret\n", stdout)

	other := newPod("selinux-level-other", "s0:c602,c603")
	suite.Require().NoError(other.Create(suite.ctx, 5*time.Minute))

	defer other.Delete(suite.ctx) //nolint:errcheck

	_, stderr, err = other.Exec(suite.ctx, "cat "+file)
	suite.Require().Error(err)
	suite.Assert().Contains(stderr, "Permission denied")
}

// TestPodHostPIDProcAccess confirms a pod_t pod sharing the host PID namespace cannot read /proc of other domains or categories and that the denial is audited.
func (suite *SELinuxSuite) TestPodHostPIDProcAccess() {
	if !suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux negative tests in permissive mode")
	}

	ip := suite.RandomDiscoveredNodeInternalIP()
	suite.skipUnlessCRILabels(ip)

	node, err := suite.GetK8sNodeByInternalIP(suite.ctx, ip)
	suite.Require().NoError(err)

	before := suite.denials(ip, "pod_t")

	podDef, err := suite.NewPod("selinux-hostpid")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node.Name).WithHostPID()

	suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

	defer podDef.Delete(suite.ctx) //nolint:errcheck

	// the shell glob drops the entries it cannot search, hence the explicit loop
	_, stderr, err := podDef.Exec(suite.ctx, "rc=0; for p in $(ls /proc | grep -E '^[0-9]+$'); do cat /proc/$p/comm >/dev/null || rc=1; done; exit $rc")
	suite.Require().Error(err)
	suite.Assert().Contains(stderr, "Permission denied")
	suite.Assert().Greater(suite.denials(ip, "pod_t"), before)
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

				// the selinux-probe test extension checks denials on purpose
				if strings.HasPrefix(fields[2], "ext_selinux_probe") {
					continue
				}

				suite.Assert().True(slices.Contains(podDomains, fields[2]) || strings.Contains(fields[3], ":c"), "host domain denied: %s", line)
			}
		}
	}
}

// extensionServiceLabel returns the process label of a running extension service.
func (suite *SELinuxSuite) extensionServiceLabel(nodeCtx context.Context, id string) string {
	pid, err := safe.StateGetByID[*runtimeres.ServicePID](nodeCtx, suite.Client.COSI, id)
	suite.Require().NoError(err)

	return suite.getLabel(nodeCtx, pid.TypedSpec().PID)
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

// TestExtensionServiceDomains checks the domain of the extension services in container mode: the type their module derives
// from the spec, with their state directories labeled for them, unless the machine config selects another type; an unknown
// type fails the service with a readable error; a module contradicting a neverallow of the config is rejected without
// touching the loaded policy.
//
//nolint:gocyclo
func (suite *SELinuxSuite) TestExtensionServiceDomains() {
	node := suite.RandomDiscoveredNodeInternalIP()
	nodeCtx := client.WithNode(suite.ctx, node)

	if pointer.SafeDeref(procfs.NewCmdline(suite.ReadCmdline(nodeCtx)).Get(constants.KernelParamSELinux).First()) == "" {
		suite.T().Skip("skipping SELinux test since SELinux is disabled")
	}

	services, err := safe.StateListAll[*v1alpha1.Service](nodeCtx, suite.Client.COSI)
	suite.Require().NoError(err)

	var name string

	for svc := range services.All() {
		if !strings.HasPrefix(svc.Metadata().ID(), "ext-") || !svc.TypedSpec().Running {
			continue
		}

		// services in host mode keep their domain
		label := suite.extensionServiceLabel(nodeCtx, svc.Metadata().ID())
		if label == constants.SelinuxLabelUnconfinedService {
			continue
		}

		name = strings.TrimPrefix(svc.Metadata().ID(), "ext-")

		suite.Assert().Equal("system_u:system_r:"+extgen.TypeName(name)+":s0", label, svc.Metadata().ID())

		module, err := safe.StateGetByID[*runtimeres.SELinuxModule](nodeCtx, suite.Client.COSI, svc.Metadata().ID())
		suite.Require().NoError(err)
		suite.Assert().Empty(module.TypedSpec().Warnings)

		for source, typ := range module.TypedSpec().Labels {
			suite.Assert().Equal("system_u:object_r:"+typ+":s0", suite.fileLabel(nodeCtx, source), source)
		}
	}

	if name == "" {
		suite.T().Skip("skipping SELinux test since no extension service runs in container mode")
	}

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Contains(status.TypedSpec().Modules, "ext-"+name)
		asrt.Empty(status.TypedSpec().Error)
	})

	cfg := extensions.NewServicesConfigV1Alpha1()
	cfg.ServiceName = name
	cfg.ServiceSELinux = &extensions.ServiceSELinux{SELinuxType: "ext_privileged_t"}

	suite.PatchMachineConfig(nodeCtx, cfg)

	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, name)

	suite.waitForExtensionServiceEvent(nodeCtx, "ext-"+name, "Started task")
	suite.Assert().Equal("system_u:system_r:ext_privileged_t:s0", suite.extensionServiceLabel(nodeCtx, "ext-"+name))

	// a type no module declares yet: the service waits for it, and starts by itself once a module declares it
	cfg.ServiceSELinux.SELinuxType = "ext_declared_later_t"

	suite.PatchMachineConfig(nodeCtx, cfg)
	suite.waitForExtensionServiceEvent(nodeCtx, "ext-"+name, "selinux type ext_declared_later_t")

	declared := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("declared-later")
	declared.PolicyContent = "(type ext_declared_later_t)\n(call ext_privileged_domain (ext_declared_later_t))\n"

	suite.PatchMachineConfig(nodeCtx, declared)

	suite.waitForExtensionServiceEvent(nodeCtx, "ext-"+name, "Started task")
	suite.Assert().Equal("system_u:system_r:ext_declared_later_t:s0", suite.extensionServiceLabel(nodeCtx, "ext-"+name))

	// the service leaves the type before its module goes
	suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, name)
	suite.waitForExtensionServiceEvent(nodeCtx, "ext-"+name, "Started task")
	suite.Assert().Equal("system_u:system_r:"+extgen.TypeName(name)+":s0", suite.extensionServiceLabel(nodeCtx, "ext-"+name))

	suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "declared-later")

	// a ceiling every extension domain contradicts: the compile fails, the service keeps running with the loaded policy
	ceiling := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("ceiling")
	ceiling.PolicyContent = "(neverallow extension_p usr_t (file (execute)))\n"

	suite.PatchMachineConfig(nodeCtx, ceiling)

	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "ceiling")

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Contains(status.TypedSpec().Modules, "config-ceiling")
		asrt.NotContains(status.TypedSpec().Loaded, "config-ceiling")
		asrt.Contains(status.TypedSpec().Loaded, "ext-"+name)
		asrt.Contains(status.TypedSpec().Error, "module config-ceiling rejected")
		asrt.Contains(status.TypedSpec().Error, "neverallow check failed")
	})

	suite.Assert().Equal("system_u:system_r:"+extgen.TypeName(name)+":s0", suite.extensionServiceLabel(nodeCtx, "ext-"+name))

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
	suite.waitForExtensionServiceEvent(nodeCtx, "ext-"+name, "Started task")
	suite.Assert().Equal("system_u:system_r:ext_beside_t:s0", suite.extensionServiceLabel(nodeCtx, "ext-"+name))

	suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, name)
	suite.waitForExtensionServiceEvent(nodeCtx, "ext-"+name, "Started task")
	suite.Assert().Equal("system_u:system_r:"+extgen.TypeName(name)+":s0", suite.extensionServiceLabel(nodeCtx, "ext-"+name))

	suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "ceiling")

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.NotContains(status.TypedSpec().Modules, "config-ceiling")
		asrt.Empty(status.TypedSpec().Error)
	})
}

// TestExtensionProbe reads the verdicts of the selinux-probe test extension (hack/test/extensions/selinux-probe) when it
// is installed: every access its specs grant works, and what they do not grant is denied; in permissive mode nothing
// is denied, and the denials show in the audit log instead.
//
//nolint:gocyclo
func (suite *SELinuxSuite) TestExtensionProbe() {
	node := suite.RandomDiscoveredNodeInternalIP()
	nodeCtx := client.WithNode(suite.ctx, node)

	if _, err := suite.Client.ServiceInfo(nodeCtx, "ext-selinux-probe"); err != nil {
		suite.T().Skip("skipping SELinux test since the selinux-probe extension is not installed")
	}

	cfg := extensions.NewServicesConfigV1Alpha1()
	cfg.ServiceName = "selinux-probe-config"
	cfg.ServiceConfigFiles = extensions.ConfigFileList{{ConfigFileContent: "probe: ok\n", ConfigFileMountPath: "/etc/probe/config.yaml"}}
	cfg.ServiceEnvironment = []string{"PROBE_MESSAGE=hello"}

	suite.PatchMachineConfig(nodeCtx, cfg)

	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, extensions.ServiceConfigKind, "selinux-probe-config")

	for _, id := range []string{"ext-selinux-probe", "ext-selinux-probe-host", "ext-selinux-probe-config"} {
		var logs string

		suite.Require().NoError(retry.Constant(2*time.Minute, retry.WithUnits(time.Second)).Retry(func() error {
			var err error

			// the log of a service which has not started yet is not registered
			if logs, err = suite.serviceLogs(nodeCtx, id); err != nil {
				return retry.ExpectedError(err)
			}

			if !strings.Contains(logs, "probe: done:") {
				return retry.ExpectedErrorf("%s: the probe has not finished", id)
			}

			return nil
		}))

		for line := range strings.SplitSeq(logs, "\n") {
			suite.Assert().NotContains(line, ": FAIL:", id)

			if !suite.SelinuxEnforcing && strings.Contains(line, "-denied: ") {
				suite.Assert().Contains(line, ": SKIP: ", id)
			}
		}
	}

	if suite.SelinuxEnforcing {
		return
	}

	audit, err := suite.serviceLogs(nodeCtx, "auditd")
	suite.Require().NoError(err)

	for _, target := range []string{"kubelet_state_t", "etcd_data_t", "audit_log_t", "ext_selinux_probe_state_t"} {
		suite.Assert().Regexp("denied  \\{ read \\}.*scontext=system_u:system_r:ext_selinux_probe_host_t:s0 tcontext=system_u:object_r:"+target+":s0 tclass=dir permissive=1", audit)
	}
}

// TestExtensionStateMCS: a file a pod creates in the state of an extension service carries no MCS category, so that the
// service, which runs without any, and a pod of other categories read it back; the module of the pod grants the state
// type, which pod_domain does not.
func (suite *SELinuxSuite) TestExtensionStateMCS() {
	ip := suite.RandomDiscoveredNodeInternalIP()
	nodeCtx := client.WithNode(suite.ctx, ip)

	if _, err := suite.Client.ServiceInfo(nodeCtx, "ext-selinux-probe"); err != nil {
		suite.T().Skip("skipping SELinux test since the selinux-probe extension is not installed")
	}

	suite.skipUnlessCRILabels(ip)

	node, err := suite.GetK8sNodeByInternalIP(suite.ctx, ip)
	suite.Require().NoError(err)

	probeClient := runtimeconfig.NewSELinuxPolicyConfigV1Alpha1("probe-client")
	probeClient.PolicyContent = "(type pod_probe_client_t)\n(call pod_domain (pod_probe_client_t))\n(allow pod_probe_client_t ext_selinux_probe_state_t (fs_classes (rw)))\n"

	suite.PatchMachineConfig(nodeCtx, probeClient)

	// the pods leave the type before its module goes
	defer suite.RemoveMachineConfigDocumentsByName(nodeCtx, runtimeconfig.SELinuxPolicyConfigKind, "probe-client")

	rtestutils.AssertResource(nodeCtx, suite.T(), suite.Client.COSI, runtimeres.SELinuxPolicyStatusID, func(status *runtimeres.SELinuxPolicyStatus, asrt *assert.Assertions) {
		asrt.Contains(status.TypedSpec().Loaded, "config-probe-client")
	})

	newPod := func(name string) podRunner {
		podDef, err := suite.NewPod(name)
		suite.Require().NoError(err)

		podDef = podDef.WithQuiet(true).WithNamespace("kube-system").WithNodeName(node.Name).WithHostVolumeMount("/var/lib/selinux-probe", "/state").
			WithSELinuxOptions(&corev1.SELinuxOptions{Type: "pod_probe_client_t"})

		suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

		return podDef
	}

	writer := newPod("selinux-state-writer")
	defer writer.Delete(suite.ctx) //nolint:errcheck

	reader := newPod("selinux-state-reader")
	defer reader.Delete(suite.ctx) //nolint:errcheck

	file := "/state/" + writer.Name()

	_, stderr, err := writer.Exec(suite.ctx, "echo record > "+file+" && cat "+file)
	suite.Require().NoError(err)
	suite.Assert().Empty(stderr, "stderr: %s", stderr)

	defer writer.Exec(suite.ctx, "rm -f "+file) //nolint:errcheck

	suite.Assert().Equal("system_u:object_r:ext_selinux_probe_state_t:s0", suite.fileLabel(nodeCtx, "/var/lib/selinux-probe/"+writer.Name()))

	stdout, _, err := reader.Exec(suite.ctx, "cat "+file)
	suite.Require().NoError(err)
	suite.Assert().Equal("record\n", stdout)

	// the service reads every file of its state at its start
	logs, err := suite.serviceLogs(nodeCtx, "ext-selinux-probe")
	suite.Require().NoError(err)

	runs := strings.Count(logs, "probe: done:")

	_, err = suite.Client.ServiceRestart(nodeCtx, "ext-selinux-probe")
	suite.Require().NoError(err)

	suite.Require().NoError(retry.Constant(2*time.Minute, retry.WithUnits(time.Second)).Retry(func() error {
		if logs, err = suite.serviceLogs(nodeCtx, "ext-selinux-probe"); err != nil {
			return retry.ExpectedError(err)
		}

		if strings.Count(logs, "probe: done:") <= runs {
			return retry.ExpectedErrorf("the probe has not run again")
		}

		return nil
	}))

	verdicts := strings.Split(logs, "probe: done:")
	suite.Assert().Contains(verdicts[len(verdicts)-2], "state-read-all: PASS")
}

// serviceLogs returns the logs of a service on the node.
func (suite *SELinuxSuite) serviceLogs(nodeCtx context.Context, id string) (string, error) {
	stream, err := suite.Client.Logs(nodeCtx, constants.SystemContainerdNamespace, common.ContainerDriver_CONTAINERD, id, false, -1)
	if err != nil {
		return "", err
	}

	reader, err := client.ReadStream(stream)
	if err != nil {
		return "", err
	}

	defer reader.Close() //nolint:errcheck

	body, err := io.ReadAll(reader)

	return string(body), err
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
