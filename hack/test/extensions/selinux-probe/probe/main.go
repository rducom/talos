// The selinux-probe extension service exercises the accesses its spec grants and the ones it must not have, one
// case at a time, and logs a verdict per case for the SELinux integration suite to read. It then stays running, so
// that the logs stay readable. PROBE_ROLE selects the cases: main, host or config, one per service of the extension.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type probeCase struct {
	name string
	run  func() error
}

var errSkip = errors.New("skipped")

var roles = map[string][]probeCase{
	"main": {
		{"rootfs-read", func() error { return readable("/etc/probe.conf", "/etc/passwd", "/usr/lib") }},
		{"rootfs-exec-dynamic", func() error { return exec.Command("/bin/busybox", "true").Run() }},
		{"state-write", func() error { return writable("/var/lib/selinux-probe") }},
		{"state-read-all", func() error { return readableTree("/var/lib/selinux-probe") }},
		{"run-socket", func() error { return listenUnix("/run/selinux-probe/probe.sock") }},
		{"device-tun", func() error { return openWrite("/dev/net/tun") }},
		{"etc-read", func() error { return readable("/etc/ssl/certs/ca-certificates.crt", "/etc/os-release") }},
		{"host-network-files", func() error { return readable("/etc/hosts", "/etc/resolv.conf") }},
		{"sysfs-write", func() error { return openWrite("/sys/class/net/lo/tx_queue_len") }},
		{"machined-socket", func() error { return connectUnix("/system/run/machined/machine.sock") }},
	},
	"host": {
		{"host-entrypoint", func() error { return readable("/usr/local/sbin/selinux-probe-host") }},
		{"rootfs-write", func() error { return writable("/") }},
		{"state-write", func() error { return writable("/var/lib/selinux-probe-host") }},
		{"own-state-through-var", func() error { return readable("/host/var/lib/selinux-probe-host") }},
		{"other-state-denied", func() error { return denied("/host/var/lib/selinux-probe") }},
		{"kubelet-state-denied", func() error { return denied("/host/var/lib/kubelet") }},
		{"etcd-state-denied", func() error { return denied("/host/var/lib/etcd") }},
		{"audit-log-denied", func() error { return denied("/host/var/log/audit") }},
	},
	"config": {
		{"config-file", func() error { return readable("/etc/probe/config.yaml") }},
		{"config-environment", func() error {
			if os.Getenv("PROBE_MESSAGE") == "" {
				return errors.New("PROBE_MESSAGE is not set")
			}

			return nil
		}},
	},
}

func main() {
	role := os.Getenv("PROBE_ROLE")

	cases, ok := roles[role]
	if !ok {
		fmt.Printf("probe: unknown PROBE_ROLE %q\n", role)
		os.Exit(1)
	}

	pass, fail := 0, 0

	for _, c := range cases {
		switch err := c.run(); {
		case err == nil:
			pass++

			fmt.Printf("probe: %s: PASS\n", c.name)
		case errors.Is(err, errSkip):
			fmt.Printf("probe: %s: SKIP: %v\n", c.name, err)
		default:
			fail++

			fmt.Printf("probe: %s: FAIL: %v\n", c.name, err)
		}
	}

	fmt.Printf("probe: done: %d pass, %d fail\n", pass, fail)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
}

// readable reads every path: the entries of a directory, the content of a file.
func readable(paths ...string) error {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			_, err = os.ReadDir(path)
		} else {
			_, err = os.ReadFile(path)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

// readableTree reads every file under dir, whoever created it: the files a pod leaves in the state of a service must be
// readable by the service.
func readableTree(dir string) error {
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.Type().IsRegular() {
			_, err = os.ReadFile(path)
		}

		return err
	})
}

// writable creates, reads back and removes a file and a directory in dir.
func writable(dir string) error {
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	file, sub := filepath.Join(dir, "probe-"+suffix), filepath.Join(dir, "probe-dir-"+suffix)

	if err := os.WriteFile(file, []byte("probe\n"), 0o600); err != nil {
		return err
	}

	if _, err := os.ReadFile(file); err != nil {
		return err
	}

	if err := os.Mkdir(sub, 0o700); err != nil {
		return err
	}

	return errors.Join(os.Remove(file), os.Remove(sub))
}

// listenUnix binds a unix socket; closing the listener removes it.
func listenUnix(path string) error {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		return err
	}

	return l.Close()
}

// connectUnix connects to a unix socket.
func connectUnix(path string) error {
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", path)
	if err != nil {
		return err
	}

	return conn.Close()
}

// openWrite opens a file for writing without writing anything.
func openWrite(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	return f.Close()
}

// denied expects the directory to be unreadable; a directory which does not exist on the node skips the case.
func denied(path string) error {
	_, err := os.ReadDir(path)

	switch {
	case err == nil:
		return fmt.Errorf("%s is readable", path)
	case errors.Is(err, syscall.EACCES):
		return nil
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%w: %v", errSkip, err)
	default:
		return err
	}
}
