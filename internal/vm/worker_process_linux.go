//go:build linux

package vm

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func workerProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid:     true,
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getuid(),
			Size:        1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getgid(),
			Size:        1,
		}},
		GidMappingsEnableSetgroups: false,
	}
}

func workerIsolationForChild() (workerIsolationConfig, error) {
	if os.Getuid() == 0 || os.Getgid() == 0 {
		return workerIsolationConfig{}, fmt.Errorf("VM worker requires a non-root host identity; mapping namespace root to host root would not isolate host access")
	}
	mountNamespace, err := namespaceIdentity("/proc/self/ns/mnt")
	if err != nil {
		return workerIsolationConfig{}, fmt.Errorf("inspect host mount namespace: %w", err)
	}
	userNamespace, err := namespaceIdentity("/proc/self/ns/user")
	if err != nil {
		return workerIsolationConfig{}, fmt.Errorf("inspect host user namespace: %w", err)
	}
	return workerIsolationConfig{HostMountNamespace: mountNamespace, HostUserNamespace: userNamespace}, nil
}

func prepareWorkerIsolation(config workerIsolationConfig) error {
	if config.HostMountNamespace == "" || config.HostUserNamespace == "" {
		return fmt.Errorf("VM worker requires host mount and user namespace identities")
	}
	mountNamespace, err := namespaceIdentity("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("inspect VM worker mount namespace: %w", err)
	}
	if mountNamespace == config.HostMountNamespace {
		return fmt.Errorf("VM worker did not enter a private mount namespace")
	}
	userNamespace, err := namespaceIdentity("/proc/self/ns/user")
	if err != nil {
		return fmt.Errorf("inspect VM worker user namespace: %w", err)
	}
	if userNamespace == config.HostUserNamespace {
		return fmt.Errorf("VM worker did not enter a private user namespace")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("VM worker must run as namespace root with a mapped host identity")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make VM worker mount propagation private: %w", err)
	}
	return nil
}

func namespaceIdentity(path string) (string, error) {
	identity, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(identity, "mnt:[") && !strings.HasPrefix(identity, "user:[") {
		return "", fmt.Errorf("unexpected namespace identity %q", identity)
	}
	return identity, nil
}
