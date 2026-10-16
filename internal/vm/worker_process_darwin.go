//go:build darwin

package vm

import (
	"fmt"
	"syscall"
)

func workerProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func workerIsolationForChild() (workerIsolationConfig, error) {
	return workerIsolationConfig{NoHostMounts: true}, nil
}

func prepareWorkerIsolation(config workerIsolationConfig) error {
	if !config.NoHostMounts || config.HostMountNamespace != "" || config.HostUserNamespace != "" {
		return fmt.Errorf("macOS VM workers require an explicit no-host-mounts isolation mode")
	}
	return nil
}
