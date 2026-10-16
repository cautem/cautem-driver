//go:build !darwin && !linux

package vm

import (
	"fmt"
	"syscall"
)

func workerProcessAttributes() *syscall.SysProcAttr { return nil }

func workerIsolationForChild() (workerIsolationConfig, error) {
	return workerIsolationConfig{}, fmt.Errorf("VM worker isolation is unsupported on this platform")
}

func prepareWorkerIsolation(workerIsolationConfig) error {
	return fmt.Errorf("VM worker isolation is unsupported on this platform")
}
