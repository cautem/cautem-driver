package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const defaultRootfsTarMaxBytes int64 = 10 * 1024 * 1024 * 1024
const defaultRootfsImageCacheMaxBytes int64 = 64 * 1024 * 1024 * 1024

// HostConfig selects the libkrun runtime bundle and host virtualization device.
// RuntimeDir can be set with CAUTEM_VM_RUNTIME_DIR.
type HostConfig struct {
	RuntimeDir               string
	KVMDevice                string
	StateDir                 string
	RootfsTarDir             string
	RootfsTarMaxBytes        int64
	RootfsImageCacheMaxBytes int64
	FormatterPath            string
	OverlaySizeBytes         uint64
	GuestAgentPath           string
	WorkerPath               string
	VCPUs                    uint8
	MemoryMiB                uint32
	kvmDeviceCheck           func(string) error
	workerIsolation          func() (workerIsolationConfig, error)
	workerProcessAttributes  func() *syscall.SysProcAttr
}

// HostCapabilities describes the runtime path accepted by the OpenShell-style
// libkrun backend. Linux uses KVM; macOS ARM64 uses Hypervisor.framework.
type HostCapabilities struct {
	OS           string
	Architecture string
	Hypervisor   string
	RuntimeDir   string
}

// DefaultHostConfig reads the VM runtime override and supplies the KVM device.
func DefaultHostConfig() HostConfig {
	runtimeDir := strings.TrimSpace(os.Getenv("CAUTEM_VM_RUNTIME_DIR"))
	if runtimeDir == "" {
		if cacheDir, err := os.UserCacheDir(); err == nil {
			runtimeDir = filepath.Join(cacheDir, "cautem", "vm-runtime")
		}
	}
	kvmDevice := strings.TrimSpace(os.Getenv("CAUTEM_KVM_DEVICE"))
	if kvmDevice == "" {
		kvmDevice = "/dev/kvm"
	}
	stateDir := strings.TrimSpace(os.Getenv("CAUTEM_VM_STATE_DIR"))
	if stateDir == "" {
		stateDir = defaultStateDir()
	}
	rootfsTarDir := strings.TrimSpace(os.Getenv("CAUTEM_VM_ROOTFS_TAR_DIR"))
	if rootfsTarDir == "" {
		rootfsTarDir = defaultRootfsTarDir()
	}
	rootfsImageCacheMaxBytes := defaultRootfsImageCacheMaxBytes
	if raw := strings.TrimSpace(os.Getenv("CAUTEM_VM_IMAGE_CACHE_MAX_BYTES")); raw != "" {
		if parsed, parseErr := strconv.ParseInt(raw, 10, 64); parseErr == nil && parsed > 0 {
			rootfsImageCacheMaxBytes = parsed
		}
	}
	guestAgentPath := strings.TrimSpace(os.Getenv("CAUTEM_VM_GUEST_AGENT"))
	if guestAgentPath == "" {
		guestAgentPath = defaultGuestAgentPath()
	}
	workerPath := strings.TrimSpace(os.Getenv("CAUTEM_VM_WORKER"))
	return normalizeHostConfig(HostConfig{
		RuntimeDir: runtimeDir, KVMDevice: kvmDevice, StateDir: stateDir,
		RootfsTarDir: rootfsTarDir, RootfsTarMaxBytes: defaultRootfsTarMaxBytes,
		RootfsImageCacheMaxBytes: rootfsImageCacheMaxBytes,
		GuestAgentPath:           guestAgentPath, WorkerPath: workerPath,
	})
}

func defaultGuestAgentPath() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	path := filepath.Join(filepath.Dir(executable), "cautem-vm-guest-agent-linux-"+runtime.GOARCH)
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
		return path
	}
	return ""
}

func normalizeHostConfig(config HostConfig) HostConfig {
	if strings.TrimSpace(config.StateDir) == "" {
		config.StateDir = defaultStateDir()
	}
	if strings.TrimSpace(config.RootfsTarDir) == "" {
		config.RootfsTarDir = defaultRootfsTarDir()
	}
	if config.RootfsTarMaxBytes <= 0 {
		config.RootfsTarMaxBytes = defaultRootfsTarMaxBytes
	}
	if config.RootfsImageCacheMaxBytes <= 0 {
		config.RootfsImageCacheMaxBytes = defaultRootfsImageCacheMaxBytes
	}
	if config.VCPUs == 0 {
		config.VCPUs = 2
	}
	if config.MemoryMiB == 0 {
		config.MemoryMiB = 2048
	}
	if strings.TrimSpace(config.KVMDevice) == "" {
		config.KVMDevice = "/dev/kvm"
	}
	return config
}

func defaultRootfsTarDir() string {
	base, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(base) == "" {
		return ""
	}
	return filepath.Join(base, "cautem", "vm", "rootfs-tars")
}

// ProbeHost verifies the current host and installed libkrun runtime bundle. It
// does not create directories, alter device permissions, or modify networking.
func ProbeHost(config HostConfig) (HostCapabilities, error) {
	return probeHost(runtime.GOOS, runtime.GOARCH, config)
}

func probeHost(goos, goarch string, config HostConfig) (HostCapabilities, error) {
	caps := HostCapabilities{OS: goos, Architecture: goarch, RuntimeDir: config.RuntimeDir}
	libName, fwName, platformErr := libKrunLibraryNames(goos, goarch)
	if platformErr != nil {
		return HostCapabilities{}, platformErr
	}
	switch goos {
	case "linux":
		caps.Hypervisor = "KVM"
		checkKVM := config.kvmDeviceCheck
		if checkKVM == nil {
			checkKVM = checkKVMDevice
		}
		if err := checkKVM(config.KVMDevice); err != nil {
			return HostCapabilities{}, err
		}
	case "darwin":
		caps.Hypervisor = "Hypervisor.framework"
	}
	if strings.TrimSpace(config.RuntimeDir) == "" {
		return HostCapabilities{}, fmt.Errorf("VM runtime directory is unset; set CAUTEM_VM_RUNTIME_DIR")
	}
	info, err := os.Stat(config.RuntimeDir)
	if err != nil {
		return HostCapabilities{}, fmt.Errorf("VM runtime directory %q is unavailable: %w", config.RuntimeDir, err)
	}
	if !info.IsDir() {
		return HostCapabilities{}, fmt.Errorf("VM runtime path %q is not a directory", config.RuntimeDir)
	}
	for _, name := range []string{libName, fwName} {
		if err := checkRuntimeLibrary(filepath.Join(config.RuntimeDir, name)); err != nil {
			return HostCapabilities{}, err
		}
	}
	return caps, nil
}

func libKrunLibraryNames(goos, goarch string) (lib, fw string, err error) {
	switch {
	case goos == "linux" && (goarch == "amd64" || goarch == "arm64"):
		return "libkrun.so", "libkrunfw.so.5", nil
	case goos == "darwin" && goarch == "arm64":
		return "libkrun.dylib", "libkrunfw.5.dylib", nil
	default:
		return "", "", fmt.Errorf("unsupported MicroVM host %s/%s; supported: Linux amd64/arm64, macOS arm64", goos, goarch)
	}
}

func checkRuntimeLibrary(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("libkrun runtime file %q is unavailable: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect libkrun runtime file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("libkrun runtime file %q must be a non-empty regular file", path)
	}
	return nil
}
