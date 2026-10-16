package vm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProbeHostRuntimeMatrix(t *testing.T) {
	t.Run("Linux capability result requires an accepted KVM check", func(t *testing.T) {
		runtimeDir := makeRuntimeBundle(t, "libkrun.so", "libkrunfw.so.5")
		config := HostConfig{
			RuntimeDir: runtimeDir,
			KVMDevice:  "/fixture/kvm",
			kvmDeviceCheck: func(path string) error {
				if path != "/fixture/kvm" {
					return os.ErrNotExist
				}
				return nil
			},
		}
		caps, err := probeHost("linux", "amd64", config)
		if err != nil {
			t.Fatalf("probeHost() error = %v", err)
		}
		if caps.Hypervisor != "KVM" || caps.Architecture != "amd64" {
			t.Fatalf("capabilities = %+v", caps)
		}
	})

	t.Run("Linux rejects a regular file as a KVM device", func(t *testing.T) {
		runtimeDir := makeRuntimeBundle(t, "libkrun.so", "libkrunfw.so.5")
		kvm := filepath.Join(t.TempDir(), "kvm")
		if err := os.WriteFile(kvm, []byte("device"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := probeHost("linux", "amd64", HostConfig{RuntimeDir: runtimeDir, KVMDevice: kvm})
		if err == nil || !strings.Contains(err.Error(), "KVM device") {
			t.Fatalf("probeHost() error = %v; want KVM validation failure", err)
		}
		if runtime.GOOS == "linux" && !strings.Contains(err.Error(), "not a character device") {
			t.Fatalf("Linux KVM validation error = %v; want regular file rejected", err)
		}
		if runtime.GOOS != "linux" && !strings.Contains(err.Error(), "only be validated on a Linux host") {
			t.Fatalf("non-Linux KVM validation error = %v; want native Linux requirement", err)
		}
	})

	t.Run("macOS arm64 selects Hypervisor framework", func(t *testing.T) {
		runtimeDir := makeRuntimeBundle(t, "libkrun.dylib", "libkrunfw.5.dylib")
		caps, err := probeHost("darwin", "arm64", HostConfig{RuntimeDir: runtimeDir})
		if err != nil {
			t.Fatalf("probeHost() error = %v", err)
		}
		if caps.Hypervisor != "Hypervisor.framework" {
			t.Fatalf("hypervisor = %q", caps.Hypervisor)
		}
	})

	t.Run("Linux without KVM access is rejected", func(t *testing.T) {
		runtimeDir := makeRuntimeBundle(t, "libkrun.so", "libkrunfw.so.5")
		_, err := probeHost("linux", "arm64", HostConfig{RuntimeDir: runtimeDir, KVMDevice: filepath.Join(t.TempDir(), "missing-kvm")})
		if err == nil || !strings.Contains(err.Error(), "KVM device") {
			t.Fatalf("probeHost() error = %v; want KVM access error", err)
		}
	})

	t.Run("unsupported host architecture is rejected", func(t *testing.T) {
		_, err := probeHost("windows", "amd64", HostConfig{RuntimeDir: t.TempDir()})
		if err == nil || !strings.Contains(err.Error(), "unsupported MicroVM host") {
			t.Fatalf("probeHost() error = %v; want unsupported-host error", err)
		}
	})

	t.Run("empty runtime files are rejected", func(t *testing.T) {
		runtimeDir := t.TempDir()
		for _, name := range []string{"libkrun.dylib", "libkrunfw.5.dylib"} {
			if err := os.WriteFile(filepath.Join(runtimeDir, name), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := probeHost("darwin", "arm64", HostConfig{RuntimeDir: runtimeDir})
		if err == nil || !strings.Contains(err.Error(), "non-empty regular file") {
			t.Fatalf("probeHost() error = %v; want empty runtime rejection", err)
		}
	})
}

func TestLibKrunLibraryNames(t *testing.T) {
	tests := []struct {
		goos, goarch string
		lib, fw      string
	}{
		{"linux", "amd64", "libkrun.so", "libkrunfw.so.5"},
		{"linux", "arm64", "libkrun.so", "libkrunfw.so.5"},
		{"darwin", "arm64", "libkrun.dylib", "libkrunfw.5.dylib"},
	}
	for _, tt := range tests {
		t.Run(tt.goos+"/"+tt.goarch, func(t *testing.T) {
			lib, fw, err := libKrunLibraryNames(tt.goos, tt.goarch)
			if err != nil {
				t.Fatalf("libKrunLibraryNames() error = %v", err)
			}
			if lib != tt.lib || fw != tt.fw {
				t.Fatalf("library names = %q, %q; want %q, %q", lib, fw, tt.lib, tt.fw)
			}
		})
	}
}

func makeRuntimeBundle(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("runtime"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
