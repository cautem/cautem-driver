package docker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cautem/cautem-driver/driver"
)

func TestDeviceRequestsForGPU(t *testing.T) {
	if DeviceRequestsForGPU(driver.Spec{}) != nil {
		t.Fatal("expected nil when GPU off")
	}
	reqs := DeviceRequestsForGPU(driver.Spec{GPU: true})
	if len(reqs) != 1 || reqs[0].Driver != "cdi" || len(reqs[0].DeviceIDs) != 1 || reqs[0].DeviceIDs[0] != defaultCDIDevice {
		t.Fatalf("reqs=%+v", reqs)
	}
	reqs = DeviceRequestsForGPU(driver.Spec{CDIDevices: []string{"nvidia.com/gpu=0", "  "}})
	if len(reqs) != 1 || len(reqs[0].DeviceIDs) != 1 || reqs[0].DeviceIDs[0] != "nvidia.com/gpu=0" {
		t.Fatalf("reqs=%+v", reqs)
	}
	t.Setenv("CAUTEM_GPU_CDI", "nvidia.com/gpu=1,nvidia.com/gpu=2")
	reqs = DeviceRequestsForGPU(driver.Spec{GPU: true})
	if len(reqs[0].DeviceIDs) != 2 {
		t.Fatalf("env ids=%v", reqs[0].DeviceIDs)
	}
}

func TestValidateGPURequestRequiresMatchingExplicitInventory(t *testing.T) {
	if err := ValidateGPURequest(driver.Spec{GPUCount: 2, CDIDevices: []string{"nvidia.com/gpu=0"}}); err == nil {
		t.Fatal("accepted mismatched GPU count")
	}
	if err := ValidateGPURequest(driver.Spec{GPUCount: 2, CDIDevices: []string{"nvidia.com/gpu=0", "nvidia.com/gpu=1"}}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateGPURequestRejectsDevicesWithoutGPURequest(t *testing.T) {
	if err := ValidateGPURequest(driver.Spec{CDIDevices: []string{"nvidia.com/gpu=0"}}); err == nil {
		t.Fatal("accepted CDI devices without GPU request")
	}
}

func TestLocalCDIDevicesAreSelectedInNumericOrder(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"nvidia10", "nvidia2", "nvidia0", "nvidiactl"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := localCDIDevices(root)
	want := []string{"nvidia.com/gpu=0", "nvidia.com/gpu=2", "nvidia.com/gpu=10"}
	if len(got) != len(want) {
		t.Fatalf("devices=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("devices=%v, want %v", got, want)
		}
	}
}

func TestLocalCDIDevicesUsesAggregateSelectorForDXG(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "dxg"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got := localCDIDevices(root)
	if len(got) != 1 || got[0] != defaultCDIDevice {
		t.Fatalf("DXG devices=%v, want [%s]", got, defaultCDIDevice)
	}
}
