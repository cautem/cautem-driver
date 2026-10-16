package docker

import (
	"testing"

	"github.com/cautem/quarshell-driver/driver"
)

func TestBackendCapabilityInfoReportsConfiguredBackendAndExtensions(t *testing.T) {
	engine := NewFromClientWithRuntimeConfig(nil, RuntimeConfig{BackendID: "podman"})
	info := engine.BackendCapabilityInfo()
	if info.ID != driver.BackendID("podman") {
		t.Fatalf("backend ID = %q; want podman", info.ID)
	}
	for _, capability := range []driver.Capability{
		driver.CapabilityInteractiveExec,
		driver.CapabilityPTY,
		driver.CapabilityLogAccess,
		driver.CapabilityFileTransfer,
		driver.CapabilityProcessWait,
		driver.CapabilityProcessLogs,
		driver.CapabilityProcessTerminal,
	} {
		if !info.Has(capability) {
			t.Errorf("backend capabilities do not include %q", capability)
		}
	}
}
