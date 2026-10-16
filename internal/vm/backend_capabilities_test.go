//go:build darwin || linux

package vm

import (
	"testing"

	"github.com/cautem/quarshell-driver/driver"
)

func TestBackendCapabilityInfoAdvertisesRuntimeExtensions(t *testing.T) {
	info := (*Driver)(nil).BackendCapabilityInfo()
	for _, capability := range []driver.Capability{
		driver.CapabilityInteractiveExec,
		driver.CapabilityPTY,
		driver.CapabilityExecTerminal,
		driver.CapabilityLogAccess,
		driver.CapabilityFileTransfer,
		driver.CapabilityLaunchSpecRestore,
		driver.CapabilityGatewayRuntimeValidation,
		driver.CapabilityProxyReadiness,
		driver.CapabilityRootfsTarStaging,
	} {
		if !info.Has(capability) {
			t.Errorf("VM backend omitted capability %q", capability)
		}
	}
}
