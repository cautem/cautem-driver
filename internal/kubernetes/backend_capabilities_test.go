package kubernetes

import (
	"testing"

	"github.com/cautem/quarshell-driver/driver"
)

func TestBackendCapabilityInfoAdvertisesRuntimeExtensions(t *testing.T) {
	info := (*Driver)(nil).BackendCapabilityInfo()
	if info.ID != "kubernetes" || !info.Has(driver.CapabilityTokenAwareStart) || !info.Has(driver.CapabilityPolicyUpdate) || !info.Has(driver.CapabilityCredentialRefresh) || !info.Has(driver.CapabilityProxyReadiness) {
		t.Fatalf("Kubernetes backend info=%+v; want token, policy, credential, and proxy readiness capabilities", info)
	}
}
