package kubernetes

import "github.com/cautem/quarshell-driver/driver"

func (*Driver) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{
		ID: "kubernetes",
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityTokenAwareStart:   {},
			driver.CapabilityPolicyUpdate:      {},
			driver.CapabilityCredentialRefresh: {},
			driver.CapabilityProxyReadiness:    {},
		},
	}
}
