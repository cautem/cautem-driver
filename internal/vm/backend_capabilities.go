package vm

import "github.com/cautem/cautem-driver/driver"

func (*Driver) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{
		ID: "vm",
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityInteractiveExec:          {},
			driver.CapabilityPTY:                      {},
			driver.CapabilityExecTerminal:             {},
			driver.CapabilityLogAccess:                {},
			driver.CapabilityFileTransfer:             {},
			driver.CapabilityLaunchSpecRestore:        {},
			driver.CapabilityGatewayRuntimeValidation: {},
			driver.CapabilityProxyReadiness:           {},
			driver.CapabilityRootfsTarStaging:         {},
		},
	}
}
