package docker

import "github.com/cautem/quarshell-driver/driver"

func (d *Driver) BackendCapabilityInfo() driver.BackendInfo {
	backendID := "docker"
	if d != nil && d.runtimeConfig.BackendID != "" {
		backendID = d.runtimeConfig.BackendID
	}
	return driver.BackendInfo{
		ID: driver.BackendID(backendID),
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityInteractiveExec: {},
			driver.CapabilityPTY:             {},
			driver.CapabilityLogAccess:       {},
			driver.CapabilityFileTransfer:    {},
			driver.CapabilityProcessWait:     {},
			driver.CapabilityProcessLogs:     {},
			driver.CapabilityProcessTerminal: {},
		},
	}
}
