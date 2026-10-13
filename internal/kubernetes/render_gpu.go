package kubernetes

import (
	"fmt"
	"strconv"
)

// configWithRequestedGPU maps the Gateway's quota-accounted GPU request to the
// standard NVIDIA device-plugin resource. driver_config cannot set this key;
// otherwise a template could allocate GPUs without passing Gateway quota.
func configWithRequestedGPU(config SandboxDriverConfig, enabled bool, count int) (SandboxDriverConfig, error) {
	if count < 0 || (!enabled && count != 0) {
		return SandboxDriverConfig{}, fmt.Errorf("GPU count must be non-negative and requires GPU to be enabled")
	}
	if !enabled {
		return config, nil
	}
	if count == 0 {
		count = 1
	}

	requests := cloneStringMap(config.Containers.Agent.Resources.Requests)
	limits := cloneStringMap(config.Containers.Agent.Resources.Limits)
	if requests == nil {
		requests = make(map[string]string)
	}
	if limits == nil {
		limits = make(map[string]string)
	}
	quantity := strconv.Itoa(count)
	requests[nvidiaGPUResourceName] = quantity
	limits[nvidiaGPUResourceName] = quantity
	config.Containers.Agent.Resources.Requests = requests
	config.Containers.Agent.Resources.Limits = limits
	config.gatewayGPUResources = true
	return config, nil
}
