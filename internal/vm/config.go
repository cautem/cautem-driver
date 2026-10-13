package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// SandboxDriverConfig is the VM driver's strict subset of the OpenShell
// sandbox driver_config schema.
type SandboxDriverConfig struct {
	GPUDeviceIDs  *[]string `json:"gpu_device_ids,omitempty"`
	RootfsTarPath string    `json:"rootfs_tar_path,omitempty"`
}

// ParseSandboxDriverConfig strictly decodes VM-specific sandbox options.
func ParseSandboxDriverConfig(raw string) (SandboxDriverConfig, error) {
	var config SandboxDriverConfig
	if strings.TrimSpace(raw) == "" {
		return config, nil
	}
	trimmed := bytes.TrimSpace([]byte(raw))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: must be an object")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: unexpected value after JSON object")
	} else if !errors.Is(err, io.EOF) {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: %w", err)
	}
	if config.GPUDeviceIDs != nil && len(*config.GPUDeviceIDs) == 0 {
		return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: gpu_device_ids must be a non-empty list when provided")
	}
	if config.GPUDeviceIDs != nil {
		for _, id := range *config.GPUDeviceIDs {
			if strings.TrimSpace(id) == "" {
				return SandboxDriverConfig{}, fmt.Errorf("invalid vm driver_config: gpu_device_ids entries must not be empty")
			}
		}
	}
	return config, nil
}

func validateSandboxName(name string) error {
	if len(name) == 0 || len(name) > 128 || name == "." || name == ".." {
		return fmt.Errorf("vm driver: invalid sandbox name; expected [A-Za-z0-9._-]{1,128}")
	}
	for _, b := range []byte(name) {
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '.', b == '_', b == '-':
		default:
			return fmt.Errorf("vm driver: invalid sandbox name; expected [A-Za-z0-9._-]{1,128}")
		}
	}
	return nil
}

func validateGPURequest(enabled bool, config SandboxDriverConfig) error {
	if config.GPUDeviceIDs == nil {
		return nil
	}
	if !enabled {
		return fmt.Errorf("invalid vm driver_config: gpu_device_ids requires a GPU request")
	}
	if len(*config.GPUDeviceIDs) > 1 {
		return fmt.Errorf("invalid vm driver_config: VM driver supports at most one gpu_device_ids entry")
	}
	return nil
}
