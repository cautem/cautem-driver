package docker

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/moby/moby/api/types/container"

	"github.com/cautem/cautem-core/defaults"
	"github.com/cautem/quarshell-driver/driver"
)

// ValidateGPURequest enforces the pinned OpenShell relationship between a
// GPU request, its explicit CDI devices, and GPUCount. It is shared by Docker
// and Podman because both backends use the same ComputeDriver Spec.
func ValidateGPURequest(spec driver.Spec) error {
	if spec.GPUCount < 0 {
		return fmt.Errorf("gpu count must not be negative")
	}
	hasDevices := len(normalizedCDIDevices(spec.CDIDevices)) > 0 || len(envCDIDevices()) > 0
	requested := spec.GPU || spec.GPUCount > 0
	if hasDevices && !requested {
		return fmt.Errorf("cdi devices require a GPU request")
	}
	if spec.GPUCount == 0 {
		return nil
	}
	devices := normalizedCDIDevices(spec.CDIDevices)
	explicit := len(devices) > 0
	if len(devices) == 0 {
		devices = envCDIDevices()
		explicit = len(devices) > 0
	}
	if len(devices) == 0 {
		devices = localCDIDevices("/dev")
	}
	if len(devices) == 0 {
		return fmt.Errorf("gpu count %d requires CDI devices or a local GPU inventory", spec.GPUCount)
	}
	if (explicit && len(devices) != spec.GPUCount) || (!explicit && len(devices) < spec.GPUCount) {
		return fmt.Errorf("gpu count (%d) exceeds CDI inventory (%d)", spec.GPUCount, len(devices))
	}
	return nil
}

const (
	defaultCDIDevice   = "nvidia.com/gpu=all"
	labelGPU           = "cautem.gpu"
	gpuSandboxImage    = defaults.ImageGPU
	guiGPUSandboxImage = defaults.ImageGUIGPU
)

// DeviceRequestsForGPU builds Docker CDI DeviceRequests for a Spec (nil if GPU off).
func DeviceRequestsForGPU(spec driver.Spec) []container.DeviceRequest {
	if !spec.GPU && len(spec.CDIDevices) == 0 {
		return nil
	}
	ids := normalizedCDIDevices(spec.CDIDevices)
	if len(ids) == 0 {
		ids = envCDIDevices()
	}
	if spec.GPUCount > 0 && len(ids) == 0 {
		ids = localCDIDevices("/dev")
	}
	if spec.GPUCount > 0 && len(ids) > spec.GPUCount {
		ids = ids[:spec.GPUCount]
	}
	if len(ids) == 0 {
		ids = []string{defaultCDIDevice}
	}
	return []container.DeviceRequest{{
		Driver:    "cdi",
		DeviceIDs: ids,
	}}
}

func normalizedCDIDevices(values []string) []string {
	ids := make([]string, 0, len(values))
	for _, id := range values {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func envCDIDevices() []string {
	return normalizedCDIDevices(strings.Split(strings.TrimSpace(os.Getenv("CAUTEM_GPU_CDI")), ","))
}

// localCDIDevices mirrors the pinned Podman inventory rule: only numbered
// /dev/nvidiaN nodes become exact CDI IDs, in deterministic numeric order.
func localCDIDevices(devRoot string) []string {
	entries, err := os.ReadDir(devRoot)
	if err != nil {
		return nil
	}
	var indexes []string
	for _, entry := range entries {
		name := entry.Name()
		index := strings.TrimPrefix(name, "nvidia")
		if index == "" || index == name || !allDigits(index) {
			continue
		}
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return numericIndex(indexes[i]) < numericIndex(indexes[j]) })
	devices := make([]string, 0, len(indexes))
	for _, index := range indexes {
		devices = append(devices, "nvidia.com/gpu="+index)
	}
	// Podman on WSL exposes the GPU as /dev/dxg rather than numbered NVIDIA
	// nodes. In that environment the pinned contract permits the aggregate CDI
	// selector, but not fabricated per-device IDs.
	if len(devices) == 0 {
		if _, err := os.Stat(strings.TrimRight(devRoot, "/") + "/dxg"); err == nil {
			return []string{defaultCDIDevice}
		}
	}
	return devices
}

func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func numericIndex(value string) int {
	result := 0
	for _, r := range value {
		result = result*10 + int(r-'0')
	}
	return result
}
